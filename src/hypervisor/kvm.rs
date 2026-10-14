// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The code the two KVM backends share.
//!
//! [`Kicker`] ends a vCPU's `KVM_RUN` from another thread. The kick signal
//! alone is not enough: one that lands while the thread is in user space,
//! between its check of the running flag and its `KVM_RUN`, is consumed by the
//! handler and the run goes ahead. So a kick first sets the vCPU's
//! `kvm_run.immediate_exit` byte, which makes the next `KVM_RUN` return `EINTR`
//! at once, and then sends the signal for a run already in progress.

use std::ops::ControlFlow;
use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::{KVM_EXIT_INTR, KVM_SYSTEM_EVENT_RESET};
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};

use crate::checkpoint::capture::Console;
use crate::checkpoint::profile::ProfileCell;
use crate::checkpoint::server::ControlSocket;
use crate::config::{BootConfig, Stop};
use crate::devices::irq::IrqLine;
use crate::devices::virtio::vsock::VsockBridge;
use crate::hypervisor::guest::Guest;
use crate::hypervisor::vcpus::{Kick, Outcome};
use crate::io_threads::{IoThreads, NetSource};
use crate::plugin::Plugin;
use crate::run::{record_start, run_to_stop};
use crate::sandbox::seccomp;
use crate::signal::kick_signal;
use crate::sync::lock_or_recover;
use crate::teardown::StopSource;
use crate::terminal;
use crate::LOG_PREFIX;

/// The [`Kick`] implementation for KVM vCPUs.
///
/// It holds each vCPU's thread and a second handle to the vCPU. A kick sets
/// `immediate_exit` through the handle and then signals the thread.
pub(crate) struct Kicker {
    /// The vCPU threads indexed by vCPU id, each `None` until its thread
    /// registers and again once the registration is dropped.
    threads: Mutex<Vec<Option<VcpuThread>>>,
}

impl Kicker {
    /// Returns a table for `count` vCPU threads, none of them registered.
    pub(crate) fn new(count: u32) -> Self {
        Self {
            threads: Mutex::new((0..count).map(|_| None).collect()),
        }
    }

    /// Registers the calling thread as vCPU `cpu`, to be kicked through `vcpu`.
    ///
    /// `vcpu` is a second handle to the vCPU, from [`kick_handle`]. The
    /// returned guard removes the entry when dropped. The thread must clear its
    /// own `immediate_exit` byte before each read of the running flag, so a
    /// kick that lands after the clear ends the run that follows.
    pub(crate) fn register(&self, cpu: u32, vcpu: VcpuFd) -> Registration<'_> {
        let thread = VcpuThread {
            // SAFETY: pthread_self is always valid on the current thread.
            tid: unsafe { libc::pthread_self() } as u64,
            vcpu,
        };
        if let Some(slot) = lock_or_recover(&self.threads).get_mut(cpu as usize) {
            *slot = Some(thread);
        }
        Registration { kicker: self, cpu }
    }

    /// Runs `inspect` on the second handle to vCPU `cpu`, if its thread is
    /// registered.
    ///
    /// The handle is a descriptor of the same vCPU, so a register read through
    /// it needs no borrow of the handle the vCPU thread runs.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub(crate) fn with_vcpu(&self, cpu: u32, inspect: impl FnOnce(&VcpuFd)) {
        if let Some(Some(thread)) = lock_or_recover(&self.threads).get(cpu as usize) {
            inspect(&thread.vcpu);
        }
    }
}

impl Kick for Kicker {
    fn kick(&self, cpu: u32) {
        if let Some(Some(thread)) = lock_or_recover(&self.threads).get_mut(cpu as usize) {
            thread.kick();
        }
    }

    fn kick_all(&self) {
        for thread in lock_or_recover(&self.threads).iter_mut().flatten() {
            thread.kick();
        }
    }
}

/// A guest interrupt line on KVM's in-kernel interrupt controller.
pub(crate) struct KvmIrqLine {
    /// The VM whose interrupt controller has the line.
    vm: Arc<VmFd>,
    /// The line's number, as `KVM_IRQ_LINE` takes it.
    gsi: u32,
}

impl KvmIrqLine {
    /// Returns the line `gsi` of `vm`.
    pub(crate) fn new(vm: Arc<VmFd>, gsi: u32) -> Self {
        Self { vm, gsi }
    }
}

impl IrqLine for KvmIrqLine {
    fn set_level(&self, level: bool) -> std::io::Result<()> {
        Ok(self.vm.set_irq_line(self.gsi, level)?)
    }
}

/// A vCPU thread as the other threads reach it.
struct VcpuThread {
    /// The pthread handle the signal goes to, as an integer.
    tid: u64,
    /// The second handle to the vCPU, from [`kick_handle`].
    vcpu: VcpuFd,
}

impl VcpuThread {
    /// Ends the thread's current or next `KVM_RUN`, unless the caller is the
    /// thread itself.
    fn kick(&mut self) {
        // A kick from the thread itself, from a plugin's `safepoint` or a sink
        // on the exit path, would end its next run before the guest ran and
        // call the hook again at once.
        // SAFETY: pthread_self is always valid on the current thread.
        if self.tid == unsafe { libc::pthread_self() } as u64 {
            return;
        }
        immediate_exit(&mut self.vcpu).store(1, Ordering::SeqCst);
        // SAFETY: pthread_kill to a live thread handle; no-op handler.
        unsafe { libc::pthread_kill(self.tid as libc::pthread_t, kick_signal()) };
    }
}

/// A vCPU thread's entry in a [`Kicker`], removed when dropped.
///
/// The removal runs on a panic as on a return, so a kick from a plugin thread
/// that outlives `boot` never signals a thread that no longer exists.
pub(crate) struct Registration<'a> {
    /// The table the entry is in.
    kicker: &'a Kicker,
    /// The vCPU id of the entry.
    cpu: u32,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Some(slot) = lock_or_recover(&self.kicker.threads).get_mut(self.cpu as usize) {
            *slot = None;
        }
    }
}

/// Starts what runs beside a KVM backend's vCPUs, in the order its seccomp
/// confinement needs.
///
/// The plugin attaches to the guest before anything runs. The filters are armed
/// before the first I/O or vCPU thread exists, and a binary's stop-signal
/// thread starts right after. The agent socket, the control socket and the stop
/// source's socket pair are created before any filter goes in, since the
/// allowlists allow accepting on a listener already held but not creating one.
/// Then the I/O threads start, with the threads the plugin asked for, each
/// filtering itself as it begins. The control socket reports `profile`, and a
/// checkpoint captures `console` beside the guest's virtio devices.
///
/// # Errors
///
/// Errors if the plugin refuses the guest, a filter does not compile, the
/// stop-signal thread cannot be started or its handlers installed, a socket
/// cannot be bound or the stop source cannot be created.
pub(crate) fn start_io_threads(
    cfg: &BootConfig,
    guest: &Arc<Guest<Kicker>>,
    deliver: impl FnMut(u8) + Send + 'static,
    net: Option<NetSource>,
    profile: Arc<ProfileCell>,
    console: Console,
) -> Result<(seccomp::Filters, IoThreads<Kicker>), Box<dyn std::error::Error + Send + Sync>> {
    let plugin_threads = guest.attach(cfg.plugin.as_ref())?;
    let filters = seccomp::Filters::arm(cfg.sandbox)?;
    // A binary's stop signals get their handlers, and the thread that receives
    // them starts, once the filters are armed, so the thread installs the `vmm`
    // filter as its first act. The terminal goes into raw mode after this, so a
    // first stop signal stops the run rather than ending the process with the
    // terminal raw.
    crate::signal::start_stop_signal_thread()?;
    let bridge = match (&cfg.agent_sock, &guest.vsock) {
        (Some(path), Some(dev)) => Some(VsockBridge::bind(
            path,
            Arc::clone(dev),
            Arc::clone(&guest.ram),
        )?),
        _ => None,
    };
    let control = cfg
        .control_sock
        .as_deref()
        .map(|path| {
            ControlSocket::bind(path, profile, cfg.checkpoint_root.as_deref()).map(|control| {
                let disk = cfg.disks.first().map(|disk| disk.path.clone());
                control.capturing("kvm", disk, console)
            })
        })
        .transpose()?;
    let source = StopSource::new()?;
    let io_threads = IoThreads::start(
        source,
        guest,
        cfg.plugin.clone(),
        deliver,
        bridge,
        net,
        control,
        plugin_threads,
    );
    Ok((filters, io_threads))
}

/// Runs the guest on one thread per vCPU and returns how the run ended.
///
/// Each vCPU thread runs `run` with its id, its vCPU, its kick handle and a
/// clone of `shared`. Once they exist the calling thread installs its own
/// filter, and then waits for the stop in [`run_to_stop`], which also stops
/// `io_threads`. The terminal stays in raw mode until this returns.
///
/// # Errors
///
/// Errors if a vCPU thread cannot be spawned, the calling thread cannot be
/// filtered, a vCPU or an I/O thread fails, or a thread does not stop. Each
/// failure stops the guest, and the error is chosen as [`run_to_stop`]
/// describes, once every thread has been joined or left running.
pub(crate) fn run_guest<S: Clone + Send + 'static>(
    guest: &Guest<Kicker>,
    shared: &S,
    vcpus: Vec<VcpuFd>,
    kick_handles: Vec<VcpuFd>,
    run: fn(u32, VcpuFd, VcpuFd, S),
    filters: seccomp::Filters,
    io_threads: IoThreads<Kicker>,
) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    let _raw = terminal::RawTerm::enable();

    // Log mode traps nothing, so the run is not confined under it.
    let confined = filters.is_armed() && !seccomp::log_mode();
    record_start(guest, confined);
    let (threads, spawned) = guest.vcpus.spawn(
        vcpus
            .into_iter()
            .zip(kick_handles)
            .map(|(vcpu, kick_handle)| (vcpu, kick_handle, shared.clone(), run)),
        |id, (vcpu, kick_handle, shared, run)| run(id, vcpu, kick_handle, shared),
    );
    let mut failure: Option<Box<dyn std::error::Error + Send + Sync>> =
        spawned.err().map(Into::into);

    // The guest is already running by now, so a failure to filter the calling
    // thread stops it like any other failure.
    if let Err(e) = filters.install() {
        // The error is printed here, since a spawn failure ahead of it is the
        // one returned.
        stderrln!("{LOG_PREFIX} {e}");
        failure.get_or_insert(e.into());
    }

    // `boot` keeps the run's claim when it sees a `LeftRunning` error, so the
    // error goes back as `run_to_stop` returned it.
    run_to_stop(guest, threads, failure, io_threads)
}

/// Runs vCPU `cpu` on the calling thread until the VM stops.
///
/// Each pass clears the vCPU's `immediate_exit` byte, checks the running flag,
/// parks at the quiesce checkpoint, lets `plugin` look at the guest from the
/// boot vCPU, and then enters the guest once. The exits both KVM backends treat
/// the same are serviced here: a PSCI system event is how the guest asked to
/// stop, and an entry failure, an internal error and a `KVM_RUN` error are
/// failures. Every other exit goes to `handle_exit`, which services it and
/// returns `ControlFlow::Break` with the run's outcome to end the loop. A run a
/// kick cut short reaches it as [`VcpuExit::Intr`]. A break reports its outcome
/// through [`Vcpus::report`](crate::hypervisor::vcpus::Vcpus::report).
pub(crate) fn run_vcpu(
    cpu: u32,
    mut vcpu: VcpuFd,
    kick_handle: VcpuFd,
    guest: &Guest<Kicker>,
    plugin: Option<&dyn Plugin>,
    mut handle_exit: impl FnMut(VcpuExit<'_>) -> ControlFlow<Outcome>,
) {
    // The vCPU filter goes in before this thread touches anything the guest
    // controls. MMIO exits are serviced on this thread, so the virtio device
    // models, which parse guest descriptors, run under it.
    seccomp::install_thread(seccomp::Thread::Vcpu);
    // The registration drops when the loop ends, before the thread reports its
    // exit, so the entry is gone before the stop kicks.
    let _registration = guest.vcpus.kicker().register(cpu, kick_handle);
    // Every KVM vCPU enters `KVM_RUN` at once. One the guest has not brought up
    // yet waits inside the run, where a kick reaches it.
    guest.vcpus.mark_started(cpu);
    // The plugin runs on vcpu0, between guest entries, because only this thread
    // can read this vCPU's registers.
    let plugin = plugin.filter(|_| cpu == 0);

    loop {
        // The byte is cleared before the running flag is read, so a kick that
        // lands from here on ends the run below at once.
        immediate_exit(&mut vcpu).store(0, Ordering::SeqCst);
        if !guest.vcpus.is_running() {
            break;
        }
        // Safe point for every vCPU: park here while vcpu0 lets a plugin look
        // at the guest, or the control socket captures it, doing on this
        // thread the work only it can.
        guest.pass_safepoint(&vcpu, cpu, plugin, |work| {
            crate::checkpoint::cpu::serve_from_regs_view(guest.arch, "kvm", cpu, &vcpu, work)
        });
        let flow = match vcpu.run() {
            Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {
                // A run that a kick cut short has completed the MMIO exit
                // before it and left `exit_reason` as it was. Linux 5.0 to 5.2
                // on arm64 complete the exit again on the next run, and so do
                // the stable series that took the same change back to 4.14.
                // That skips one more guest instruction, so the reason is
                // cleared here. x86 does not read the field when it enters the
                // guest.
                vcpu.get_kvm_run().exit_reason = KVM_EXIT_INTR;
                handle_exit(VcpuExit::Intr)
            }
            // PSCI `SYSTEM_RESET` or `SYSTEM_OFF`. An x86 guest raises none.
            Ok(VcpuExit::SystemEvent(event, _)) => {
                ControlFlow::Break(Outcome::Stopped(if event == KVM_SYSTEM_EVENT_RESET {
                    Stop::SystemReset
                } else {
                    Stop::SystemOff
                }))
            }
            Ok(VcpuExit::FailEntry(reason, entry_cpu)) => ControlFlow::Break(Outcome::Failed(
                format!("vcpu{cpu}: KVM entry failed reason={reason:#x} cpu={entry_cpu}"),
            )),
            Ok(VcpuExit::InternalError) => {
                ControlFlow::Break(Outcome::Failed(format!("vcpu{cpu}: KVM internal error")))
            }
            Err(e) => ControlFlow::Break(Outcome::Failed(format!("vcpu{cpu}: KVM_RUN error: {e}"))),
            Ok(exit) => handle_exit(exit),
        };
        if let ControlFlow::Break(outcome) = flow {
            guest.vcpus.report(outcome);
            break;
        }
    }
}

/// Returns the failure that ends the run of vCPU `cpu`, for an exit its backend
/// does not service.
pub(crate) fn unhandled_exit(cpu: u32, exit: &VcpuExit<'_>) -> ControlFlow<Outcome> {
    ControlFlow::Break(Outcome::Failed(format!(
        "vcpu{cpu}: unhandled exit {exit:?}"
    )))
}

/// Returns the `kvm_run.immediate_exit` byte of `vcpu`.
///
/// The vCPU thread, a thread that kicks it and the kernel each reach the byte
/// through a mapping of their own, so it is read and written as an atomic.
pub(crate) fn immediate_exit(vcpu: &mut VcpuFd) -> &AtomicU8 {
    let byte: *mut u8 = &mut vcpu.get_kvm_run().immediate_exit;
    // SAFETY: `byte` points into the mapping `vcpu` owns, which outlives the
    // borrow, and an `AtomicU8` has the layout of the `u8` it points to.
    unsafe { AtomicU8::from_ptr(byte) }
}

/// Returns a second handle to `vcpu`, with its own mapping of the run struct.
///
/// # Errors
///
/// Errors if the descriptor cannot be duplicated or the run struct cannot be
/// mapped.
pub(crate) fn kick_handle(vm: &VmFd, vcpu: &VcpuFd) -> std::io::Result<VcpuFd> {
    // SAFETY: `vcpu` owns the descriptor and outlives the borrow.
    let descriptor = unsafe { BorrowedFd::borrow_raw(vcpu.as_raw_fd()) }.try_clone_to_owned()?;
    // SAFETY: `descriptor` is a vCPU of `vm`, and the handle takes it over.
    unsafe { vm.create_vcpu_from_rawfd(descriptor.into_raw_fd()) }.map_err(std::io::Error::from)
}

// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. These tests read this
// process's own `/proc` entries.
#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod stop_tests {
    use super::*;
    use crate::config::BootConfig;
    use crate::plugin::{CpuHandle, VmHandle};
    use crate::run::StopHandle;
    use crate::signal::install_kick_handler;
    use kvm_ioctls::Kvm;
    use std::fs::File;
    use std::os::fd::RawFd;
    use std::sync::atomic::AtomicBool;
    use std::sync::{mpsc, Arc};
    use std::time::{Duration, Instant};

    /// Returns a kernel image the boot vCPU starts, for a test that never lets
    /// it run.
    fn kernel() -> Vec<u8> {
        #[cfg(target_arch = "x86_64")]
        let image = crate::arch::x86_64::loader::tests::synthetic_bzimage();
        #[cfg(target_arch = "aarch64")]
        let image =
            crate::arch::aarch64::loader::tests::synthetic_image(0x8_0000, 0x40_0000, 0x1000);
        image
    }

    /// Returns a kernel image whose boot vCPU spins in the guest and never
    /// exits.
    fn spinning_kernel() -> Vec<u8> {
        #[cfg(target_arch = "x86_64")]
        let image = crate::arch::x86_64::loader::tests::spinning_bzimage();
        #[cfg(target_arch = "aarch64")]
        let image = crate::arch::aarch64::loader::tests::spinning_image();
        image
    }

    /// A plugin whose `safepoint` panics on its first call, after recording
    /// that it was reached.
    struct PanicAtSafepoint {
        /// Whether `safepoint` has run.
        reached: AtomicBool,
    }

    impl Plugin for PanicAtSafepoint {
        fn safepoint(&self, _cpu: &dyn CpuHandle) {
            self.reached.store(true, Ordering::SeqCst);
            panic!("plugin failure under test");
        }
    }

    /// A plugin whose `safepoint` waits until the run is stopping, for at most
    /// five seconds, as one that holds a pause for another process does.
    struct WaitsInSafepoint {
        /// Whether `safepoint` has run.
        reached: AtomicBool,
    }

    impl Plugin for WaitsInSafepoint {
        fn safepoint(&self, cpu: &dyn CpuHandle) {
            self.reached.store(true, Ordering::SeqCst);
            // `yield_now` rather than a sleep, since the vCPU allowlist has no
            // `clock_nanosleep`.
            let deadline = Instant::now() + Duration::from_secs(5);
            while !cpu.is_stopping() && Instant::now() < deadline {
                std::thread::yield_now();
            }
        }
    }

    /// A plugin that starts one thread in `attach`, which waits for the stop,
    /// or panics at once when asked to.
    struct SpawnsAThread {
        /// Whether the thread panics rather than waiting.
        panics: bool,
        /// Whether the thread has seen the stop and returned.
        ended: Arc<AtomicBool>,
    }

    impl Plugin for SpawnsAThread {
        fn attach(&self, vmm: Arc<dyn VmHandle>) -> std::io::Result<()> {
            let (panics, ended) = (self.panics, Arc::clone(&self.ended));
            vmm.spawn(
                "plugin-wait",
                Box::new(move |stop| {
                    assert!(!panics, "plugin thread failure under test");
                    let _ = stop.sleep(Duration::from_secs(30));
                    ended.store(true, Ordering::SeqCst);
                }),
            )
        }
    }

    /// Returns the `Seccomp:` value of this process's thread `id`.
    fn seccomp_mode(id: libc::pid_t) -> Option<String> {
        std::fs::read_to_string(format!("/proc/self/task/{id}/status"))
            .ok()?
            .lines()
            .find_map(|line| {
                line.strip_prefix("Seccomp:")
                    .map(|mode| mode.trim().to_string())
            })
    }

    /// Returns the configuration of a two-vCPU boot of `kernel`.
    ///
    /// The seccomp filters are on in a release build, so a vCPU thread exits
    /// under the vCPU allowlist as it would in production. A debug build's std
    /// checks every descriptor it closes with `fcntl`, which that allowlist
    /// refuses, so there the filters stay off.
    fn config(kernel: Vec<u8>, plugin: Option<Arc<dyn Plugin>>) -> BootConfig {
        BootConfig {
            kernel,
            initramfs: None,
            mem_bytes: 128 << 20,
            cmdline: String::new(),
            disks: Vec::new(),
            fs_shares: Vec::new(),
            fs: Vec::new(),
            net: false,
            net_gateway: None,
            net_tap: None,
            net_mac: None,
            events: None,
            sandbox_id: "stop-test".to_string(),
            vcpus: 2,
            agent_sock: None,
            profile_out: None,
            control_sock: None,
            checkpoint_root: None,
            plugin,
            sandbox: !cfg!(debug_assertions),
            stop: None,
        }
    }

    /// Returns the kernel's id for the thread named `name`, or `None` if no
    /// thread of this process has that name.
    fn thread_id(name: &str) -> Option<libc::pid_t> {
        std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(Result::ok)
            .find(|task| {
                std::fs::read_to_string(task.path().join("comm"))
                    .is_ok_and(|comm| comm.trim_end() == name)
            })
            .and_then(|task| task.file_name().to_str()?.parse().ok())
    }

    /// Returns every descriptor of this process that refers to vCPU `cpu`.
    fn vcpu_descriptors(cpu: u32) -> Vec<RawFd> {
        let vcpu = format!("anon_inode:kvm-vcpu:{cpu}");
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|fd| std::fs::read_link(fd.path()).is_ok_and(|link| link.as_os_str() == &*vcpu))
            .filter_map(|fd| fd.file_name().to_str()?.parse().ok())
            .collect()
    }

    // The boot vCPU's plugin panics before the first guest entry, while the
    // secondary is in `KVM_RUN` or on its way there. `boot` returns only if the
    // panicking thread's exit wakes the loop that ends the VM, and it returns
    // the panic as the failure. A secondary the stop does not reach is left
    // running and named in the error, so the exact error is the check that the
    // stop reached it. Ignored by default: it needs a usable `/dev/kvm`, and
    // `boot` takes the terminal into raw mode and reads stdin for the guest, so
    // it runs on its own, by name, with `--ignored`.
    #[test]
    #[ignore]
    fn plugin_panic_on_the_boot_vcpu_ends_the_vm() {
        assert!(Kvm::new().is_ok(), "/dev/kvm is not usable");
        let plugin = Arc::new(PanicAtSafepoint {
            reached: AtomicBool::new(false),
        });
        let (sender, receiver) = mpsc::channel();
        let booted = Arc::clone(&plugin);
        std::thread::spawn(move || {
            let outcome = crate::boot(config(kernel(), Some(booted))).map_err(|e| e.to_string());
            let _ = sender.send(outcome);
        });
        let outcome = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("boot returns once the boot vCPU's plugin panicked");
        assert!(
            plugin.reached.load(Ordering::SeqCst),
            "the boot vCPU never reached the plugin"
        );
        let error = outcome.expect_err("boot reported a stop for a panic");
        assert_eq!(error, "vcpu0: panicked (plugin failure under test)");
    }

    // A secondary's `KVM_RUN` fails while the boot vCPU is in a guest that
    // never exits, so `boot` returns only if the secondary's exit wakes the
    // loop that ends the VM, and it returns the failed run as the failure, with
    // no vCPU named as left running. The test causes the failure from outside
    // the VMM: it replaces the secondary's vCPU descriptor with `/dev/null`,
    // which refuses the next `KVM_RUN`. Ignored by default, as the test above
    // is.
    #[test]
    #[ignore]
    fn failed_run_on_a_secondary_ends_the_vm() {
        assert!(Kvm::new().is_ok(), "/dev/kvm is not usable");
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let outcome = crate::boot(config(spinning_kernel(), None)).map_err(|e| e.to_string());
            let _ = sender.send(outcome);
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let secondary = loop {
            if let Some(id) = thread_id("vcpu1") {
                break id;
            }
            assert!(Instant::now() < deadline, "the secondary never started");
            std::thread::sleep(Duration::from_millis(1));
        };

        let null = File::open("/dev/null").unwrap();
        let descriptors = vcpu_descriptors(1);
        assert!(!descriptors.is_empty(), "the secondary has no descriptor");
        for descriptor in descriptors {
            // SAFETY: both descriptors are open. The vCPU handle still owns
            // `descriptor` and closes what it now refers to.
            let replaced = unsafe { libc::dup2(null.as_raw_fd(), descriptor) };
            assert_eq!(replaced, descriptor);
        }

        // The signal ends a run in progress. It is repeated, since one that
        // lands before the run starts is lost.
        let outcome = loop {
            // SAFETY: a signal to a thread of this process, for which `boot`
            // installed a handler that does nothing.
            unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), secondary, kick_signal()) };
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(outcome) => break outcome,
                Err(mpsc::RecvTimeoutError::Timeout) => assert!(
                    Instant::now() < deadline,
                    "boot did not return after the secondary's run failed"
                ),
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!("boot panicked"),
            }
        };
        let error = outcome.expect_err("boot reported a stop for a failed run");
        assert!(error.starts_with("vcpu1: KVM_RUN error"), "{error}");
        assert!(!error.contains("did not stop"), "{error}");
    }

    // The guest never exits, so only the request can end the run. Ignored by
    // default, as the tests above are.
    #[test]
    #[ignore]
    fn request_stops_a_guest_that_never_exits() {
        assert!(Kvm::new().is_ok(), "/dev/kvm is not usable");
        let run = crate::spawn(config(spinning_kernel(), None)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        run.request_stop();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !run.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(run.is_finished(), "the run ends once the stop is requested");
        let outcome = run.wait();
        assert!(
            matches!(outcome, Ok(Stop::Requested)),
            "the run returned {outcome:?}"
        );
    }

    // The boot vCPU waits in its plugin's `safepoint` when the stop is
    // requested. The plugin has to see the stop and return, or the stop leaves
    // the vCPU running and fails the run. Ignored by default, as the tests
    // above are.
    #[test]
    #[ignore]
    fn plugin_waiting_in_safepoint_sees_the_stop() {
        assert!(Kvm::new().is_ok(), "/dev/kvm is not usable");
        let plugin = Arc::new(WaitsInSafepoint {
            reached: AtomicBool::new(false),
        });
        let (stop, registration) = StopHandle::new_pair().unwrap();
        let mut cfg = config(
            spinning_kernel(),
            Some(Arc::clone(&plugin) as Arc<dyn Plugin>),
        );
        cfg.stop = Some(registration);
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(crate::boot(cfg).map_err(|e| e.to_string()));
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !plugin.reached.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "the boot vCPU never reached the plugin"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        stop.request_stop();
        let outcome = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("boot returns once the stop is requested");
        assert!(
            matches!(outcome, Ok(Stop::Requested)),
            "boot returned {outcome:?}"
        );
    }

    // The filter is checked only in a release build, where the filters are on.
    // Ignored by default, as the tests above are.
    #[test]
    #[ignore]
    fn plugin_thread_is_filtered_and_ends_with_the_run() {
        assert!(Kvm::new().is_ok(), "/dev/kvm is not usable");
        let plugin = Arc::new(SpawnsAThread {
            panics: false,
            ended: Arc::new(AtomicBool::new(false)),
        });
        let (stop, registration) = StopHandle::new_pair().unwrap();
        let mut cfg = config(
            spinning_kernel(),
            Some(Arc::clone(&plugin) as Arc<dyn Plugin>),
        );
        cfg.stop = Some(registration);
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(crate::boot(cfg).map_err(|e| e.to_string()));
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let thread = loop {
            if let Some(id) = thread_id("plugin-wait") {
                break id;
            }
            assert!(Instant::now() < deadline, "the plugin thread never started");
            std::thread::sleep(Duration::from_millis(1));
        };
        // The thread is named before its first instruction installs the filter,
        // so the mode is read until it changes or a deadline passes.
        if !cfg!(debug_assertions) {
            let filtered = Instant::now() + Duration::from_secs(2);
            while seccomp_mode(thread).as_deref() != Some("2") {
                assert!(Instant::now() < filtered, "the plugin thread is unfiltered");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        stop.request_stop();
        let outcome = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("boot returns once the stop is requested");
        assert!(
            matches!(outcome, Ok(Stop::Requested)),
            "boot returned {outcome:?}"
        );
        assert!(
            plugin.ended.load(Ordering::SeqCst),
            "boot returned before the plugin thread ended"
        );
    }

    // The run fails as it does for a vCPU that panics. Ignored by default, as
    // the tests above are.
    #[test]
    #[ignore]
    fn plugin_thread_panic_fails_the_run() {
        assert!(Kvm::new().is_ok(), "/dev/kvm is not usable");
        let plugin = Arc::new(SpawnsAThread {
            panics: true,
            ended: Arc::new(AtomicBool::new(false)),
        });
        let cfg = config(spinning_kernel(), Some(plugin as Arc<dyn Plugin>));
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(crate::boot(cfg).map_err(|e| e.to_string()));
        });
        let outcome = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("boot returns once the plugin thread panicked");
        let error = outcome.expect_err("boot reported a stop for a panic");
        assert_eq!(error, "plugin-wait: panicked");
    }

    // Ignored by default, as the tests above are.
    #[test]
    #[ignore]
    fn ledger_records_the_start_each_vcpu_and_the_stop() {
        assert!(Kvm::new().is_ok(), "/dev/kvm is not usable");
        let path =
            std::env::temp_dir().join(format!("hvi-lifecycle-{}.ndjson", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let (stop, registration) = StopHandle::new_pair().unwrap();
        let mut cfg = config(spinning_kernel(), None);
        cfg.events = Some(path.to_str().unwrap().to_string());
        cfg.stop = Some(registration);
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(crate::boot(cfg).map_err(|e| e.to_string()));
        });
        std::thread::sleep(Duration::from_millis(100));
        stop.request_stop();
        let outcome = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("boot returns once the stop is requested");
        assert!(
            matches!(outcome, Ok(Stop::Requested)),
            "boot returned {outcome:?}"
        );

        let records: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .filter(|record: &serde_json::Value| record["provenance"] == "vmm")
            .collect();
        std::fs::remove_file(&path).unwrap();
        let sources: Vec<&str> = records
            .iter()
            .map(|r| r["source"].as_str().unwrap())
            .collect();
        assert_eq!(
            sources,
            [
                "vmm.start",
                "vmm.vcpu_started",
                "vmm.vcpu_started",
                "vmm.stop"
            ],
            "{records:?}"
        );
        assert_eq!(records[0]["payload"]["vcpus"], 2);
        assert_eq!(records[0]["payload"]["mem_bytes"], 128 << 20);
        let mut started: Vec<u64> = records[1..3]
            .iter()
            .map(|r| r["payload"]["vcpu"].as_u64().unwrap())
            .collect();
        started.sort_unstable();
        assert_eq!(started, [0, 1]);
        assert_eq!(records[3]["payload"]["reason"], "requested");
    }

    // Ignored by default, as it needs a usable `/dev/kvm`.
    #[test]
    #[ignore]
    fn kick_before_the_run_ends_it_at_once() {
        let kvm = Kvm::new().expect("/dev/kvm is not usable");
        let vm = kvm.create_vm().unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        #[cfg(target_arch = "aarch64")]
        {
            let mut kvi = kvm_bindings::kvm_vcpu_init::default();
            vm.get_preferred_target(&mut kvi).unwrap();
            vcpu.vcpu_init(&kvi).unwrap();
        }
        install_kick_handler();
        let kicker = Kicker::new(1);
        let _registration = kicker.register(0, kick_handle(&vm, &vcpu).unwrap());
        // Kicked from another thread, as a kick to itself is dropped. The
        // signal lands here before the run starts, the case a signal alone
        // loses.
        std::thread::scope(|scope| {
            scope.spawn(|| kicker.kick(0));
        });
        let error = vcpu.run().expect_err("the run went ahead after the kick");
        assert_eq!(error.errno(), libc::EINTR);
        immediate_exit(&mut vcpu).store(0, Ordering::SeqCst);
        let mut threads = lock_or_recover(&kicker.threads);
        let registered = threads[0].as_mut().expect("the thread is registered");
        assert_eq!(
            immediate_exit(&mut registered.vcpu).load(Ordering::SeqCst),
            0
        );
    }
}

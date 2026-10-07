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

use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use kvm_ioctls::{VcpuFd, VmFd};

use crate::config::{BootConfig, Stop};
use crate::devices::irq::IrqLine;
use crate::devices::virtio::vsock::VsockBridge;
use crate::hypervisor::guest::{Cpu, Guest};
use crate::hypervisor::vcpus::Kick;
use crate::io_threads::{IoThreads, NetSource};
use crate::plugin::{Plugin, VmHandle};
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
/// before the first I/O or vCPU thread exists. The agent socket and the stop
/// source's socket pair are created before any filter goes in, since the
/// allowlists allow accepting on a listener already held but not creating one.
/// Then the I/O threads start, each filtering itself as it begins.
///
/// # Errors
///
/// Errors if the plugin refuses the guest, a filter does not compile, the agent
/// socket cannot be bound or the stop source cannot be created.
pub(crate) fn start_io_threads(
    cfg: &BootConfig,
    guest: &Arc<Guest<Kicker>>,
    deliver: impl FnMut(u8) + Send + 'static,
    net: Option<NetSource>,
) -> Result<(seccomp::Filters, IoThreads), Box<dyn std::error::Error>> {
    if let Some(plugin) = &cfg.plugin {
        plugin.attach(Arc::clone(guest) as Arc<dyn VmHandle>)?;
    }
    let filters = seccomp::Filters::arm(cfg.sandbox)?;
    let bridge = match (&cfg.agent_sock, &guest.vsock) {
        (Some(path), Some(dev)) => Some(VsockBridge::bind(
            path,
            Arc::clone(dev),
            Arc::clone(&guest.ram),
        )?),
        _ => None,
    };
    let source = StopSource::new()?;
    let io_threads = IoThreads::start(source, guest, cfg.plugin.clone(), deliver, bridge, net);
    Ok((filters, io_threads))
}

/// Runs the guest on one thread per vCPU and returns how it asked to stop.
///
/// Each vCPU thread runs `run` with its id, its vCPU, its kick handle and a
/// clone of `shared`. Once they exist the calling thread installs its own
/// filter, and once they have exited it stops `io_threads` and writes out the
/// ledger tail. The terminal stays in raw mode until this returns.
///
/// # Errors
///
/// Errors if a vCPU thread cannot be spawned, the calling thread cannot be
/// filtered or an I/O thread does not stop. Each failure stops the guest, and
/// the first one is returned once every thread has been joined or left running.
pub(crate) fn run_guest<S: Clone + Send + 'static>(
    guest: &Guest<Kicker>,
    shared: &S,
    vcpus: Vec<VcpuFd>,
    kick_handles: Vec<VcpuFd>,
    run: fn(u32, VcpuFd, VcpuFd, S),
    filters: seccomp::Filters,
    io_threads: IoThreads,
) -> Result<Stop, Box<dyn std::error::Error>> {
    let _raw = terminal::RawTerm::enable();

    let (threads, spawned) = guest.vcpus.spawn(
        vcpus
            .into_iter()
            .zip(kick_handles)
            .map(|(vcpu, kick_handle)| (vcpu, kick_handle, shared.clone(), run)),
        |id, (vcpu, kick_handle, shared, run)| run(id, vcpu, kick_handle, shared),
    );
    let mut failure: Option<Box<dyn std::error::Error>> = spawned.err().map(Into::into);

    // The guest is already running by now, so a failure to filter the main
    // thread stops it like any other failure.
    if let Err(e) = filters.install() {
        // The error is printed here, since a spawn failure ahead of it is the
        // one returned.
        eprintln!("{LOG_PREFIX} {e}");
        failure.get_or_insert(e.into());
        guest.vcpus.stop();
    }

    threads.join();

    // The guest has stopped. End the I/O threads (see `teardown`) and write out
    // the ledger tail, which the flush cadence alone would leave in the buffer.
    if let Err(e) = io_threads.stop() {
        failure.get_or_insert(e.into());
    }
    lock_or_recover(&guest.ledger).flush();
    if let Some(e) = failure {
        return Err(e);
    }

    Ok(guest.vcpus.stop_reason())
}

/// Runs vCPU `cpu` on the calling thread until the VM stops.
///
/// Each pass clears the vCPU's `immediate_exit` byte, checks the running flag,
/// parks at the quiesce checkpoint, lets `plugin` look at the guest from the
/// boot vCPU, and then calls `run`. `run` enters the guest once, services the
/// exit, and returns `false` to end the loop. Every way out of the loop ends
/// the VM, a panic included.
pub(crate) fn run_vcpu(
    cpu: u32,
    mut vcpu: VcpuFd,
    kick_handle: VcpuFd,
    guest: &Guest<Kicker>,
    plugin: Option<&dyn Plugin>,
    mut run: impl FnMut(&mut VcpuFd) -> bool,
) {
    // The vCPU filter goes in before this thread touches anything the guest
    // controls. MMIO exits are serviced on this thread, so the virtio device
    // models, which parse guest descriptors, run under it.
    seccomp::install_thread(seccomp::Thread::Vcpu);
    // The guard lives for the whole run, so every way out ends the VM. A
    // secondary that ended alone would leave the VM running with one vCPU fewer
    // and the join in `run_guest` blocked. It is declared before the
    // registration, so the registration drops first and the entry is gone
    // before the stop kicks.
    let _stop = guest.vcpus.stop_on_drop();
    let _registration = guest.vcpus.kicker().register(cpu, kick_handle);
    // Every KVM vCPU enters `KVM_RUN` at once. One the guest has not brought up
    // yet waits inside the run, where a kick reaches it.
    guest.vcpus.mark_started();
    let is_boot = cpu == 0;

    loop {
        // The byte is cleared before the running flag is read, so a kick that
        // lands from here on ends the run below at once.
        immediate_exit(&mut vcpu).store(0, Ordering::SeqCst);
        if !guest.vcpus.is_running() {
            break;
        }
        // Safe point for every vCPU: park here while cpu0 lets a plugin look at
        // the guest.
        guest.vcpus.checkpoint();
        // The plugin runs on cpu0, between guest entries, because only this
        // thread can read this vCPU's registers. It is on the hot path: with no
        // plugin this is a null check.
        if is_boot {
            if let Some(plugin) = plugin {
                plugin.safepoint(&Cpu { vcpu: &vcpu, guest });
            }
        }
        if !run(&mut vcpu) {
            break;
        }
    }
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
    use crate::plugin::CpuHandle;
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
            disk: None,
            fs_shares: Vec::new(),
            net: false,
            net_gateway: None,
            net_tap: None,
            net_mac: None,
            events: None,
            sandbox_id: "stop-test".to_string(),
            vcpus: 2,
            agent_sock: None,
            plugin,
            sandbox: !cfg!(debug_assertions),
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
    // panicking thread ends the VM on its way out; a secondary left running
    // keeps the join in `run_guest` blocked, so the bound is the assertion.
    // Ignored by default: it needs a usable `/dev/kvm`, and `boot` takes the
    // terminal into raw mode and reads stdin for the guest, so it runs on its
    // own, by name, with `--ignored`.
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
        // `boot` has to have run to the end and returned a stop, whichever stop
        // it reports.
        assert!(outcome.is_ok(), "boot failed before the stop: {outcome:?}");
    }

    // A secondary's `KVM_RUN` fails while the boot vCPU is in a guest that
    // never exits, so `boot` returns only if the secondary's exit ends the VM.
    // The test causes the failure from outside the VMM: it replaces the
    // secondary's vCPU descriptor with `/dev/null`, which refuses the next
    // `KVM_RUN`. Ignored by default, as the test above is.
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
            if let Some(id) = thread_id("cpu1") {
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
        assert!(outcome.is_ok(), "boot failed before the stop: {outcome:?}");
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

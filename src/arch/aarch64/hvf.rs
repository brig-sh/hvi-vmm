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

//! The arm64 guest on Hypervisor.framework, SMP-capable.
//!
//! One thread per vCPU (an `applevisor::Vcpu` is thread-bound). cpu0 boots at
//! the kernel entry; secondaries park until the guest brings them up via PSCI
//! `CPU_ON`. Guest RAM is a `GuestRam` shared by every vCPU thread; devices,
//! the event emitter, and the vCPU-handle list are shared behind locks. A
//! plugin, if the caller supplied one, is called on cpu0 between guest
//! entries — see [`crate::plugin`].
//!
//! The exit-loop's timer/WFI/PC handling and the SMP hand-off are the
//! boot-debug frontier.

// Resolved once while the VM is built, before any guest request; see
// clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::os::fd::{AsFd, BorrowedFd};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use applevisor::prelude::{
    ExitReason, GicConfig, GicEnabled, Reg, SysReg, Vcpu, VcpuHandle, VirtualMachine,
    VirtualMachineConfig, VirtualMachineInstance,
};

use crate::arch::aarch64::esr::{DataAbort, Ec};
use crate::arch::aarch64::fdt;
use crate::arch::aarch64::layout::{
    virtio_fs_base, virtio_fs_spi, GicLayout, GicVersion, DEVICE_WINDOW_END, RAM_BASE, UART_BASE,
    UART_SIZE, UART_SPI, VIRTIO_BASE, VIRTIO_NET_BASE, VIRTIO_NET_SPI, VIRTIO_SIZE, VIRTIO_SPI,
    VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_SPI,
};
use crate::arch::aarch64::loader;
use crate::config::{check_export_overlap, BootConfig, Stop};
use crate::devices::legacy::pl011::Pl011;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::fs::fdlimit;
use crate::devices::virtio::fs::server::{self, VirtioFs};
use crate::devices::virtio::mmio;
use crate::devices::virtio::net::{self, GatewayRelay, VirtioNet};
use crate::devices::virtio::vsock::{self, VirtioVsock};
use crate::events::Emitter;
use crate::hypervisor::vcpus::{Kick, Vcpus};
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::{CpuHandle, GuestArch, IoSink, Plugin, RamRegion, RegsView, VmHandle};
use crate::sandbox::seatbelt;
use crate::signal::install_kick_handler;
use crate::sync::lock_or_recover;
use crate::teardown::{join_by, kick_until_finished, StopSource, StopToken, STOP_TIMEOUT};
use crate::terminal;
use crate::LOG_PREFIX;
use vm_memory::{Address, GuestMemoryBackend, GuestMemoryRegion};

/// The VM handle once the GICv3 is configured (Send/Sync; cloned per thread).
type VmGic = VirtualMachineInstance<GicEnabled>;

/// GIC INTIDs: SPIs start at 32.
const UART_INTID: u32 = 32 + UART_SPI;
const VIRTIO_INTID: u32 = 32 + VIRTIO_SPI;
const VIRTIO_NET_INTID: u32 = 32 + VIRTIO_NET_SPI;
const VIRTIO_VSOCK_INTID: u32 = 32 + VIRTIO_VSOCK_SPI;

/// PSCI function IDs (SMC64/HVC calling convention) we recognise.
mod psci {
    pub const VERSION: u64 = 0x8400_0000;
    pub const CPU_OFF: u64 = 0x8400_0002;
    pub const SYSTEM_OFF: u64 = 0x8400_0008;
    pub const SYSTEM_RESET: u64 = 0x8400_0009;
    pub const FEATURES: u64 = 0x8400_000a;
    pub const CPU_ON_64: u64 = 0xc400_0003;
    pub const SUCCESS: u64 = 0;
    pub const NOT_SUPPORTED: u64 = (-1i64) as u64;
}

/// A secondary vCPU's start mailbox, filled by a PSCI `CPU_ON`.
struct Secondary {
    mbox: Mutex<Option<(u64, u64)>>, // (entry point, context id)
    cv: Condvar,
}

/// The [`Kick`] implementation for Hypervisor.framework vCPUs.
///
/// It holds each vCPU's handle and the secondaries' `CPU_ON` mailboxes. A kick
/// is `hv_vcpus_exit`. It ends a run in progress, and one that reaches a vCPU
/// outside its run stays pending and ends its next run at once. A secondary
/// that waits for `CPU_ON` is in no run, so the stop also wakes its mailbox.
struct Kicker {
    /// The VM the vCPUs belong to.
    vm: VmGic,
    /// Each vCPU's handle indexed by vCPU id, `None` until its thread has
    /// created the vCPU.
    handles: Mutex<Vec<Option<VcpuHandle>>>,
    /// The `CPU_ON` mailboxes of the secondaries.
    secondaries: Vec<Secondary>,
}

impl Kicker {
    /// Returns a table for `count` vCPUs of `vm`, none of them registered.
    fn new(vm: VmGic, count: u32, secondaries: Vec<Secondary>) -> Self {
        Self {
            vm,
            handles: Mutex::new((0..count).map(|_| None).collect()),
            secondaries,
        }
    }

    /// Registers `vcpu`, which the calling thread created, as vCPU `cpu`.
    ///
    /// It also records the vCPU as the calling thread's own, so a kick from
    /// this thread leaves it out.
    fn register(&self, cpu: u32, vcpu: &Vcpu) {
        OWN_VCPU.with(|own| own.set(Some(vcpu.id())));
        if let Some(slot) = lock_or_recover(&self.handles).get_mut(cpu as usize) {
            *slot = Some(vcpu.get_handle());
        }
    }
}

impl Kick for Kicker {
    fn kick_all(&self) {
        // A cancel a vCPU sends itself stays pending and ends its next run
        // before the guest ran, so a plugin that kicked from `safepoint` would
        // run again at once.
        let own = OWN_VCPU.with(std::cell::Cell::get);
        let others: Vec<VcpuHandle> = lock_or_recover(&self.handles)
            .iter()
            .flatten()
            .filter(|handle| Some(handle.id()) != own)
            .cloned()
            .collect();
        let _ = self.vm.vcpus_exit(&others);
    }

    fn kick_halted(&self) {
        for sec in self.secondaries.iter() {
            // The lock is taken so a secondary cannot be between its check of
            // the running flag and its wait when the notify lands.
            let _mbox = lock_or_recover(&sec.mbox);
            sec.cv.notify_all();
        }
    }
}

/// One tagged virtio-fs export, its dynamically assigned transport slot, and
/// the wake signal its dedicated worker thread (`spawn_fs_worker`) parks on.
#[derive(Clone)]
struct SharedFs {
    base: u64,
    intid: u32,
    dev: Arc<Mutex<VirtioFs>>,
    wake: Arc<FsWake>,
}

/// A virtio-fs device's coalescing wake signal (Stage A: one dedicated
/// worker thread per device, off the vCPU's exit path). `service_fs` calls
/// [`FsWake::wake`] unconditionally on every `QUEUE_NOTIFY`, whether or not
/// the worker looks idle; the worker's [`FsWake::park`] is the standard
/// predicate-plus-`Condvar` pattern, so a notify landing between the
/// worker's post-drain recheck and it actually parking is observed rather
/// than lost -- see `spawn_fs_worker` for the full argument.
struct FsWake {
    state: Mutex<FsWakeState>,
    ready: Condvar,
}

/// The flags behind [`FsWake`].
#[derive(Default)]
struct FsWakeState {
    /// A notify arrived since the worker last drained.
    woken: bool,
    /// The stop has been requested.
    stopped: bool,
}

impl FsWake {
    fn new() -> Self {
        Self {
            state: Mutex::new(FsWakeState::default()),
            ready: Condvar::new(),
        }
    }

    /// Signals the worker. Safe to call whether or not it is currently
    /// parked -- a signal that arrives mid-drain is simply picked up on the
    /// worker's next pass, never lost.
    fn wake(&self) {
        let mut state = lock_or_recover(&self.state);
        state.woken = true;
        self.ready.notify_one();
    }

    /// Requests that the worker exit at its next pass.
    fn stop(&self) {
        let mut state = lock_or_recover(&self.state);
        state.stopped = true;
        self.ready.notify_one();
    }

    /// Blocks until the next [`FsWake::wake`] or [`FsWake::stop`].
    ///
    /// Clears the wake flag on return and returns `false` once stopped. Must
    /// not be called with the virtio-fs device mutex held.
    fn park(&self) -> bool {
        let mut state = lock_or_recover(&self.state);
        while !state.woken && !state.stopped {
            state = self.ready.wait(state).unwrap();
        }
        state.woken = false;
        !state.stopped
    }
}

/// How many virtio-fs chains a vCPU services in its own exit before handing
/// the rest to the device's worker thread. Chosen so a single guest syscall's
/// worth of requests never pays a thread handoff, while a guest that has
/// queued deeply still gets serviced off the vCPU.
const FS_INLINE_BUDGET: u16 = 8;

/// State shared across all vCPU threads.
#[derive(Clone)]
struct Shared {
    vm: VmGic,
    mem: Arc<GuestRam>,
    pl011: Arc<Mutex<Pl011>>,
    virtio: Option<Arc<Mutex<VirtioBlk>>>,
    net: Option<Arc<Mutex<VirtioNet>>>,
    vsock: Option<Arc<Mutex<VirtioVsock>>>,
    fs: Vec<SharedFs>,
    emit: Arc<Mutex<Emitter>>,
    /// The vCPU threads, the stop and the quiesce that parks them.
    vcpus: Arc<Vcpus<Kicker>>,
    kernel_addr: u64,
    dtb_addr: u64,
    /// Whoever is watching this guest, if anyone.
    plugin: Option<Arc<dyn Plugin>>,
    /// The object backing guest RAM, for a plugin that hands the same pages to
    /// another process.
    ram_file: Arc<std::fs::File>,
    sandbox_id: String,
}

/// Boots `cfg` and runs until the guest powers off.
///
/// Every thread this call itself starts has exited when it returns, or the call
/// returns an error naming the one that did not stop within
/// [`crate::teardown::STOP_TIMEOUT`]. What remains of the VM is a `VmHandle` a
/// plugin kept, in a field or on a thread it started from `attach`.
pub fn boot(cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error>> {
    // Refuse a kernel that is not a flat Image before the VM, its RAM, the
    // devices and the event ledger exist.
    loader::LoadedKernel::from_header(&cfg.kernel)?;
    // And exports that contradict each other, for the same reason: this is a
    // statement about the configuration, decidable before anything is built.
    check_export_overlap(&cfg.fs_shares)?;
    let num_cpus = cfg.vcpus.max(1);

    // In-kernel GICv3; sizes from the framework so the DTB matches hv_gic.
    let gicd_align = GicConfig::get_distributor_base_alignment()? as u64;
    let gicr_align = GicConfig::get_redistributor_base_alignment()? as u64;
    let gic = GicLayout {
        // Apple's hv_gic is a GICv3; unlike KVM there is nothing to negotiate.
        version: GicVersion::V3,
        gicd_base: align_down(GicLayout::QEMU_VIRT.gicd_base, gicd_align),
        gicd_size: GicConfig::get_distributor_size()? as u64,
        gicr_base: align_down(GicLayout::QEMU_VIRT.gicr_base, gicr_align),
        gicr_size: GicConfig::get_redistributor_region_size()? as u64,
    };
    eprintln!(
        "{LOG_PREFIX} {num_cpus} vCPU(s)  GICD {:#x}+{:#x}  GICR {:#x}+{:#x}  UART {:#x}",
        gic.gicd_base, gic.gicd_size, gic.gicr_base, gic.gicr_size, UART_BASE
    );
    // Every device window has to clear the GIC, and only here is it known how
    // much GIC there is: the framework sizes the redistributor region, and it
    // is far larger than QEMU's. The fixed windows are checked once, the
    // virtio-fs ones again below as each share is placed, because those climb
    // with the share count.
    let gic_end = gic.gicr_base.saturating_add(gic.gicr_size);
    for (name, base, size) in [
        ("UART", UART_BASE, UART_SIZE),
        ("virtio-blk", VIRTIO_BASE, VIRTIO_SIZE),
        ("virtio-net", VIRTIO_NET_BASE, VIRTIO_SIZE),
        ("virtio-vsock", VIRTIO_VSOCK_BASE, VIRTIO_SIZE),
    ] {
        let end = base.saturating_add(size);
        if base < gic_end || end > DEVICE_WINDOW_END {
            return Err(format!(
                "{name} at {base:#x}..{end:#x} does not fit between the GIC \
                 (ends {gic_end:#x}) and {DEVICE_WINDOW_END:#x}"
            )
            .into());
        }
    }

    let mut gic_config = GicConfig::new();
    gic_config.set_distributor_base(gic.gicd_base)?;
    gic_config.set_redistributor_base(gic.gicr_base)?;
    let vm = VirtualMachine::with_gic(VirtualMachineConfig::new(), gic_config)?;

    // Guest RAM: one region mapped at RAM_BASE, backed by a shareable object
    // rather than allocated by applevisor, so an out-of-process plugin can
    // map the same pages. applevisor's memory_create uses hv_vm_allocate,
    // which hands back a pointer with no nameable backing object; hv_vm_map
    // accepts any page-aligned host pointer, so the guest gets the mapping
    // `GuestRam` made of the object. This is the path `hvi smoke --shm`
    // exercises.
    let shared_ram = SharedRam::new(cfg.mem_bytes as usize)?;
    let ram = Arc::new(GuestRam::new(
        &shared_ram,
        &[shared_ram.region_at(RAM_BASE)],
    )?);
    for region in ram.memory().iter() {
        let ipa = region.start_addr().raw_value();
        // SAFETY: the region is a live, page-aligned mapping of `len()` bytes
        // that lives as long as `ram`, which outlives the VM.
        let ret = unsafe {
            applevisor_sys::hv_vm_map(
                region.as_ptr().cast::<std::ffi::c_void>(),
                ipa,
                region.len() as usize,
                applevisor_sys::HV_MEMORY_READ
                    | applevisor_sys::HV_MEMORY_WRITE
                    | applevisor_sys::HV_MEMORY_EXEC,
            )
        };
        if ret != 0 {
            return Err(format!("hv_vm_map(guest RAM -> {ipa:#x}) failed: {ret:#x}").into());
        }
    }

    let virtio = match &cfg.disk {
        Some(path) => {
            eprintln!("{LOG_PREFIX} virtio-blk: {path}");
            Some(Arc::new(Mutex::new(VirtioBlk::open(path)?)))
        }
        None => None,
    };
    // virtio-net: gateway relay (real egress) when a gateway socket is given,
    // else the built-in user-space stack. `net_reader` carries the gateway read
    // side to the RX reader thread, spawned once the shared state exists.
    //
    // Tap attach needs /dev/net/tun, which macOS does not have. Refusing beats
    // silently booting on another backend: a guest on the wrong network is
    // indistinguishable from success from the outside.
    if let Some(ifname) = &cfg.net_tap {
        return Err(
            format!("--net-tap {ifname}: no /dev/net/tun on macOS; use --net-gateway").into(),
        );
    }
    let mut net_reader: Option<std::os::unix::net::UnixStream> = None;
    let net_dev = if let Some(sock) = &cfg.net_gateway {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(stream) => match stream.try_clone() {
                Ok(reader) => {
                    eprintln!("{LOG_PREFIX} virtio-net: gvisor-tap gateway relay via {sock} (guest 10.87.0.2, gw/DNS 10.87.0.1)");
                    net_reader = Some(reader);
                    Some(VirtioNet::with_gateway(stream))
                }
                Err(e) => {
                    eprintln!(
                        "{LOG_PREFIX} WARNING: cannot clone gateway socket ({e}); net disabled"
                    );
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "{LOG_PREFIX} WARNING: gateway {sock} unreachable ({e}); falling back to the {}",
                    net::stub_stack_line()
                );
                Some(VirtioNet::new())
            }
        }
    } else if cfg.net {
        eprintln!("{LOG_PREFIX} virtio-net: {}", net::stub_stack_line());
        Some(VirtioNet::new())
    } else {
        None
    };

    let net = net::share(net_dev, cfg.net_mac);

    let vsock = cfg.agent_sock.as_ref().map(|sock| {
        eprintln!("{LOG_PREFIX} virtio-vsock: agent bridge on {sock} (guest cid 3, port 1024)");
        Arc::new(Mutex::new(VirtioVsock::new()))
    });
    // Bind before Seatbelt is installed. Accepting on this already-open
    // listener remains allowed afterwards; acquiring a new socket does not.
    // It is non-blocking so the bridge can poll it beside the stop token.
    let agent_listener = match &cfg.agent_sock {
        Some(path) => {
            let _ = std::fs::remove_file(path);
            let listener = std::os::unix::net::UnixListener::bind(path)
                .map_err(|e| format!("bind agent socket {path}: {e}"))?;
            listener.set_nonblocking(true)?;
            Some(listener)
        }
        None => None,
    };
    // The stop source's socket pair is created before Seatbelt for the same
    // reason.
    let stop_source = StopSource::new()?;
    let mut fs = Vec::with_capacity(cfg.fs_shares.len());
    let mut fs_access = Vec::with_capacity(cfg.fs_shares.len());
    let mut fs_tags = std::collections::HashSet::new();
    for (index, share) in cfg.fs_shares.iter().enumerate() {
        if !fs_tags.insert(share.tag.as_str()) {
            return Err(format!("duplicate virtio-fs tag {:?}", share.tag).into());
        }
        let base = virtio_fs_base(index).ok_or("too many virtio-fs devices")?;
        let spi = virtio_fs_spi(index).ok_or("too many virtio-fs devices")?;
        let end = base
            .checked_add(VIRTIO_SIZE)
            .ok_or("virtio-fs MMIO address overflow")?;
        // Same two bounds as the fixed windows above; these move with the
        // share count, so they are checked per share.
        if base < gic_end || end > DEVICE_WINDOW_END {
            return Err(format!(
                "virtio-fs device {index} at {base:#x}..{end:#x} does not fit \
                 between the GIC (ends {gic_end:#x}) and {DEVICE_WINDOW_END:#x}"
            )
            .into());
        }
        let root = std::fs::canonicalize(&share.path)?;
        let access = if share.mode.writable() {
            "read-write"
        } else {
            "read-only"
        };
        // Raise the descriptor limit before the first share exists, and say
        // what we got.
        //
        // virtio-fs pins one host fd per open guest handle, so the guest's
        // concurrency is spent out of this process's table. macOS gives a
        // process launched outside a terminal 256, which a build inside the
        // guest exhausts without trying -- and what the guest then saw was
        // "Input/output error" on random unrelated files, because every
        // unmapped host errno was reported as EIO.
        //
        // Logging the number is deliberate and unconditional: diagnosing this
        // from the guest side took a session of guessing, and one line here
        // would have ended it in a single run.
        if index == 0 {
            match fdlimit::raise_open_file_limit() {
                Ok(limit) => eprintln!("{LOG_PREFIX} open-file limit: {limit}"),
                Err(e) => eprintln!(
                    "{LOG_PREFIX} open-file limit: could not raise it ({e}); \
                     a busy guest may see EMFILE as I/O errors"
                ),
            }
        }
        eprintln!(
            "{LOG_PREFIX} virtio-fs[{index}]: {} as {:?} ({access})",
            root.display(),
            share.tag
        );
        fs_access.push((root.clone(), share.mode.writable()));
        fs.push(SharedFs {
            base,
            intid: 32 + spi,
            dev: Arc::new(Mutex::new(VirtioFs::new(
                root,
                &share.tag,
                share.mode.writable(),
                share.cache,
            )?)),
            wake: Arc::new(FsWake::new()),
        });
    }
    let has_blk = virtio.is_some();
    let has_net = net.is_some();
    let has_vsock = vsock.is_some();
    let fdt_devices = fdt::VirtioDevices {
        blk: has_blk,
        net: has_net,
        vsock: has_vsock,
        fs_count: fs.len(),
    };

    let emitter = Emitter::new(cfg.events.as_deref(), &cfg.sandbox_id)?;
    if emitter.enabled() {
        eprintln!(
            "{LOG_PREFIX} event ledger: {}",
            cfg.events.as_deref().unwrap_or("")
        );
    }

    let layout = loader::Payload {
        kernel: &cfg.kernel,
        initramfs: cfg.initramfs.as_deref(),
        cmdline: &cfg.cmdline,
    }
    .load(ram.memory(), cfg.mem_bytes, &gic, num_cpus, fdt_devices)?;

    let secondaries: Vec<Secondary> = (0..num_cpus)
        .map(|_| Secondary {
            mbox: Mutex::new(None),
            cv: Condvar::new(),
        })
        .collect();
    let kicker = Kicker::new(vm.clone(), num_cpus, secondaries);

    let shared = Shared {
        vm: vm.clone(),
        mem: ram,
        pl011: Arc::new(Mutex::new(Pl011::new())),
        virtio,
        net,
        vsock,
        fs,
        emit: Arc::new(Mutex::new(emitter)),
        vcpus: Arc::new(Vcpus::new(num_cpus, kicker)),
        kernel_addr: layout.kernel_addr,
        dtb_addr: layout.dtb_addr,
        plugin: cfg.plugin.clone(),
        ram_file: Arc::clone(shared_ram.file()),
        sandbox_id: cfg.sandbox_id.clone(),
    };

    // Hand the plugin the guest before any vCPU runs, so nothing happens
    // between the first instruction and the attach.
    if let Some(obs) = &shared.plugin {
        obs.attach(Arc::new(shared.clone()) as Arc<dyn VmHandle>)?;
    }

    let _raw = terminal::RawTerm::enable();

    // Confine the process before the first helper thread exists. Everything
    // above acquires host authority (the VM, the guest-RAM mapping, the block
    // file, the ledger, the gateway connection, the listeners, the terminal),
    // and everything below only services guest I/O with what is already open.
    // An error here returns before there is a thread to stop. See
    // `sandbox::seatbelt`.
    //
    // Failing closed: a profile that will not install is a profile nobody has
    // tested, and continuing would hand a guest-facing process the host's full
    // ambient authority under a log line claiming it was sandboxed.
    if cfg.sandbox {
        seatbelt::enter_with_shares(&fs_access)
            .map_err(|e| format!("{e}; re-run with --no-sandbox to boot unconfined"))?;
        eprintln!("{LOG_PREFIX} seatbelt sandbox: on (deny default)");
    } else {
        eprintln!(
            "{LOG_PREFIX} seatbelt sandbox: OFF (--no-sandbox) — the VMM keeps full host authority"
        );
    }

    // Helper threads. Each polls its stop token beside its own descriptor, or
    // takes the stop through its `FsWake`, and is joined after the vCPUs.
    install_kick_handler();
    let input = {
        let kick = Arc::clone(&shared.vcpus);
        let (vm, pl011) = (vm.clone(), Arc::clone(&shared.pl011));
        terminal::input::spawn(
            shared.plugin.clone(),
            stop_source.token(),
            move || kick.kicker().kick_all(),
            move |byte| {
                let level = {
                    let mut p = lock_or_recover(&pl011);
                    p.push_rx(byte);
                    p.irq_level()
                };
                let _ = vm.gic_set_spi(UART_INTID, level);
            },
        )
    };
    let mut helpers: Vec<(&str, JoinHandle<()>)> = Vec::new();
    let mut readahead_stops = Vec::new();
    if let (Some(listener), Some(dev)) = (agent_listener, &shared.vsock) {
        helpers.push((
            "agent bridge",
            spawn_vsock_bridge(
                listener,
                Arc::clone(dev),
                Arc::clone(&shared.mem),
                vm.clone(),
                Arc::clone(&shared.vcpus),
                stop_source.token(),
            ),
        ));
    }
    if let (Some(reader), Some(dev)) = (net_reader, &shared.net) {
        helpers.push((
            "gateway relay",
            spawn_net_gateway_reader(
                reader,
                Arc::clone(dev),
                Arc::clone(&shared.mem),
                vm.clone(),
                Arc::clone(&shared.vcpus),
                stop_source.token(),
            ),
        ));
    }
    // Stage A: each virtio-fs device gets its own worker thread so FUSE
    // servicing (every host pread/pwrite/stat/getxattr the guest's requests
    // need) never runs on a vCPU thread. See `spawn_fs_worker`.
    for fs in &shared.fs {
        helpers.push((
            "virtio-fs worker",
            spawn_fs_worker(
                Arc::clone(&fs.dev),
                fs.intid,
                Arc::clone(&shared.mem),
                vm.clone(),
                Arc::clone(&shared.vcpus),
                Arc::clone(&fs.wake),
            ),
        ));
        let (workers, stop) = lock_or_recover(&fs.dev).start_readahead();
        helpers.extend(
            workers
                .into_iter()
                .map(|worker| ("virtio-fs readahead", worker)),
        );
        readahead_stops.push(stop);
    }

    // One thread per vCPU. From here on a failure stops the guest and is
    // reported once every thread has been joined or left running, and the first
    // failure is the one reported.
    let (threads, spawned) = shared
        .vcpus
        .spawn((0..num_cpus).map(|_| shared.clone()), run_cpu);
    let mut failure: Option<Box<dyn std::error::Error>> = spawned.err().map(Into::into);
    threads.join();

    // The guest has stopped. End the I/O threads (see `teardown`) and write out
    // the ledger tail, which the flush cadence alone would leave in the buffer.
    stop_source.request_stop();
    for fs in &shared.fs {
        fs.wake.stop();
    }
    for stop in &readahead_stops {
        stop.stop();
    }
    let deadline = std::time::Instant::now() + STOP_TIMEOUT;
    kick_until_finished(&input, deadline);
    for (name, thread) in std::iter::once(("console reader", input)).chain(helpers) {
        if let Err(e) = join_by(name, thread, deadline) {
            eprintln!("{LOG_PREFIX} {e}; left running");
            failure.get_or_insert(e.into());
        }
    }
    lock_or_recover(&shared.emit).flush();

    // What the guest actually spent, reported once on the way out. #34 asks
    // for this number before any limit is tightened: a ceiling picked without
    // knowing what a real build needs is a ceiling that breaks one.
    for (index, fs) in shared.fs.iter().enumerate() {
        let dev = fs.dev.lock();
        let dev = match dev {
            Ok(d) => d,
            Err(poisoned) => poisoned.into_inner(),
        };
        eprintln!(
            "{LOG_PREFIX} virtio-fs[{index}]: peak {} of {} guest handles",
            dev.peak_handles(),
            dev.handle_limit()
        );
        let hist: Vec<String> = dev
            .op_stats()
            .into_iter()
            .map(|(o, c, n)| {
                format!(
                    "{}({})={}/{:.1}ms",
                    server::opcode_name(o),
                    o,
                    c,
                    n as f64 / 1e6
                )
            })
            .collect();
        eprintln!("{LOG_PREFIX} virtio-fs[{index}] ops: {}", hist.join(" "));
        let (hits, waits, misses) = dev.readahead_stats();
        eprintln!(
            "{LOG_PREFIX} virtio-fs[{index}] readahead: hits={hits} waits={waits} misses={misses}"
        );
    }

    if let Some(e) = failure {
        return Err(e);
    }
    Ok(shared.vcpus.stop_reason())
}

thread_local! {
    /// The reason this thread's vCPU last left the guest.
    ///
    /// Recorded so the panic report in [`run_cpu`] can name it. `catch_unwind`
    /// runs on the thread that panicked, so a thread-local survives the unwind
    /// and is readable there, and it costs the other vCPU threads nothing.
    static LAST_EXIT: std::cell::Cell<Option<ExitReason>> =
        const { std::cell::Cell::new(None) };

    /// The handle id of this thread's vCPU, so a kick can leave it out.
    static OWN_VCPU: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// What this thread's vCPU last exited for, if it has run at all.
fn last_exit() -> Option<ExitReason> {
    LAST_EXIT.with(std::cell::Cell::get)
}

/// A single vCPU: create it, position it (boot entry, or wait for CPU_ON), and
/// run its exit loop until the VM stops.
fn run_cpu(cpu_id: u32, sh: Shared) {
    let vcpu = match sh.vm.vcpu_create() {
        Ok(v) => v,
        Err(e) => {
            // The secondaries would otherwise wait for a CPU_ON that cannot
            // arrive, and the join in `boot` with them.
            eprintln!("{LOG_PREFIX} cpu{cpu_id}: vcpu_create failed: {e:?}");
            sh.vcpus.stop();
            return;
        }
    };
    // Held for the rest of the run, so every way out ends the VM. A secondary
    // that ended alone would otherwise leave the VM running with one vCPU fewer
    // and the join in `boot` blocked. Declared after the vCPU so it drops
    // first: the VM is stopped while this vCPU still exists, and its
    // destruction is outside the stop.
    let _stop = sh.vcpus.stop_on_drop();
    let _ = vcpu.set_trap_debug_exceptions(false);
    let _ = vcpu.set_trap_debug_reg_accesses(false);
    // GICv3 affinity: aff0 = cpu id, RES1 bit 31 set.
    let _ = vcpu.set_sys_reg(SysReg::MPIDR_EL1, 0x8000_0000 | u64::from(cpu_id));
    sh.vcpus.kicker().register(cpu_id, &vcpu);

    if cpu_id == 0 {
        let _ = vcpu.set_reg(Reg::PC, sh.kernel_addr);
        let _ = vcpu.set_reg(Reg::X0, sh.dtb_addr);
        let _ = vcpu.set_reg(Reg::X1, 0);
        let _ = vcpu.set_reg(Reg::X2, 0);
        let _ = vcpu.set_reg(Reg::X3, 0);
        let _ = vcpu.set_reg(Reg::CPSR, 0x3c5); // EL1h, DAIF masked
    } else {
        // Park until the guest brings this cpu up via PSCI CPU_ON.
        let sec = &sh.vcpus.kicker().secondaries[cpu_id as usize];
        let mut mbox = sec.mbox.lock().unwrap();
        while mbox.is_none() && sh.vcpus.is_running() {
            mbox = sec.cv.wait(mbox).unwrap();
        }
        match mbox.take() {
            Some((entry, ctx)) => {
                drop(mbox);
                eprintln!("{LOG_PREFIX} cpu{cpu_id}: PSCI CPU_ON -> {entry:#x}");
                let _ = vcpu.set_reg(Reg::PC, entry);
                let _ = vcpu.set_reg(Reg::X0, ctx);
                let _ = vcpu.set_reg(Reg::CPSR, 0x3c5);
            }
            None => return, // stopped while waiting
        }
    }

    let is_boot = cpu_id == 0;
    // The loop runs inside `catch_unwind` only for the report. A panic is
    // reported with where the guest was and what it last did, and the guard
    // ends the VM on the way out.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        while sh.vcpus.is_running() {
            // Safe point for every vCPU: park here while cpu0 lets a plugin
            // look at the guest.
            sh.vcpus.checkpoint();
            // The plugin runs on cpu0, between guest entries, because only this
            // thread can read this vCPU's registers. It is on the hot path:
            // with no plugin this is a null check.
            if is_boot {
                if let Some(obs) = sh.plugin.clone() {
                    obs.safepoint(&Cpu {
                        vcpu: &vcpu,
                        sh: &sh,
                    });
                }
            }

            if let Err(e) = vcpu.run() {
                eprintln!("{LOG_PREFIX} cpu{cpu_id}: vcpu run failed: {e:?}");
                break;
            }
            let exit = vcpu.get_exit_info();
            LAST_EXIT.with(|last| last.set(Some(exit.reason)));
            match exit.reason {
                ExitReason::EXCEPTION => {
                    let syn = exit.exception.syndrome;
                    match Ec::from_syndrome(syn) {
                        Ec::Hvc | Ec::Smc => {
                            if service_psci(&vcpu, &sh) {
                                break; // SYSTEM_OFF/RESET
                            }
                            // Not restartable: the saved PC is already past
                            // HVC/SMC.
                        }
                        Ec::DataAbort => {
                            let ipa = exit.exception.physical_address;
                            if (UART_BASE..UART_BASE + UART_SIZE).contains(&ipa) {
                                service_uart(&vcpu, &sh, ipa - UART_BASE, syn);
                                advance_pc(&vcpu);
                            } else if (VIRTIO_BASE..VIRTIO_BASE + VIRTIO_SIZE).contains(&ipa) {
                                if let Some(dev) = &sh.virtio {
                                    service_dev(
                                        &vcpu,
                                        &sh,
                                        dev,
                                        VIRTIO_INTID,
                                        ipa - VIRTIO_BASE,
                                        syn,
                                    );
                                }
                                advance_pc(&vcpu);
                            } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE)
                                .contains(&ipa)
                            {
                                if let Some(dev) = &sh.net {
                                    service_net(&vcpu, &sh, dev, ipa - VIRTIO_NET_BASE, syn);
                                }
                                advance_pc(&vcpu);
                            } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE)
                                .contains(&ipa)
                            {
                                if let Some(dev) = &sh.vsock {
                                    service_vsock(&vcpu, &sh, dev, ipa - VIRTIO_VSOCK_BASE, syn);
                                }
                                advance_pc(&vcpu);
                            } else if let Some(fs) = sh
                                .fs
                                .iter()
                                .find(|fs| (fs.base..fs.base + VIRTIO_SIZE).contains(&ipa))
                            {
                                service_fs(&vcpu, &sh, fs, ipa - fs.base, syn);
                                advance_pc(&vcpu);
                            } else {
                                eprintln!(
                                    "{LOG_PREFIX} cpu{cpu_id}: unhandled MMIO at {ipa:#x} (pc {:#x})",
                                    vcpu.get_reg(Reg::PC).unwrap_or(0)
                                );
                                break;
                            }
                        }
                        Ec::SysReg => {
                            // RAZ/WI: unmodeled system register.
                            let iss = syn & 0x1ff_ffff;
                            if iss & 1 == 1 {
                                write_gpr(&vcpu, ((iss >> 5) & 0x1f) as u8, 0);
                            }
                            advance_pc(&vcpu);
                        }
                        Ec::Other(0x01) => {} // WFx: hvf handled the wait.
                        other => {
                            eprintln!(
                                "{LOG_PREFIX} cpu{cpu_id}: unhandled exception {other:?} (pc {:#x})",
                                vcpu.get_reg(Reg::PC).unwrap_or(0)
                            );
                            break;
                        }
                    }
                }
                ExitReason::VTIMER_ACTIVATED => {
                    let _ = vcpu.set_vtimer_mask(true);
                }
                ExitReason::CANCELED => {} // kicked for a snapshot or a stop
                ExitReason::UNKNOWN => {
                    // hvf could not say why it exited, so there is nothing to
                    // resume into.
                    eprintln!(
                        "{LOG_PREFIX} cpu{cpu_id}: unknown exit reason (pc {:#x})",
                        vcpu.get_reg(Reg::PC).unwrap_or(0)
                    );
                    break;
                }
            }
        }
    }));

    if let Err(payload) = outcome {
        // The report names where the guest was and what it last did, so it is
        // usable without a debugger. `payload` carries the panic message for
        // the two types a `panic!` produces.
        let what = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown payload".to_string());
        eprintln!(
            "{LOG_PREFIX} cpu{cpu_id}: panicked ({what}); last exit {:?}, pc {:#x}",
            last_exit(),
            vcpu.get_reg(Reg::PC).unwrap_or(0)
        );
    }
}

/// [`VmHandle`] over the shared VM state: what a plugin gets at attach time.
impl VmHandle for Shared {
    fn arch(&self) -> GuestArch {
        GuestArch::Aarch64
    }

    fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    fn ram(&self) -> &GuestRam {
        &self.mem
    }

    fn ram_fd(&self) -> BorrowedFd<'_> {
        self.ram_file.as_fd()
    }

    fn ram_regions(&self) -> Vec<RamRegion> {
        self.mem.regions()
    }

    fn ledger(&self) -> &Arc<Mutex<Emitter>> {
        &self.emit
    }

    fn has_block(&self) -> bool {
        self.virtio.is_some()
    }

    fn has_net(&self) -> bool {
        self.net.is_some()
    }

    fn set_block_sink(&self, sink: Arc<dyn IoSink>) {
        if let Some(dev) = &self.virtio {
            if let Ok(mut d) = dev.lock() {
                d.set_io_sink(sink);
            }
        }
    }

    fn set_net_sink(&self, sink: Arc<dyn IoSink>) {
        if let Some(dev) = &self.net {
            if let Ok(mut d) = dev.lock() {
                d.set_io_sink(sink);
            }
        }
    }

    fn kick(&self) {
        self.vcpus.kicker().kick_all();
    }
}

/// [`CpuHandle`] over the boot vCPU at a safe point. Borrows rather than
/// clones: it lives only for the duration of one [`Plugin::safepoint`] call.
struct Cpu<'a> {
    vcpu: &'a Vcpu,
    sh: &'a Shared,
}

impl CpuHandle for Cpu<'_> {
    fn arch(&self) -> GuestArch {
        GuestArch::Aarch64
    }

    fn ram(&self) -> &GuestRam {
        &self.sh.mem
    }

    fn regs(&self) -> RegsView {
        let ttbr1 = self.vcpu.get_sys_reg(SysReg::TTBR1_EL1).unwrap_or(0);
        RegsView {
            // arm64's kernel-half page-table base is the walk root.
            root: ttbr1,
            pc: self.vcpu.get_reg(Reg::PC).unwrap_or(0),
            cpsr: self.vcpu.get_reg(Reg::CPSR).unwrap_or(0),
            ttbr0: self.vcpu.get_sys_reg(SysReg::TTBR0_EL1).unwrap_or(0),
            ttbr1,
            sctlr: self.vcpu.get_sys_reg(SysReg::SCTLR_EL1).unwrap_or(0),
            sp_el1: self.vcpu.get_sys_reg(SysReg::SP_EL1).unwrap_or(0),
            tcr: self.vcpu.get_sys_reg(SysReg::TCR_EL1).unwrap_or(0),
            current_task: self.vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0),
        }
    }

    fn pause(&self) -> bool {
        self.sh.vcpus.pause()
    }

    fn resume(&self) {
        self.sh.vcpus.resume();
    }

    fn ledger(&self) -> &Arc<Mutex<Emitter>> {
        &self.sh.emit
    }
}

/// Handles a PSCI call. Returns `true` if the VM should stop
/// (SYSTEM_OFF/RESET).
fn service_psci(vcpu: &Vcpu, sh: &Shared) -> bool {
    let fid = vcpu.get_reg(Reg::X0).unwrap_or(0);
    match fid {
        psci::VERSION => {
            let _ = vcpu.set_reg(Reg::X0, 0x0001_0000); // v1.0
            false
        }
        psci::SYSTEM_OFF => {
            sh.vcpus.set_stop_reason(Stop::SystemOff);
            true
        }
        psci::SYSTEM_RESET => {
            sh.vcpus.set_stop_reason(Stop::SystemReset);
            true
        }
        psci::FEATURES => {
            let q = vcpu.get_reg(Reg::X1).unwrap_or(0);
            let known = matches!(
                q,
                psci::VERSION
                    | psci::SYSTEM_OFF
                    | psci::SYSTEM_RESET
                    | psci::FEATURES
                    | psci::CPU_ON_64
            );
            let _ = vcpu.set_reg(
                Reg::X0,
                if known {
                    psci::SUCCESS
                } else {
                    psci::NOT_SUPPORTED
                },
            );
            false
        }
        psci::CPU_ON_64 => {
            let target = vcpu.get_reg(Reg::X1).unwrap_or(0);
            let entry = vcpu.get_reg(Reg::X2).unwrap_or(0);
            let ctx = vcpu.get_reg(Reg::X3).unwrap_or(0);
            let idx = (target & 0xff) as usize; // aff0
            let secondaries = &sh.vcpus.kicker().secondaries;
            let ret = if idx != 0 && idx < secondaries.len() {
                let sec = &secondaries[idx];
                *sec.mbox.lock().unwrap() = Some((entry, ctx));
                sec.cv.notify_all();
                psci::SUCCESS
            } else {
                psci::NOT_SUPPORTED
            };
            let _ = vcpu.set_reg(Reg::X0, ret);
            false
        }
        psci::CPU_OFF => {
            let _ = vcpu.set_reg(Reg::X0, psci::SUCCESS);
            false
        }
        _ => {
            let _ = vcpu.set_reg(Reg::X0, psci::NOT_SUPPORTED);
            false
        }
    }
}

/// Services a PL011 MMIO access and drives its interrupt line.
fn service_uart(vcpu: &Vcpu, sh: &Shared, offset: u64, syndrome: u64) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    let level = {
        let mut p = lock_or_recover(&sh.pl011);
        if da.is_write {
            let v = read_gpr(vcpu, da.reg);
            p.mmio(offset, true, v);
        } else {
            let v = p.mmio(offset, false, 0) & width_mask(da.width);
            write_gpr(vcpu, da.reg, v);
        }
        p.irq_level()
    };
    let _ = sh.vm.gic_set_spi(UART_INTID, level);
}

/// Services a virtio-blk MMIO access, drains its captured events, and drives
/// its interrupt line.
fn service_dev(
    vcpu: &Vcpu,
    sh: &Shared,
    dev: &Arc<Mutex<VirtioBlk>>,
    intid: u32,
    offset: u64,
    syndrome: u64,
) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    let (level, events) = {
        let mut d = lock_or_recover(dev);
        if da.is_write {
            let v = read_gpr(vcpu, da.reg);
            d.mmio(&sh.mem, offset, true, v);
        } else {
            let v = d.mmio(&sh.mem, offset, false, 0) & width_mask(da.width);
            write_gpr(vcpu, da.reg, v);
        }
        (d.irq_level(), d.take_events())
    };
    if !events.is_empty() {
        let mut e = lock_or_recover(&sh.emit);
        for ev in &events {
            e.captured(ev);
        }
    }
    let _ = sh.vm.gic_set_spi(intid, level);
}

/// Services a virtio-net MMIO access (same shape as `service_dev`).
fn service_net(vcpu: &Vcpu, sh: &Shared, dev: &Arc<Mutex<VirtioNet>>, offset: u64, syndrome: u64) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    let (level, events) = {
        let mut d = lock_or_recover(dev);
        if da.is_write {
            let v = read_gpr(vcpu, da.reg);
            d.mmio(&sh.mem, offset, true, v);
        } else {
            let v = d.mmio(&sh.mem, offset, false, 0) & width_mask(da.width);
            write_gpr(vcpu, da.reg, v);
        }
        (d.irq_level(), d.take_events())
    };
    if !events.is_empty() {
        let mut e = lock_or_recover(&sh.emit);
        for ev in &events {
            e.captured(ev);
        }
    }
    let _ = sh.vm.gic_set_spi(VIRTIO_NET_INTID, level);
}

/// Services a virtio-vsock MMIO access and drives its interrupt line. The
/// device relays guest<->host bytes over the agent Unix socket internally.
fn service_vsock(
    vcpu: &Vcpu,
    sh: &Shared,
    dev: &Arc<Mutex<VirtioVsock>>,
    offset: u64,
    syndrome: u64,
) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    // Under the device lock, as on every vsock path, since the bridge threads
    // drive the line too.
    let mut d = lock_or_recover(dev);
    if da.is_write {
        let v = read_gpr(vcpu, da.reg);
        d.mmio(&sh.mem, offset, true, v);
    } else {
        let v = d.mmio(&sh.mem, offset, false, 0) & width_mask(da.width);
        write_gpr(vcpu, da.reg, v);
    }
    let _ = sh.vm.gic_set_spi(VIRTIO_VSOCK_INTID, d.irq_level());
}

/// Services a virtio-fs MMIO transport access.
///
/// Every register except `QUEUE_NOTIFY` is handled inline here exactly as
/// the other virtio devices are: they are cheap and already serialised by
/// the device mutex. `QUEUE_NOTIFY` is the one exception (Stage A): `mmio`
/// itself only records the queue index (see its doc comment), so servicing
/// it here would mean nothing to observe yet -- the request has not run.
/// Instead this wakes the device's worker thread and returns without
/// touching the GIC; the worker raises the SPI itself once its drain pass
/// settles (`spawn_fs_worker`), coalescing however many requests that pass
/// served into one interrupt.
///
/// `INTERRUPT_ACK` is deliberately not special-cased: it still falls
/// through to the `gic_set_spi(intid, d.irq_level())` below exactly as
/// before, which is what keeps the SPI line consistent if a completion from
/// the worker lands concurrently with the ack (both take the device mutex,
/// so the read of `irq_level()` after the ack always reflects the true
/// post-ack state, worker races included).
fn service_fs(vcpu: &Vcpu, sh: &Shared, fs: &SharedFs, offset: u64, syndrome: u64) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    let is_notify = da.is_write && offset == mmio::QUEUE_NOTIFY;
    {
        let mut d = lock_or_recover(&fs.dev);
        if da.is_write {
            let v = read_gpr(vcpu, da.reg);
            d.mmio(&sh.mem, offset, true, v);
        } else {
            let v = d.mmio(&sh.mem, offset, false, 0) & width_mask(da.width);
            write_gpr(vcpu, da.reg, v);
        }
        // Inside the lock, deliberately. Now that a worker thread also drives
        // this device, reading the level here and setting the line after
        // releasing lets the two interleave: an INTERRUPT_ACK that observes
        // `irq_level() == false` can set the line low *after* a worker that
        // just completed a request set it high, leaving a filled used ring
        // with no interrupt. If that was the guest's last outstanding
        // request nothing will notify again and the FUSE call hangs. Setting
        // the line while still holding the mutex makes the last writer of
        // the line the last observer of `interrupt_status`.
        if !is_notify {
            let _ = sh.vm.gic_set_spi(fs.intid, d.irq_level());
        }
    }
    if is_notify {
        // Service a shallow queue right here rather than paying a thread
        // handoff for it. Waking the worker costs ~20us of park/unpark and
        // context switch, against ~7us of host time for a 4 KiB write, so
        // handing every request over made small-write workloads 2.6x slower
        // than the pre-worker code. Anything past the budget goes to the
        // worker, which is where a deep queue belongs: the handoff is
        // amortised and the vCPU gets to run the guest while it drains.
        let (remaining, level) = {
            let mut d = lock_or_recover(&fs.dev);
            let remaining = d.drain_notified_bounded(&sh.mem, FS_INLINE_BUDGET);
            (remaining, d.irq_level())
        };
        let _ = sh.vm.gic_set_spi(fs.intid, level);
        if remaining {
            fs.wake.wake();
        }
    }
}

/// Bridges the host agent Unix socket to the guest vsock device. Each accepted
/// connection is opened to the guest agent (host CID 2 -> guest CID 3, port
/// 1024) and relayed both ways by a per-connection reader thread. After any
/// host->guest injection the vsock GIC line is raised and the vCPUs kicked so
/// the guest drains its RX queue promptly.
///
/// The listener is non-blocking, so the accept loop can poll it beside the stop
/// token. The per-connection readers poll the same token, and the listener
/// thread joins the ones still running before it exits.
fn spawn_vsock_bridge(
    listener: std::os::unix::net::UnixListener,
    dev: Arc<Mutex<VirtioVsock>>,
    mem: Arc<GuestRam>,
    vm: VmGic,
    vcpus: Arc<Vcpus<Kicker>>,
    stop: StopToken,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        eprintln!("{LOG_PREFIX} vsock bridge: listening");
        let mut relays: Vec<JoinHandle<()>> = Vec::new();
        loop {
            match stop.wait(listener.as_fd()) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    eprintln!("{LOG_PREFIX} vsock bridge: {e}; no longer accepting");
                    break;
                }
            }
            let Ok((stream, _)) = listener.accept() else {
                continue;
            };
            let Ok(reader) = stream.try_clone() else {
                continue;
            };
            let Ok(writer) = stream.try_clone() else {
                continue;
            };

            // Register the connection and send the guest agent a REQUEST.
            let mut d = lock_or_recover(&dev);
            let Ok(port) = d.add_conn(stream) else {
                continue;
            };
            d.connect(&mem, port);
            let _ = vm.gic_set_spi(VIRTIO_VSOCK_INTID, d.irq_level());
            let writer_gate = d.writer_gate(port);
            drop(d);
            vcpus.kicker().kick_all();
            let Some(writer_gate) = writer_gate else {
                continue;
            };

            // Per-connection writer thread: the guest -> host bytes the vCPU
            // could not send. It waits for the socket to take them, without
            // the device lock.
            let (dev3, mem3, vm3, vcpus3, stop3) = (
                Arc::clone(&dev),
                Arc::clone(&mem),
                vm.clone(),
                Arc::clone(&vcpus),
                stop.clone(),
            );
            relays.retain(|handle| !handle.is_finished());
            relays.push(std::thread::spawn(move || loop {
                writer_gate.wait_open();
                match stop3.wait_writable(writer.as_fd()) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(e) => {
                        eprintln!("{LOG_PREFIX} vsock bridge: {e}; guest bytes dropped");
                        let mut d = lock_or_recover(&dev3);
                        d.host_gone(&mem3, port);
                        let _ = vm3.gic_set_spi(VIRTIO_VSOCK_INTID, d.irq_level());
                        drop(d);
                        vcpus3.kicker().kick_all();
                        break;
                    }
                }
                let mut d = lock_or_recover(&dev3);
                let needed = d.flush_to_host(&mem3, port);
                let _ = vm3.gic_set_spi(VIRTIO_VSOCK_INTID, d.irq_level());
                drop(d);
                vcpus3.kicker().kick_all();
                if !needed {
                    break;
                }
            }));

            // Per-connection reader thread: host -> guest.
            let dev2 = Arc::clone(&dev);
            let mem2 = Arc::clone(&mem);
            let vm2 = vm.clone();
            let vcpus2 = Arc::clone(&vcpus);
            let stop2 = stop.clone();
            relays.retain(|handle| !handle.is_finished());
            relays.push(std::thread::spawn(move || {
                let mut reader = reader;
                let mut buf = [0u8; 8192];
                loop {
                    match stop2.wait(reader.as_fd()) {
                        Ok(true) => {}
                        // A stop ends the connection like a peer close, so the
                        // device releases it.
                        Ok(false) => break,
                        Err(e) => {
                            eprintln!("{LOG_PREFIX} vsock bridge: {e}; connection closed");
                            break;
                        }
                    }
                    // `add_conn` makes the socket non-blocking, so a read can
                    // find nothing even after the poll.
                    let n = match vsock::read_host(&mut reader, &mut buf) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) if vsock::retry_read(&e) => continue,
                        Err(_) => break,
                    };
                    let gate = {
                        let mut d = lock_or_recover(&dev2);
                        let gate = d.host_data(&mem2, port, &buf[..n]);
                        let _ = vm2.gic_set_spi(VIRTIO_VSOCK_INTID, d.irq_level());
                        gate
                    };
                    vcpus2.kicker().kick_all();
                    // `HostGate::wait` says why its result is not needed.
                    if let Some(gate) = gate {
                        gate.wait(|| stop2.keep_waiting(reader.as_fd()));
                    }
                }
                let mut d = lock_or_recover(&dev2);
                d.host_closed(&mem2, port);
                let _ = vm2.gic_set_spi(VIRTIO_VSOCK_INTID, d.irq_level());
                drop(d);
                vcpus2.kicker().kick_all();
            }));
        }
        // Dropping the connections shuts their sockets down and opens their
        // gates, so every reader and writer ends.
        lock_or_recover(&dev).drop_conns();
        for relay in relays {
            let _ = relay.join();
        }
    })
}

/// Reads gateway->guest Ethernet frames (4-byte big-endian length prefix, the
/// gvisor-tap-vsock QEMU stream protocol) and injects each into the guest RX
/// queue under the device lock, raising the net GIC line and kicking the vCPUs.
/// Exits when the gateway closes the connection or the stop is requested.
///
/// [`GatewayRelay`] owns the wait, the drain and the framing. This thread
/// supplies the delivery under the device lock, the interrupt and the kick.
fn spawn_net_gateway_reader(
    reader: std::os::unix::net::UnixStream,
    dev: Arc<Mutex<VirtioNet>>,
    mem: Arc<GuestRam>,
    vm: VmGic,
    vcpus: Arc<Vcpus<Kicker>>,
    stop: StopToken,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let relayed = GatewayRelay::new(reader).run(&stop, |frame| {
            let level = {
                let mut d = lock_or_recover(&dev);
                d.deliver(&mem, frame);
                d.irq_level()
            };
            let _ = vm.gic_set_spi(VIRTIO_NET_INTID, level);
            vcpus.kicker().kick_all();
        });
        if let Err(e) = relayed {
            eprintln!("{LOG_PREFIX} virtio-net: {e}; gateway relay stopped");
        }
    })
}

/// Runs a virtio-fs device's FUSE servicing off the vCPU thread (Stage A of
/// the virtio-fs concurrency work). `service_fs` only ever records a
/// `QUEUE_NOTIFY` and calls `wake.wake()`; every host syscall a request
/// needs -- `pread`, `pwrite`, `stat`, `getxattr`, all of it -- happens here
/// instead, so a vCPU is never blocked behind the host filesystem and the
/// guest can keep more than one request in flight.
///
/// One worker per device, not a pool: `VirtioFs` still has exactly one
/// `Mutex` guarding all of its state, so this thread is the only thing
/// draining a given device, same as the vCPU thread used to be. A pool
/// would need to split that state first (separate per-handle locks, I/O
/// outside the lock) -- that is Stage B, out of scope here.
///
/// Interrupts are coalesced by construction: `drain_notified` empties every
/// flagged queue under one lock acquisition, so this raises the SPI and
/// kicks the vCPUs once per drain pass, not once per request however many
/// requests that pass served.
///
/// No lost wakeups: `wake.park()` is the standard predicate-plus-`Condvar`
/// pattern (see `FsWake`), and the vCPU thread signals unconditionally on
/// every notify, so a notify racing this loop is either folded into the
/// drain already in progress (both sides serialise on the device mutex) or
/// observed by the next `park()` call. The device mutex is held only for
/// the drain itself, never across `park()`.
///
/// Shutdown: `boot` calls [`FsWake::stop`] once the vCPUs have exited, and the
/// worker leaves its loop at the next `park`. It then drains the chains
/// announced by a wake that arrived with the stop.
fn spawn_fs_worker(
    dev: Arc<Mutex<VirtioFs>>,
    intid: u32,
    mem: Arc<GuestRam>,
    vm: VmGic,
    vcpus: Arc<Vcpus<Kicker>>,
    wake: Arc<FsWake>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        while wake.park() {
            {
                let mut d = lock_or_recover(&dev);
                d.drain_notified(&mem);
                // Raised under the same mutex the vCPU's INTERRUPT_ACK takes,
                // so the two cannot interleave into a low line over a non-empty
                // used ring. See the matching comment in `service_fs`.
                let _ = vm.gic_set_spi(intid, d.irq_level());
            }
            // Outside the lock: `kick_all` takes the vCPU-handle mutex, and it
            // does not need to be atomic with the line, only to follow it.
            vcpus.kicker().kick_all();
        }
        // A wake that arrived with the stop was cleared by that last `park`,
        // and the chains it announced are still in the ring. `stop` runs only
        // after every vCPU has been joined, so no further wake can come and
        // nothing else touches the device. One unbounded pass drains every
        // remaining chain, and no vCPU is left to interrupt.
        lock_or_recover(&dev).drain_notified(&mem);
    })
}

/// Zero-extension mask for a load of `width` bytes.
fn width_mask(width: u8) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (width * 8)) - 1
    }
}

/// Reads general-purpose register `idx` (31 = XZR, reads as 0).
fn read_gpr(vcpu: &Vcpu, idx: u8) -> u64 {
    gpr(idx).map_or(0, |r| vcpu.get_reg(r).unwrap_or(0))
}

/// Writes `value` to general-purpose register `idx` (31 = XZR, discarded).
fn write_gpr(vcpu: &Vcpu, idx: u8, value: u64) {
    if let Some(r) = gpr(idx) {
        let _ = vcpu.set_reg(r, value);
    }
}

/// Advances PC past a 4-byte instruction (restartable exceptions only).
fn advance_pc(vcpu: &Vcpu) {
    let pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
    let _ = vcpu.set_reg(Reg::PC, pc + 4);
}

/// Rounds `v` down to a multiple of `align` (a power of two).
fn align_down(v: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    v & !(align - 1)
}

/// Maps a data-abort source-register index (`SRT`) to an `applevisor` register.
fn gpr(idx: u8) -> Option<Reg> {
    Some(match idx {
        0 => Reg::X0,
        1 => Reg::X1,
        2 => Reg::X2,
        3 => Reg::X3,
        4 => Reg::X4,
        5 => Reg::X5,
        6 => Reg::X6,
        7 => Reg::X7,
        8 => Reg::X8,
        9 => Reg::X9,
        10 => Reg::X10,
        11 => Reg::X11,
        12 => Reg::X12,
        13 => Reg::X13,
        14 => Reg::X14,
        15 => Reg::X15,
        16 => Reg::X16,
        17 => Reg::X17,
        18 => Reg::X18,
        19 => Reg::X19,
        20 => Reg::X20,
        21 => Reg::X21,
        22 => Reg::X22,
        23 => Reg::X23,
        24 => Reg::X24,
        25 => Reg::X25,
        26 => Reg::X26,
        27 => Reg::X27,
        28 => Reg::X28,
        29 => Reg::X29,
        30 => Reg::X30,
        _ => return None,
    })
}

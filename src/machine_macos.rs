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

// Resolved once while the machine is built, before any guest request;
// see clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use applevisor::prelude::{
    ExitReason, GicConfig, GicEnabled, GicIntId, Reg, SysReg, Vcpu, VcpuHandle, VirtualMachine,
    VirtualMachineConfig, VirtualMachineInstance,
};

use crate::boot;
use crate::config::{check_export_overlap, BootConfig, Stop};
use crate::esr::{self, DataAbort, Ec, SysRegAccess};
use crate::events::Emitter;
use crate::fdt;
use crate::guestmem::GuestRam;
use crate::layout::{
    virtio_fs_base, virtio_fs_spi, GicLayout, GicVersion, DEVICE_WINDOW_END, RAM_BASE, UART_BASE,
    UART_SIZE, UART_SPI, VIRTIO_BASE, VIRTIO_NET_BASE, VIRTIO_NET_SPI, VIRTIO_SIZE, VIRTIO_SPI,
    VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_SPI,
};
use crate::pl011::Pl011;
use crate::plugin::{CpuHandle, GuestArch, IoSink, MemRegion, Plugin, RegsView, VmHandle};
use crate::sync::lock_or_recover;
use crate::teardown::{join_by, StopSource, StopToken, STOP_TIMEOUT};
use crate::virtio::{reg, VirtioBlk};
use crate::virtio_fs::VirtioFs;
use crate::virtio_net::VirtioNet;
use crate::virtio_vsock::VirtioVsock;
use vm_memory::{Address, GuestMemoryBackend, GuestMemoryRegion};

/// The VM handle once the GICv3 is configured (Send/Sync; cloned per thread).
type VmGic = VirtualMachineInstance<GicEnabled>;

/// Host key that asks the plugin for an observation now: Ctrl-] (GS, 0x1d).
const REQUEST_KEY: u8 = 0x1d;
/// The signal that ends the console reader's blocking read at stop.
const KICK_SIGNAL: libc::c_int = libc::SIGUSR1;
/// GIC INTIDs: SPIs start at 32.
const UART_INTID: u32 = 32 + UART_SPI;
const VIRTIO_INTID: u32 = 32 + VIRTIO_SPI;
const VIRTIO_NET_INTID: u32 = 32 + VIRTIO_NET_SPI;
const VIRTIO_VSOCK_INTID: u32 = 32 + VIRTIO_VSOCK_SPI;

/// PSTATE a vCPU enters the kernel with: DAIF masked, SP_ELx selected, at EL1
/// (`M = 0b0101`, EL1h) or, when the guest owns EL2, at EL2 (`M = 0b1001`,
/// EL2h). The boot vCPU and every `CPU_ON` secondary must use the same one:
/// Linux compares the mode each CPU booted in and, when they differ, prints
/// "CPUs started in inconsistent modes" and leaves KVM disabled.
const CPSR_EL1H: u64 = 0x3c5;
const CPSR_EL2H: u64 = 0x3c9;

/// The PSTATE every vCPU of this guest enters the kernel with.
fn entry_cpsr(nested_virt: bool) -> u64 {
    if nested_virt {
        CPSR_EL2H
    } else {
        CPSR_EL1H
    }
}

/// How a vCPU first enters the guest.
enum Entry {
    /// The boot vCPU, at the kernel with the devicetree in X0.
    Boot { kernel: u64, dtb: u64 },
    /// A secondary, at the entry point a PSCI `CPU_ON` named.
    CpuOn { entry: u64, ctx: u64 },
}

/// The registers a vCPU starts with. Both kinds of entry take their PSTATE
/// from [`entry_cpsr`] here, so a secondary cannot enter at a different
/// exception level from the boot vCPU.
fn entry_regs(entry: Entry, nested_virt: bool) -> Vec<(Reg, u64)> {
    let cpsr = entry_cpsr(nested_virt);
    match entry {
        Entry::Boot { kernel, dtb } => vec![
            (Reg::PC, kernel),
            (Reg::X0, dtb),
            (Reg::X1, 0),
            (Reg::X2, 0),
            (Reg::X3, 0),
            (Reg::CPSR, cpsr),
        ],
        Entry::CpuOn { entry, ctx } => vec![(Reg::PC, entry), (Reg::X0, ctx), (Reg::CPSR, cpsr)],
    }
}

/// The vCPU registers the sysreg path reads and writes. [`Vcpu`] implements
/// it; the tests implement it over a map, so that path runs without a VM.
trait VcpuRegs {
    fn get(&self, reg: Reg) -> u64;
    fn set(&self, reg: Reg, value: u64);
    fn get_sys(&self, reg: SysReg) -> u64;
    fn set_sys(&self, reg: SysReg, value: u64) -> Result<(), String>;
}

impl VcpuRegs for Vcpu {
    fn get(&self, reg: Reg) -> u64 {
        self.get_reg(reg).unwrap_or(0)
    }
    fn set(&self, reg: Reg, value: u64) {
        let _ = self.set_reg(reg, value);
    }
    fn get_sys(&self, reg: SysReg) -> u64 {
        self.get_sys_reg(reg).unwrap_or(0)
    }
    fn set_sys(&self, reg: SysReg, value: u64) -> Result<(), String> {
        self.set_sys_reg(reg, value).map_err(|e| format!("{e:?}"))
    }
}

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

/// The stop a PSCI call asks for, when it asks for the VM to end.
fn psci_stop(fid: u64) -> Option<Stop> {
    match fid {
        psci::SYSTEM_OFF => Some(Stop::SystemOff),
        psci::SYSTEM_RESET => Some(Stop::SystemReset),
        _ => None,
    }
}

/// How far to step PC once a PSCI call that trapped as `ec` has been
/// serviced, or `None` when the call ended the VM and nothing resumes.
///
/// The two conduits return to different places. A trapped HVC reports the
/// instruction after it, but a trapped SMC reports the SMC itself (its
/// preferred return address is the SMC, for a monitor that emulates it).
/// Without the step the guest re-issues the SMC with the result in X0 as the
/// function ID and never gets past its first PSCI call. The step does not
/// depend on the function ID: an unknown one gets NOT_SUPPORTED and the
/// guest still has to move on.
fn psci_resume_step(ec: Ec, fid: u64) -> Option<u64> {
    if psci_stop(fid).is_some() {
        return None;
    }
    Some(if ec == Ec::Smc { 4 } else { 0 })
}

/// `HCR_EL2.TSC`: SMC from EL1 traps to EL2.
const HCR_EL2_TSC: u64 = 1 << 19;

/// Whether a PSCI call that trapped as `ec` from `cpsr` is the outer guest's
/// own, and so hvi's to serve. `hcr_el2` is the guest's own (virtual)
/// `HCR_EL2`, which only means something when the guest owns EL2.
///
/// A guest at EL1 has nobody but hvi above it, so its calls are always
/// served. A guest that owns EL2 has a hypervisor of its own: from its EL2,
/// and from EL1 with `TSC` clear (the nVHE host kernel making PSCI calls to
/// what it takes for firmware), the call is meant for hvi. An HVC from EL1,
/// or an SMC from EL1 with `TSC` set, belongs to the guest's own hypervisor;
/// that is where the hardware sends it. If one ever reaches hvi it is refused
/// with NOT_SUPPORTED, so a nested guest cannot power the outer one off or
/// start its vCPUs.
///
/// The test is `TSC` and not `HCR_EL2.VM`. VM says stage 2 is on, not that a
/// nested guest runs: protected-mode KVM runs its own host kernel with stage
/// 2 on, and that host's PSCI calls are the guest's, not a nested guest's.
/// KVM sets `TSC` for the guests it runs, and pKVM sets it for its host too,
/// which then makes its own firmware calls from EL2.
fn psci_is_ours(nested_virt: bool, ec: Ec, cpsr: u64, hcr_el2: u64) -> bool {
    if !nested_virt || (cpsr >> 2) & 0b11 == 2 {
        return true;
    }
    ec == Ec::Smc && hcr_el2 & HCR_EL2_TSC == 0
}

/// How far to step PC past a PSCI call hvi refused: it is not serviced, so
/// no function ID can end the VM.
fn refused_psci_step(ec: Ec) -> u64 {
    if ec == Ec::Smc {
        4
    } else {
        0
    }
}

#[cfg(test)]
mod psci_tests {
    use super::*;

    const RESUMING: [u64; 6] = [
        psci::VERSION,
        psci::CPU_ON_64,
        psci::CPU_OFF,
        psci::FEATURES,
        0x8400_0006, // MIGRATE_INFO_TYPE, which Linux asks for and hvi lacks
        0xdead_beef, // not a PSCI function at all
    ];

    /// An SMC resumes past itself, whatever it asked for. This is the step
    /// whose absence left a guest re-issuing its first PSCI call forever.
    #[test]
    fn smc_steps_past_the_instruction() {
        for fid in RESUMING {
            assert_eq!(psci_resume_step(Ec::Smc, fid), Some(4), "fid {fid:#x}");
        }
    }

    /// A trapped HVC already reports the next instruction; stepping it too
    /// would skip one instruction of the guest's.
    #[test]
    fn hvc_resumes_where_it_was_reported() {
        for fid in RESUMING {
            assert_eq!(psci_resume_step(Ec::Hvc, fid), Some(0), "fid {fid:#x}");
        }
    }

    /// SYSTEM_OFF and SYSTEM_RESET end the VM over either conduit, so there
    /// is no PC to step.
    #[test]
    fn stopping_calls_resume_nothing() {
        for ec in [Ec::Hvc, Ec::Smc] {
            assert_eq!(psci_resume_step(ec, psci::SYSTEM_OFF), None);
            assert_eq!(psci_resume_step(ec, psci::SYSTEM_RESET), None);
        }
        assert!(matches!(psci_stop(psci::SYSTEM_OFF), Some(Stop::SystemOff)));
        assert!(matches!(
            psci_stop(psci::SYSTEM_RESET),
            Some(Stop::SystemReset)
        ));
        assert!(psci_stop(0xdead_beef).is_none());
    }
}

/// A secondary vCPU's start mailbox, filled by a PSCI `CPU_ON`.
struct Secondary {
    mbox: Mutex<Option<(u64, u64)>>, // (entry point, context id)
    cv: Condvar,
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
    running: Arc<AtomicBool>,
    handles: Arc<Mutex<Vec<VcpuHandle>>>,
    secondaries: Arc<Vec<Secondary>>,
    stop: Arc<Mutex<Option<Stop>>>,
    kernel_addr: u64,
    dtb_addr: u64,
    num_cpus: u32,
    /// Parks every vCPU at a safe point so an observation sees a still guest.
    quiesce: Arc<crate::quiesce::Quiesce>,
    /// Whoever is watching this guest, if anyone.
    plugin: Option<Arc<dyn Plugin>>,
    /// The object backing guest RAM, for a plugin that hands the same pages to
    /// another process.
    ram_file: Arc<std::fs::File>,
    sandbox_id: String,
    /// The guest owns EL2 (`--nested-virt`): vCPUs enter at EL2h.
    nested_virt: bool,
    /// Sysreg encodings the guest trapped on from EL2 and hvi does not
    /// model, each logged once per boot.
    unknown_el2: Arc<UnknownEl2Traps>,
    /// Set once a PSCI call that belonged to the guest's own hypervisor has
    /// been refused and logged.
    refused_psci_logged: Arc<AtomicBool>,
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
    boot::LoadedKernel::from_header(&cfg.kernel)?;
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
        "[hvi] {num_cpus} vCPU(s)  GICD {:#x}+{:#x}  GICR {:#x}+{:#x}  UART {:#x}",
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

    // EL2 for the guest is decided here, before the VM and its RAM exist, so
    // an unsupported host is a refusal and not a guest that dies later.
    let mut vm_config = VirtualMachineConfig::new();
    let mut fdt_options = fdt::Options::default();
    if cfg.nested_virt {
        fdt_options = enable_el2(&mut vm_config)?;
    }

    let mut gic_config = GicConfig::new();
    gic_config.set_distributor_base(gic.gicd_base)?;
    gic_config.set_redistributor_base(gic.gicr_base)?;
    let vm = VirtualMachine::with_gic(vm_config, gic_config)?;

    // Guest RAM: one region mapped at RAM_BASE, backed by a shareable object
    // rather than allocated by applevisor, so an out-of-process plugin can
    // map the same pages. applevisor's memory_create uses hv_vm_allocate,
    // which hands back a pointer with no nameable backing object; hv_vm_map
    // accepts any page-aligned host pointer, so the guest gets the mapping
    // `GuestRam` made of the object. This is the path `hvi smoke --shm`
    // exercises.
    let shared_ram = crate::sharedmem::SharedRam::new(cfg.mem_bytes as usize)?;
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
            eprintln!("[hvi] virtio-blk: {path}");
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
    let net = if let Some(sock) = &cfg.net_gateway {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(stream) => match stream.try_clone() {
                Ok(reader) => {
                    eprintln!("[hvi] virtio-net: gvisor-tap gateway relay via {sock} (guest 10.87.0.2, gw/DNS 10.87.0.1)");
                    net_reader = Some(reader);
                    Some(VirtioNet::with_gateway(stream))
                }
                Err(e) => {
                    eprintln!("[hvi] WARNING: cannot clone gateway socket ({e}); net disabled");
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "[hvi] WARNING: gateway {sock} unreachable ({e}); falling back to the {}",
                    crate::virtio_net::stub_stack_line()
                );
                Some(VirtioNet::new())
            }
        }
    } else if cfg.net {
        eprintln!("[hvi] virtio-net: {}", crate::virtio_net::stub_stack_line());
        Some(VirtioNet::new())
    } else {
        None
    };

    let net = crate::virtio_net::share(net, cfg.net_mac);

    let vsock = cfg.agent_sock.as_ref().map(|sock| {
        eprintln!("[hvi] virtio-vsock: agent bridge on {sock} (guest cid 3, port 1024)");
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
            match crate::fdlimit::raise_open_file_limit() {
                Ok(limit) => eprintln!("[hvi] open-file limit: {limit}"),
                Err(e) => eprintln!(
                    "[hvi] open-file limit: could not raise it ({e}); \
                     a busy guest may see EMFILE as I/O errors"
                ),
            }
        }
        eprintln!(
            "[hvi] virtio-fs[{index}]: {} as {:?} ({access})",
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
            "[hvi] event ledger: {}",
            cfg.events.as_deref().unwrap_or("")
        );
    }

    let layout = boot::Payload {
        kernel: &cfg.kernel,
        initramfs: cfg.initramfs.as_deref(),
        cmdline: &cfg.cmdline,
    }
    .load(
        ram.memory(),
        cfg.mem_bytes,
        &gic,
        num_cpus,
        fdt_devices,
        fdt_options,
    )?;

    let secondaries: Vec<Secondary> = (0..num_cpus)
        .map(|_| Secondary {
            mbox: Mutex::new(None),
            cv: Condvar::new(),
        })
        .collect();

    let shared = Shared {
        vm: vm.clone(),
        mem: ram,
        pl011: Arc::new(Mutex::new(Pl011::new())),
        virtio,
        net,
        vsock,
        fs,
        emit: Arc::new(Mutex::new(emitter)),
        running: Arc::new(AtomicBool::new(true)),
        handles: Arc::new(Mutex::new(Vec::new())),
        secondaries: Arc::new(secondaries),
        stop: Arc::new(Mutex::new(None)),
        kernel_addr: layout.kernel_addr,
        dtb_addr: layout.dtb_addr,
        quiesce: Arc::new(crate::quiesce::Quiesce::new()),
        plugin: cfg.plugin.clone(),
        ram_file: Arc::clone(shared_ram.file()),
        sandbox_id: cfg.sandbox_id.clone(),
        num_cpus,
        nested_virt: cfg.nested_virt,
        unknown_el2: Arc::default(),
        refused_psci_logged: Arc::default(),
    };

    // Hand the plugin the guest before any vCPU runs, so nothing happens
    // between the first instruction and the attach.
    if let Some(obs) = &shared.plugin {
        obs.attach(Arc::new(shared.clone()) as Arc<dyn VmHandle>)?;
    }

    let _raw = RawTerm::enable();

    // Confine the process before the first helper thread exists. Everything
    // above acquires host authority (the VM, the guest-RAM mapping, the block
    // file, the ledger, the gateway connection, the listeners, the terminal),
    // and everything below only services guest I/O with what is already open.
    // An error here returns before there is a thread to stop. See `sandbox`.
    //
    // Failing closed: a profile that will not install is a profile nobody has
    // tested, and continuing would hand a guest-facing process the host's full
    // ambient authority under a log line claiming it was sandboxed.
    if cfg.sandbox {
        crate::sandbox::enter_with_shares(&fs_access)
            .map_err(|e| format!("{e}; re-run with --no-sandbox to boot unconfined"))?;
        eprintln!("[hvi] seatbelt sandbox: on (deny default)");
    } else {
        eprintln!("[hvi] seatbelt sandbox: OFF (--no-sandbox) — the VMM keeps full host authority");
    }

    // Helper threads. Each polls its stop token beside its own descriptor, or
    // takes the stop through its `FsWake`, and is joined after the vCPUs.
    install_kick_handler();
    let input = spawn_input_thread(
        vm.clone(),
        Arc::clone(&shared.pl011),
        shared.plugin.clone(),
        Arc::clone(&shared.handles),
        stop_source.token(),
    );
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
                Arc::clone(&shared.handles),
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
                Arc::clone(&shared.handles),
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
                Arc::clone(&shared.handles),
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

    // One thread per vCPU; join them all (cpu0 ends on PSCI SYSTEM_OFF and
    // stops the rest).
    let mut joins = Vec::new();
    for cpu in 0..num_cpus {
        let sh = shared.clone();
        joins.push(std::thread::spawn(move || run_cpu(cpu, sh)));
    }
    for j in joins {
        let _ = j.join();
    }

    // The guest has stopped. End the helper threads (see `teardown`) and write
    // out the ledger tail, which the flush cadence alone would leave in the
    // buffer.
    stop_source.request_stop();
    for fs in &shared.fs {
        fs.wake.stop();
    }
    for stop in &readahead_stops {
        stop.stop();
    }
    let deadline = std::time::Instant::now() + STOP_TIMEOUT;
    kick_until_finished(&input, deadline);
    let mut stuck = None;
    for (name, thread) in std::iter::once(("console reader", input)).chain(helpers) {
        if let Err(e) = join_by(name, thread, deadline) {
            eprintln!("[hvi] {e}; left running");
            stuck.get_or_insert(e);
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
            "[hvi] virtio-fs[{index}]: peak {} of {} guest handles",
            dev.peak_handles(),
            dev.handle_limit()
        );
        let hist: Vec<String> = dev
            .op_stats()
            .into_iter()
            .map(|(o, c, n)| {
                format!(
                    "{}({})={}/{:.1}ms",
                    crate::virtio_fs::opcode_name(o),
                    o,
                    c,
                    n as f64 / 1e6
                )
            })
            .collect();
        eprintln!("[hvi] virtio-fs[{index}] ops: {}", hist.join(" "));
        let (hits, waits, misses) = dev.readahead_stats();
        eprintln!("[hvi] virtio-fs[{index}] readahead: hits={hits} waits={waits} misses={misses}");
    }

    if let Some(e) = stuck {
        return Err(e.into());
    }
    let stop = shared.stop.lock().unwrap().unwrap_or(Stop::SystemOff);
    Ok(stop)
}

thread_local! {
    /// The reason this thread's vCPU last left the guest.
    ///
    /// Recorded so the panic report in [`run_cpu`] can name it. `catch_unwind`
    /// runs on the thread that panicked, so a thread-local survives the unwind
    /// and is readable there, and it costs the other vCPU threads nothing.
    static LAST_EXIT: std::cell::Cell<Option<ExitReason>> =
        const { std::cell::Cell::new(None) };
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
            // Returning alone left every other thread waiting on a vCPU that
            // will never exist: the secondaries block for a CPU_ON that
            // cannot arrive and the join in `boot` never returns. A vCPU that
            // cannot be created ends the VM (#35).
            eprintln!("[hvi] cpu{cpu_id}: vcpu_create failed: {e:?}");
            stop_all(&sh);
            return;
        }
    };
    let _ = vcpu.set_trap_debug_exceptions(false);
    let _ = vcpu.set_trap_debug_reg_accesses(false);
    // GICv3 affinity: aff0 = cpu id, RES1 bit 31 set.
    let _ = vcpu.set_sys_reg(SysReg::MPIDR_EL1, 0x8000_0000 | u64::from(cpu_id));
    sh.handles.lock().unwrap().push(vcpu.get_handle());
    if sh.nested_virt {
        if let Err(e) = hide_sme(&vcpu) {
            eprintln!("[hvi] cpu{cpu_id}: cannot hide SME from a guest at EL2: {e:?}");
            stop_all(&sh);
            return;
        }
    }

    if cpu_id == 0 {
        let entry = Entry::Boot {
            kernel: sh.kernel_addr,
            dtb: sh.dtb_addr,
        };
        for (reg, value) in entry_regs(entry, sh.nested_virt) {
            let _ = vcpu.set_reg(reg, value);
        }
    } else {
        // Park until the guest brings this cpu up via PSCI CPU_ON.
        let sec = &sh.secondaries[cpu_id as usize];
        let mut mbox = sec.mbox.lock().unwrap();
        while mbox.is_none() && sh.running.load(Ordering::SeqCst) {
            mbox = sec.cv.wait(mbox).unwrap();
        }
        match mbox.take() {
            Some((entry, ctx)) => {
                drop(mbox);
                eprintln!("[hvi] cpu{cpu_id}: PSCI CPU_ON -> {entry:#x}");
                for (reg, value) in entry_regs(Entry::CpuOn { entry, ctx }, sh.nested_virt) {
                    let _ = vcpu.set_reg(reg, value);
                }
            }
            None => return, // stopped while waiting
        }
    }

    let is_boot = cpu_id == 0;
    // The loop runs inside `catch_unwind` so a panic ends the VM with a
    // report rather than leaving it alive with one thread missing. A panic
    // in a plugin hook is the case that matters: those run between guest
    // entries with the other vCPUs parked in `checkpoint`, and nothing was
    // releasing them (#35).
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        while sh.running.load(Ordering::SeqCst) {
            // Safe point for every vCPU: park here while cpu0 lets a plugin
            // look at the guest.
            sh.quiesce.checkpoint();
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
                // Same shape as the four paths in #35, and not listed there:
                // breaking alone left `running` true and the VM hung.
                eprintln!("[hvi] cpu{cpu_id}: vcpu run failed: {e:?}");
                stop_all(&sh);
                break;
            }
            let exit = vcpu.get_exit_info();
            LAST_EXIT.with(|last| last.set(Some(exit.reason)));
            match exit.reason {
                ExitReason::EXCEPTION => {
                    let syn = exit.exception.syndrome;
                    match Ec::from_syndrome(syn) {
                        ec @ (Ec::Hvc | Ec::Smc) => {
                            // Read before servicing: the reply overwrites X0.
                            let fid = vcpu.get_reg(Reg::X0).unwrap_or(0);
                            let ours = !sh.nested_virt
                                || psci_is_ours(
                                    true,
                                    ec,
                                    vcpu.get_reg(Reg::CPSR).unwrap_or(0),
                                    vcpu.get_sys_reg(SysReg::HCR_EL2).unwrap_or(0),
                                );
                            if !ours {
                                let _ = vcpu.set_reg(Reg::X0, psci::NOT_SUPPORTED);
                                if !sh.refused_psci_logged.swap(true, Ordering::Relaxed) {
                                    eprintln!(
                                        "[hvi] cpu{cpu_id}: refused PSCI {fid:#x} over {ec:?} \
                                         from EL1; it belongs to the guest's own \
                                         hypervisor (logged once)"
                                    );
                                }
                                let pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
                                let _ = vcpu.set_reg(Reg::PC, pc + refused_psci_step(ec));
                                continue;
                            }
                            service_psci(&vcpu, &sh);
                            match psci_resume_step(ec, fid) {
                                None => break, // SYSTEM_OFF/RESET
                                Some(0) => {}
                                Some(step) => {
                                    let pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
                                    let _ = vcpu.set_reg(Reg::PC, pc + step);
                                }
                            }
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
                                    "[hvi] cpu{cpu_id}: unhandled MMIO at {ipa:#x} (pc {:#x})",
                                    vcpu.get_reg(Reg::PC).unwrap_or(0)
                                );
                                // Any vCPU, not only the boot one: a secondary
                                // that gave up left the VM running with one
                                // fewer
                                // vCPU and nothing said so (#35).
                                stop_all(&sh);
                                break;
                            }
                        }
                        Ec::SysReg => {
                            let access = SysRegAccess::from_syndrome(syn);
                            if let Some(line) =
                                service_sysreg(&vcpu, sh.nested_virt, access, &sh.unknown_el2)
                            {
                                eprintln!("[hvi] cpu{cpu_id}: {line}");
                            }
                            advance_pc(&vcpu);
                        }
                        Ec::Other(0x01) => {} // WFx: hvf handled the wait.
                        other => {
                            eprintln!(
                                "[hvi] cpu{cpu_id}: unhandled exception {other:?} (pc {:#x})",
                                vcpu.get_reg(Reg::PC).unwrap_or(0)
                            );
                            stop_all(&sh);
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
                    // resume into. Breaking alone left `running` true, so the
                    // secondaries kept waiting and `boot` never joined (#35).
                    eprintln!(
                        "[hvi] cpu{cpu_id}: unknown exit reason (pc {:#x})",
                        vcpu.get_reg(Reg::PC).unwrap_or(0)
                    );
                    stop_all(&sh);
                    break;
                }
            }
        }
    }));

    if let Err(payload) = outcome {
        // Name the thread, where the guest was, and what it last did, so the
        // report is usable without a debugger. `payload` carries the panic
        // message for the two types a `panic!` produces.
        let what = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown payload".to_string());
        eprintln!(
            "[hvi] cpu{cpu_id}: panicked ({what}); last exit {:?}, pc {:#x}",
            last_exit(),
            vcpu.get_reg(Reg::PC).unwrap_or(0)
        );
        stop_all(&sh);
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

    fn ram_regions(&self) -> Vec<MemRegion> {
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
        kick_all(&self.vm, &self.handles);
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
        // cpu0 drives this, so it waits for the *other* vCPUs and never parks
        // itself. On failure the quiesce is released here, so a caller that
        // gets `false` owes nothing.
        self.sh.quiesce.request();
        kick_all(&self.sh.vm, &self.sh.handles);
        if self.sh.quiesce.wait_for(self.sh.num_cpus.saturating_sub(1)) {
            true
        } else {
            self.sh.quiesce.release();
            false
        }
    }

    fn resume(&self) {
        self.sh.quiesce.release();
    }

    fn ledger(&self) -> &Arc<Mutex<Emitter>> {
        &self.sh.emit
    }
}

/// Hides SME from a vCPU of a guest that owns EL2: clears
/// `ID_AA64PFR1_EL1.SME` (bits 27:24) and every field of `ID_AA64SMFR0_EL1`.
///
/// Hypervisor.framework offers SME to a guest at EL1, but with EL2 enabled an
/// access to `SMCR_EL2` is undefined (macOS 26.7, Apple M5 Pro). Linux's EL2
/// setup writes `SMCR_EL2` whenever the ID register says SME is there, so
/// without this the kernel takes an undefined-instruction exception in its
/// hyp stub before it prints anything, and loops on it with nothing on the
/// console. SMFR0 describes the SME features; left populated it would claim
/// features of an extension the guest is told it does not have.
fn hide_sme(vcpu: &Vcpu) -> applevisor::error::Result<()> {
    let pfr1 = vcpu.get_sys_reg(SysReg::ID_AA64PFR1_EL1)?;
    vcpu.set_sys_reg(SysReg::ID_AA64PFR1_EL1, pfr1 & !(0xf << 24))?;
    vcpu.set_sys_reg(SysReg::ID_AA64SMFR0_EL1, 0)
}

/// Names the EL2 register a trapped access reaches, when the VMM services it
/// for a guest that owns EL2. `None` sends the access down the RAZ/WI path.
///
/// Only an access made at EL2 qualifies. From EL1 or EL0 these registers are
/// undefined, so such an access is never a write by the guest's hypervisor.
/// Serving it would let code below that hypervisor, a nested guest included,
/// change the hypervisor's timer control.
///
/// Only `CNTHCTL_EL2` is here, because it is the only EL2 register a Linux
/// guest at EL2 was seen to trap on (macOS 26.7, Apple M5 Pro), and RAZ/WI
/// breaks it. The guest kernel's boot-time write that lets EL1 use the
/// physical timer was dropped, so the kernel's first `CNTP_CTL_EL0` read
/// trapped to its own hyp stub, which cannot service it, and the guest spun
/// there with nothing on the console. KVM in the guest also rewrites this
/// register on every switch into and out of its own guests.
fn el2_sysreg(cpsr: u64, access: SysRegAccess) -> Option<SysReg> {
    if (cpsr >> 2) & 0b11 != 2 {
        return None;
    }
    match access.reg {
        esr::CNTHCTL_EL2 => Some(SysReg::CNTHCTL_EL2),
        _ => None,
    }
}

/// Performs `access` on `reg`, keeping the value in the vCPU through the
/// framework, which applies it.
fn service_el2_sysreg(vcpu: &impl VcpuRegs, reg: SysReg, access: SysRegAccess) {
    if access.is_read {
        write_gpr(vcpu, access.rt, vcpu.get_sys(reg));
    } else if let Err(e) = vcpu.set_sys(reg, read_gpr(vcpu, access.rt)) {
        eprintln!("[hvi] cannot set {reg:?} for the guest: {e}");
    }
}

/// Sysreg encodings that a guest owning EL2 trapped on from EL2 and that hvi
/// takes as RAZ/WI, so each is reported once per boot.
///
/// `CNTHCTL_EL2` was such a register until hvi modelled it, and the guest
/// hung on it with nothing on the console to say why. The next one should
/// leave a line naming the register.
#[derive(Default)]
struct UnknownEl2Traps(Mutex<std::collections::HashSet<esr::SysRegEncoding>>);

impl UnknownEl2Traps {
    /// The line to log for `access`, the first time its encoding is seen.
    fn first(&self, access: SysRegAccess) -> Option<String> {
        if !lock_or_recover(&self.0).insert(access.reg) {
            return None;
        }
        let (op0, op1, crn, crm, op2) = access.reg;
        Some(format!(
            "guest EL2 {} of S{op0}_{op1}_C{crn}_C{crm}_{op2} is not modelled; RAZ/WI (logged once)",
            if access.is_read { "read" } else { "write" }
        ))
    }
}

/// Services a trapped `MSR`/`MRS`: RAZ/WI for an unmodeled system register,
/// except the EL2 ones a guest that owns EL2 relies on (see [`el2_sysreg`]).
/// The caller steps PC past the instruction. Returns a line to log when a
/// guest that owns EL2 made an access from EL2 that took the RAZ/WI path for
/// the first time this boot.
fn service_sysreg(
    vcpu: &impl VcpuRegs,
    nested_virt: bool,
    access: SysRegAccess,
    unknown: &UnknownEl2Traps,
) -> Option<String> {
    let at_el2 = nested_virt && (vcpu.get(Reg::CPSR) >> 2) & 0b11 == 2;
    let el2 = if nested_virt {
        el2_sysreg(vcpu.get(Reg::CPSR), access)
    } else {
        None
    };
    if let Some(reg) = el2 {
        service_el2_sysreg(vcpu, reg, access);
        return None;
    }
    if access.is_read {
        write_gpr(vcpu, access.rt, 0);
    }
    if at_el2 {
        unknown.first(access)
    } else {
        None
    }
}

/// Turns on EL2 for the guest in `vm_config` and returns the devicetree
/// options a guest at EL2 needs.
///
/// # Errors
///
/// Refuses when Hypervisor.framework reports no EL2 on this host, or when the
/// framework's timer INTIDs disagree with the ones the devicetree advertises.
fn enable_el2(
    vm_config: &mut VirtualMachineConfig,
) -> Result<fdt::Options, Box<dyn std::error::Error>> {
    let ppi = el2_support()?.map_err(|detail| {
        format!("nested virtualization requested but not supported by this host: {detail}")
    })?;
    vm_config.set_el2_enabled(true)?;
    eprintln!(
        "[hvi] nested virtualization: EL2 enabled (psci conduit smc, gic maintenance ppi {ppi})"
    );
    Ok(fdt::Options {
        psci_conduit: fdt::PsciConduit::Smc,
        gic_maintenance_ppi: Some(ppi),
    })
}

/// Whether this host can boot a guest with `--nested-virt`: the one check
/// both `boot` and `hvi caps` make, so `caps` saying supported means a boot
/// accepts the host. `Ok(Ok(ppi))` carries the GIC maintenance PPI;
/// `Ok(Err(detail))` says why not.
///
/// # Errors
///
/// Errors only when Hypervisor.framework cannot be asked.
pub fn el2_support() -> Result<Result<u32, String>, Box<dyn std::error::Error>> {
    if !VirtualMachineConfig::get_el2_supported()? {
        return Ok(Err("Hypervisor.framework reports no EL2".into()));
    }
    // The devicetree's timer PPIs are constants. A guest at EL1 uses the
    // virtual timer. A kernel booted at EL2 uses the EL1 physical timer (PPI
    // 14) under nVHE, the only mode the framework offers, and would use the
    // hypervisor timer (PPI 10) under VHE. One wired to the wrong PPI boots
    // with a clock that never ticks, so the constants are checked against the
    // framework before that guest runs.
    for (id, ppi, name) in [
        (
            GicIntId::EL1_VIRTUAL_TIMER,
            fdt::TIMER_PPI_VIRT,
            "EL1 virtual",
        ),
        (
            GicIntId::EL1_PHYSICAL_TIMER,
            fdt::TIMER_PPI_PHYS,
            "EL1 physical",
        ),
        (
            GicIntId::EL2_PHYSICAL_TIMER,
            fdt::TIMER_PPI_HYP_PHYS,
            "EL2 physical",
        ),
    ] {
        let intid = GicConfig::get_intid(id)?;
        if intid != ppi + 16 {
            return Ok(Err(format!(
                "the {name} timer is INTID {intid} in Hypervisor.framework, but the \
                 devicetree advertises PPI {ppi} (INTID {})",
                ppi + 16
            )));
        }
    }
    let maintenance = GicConfig::get_intid(GicIntId::MAINTENANCE)?;
    Ok(maintenance
        .checked_sub(16)
        .ok_or_else(|| format!("GIC maintenance interrupt {maintenance} is not a PPI")))
}

/// Handles a PSCI call: writes the reply, or records the stop and stops every
/// vCPU for SYSTEM_OFF/RESET. [`psci_resume_step`] decides where the caller
/// resumes.
fn service_psci(vcpu: &Vcpu, sh: &Shared) {
    let fid = vcpu.get_reg(Reg::X0).unwrap_or(0);
    if let Some(stop) = psci_stop(fid) {
        *sh.stop.lock().unwrap() = Some(stop);
        stop_all(sh);
        return;
    }
    match fid {
        psci::VERSION => {
            let _ = vcpu.set_reg(Reg::X0, 0x0001_0000); // v1.0
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
        }
        psci::CPU_ON_64 => {
            let target = vcpu.get_reg(Reg::X1).unwrap_or(0);
            let entry = vcpu.get_reg(Reg::X2).unwrap_or(0);
            let ctx = vcpu.get_reg(Reg::X3).unwrap_or(0);
            let idx = (target & 0xff) as usize; // aff0
            let ret = if idx != 0 && idx < sh.num_cpus as usize {
                let sec = &sh.secondaries[idx];
                *sec.mbox.lock().unwrap() = Some((entry, ctx));
                sec.cv.notify_all();
                psci::SUCCESS
            } else {
                psci::NOT_SUPPORTED
            };
            let _ = vcpu.set_reg(Reg::X0, ret);
        }
        psci::CPU_OFF => {
            let _ = vcpu.set_reg(Reg::X0, psci::SUCCESS);
        }
        _ => {
            let _ = vcpu.set_reg(Reg::X0, psci::NOT_SUPPORTED);
        }
    }
}

/// Signals all vCPUs to stop and kicks them out of `run()`.
fn stop_all(sh: &Shared) {
    sh.running.store(false, Ordering::SeqCst);
    // Nobody may still be parked at a checkpoint once the VM is stopping. A
    // plugin that panicked between `request` and `release` left every other
    // vCPU waiting there with no one left to release them (#35).
    sh.quiesce.release();
    if let Ok(handles) = sh.handles.lock() {
        let _ = sh.vm.vcpus_exit(handles.as_slice());
    }
    for sec in sh.secondaries.iter() {
        sec.cv.notify_all();
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
    let level = {
        let mut d = lock_or_recover(dev);
        if da.is_write {
            let v = read_gpr(vcpu, da.reg);
            d.mmio(&sh.mem, offset, true, v);
        } else {
            let v = d.mmio(&sh.mem, offset, false, 0) & width_mask(da.width);
            write_gpr(vcpu, da.reg, v);
        }
        d.irq_level()
    };
    let _ = sh.vm.gic_set_spi(VIRTIO_VSOCK_INTID, level);
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
    let is_notify = da.is_write && offset == reg::QUEUE_NOTIFY;
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
    handles: Arc<Mutex<Vec<VcpuHandle>>>,
    stop: StopToken,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        eprintln!("[hvi] vsock bridge: listening");
        let mut readers: Vec<JoinHandle<()>> = Vec::new();
        loop {
            match stop.wait(listener.as_fd()) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    eprintln!("[hvi] vsock bridge: {e}; no longer accepting");
                    break;
                }
            }
            let Ok((stream, _)) = listener.accept() else {
                continue;
            };
            // The device writes to this socket and must block, or a full send
            // buffer would split a frame. On macOS an accepted socket inherits
            // the listener's non-blocking flag, so blocking mode is set here.
            if stream.set_nonblocking(false).is_err() {
                continue;
            }
            let Ok(reader) = stream.try_clone() else {
                continue;
            };

            // Register the connection and send the guest agent a REQUEST.
            let mut d = lock_or_recover(&dev);
            let port = d.add_conn(stream);
            d.connect(&mem, port);
            let level = d.irq_level();
            drop(d);
            let _ = vm.gic_set_spi(VIRTIO_VSOCK_INTID, level);
            kick_all(&vm, &handles);

            // Per-connection reader thread: host -> guest.
            let dev2 = Arc::clone(&dev);
            let mem2 = Arc::clone(&mem);
            let vm2 = vm.clone();
            let handles2 = Arc::clone(&handles);
            let stop2 = stop.clone();
            readers.retain(|handle| !handle.is_finished());
            readers.push(std::thread::spawn(move || {
                let mut reader = reader;
                let mut buf = [0u8; 8192];
                loop {
                    match stop2.wait(reader.as_fd()) {
                        Ok(true) => {}
                        // A stop ends the connection like a peer close, so the
                        // device releases it.
                        Ok(false) => break,
                        Err(e) => {
                            eprintln!("[hvi] vsock bridge: {e}; connection closed");
                            break;
                        }
                    }
                    let n = match crate::virtio_vsock::read_host(&mut reader, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let level = {
                        let mut d = lock_or_recover(&dev2);
                        d.host_data(&mem2, port, &buf[..n]);
                        d.irq_level()
                    };
                    let _ = vm2.gic_set_spi(VIRTIO_VSOCK_INTID, level);
                    kick_all(&vm2, &handles2);
                }
                let level = {
                    let mut d = lock_or_recover(&dev2);
                    d.host_closed(&mem2, port);
                    d.irq_level()
                };
                let _ = vm2.gic_set_spi(VIRTIO_VSOCK_INTID, level);
                kick_all(&vm2, &handles2);
            }));
        }
        for reader in readers {
            let _ = reader.join();
        }
    })
}

/// Reads gateway->guest Ethernet frames (4-byte big-endian length prefix, the
/// gvisor-tap-vsock QEMU stream protocol) and injects each into the guest RX
/// queue under the device lock, raising the net GIC line and kicking the vCPUs.
/// Exits when the gateway closes the connection or the stop is requested.
///
/// [`crate::virtio_net::GatewayRelay`] owns the wait, the drain and the
/// framing. This thread supplies the delivery under the device lock, the
/// interrupt and the kick.
fn spawn_net_gateway_reader(
    reader: std::os::unix::net::UnixStream,
    dev: Arc<Mutex<VirtioNet>>,
    mem: Arc<GuestRam>,
    vm: VmGic,
    handles: Arc<Mutex<Vec<VcpuHandle>>>,
    stop: StopToken,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let relayed = crate::virtio_net::GatewayRelay::new(reader).run(&stop, |frame| {
            let level = {
                let mut d = lock_or_recover(&dev);
                d.deliver(&mem, frame);
                d.irq_level()
            };
            let _ = vm.gic_set_spi(VIRTIO_NET_INTID, level);
            kick_all(&vm, &handles);
        });
        if let Err(e) = relayed {
            eprintln!("[hvi] virtio-net: {e}; gateway relay stopped");
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
    handles: Arc<Mutex<Vec<VcpuHandle>>>,
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
            kick_all(&vm, &handles);
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

/// Sends the kick signal to `thread` until it has exited or `deadline` passes.
///
/// The console reader can be blocked in a read of stdin, a descriptor it shares
/// with the rest of the process, where the stop token cannot reach it. The
/// signal ends the read with `EINTR`; it is repeated because a signal that
/// lands before the read blocks is lost. A wait the signal cannot end, such as
/// a plugin blocking in `request`, ends the loop at the deadline instead.
fn kick_until_finished(thread: &JoinHandle<()>, deadline: std::time::Instant) {
    use std::os::unix::thread::JoinHandleExt;
    while !thread.is_finished() && std::time::Instant::now() < deadline {
        // SAFETY: the handle has not been joined, so its thread id is live;
        // the handler is a no-op. The cast is for musl, where std and libc
        // spell `pthread_t` differently.
        unsafe { libc::pthread_kill(thread.as_pthread_t() as libc::pthread_t, KICK_SIGNAL) };
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Installs a no-op handler for the kick signal.
///
/// The handler is installed without `SA_RESTART`, so a blocking call the signal
/// interrupts returns `EINTR` instead of resuming: the console reader's read of
/// stdin.
fn install_kick_handler() {
    extern "C" fn noop(_: libc::c_int) {}
    // SAFETY: installing a trivial signal handler before the helper threads
    // exist.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = noop as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(KICK_SIGNAL, &sa, std::ptr::null_mut());
    }
}

/// Reads host stdin and feeds it to the guest UART, raising the UART's GIC
/// line.
///
/// With a plugin attached, [`REQUEST_KEY`] is intercepted and asks it for an
/// observation instead of reaching the guest; with no plugin the key is an
/// ordinary byte, so a run with no plugin passes stdin through untouched.
fn spawn_input_thread(
    vm: VmGic,
    pl011: Arc<Mutex<Pl011>>,
    plugin: Option<Arc<dyn Plugin>>,
    handles: Arc<Mutex<Vec<VcpuHandle>>>,
    stop: StopToken,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut byte = [0u8; 1];
        loop {
            match stop.wait(stdin.as_fd()) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    eprintln!("[hvi] console: {e}; console input stopped");
                    break;
                }
            }
            // SAFETY: reading one byte from fd 0.
            let n = unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                // The kick signal: the stop is seen at the top of the loop.
                continue;
            }
            if n <= 0 {
                break;
            }
            if byte[0] == REQUEST_KEY {
                if let Some(obs) = &plugin {
                    obs.request();
                    kick_all(&vm, &handles);
                    continue;
                }
            }
            let level = {
                let mut p = lock_or_recover(&pl011);
                p.push_rx(byte[0]);
                p.irq_level()
            };
            let _ = vm.gic_set_spi(UART_INTID, level);
        }
    })
}

/// Kicks every registered vCPU out of `run()`.
fn kick_all(vm: &VmGic, handles: &Arc<Mutex<Vec<VcpuHandle>>>) {
    if let Ok(h) = handles.lock() {
        let _ = vm.vcpus_exit(h.as_slice());
    }
}

/// Reads general-purpose register `idx` (31 = XZR, reads as 0).
fn read_gpr(vcpu: &impl VcpuRegs, idx: u8) -> u64 {
    gpr(idx).map_or(0, |r| vcpu.get(r))
}

/// Writes `value` to general-purpose register `idx` (31 = XZR, discarded).
fn write_gpr(vcpu: &impl VcpuRegs, idx: u8, value: u64) {
    if let Some(r) = gpr(idx) {
        vcpu.set(r, value);
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

/// Puts stdin into raw mode for the guest console, restoring it on drop. A
/// no-op (returns `None`) when stdin is not a tty (detached/backend mode).
struct RawTerm {
    orig: libc::termios,
}

impl RawTerm {
    fn enable() -> Option<RawTerm> {
        // SAFETY: fd 0; termios is POD; calls are checked.
        unsafe {
            if libc::isatty(0) == 0 {
                return None;
            }
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut orig) != 0 {
                return None;
            }
            let mut raw = orig;
            libc::cfmakeraw(&mut raw);
            if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
                return None;
            }
            Some(RawTerm { orig })
        }
    }
}

impl Drop for RawTerm {
    fn drop(&mut self) {
        // SAFETY: restoring the saved settings on fd 0.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.orig);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Both entry states name the exception level they claim, with DAIF
    /// masked and SP_ELx selected. A guest that owns EL2 but enters at EL1
    /// reports "HYP mode not available" and gets no /dev/kvm.
    #[test]
    fn entry_cpsr_names_the_exception_level() {
        assert_eq!(entry_cpsr(false) & 0xf, 0b0101, "EL1h");
        assert_eq!(entry_cpsr(true) & 0xf, 0b1001, "EL2h");
        for cpsr in [entry_cpsr(false), entry_cpsr(true)] {
            assert_eq!(cpsr & 0x3c0, 0x3c0, "DAIF masked");
        }
    }

    fn cnthctl(is_read: bool) -> SysRegAccess {
        SysRegAccess {
            reg: esr::CNTHCTL_EL2,
            rt: 0,
            is_read,
        }
    }

    /// The guest's hypervisor at EL2 reads and writes CNTHCTL_EL2 through
    /// the VMM; RAZ/WI there hangs its kernel before the console.
    #[test]
    fn cnthctl_el2_is_served_at_el2() {
        for is_read in [true, false] {
            assert!(matches!(
                el2_sysreg(CPSR_EL2H, cnthctl(is_read)),
                Some(SysReg::CNTHCTL_EL2)
            ));
        }
    }

    /// The same access from EL1 or EL0 is not the guest's hypervisor. It
    /// must not reach the register, or a nested guest could change the timer
    /// control of the hypervisor running it.
    #[test]
    fn cnthctl_el2_is_not_served_below_el2() {
        let el0t = 0x3c0;
        for cpsr in [CPSR_EL1H, el0t] {
            for is_read in [true, false] {
                assert!(el2_sysreg(cpsr, cnthctl(is_read)).is_none());
            }
        }
    }

    /// Any other register at EL2 keeps the RAZ/WI path.
    #[test]
    fn other_sysregs_at_el2_stay_raz_wi() {
        let cntp_ctl_el0 = SysRegAccess {
            reg: (3, 3, 14, 2, 1),
            rt: 0,
            is_read: true,
        };
        assert!(el2_sysreg(CPSR_EL2H, cntp_ctl_el0).is_none());
    }

    /// A register file over two maps, standing in for a vCPU.
    #[derive(Default)]
    struct FakeRegs {
        regs: std::cell::RefCell<std::collections::HashMap<Reg, u64>>,
        sys: std::cell::RefCell<std::collections::HashMap<SysReg, u64>>,
    }

    impl VcpuRegs for FakeRegs {
        fn get(&self, reg: Reg) -> u64 {
            self.regs.borrow().get(&reg).copied().unwrap_or(0)
        }
        fn set(&self, reg: Reg, value: u64) {
            self.regs.borrow_mut().insert(reg, value);
        }
        fn get_sys(&self, reg: SysReg) -> u64 {
            self.sys.borrow().get(&reg).copied().unwrap_or(0)
        }
        fn set_sys(&self, reg: SysReg, value: u64) -> Result<(), String> {
            self.sys.borrow_mut().insert(reg, value);
            Ok(())
        }
    }

    /// `msr cnthctl_el2, x3` then `mrs x5, cnthctl_el2`, from `cpsr`.
    fn write_then_read(nested_virt: bool, cpsr: u64) -> (Option<u64>, u64) {
        let vcpu = FakeRegs::default();
        vcpu.set(Reg::CPSR, cpsr);
        vcpu.set(Reg::X3, 0x3);
        vcpu.set(Reg::X5, 0xffff);
        let access = |rt, is_read| SysRegAccess {
            reg: esr::CNTHCTL_EL2,
            rt,
            is_read,
        };
        let unknown = UnknownEl2Traps::default();
        assert!(service_sysreg(&vcpu, nested_virt, access(3, false), &unknown).is_none());
        let kept = vcpu.sys.borrow().get(&SysReg::CNTHCTL_EL2).copied();
        assert!(service_sysreg(&vcpu, nested_virt, access(5, true), &unknown).is_none());
        (kept, vcpu.get(Reg::X5))
    }

    /// With the guest owning EL2, its hypervisor's write reaches the vCPU's
    /// register and its read gets that value back.
    #[test]
    fn nested_guest_at_el2_keeps_cnthctl_el2() {
        assert_eq!(write_then_read(true, CPSR_EL2H), (Some(0x3), 0x3));
    }

    /// Without --nested-virt the register is RAZ/WI, as every unmodeled one
    /// is: nothing is written and the read gives 0.
    #[test]
    fn default_guest_gets_raz_wi_for_cnthctl_el2() {
        assert_eq!(write_then_read(false, CPSR_EL2H), (None, 0));
    }

    /// The same access from EL1 is RAZ/WI too, even with the guest owning
    /// EL2.
    #[test]
    fn nested_guest_at_el1_gets_raz_wi_for_cnthctl_el2() {
        assert_eq!(write_then_read(true, CPSR_EL1H), (None, 0));
    }

    /// The boot vCPU and a CPU_ON secondary enter with the same PSTATE, for
    /// either kind of guest. A secondary at EL1 beside a boot vCPU at EL2 is
    /// the "inconsistent modes" boot that leaves KVM off.
    #[test]
    fn boot_and_cpu_on_enter_at_the_same_level() {
        let cpsr_of = |regs: Vec<(Reg, u64)>| {
            regs.into_iter()
                .find(|(r, _)| *r == Reg::CPSR)
                .map(|(_, v)| v)
        };
        for nested_virt in [false, true] {
            let boot = entry_regs(Entry::Boot { kernel: 1, dtb: 2 }, nested_virt);
            let cpu_on = entry_regs(Entry::CpuOn { entry: 3, ctx: 4 }, nested_virt);
            assert_eq!(cpsr_of(boot), Some(entry_cpsr(nested_virt)));
            assert_eq!(cpsr_of(cpu_on), Some(entry_cpsr(nested_virt)));
        }
        let cpu_on = entry_regs(Entry::CpuOn { entry: 3, ctx: 4 }, false);
        assert!(cpu_on.contains(&(Reg::PC, 3)) && cpu_on.contains(&(Reg::X0, 4)));
    }

    /// `LORC_EL1` and `MDCCINT_EL1`, which Linux touched from EL2 on the
    /// hardware tried and hvi leaves RAZ/WI.
    const LORC_EL1: esr::SysRegEncoding = (3, 0, 10, 4, 3);
    const MDCCINT_EL1: esr::SysRegEncoding = (2, 0, 0, 2, 0);

    fn sysreg(reg: esr::SysRegEncoding, rt: u8, is_read: bool) -> SysRegAccess {
        SysRegAccess { reg, rt, is_read }
    }

    /// An unmodelled access from the guest's EL2 is logged the first time
    /// its encoding is seen and never again that boot, in either direction.
    /// It still reads as zero.
    #[test]
    fn unknown_el2_access_is_logged_once_per_encoding() {
        let vcpu = FakeRegs::default();
        vcpu.set(Reg::CPSR, CPSR_EL2H);
        vcpu.set(Reg::X4, 0xffff);
        let unknown = UnknownEl2Traps::default();
        let first = service_sysreg(&vcpu, true, sysreg(LORC_EL1, 31, false), &unknown);
        let line = first.expect("the first LORC_EL1 access is logged");
        assert!(line.contains("write of S3_0_C10_C4_3"), "{line}");
        assert!(service_sysreg(&vcpu, true, sysreg(LORC_EL1, 31, false), &unknown).is_none());
        assert!(service_sysreg(&vcpu, true, sysreg(LORC_EL1, 4, true), &unknown).is_none());
        assert_eq!(vcpu.get(Reg::X4), 0, "an unlogged read is still RAZ");
        let other = service_sysreg(&vcpu, true, sysreg(MDCCINT_EL1, 4, true), &unknown);
        assert!(other
            .expect("a new encoding is logged")
            .contains("read of S2_0_C0_C2_0"));
    }

    /// Nothing is logged for a register hvi serves, for an access from
    /// EL1, or for a guest that does not own EL2.
    #[test]
    fn only_unmodelled_el2_accesses_of_a_nested_guest_are_logged() {
        let unknown = UnknownEl2Traps::default();
        let at = |cpsr| {
            let vcpu = FakeRegs::default();
            vcpu.set(Reg::CPSR, cpsr);
            vcpu
        };
        let served = sysreg(esr::CNTHCTL_EL2, 3, false);
        assert!(service_sysreg(&at(CPSR_EL2H), true, served, &unknown).is_none());
        assert!(
            service_sysreg(&at(CPSR_EL1H), true, sysreg(LORC_EL1, 3, false), &unknown).is_none()
        );
        assert!(
            service_sysreg(&at(CPSR_EL2H), false, sysreg(LORC_EL1, 3, false), &unknown).is_none()
        );
        // None of the above used up LORC_EL1's one line.
        assert!(
            service_sysreg(&at(CPSR_EL2H), true, sysreg(LORC_EL1, 3, false), &unknown).is_some()
        );
    }

    const EL0T: u64 = 0x3c0;

    /// The path the guest's nVHE host kernel takes: SMC from EL1 with TSC
    /// clear. It is served, and so is anything from the guest's EL2.
    #[test]
    fn psci_from_the_guest_hypervisor_or_its_host_is_served() {
        assert!(psci_is_ours(true, Ec::Smc, CPSR_EL1H, 0));
        for hcr in [0, HCR_EL2_TSC] {
            assert!(psci_is_ours(true, Ec::Smc, CPSR_EL2H, hcr));
            assert!(psci_is_ours(true, Ec::Hvc, CPSR_EL2H, hcr));
        }
    }

    /// An HVC from EL1, or an SMC from EL1 with TSC set, belongs to the
    /// guest's own hypervisor and is refused if it ever reaches hvi.
    #[test]
    fn psci_meant_for_the_guest_hypervisor_is_refused() {
        assert!(!psci_is_ours(true, Ec::Smc, CPSR_EL1H, HCR_EL2_TSC));
        assert!(!psci_is_ours(true, Ec::Smc, EL0T, HCR_EL2_TSC));
        assert!(!psci_is_ours(true, Ec::Hvc, CPSR_EL1H, 0));
        assert!(!psci_is_ours(true, Ec::Hvc, CPSR_EL1H, HCR_EL2_TSC));
        assert_eq!(refused_psci_step(Ec::Smc), 4);
        assert_eq!(refused_psci_step(Ec::Hvc), 0);
    }

    /// A guest at EL1 is unchanged: its HVC PSCI is served whatever a
    /// meaningless HCR_EL2 read says.
    #[test]
    fn psci_of_a_guest_without_el2_is_always_served() {
        for hcr in [0, HCR_EL2_TSC] {
            assert!(psci_is_ours(false, Ec::Hvc, CPSR_EL1H, hcr));
            assert!(psci_is_ours(false, Ec::Smc, CPSR_EL1H, hcr));
        }
    }
}

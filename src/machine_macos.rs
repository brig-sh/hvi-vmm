//! Boot an arm64 Linux guest and run it, SMP-capable.
//!
//! One thread per vCPU (an `applevisor::Vcpu` is thread-bound). cpu0 boots at
//! the kernel entry; secondaries park until the guest brings them up via PSCI
//! `CPU_ON`. Guest RAM is a `Send + Sync` `GuestRam` over the host mapping;
//! devices, the event emitter, and the vCPU-handle list are shared behind
//! locks. A plugin, if the caller supplied one, is called on cpu0 between
//! guest entries — see [`crate::plugin`].
//!
//! The exit-loop's timer/WFI/PC handling and the SMP hand-off are the
//! boot-debug frontier.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use applevisor::prelude::{
    ExitReason, GicConfig, GicEnabled, Reg, SysReg, Vcpu, VcpuHandle, VirtualMachine,
    VirtualMachineConfig, VirtualMachineInstance,
};

use crate::boot::Arm64Image;
use crate::config::{BootConfig, Stop};
use crate::esr::{DataAbort, Ec};
use crate::events::Emitter;
use crate::fdt;
use crate::guestmem::GuestRam;
use crate::layout::{
    virtio_fs_base, virtio_fs_spi, GicLayout, GicVersion, GuestLayout, RAM_BASE, UART_BASE,
    UART_SIZE, UART_SPI, VIRTIO_BASE, VIRTIO_NET_BASE, VIRTIO_NET_SPI, VIRTIO_SIZE, VIRTIO_SPI,
    VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_SPI,
};
use crate::pl011::Pl011;
use crate::plugin::{CpuHandle, GuestArch, IoSink, MemRegion, Plugin, RegsView, VmHandle};
use crate::virtio::{reg, VirtioBlk};
use crate::virtio_fs::VirtioFs;
use crate::virtio_net::VirtioNet;
use crate::virtio_vsock::VirtioVsock;

/// The VM handle once the GICv3 is configured (Send/Sync; cloned per thread).
type VmGic = VirtualMachineInstance<GicEnabled>;

/// Host key that asks the plugin for an observation now: Ctrl-] (GS, 0x1d).
const REQUEST_KEY: u8 = 0x1d;
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
    woken: Mutex<bool>,
    ready: Condvar,
}

impl FsWake {
    fn new() -> Self {
        Self {
            woken: Mutex::new(false),
            ready: Condvar::new(),
        }
    }

    /// Signals the worker. Safe to call whether or not it is currently
    /// parked -- a signal that arrives mid-drain is simply picked up on the
    /// worker's next pass, never lost.
    fn wake(&self) {
        let mut woken = self.woken.lock().unwrap();
        *woken = true;
        self.ready.notify_one();
    }

    /// Blocks until the next [`FsWake::wake`], then clears the flag. Never
    /// called with the virtio-fs device mutex held -- this is purely the
    /// wake signal, independent of the device's own lock.
    fn park(&self) {
        let mut woken = self.woken.lock().unwrap();
        while !*woken {
            woken = self.ready.wait(woken).unwrap();
        }
        *woken = false;
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
    /// Guest RAM's shareable descriptor and extent, for a plugin that hands
    /// the same pages to another process.
    ram_fd: std::os::fd::RawFd,
    ram_len: u64,
    sandbox_id: String,
}

/// Boots `cfg` and runs until the guest powers off.
pub fn boot(cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error>> {
    let img = Arm64Image::parse(&cfg.kernel)?;
    let kernel_size = img.reserved_size(cfg.kernel.len() as u64);
    let initrd_len = cfg.initramfs.as_ref().map_or(0, |v| v.len() as u64);
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

    let mut gic_config = GicConfig::new();
    gic_config.set_distributor_base(gic.gicd_base)?;
    gic_config.set_redistributor_base(gic.gicr_base)?;
    let vm = VirtualMachine::with_gic(VirtualMachineConfig::new(), gic_config)?;

    // Guest RAM: one region mapped at RAM_BASE, allocated from a shareable
    // object rather than by applevisor, so an out-of-process plugin can
    // map the same pages. applevisor's memory_create uses hv_vm_allocate, which
    // hands back a pointer with no nameable backing object; hv_vm_map accepts
    // any page-aligned host pointer, so we allocate and map it ourselves. This
    // is the path `hvi smoke --shm` exercises.
    let guest_ram = crate::sharedmem::SharedRam::new(cfg.mem_bytes as usize)?;
    // SAFETY: `mem` is a live, page-aligned mapping of `mem.len()` bytes that
    // outlives the VM (dropped at the end of `boot`).
    let ret = unsafe {
        applevisor_sys::hv_vm_map(
            guest_ram.as_ptr().cast::<std::ffi::c_void>(),
            RAM_BASE,
            guest_ram.len(),
            applevisor_sys::HV_MEMORY_READ
                | applevisor_sys::HV_MEMORY_WRITE
                | applevisor_sys::HV_MEMORY_EXEC,
        )
    };
    if ret != 0 {
        return Err(format!("hv_vm_map(guest RAM -> {RAM_BASE:#x}) failed: {ret:#x}").into());
    }
    let ram = Arc::new(GuestRam::new(guest_ram.as_ptr(), RAM_BASE, guest_ram.len()));

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
                    Some(Arc::new(Mutex::new(VirtioNet::with_gateway(stream))))
                }
                Err(e) => {
                    eprintln!("[hvi] WARNING: cannot clone gateway socket ({e}); net disabled");
                    None
                }
            },
            Err(e) => {
                eprintln!("[hvi] WARNING: cannot reach gateway {sock} ({e}); falling back to built-in stack");
                Some(Arc::new(Mutex::new(VirtioNet::new())))
            }
        }
    } else if cfg.net {
        eprintln!("[hvi] virtio-net: user-space (guest 10.0.2.15, gw 10.0.2.2, DHCP)");
        Some(Arc::new(Mutex::new(VirtioNet::new())))
    } else {
        None
    };
    let vsock = cfg.agent_sock.as_ref().map(|sock| {
        eprintln!("[hvi] virtio-vsock: agent bridge on {sock} (guest cid 3, port 1024)");
        Arc::new(Mutex::new(VirtioVsock::new()))
    });
    // Bind before Seatbelt is installed. Accepting on this already-open
    // listener remains allowed afterwards; acquiring a new socket does not.
    let agent_listener = match &cfg.agent_sock {
        Some(path) => {
            let _ = std::fs::remove_file(path);
            Some(
                std::os::unix::net::UnixListener::bind(path)
                    .map_err(|e| format!("bind agent socket {path}: {e}"))?,
            )
        }
        None => None,
    };
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
        if end > gic.gicd_base {
            return Err("virtio-fs MMIO devices would overlap the GIC".into());
        }
        let root = std::fs::canonicalize(&share.path)?;
        let access = if share.mode.writable() {
            "read-write"
        } else {
            "read-only"
        };
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

    // Two DTB passes: its length feeds the initramfs placement.
    let provisional = GuestLayout::new(
        cfg.mem_bytes,
        img.text_offset,
        kernel_size,
        0x4000,
        initrd_len,
    );
    let dtb0 = fdt::build(&provisional, &gic, num_cpus, &cfg.cmdline, fdt_devices)?;
    let layout = GuestLayout::new(
        cfg.mem_bytes,
        img.text_offset,
        kernel_size,
        dtb0.len() as u64,
        initrd_len,
    );
    let dtb = fdt::build(&layout, &gic, num_cpus, &cfg.cmdline, fdt_devices)?;
    layout.validate()?;

    ram.write(layout.kernel_addr, &cfg.kernel)?;
    ram.write(layout.dtb_addr, &dtb)?;
    if let Some(initramfs) = &cfg.initramfs {
        ram.write(layout.initrd_addr, initramfs)?;
    }

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
        ram_fd: guest_ram.fd(),
        ram_len: guest_ram.len() as u64,
        sandbox_id: cfg.sandbox_id.clone(),
        num_cpus,
    };

    // Hand the plugin the guest before any vCPU runs, so nothing happens
    // between the first instruction and the attach.
    if let Some(obs) = &shared.plugin {
        obs.attach(Arc::new(shared.clone()) as Arc<dyn VmHandle>)?;
    }

    // Host-side helper: keystrokes -> UART RX. Kicks vCPUs via the shared
    // handle list (never touches guest RAM).
    spawn_input_thread(
        vm.clone(),
        Arc::clone(&shared.pl011),
        shared.plugin.clone(),
        Arc::clone(&shared.handles),
    );
    if let (Some(listener), Some(dev)) = (agent_listener, &shared.vsock) {
        spawn_vsock_bridge(
            listener,
            Arc::clone(dev),
            Arc::clone(&shared.mem),
            vm.clone(),
            Arc::clone(&shared.handles),
        );
    }
    if let (Some(reader), Some(dev)) = (net_reader, &shared.net) {
        spawn_net_gateway_reader(
            reader,
            Arc::clone(dev),
            Arc::clone(&shared.mem),
            vm.clone(),
            Arc::clone(&shared.handles),
        );
    }
    // Stage A: each virtio-fs device gets its own worker thread so FUSE
    // servicing (every host pread/pwrite/stat/getxattr the guest's requests
    // need) never runs on a vCPU thread. See `spawn_fs_worker`.
    for fs in &shared.fs {
        spawn_fs_worker(
            Arc::clone(&fs.dev),
            fs.intid,
            Arc::clone(&shared.mem),
            vm.clone(),
            Arc::clone(&shared.handles),
            Arc::clone(&fs.wake),
        );
    }
    let _raw = RawTerm::enable();

    // Confine the process. Deliberately the last line before the guest runs:
    // everything above acquires host authority (the VM, the guest-RAM mapping,
    // the block file, the ledger, the gateway connection, the listeners, the
    // terminal), everything below only services guest I/O with what is already
    // open. See `sandbox`.
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

    let stop = shared.stop.lock().unwrap().unwrap_or(Stop::SystemOff);
    Ok(stop)
}

/// A single vCPU: create it, position it (boot entry, or wait for CPU_ON), and
/// run its exit loop until the VM stops.
fn run_cpu(cpu_id: u32, sh: Shared) {
    let vcpu = match sh.vm.vcpu_create() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[hvi] cpu{cpu_id}: vcpu_create failed: {e:?}");
            return;
        }
    };
    let _ = vcpu.set_trap_debug_exceptions(false);
    let _ = vcpu.set_trap_debug_reg_accesses(false);
    // GICv3 affinity: aff0 = cpu id, RES1 bit 31 set.
    let _ = vcpu.set_sys_reg(SysReg::MPIDR_EL1, 0x8000_0000 | u64::from(cpu_id));
    sh.handles.lock().unwrap().push(vcpu.get_handle());

    if cpu_id == 0 {
        let _ = vcpu.set_reg(Reg::PC, sh.kernel_addr);
        let _ = vcpu.set_reg(Reg::X0, sh.dtb_addr);
        let _ = vcpu.set_reg(Reg::X1, 0);
        let _ = vcpu.set_reg(Reg::X2, 0);
        let _ = vcpu.set_reg(Reg::X3, 0);
        let _ = vcpu.set_reg(Reg::CPSR, 0x3c5); // EL1h, DAIF masked
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
                let _ = vcpu.set_reg(Reg::PC, entry);
                let _ = vcpu.set_reg(Reg::X0, ctx);
                let _ = vcpu.set_reg(Reg::CPSR, 0x3c5);
            }
            None => return, // stopped while waiting
        }
    }

    let is_boot = cpu_id == 0;
    while sh.running.load(Ordering::SeqCst) {
        // Safe point for every vCPU: park here while cpu0 lets a plugin
        // look at the guest.
        sh.quiesce.checkpoint();
        // The plugin runs on cpu0, between guest entries, because only this
        // thread can read this vCPU's registers. It is on the hot path: with
        // no plugin this is a null check.
        if is_boot {
            if let Some(obs) = sh.plugin.clone() {
                obs.safepoint(&Cpu {
                    vcpu: &vcpu,
                    sh: &sh,
                });
            }
        }

        if vcpu.run().is_err() {
            break;
        }
        let exit = vcpu.get_exit_info();
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
                                service_dev(&vcpu, &sh, dev, VIRTIO_INTID, ipa - VIRTIO_BASE, syn);
                            }
                            advance_pc(&vcpu);
                        } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&ipa) {
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
                            if is_boot {
                                stop_all(&sh);
                            }
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
                            "[hvi] cpu{cpu_id}: unhandled exception {other:?} (pc {:#x})",
                            vcpu.get_reg(Reg::PC).unwrap_or(0)
                        );
                        if is_boot {
                            stop_all(&sh);
                        }
                        break;
                    }
                }
            }
            ExitReason::VTIMER_ACTIVATED => {
                let _ = vcpu.set_vtimer_mask(true);
            }
            ExitReason::CANCELED => {} // kicked for a snapshot or a stop
            ExitReason::UNKNOWN => break,
        }
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

    fn ram_fd(&self) -> std::os::fd::RawFd {
        self.ram_fd
    }

    fn ram_regions(&self) -> Vec<MemRegion> {
        // One region: this backend maps all of guest RAM at RAM_BASE from the
        // start of the shareable object.
        vec![MemRegion {
            gpa: RAM_BASE,
            size: self.ram_len,
            file_offset: 0,
        }]
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
            *sh.stop.lock().unwrap() = Some(Stop::SystemOff);
            stop_all(sh);
            true
        }
        psci::SYSTEM_RESET => {
            *sh.stop.lock().unwrap() = Some(Stop::SystemReset);
            stop_all(sh);
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
            let ret = if idx != 0 && idx < sh.num_cpus as usize {
                let sec = &sh.secondaries[idx];
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

/// Signals all vCPUs to stop and kicks them out of `run()`.
fn stop_all(sh: &Shared) {
    sh.running.store(false, Ordering::SeqCst);
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
        let mut p = sh.pl011.lock().unwrap();
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
        let mut d = dev.lock().unwrap();
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
        let mut e = sh.emit.lock().unwrap();
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
        let mut d = dev.lock().unwrap();
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
        let mut e = sh.emit.lock().unwrap();
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
        let mut d = dev.lock().unwrap();
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
        let mut d = fs.dev.lock().unwrap();
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
            let mut d = fs.dev.lock().unwrap();
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
fn spawn_vsock_bridge(
    listener: std::os::unix::net::UnixListener,
    dev: Arc<Mutex<VirtioVsock>>,
    mem: Arc<GuestRam>,
    vm: VmGic,
    handles: Arc<Mutex<Vec<VcpuHandle>>>,
) {
    std::thread::spawn(move || {
        eprintln!("[hvi] vsock bridge: listening");
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(reader) = stream.try_clone() else {
                continue;
            };

            // Register the connection and send the guest agent a REQUEST.
            let mut d = dev.lock().unwrap();
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
            std::thread::spawn(move || {
                let mut reader = reader;
                let mut buf = [0u8; 8192];
                loop {
                    let n = match crate::virtio_vsock::read_host(&mut reader, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let level = {
                        let mut d = dev2.lock().unwrap();
                        d.host_data(&mem2, port, &buf[..n]);
                        d.irq_level()
                    };
                    let _ = vm2.gic_set_spi(VIRTIO_VSOCK_INTID, level);
                    kick_all(&vm2, &handles2);
                }
                let level = {
                    let mut d = dev2.lock().unwrap();
                    d.host_closed(&mem2, port);
                    d.irq_level()
                };
                let _ = vm2.gic_set_spi(VIRTIO_VSOCK_INTID, level);
                kick_all(&vm2, &handles2);
            });
        }
    });
}

/// Reads gateway->guest Ethernet frames (4-byte big-endian length prefix, the
/// gvisor-tap-vsock QEMU stream protocol) and injects each into the guest RX
/// queue under the device lock, raising the net GIC line and kicking the vCPUs.
/// Exits when the gateway closes the connection.
fn spawn_net_gateway_reader(
    mut reader: std::os::unix::net::UnixStream,
    dev: Arc<Mutex<VirtioNet>>,
    mem: Arc<GuestRam>,
    vm: VmGic,
    handles: Arc<Mutex<Vec<VcpuHandle>>>,
) {
    use std::io::Read;
    std::thread::spawn(move || {
        let mut hdr = [0u8; 4];
        loop {
            if reader.read_exact(&mut hdr).is_err() {
                break; // gateway closed
            }
            let len = u32::from_be_bytes(hdr) as usize;
            if len == 0 || len > 65_536 {
                continue; // ignore keepalives / implausible frames
            }
            let mut frame = vec![0u8; len];
            if reader.read_exact(&mut frame).is_err() {
                break;
            }
            let level = {
                let mut d = dev.lock().unwrap();
                d.deliver(&mem, &frame);
                d.irq_level()
            };
            let _ = vm.gic_set_spi(VIRTIO_NET_INTID, level);
            kick_all(&vm, &handles);
        }
    });
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
/// Shutdown: like the vsock bridge and the net gateway reader, this runs
/// until the process exits. There is no VM teardown path today for any of
/// the host-side bridge threads to hook into, so this does not invent one.
fn spawn_fs_worker(
    dev: Arc<Mutex<VirtioFs>>,
    intid: u32,
    mem: Arc<GuestRam>,
    vm: VmGic,
    handles: Arc<Mutex<Vec<VcpuHandle>>>,
    wake: Arc<FsWake>,
) {
    std::thread::spawn(move || loop {
        wake.park();
        {
            let mut d = dev.lock().unwrap();
            d.drain_notified(&mem);
            // Raised under the same mutex the vCPU's INTERRUPT_ACK takes, so
            // the two cannot interleave into a low line over a non-empty
            // used ring -- see the matching comment in `service_fs`.
            let _ = vm.gic_set_spi(intid, d.irq_level());
        }
        // Outside the lock: `kick_all` takes the vCPU-handle mutex, and it
        // does not need to be atomic with the line, only to follow it.
        kick_all(&vm, &handles);
    });
}

/// Zero-extension mask for a load of `width` bytes.
fn width_mask(width: u8) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (width * 8)) - 1
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
) {
    std::thread::spawn(move || {
        let mut byte = [0u8; 1];
        loop {
            let n = unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
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
                let mut p = pl011.lock().unwrap();
                p.push_rx(byte[0]);
                p.irq_level()
            };
            let _ = vm.gic_set_spi(UART_INTID, level);
        }
    });
}

/// Kicks every registered vCPU out of `run()`.
fn kick_all(vm: &VmGic, handles: &Arc<Mutex<Vec<VcpuHandle>>>) {
    if let Ok(h) = handles.lock() {
        let _ = vm.vcpus_exit(h.as_slice());
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

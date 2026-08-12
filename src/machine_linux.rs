//! Boot an arm64 Linux guest on KVM (Linux host) and run it, SMP-capable.
//!
//! The Linux counterpart of `machine_macos`. KVM gives us an **in-kernel
//! GIC** and **in-kernel PSCI**, so this backend is structurally simpler than
//! the hvf one: secondaries are created `POWER_OFF` and brought up by the
//! guest's own PSCI `CPU_ON` (handled entirely in-kernel — no mailbox), and
//! interrupts are a single `set_irq_line`, which also wakes a WFI'd vCPU (no
//! explicit kick for delivery). We only signal-kick a vCPU to (a) get cpu0 to
//! its next safe point, where a plugin runs, and (b) break secondaries out
//! of `KVM_RUN` at shutdown.
//!
//! Everything else — image/layout/DTB, virtio devices, PL011, the RawEvent
//! ledger, and the plugin seam — is the same hypervisor-agnostic code the
//! macOS backend uses.
//!
//! The GIC version is negotiated, not chosen: KVM's vGIC borrows the host's CPU
//! interface, so a GICv3 host serves vGICv3 and a GIC-400 host serves vGICv2
//! only. We ask for v3 and fall back to v2, laying out the DTB to match.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    kvm_create_device, kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
    kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, kvm_userspace_memory_region, kvm_vcpu_init,
    KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2, KVM_DEV_ARM_VGIC_CTRL_INIT,
    KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
    KVM_SYSTEM_EVENT_RESET, KVM_VGIC_V2_ADDR_TYPE_CPU, KVM_VGIC_V2_ADDR_TYPE_DIST,
    KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};

use crate::boot::Arm64Image;
use crate::config::{BootConfig, Stop};
use crate::events::Emitter;
use crate::fdt;
use crate::guestmem::GuestRam;
use crate::layout::{
    GicLayout, GicVersion, GuestLayout, RAM_BASE, UART_BASE, UART_SIZE, UART_SPI, VIRTIO_BASE,
    VIRTIO_NET_BASE, VIRTIO_NET_SPI, VIRTIO_SIZE, VIRTIO_SPI, VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_SPI,
};
use crate::pl011::Pl011;
use crate::plugin::{CpuHandle, GuestArch, IoSink, MemRegion, Plugin, RegsView, VmHandle};
use crate::virtio::VirtioBlk;
use crate::virtio_net::VirtioNet;
use crate::virtio_vsock::VirtioVsock;

// --- ONE_REG ids (architectural KVM ABI, aarch64). ---------------
// Core regs: KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE |
// (byte_off/4).
const REG_X0: u64 = 0x6030_0000_0010_0000;
const REG_PC: u64 = 0x6030_0000_0010_0040;
const REG_PSTATE: u64 = 0x6030_0000_0010_0042;
const REG_SP_EL1: u64 = 0x6030_0000_0010_0044;
// System regs: KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG | enc.
const REG_SCTLR_EL1: u64 = 0x6030_0000_0013_c080;
const REG_TTBR0_EL1: u64 = 0x6030_0000_0013_c100;
const REG_TTBR1_EL1: u64 = 0x6030_0000_0013_c101;
const REG_TCR_EL1: u64 = 0x6030_0000_0013_c102;
// SP_EL0 is a core register (user_pt_regs.sp), not a sysreg: Linux keeps
// `current` there while running in the kernel.
const REG_SP_EL0: u64 = 0x6030_0000_0010_003e;

/// PSTATE = EL1h + DAIF masked (the arm64 Linux boot-protocol entry state).
const PSTATE_EL1H_DAIF: u64 = 0x3c5;

/// Host key that asks the plugin for an observation now: Ctrl-] (GS, 0x1d).
const REQUEST_KEY: u8 = 0x1d;
/// Signal used to break a vCPU out of `KVM_RUN` (snapshot / shutdown).
const KICK_SIGNAL: libc::c_int = libc::SIGUSR1;

/// GICv3 architectural region sizes (KVM derives redist count from vCPUs, but
/// the DTB `reg` must describe the whole region).
const GICD_SIZE: u64 = 0x1_0000;
const GICR_FRAME: u64 = 0x2_0000; // per-vCPU redistributor frame

/// KVM GSI for SPI `spi` (our layout SPI number; INTID = 32 + spi).
fn spi_gsi(spi: u32) -> u32 {
    const KVM_ARM_IRQ_TYPE_SPI: u32 = 1;
    const KVM_ARM_IRQ_TYPE_SHIFT: u32 = 24;
    (KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) | (32 + spi)
}

fn set_u64(vcpu: &VcpuFd, id: u64, val: u64) {
    let _ = vcpu.set_one_reg(id, &val.to_le_bytes());
}
fn get_u64(vcpu: &VcpuFd, id: u64) -> u64 {
    let mut b = [0u8; 8];
    vcpu.get_one_reg(id, &mut b)
        .map(|_| u64::from_le_bytes(b))
        .unwrap_or(0)
}

/// State shared across vCPU threads and the helper threads.
#[derive(Clone)]
struct Shared {
    vm: Arc<VmFd>,
    mem: Arc<GuestRam>,
    pl011: Arc<Mutex<Pl011>>,
    virtio: Option<Arc<Mutex<VirtioBlk>>>,
    net: Option<Arc<Mutex<VirtioNet>>>,
    vsock: Option<Arc<Mutex<VirtioVsock>>>,
    emit: Arc<Mutex<Emitter>>,
    running: Arc<AtomicBool>,
    /// Per-vCPU pthread handles, for signal-kicks (index = cpu id).
    threads: Arc<Mutex<Vec<u64>>>,
    stop: Arc<Mutex<Option<Stop>>>,
    /// Parks every vCPU at a safe point so an observation sees a still guest.
    quiesce: Arc<crate::quiesce::Quiesce>,
    /// Whoever is watching this guest, if anyone.
    plugin: Option<Arc<dyn Plugin>>,
    /// Guest RAM's shareable descriptor and extent, for a plugin that hands
    /// the same pages to another process.
    ram_fd: std::os::fd::RawFd,
    ram_len: u64,
    sandbox_id: String,
    /// vCPU count, so a pause knows how many threads must park.
    num_cpus: u32,
}

/// Boots `cfg` on KVM and runs until the guest powers off.
pub fn boot(cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error>> {
    install_kick_handler();

    let img = Arm64Image::parse(&cfg.kernel)?;
    let kernel_size = img.reserved_size(cfg.kernel.len() as u64);
    let initrd_len = cfg.initramfs.as_ref().map_or(0, |v| v.len() as u64);
    let num_cpus = cfg.vcpus.max(1);

    let kvm = Kvm::new()?;
    let vm = kvm.create_vm()?;

    // The guest GIC has to be created before the DTB is built, because which
    // version we get decides what the DTB must describe — and we do not get to
    // choose. KVM's vGIC borrows the host's CPU interface, so a GICv3 host
    // serves vGICv3 while a GIC-400 host (Raspberry Pi 5 and most Cortex-A72/
    // A76 SoCs) serves vGICv2 only. Ask for v3 and fall back on failure: a
    // rejected KVM_CREATE_DEVICE creates nothing, so this costs one ioctl.
    //
    // Deliberately *not* KVM_CREATE_DEVICE_TEST: with that flag the kernel
    // leaves `fd` at 0, and kvm-ioctls would wrap descriptor 0 in a `DeviceFd`
    // that closes stdin when dropped.
    let (gicfd, version) = match vm.create_device(&mut kvm_create_device {
        type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
        fd: 0,
        flags: 0,
    }) {
        Ok(fd) => (fd, GicVersion::V3),
        Err(e) => {
            eprintln!("[hvi/kvm] vGICv3 unavailable ({e}); falling back to vGICv2");
            let fd = vm.create_device(&mut kvm_create_device {
                type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
                fd: 0,
                flags: 0,
            })?;
            (fd, GicVersion::V2)
        }
    };

    // Placement (QEMU virt values; the DTB and KVM must agree). Under v3 the
    // redistributor region spans one 128 KiB frame per vCPU; under v2 the CPU
    // interface is a single fixed window shared by every vCPU.
    let gic = match version {
        GicVersion::V3 => GicLayout {
            version,
            gicd_base: GicLayout::QEMU_VIRT.gicd_base,
            gicd_size: GICD_SIZE,
            gicr_base: GicLayout::QEMU_VIRT.gicr_base,
            gicr_size: u64::from(num_cpus) * GICR_FRAME,
        },
        GicVersion::V2 => GicLayout::QEMU_VIRT_V2,
    };
    if version == GicVersion::V2 && num_cpus > GicLayout::V2_MAX_CPUS {
        return Err(format!(
            "this host offers only vGICv2, which supports at most {} vCPUs (asked for {num_cpus})",
            GicLayout::V2_MAX_CPUS
        )
        .into());
    }
    eprintln!(
        "[hvi/kvm] {num_cpus} vCPU(s)  {:?}  GICD {:#x}+{:#x}  {} {:#x}+{:#x}",
        version,
        gic.gicd_base,
        gic.gicd_size,
        match version {
            GicVersion::V3 => "GICR",
            GicVersion::V2 => "GICC",
        },
        gic.gicr_base,
        gic.gicr_size
    );

    // Guest RAM: one anonymous mmap registered as a KVM memory slot; GuestRam
    // wraps its host pointer for shared access across threads.
    let size = cfg.mem_bytes as usize;
    // Guest RAM comes from a shareable object (a memfd) rather than an
    // anonymous private mapping, so an out-of-process plugin can map
    // the same pages. KVM only needs a valid host address, so the guest is
    // unaffected.
    let guest_ram = crate::sharedmem::SharedRam::new(size)?;
    let host = guest_ram.as_ptr().cast::<libc::c_void>();
    let region = kvm_userspace_memory_region {
        slot: 0,
        flags: 0,
        guest_phys_addr: RAM_BASE,
        memory_size: cfg.mem_bytes,
        userspace_addr: host as u64,
    };
    // SAFETY: `host` is a valid mapping of `size` bytes that outlives the VM.
    unsafe { vm.set_user_memory_region(region)? };
    let ram = Arc::new(GuestRam::new(host.cast::<u8>(), RAM_BASE, size));

    // Devices (same modules as the macOS backend).
    let virtio = match &cfg.disk {
        Some(path) => {
            eprintln!("[hvi/kvm] virtio-blk: {path}");
            Some(Arc::new(Mutex::new(VirtioBlk::open(path)?)))
        }
        None => None,
    };
    let mut net_reader: Option<std::os::unix::net::UnixStream> = None;
    let mut net_tap_reader: Option<std::fs::File> = None;
    let net = if let Some(ifname) = &cfg.net_tap {
        // urunc already created the tap and redirected the veth to it, so all
        // that is left is to attach -- that is what brings carrier up. An
        // unusable tap fails the boot: falling back to the built-in stack
        // would put the guest on the wrong network, which from the outside is
        // indistinguishable from success.
        let file = crate::tap::open(ifname).map_err(|e| format!("--net-tap {ifname}: {e}"))?;
        let reader = file
            .try_clone()
            .map_err(|e| format!("--net-tap {ifname}: cloning the tap fd: {e}"))?;
        eprintln!("[hvi/kvm] virtio-net: tap {ifname}");
        net_tap_reader = Some(reader);
        let mut dev = VirtioNet::with_tap(file);
        // The redirect hands us the veth's frames unchanged, so the guest has
        // to answer to the veth's MAC.
        match cfg.net_mac.as_deref().map(crate::tap::parse_mac) {
            Some(Some(mac)) => dev.set_mac(mac),
            Some(None) => {
                eprintln!("[hvi/kvm] WARNING: unparsable --net-mac; keeping the default");
            }
            None => {}
        }
        Some(Arc::new(Mutex::new(dev)))
    } else if let Some(sock) = &cfg.net_gateway {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(stream) => match stream.try_clone() {
                Ok(reader) => {
                    eprintln!("[hvi/kvm] virtio-net: gvisor-tap gateway relay via {sock}");
                    net_reader = Some(reader);
                    Some(Arc::new(Mutex::new(VirtioNet::with_gateway(stream))))
                }
                Err(_) => None,
            },
            Err(e) => {
                eprintln!("[hvi/kvm] WARNING: gateway {sock} unreachable ({e}); built-in stack");
                Some(Arc::new(Mutex::new(VirtioNet::new())))
            }
        }
    } else if cfg.net {
        Some(Arc::new(Mutex::new(VirtioNet::new())))
    } else {
        None
    };
    let vsock = cfg
        .agent_sock
        .as_ref()
        .map(|_| Arc::new(Mutex::new(VirtioVsock::new())));
    let has_blk = virtio.is_some();
    let has_net = net.is_some();
    let has_vsock = vsock.is_some();

    let emitter = Emitter::new(cfg.events.as_deref(), &cfg.sandbox_id)?;
    // Two DTB passes (its length feeds the initramfs placement).
    let provisional = GuestLayout::new(
        cfg.mem_bytes,
        img.text_offset,
        kernel_size,
        0x4000,
        initrd_len,
    );
    let dtb0 = fdt::build(
        &provisional,
        &gic,
        num_cpus,
        &cfg.cmdline,
        has_blk,
        has_net,
        has_vsock,
    )?;
    let layout = GuestLayout::new(
        cfg.mem_bytes,
        img.text_offset,
        kernel_size,
        dtb0.len() as u64,
        initrd_len,
    );
    let dtb = fdt::build(
        &layout,
        &gic,
        num_cpus,
        &cfg.cmdline,
        has_blk,
        has_net,
        has_vsock,
    )?;
    layout.validate()?;

    ram.write(layout.kernel_addr, &cfg.kernel)?;
    ram.write(layout.dtb_addr, &dtb)?;
    if let Some(initramfs) = &cfg.initramfs {
        ram.write(layout.initrd_addr, initramfs)?;
    }

    // Place the GIC regions (the device itself was created above, before the
    // DTB). The address-type constants differ per version, and v2 takes a CPU
    // interface where v3 takes a redistributor. NR_IRQS + INIT follow the vCPUs.
    match version {
        GicVersion::V3 => {
            set_gic_addr(&gicfd, KVM_VGIC_V3_ADDR_TYPE_DIST, gic.gicd_base)?;
            set_gic_addr(&gicfd, KVM_VGIC_V3_ADDR_TYPE_REDIST, gic.gicr_base)?;
        }
        GicVersion::V2 => {
            set_gic_addr(&gicfd, KVM_VGIC_V2_ADDR_TYPE_DIST, gic.gicd_base)?;
            set_gic_addr(&gicfd, KVM_VGIC_V2_ADDR_TYPE_CPU, gic.gicr_base)?;
        }
    }

    // Create + init all vCPUs. Secondaries start powered off; the guest's PSCI
    // CPU_ON (in-kernel) wakes them.
    let mut kvi = kvm_vcpu_init::default();
    vm.get_preferred_target(&mut kvi)?;
    kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
    let mut vcpus = Vec::with_capacity(num_cpus as usize);
    for id in 0..num_cpus {
        let vcpu = vm.create_vcpu(u64::from(id))?;
        let mut kvi_cpu = kvi;
        if id != 0 {
            kvi_cpu.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
        }
        vcpu.vcpu_init(&kvi_cpu)?;
        vcpus.push(vcpu);
    }

    // Number of SPIs (multiple of 32), then finalize the GIC.
    let nr_irqs: u32 = 256;
    set_gic_attr_u32(&gicfd, KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &nr_irqs)?;
    let init_attr = kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
        addr: 0,
    };
    gicfd.set_device_attr(&init_attr)?;

    // Primary vCPU boot state: PC = kernel entry, X0 = DTB, PSTATE = EL1h/DAIF.
    set_u64(&vcpus[0], REG_PC, layout.kernel_addr);
    set_u64(&vcpus[0], REG_X0, layout.dtb_addr);
    set_u64(&vcpus[0], REG_PSTATE, PSTATE_EL1H_DAIF);

    let vm = Arc::new(vm);
    let shared = Shared {
        vm: Arc::clone(&vm),
        mem: ram,
        pl011: Arc::new(Mutex::new(Pl011::new())),
        virtio,
        net,
        vsock,
        emit: Arc::new(Mutex::new(emitter)),
        running: Arc::new(AtomicBool::new(true)),
        threads: Arc::new(Mutex::new(vec![0u64; num_cpus as usize])),
        stop: Arc::new(Mutex::new(None)),
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

    // Arm the seccomp filters before the first thread is spawned. This compiles
    // both allowlists and fails the boot if either will not, so a bad list is an
    // error here rather than a SIGSYS inside a device thread later. Nothing is
    // filtered yet: each thread installs its own as it starts (see `seccomp`).
    if cfg.sandbox {
        crate::seccomp::arm()?;
    }

    // Every listener is bound here, before any filter goes in: the seccomp
    // allowlists permit accept4 on a listener we already hold but not socket or
    // bind, so a listener created later would be trapped.
    let agent_listener = match &cfg.agent_sock {
        Some(path) => Some(bind_unix(path)?),
        None => None,
    };

    // Helper threads.
    spawn_input_thread(shared.clone());
    if let (Some(listener), Some(dev)) = (agent_listener, &shared.vsock) {
        spawn_vsock_bridge(
            listener,
            Arc::clone(dev),
            Arc::clone(&shared.mem),
            Arc::clone(&vm),
        );
    }
    if let (Some(reader), Some(dev)) = (net_reader, &shared.net) {
        spawn_net_gateway_reader(
            reader,
            Arc::clone(dev),
            Arc::clone(&shared.mem),
            Arc::clone(&vm),
        );
    }
    if let (Some(reader), Some(dev)) = (net_tap_reader, &shared.net) {
        spawn_net_tap_reader(
            reader,
            Arc::clone(dev),
            Arc::clone(&shared.mem),
            Arc::clone(&vm),
        );
    }
    let _raw = RawTerm::enable();

    // One thread per vCPU.
    let mut joins = Vec::new();
    for (id, vcpu) in vcpus.into_iter().enumerate() {
        let sh = shared.clone();
        joins.push(std::thread::spawn(move || run_cpu(id as u32, vcpu, sh)));
    }

    // The main thread filters itself last, once everything it had to spawn
    // exists. Doing it in this order is what lets both allowlists refuse
    // `seccomp` itself: nothing is ever created underneath a filter except the
    // per-connection vsock readers, which inherit one on purpose.
    if cfg.sandbox {
        crate::seccomp::install(crate::seccomp::Thread::Vmm)?;
        let (vmm, vcpu) = crate::seccomp::allowed_counts()?;
        if crate::seccomp::log_mode() {
            eprintln!(
                "[hvi] seccomp: LOGGING ONLY ({}=log) — denials are recorded, not enforced",
                crate::seccomp::LOG_ENV
            );
        } else {
            eprintln!("[hvi] seccomp: on (vmm {vmm} syscalls, vcpu {vcpu}, trap on mismatch)");
        }
    } else {
        eprintln!(
            "[hvi] seccomp: OFF (--no-sandbox) — the VMM keeps the full host syscall surface"
        );
    }

    for j in joins {
        let _ = j.join();
    }

    let stop = shared.stop.lock().unwrap().unwrap_or(Stop::SystemOff);
    Ok(stop)
}

/// A single vCPU thread: KVM_RUN loop with MMIO/PSCI handling.
fn run_cpu(cpu_id: u32, mut vcpu: VcpuFd, sh: Shared) {
    // The tight filter, installed before this thread touches anything the guest
    // controls: MMIO exits are serviced inline here, so the virtio device models
    // -- the code that parses guest descriptors -- run on this thread.
    crate::seccomp::install_thread(crate::seccomp::Thread::Vcpu);
    // SAFETY: pthread_self is always valid on the current thread.
    let tid = unsafe { libc::pthread_self() } as u64;
    if let Ok(mut t) = sh.threads.lock() {
        if (cpu_id as usize) < t.len() {
            t[cpu_id as usize] = tid;
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

        match vcpu.run() {
            Ok(VcpuExit::MmioRead(addr, data)) => on_mmio(&sh, addr, true, data),
            Ok(VcpuExit::MmioWrite(addr, data)) => {
                // Copy out first: `data` borrows the run struct.
                let mut buf = [0u8; 8];
                let n = data.len().min(8);
                buf[..n].copy_from_slice(&data[..n]);
                on_mmio_write(&sh, addr, &buf[..n]);
            }
            Ok(VcpuExit::SystemEvent(evtype, _)) => {
                // PSCI SYSTEM_RESET vs SYSTEM_OFF (and anything else -> off).
                let s = if evtype == KVM_SYSTEM_EVENT_RESET {
                    Stop::SystemReset
                } else {
                    Stop::SystemOff
                };
                *sh.stop.lock().unwrap() = Some(s);
                stop_all(&sh);
                break;
            }
            Ok(VcpuExit::Hlt) => break,
            Ok(VcpuExit::Intr) => {} // kicked (snapshot / shutdown) — loop re-checks
            Ok(VcpuExit::FailEntry(reason, cpu)) => {
                eprintln!("[hvi/kvm] cpu{cpu_id}: KVM entry failed reason={reason:#x} cpu={cpu}");
                if is_boot {
                    stop_all(&sh);
                }
                break;
            }
            Ok(other) => {
                eprintln!("[hvi/kvm] cpu{cpu_id}: unhandled exit {other:?}");
                if is_boot {
                    stop_all(&sh);
                }
                break;
            }
            Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {} // kicked / retry
            Err(e) => {
                eprintln!("[hvi/kvm] cpu{cpu_id}: KVM_RUN error: {e}");
                break;
            }
        }
    }
}

/// Services an MMIO **read**: fills `data` with the addressed device's value.
fn on_mmio(sh: &Shared, addr: u64, _read: bool, data: &mut [u8]) {
    let width = data.len();
    let val = read_device(sh, addr);
    let bytes = val.to_le_bytes();
    let n = width.min(8);
    data[..n].copy_from_slice(&bytes[..n]);
}

/// Reads the device register at `addr` and drives its interrupt line.
fn read_device(sh: &Shared, addr: u64) -> u64 {
    if (UART_BASE..UART_BASE + UART_SIZE).contains(&addr) {
        let (v, level) = {
            let mut p = sh.pl011.lock().unwrap();
            let v = p.mmio(addr - UART_BASE, false, 0);
            (v, p.irq_level())
        };
        let _ = sh.vm.set_irq_line(spi_gsi(UART_SPI), level);
        v
    } else if (VIRTIO_BASE..VIRTIO_BASE + VIRTIO_SIZE).contains(&addr) {
        dev_read(sh, sh.virtio.as_ref(), VIRTIO_SPI, addr - VIRTIO_BASE)
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        dev_read(sh, sh.net.as_ref(), VIRTIO_NET_SPI, addr - VIRTIO_NET_BASE)
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        vsock_read(sh, addr - VIRTIO_VSOCK_BASE)
    } else {
        0
    }
}

/// Services an MMIO **write** to the addressed device.
fn on_mmio_write(sh: &Shared, addr: u64, data: &[u8]) {
    let mut b = [0u8; 8];
    b[..data.len()].copy_from_slice(data);
    let val = u64::from_le_bytes(b);
    if (UART_BASE..UART_BASE + UART_SIZE).contains(&addr) {
        let level = {
            let mut p = sh.pl011.lock().unwrap();
            p.mmio(addr - UART_BASE, true, val);
            p.irq_level()
        };
        let _ = sh.vm.set_irq_line(spi_gsi(UART_SPI), level);
    } else if (VIRTIO_BASE..VIRTIO_BASE + VIRTIO_SIZE).contains(&addr) {
        dev_write(sh, sh.virtio.as_ref(), VIRTIO_SPI, addr - VIRTIO_BASE, val);
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        dev_write(
            sh,
            sh.net.as_ref(),
            VIRTIO_NET_SPI,
            addr - VIRTIO_NET_BASE,
            val,
        );
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        vsock_write(sh, addr - VIRTIO_VSOCK_BASE, val);
    }
}

/// Generic virtio-blk/net read: `mmio`, drain events to the ledger, set IRQ.
fn dev_read<D: VirtioMmio>(sh: &Shared, dev: Option<&Arc<Mutex<D>>>, spi: u32, off: u64) -> u64 {
    let Some(dev) = dev else { return 0 };
    let (v, level, events) = {
        let mut d = dev.lock().unwrap();
        let v = d.mmio(&sh.mem, off, false, 0);
        (v, d.irq_level(), d.take_events())
    };
    drain(sh, &events);
    let _ = sh.vm.set_irq_line(spi_gsi(spi), level);
    v
}

fn dev_write<D: VirtioMmio>(
    sh: &Shared,
    dev: Option<&Arc<Mutex<D>>>,
    spi: u32,
    off: u64,
    val: u64,
) {
    let Some(dev) = dev else { return };
    let (level, events) = {
        let mut d = dev.lock().unwrap();
        d.mmio(&sh.mem, off, true, val);
        (d.irq_level(), d.take_events())
    };
    drain(sh, &events);
    let _ = sh.vm.set_irq_line(spi_gsi(spi), level);
}

fn vsock_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.vsock.as_ref() else {
        return 0;
    };
    let (v, level) = {
        let mut d = dev.lock().unwrap();
        let v = d.mmio(&sh.mem, off, false, 0);
        (v, d.irq_level())
    };
    let _ = sh.vm.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), level);
    v
}

fn vsock_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.vsock.as_ref() else { return };
    let level = {
        let mut d = dev.lock().unwrap();
        d.mmio(&sh.mem, off, true, val);
        d.irq_level()
    };
    let _ = sh.vm.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), level);
}

fn drain(sh: &Shared, events: &[crate::events::CapturedEvent]) {
    if events.is_empty() {
        return;
    }
    let mut e = sh.emit.lock().unwrap();
    for ev in events {
        e.captured(ev);
    }
}

/// The virtio-mmio surface `dev_read`/`dev_write` need (blk and net share it).
trait VirtioMmio {
    fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64;
    fn irq_level(&self) -> bool;
    fn take_events(&mut self) -> Vec<crate::events::CapturedEvent>;
}
impl VirtioMmio for VirtioBlk {
    fn mmio(&mut self, m: &GuestRam, o: u64, w: bool, v: u64) -> u64 {
        VirtioBlk::mmio(self, m, o, w, v)
    }
    fn irq_level(&self) -> bool {
        VirtioBlk::irq_level(self)
    }
    fn take_events(&mut self) -> Vec<crate::events::CapturedEvent> {
        VirtioBlk::take_events(self)
    }
}
impl VirtioMmio for VirtioNet {
    fn mmio(&mut self, m: &GuestRam, o: u64, w: bool, v: u64) -> u64 {
        VirtioNet::mmio(self, m, o, w, v)
    }
    fn irq_level(&self) -> bool {
        VirtioNet::irq_level(self)
    }
    fn take_events(&mut self) -> Vec<crate::events::CapturedEvent> {
        VirtioNet::take_events(self)
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
        // cpu0 is the one that reaches the plugin hook.
        kick_cpu0(self);
    }
}

/// [`CpuHandle`] over the boot vCPU at a safe point. Borrows rather than
/// clones: it lives only for the duration of one [`Plugin::safepoint`] call.
struct Cpu<'a> {
    vcpu: &'a VcpuFd,
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
        let ttbr1 = get_u64(self.vcpu, REG_TTBR1_EL1);
        RegsView {
            // arm64's kernel-half page-table base is the walk root.
            root: ttbr1,
            pc: get_u64(self.vcpu, REG_PC),
            cpsr: get_u64(self.vcpu, REG_PSTATE),
            ttbr0: get_u64(self.vcpu, REG_TTBR0_EL1),
            ttbr1,
            sctlr: get_u64(self.vcpu, REG_SCTLR_EL1),
            sp_el1: get_u64(self.vcpu, REG_SP_EL1),
            tcr: get_u64(self.vcpu, REG_TCR_EL1),
            current_task: get_u64(self.vcpu, REG_SP_EL0),
        }
    }

    fn pause(&self) -> bool {
        // cpu0 drives this, so it waits for the *other* vCPUs and never parks
        // itself. On failure the quiesce is released here, so a caller that
        // gets `false` owes nothing.
        self.sh.quiesce.request();
        kick_all(self.sh);
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

/// Signals all vCPU threads to stop and kicks them out of `KVM_RUN`.
fn stop_all(sh: &Shared) {
    sh.running.store(false, Ordering::SeqCst);
    kick_all(sh);
}

fn kick_all(sh: &Shared) {
    if let Ok(t) = sh.threads.lock() {
        for &tid in t.iter() {
            if tid != 0 {
                // SAFETY: pthread_kill to a live thread handle; no-op handler.
                unsafe { libc::pthread_kill(tid as libc::pthread_t, KICK_SIGNAL) };
            }
        }
    }
}

fn kick_cpu0(sh: &Shared) {
    if let Ok(t) = sh.threads.lock() {
        if let Some(&tid) = t.first() {
            if tid != 0 {
                unsafe { libc::pthread_kill(tid as libc::pthread_t, KICK_SIGNAL) };
            }
        }
    }
}

/// Installs a no-op handler for the kick signal (without SA_RESTART, so KVM_RUN
/// returns EINTR). Idempotent enough for a single VM per process.
fn install_kick_handler() {
    extern "C" fn noop(_: libc::c_int) {}
    // SAFETY: installing a trivial signal handler at startup.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = noop as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0; // no SA_RESTART
        libc::sigaction(KICK_SIGNAL, &sa, std::ptr::null_mut());
    }
}

fn set_gic_addr(
    gic: &kvm_ioctls::DeviceFd,
    addr_type: u32,
    gpa: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let val: u64 = gpa;
    let attr = kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(addr_type),
        addr: std::ptr::addr_of!(val) as u64,
    };
    gic.set_device_attr(&attr)?;
    Ok(())
}

fn set_gic_attr_u32(
    gic: &kvm_ioctls::DeviceFd,
    group: u32,
    attr: u64,
    val: &u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let a = kvm_device_attr {
        flags: 0,
        group,
        attr,
        addr: std::ptr::addr_of!(*val) as u64,
    };
    gic.set_device_attr(&a)?;
    Ok(())
}

/// Feeds host stdin to the guest UART.
///
/// With a plugin attached, [`REQUEST_KEY`] is intercepted and asks it for an
/// observation instead of reaching the guest; with no plugin the key is an
/// ordinary byte, so a run with no plugin passes stdin through untouched.
fn spawn_input_thread(sh: Shared) {
    std::thread::spawn(move || {
        crate::seccomp::install_thread(crate::seccomp::Thread::Vmm);
        let mut byte = [0u8; 1];
        loop {
            // SAFETY: reading one byte from fd 0.
            let n = unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
            if n <= 0 {
                break;
            }
            if byte[0] == REQUEST_KEY {
                if let Some(obs) = &sh.plugin {
                    obs.request();
                    kick_cpu0(&sh);
                    continue;
                }
            }
            let level = {
                let mut p = sh.pl011.lock().unwrap();
                p.push_rx(byte[0]);
                p.irq_level()
            };
            let _ = sh.vm.set_irq_line(spi_gsi(UART_SPI), level);
        }
    });
}

/// Bridges the host agent Unix socket to the guest vsock device (exec).
fn spawn_vsock_bridge(
    listener: std::os::unix::net::UnixListener,
    dev: Arc<Mutex<VirtioVsock>>,
    mem: Arc<GuestRam>,
    vm: Arc<VmFd>,
) {
    std::thread::spawn(move || {
        crate::seccomp::install_thread(crate::seccomp::Thread::Vmm);
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(reader) = stream.try_clone() else {
                continue;
            };
            let port = {
                let mut d = dev.lock().unwrap();
                let port = d.add_conn(stream);
                d.connect(&mem, port);
                let level = d.irq_level();
                drop(d);
                let _ = vm.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), level);
                port
            };
            let dev2 = Arc::clone(&dev);
            let mem2 = Arc::clone(&mem);
            let vm2 = Arc::clone(&vm);
            std::thread::spawn(move || {
                use std::io::Read;
                let mut reader = reader;
                let mut buf = [0u8; 8192];
                loop {
                    let n = match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let level = {
                        let mut d = dev2.lock().unwrap();
                        d.host_data(&mem2, port, &buf[..n]);
                        d.irq_level()
                    };
                    let _ = vm2.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), level);
                }
                let level = {
                    let mut d = dev2.lock().unwrap();
                    d.host_closed(&mem2, port);
                    d.irq_level()
                };
                let _ = vm2.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), level);
            });
        }
    });
}

/// Pumps frames from the tap into the guest.
///
/// Unlike the gateway stream there is no length prefix: one `read` returns
/// exactly one frame, preceded by the `virtio_net_hdr` the tap was created
/// with, which `tap::strip_vnet_hdr` drops before delivering.
fn spawn_net_tap_reader(
    mut reader: std::fs::File,
    dev: Arc<Mutex<VirtioNet>>,
    mem: Arc<GuestRam>,
    vm: Arc<VmFd>,
) {
    use std::io::Read;
    std::thread::spawn(move || {
        crate::seccomp::install_thread(crate::seccomp::Thread::Vmm);
        let mut buf = vec![0u8; 65_536];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let Some(frame) = crate::tap::strip_vnet_hdr(&buf, n) else {
                continue;
            };
            let level = {
                let mut d = dev.lock().unwrap();
                d.deliver(&mem, frame);
                d.irq_level()
            };
            let _ = vm.set_irq_line(spi_gsi(VIRTIO_NET_SPI), level);
        }
    });
}

/// Reads gateway->guest frames (4-byte BE length prefix) and injects them.
fn spawn_net_gateway_reader(
    mut reader: std::os::unix::net::UnixStream,
    dev: Arc<Mutex<VirtioNet>>,
    mem: Arc<GuestRam>,
    vm: Arc<VmFd>,
) {
    use std::io::Read;
    std::thread::spawn(move || {
        crate::seccomp::install_thread(crate::seccomp::Thread::Vmm);
        let mut hdr = [0u8; 4];
        loop {
            if reader.read_exact(&mut hdr).is_err() {
                break;
            }
            let len = u32::from_be_bytes(hdr) as usize;
            if len == 0 || len > 65_536 {
                continue;
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
            let _ = vm.set_irq_line(spi_gsi(VIRTIO_NET_SPI), level);
        }
    });
}

/// Puts stdin into raw mode for the guest console, restoring it on drop.
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
        // SAFETY: restoring saved settings on fd 0.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.orig);
        }
    }
}

/// Binds a Unix listener at `path`, clearing a stale socket from a previous run
/// first (which would otherwise make `bind` fail with EADDRINUSE).
///
/// The caller used to do this inside the thread it spawned. It does it in
/// `boot` instead because the seccomp filters allow `accept4` but not `socket`
/// or `bind` -- a listener created after the filter is in would be killed --
/// and because a failure is now a boot error the caller sees rather than a line
/// in the log of a guest that is already running.
fn bind_unix(path: &str) -> std::io::Result<std::os::unix::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    std::os::unix::net::UnixListener::bind(path)
        .map_err(|e| std::io::Error::new(e.kind(), format!("cannot bind Unix socket {path}: {e}")))
}

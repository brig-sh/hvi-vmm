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

//! The arm64 guest on KVM, SMP-capable.
//!
//! The Linux counterpart of `hvf`. KVM gives us an **in-kernel GIC** and
//! **in-kernel PSCI**, so this backend is structurally simpler than the hvf
//! one: secondaries are created `POWER_OFF` and brought up by the guest's own
//! PSCI `CPU_ON` (handled entirely in-kernel, with no mailbox), and interrupts
//! are a single `set_irq_line`, which also wakes a WFI'd vCPU (no explicit kick
//! for delivery). A kick sets the vCPU's `immediate_exit` byte and signals its
//! thread. It gets cpu0 to its next safe point, where a plugin runs, gets the
//! other vCPUs to theirs for a pause, and breaks every vCPU out of `KVM_RUN`
//! when the VM stops.
//!
//! Everything else — image/layout/DTB, virtio devices, PL011, the RawEvent
//! ledger, and the plugin seam — is the same hypervisor-agnostic code the
//! macOS backend uses.
//!
//! The GIC version is negotiated, not chosen: KVM's vGIC borrows the host's CPU
//! interface, so a GICv3 host serves vGICv3 and a GIC-400 host serves vGICv2
//! only. We ask for v3 and fall back to v2, laying out the DTB to match.
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this
// VMM's own.
#![allow(clippy::disallowed_methods)]

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use kvm_bindings::{
    kvm_create_device, kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
    kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, kvm_vcpu_init, KVM_ARM_VCPU_POWER_OFF,
    KVM_ARM_VCPU_PSCI_0_2, KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR,
    KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_GRP_NR_IRQS, KVM_EXIT_INTR, KVM_SYSTEM_EVENT_RESET,
    KVM_VGIC_V2_ADDR_TYPE_CPU, KVM_VGIC_V2_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_DIST,
    KVM_VGIC_V3_ADDR_TYPE_REDIST,
};
use kvm_ioctls::{Cap, Kvm, VcpuExit, VcpuFd, VmFd};

use crate::arch::aarch64::fdt;
use crate::arch::aarch64::layout::{
    GicLayout, GicVersion, RAM_BASE, UART_BASE, UART_SIZE, UART_SPI, VIRTIO_BASE, VIRTIO_NET_BASE,
    VIRTIO_NET_SPI, VIRTIO_SIZE, VIRTIO_SPI, VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_SPI,
};
use crate::arch::aarch64::loader;
use crate::config::{BootConfig, Stop};
use crate::devices::legacy::pl011::Pl011;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::net::{self, GatewayRelay, TapRelay, VirtioNet};
use crate::devices::virtio::tap;
use crate::devices::virtio::vsock::VirtioVsock;
use crate::events::Emitter;
use crate::hypervisor::quiesce::Quiesce;
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::{CpuHandle, GuestArch, IoSink, Plugin, RamRegion, RegsView, VmHandle};
use crate::sandbox::seccomp;
use crate::sync::lock_or_recover;
use crate::teardown::{join_by, StopSource, StopToken, STOP_TIMEOUT};

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
    /// The vCPU threads (index = cpu id), `None` until a thread has registered
    /// itself and again once it has exited.
    threads: Arc<Mutex<Vec<Option<VcpuThread>>>>,
    stop: Arc<Mutex<Option<Stop>>>,
    /// Parks every vCPU at a safe point so an observation sees a still guest.
    quiesce: Arc<Quiesce>,
    /// Whoever is watching this guest, if anyone.
    plugin: Option<Arc<dyn Plugin>>,
    /// The object backing guest RAM, for a plugin that hands the same pages to
    /// another process.
    ram_file: Arc<std::fs::File>,
    sandbox_id: String,
    /// vCPU count, so a pause knows how many threads must park.
    num_cpus: u32,
}

/// Boots `cfg` on KVM and runs until the guest powers off.
///
/// Every thread this call itself starts has exited when it returns, or the call
/// returns an error naming the one that did not stop within
/// [`crate::teardown::STOP_TIMEOUT`]. What remains of the VM is a `VmHandle` a
/// plugin kept, in a field or on a thread it started from `attach`.
pub fn boot(cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error>> {
    if !cfg.fs_shares.is_empty() {
        return Err(
            "--share-ro/--share-rw are currently implemented by the macOS HVI backend only".into(),
        );
    }
    install_kick_handler();
    // Refuse a kernel that is not a flat Image before the VM, its RAM, the
    // devices and the event ledger exist.
    loader::LoadedKernel::from_header(&cfg.kernel)?;

    let num_cpus = cfg.vcpus.max(1);

    let kvm = Kvm::new()?;
    // A kick relies on `kvm_run.immediate_exit`. Without it, one that lands
    // just before `KVM_RUN` is lost, and a stop with it.
    if !kvm.check_extension(Cap::ImmediateExit) {
        return Err("hvi needs KVM_CAP_IMMEDIATE_EXIT, which Linux 4.11 added".into());
    }
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

    // Placement (QEMU virt values; the DTB and KVM must agree). Sizing and the
    // v2 vCPU cap both live in `for_vcpus`, so they are unit-testable on a host
    // with no KVM at all.
    let gic = GicLayout::for_vcpus(version, num_cpus)?;
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

    // Guest RAM: one region at RAM_BASE, backed by a shareable object (a
    // memfd) so an out-of-process plugin can map the same pages. KVM only
    // needs a valid host address, so the guest is unaffected.
    let shared_ram = SharedRam::new(cfg.mem_bytes as usize)?;
    let ram = Arc::new(GuestRam::new(
        &shared_ram,
        &[shared_ram.region_at(RAM_BASE)],
    )?);
    ram.register_kvm_slots(&vm)?;

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
    let net_dev = if let Some(ifname) = &cfg.net_tap {
        // urunc already created the tap and redirected the veth to it, so all
        // that is left is to attach -- that is what brings carrier up. An
        // unusable tap fails the boot: falling back to the built-in stack
        // would put the guest on the wrong network, which from the outside is
        // indistinguishable from success.
        let file = tap::open(ifname).map_err(|e| format!("--net-tap {ifname}: {e}"))?;
        let reader = file
            .try_clone()
            .map_err(|e| format!("--net-tap {ifname}: cloning the tap fd: {e}"))?;
        eprintln!("[hvi/kvm] virtio-net: tap {ifname}");
        net_tap_reader = Some(reader);
        Some(VirtioNet::with_tap(file))
    } else if let Some(sock) = &cfg.net_gateway {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(stream) => match stream.try_clone() {
                Ok(reader) => {
                    eprintln!("[hvi/kvm] virtio-net: gvisor-tap gateway relay via {sock}");
                    net_reader = Some(reader);
                    Some(VirtioNet::with_gateway(stream))
                }
                Err(e) => {
                    eprintln!("[hvi/kvm] WARNING: cannot clone gateway socket ({e}); net disabled");
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "[hvi/kvm] WARNING: gateway {sock} unreachable ({e}); falling back to the {}",
                    net::stub_stack_line()
                );
                Some(VirtioNet::new())
            }
        }
    } else if cfg.net {
        eprintln!("[hvi/kvm] virtio-net: {}", net::stub_stack_line());
        Some(VirtioNet::new())
    } else {
        None
    };

    let net = net::share(net_dev, cfg.net_mac);

    let vsock = cfg
        .agent_sock
        .as_ref()
        .map(|_| Arc::new(Mutex::new(VirtioVsock::new())));
    let has_blk = virtio.is_some();
    let has_net = net.is_some();
    let has_vsock = vsock.is_some();
    let fdt_devices = fdt::VirtioDevices {
        blk: has_blk,
        net: has_net,
        vsock: has_vsock,
        fs_count: 0,
    };

    let emitter = Emitter::new(cfg.events.as_deref(), &cfg.sandbox_id)?;
    let layout = loader::Payload {
        kernel: &cfg.kernel,
        initramfs: cfg.initramfs.as_deref(),
        cmdline: &cfg.cmdline,
    }
    .load(ram.memory(), cfg.mem_bytes, &gic, num_cpus, fdt_devices)?;

    // Place the GIC regions (the device itself was created above, before the
    // DTB). The address-type constants differ per version, and v2 takes a CPU
    // interface where v3 takes a redistributor. NR_IRQS + INIT follow the
    // vCPUs.
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
    let mut kickers = Vec::with_capacity(num_cpus as usize);
    for id in 0..num_cpus {
        let vcpu = vm.create_vcpu(u64::from(id))?;
        let mut kvi_cpu = kvi;
        if id != 0 {
            kvi_cpu.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
        }
        vcpu.vcpu_init(&kvi_cpu)?;
        kickers.push(kick_handle(&vm, &vcpu)?);
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
        threads: Arc::new(Mutex::new((0..num_cpus).map(|_| None).collect())),
        stop: Arc::new(Mutex::new(None)),
        quiesce: Arc::new(Quiesce::new()),
        plugin: cfg.plugin.clone(),
        ram_file: Arc::clone(shared_ram.file()),
        sandbox_id: cfg.sandbox_id.clone(),
        num_cpus,
    };

    // Hand the plugin the guest before any vCPU runs, so nothing happens
    // between the first instruction and the attach.
    if let Some(obs) = &shared.plugin {
        obs.attach(Arc::new(shared.clone()) as Arc<dyn VmHandle>)?;
    }

    // Arm the seccomp filters before the first thread is spawned. This compiles
    // both allowlists and fails the boot if either will not, so a bad list is
    // an error here rather than a SIGSYS inside a device thread later. Nothing
    // is filtered yet: each thread installs its own as it starts (see
    // `sandbox::seccomp`).
    let allowed_counts = if cfg.sandbox {
        seccomp::arm()?;
        Some(seccomp::allowed_counts()?)
    } else {
        None
    };

    // Every listener is bound here, before any filter goes in: the seccomp
    // allowlists permit accept4 on a listener we already hold but not socket or
    // bind, so a listener created later would be trapped.
    let agent_listener = match &cfg.agent_sock {
        Some(path) => Some(bind_unix(path)?),
        None => None,
    };
    // The stop source's socket pair is created here for the same reason.
    let stop_source = StopSource::new()?;

    // Helper threads. Each polls its stop token beside its own descriptor and
    // is joined after the vCPUs; `teardown` describes the stop.
    let input = spawn_input_thread(shared.clone(), stop_source.token());
    let mut helpers: Vec<(&str, JoinHandle<()>)> = Vec::new();
    if let (Some(listener), Some(dev)) = (agent_listener, &shared.vsock) {
        helpers.push((
            "agent bridge",
            spawn_vsock_bridge(
                listener,
                Arc::clone(dev),
                Arc::clone(&shared.mem),
                Arc::clone(&vm),
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
                Arc::clone(&vm),
                stop_source.token(),
            ),
        ));
    }
    if let (Some(reader), Some(dev)) = (net_tap_reader, &shared.net) {
        helpers.push((
            "tap relay",
            spawn_net_tap_reader(
                reader,
                Arc::clone(dev),
                Arc::clone(&shared.mem),
                Arc::clone(&vm),
                stop_source.token(),
            ),
        ));
    }
    let _raw = RawTerm::enable();

    // One thread per vCPU. From here on a failure stops the guest and is
    // reported once every thread has been joined or left running, and the first
    // failure is the one reported.
    let mut failure: Option<Box<dyn std::error::Error>> = None;
    let mut joins = Vec::new();
    for (id, (vcpu, kicker)) in vcpus.into_iter().zip(kickers).enumerate() {
        let sh = shared.clone();
        // The thread is named after its vCPU, so the panic hook's report says
        // which one panicked.
        let spawned = std::thread::Builder::new()
            .name(format!("cpu{id}"))
            .spawn(move || run_cpu(id as u32, vcpu, kicker, sh));
        match spawned {
            Ok(join) => joins.push(join),
            Err(e) => {
                failure = Some(format!("spawning the cpu{id} thread: {e}").into());
                stop_all(&shared);
                break;
            }
        }
    }

    // The main thread filters itself last, once everything it had to spawn
    // exists. Doing it in this order is what lets both allowlists refuse
    // `seccomp` itself: nothing is ever created underneath a filter except the
    // per-connection vsock readers, which are spawned under it and inherit it.
    // The guest is already running by now, so a failure here stops it and is
    // reported once every thread has been joined or left running.
    let confined = if cfg.sandbox {
        seccomp::install(seccomp::Thread::Vmm)
    } else {
        Ok(())
    };
    match (confined, allowed_counts) {
        (Err(e), _) => {
            // Printed here, since a spawn failure ahead of it is the one
            // reported.
            eprintln!("[hvi/kvm] {e}");
            failure.get_or_insert(e.into());
            stop_all(&shared);
        }
        (Ok(()), Some((vmm, vcpu))) => {
            if seccomp::log_mode() {
                eprintln!(
                    "[hvi] seccomp: LOGGING ONLY ({}=log) — denials are recorded, not enforced",
                    seccomp::LOG_ENV
                );
            } else {
                eprintln!("[hvi] seccomp: on (vmm {vmm} syscalls, vcpu {vcpu}, trap on mismatch)");
            }
        }
        (Ok(()), None) => eprintln!(
            "[hvi] seccomp: OFF (--no-sandbox) — the VMM keeps the full host syscall surface"
        ),
    }

    for j in joins {
        let _ = j.join();
    }

    // The guest has stopped. End the helper threads (see `teardown`) and write
    // out the ledger tail, which the flush cadence alone would leave in the
    // buffer.
    stop_source.request_stop();
    let deadline = std::time::Instant::now() + STOP_TIMEOUT;
    kick_until_finished(&input, deadline);
    for (name, thread) in std::iter::once(("console reader", input)).chain(helpers) {
        if let Err(e) = join_by(name, thread, deadline) {
            eprintln!("[hvi/kvm] {e}; left running");
            failure.get_or_insert(e.into());
        }
    }
    lock_or_recover(&shared.emit).flush();
    if let Some(e) = failure {
        return Err(e);
    }

    let stop = shared.stop.lock().unwrap().unwrap_or(Stop::SystemOff);
    Ok(stop)
}

/// A vCPU thread as the other threads reach it, the target of a kick.
///
/// The kick signal alone is not enough: one that lands while the thread is in
/// user space, between its check of `running` and its `KVM_RUN`, is consumed by
/// the handler and the run goes ahead. So a kick first sets the vCPU's
/// `kvm_run.immediate_exit` byte, which makes the next `KVM_RUN` return `EINTR`
/// at once, and then sends the signal for a run already in progress.
struct VcpuThread {
    /// The pthread handle the signal goes to, as an integer.
    tid: u64,
    /// A handle to the vCPU that the kick owns, from [`kick_handle`].
    vcpu: VcpuFd,
}

impl VcpuThread {
    /// Registers the calling thread as `cpu` in `threads`, to be kicked through
    /// `vcpu`.
    ///
    /// The returned guard removes the entry when dropped. The thread must clear
    /// its own `immediate_exit` byte before each read of `running`, so a kick
    /// that lands after the clear ends the run that follows.
    fn register(
        threads: &Mutex<Vec<Option<VcpuThread>>>,
        cpu: usize,
        vcpu: VcpuFd,
    ) -> Registration<'_> {
        let thread = VcpuThread {
            // SAFETY: pthread_self is always valid on the current thread.
            tid: unsafe { libc::pthread_self() } as u64,
            vcpu,
        };
        if let Some(slot) = lock_or_recover(threads).get_mut(cpu) {
            *slot = Some(thread);
        }
        Registration { threads, cpu }
    }

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
        unsafe { libc::pthread_kill(self.tid as libc::pthread_t, KICK_SIGNAL) };
    }
}

/// Returns the `kvm_run.immediate_exit` byte of `vcpu`.
///
/// The vCPU thread, a thread that kicks it and the kernel each reach the byte
/// through a mapping of their own, so it is read and written as an atomic.
fn immediate_exit(vcpu: &mut VcpuFd) -> &AtomicU8 {
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
fn kick_handle(vm: &VmFd, vcpu: &VcpuFd) -> std::io::Result<VcpuFd> {
    // SAFETY: `vcpu` owns the descriptor and outlives the borrow.
    let descriptor = unsafe { BorrowedFd::borrow_raw(vcpu.as_raw_fd()) }.try_clone_to_owned()?;
    // SAFETY: `descriptor` is a vCPU of `vm`, and the handle takes it over.
    unsafe { vm.create_vcpu_from_rawfd(descriptor.into_raw_fd()) }.map_err(std::io::Error::from)
}

/// A vCPU thread's entry in `Shared::threads`, removed when dropped.
///
/// The removal runs on a panic as on a return, so a kick from a plugin thread
/// that outlives `boot` never signals a thread that no longer exists.
struct Registration<'a> {
    threads: &'a Mutex<Vec<Option<VcpuThread>>>,
    cpu: usize,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Some(slot) = lock_or_recover(self.threads).get_mut(self.cpu) {
            *slot = None;
        }
    }
}

/// A guard that ends the VM when dropped.
///
/// The drop calls [`stop_all`], on a panic as on a return.
struct StopOnDrop<'a> {
    sh: &'a Shared,
}

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        stop_all(self.sh);
    }
}

/// Runs one vCPU until the VM stops, servicing its MMIO and PSCI exits.
fn run_cpu(cpu_id: u32, mut vcpu: VcpuFd, kicker: VcpuFd, sh: Shared) {
    // The tight filter, installed before this thread touches anything the guest
    // controls: MMIO exits are serviced inline here, so the virtio device
    // models -- the code that parses guest descriptors -- run on this
    // thread.
    seccomp::install_thread(seccomp::Thread::Vcpu);
    // Held for the whole run, so every way out ends the VM. A secondary that
    // ended alone would otherwise leave the VM running with one vCPU fewer and
    // the join in `boot` blocked. Declared before the registration so the
    // registration drops first: the entry is removed before the stop kicks.
    let _stop = StopOnDrop { sh: &sh };
    let _registration = VcpuThread::register(&sh.threads, cpu_id as usize, kicker);
    let is_boot = cpu_id == 0;

    loop {
        // Cleared before `running` is read, so a kick that lands from here on
        // ends the run below at once.
        immediate_exit(&mut vcpu).store(0, Ordering::SeqCst);
        if !sh.running.load(Ordering::SeqCst) {
            break;
        }
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
                break;
            }
            Ok(VcpuExit::Hlt) => break,
            Ok(VcpuExit::Intr) => {} // kicked (snapshot / shutdown) — loop re-checks
            Ok(VcpuExit::FailEntry(reason, cpu)) => {
                eprintln!("[hvi/kvm] cpu{cpu_id}: KVM entry failed reason={reason:#x} cpu={cpu}");
                break;
            }
            Ok(other) => {
                eprintln!("[hvi/kvm] cpu{cpu_id}: unhandled exit {other:?}");
                break;
            }
            Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {
                // A run that a kick cut short has completed the MMIO exit
                // before it and left `exit_reason` as it was. Linux 5.0 to 5.2,
                // and the stable series that took that change back to 4.14,
                // complete the exit again on the next run, which skips one more
                // guest instruction, so the reason is cleared here.
                vcpu.get_kvm_run().exit_reason = KVM_EXIT_INTR;
            }
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

/// Ends the VM.
///
/// Clears `running`, releases the quiesce so no vCPU stays parked at a
/// checkpoint, and kicks every vCPU out of `KVM_RUN`. Only the first call
/// kicks; a later one just releases the quiesce again.
fn stop_all(sh: &Shared) {
    let was_running = sh.running.swap(false, Ordering::SeqCst);
    // A vCPU parked at a quiesce checkpoint waits on a condition variable the
    // kick cannot end. Releasing sends it on to its run, which the kick ends,
    // and it sees `running` at the top of its loop. Released on every call,
    // since a request can follow the first release.
    sh.quiesce.release();
    // One round of kicks is enough. A thread that registered before the round
    // has its `immediate_exit` byte set, and one that registers after it reads
    // `running` as false at the top of its loop.
    if was_running {
        kick_all(sh);
    }
}

/// Kicks every vCPU.
fn kick_all(sh: &Shared) {
    for thread in lock_or_recover(&sh.threads).iter_mut().flatten() {
        thread.kick();
    }
}

/// Kicks the boot vCPU, the one that runs the plugin.
fn kick_cpu0(sh: &Shared) {
    if let Some(Some(thread)) = lock_or_recover(&sh.threads).first_mut() {
        thread.kick();
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
/// interrupts returns `EINTR` instead of resuming: `KVM_RUN` on a vCPU thread,
/// or the console reader's read of stdin.
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
fn spawn_input_thread(sh: Shared, stop: StopToken) -> JoinHandle<()> {
    std::thread::spawn(move || {
        seccomp::install_thread(seccomp::Thread::Vmm);
        let stdin = std::io::stdin();
        let mut byte = [0u8; 1];
        loop {
            match stop.wait(stdin.as_fd()) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    eprintln!("[hvi/kvm] console: {e}; console input stopped");
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
                if let Some(obs) = &sh.plugin {
                    obs.request();
                    kick_cpu0(&sh);
                    continue;
                }
            }
            let level = {
                let mut p = lock_or_recover(&sh.pl011);
                p.push_rx(byte[0]);
                p.irq_level()
            };
            let _ = sh.vm.set_irq_line(spi_gsi(UART_SPI), level);
        }
    })
}

/// Bridges the host agent Unix socket to the guest vsock device (exec).
///
/// The listener is non-blocking, so the accept loop can poll it beside the stop
/// token. The per-connection readers poll the same token, and the listener
/// thread joins the ones still running before it exits.
fn spawn_vsock_bridge(
    listener: std::os::unix::net::UnixListener,
    dev: Arc<Mutex<VirtioVsock>>,
    mem: Arc<GuestRam>,
    vm: Arc<VmFd>,
    stop: StopToken,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        seccomp::install_thread(seccomp::Thread::Vmm);
        let mut readers: Vec<JoinHandle<()>> = Vec::new();
        loop {
            match stop.wait(listener.as_fd()) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    eprintln!("[hvi/kvm] vsock bridge: {e}; no longer accepting");
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
            let port = {
                let mut d = lock_or_recover(&dev);
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
            let stop2 = stop.clone();
            readers.retain(|handle| !handle.is_finished());
            readers.push(std::thread::spawn(move || {
                use std::io::Read;
                let mut reader = reader;
                let mut buf = [0u8; 8192];
                loop {
                    match stop2.wait(reader.as_fd()) {
                        Ok(true) => {}
                        // A stop ends the connection like a peer close, so the
                        // device releases it.
                        Ok(false) => break,
                        Err(e) => {
                            eprintln!("[hvi/kvm] vsock bridge: {e}; connection closed");
                            break;
                        }
                    }
                    let n = match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let level = {
                        let mut d = lock_or_recover(&dev2);
                        d.host_data(&mem2, port, &buf[..n]);
                        d.irq_level()
                    };
                    let _ = vm2.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), level);
                }
                let level = {
                    let mut d = lock_or_recover(&dev2);
                    d.host_closed(&mem2, port);
                    d.irq_level()
                };
                let _ = vm2.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), level);
            }));
        }
        for reader in readers {
            let _ = reader.join();
        }
    })
}

/// Injects tap frames into the guest.
///
/// [`TapRelay`] owns the wait and the drain. This thread supplies the delivery
/// under the device lock and the interrupt.
fn spawn_net_tap_reader(
    reader: std::fs::File,
    dev: Arc<Mutex<VirtioNet>>,
    mem: Arc<GuestRam>,
    vm: Arc<VmFd>,
    stop: StopToken,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        seccomp::install_thread(seccomp::Thread::Vmm);
        let relayed = TapRelay::new(reader).run(&stop, |frame| {
            let level = {
                let mut d = lock_or_recover(&dev);
                d.deliver(&mem, frame);
                d.irq_level()
            };
            let _ = vm.set_irq_line(spi_gsi(VIRTIO_NET_SPI), level);
        });
        if let Err(e) = relayed {
            eprintln!("[hvi/kvm] virtio-net: {e}; tap relay stopped");
        }
    })
}

/// Injects gateway frames into the guest, each prefixed by a 4-byte big-endian
/// length.
///
/// [`GatewayRelay`] owns the wait, the drain and the framing. This thread
/// supplies the delivery under the device lock and the interrupt.
fn spawn_net_gateway_reader(
    reader: std::os::unix::net::UnixStream,
    dev: Arc<Mutex<VirtioNet>>,
    mem: Arc<GuestRam>,
    vm: Arc<VmFd>,
    stop: StopToken,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        seccomp::install_thread(seccomp::Thread::Vmm);
        let relayed = GatewayRelay::new(reader).run(&stop, |frame| {
            let level = {
                let mut d = lock_or_recover(&dev);
                d.deliver(&mem, frame);
                d.irq_level()
            };
            let _ = vm.set_irq_line(spi_gsi(VIRTIO_NET_SPI), level);
        });
        if let Err(e) = relayed {
            eprintln!("[hvi/kvm] virtio-net: {e}; gateway relay stopped");
        }
    })
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
        // TCSAFLUSH discards unread input, so keystrokes and terminal answers
        // still queued for the guest never reach the shell.
        // SAFETY: restoring the saved settings on fd 0.
        unsafe {
            libc::tcsetattr(0, libc::TCSAFLUSH, &self.orig);
        }
    }
}

/// Binds a non-blocking Unix listener at `path`, clearing a stale socket from a
/// previous run first (which would otherwise make `bind` fail with EADDRINUSE).
///
/// The listener is non-blocking so the bridge can poll it beside the stop token
/// and then accept without blocking.
fn bind_unix(path: &str) -> std::io::Result<std::os::unix::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("cannot bind Unix socket {path}: {e}"))
    })?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(test)]
mod stop_tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::RawFd;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// A plugin whose `safepoint` panics on its first call, after recording
    /// that it was reached.
    struct PanicAtSafepoint {
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
    // keeps the join in `boot` blocked, so the bound is the assertion. Ignored
    // by default: it needs a usable `/dev/kvm`, and `boot` takes the terminal
    // into raw mode and reads stdin for the guest, so it runs on its own, by
    // name, with `--ignored`.
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
            let outcome = boot(config(
                loader::tests::synthetic_image(0x8_0000, 0x40_0000, 0x1000),
                Some(booted),
            ))
            .map_err(|e| e.to_string());
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
            let outcome =
                boot(config(loader::tests::spinning_image(), None)).map_err(|e| e.to_string());
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
            unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), secondary, KICK_SIGNAL) };
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

    #[test]
    #[ignore]
    fn kick_before_the_run_ends_it_at_once() {
        let kvm = Kvm::new().expect("/dev/kvm is not usable");
        let vm = kvm.create_vm().unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();
        install_kick_handler();
        let kicker = VcpuThread {
            // SAFETY: pthread_self is always valid on the current thread.
            tid: unsafe { libc::pthread_self() } as u64,
            vcpu: kick_handle(&vm, &vcpu).unwrap(),
        };
        // Kicked from another thread, as a kick to itself is dropped. The
        // signal lands here before the run starts, the case a signal alone
        // loses.
        let mut kicker = std::thread::spawn(move || {
            let mut kicker = kicker;
            kicker.kick();
            kicker
        })
        .join()
        .unwrap();
        let error = vcpu.run().expect_err("the run went ahead after the kick");
        assert_eq!(error.errno(), libc::EINTR);
        immediate_exit(&mut vcpu).store(0, Ordering::SeqCst);
        assert_eq!(immediate_exit(&mut kicker.vcpu).load(Ordering::SeqCst), 0);
    }
}

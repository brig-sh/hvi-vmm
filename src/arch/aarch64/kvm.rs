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

use std::os::fd::AsFd;
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
use crate::hypervisor::guest::{Guest, VcpuRegs};
use crate::hypervisor::kvm::{kick_handle, run_vcpu, Kicker};
use crate::hypervisor::vcpus::{Kick, Vcpus};
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::{GuestArch, Plugin, RegsView, VmHandle};
use crate::sandbox::seccomp;
use crate::signal::install_kick_handler;
use crate::sync::lock_or_recover;
use crate::teardown::{join_by, kick_until_finished, StopSource, StopToken, STOP_TIMEOUT};
use crate::terminal;
use crate::LOG_PREFIX;

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
    /// The guest's RAM, virtio devices and vCPUs.
    guest: Arc<Guest<Kicker>>,
    pl011: Arc<Mutex<Pl011>>,
    /// Whoever is watching this guest, if anyone.
    plugin: Option<Arc<dyn Plugin>>,
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
            eprintln!("{LOG_PREFIX} vGICv3 unavailable ({e}); falling back to vGICv2");
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
        "{LOG_PREFIX} {num_cpus} vCPU(s)  {:?}  GICD {:#x}+{:#x}  {} {:#x}+{:#x}",
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
            eprintln!("{LOG_PREFIX} virtio-blk: {path}");
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
        eprintln!("{LOG_PREFIX} virtio-net: tap {ifname}");
        net_tap_reader = Some(reader);
        Some(VirtioNet::with_tap(file))
    } else if let Some(sock) = &cfg.net_gateway {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(stream) => match stream.try_clone() {
                Ok(reader) => {
                    eprintln!("{LOG_PREFIX} virtio-net: gvisor-tap gateway relay via {sock}");
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
    let mut kick_handles = Vec::with_capacity(num_cpus as usize);
    for id in 0..num_cpus {
        let vcpu = vm.create_vcpu(u64::from(id))?;
        let mut kvi_cpu = kvi;
        if id != 0 {
            kvi_cpu.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
        }
        vcpu.vcpu_init(&kvi_cpu)?;
        kick_handles.push(kick_handle(&vm, &vcpu)?);
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
        guest: Arc::new(Guest {
            arch: GuestArch::Aarch64,
            sandbox_id: cfg.sandbox_id.clone(),
            ram,
            shared_ram,
            ledger: Arc::new(Mutex::new(emitter)),
            block: virtio,
            net,
            vsock,
            vcpus: Arc::new(Vcpus::new(num_cpus, Kicker::new(num_cpus))),
        }),
        pl011: Arc::new(Mutex::new(Pl011::new())),
        plugin: cfg.plugin.clone(),
    };

    // Hand the plugin the guest before any vCPU runs, so nothing happens
    // between the first instruction and the attach.
    if let Some(obs) = &shared.plugin {
        obs.attach(Arc::clone(&shared.guest) as Arc<dyn VmHandle>)?;
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
    let input = {
        let (sh, vcpus) = (shared.clone(), Arc::clone(&shared.guest.vcpus));
        terminal::input::spawn(
            shared.plugin.clone(),
            stop_source.token(),
            move || vcpus.kicker().kick(0),
            move |byte| {
                let level = {
                    let mut p = lock_or_recover(&sh.pl011);
                    p.push_rx(byte);
                    p.irq_level()
                };
                let _ = sh.vm.set_irq_line(spi_gsi(UART_SPI), level);
            },
        )
    };
    let mut helpers: Vec<(&str, JoinHandle<()>)> = Vec::new();
    if let (Some(listener), Some(dev)) = (agent_listener, &shared.guest.vsock) {
        helpers.push((
            "agent bridge",
            spawn_vsock_bridge(
                listener,
                Arc::clone(dev),
                Arc::clone(&shared.guest.ram),
                Arc::clone(&vm),
                stop_source.token(),
            ),
        ));
    }
    if let (Some(reader), Some(dev)) = (net_reader, &shared.guest.net) {
        helpers.push((
            "gateway relay",
            spawn_net_gateway_reader(
                reader,
                Arc::clone(dev),
                Arc::clone(&shared.guest.ram),
                Arc::clone(&vm),
                stop_source.token(),
            ),
        ));
    }
    if let (Some(reader), Some(dev)) = (net_tap_reader, &shared.guest.net) {
        helpers.push((
            "tap relay",
            spawn_net_tap_reader(
                reader,
                Arc::clone(dev),
                Arc::clone(&shared.guest.ram),
                Arc::clone(&vm),
                stop_source.token(),
            ),
        ));
    }
    let _raw = terminal::RawTerm::enable();

    // One thread per vCPU. From here on a failure stops the guest and is
    // reported once every thread has been joined or left running, and the first
    // failure is the one reported.
    let (threads, spawned) = shared.guest.vcpus.spawn(
        vcpus
            .into_iter()
            .zip(kick_handles)
            .map(|(vcpu, kick_handle)| (vcpu, kick_handle, shared.clone())),
        |id, (vcpu, kick_handle, sh)| run_cpu(id, vcpu, kick_handle, sh),
    );
    let mut failure: Option<Box<dyn std::error::Error>> = spawned.err().map(Into::into);

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
            eprintln!("{LOG_PREFIX} {e}");
            failure.get_or_insert(e.into());
            shared.guest.vcpus.stop();
        }
        (Ok(()), Some((vmm, vcpu))) => {
            if seccomp::log_mode() {
                eprintln!(
                    "{LOG_PREFIX} seccomp: LOGGING ONLY ({}=log) — denials are recorded, not enforced",
                    seccomp::LOG_ENV
                );
            } else {
                eprintln!(
                    "{LOG_PREFIX} seccomp: on (vmm {vmm} syscalls, vcpu {vcpu}, trap on mismatch)"
                );
            }
        }
        (Ok(()), None) => eprintln!(
            "{LOG_PREFIX} seccomp: OFF (--no-sandbox) — the VMM keeps the full host syscall surface"
        ),
    }

    threads.join();

    // The guest has stopped. End the I/O threads (see `teardown`) and write
    // out the ledger tail, which the flush cadence alone would leave in the
    // buffer.
    stop_source.request_stop();
    let deadline = std::time::Instant::now() + STOP_TIMEOUT;
    kick_until_finished(&input, deadline);
    for (name, thread) in std::iter::once(("console reader", input)).chain(helpers) {
        if let Err(e) = join_by(name, thread, deadline) {
            eprintln!("{LOG_PREFIX} {e}; left running");
            failure.get_or_insert(e.into());
        }
    }
    lock_or_recover(&shared.guest.ledger).flush();
    if let Some(e) = failure {
        return Err(e);
    }

    Ok(shared.guest.vcpus.stop_reason())
}

/// Runs one vCPU until the VM stops, servicing its MMIO and PSCI exits.
fn run_cpu(cpu_id: u32, vcpu: VcpuFd, kick_handle: VcpuFd, sh: Shared) {
    run_vcpu(
        cpu_id,
        vcpu,
        kick_handle,
        &sh.guest,
        sh.plugin.as_deref(),
        |vcpu| {
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
                    // PSCI SYSTEM_RESET vs SYSTEM_OFF (and anything else ->
                    // off).
                    let s = if evtype == KVM_SYSTEM_EVENT_RESET {
                        Stop::SystemReset
                    } else {
                        Stop::SystemOff
                    };
                    sh.guest.vcpus.set_stop_reason(s);
                    return false;
                }
                Ok(VcpuExit::Hlt) => return false,
                // Kicked for a snapshot or a stop; the loop checks which.
                Ok(VcpuExit::Intr) => {}
                Ok(VcpuExit::FailEntry(reason, cpu)) => {
                    eprintln!(
                        "{LOG_PREFIX} cpu{cpu_id}: KVM entry failed reason={reason:#x} cpu={cpu}"
                    );
                    return false;
                }
                Ok(other) => {
                    eprintln!("{LOG_PREFIX} cpu{cpu_id}: unhandled exit {other:?}");
                    return false;
                }
                Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {
                    // A run that a kick cut short has completed the MMIO exit
                    // before it and left `exit_reason` as it was. Linux 5.0 to
                    // 5.2, and the stable series that took that change back to
                    // 4.14, complete the exit again on the next run, which
                    // skips one more guest instruction, so the reason is
                    // cleared here.
                    vcpu.get_kvm_run().exit_reason = KVM_EXIT_INTR;
                }
                Err(e) => {
                    eprintln!("{LOG_PREFIX} cpu{cpu_id}: KVM_RUN error: {e}");
                    return false;
                }
            }
            true
        },
    );
}

impl VcpuRegs for VcpuFd {
    fn regs(&self) -> RegsView {
        let ttbr1 = get_u64(self, REG_TTBR1_EL1);
        RegsView {
            // arm64's kernel-half page-table base is the walk root.
            root: ttbr1,
            pc: get_u64(self, REG_PC),
            cpsr: get_u64(self, REG_PSTATE),
            ttbr0: get_u64(self, REG_TTBR0_EL1),
            ttbr1,
            sctlr: get_u64(self, REG_SCTLR_EL1),
            sp_el1: get_u64(self, REG_SP_EL1),
            tcr: get_u64(self, REG_TCR_EL1),
            current_task: get_u64(self, REG_SP_EL0),
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
        dev_read(sh, sh.guest.block.as_ref(), VIRTIO_SPI, addr - VIRTIO_BASE)
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        dev_read(
            sh,
            sh.guest.net.as_ref(),
            VIRTIO_NET_SPI,
            addr - VIRTIO_NET_BASE,
        )
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
        dev_write(
            sh,
            sh.guest.block.as_ref(),
            VIRTIO_SPI,
            addr - VIRTIO_BASE,
            val,
        );
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        dev_write(
            sh,
            sh.guest.net.as_ref(),
            VIRTIO_NET_SPI,
            addr - VIRTIO_NET_BASE,
            val,
        );
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        vsock_write(sh, addr - VIRTIO_VSOCK_BASE, val);
    }
}

/// Services a read of register `off` of a virtio-blk or virtio-net device.
///
/// The device's captured events then go to the ledger, and its line is set to
/// its level.
fn dev_read<D: VirtioMmio>(sh: &Shared, dev: Option<&Arc<Mutex<D>>>, spi: u32, off: u64) -> u64 {
    let Some(dev) = dev else { return 0 };
    let (v, level, events) = {
        let mut d = dev.lock().unwrap();
        let v = d.mmio(&sh.guest.ram, off, false, 0);
        (v, d.irq_level(), d.take_events())
    };
    drain(sh, &events);
    let _ = sh.vm.set_irq_line(spi_gsi(spi), level);
    v
}

/// Services a write of `val` to register `off` of a virtio-blk or virtio-net
/// device.
///
/// The device's captured events then go to the ledger.
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
        d.mmio(&sh.guest.ram, off, true, val);
        (d.irq_level(), d.take_events())
    };
    drain(sh, &events);
    let _ = sh.vm.set_irq_line(spi_gsi(spi), level);
}

/// Services a read of virtio-vsock register `off`.
// The vsock line is set under the device lock on every path, since the bridge
// threads drive it too.
fn vsock_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.guest.vsock.as_ref() else {
        return 0;
    };
    let mut d = dev.lock().unwrap();
    let v = d.mmio(&sh.guest.ram, off, false, 0);
    let _ = sh.vm.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), d.irq_level());
    v
}

/// Services a write of `val` to virtio-vsock register `off`.
fn vsock_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.guest.vsock.as_ref() else {
        return;
    };
    let mut d = dev.lock().unwrap();
    d.mmio(&sh.guest.ram, off, true, val);
    let _ = sh.vm.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), d.irq_level());
}

/// Moves a device's captured `events` into the ledger.
fn drain(sh: &Shared, events: &[crate::events::CapturedEvent]) {
    if events.is_empty() {
        return;
    }
    let mut e = sh.guest.ledger.lock().unwrap();
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
            let (port, writer_gate) = {
                let mut d = lock_or_recover(&dev);
                let Ok(port) = d.add_conn(stream) else {
                    continue;
                };
                d.connect(&mem, port);
                let _ = vm.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), d.irq_level());
                (port, d.writer_gate(port))
            };
            let Some(writer_gate) = writer_gate else {
                continue;
            };
            // Guest -> host bytes the vCPU could not send. The writer waits
            // for the socket to take them, without the device lock.
            let (dev3, mem3, vm3, stop3) = (
                Arc::clone(&dev),
                Arc::clone(&mem),
                Arc::clone(&vm),
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
                        let _ = vm3.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), d.irq_level());
                        break;
                    }
                }
                let mut d = lock_or_recover(&dev3);
                let needed = d.flush_to_host(&mem3, port);
                let _ = vm3.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), d.irq_level());
                if !needed {
                    break;
                }
            }));
            let dev2 = Arc::clone(&dev);
            let mem2 = Arc::clone(&mem);
            let vm2 = Arc::clone(&vm);
            let stop2 = stop.clone();
            relays.retain(|handle| !handle.is_finished());
            relays.push(std::thread::spawn(move || {
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
                            eprintln!("{LOG_PREFIX} vsock bridge: {e}; connection closed");
                            break;
                        }
                    }
                    // `add_conn` makes the socket non-blocking, so a read can
                    // find nothing even after the poll.
                    let n = match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) if crate::devices::virtio::vsock::retry_read(&e) => continue,
                        Err(_) => break,
                    };
                    let gate = {
                        let mut d = lock_or_recover(&dev2);
                        let gate = d.host_data(&mem2, port, &buf[..n]);
                        let _ = vm2.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), d.irq_level());
                        gate
                    };
                    // `HostGate::wait` says why its result is not needed.
                    if let Some(gate) = gate {
                        gate.wait(|| stop2.keep_waiting(reader.as_fd()));
                    }
                }
                let mut d = lock_or_recover(&dev2);
                d.host_closed(&mem2, port);
                let _ = vm2.set_irq_line(spi_gsi(VIRTIO_VSOCK_SPI), d.irq_level());
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
            eprintln!("{LOG_PREFIX} virtio-net: {e}; tap relay stopped");
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
            eprintln!("{LOG_PREFIX} virtio-net: {e}; gateway relay stopped");
        }
    })
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

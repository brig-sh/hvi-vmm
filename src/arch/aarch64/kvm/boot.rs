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

//! The boot of an arm64 guest on KVM, from the VM and its vGIC, its RAM and
//! devices to the vCPUs and the run.

use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    kvm_vcpu_init, KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2, KVM_ARM_VCPU_PTRAUTH_ADDRESS,
    KVM_ARM_VCPU_PTRAUTH_GENERIC,
};
use kvm_ioctls::{Cap, Kvm};

use super::gic::{spi_gsi, Vgic};
use super::regs::{setup_boot_regs, try_get_u64, REG_MPIDR_EL1};
use super::vcpu::{run_cpu, VcpuContext};
use crate::arch::aarch64::fdt;
use crate::arch::aarch64::layout::{
    mpidr_affinity, place_virtio_fs, virtio_blk_base, virtio_blk_spi, GicLayout, GicVersion,
    GIC_NUM_IRQS, MPIDR_AFFINITY_MASK, RAM_BASE, UART_SPI, VIRTIO_NET_SPI, VIRTIO_VSOCK_SPI,
};
use crate::arch::aarch64::loader;
use crate::config::{BootConfig, Stop};
use crate::devices::legacy::pl011::Pl011;
use crate::devices::legacy::rtc_pl031::Pl031;
use crate::devices::virtio::block;
use crate::devices::virtio::fs::vhost_user;
use crate::devices::virtio::net::{self, VirtioNet};
use crate::devices::virtio::tap;
use crate::devices::virtio::vsock::VirtioVsock;
use crate::events::Ledger;
use crate::hypervisor::guest::{Disk, Guest, PluginThreads};
use crate::hypervisor::kvm::{kick_handle, run_guest, start_io_threads, Kicker, KvmIrqLine};
use crate::hypervisor::vcpus::Vcpus;
use crate::io_threads::NetSource;
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::GuestArch;
use crate::signal::install_kick_handler;
use crate::LOG_PREFIX;

/// Boots `cfg` on KVM (arm64), as [`crate::boot`] describes.
pub(crate) fn boot(mut cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    // The Linux backends serve only exports a caller's vhost-user daemon
    // serves, and the caller starts the daemon.
    if let Some(share) = cfg.fs_shares.first() {
        return Err(format!(
            "virtio-fs {:?}: hvi serves a directory on macOS only; on Linux, run \
             virtiofsd for it and pass --fs tag=<tag>,socket=<socket>",
            share.tag
        )
        .into());
    }
    crate::config::check_fs(&cfg.fs, cfg.vcpus.max(1))?;
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

    // The guest GIC has to exist before the DTB is built, because the version
    // KVM creates decides what the DTB describes.
    let vgic = Vgic::create(&vm)?;
    let version = vgic.version();

    // The DTB and KVM must agree on this placement.
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

    // Guest RAM: one region at RAM_BASE, backed by a shareable object (a memfd)
    // so an out-of-process plugin can map the same pages. KVM only needs a
    // valid host address, so the guest is unaffected.
    let shared_ram = SharedRam::new(cfg.mem_bytes as usize)?;
    let ram = Arc::new(GuestRam::new(
        &shared_ram,
        &[shared_ram.region_at(RAM_BASE)],
    )?);
    ram.register_kvm_slots(&vm)?;

    let disks = Disk::place(block::open_disks(&cfg.disks)?, virtio_blk_base);
    let mut net_source: Option<NetSource> = None;
    let net_dev = if let Some(ifname) = &cfg.net_tap {
        // The caller created the tap, so this only attaches to it, which brings
        // carrier up. An unusable tap fails the boot, because the built-in
        // stack would put the guest on the wrong network and nothing outside
        // the guest could tell.
        let file = tap::open(ifname).map_err(|e| format!("--net-tap {ifname}: {e}"))?;
        let reader = file
            .try_clone()
            .map_err(|e| format!("--net-tap {ifname}: cloning the tap fd: {e}"))?;
        eprintln!("{LOG_PREFIX} virtio-net: tap {ifname}");
        net_source = Some(NetSource::Tap(reader));
        Some(VirtioNet::with_tap(file))
    } else if let Some(sock) = &cfg.net_gateway {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(stream) => match stream.try_clone() {
                Ok(reader) => {
                    eprintln!("{LOG_PREFIX} virtio-net: gvisor-tap gateway relay via {sock}");
                    net_source = Some(NetSource::Gateway(reader));
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
    // virtio-fs: one transport per export, each served by the caller's daemon.
    let fs = vhost_user::attach(&cfg.fs, shared_ram.as_raw_fd(), |index| {
        place_virtio_fs(index, &gic, Some(GIC_NUM_IRQS)).map_err(std::io::Error::other)
    })?;

    let has_net = net.is_some();
    let has_vsock = vsock.is_some();
    let fdt_devices = fdt::VirtioDevices {
        blk_count: disks.len(),
        net: has_net,
        vsock: has_vsock,
        fs_count: fs.len(),
    };

    let ledger = Ledger::new(cfg.events.as_deref(), &cfg.sandbox_id)?;
    let layout = loader::Payload {
        kernel: &cfg.kernel,
        initramfs: cfg.initramfs.as_deref(),
        cmdline: &cfg.cmdline,
    }
    .load(ram.memory(), cfg.mem_bytes, &gic, num_cpus, fdt_devices)?;

    vgic.set_regions(&gic)?;

    // Secondaries start powered off, and the guest's PSCI `CPU_ON` wakes them.
    let mut kvi = kvm_vcpu_init::default();
    vm.get_preferred_target(&mut kvi)?;
    kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
    // KVM hides pointer authentication from the guest unless asked for it, and
    // refuses a request for one of its two kinds without the other.
    if vm.check_extension(Cap::ArmPtrAuthAddress) && vm.check_extension(Cap::ArmPtrAuthGeneric) {
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS | 1 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
    }
    let mut vcpus = Vec::with_capacity(num_cpus as usize);
    let mut kick_handles = Vec::with_capacity(num_cpus as usize);
    for id in 0..num_cpus {
        let vcpu = vm.create_vcpu(u64::from(id))?;
        let mut kvi_cpu = kvi;
        if id != 0 {
            kvi_cpu.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
        }
        vcpu.vcpu_init(&kvi_cpu)?;
        // The devicetree names each vCPU by the affinity KVM gives it at reset.
        // A host kernel that numbered vCPUs another way would leave the guest's
        // CPU_ON unable to reach them.
        let affinity = try_get_u64(&vcpu, REG_MPIDR_EL1)? & MPIDR_AFFINITY_MASK;
        let expected = u64::from(mpidr_affinity(id));
        if affinity != expected {
            return Err(format!(
                "vcpu{id}: KVM gave it affinity {affinity:#x}, but the devicetree names it {expected:#x}"
            )
            .into());
        }
        kick_handles.push(kick_handle(&vm, &vcpu)?);
        vcpus.push(vcpu);
    }

    vgic.finalize(GIC_NUM_IRQS)?;

    setup_boot_regs(&vcpus[0], layout.kernel_addr, layout.dtb_addr);

    let vm = Arc::new(vm);
    let context = VcpuContext {
        guest: Arc::new(Guest {
            arch: GuestArch::Aarch64,
            sandbox_id: cfg.sandbox_id.clone(),
            ram,
            shared_ram,
            ledger: Arc::new(ledger),
            disks,
            net,
            vsock,
            vcpus: Arc::new(Vcpus::new(
                num_cpus,
                Kicker::new(num_cpus),
                cfg.take_stop_handle()?,
            )),
            plugin_threads: PluginThreads::new(),
        }),
        pl011: Arc::new(Mutex::new(Pl011::new())),
        rtc: Arc::new(Mutex::new(Pl031::new())),
        fs: Arc::new(fs),
        plugin: cfg.plugin.clone(),
    };

    let line = |spi| Arc::new(KvmIrqLine::new(Arc::clone(&vm), spi_gsi(spi)));
    context.pl011.lock().unwrap().connect_irq(line(UART_SPI));
    context.guest.connect_irqs(
        // `open_disks` refused more disks than there are SPIs.
        |index| line(virtio_blk_spi(index).expect("every disk should have an SPI")),
        line(VIRTIO_NET_SPI),
        line(VIRTIO_VSOCK_SPI),
    );
    for export in context.fs.iter() {
        export.dev.lock().unwrap().connect_irq(line(export.irq));
    }
    // A vCPU in an export's reset waits on its daemon, where no kick reaches
    // it. Ending the connections at the stop frees it.
    let fs = Arc::clone(&context.fs);
    context
        .guest
        .vcpus
        .on_stop(move || vhost_user::shut_down(&fs));

    let (filters, mut io_threads, ledger_guard) = start_io_threads(
        &cfg,
        &context.guest,
        {
            let pl011 = Arc::clone(&context.pl011);
            move |byte| pl011.lock().unwrap().push_rx(byte)
        },
        net_source,
    )?;
    vhost_user::start_interrupt_threads(&context.fs, &mut io_threads);

    // The run closes the ledger from here on.
    ledger_guard.disarm();

    run_guest(
        &context.guest,
        &context,
        vcpus,
        kick_handles,
        run_cpu,
        filters,
        io_threads,
    )
}

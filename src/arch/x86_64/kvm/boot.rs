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

//! The boot of an x86-64 guest on KVM, from the VM, its RAM and devices to the
//! vCPUs and the run.

use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use kvm_bindings::kvm_pit_config;
use kvm_ioctls::{Cap, Kvm};

use super::cpuid::guest_cpuid;
use super::regs::{setup_long_mode, write_boot_gdt, write_boot_page_tables};
use super::vcpu::{run_cpu, VcpuContext};
use crate::arch::x86_64::acpi::{self, MmioDevice};
use crate::arch::x86_64::layout::{
    virtio_blk_base, virtio_blk_gsi, virtio_fs_base, virtio_fs_gsi, ACPI_ADDR, COM1_GSI,
    HIGH_RAM_BASE, MAX_FS_DEVICES, MMIO_GAP_START, MPTABLE_ADDR, RAM_BASE, VIRTIO_NET_BASE,
    VIRTIO_NET_GSI, VIRTIO_SIZE, VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_GSI,
};
use crate::arch::x86_64::loader::{splice_kernel_args, LoadedKernel};
use crate::arch::x86_64::{mptable, MAX_VCPUS};
use crate::config::{BootConfig, Stop};
use crate::devices::legacy::acpi_pm::PmRegisters;
use crate::devices::legacy::rtc_cmos::RtcCmos;
use crate::devices::legacy::uart16550::Uart16550;
use crate::devices::virtio::block;
use crate::devices::virtio::fs::vhost_user::{self, Export};
use crate::devices::virtio::net::{self, VirtioNet};
use crate::devices::virtio::tap;
use crate::devices::virtio::vsock::VirtioVsock;
use crate::events::Ledger;
use crate::hypervisor::guest::{Disk, Guest, PluginThreads};
use crate::hypervisor::kvm::{kick_handle, run_guest, start_io_threads, Kicker, KvmIrqLine};
use crate::hypervisor::vcpus::{Kick, Vcpus};
use crate::io_threads::NetSource;
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::{GuestArch, RamRegion};
use crate::signal::install_kick_handler;
use crate::LOG_PREFIX;

/// Returns the virtio-mmio devices the DSDT describes, the disks first and in
/// order, then net, vsock and the exports.
///
/// Linux registers them in this order, so the disks keep their argv order. The
/// guest still has to tell them apart by serial.
fn mmio_devices(disks: usize, net: bool, vsock: bool, exports: &[Export]) -> Vec<MmioDevice> {
    let device = |base: u64, gsi: u32| MmioDevice {
        base,
        size: VIRTIO_SIZE,
        gsi,
    };
    let mut devices: Vec<MmioDevice> = (0..disks)
        .filter_map(|index| Some(device(virtio_blk_base(index)?, virtio_blk_gsi(index)?)))
        .collect();
    if net {
        devices.push(device(VIRTIO_NET_BASE, VIRTIO_NET_GSI));
    }
    if vsock {
        devices.push(device(VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_GSI));
    }
    devices.extend(exports.iter().map(|export| device(export.base, export.irq)));
    devices
}

/// Boots `cfg` on KVM (x86-64), as [`crate::boot`] describes.
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
    let num_cpus = cfg.vcpus.max(1);
    if num_cpus > MAX_VCPUS {
        return Err(
            format!("x86-64 supports at most {MAX_VCPUS} vCPUs (asked for {num_cpus})").into(),
        );
    }
    install_kick_handler();

    let kvm = Kvm::new()?;
    // A kick relies on `kvm_run.immediate_exit`. Without it, one that lands
    // just before `KVM_RUN` is lost, and a stop with it.
    if !kvm.check_extension(Cap::ImmediateExit) {
        return Err("hvi needs KVM_CAP_IMMEDIATE_EXIT, which Linux 4.11 added".into());
    }
    let vm = kvm.create_vm()?;

    // Intel VMX needs a TSS and an identity-map page for guest-mode setup, even
    // though the guest enters directly in long mode. Set them before creating
    // the irqchip and the vCPUs.
    vm.set_tss_address(0xfffb_d000)?;
    vm.set_identity_map_address(0xfffb_c000)?;

    // Guest RAM, split around the sub-4 GiB MMIO hole (see MMIO_GAP_START): the
    // backing object is one contiguous memfd, and the high half is the bytes
    // after the low half, mapped at HIGH_RAM_BASE. The object is shareable so
    // an out-of-process plugin can map the same pages; KVM only needs a valid
    // host address, so the guest is unaffected.
    let low_bytes = cfg.mem_bytes.min(MMIO_GAP_START);
    let high_bytes = cfg.mem_bytes.saturating_sub(low_bytes);
    let shared_ram = SharedRam::new(cfg.mem_bytes as usize)?;
    let mut regions = vec![RamRegion {
        gpa: RAM_BASE,
        size: low_bytes,
        file_offset: 0,
    }];
    if high_bytes > 0 {
        regions.push(RamRegion {
            gpa: HIGH_RAM_BASE,
            size: high_bytes,
            file_offset: low_bytes,
        });
        eprintln!(
            "{LOG_PREFIX} RAM {} MiB: {} MiB at {:#x} + {} MiB at {HIGH_RAM_BASE:#x}",
            cfg.mem_bytes >> 20,
            low_bytes >> 20,
            RAM_BASE,
            high_bytes >> 20
        );
    }
    let ram = Arc::new(GuestRam::new(&shared_ram, &regions)?);
    ram.register_kvm_slots(&vm)?;

    vm.create_irq_chip()?;
    vm.create_pit2(kvm_pit_config::default())?;

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
        match (virtio_fs_base(index), virtio_fs_gsi(index)) {
            (Some(base), Some(gsi)) => Ok((base, gsi)),
            _ => Err(std::io::Error::other(format!(
                "virtio-fs export {index}: x86-64 has interrupt lines for {MAX_FS_DEVICES} exports"
            ))),
        }
    })?;

    // Kernel command line: the caller's args and the ttyS0 console. The devices
    // are in the DSDT.
    let ours = "console=ttyS0";
    let cmdline = splice_kernel_args(cfg.cmdline.trim(), ours);

    // Load the kernel, write boot_params and the command line, then place the
    // initrd, the MP table and the ACPI tables.
    let initrd_len = cfg.initramfs.as_ref().map_or(0, |v| v.len() as u64);
    let kernel = LoadedKernel::load(ram.memory(), &cfg.kernel, &cmdline, initrd_len)?;
    if let (Some(addr), Some(initramfs)) = (kernel.initrd_addr, &cfg.initramfs) {
        ram.write(addr, initramfs)?;
    }
    ram.write(MPTABLE_ADDR, &mptable::build(num_cpus))?;
    ram.write(
        ACPI_ADDR,
        &acpi::build(
            num_cpus,
            &mmio_devices(disks.len(), net.is_some(), vsock.is_some(), &fs),
        ),
    )?;
    write_boot_page_tables(&ram)?;
    write_boot_gdt(&ram)?;
    eprintln!(
        "{LOG_PREFIX} {num_cpus} vCPU(s)  {} entry@{:#x}",
        kernel.format, kernel.entry
    );

    // vCPUs. The BSP enters in long mode; APs wait for the guest's SIPI.
    let cpuid = guest_cpuid(kvm.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?);
    let trace = std::env::var_os("HVI_X86_TRACE").is_some();
    // What the guest gets depends on the host's KVM, so the trace prints leaf 1
    // and KVM's feature leaf.
    if trace {
        for entry in cpuid.as_slice() {
            if entry.function == 1 || entry.function == 0x4000_0001 {
                stderrln!(
                    "[trace] CPUID {:#x}: eax={:#010x} ecx={:#010x}",
                    entry.function,
                    entry.eax,
                    entry.ecx
                );
            }
        }
    }
    let mut vcpus = Vec::with_capacity(num_cpus as usize);
    let mut kick_handles = Vec::with_capacity(num_cpus as usize);
    for id in 0..num_cpus {
        let vcpu = vm.create_vcpu(u64::from(id))?;
        vcpu.set_cpuid2(&cpuid)?;
        if id == 0 {
            setup_long_mode(&vcpu, kernel.entry, kernel.zero_page_addr)?;
        }
        kick_handles.push(kick_handle(&vm, &vcpu)?);
        vcpus.push(vcpu);
    }

    let vm = Arc::new(vm);
    let context = VcpuContext {
        guest: Arc::new(Guest {
            arch: GuestArch::X86_64,
            sandbox_id: cfg.sandbox_id.clone(),
            ram,
            shared_ram,
            ledger: Arc::new(Ledger::new(cfg.events.as_deref(), &cfg.sandbox_id)?),
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
        uart: Arc::new(Mutex::new(Uart16550::new())),
        rtc: Arc::new(Mutex::new(RtcCmos::new())),
        pm: Arc::new(Mutex::new(PmRegisters::default())),
        fs: Arc::new(fs),
        plugin: cfg.plugin.clone(),
    };

    let line = |gsi| Arc::new(KvmIrqLine::new(Arc::clone(&vm), gsi));
    context.uart.lock().unwrap().connect_irq(line(COM1_GSI));
    context.guest.connect_irqs(
        // `open_disks` refused more disks than there are GSIs.
        |index| line(virtio_blk_gsi(index).expect("every disk should have a GSI")),
        line(VIRTIO_NET_GSI),
        line(VIRTIO_VSOCK_GSI),
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
            let uart = Arc::clone(&context.uart);
            move |byte| uart.lock().unwrap().push_rx(byte)
        },
        net_source,
    )?;
    vhost_user::start_interrupt_threads(&context.fs, &mut io_threads);
    // Debug watchdog: force a register dump on a stuck guest (HVI_X86_TRACE).
    if trace {
        let guest = Arc::clone(&context.guest);
        io_threads.spawn("trace watchdog", move |watch| {
            for _ in 0..4 {
                match watch.sleep(std::time::Duration::from_secs(2)) {
                    Ok(true) => guest.vcpus.kicker().kick(0),
                    Ok(false) => break,
                    Err(e) => {
                        stderrln!("{LOG_PREFIX} trace watchdog: {e}; trace watchdog stopped");
                        break;
                    }
                }
            }
        });
    }

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

#[cfg(test)]
mod tests {
    use super::{boot, mmio_devices, MmioDevice};
    use crate::config::BootConfig;

    // The DSDT lists the disks first, in order, so Linux registers them in argv
    // order.
    #[test]
    fn mmio_devices_list_every_disk_first_and_in_order() {
        let gsis = |disks, net, vsock| -> Vec<(u64, u32)> {
            mmio_devices(disks, net, vsock, &[])
                .iter()
                .map(|d| (d.base, d.gsi))
                .collect()
        };
        assert_eq!(
            gsis(3, true, false),
            [
                (0xd000_0000, 5),
                (0xd000_0600, 9),
                (0xd000_0800, 10),
                (0xd000_0200, 6)
            ]
        );
        assert!(gsis(0, false, false).is_empty());
        assert_eq!(gsis(1, false, true), [(0xd000_0000, 5), (0xd000_0400, 7)]);
        assert!(mmio_devices(1, false, false, &[]).iter().all(|d| *d
            == MmioDevice {
                base: 0xd000_0000,
                size: 0x200,
                gsi: 5
            }));
    }

    #[test]
    fn more_vcpus_than_the_cap_are_refused() {
        let cfg = BootConfig {
            kernel: Vec::new(),
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
            sandbox_id: "cap-test".to_string(),
            vcpus: 255,
            agent_sock: None,
            plugin: None,
            sandbox: false,
            stop: None,
        };
        let error = boot(cfg).unwrap_err().to_string();
        assert_eq!(error, "x86-64 supports at most 254 vCPUs (asked for 255)");
    }
}

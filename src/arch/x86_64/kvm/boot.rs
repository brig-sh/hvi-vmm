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
use kvm_ioctls::{Cap, Kvm, VmFd};

use super::cpuid::guest_cpuid;
use super::regs::{setup_long_mode, write_boot_gdt, write_boot_page_tables};
use super::vcpu::{port_bus, run_cpu, VcpuContext};
use crate::arch::x86_64::acpi;
use crate::arch::x86_64::layout::{
    virtio_slots, ACPI_ADDR, COM1_GSI, HIGH_RAM_BASE, MMIO_GAP_START, MPTABLE_ADDR, RAM_BASE,
};
use crate::arch::x86_64::loader::{splice_kernel_args, LoadedKernel};
use crate::arch::x86_64::mptable;
use crate::config::{BootConfig, Stop};
use crate::devices::irq::{self, Chip as _};
use crate::devices::legacy::uart16550::Uart16550;
use crate::devices::manager::{DeviceManager, Devices};
use crate::events::Ledger;
use crate::hypervisor::guest::{mmio_report_limiter, Guest, PluginThreads};
use crate::hypervisor::kvm::{
    self, kick_handle, register_ioeventfd, run_guest, start_io_threads, Kicker,
};
use crate::hypervisor::vcpus::{Kick, Vcpus};
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::{GuestArch, RamRegion};
use crate::signal::install_kick_handler;
use crate::LOG_PREFIX;

/// Boots `cfg` on KVM (x86-64), as [`crate::boot`] describes.
pub(crate) fn boot(mut cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    let num_cpus = cfg.vcpus.max(1);
    // Refuse more virtio devices than the IOAPIC has lines for before any of
    // them opens.
    let slots = virtio_slots();
    slots.check_room(cfg.virtio_device_count())?;
    install_kick_handler();

    let kvm = Kvm::new()?;
    // A kick relies on `kvm_run.immediate_exit`. Without it, one that lands
    // just before `KVM_RUN` is lost, and a stop with it.
    if !kvm.check_extension(Cap::ImmediateExit) {
        return Err("hvi needs KVM_CAP_IMMEDIATE_EXIT, which Linux 4.11 added".into());
    }
    let vm = Arc::new(kvm.create_vm()?);

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

    // The ledger exists first, since each device's transport writes to it.
    let ledger = Arc::new(Ledger::new(cfg.events.as_deref(), &cfg.sandbox_id)?);
    let irq_chip = KernelIoApic {
        vm: Arc::clone(&vm),
    };
    let com1_line = irq_chip.line(COM1_GSI);
    let mut devices = DeviceManager::new(&ram, &ledger, slots, irq_chip, {
        let vm = Arc::clone(&vm);
        move |fd, address, value| register_ioeventfd(&vm, fd, address, value)
    });
    devices.attach_virtio_devices(&cfg, shared_ram.as_raw_fd())?;

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
        &acpi::build(num_cpus, &acpi::virtio_devices(devices.records())),
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

    let Devices {
        mmio_bus,
        disks,
        net,
        mut host,
    } = devices.finish();
    let uart = Arc::new(Mutex::new(Uart16550::new()));
    let context = VcpuContext {
        guest: Arc::new(Guest {
            arch: GuestArch::X86_64,
            sandbox_id: cfg.sandbox_id.clone(),
            ram,
            shared_ram,
            ledger,
            mmio_bus,
            mmio_report_limiter: mmio_report_limiter(),
            disks,
            net,
            vcpus: Arc::new(Vcpus::new(
                num_cpus,
                Kicker::new(num_cpus),
                cfg.take_stop_handle()?,
            )),
            plugin_threads: PluginThreads::new(),
        }),
        port_bus: Arc::new(port_bus(&uart)?),
        plugin: cfg.plugin.clone(),
    };

    uart.lock().unwrap().connect_irq(com1_line);
    // Debug watchdog: force a register dump on a stuck guest (HVI_X86_TRACE).
    if trace {
        let guest = Arc::clone(&context.guest);
        host.spawn("trace watchdog", move |watch| {
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
    let (filters, io_threads, ledger_guard) = start_io_threads(
        &cfg,
        &context.guest,
        move |byte| uart.lock().unwrap().push_rx(byte),
        host,
    )?;

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

/// The in-kernel IOAPIC of an x86-64 guest on KVM, whose lines are its pins.
struct KernelIoApic {
    /// The VM whose IOAPIC has the lines.
    vm: Arc<VmFd>,
}

impl irq::Chip for KernelIoApic {
    fn line(&self, gsi: u32) -> Arc<dyn irq::Line> {
        Arc::new(kvm::IrqLine::new(Arc::clone(&self.vm), gsi))
    }
}

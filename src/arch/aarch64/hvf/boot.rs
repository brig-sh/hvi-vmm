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

//! The boot of an arm64 guest on Hypervisor.framework, from the VM and its GIC,
//! its RAM and devices and the sandbox to the vCPU threads and the run.

use std::sync::Arc;

use applevisor::prelude::{VirtualMachine, VirtualMachineConfig};

use super::gic::{gic_config, gic_layout, HvfIrqLine};
use super::kick::Kicker;
use super::vcpu::{run_cpu, VcpuContext};
use crate::arch::aarch64::fdt;
use crate::arch::aarch64::layout::{VirtioSlots, RAM_BASE, UART_BASE, UART_SPI};
use crate::arch::aarch64::loader;
use crate::config::{BootConfig, Stop};
use crate::devices::irq::IrqLine;
use crate::devices::manager::{DeviceManager, Devices};
use crate::events::Ledger;
use crate::hypervisor::guest::{mmio_report_limiter, Guest, PluginThreads};
use crate::hypervisor::vcpus::Vcpus;
use crate::io_threads::IoThreads;
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::GuestArch;
use crate::run::{record_start, run_to_stop};
use crate::sandbox::seatbelt;
use crate::signal::install_kick_handler;
use crate::teardown::StopSource;
use crate::terminal;
use crate::LOG_PREFIX;
use vm_memory::{Address, GuestMemoryBackend, GuestMemoryRegion};

/// Boots `cfg` on Hypervisor.framework, as [`crate::boot`] describes.
pub(crate) fn boot(mut cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    // Refuse a kernel that is not a flat Image before the VM, its RAM, the
    // devices and the event ledger exist.
    loader::LoadedKernel::from_header(&cfg.kernel)?;
    let num_cpus = cfg.vcpus.max(1);

    let gic = gic_layout()?;
    eprintln!(
        "{LOG_PREFIX} {num_cpus} vCPU(s)  GICD {:#x}+{:#x}  GICR {:#x}+{:#x}  UART {:#x}",
        gic.gicd_base, gic.gicd_size, gic.gicr_base, gic.gicr_size, UART_BASE
    );
    // Every device range sits above the UART, so the GIC has to end at or below
    // it. The framework sizes the redistributor region, so the GIC's end is
    // known only here.
    let gic_end = gic.gicr_base.saturating_add(gic.gicr_size);
    if gic_end > UART_BASE {
        return Err(format!(
            "placing the devices: the GIC ends at {gic_end:#x}, past the UART at {UART_BASE:#x}"
        )
        .into());
    }
    let vm = VirtualMachine::with_gic(VirtualMachineConfig::new(), gic_config(&gic)?)?;

    // Guest RAM: one region mapped at RAM_BASE, backed by a shareable object
    // rather than allocated by applevisor, so an out-of-process plugin can map
    // the same pages. applevisor's memory_create uses hv_vm_allocate, which
    // hands back a pointer with no nameable backing object; hv_vm_map accepts
    // any page-aligned host pointer, so the guest gets the mapping `GuestRam`
    // made of the object. This is the path `hvi smoke --shm` exercises.
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

    // Each device's transport writes to the ledger, and its line kicks the
    // vCPUs, so both exist before the devices.
    let ledger = Arc::new(Ledger::new(cfg.events.as_deref(), &cfg.sandbox_id)?);
    if ledger.is_enabled() {
        eprintln!(
            "{LOG_PREFIX} event ledger: {}",
            cfg.events.as_deref().unwrap_or("")
        );
    }
    let vcpus = Arc::new(Vcpus::new(
        num_cpus,
        Kicker::new(vm.clone(), num_cpus),
        cfg.take_stop_handle()?,
    ));
    let placement = VirtioSlots {
        gic,
        num_irqs: None,
    };
    let mut devices = DeviceManager::new(&ram, &ledger, placement, {
        let (vm, vcpus) = (vm.clone(), Arc::clone(&vcpus));
        move |spi| {
            Arc::new(HvfIrqLine::new(vm.clone(), spi, Some(Arc::clone(&vcpus)))) as Arc<dyn IrqLine>
        }
    });
    let pl011 = devices.attach_uart_and_rtc()?;
    devices.attach_virtio_devices(&cfg)?;
    // Seatbelt allows using a socket but not creating one, so the agent socket
    // and the stop source's socket pair exist before it goes in.
    let stop_source = StopSource::new()?;
    let fdt_devices = fdt::virtio_devices(devices.records());

    let layout = loader::Payload {
        kernel: &cfg.kernel,
        initramfs: cfg.initramfs.as_deref(),
        cmdline: &cfg.cmdline,
    }
    .load(ram.memory(), cfg.mem_bytes, &gic, num_cpus, &fdt_devices)?;

    let Devices {
        mmio_bus,
        disks,
        net,
        host,
        exports,
    } = devices.finish();
    let context = VcpuContext {
        vm: vm.clone(),
        guest: Arc::new(Guest {
            arch: GuestArch::Aarch64,
            sandbox_id: cfg.sandbox_id.clone(),
            ram,
            shared_ram,
            ledger,
            mmio_bus,
            mmio_report_limiter: mmio_report_limiter(),
            disks,
            net,
            vcpus,
            plugin_threads: PluginThreads::new(),
        }),
        kernel_addr: layout.kernel_addr,
        dtb_addr: layout.dtb_addr,
        plugin: cfg.plugin.clone(),
    };
    pl011
        .lock()
        .unwrap()
        .connect_irq(Arc::new(HvfIrqLine::new(vm.clone(), UART_SPI, None)));

    // Hand the plugin the guest before any vCPU runs, so nothing happens
    // between the first instruction and the attach.
    let (plugin_threads, ledger_guard) = context.guest.attach(context.plugin.as_ref())?;

    // A binary's stop signals get their handlers, and the thread that receives
    // them starts, before the terminal goes into raw mode, so a first stop
    // signal stops the run rather than ending the process with the terminal
    // raw. The sandbox below confines the whole process, that thread included.
    crate::signal::start_stop_signal_thread()?;

    let _raw = terminal::RawTerm::enable();

    // Confine the process before the first I/O thread exists. Everything above
    // acquires host authority (the VM, the guest-RAM mapping, the block file,
    // the ledger, the gateway connection, the listeners, the terminal), and
    // everything below only services guest I/O with what is already open. An
    // error here returns before there is an I/O thread to stop. See
    // `sandbox::seatbelt`.
    //
    // A profile that does not install fails the boot, because continuing would
    // leave a guest-facing process with the host's full authority.
    if cfg.sandbox {
        let fs_access: Vec<_> = exports
            .iter()
            .map(|export| (export.root.clone(), export.writable))
            .collect();
        seatbelt::enter_with_shares(&fs_access)
            .map_err(|e| format!("{e}; re-run with --no-sandbox to boot unconfined"))?;
        stderrln!("{LOG_PREFIX} seatbelt: on (deny default)");
    } else {
        stderrln!("{LOG_PREFIX} seatbelt: OFF (--no-sandbox); the VMM keeps full host authority");
    }

    // The I/O threads, which are joined after the vCPUs. `teardown` describes
    // the stop.
    install_kick_handler();
    let io_threads = IoThreads::start(
        stop_source,
        &context.guest,
        context.plugin.clone(),
        move |byte| pl011.lock().unwrap().push_rx(byte),
        plugin_threads,
        host,
    );
    // The run closes the ledger from here on.
    ledger_guard.disarm();
    let _current = record_start(&context.guest, cfg.sandbox);
    // One thread per vCPU. From here on a failure stops the guest and is
    // reported once every thread has been joined or left running, and the first
    // failure is the one reported.
    let (threads, spawned) = context
        .guest
        .vcpus
        .spawn((0..num_cpus).map(|_| context.clone()), run_cpu);
    let failure: Option<Box<dyn std::error::Error + Send + Sync>> = spawned.err().map(Into::into);
    let result = run_to_stop(&context.guest, threads, failure, io_threads);

    // Report what the guest used, so a limit can be set from a real number.
    for (index, export) in exports.iter().enumerate() {
        export.report_usage(index);
    }

    // `boot` keeps the run's claim when it sees a `LeftRunning` error, so the
    // error goes back as `run_to_stop` returned it.
    result
}

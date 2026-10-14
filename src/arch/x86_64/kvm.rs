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

//! The x86-64 guest on KVM, SMP-capable.
//!
//! The x86 counterpart of `aarch64::kvm`. KVM runs the LAPIC, the IOAPIC and
//! the PIT in the kernel (`create_irq_chip`, `create_pit2`), and the guest
//! brings up its APs with INIT-SIPI-SIPI, which the kernel handles. The VMM
//! enters the BSP in long mode and runs every vCPU thread. It builds the
//! initial long-mode state (identity page tables, flat 64-bit segments,
//! CR0/CR3/CR4/EFER), loads the bzImage or vmlinux, writes `boot_params` (see
//! `super::loader`), and enters at the 64-bit entry with RSI pointing at the
//! zero page.
//!
//! Devices are the shared virtio-mmio blk/net/vsock (serviced on
//! `KVM_EXIT_MMIO`) plus a 16550 serial on port I/O (`KVM_EXIT_IO`). The guest
//! powers off and resets through the ACPI PM1 control and reset registers,
//! which the exit loop serves as ports. A guest without ACPI resets through the
//! i8042's CPU-reset command. A plugin, if the caller supplied one, sees CR3 as
//! the walk root.
//!
//! A long-mode entry needs KVM's `set_tss_address` and identity map, which
//! Intel VMX requires. It also needs `set_cpuid2`, since the guest reads CPUID
//! for feature detection and early boot triple-faults without it. That CPUID
//! must advertise RDRAND, or the KASLR entropy path stalls. Set
//! `HVI_X86_TRACE=1` for exit and register tracing.
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this
// VMM's own.
#![allow(clippy::disallowed_methods)]

use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kvm_bindings::{kvm_dtable, kvm_pit_config, kvm_segment, CpuId};
use kvm_ioctls::{Cap, Kvm, VcpuExit, VcpuFd};

use crate::arch::x86_64::acpi;
use crate::arch::x86_64::layout::{
    ACPI_ADDR, ACPI_PM_PORT, BOOT_STACK, COM1_GSI, COM1_PORT, GDT_ADDR, HIGH_RAM_BASE,
    I8042_COMMAND_PORT, MMIO_GAP_START, MPTABLE_ADDR, PDPT_ADDR, PML4_ADDR, RAM_BASE,
    VIRTIO_BLK_BASE, VIRTIO_BLK_GSI, VIRTIO_NET_BASE, VIRTIO_NET_GSI, VIRTIO_SIZE,
    VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_GSI,
};
use crate::arch::x86_64::loader::LoadedKernel;
use crate::arch::x86_64::{mptable, MAX_VCPUS};
use crate::checkpoint::capture::Console;
use crate::checkpoint::profile::{
    device, hex, sha256_hex, MachineProfile, ProfileCell, UNKNOWN, X86Platform,
};
use crate::config::{BootConfig, Stop};
use crate::devices::legacy::acpi_pm::{PmRegisters, PM_REGISTERS_LEN};
use crate::devices::legacy::rtc_cmos::{RtcCmos, RTC_DATA_PORT, RTC_INDEX_PORT};
use crate::devices::legacy::uart16550::Uart16550;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::net::{self, VirtioNet};
use crate::devices::virtio::tap;
use crate::devices::virtio::vsock::VirtioVsock;
use crate::events::{CapturedEvent, Emitter};
use crate::hypervisor::guest::{Guest, PluginThreads, SafepointVcpu};
use crate::hypervisor::kvm::{
    kick_handle, run_guest, run_vcpu, start_io_threads, unhandled_exit, Kicker, KvmIrqLine,
};
use crate::hypervisor::vcpus::{Kick, Outcome, Vcpus};
use crate::io_threads::NetSource;
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::{GuestArch, Plugin, RamRegion, RegsView};
use crate::signal::install_kick_handler;
use crate::sync::lock_or_recover;
use crate::LOG_PREFIX;

/// The i8042's CPU-reset command, on [`I8042_COMMAND_PORT`].
const I8042_RESET_CPU: u8 = 0xfe;
/// The i8042 status the guest reads.
///
/// The input buffer reads empty, so the kernel's reset path sends its command
/// at once. The other bits read set, as on a port with nothing behind it, so a
/// guest that probes for the controller finds none at its first flush.
const I8042_STATUS: u8 = !0x02;

// Long-mode control-register values (Firecracker's boot values).
const CR0_PE_PG: u64 = 0x8005_0033; // PE|MP|ET|NE|WP|AM|PG
const CR4_PAE: u64 = 0x0000_0020; // PAE
const EFER_LME_LMA: u64 = 0x0000_0500; // LME|LMA
const PDE64_PRESENT_RW_PS: u64 = 0x83; // present | writable | page-size (1 GiB)
const PDE64_PRESENT_RW: u64 = 0x03; // present | writable (table)

/// The CPUID leaf 1 ECX bit that says the local APIC timer has a TSC-deadline
/// mode.
const CPUID_1_ECX_TSC_DEADLINE_TIMER: u32 = 1 << 24;
/// The CPUID leaf 1 ECX bit for RDRAND.
const CPUID_1_ECX_RDRAND: u32 = 1 << 30;
/// The CPUID leaf 1 ECX bit that says the CPU runs under a hypervisor.
const CPUID_1_ECX_HYPERVISOR: u32 = 1 << 31;
/// The CPUID leaf 7, subleaf 0, EBX bit for RDSEED.
const CPUID_7_0_EBX_RDSEED: u32 = 1 << 18;

/// The shortest pause the guest is notified of.
///
/// It stays below the soft-lockup and RCU stall thresholds a Linux guest can be
/// set to, and above the pause an observation takes. Each notice resets the
/// soft-lockup check of its vCPU and the guest-wide RCU stall and hung-task
/// checks, so leaving out shorter pauses keeps those checks armed through
/// frequent observations.
const MIN_NOTIFIED_PAUSE: Duration = Duration::from_secs(1);

/// State shared across the vCPU threads.
#[derive(Clone)]
struct Shared {
    /// The guest's RAM, virtio devices and vCPUs.
    guest: Arc<Guest<Kicker>>,
    uart: Arc<Mutex<Uart16550>>,
    /// The CMOS RTC: without it a guest hangs in read_persistent_clock64().
    rtc: Arc<Mutex<RtcCmos>>,
    /// The ACPI PM1 and reset registers, which the guest writes to power off or
    /// reset.
    pm: Arc<Mutex<PmRegisters>>,
    /// Whoever is watching this guest, if anyone.
    plugin: Option<Arc<dyn Plugin>>,
}

/// Returns `supported`, the CPUID KVM supports, with the bits added that the
/// guest needs.
///
/// RDRAND and RDSEED give the guest's early KASLR and entropy path a source,
/// which the host must have. The hypervisor bit tells the guest it runs under
/// KVM, so it reads KVM's leaves from `0x4000_0000` and uses the paravirtual
/// features they list. The TSC-deadline bit offers the local APIC timer mode
/// that KVM's in-kernel local APIC emulates. Every KVM that hvi runs on reports
/// `KVM_CAP_TSC_DEADLINE_TIMER`, so the bit is set without a check. Newer KVMs
/// report the hypervisor and TSC-deadline bits themselves.
fn guest_cpuid(mut supported: CpuId) -> CpuId {
    for entry in supported.as_mut_slice() {
        match entry.function {
            1 => {
                entry.ecx |=
                    CPUID_1_ECX_TSC_DEADLINE_TIMER | CPUID_1_ECX_RDRAND | CPUID_1_ECX_HYPERVISOR;
            }
            7 if entry.index == 0 => entry.ebx |= CPUID_7_0_EBX_RDSEED,
            _ => {}
        }
    }
    supported
}

/// Splices the parameters we own into a caller-supplied kernel command line.
///
/// A bare `--` on a Linux command line ends the kernel's own parameters:
/// everything after it is handed to init as argv. Callers that boot a wrapper
/// init end their line that way -- urunc's is
/// `... rdinit=/init -- <container entrypoint>` -- so appending our device
/// descriptors would put them on the wrong side of the separator. The guest
/// would then come up with no virtio devices at all and pass
/// `virtio_mmio.device=...` to init as an argument, which is exactly as
/// confusing to debug as it sounds: the devices are attached, the command line
/// looks right, and nothing probes.
///
/// So insert ahead of the first standalone `--`, and append when there is none.
/// Operating on byte offsets rather than tokens keeps the caller's quoting
/// (`bash -lc 'a; b'`) intact.
fn splice_kernel_args(base: &str, extra: &str) -> String {
    if extra.is_empty() {
        return base.to_string();
    }
    if base.is_empty() {
        return extra.to_string();
    }
    let sep = base.match_indices("--").find(|(i, _)| {
        let starts_token = *i == 0 || base.as_bytes()[i - 1] == b' ';
        let end = i + 2;
        let ends_token = end == base.len() || base.as_bytes()[end] == b' ';
        starts_token && ends_token
    });
    match sep {
        Some((i, _)) => {
            let (head, tail) = base.split_at(i);
            format!("{} {} {}", head.trim_end(), extra, tail)
        }
        None => format!("{base} {extra}"),
    }
}

/// The CPUID leaves the profile records, as `(leaf, subleaf)`: the vendor,
/// the family and the basic features, the structured extended features, the
/// XSAVE layout and the extended features. A guest kernel decides what to use
/// from these once, at boot.
const PROFILE_LEAVES: [(u32, u32); 6] = [
    (0x0, 0),
    (0x1, 0),
    (0x7, 0),
    (0xd, 0),
    (0xd, 1),
    (0x8000_0001, 0),
];

/// Writes `id` into `cpuid` as the CPU's APIC ID: bits 31:24 of leaf 1 EBX and
/// the x2APIC ID in EDX of every subleaf of 0xb and 0x1f.
///
/// `KVM_GET_SUPPORTED_CPUID` passes through the APIC ID of whichever host CPU
/// the calling thread happened to run on. Left as it is, every guest CPU reads
/// the same foreign ID, not the one KVM's local APIC and the MP table give it,
/// and two boots of one configuration record different profiles, so no x86
/// guest could ever be restored, even on the host it came from.
fn set_apic_id(cpuid: &mut [kvm_bindings::kvm_cpuid_entry2], id: u32) {
    for e in cpuid {
        match e.function {
            1 => e.ebx = (e.ebx & 0x00ff_ffff) | ((id & 0xff) << 24),
            0xb | 0x1f => e.edx = id,
            _ => {}
        }
    }
}

/// Returns the CPU's identity from `cpuid` as the guest reads it: the vendor
/// string and the display family, model and stepping.
fn cpu_ident(cpuid: &[kvm_bindings::kvm_cpuid_entry2]) -> Option<String> {
    let leaf = |function| {
        cpuid
            .iter()
            .find(|e| e.function == function && e.index == 0)
    };
    let vendor_leaf = leaf(0)?;
    let vendor: Vec<u8> = [vendor_leaf.ebx, vendor_leaf.edx, vendor_leaf.ecx]
        .iter()
        .flat_map(|r| r.to_le_bytes())
        .collect();
    let eax = leaf(1)?.eax;
    let base_family = (eax >> 8) & 0xf;
    let family = if base_family == 0xf {
        base_family + ((eax >> 20) & 0xff)
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xf {
        ((eax >> 4) & 0xf) | (((eax >> 16) & 0xf) << 4)
    } else {
        (eax >> 4) & 0xf
    };
    Some(format!(
        "{} family {family:#x} model {model:#x} stepping {:#x}",
        String::from_utf8_lossy(&vendor),
        eax & 0xf
    ))
}

/// Returns the machine profile of this boot.
///
/// `cpuid` is the table vCPU 0 was given, the guest's view rather than the
/// host's. The others differ only in their APIC ID. The counter is the TSC, at
/// the rate KVM gives the boot vCPU.
fn boot_profile(
    cfg: &BootConfig,
    ram: &GuestRam,
    cpuid: &[kvm_bindings::kvm_cpuid_entry2],
    boot: &VcpuFd,
    zero_page: u64,
    devices: (bool, Option<&str>, bool),
) -> MachineProfile {
    let mut p = MachineProfile::for_this_host("x86_64", "kvm");
    p.cpu.ident = cpu_ident(cpuid);
    for (function, index) in PROFILE_LEAVES {
        // A leaf KVM does not serve is recorded as unread, which the
        // compatibility check refuses on either side.
        let value = cpuid
            .iter()
            .find(|e| e.function == function && e.index == index)
            .map_or_else(
                || UNKNOWN.to_string(),
                |e| {
                    format!(
                        "eax={},ebx={},ecx={},edx={}",
                        hex(u64::from(e.eax)),
                        hex(u64::from(e.ebx)),
                        hex(u64::from(e.ecx)),
                        hex(u64::from(e.edx))
                    )
                },
            );
        p.cpu
            .id_regs
            .insert(format!("cpuid.{function:#010x}.{index}"), value);
    }
    p.counter_freq_hz = boot.get_tsc_khz().map_or(0, |khz| u64::from(khz) * 1000);
    p.x86 = Some(X86Platform {
        irqchip: "kvm".to_string(),
        pit: true,
    });
    p.ram_regions = ram.regions().into_iter().map(Into::into).collect();
    p.vcpus = cfg.vcpus.max(1);
    let (blk, net_mode, vsock) = devices;
    p.devices = vec![
        device("uart16550", u64::from(COM1_PORT), Some(COM1_GSI), None),
        device("rtc-cmos", u64::from(RTC_INDEX_PORT), None, None),
    ];
    if blk {
        p.devices.push(device(
            "virtio-blk",
            VIRTIO_BLK_BASE,
            Some(VIRTIO_BLK_GSI),
            Some(VirtioBlk::FEATURES),
        ));
    }
    if let Some(mode) = net_mode {
        let mut net = device(
            "virtio-net",
            VIRTIO_NET_BASE,
            Some(VIRTIO_NET_GSI),
            Some(VirtioNet::FEATURES),
        );
        net.mode = Some(mode.to_string());
        p.devices.push(net);
    }
    if vsock {
        p.devices.push(device(
            "virtio-vsock",
            VIRTIO_VSOCK_BASE,
            Some(VIRTIO_VSOCK_GSI),
            Some(VirtioVsock::FEATURES),
        ));
    }
    let mut page = vec![0u8; 4096];
    if ram.read(zero_page, &mut page).is_ok() {
        p.firmware.boot_params_sha256 = Some(sha256_hex(&page));
    }
    p.agent_sock = cfg.agent_sock.is_some();
    p
}

/// Boots `cfg` on KVM (x86-64), as [`crate::boot`] describes.
pub(crate) fn boot(mut cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    cfg.validate()?;
    cfg.require_native_profile("KVM")?;
    if !cfg.fs_shares.is_empty() {
        return Err(
            "--share-ro/--share-rw are currently implemented by the macOS HVI backend only".into(),
        );
    }
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

    // Intel VMX needs a TSS + an identity-map page for guest-mode setup, even
    // though we enter directly in long mode (Firecracker/CH do the same). Set
    // them before creating the irqchip/vCPUs.
    vm.set_tss_address(0xfffb_d000)?;
    vm.set_identity_map_address(0xfffb_c000)?;

    // Guest RAM, split around the sub-4 GiB MMIO hole (see MMIO_GAP_START):
    // the backing object is one contiguous memfd, and the high half is the
    // bytes after the low half, mapped at HIGH_RAM_BASE. The object is
    // shareable so an out-of-process plugin can map the same pages; KVM only
    // needs a valid host address, so the guest is unaffected.
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

    // In-kernel LAPIC + IOAPIC + PIT.
    vm.create_irq_chip()?;
    vm.create_pit2(kvm_pit_config::default())?;

    // Devices.
    let virtio = match &cfg.disk {
        Some(path) => {
            eprintln!("{LOG_PREFIX} virtio-blk: {path}");
            Some(Arc::new(Mutex::new(VirtioBlk::open(path)?)))
        }
        None => None,
    };
    let mut net_source: Option<NetSource> = None;
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

    // Kernel command line: caller's args + ttyS0 console + virtio-mmio device
    // descriptors for whatever we attached. (KASLR works now that the guest
    // CPUID advertises RDRAND, so no nokaslr.)
    let mut ours = String::from("console=ttyS0");
    if virtio.is_some() {
        ours += &format!(" virtio_mmio.device=0x200@{VIRTIO_BLK_BASE:#x}:{VIRTIO_BLK_GSI}");
    }
    if net.is_some() {
        ours += &format!(" virtio_mmio.device=0x200@{VIRTIO_NET_BASE:#x}:{VIRTIO_NET_GSI}");
    }
    if vsock.is_some() {
        ours += &format!(" virtio_mmio.device=0x200@{VIRTIO_VSOCK_BASE:#x}:{VIRTIO_VSOCK_GSI}");
    }
    let cmdline = splice_kernel_args(cfg.cmdline.trim(), &ours);

    // Load the kernel, write boot_params and the command line, then place the
    // initrd, the MP table and the ACPI tables.
    let initrd_len = cfg.initramfs.as_ref().map_or(0, |v| v.len() as u64);
    let kernel = LoadedKernel::load(ram.memory(), &cfg.kernel, &cmdline, initrd_len)?;
    if let (Some(addr), Some(initramfs)) = (kernel.initrd_addr, &cfg.initramfs) {
        ram.write(addr, initramfs)?;
    }
    ram.write(MPTABLE_ADDR, &mptable::build(num_cpus))?;
    ram.write(ACPI_ADDR, &acpi::build(num_cpus))?;
    write_boot_page_tables(&ram)?;
    write_boot_gdt(&ram)?;
    eprintln!(
        "{LOG_PREFIX} {num_cpus} vCPU(s)  {} entry@{:#x}",
        kernel.format, kernel.entry
    );

    // vCPUs. Each vCPU's copy of the CPUID carries its own APIC ID, and
    // `cpuid` is left as vCPU 0's for the profile. The BSP enters in long
    // mode; APs wait for the guest's SIPI.
    let mut cpuid = guest_cpuid(kvm.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?);
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
    set_apic_id(cpuid.as_mut_slice(), 0);
    let mut vcpus = Vec::with_capacity(num_cpus as usize);
    let mut kick_handles = Vec::with_capacity(num_cpus as usize);
    for id in 0..num_cpus {
        let vcpu = vm.create_vcpu(u64::from(id))?;
        let mut own = cpuid.clone();
        set_apic_id(own.as_mut_slice(), id);
        vcpu.set_cpuid2(&own)?;
        if id == 0 {
            setup_long_mode(&vcpu, kernel.entry, kernel.zero_page_addr)?;
        }
        kick_handles.push(kick_handle(&vm, &vcpu)?);
        vcpus.push(vcpu);
    }

    // The profile is complete now, so its file is written before any filter
    // goes in.
    let net_mode = match (&net, &net_source) {
        (Some(_), Some(NetSource::Tap(_))) => Some("tap"),
        (Some(_), Some(NetSource::Gateway(_))) => Some("gateway"),
        (Some(_), None) => Some("stub"),
        (None, _) => None,
    };
    let profile = Arc::new(ProfileCell::new(
        boot_profile(
            &cfg,
            &ram,
            cpuid.as_slice(),
            &vcpus[0],
            kernel.zero_page_addr,
            (virtio.is_some(), net_mode, vsock.is_some()),
        ),
        cfg.profile_out.as_deref(),
    )?);
    profile.complete(|_| {})?;

    let vm = Arc::new(vm);
    let shared = Shared {
        guest: Arc::new(Guest {
            arch: GuestArch::X86_64,
            sandbox_id: cfg.sandbox_id.clone(),
            ram,
            shared_ram,
            ledger: Arc::new(Mutex::new(Emitter::new(
                cfg.events.as_deref(),
                &cfg.sandbox_id,
            )?)),
            block: virtio,
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
        plugin: cfg.plugin.clone(),
    };

    // Each device sets its own interrupt line, from the methods that change its
    // level and so under the lock that decides it.
    let line = |gsi| Arc::new(KvmIrqLine::new(Arc::clone(&vm), gsi));
    lock_or_recover(&shared.uart).connect_irq(line(COM1_GSI));
    shared.guest.connect_irqs(
        line(VIRTIO_BLK_GSI),
        line(VIRTIO_NET_GSI),
        line(VIRTIO_VSOCK_GSI),
    );

    // The plugin attach, the seccomp arm and the I/O threads, in the order the
    // filters need. Each polls its stop token beside its own descriptor and is
    // joined after the vCPUs; `teardown` describes the stop.
    let (filters, mut io_threads) = start_io_threads(
        &cfg,
        &shared.guest,
        {
            let uart = Arc::clone(&shared.uart);
            move |byte| lock_or_recover(&uart).push_rx(byte)
        },
        net_source,
        profile,
        Console::Com1 {
            uart: Arc::clone(&shared.uart),
            rtc: Arc::clone(&shared.rtc),
        },
    )?;
    // Debug watchdog: force a register dump on a stuck guest (HVI_X86_TRACE).
    if trace {
        let guest = Arc::clone(&shared.guest);
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

    // `boot` keeps the run's claim when it sees a `LeftRunning` error, so the
    // error goes back as `run_guest` returned it.
    run_guest(
        &shared.guest,
        &shared,
        vcpus,
        kick_handles,
        run_cpu,
        filters,
        io_threads,
    )
}

/// A flat segment descriptor for `KVM_SET_SREGS` (base 0, 4 GiB limit).
fn seg(selector: u16, code: bool) -> kvm_segment {
    kvm_segment {
        base: 0,
        limit: 0xf_ffff,
        selector,
        type_: if code { 0b1011 } else { 0b0011 }, // exec/read vs read/write, accessed
        present: 1,
        dpl: 0,
        db: u8::from(!code), // data=1, 64-bit code=0
        s: 1,
        l: u8::from(code), // 64-bit code segment
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

/// Sets the BSP into 64-bit long mode with `rip=entry`, `rsi=zero_page`.
fn setup_long_mode(
    vcpu: &VcpuFd,
    entry: u64,
    zero_page: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut sregs = vcpu.get_sregs()?;
    let cs = seg(0x08, true);
    let ds = seg(0x10, false);
    sregs.cs = cs;
    sregs.ds = ds;
    sregs.es = ds;
    sregs.fs = ds;
    sregs.gs = ds;
    sregs.ss = ds;
    sregs.gdt = kvm_dtable {
        base: GDT_ADDR,
        limit: 3 * 8 - 1,
        padding: [0; 3],
    };
    sregs.cr3 = PML4_ADDR;
    sregs.cr0 = CR0_PE_PG;
    sregs.cr4 = CR4_PAE;
    sregs.efer = EFER_LME_LMA;
    vcpu.set_sregs(&sregs)?;

    let mut regs = vcpu.get_regs()?;
    regs.rip = entry;
    regs.rsi = zero_page; // boot_params
    regs.rsp = BOOT_STACK;
    regs.rbp = BOOT_STACK;
    regs.rflags = 0x2; // reserved bit set
    vcpu.set_regs(&regs)?;
    Ok(())
}

/// Identity-maps the first 4 GiB with 1 GiB pages: `PML4[0]`->PDPT,
/// `PDPT[0..4]` = huge leaves. Covers RAM, the virtio MMIO hole, and the APIC
/// region.
fn write_boot_page_tables(ram: &GuestRam) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ram.write_u64(PML4_ADDR, PDPT_ADDR | PDE64_PRESENT_RW)?;
    for i in 0..4u64 {
        ram.write_u64(PDPT_ADDR + i * 8, (i << 30) | PDE64_PRESENT_RW_PS)?;
    }
    Ok(())
}

/// A tiny boot GDT (null, 64-bit code, data) matching `seg()` above.
fn write_boot_gdt(ram: &GuestRam) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Access/flags encoded to match the kvm_segment cache we set.
    let code: u64 = 0x00af_9b00_0000_ffff; // present, code, long-mode, g
    let data: u64 = 0x00cf_9300_0000_ffff; // present, data, 32-bit, g
    ram.write_u64(GDT_ADDR, 0)?;
    ram.write_u64(GDT_ADDR + 8, code)?;
    ram.write_u64(GDT_ADDR + 16, data)?;
    Ok(())
}

/// Runs one vCPU until the VM stops, servicing its port I/O and MMIO exits.
fn run_cpu(cpu_id: u32, vcpu: VcpuFd, kick_handle: VcpuFd, sh: Shared) {
    let dbg = std::env::var_os("HVI_X86_TRACE").is_some();
    let mut n_exit = 0u64;
    run_vcpu(
        cpu_id,
        vcpu,
        kick_handle,
        &sh.guest,
        sh.plugin.as_deref(),
        // The x86-64 export is still the plugin's register view.
        |vcpu, work| {
            crate::checkpoint::cpu::serve_from_regs_view(sh.guest.arch, "kvm", cpu_id, vcpu, work)
        },
        |exit| {
            // The trace reads registers through the vCPU's second handle, since
            // the exit borrows the one the run uses.
            let dump = |tag: &str| {
                let kicker = sh.guest.vcpus.kicker();
                kicker.with_vcpu(cpu_id, |vcpu| dump_regs(vcpu, &sh.guest.ram, cpu_id, tag));
            };
            match exit {
                VcpuExit::IoIn(port, data) => {
                    if dbg && n_exit < 80 {
                        stderrln!("[trace] vcpu{cpu_id} IoIn {port:#x}");
                        n_exit += 1;
                    }
                    // The PM1 registers are 16 bits wide, so the ACPI block
                    // takes the whole access. Every other port is a byte port.
                    if let Some(offset) = pm_offset(port) {
                        lock_or_recover(&sh.pm).read(offset, data);
                    } else {
                        for b in data.iter_mut() {
                            *b = pio_read(&sh, port);
                        }
                    }
                }
                VcpuExit::IoOut(port, data) => {
                    let stop = if let Some(offset) = pm_offset(port) {
                        lock_or_recover(&sh.pm).write(offset, data)
                    } else {
                        for &b in data.iter() {
                            pio_write(&sh, port, b);
                        }
                        pio_stop(port, data)
                    };
                    // A write that ends the run is traced past the first exits
                    // too.
                    if dbg && (n_exit < 80 || stop.is_some()) {
                        stderrln!(
                            "[trace] vcpu{cpu_id} IoOut {port:#x} = {:02x?}",
                            &data[..data.len().min(4)]
                        );
                        n_exit += 1;
                    }
                    if let Some(stop) = stop {
                        return ControlFlow::Break(Outcome::Stopped(stop));
                    }
                }
                VcpuExit::MmioRead(addr, data) => {
                    if dbg && n_exit < 80 {
                        stderrln!("[trace] vcpu{cpu_id} MmioRead {addr:#x}");
                        n_exit += 1;
                    }
                    let val = mmio_read(&sh, addr);
                    let n = data.len().min(8);
                    data[..n].copy_from_slice(&val.to_le_bytes()[..n]);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if dbg && n_exit < 80 {
                        stderrln!("[trace] vcpu{cpu_id} MmioWrite {addr:#x}");
                        n_exit += 1;
                    }
                    let mut b = [0u8; 8];
                    let n = data.len().min(8);
                    b[..n].copy_from_slice(&data[..n]);
                    mmio_write(&sh, addr, u64::from_le_bytes(b));
                }
                VcpuExit::Shutdown => {
                    if dbg {
                        dump("SHUTDOWN");
                    }
                    return ControlFlow::Break(Outcome::Stopped(Stop::SystemReset));
                }
                VcpuExit::Intr => {
                    if dbg && cpu_id == 0 {
                        dump("kick");
                    }
                }
                other => return unhandled_exit(cpu_id, &other),
            }
            ControlFlow::Continue(())
        },
    );
}

impl SafepointVcpu for VcpuFd {
    fn regs(&self) -> RegsView {
        // CR3 is the walk root on x86-64; the arm64 registers stay zero.
        RegsView {
            root: self.get_sregs().map(|s| s.cr3).unwrap_or(0),
            pc: self.get_regs().map(|r| r.rip).unwrap_or(0),
            ..RegsView::default()
        }
    }

    fn notify_guest_paused(&self, paused_for: Duration) {
        if paused_for < MIN_NOTIFIED_PAUSE {
            return;
        }
        // The notice is the mark `KVM_KVMCLOCK_CTRL` leaves in the vCPU's
        // kvm-clock page. KVM refuses it with `EINVAL` while the guest has no
        // kvm-clock set up, such as early in boot, and then nothing in the
        // guest would read it.
        if let Err(e) = self.kvmclock_ctrl() {
            if e.errno() != libc::EINVAL {
                stderrln!("{LOG_PREFIX} could not notify the guest of the pause: {e}");
            }
        }
    }
}

/// Dumps the vCPU's control/state registers + the instruction bytes at RIP
/// (assuming the early kernel is identity-mapped) (debug).
fn dump_regs(vcpu: &VcpuFd, mem: &GuestRam, cpu_id: u32, tag: &str) {
    if let (Ok(r), Ok(s)) = (vcpu.get_regs(), vcpu.get_sregs()) {
        let mut code = [0u8; 16];
        let _ = mem.read(r.rip, &mut code);
        stderrln!(
            "[trace] vcpu{cpu_id} {tag}: rip={:#x} rsp={:#x} rflags={:#x} cs.sel={:#x} cs.l={} cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x} code@rip={:02x?}",
            r.rip, r.rsp, r.rflags, s.cs.selector, s.cs.l, s.cr0, s.cr3, s.cr4, s.efer, code
        );
    }
}

/// Routes a port-I/O read to the device behind `port` and returns the value.
///
/// Split from [`pio_read`] so the routing is callable without a live vCPU.
fn pio_dispatch_read(uart: &Mutex<Uart16550>, rtc: &Mutex<RtcCmos>, port: u16) -> u8 {
    if (COM1_PORT..COM1_PORT + 8).contains(&port) {
        uart.lock().unwrap().pio_read(port - COM1_PORT)
    } else if port == RTC_INDEX_PORT || port == RTC_DATA_PORT {
        rtc.lock().unwrap().pio_read(port)
    } else if port == I8042_COMMAND_PORT {
        I8042_STATUS
    } else {
        0xff
    }
}

/// Routes a port-I/O write; the write half of [`pio_dispatch_read`].
fn pio_dispatch_write(uart: &Mutex<Uart16550>, rtc: &Mutex<RtcCmos>, port: u16, val: u8) {
    if (COM1_PORT..COM1_PORT + 8).contains(&port) {
        uart.lock().unwrap().pio_write(port - COM1_PORT, val);
    } else if port == RTC_INDEX_PORT || port == RTC_DATA_PORT {
        rtc.lock().unwrap().pio_write(port, val);
    }
}

/// Returns [`Stop::SystemReset`] for the i8042's CPU-reset command written as
/// one byte, or `None` for any other byte-port write.
fn pio_stop(port: u16, data: &[u8]) -> Option<Stop> {
    (port == I8042_COMMAND_PORT && *data == [I8042_RESET_CPU]).then_some(Stop::SystemReset)
}

/// Returns the offset of `port` in the ACPI registers, or `None` when the port
/// is not one of them.
fn pm_offset(port: u16) -> Option<u16> {
    port.checked_sub(ACPI_PM_PORT)
        .filter(|&offset| offset < PM_REGISTERS_LEN)
}

/// Services an `in` from `port`.
fn pio_read(sh: &Shared, port: u16) -> u8 {
    pio_dispatch_read(&sh.uart, &sh.rtc, port)
}

/// Services an `out` of `val` to `port`.
fn pio_write(sh: &Shared, port: u16, val: u8) {
    pio_dispatch_write(&sh.uart, &sh.rtc, port, val);
}

/// Services an MMIO read of the virtio register at `addr`.
fn mmio_read(sh: &Shared, addr: u64) -> u64 {
    if (VIRTIO_BLK_BASE..VIRTIO_BLK_BASE + VIRTIO_SIZE).contains(&addr) {
        blk_read(sh, addr - VIRTIO_BLK_BASE)
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        net_read(sh, addr - VIRTIO_NET_BASE)
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        vsock_read(sh, addr - VIRTIO_VSOCK_BASE)
    } else {
        0
    }
}

/// Services an MMIO write of `val` to the virtio register at `addr`.
fn mmio_write(sh: &Shared, addr: u64, val: u64) {
    if (VIRTIO_BLK_BASE..VIRTIO_BLK_BASE + VIRTIO_SIZE).contains(&addr) {
        blk_write(sh, addr - VIRTIO_BLK_BASE, val);
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        net_write(sh, addr - VIRTIO_NET_BASE, val);
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        vsock_write(sh, addr - VIRTIO_VSOCK_BASE, val);
    }
}

/// Moves a device's captured `events` into the ledger.
fn drain(sh: &Shared, events: &[CapturedEvent]) {
    if events.is_empty() {
        return;
    }
    let mut e = sh.guest.ledger.lock().unwrap();
    for ev in events {
        e.captured(ev);
    }
}

/// Services a read of virtio-blk register `off`.
///
/// The device's captured events then go to the ledger.
fn blk_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.guest.block.as_ref() else {
        return 0;
    };
    let (v, events) = {
        let mut d = dev.lock().unwrap();
        let v = d.mmio(&sh.guest.ram, off, false, 0);
        (v, d.take_events())
    };
    drain(sh, &events);
    v
}

/// Services a write of `val` to virtio-blk register `off`.
///
/// The device's captured events then go to the ledger.
fn blk_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.guest.block.as_ref() else {
        return;
    };
    let events = {
        let mut d = dev.lock().unwrap();
        d.mmio(&sh.guest.ram, off, true, val);
        d.take_events()
    };
    drain(sh, &events);
}

/// Services a read of virtio-net register `off`.
///
/// The device's captured events then go to the ledger.
fn net_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.guest.net.as_ref() else {
        return 0;
    };
    let (v, events) = {
        let mut d = dev.lock().unwrap();
        let v = d.mmio(&sh.guest.ram, off, false, 0);
        (v, d.take_events())
    };
    drain(sh, &events);
    v
}

/// Services a write of `val` to virtio-net register `off`.
///
/// The device's captured events then go to the ledger.
fn net_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.guest.net.as_ref() else {
        return;
    };
    let events = {
        let mut d = dev.lock().unwrap();
        d.mmio(&sh.guest.ram, off, true, val);
        d.take_events()
    };
    drain(sh, &events);
}

/// Services a read of virtio-vsock register `off`.
fn vsock_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.guest.vsock.as_ref() else {
        return 0;
    };
    dev.lock().unwrap().mmio(&sh.guest.ram, off, false, 0)
}

/// Services a write of `val` to virtio-vsock register `off`.
fn vsock_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.guest.vsock.as_ref() else {
        return;
    };
    let mut d = dev.lock().unwrap();
    d.mmio(&sh.guest.ram, off, true, val);
}

#[cfg(test)]
mod cmdline_tests {
    use super::splice_kernel_args;

    const OURS: &str = "console=ttyS0 virtio_mmio.device=0x200@0xd0000000:5";

    /// The regression: urunc's line ends with the container entrypoint after a
    /// bare `--`, so our parameters must land before it or the kernel never
    /// parses them.
    #[test]
    fn inserts_before_the_init_argv_separator() {
        let base = "panic=-1 console=ttyS0 root=/dev/vda rw rdinit=/init -- bash -lc 'id; echo hi'";
        let got = splice_kernel_args(base, OURS);
        assert_eq!(
            got,
            "panic=-1 console=ttyS0 root=/dev/vda rw rdinit=/init \
             console=ttyS0 virtio_mmio.device=0x200@0xd0000000:5 -- bash -lc 'id; echo hi'"
        );
        // Everything we add is a kernel parameter, so none of it may appear
        // after the separator.
        let (kernel_part, init_part) = got.split_once(" -- ").expect("separator survives");
        assert!(kernel_part.contains("virtio_mmio.device"));
        assert!(!init_part.contains("virtio_mmio.device"));
    }

    /// The caller's quoting has to survive: a token-split-and-rejoin would
    /// collapse the entrypoint's embedded spaces.
    #[test]
    fn preserves_quoting_in_the_init_argv() {
        let base = "rdinit=/init -- bash -lc 'sleep 6; echo done'";
        let got = splice_kernel_args(base, OURS);
        assert!(got.ends_with("-- bash -lc 'sleep 6; echo done'"), "{got}");
    }

    /// A `--` inside init's argv is not a second separator; only the first one
    /// ends the kernel parameters.
    #[test]
    fn splits_on_the_first_separator_only() {
        let base = "root=/dev/vda -- prog -- --flag";
        let got = splice_kernel_args(base, "console=ttyS0");
        assert_eq!(got, "root=/dev/vda console=ttyS0 -- prog -- --flag");
    }

    /// Without a separator there is nothing to protect, so append.
    #[test]
    fn appends_when_there_is_no_separator() {
        let got = splice_kernel_args("root=/dev/vda rw", OURS);
        assert_eq!(got, format!("root=/dev/vda rw {OURS}"));
    }

    /// `--` must be a token of its own: these are ordinary parameters that
    /// merely contain two dashes, and splitting on them would corrupt the line.
    #[test]
    fn ignores_dashes_that_are_not_a_bare_token() {
        for base in ["panic=-1 foo=--bar", "quiet--verbose root=/dev/vda"] {
            let got = splice_kernel_args(base, "console=ttyS0");
            assert_eq!(got, format!("{base} console=ttyS0"), "base: {base}");
        }
    }

    #[test]
    fn handles_empty_inputs() {
        assert_eq!(splice_kernel_args("", OURS), OURS);
        assert_eq!(splice_kernel_args("root=/dev/vda", ""), "root=/dev/vda");
    }

    /// A line that is nothing but the separator still has to keep it last.
    #[test]
    fn separator_at_the_end_stays_last() {
        let got = splice_kernel_args("rdinit=/init --", "console=ttyS0");
        assert_eq!(got, "rdinit=/init console=ttyS0 --");
    }
}

#[cfg(test)]
mod vcpu_cap_tests {
    use super::boot;
    use crate::config::BootConfig;

    #[test]
    fn more_vcpus_than_the_cap_are_refused() {
        let cfg = BootConfig {
            kernel: Vec::new(),
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

#[cfg(test)]
mod cpuid_tests {
    use kvm_bindings::{kvm_cpuid_entry2, CpuId};

    use super::{
        guest_cpuid, CPUID_1_ECX_HYPERVISOR, CPUID_1_ECX_RDRAND, CPUID_1_ECX_TSC_DEADLINE_TIMER,
        CPUID_7_0_EBX_RDSEED,
    };

    /// Leaf 1 ECX as an older KVM, such as Linux 6.8's, reports it, with SSE3
    /// and x2APIC set and neither the hypervisor bit nor the TSC-deadline bit.
    const LEAF_1_ECX: u32 = 1 | 1 << 21;
    /// Leaf 7 subleaf 0 EBX as KVM reports it, with FSGSBASE set and RDSEED
    /// clear.
    const LEAF_7_EBX: u32 = 1;

    /// Returns a CPUID entry with the given leaf, subleaf and registers.
    fn entry(function: u32, index: u32, ebx: u32, ecx: u32, edx: u32) -> kvm_cpuid_entry2 {
        kvm_cpuid_entry2 {
            function,
            index,
            ebx,
            ecx,
            edx,
            ..Default::default()
        }
    }

    #[test]
    fn guest_cpuid_adds_its_bits_and_keeps_other_leaves() {
        // Leaf 7 subleaf 1 and KVM's signature leaf, "KVMKVMKVM", which
        // `guest_cpuid` must leave alone.
        let untouched = [
            entry(7, 1, 0, 0, 0),
            entry(0x4000_0000, 0, 0x4b4d_564b, 0x564b_4d56, 0x4d),
        ];
        let mut entries = vec![entry(1, 0, 0, LEAF_1_ECX, 0), entry(7, 0, LEAF_7_EBX, 0, 0)];
        entries.extend(untouched);
        let cpuid = guest_cpuid(CpuId::from_entries(&entries).unwrap());

        let entries = cpuid.as_slice();
        assert_eq!(
            entries[0].ecx,
            LEAF_1_ECX
                | CPUID_1_ECX_TSC_DEADLINE_TIMER
                | CPUID_1_ECX_RDRAND
                | CPUID_1_ECX_HYPERVISOR
        );
        assert_eq!(entries[1].ebx, LEAF_7_EBX | CPUID_7_0_EBX_RDSEED);
        assert_eq!(entries[2..], untouched);
    }
}

#[cfg(test)]
mod pio_tests {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use super::*;
    use crate::devices::irq::IrqLine;

    /// The guest reaches the RTC only through the vCPU exit handler's port
    /// dispatch, so a routing slip (0x70/0x71 falling through to the 0xff
    /// default) would re-open the boot hang the device exists to fix -- with
    /// the device's own unit tests still green. Drive the ports as the guest
    /// does and pin the answer to what the device itself returns.
    #[test]
    fn rtc_ports_reach_the_device() {
        let uart = Mutex::new(Uart16550::new());
        let rtc = Mutex::new(RtcCmos::new());

        // out 0x70, 0x0b; in 0x71 -- status register B.
        const REG_B: u8 = 0x0b;
        pio_dispatch_write(&uart, &rtc, RTC_INDEX_PORT, REG_B);
        let via_ports = pio_dispatch_read(&uart, &rtc, RTC_DATA_PORT);

        // The same register read straight from a device instance must match:
        // the dispatch adds routing, not behavior.
        let mut direct = RtcCmos::new();
        direct.pio_write(RTC_INDEX_PORT, REG_B);
        assert_eq!(via_ports, direct.pio_read(RTC_DATA_PORT));
        // And status B still reports what the rtc_cmos tests pin: BCD, 24h.
        assert_eq!(via_ports & 0x04, 0, "DM clear means BCD");
        assert_eq!(via_ports & 0x02, 0x02, "24-hour mode");
    }

    // The guest programs COM1's pin as edge-triggered. This is its transmit
    // start, split across two vCPUs: one enables THR-empty, the interrupted
    // one reads IIR, and the THR writes that follow must raise a new edge.
    #[test]
    fn com1_rises_again_for_the_writes_after_an_iir_read() {
        let line = Arc::new(EdgeCounter::default());
        let mut com1 = Uart16550::new();
        com1.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
        let uart = Mutex::new(com1);
        let rtc = Mutex::new(RtcCmos::new());
        const IER: u16 = COM1_PORT + 1;
        const IIR: u16 = COM1_PORT + 2;

        pio_dispatch_write(&uart, &rtc, IER, 0x02);
        assert_eq!(line.edges.load(Ordering::SeqCst), 1);
        assert_eq!(pio_dispatch_read(&uart, &rtc, IIR), 0xc2);
        assert!(
            !line.high.load(Ordering::SeqCst),
            "the IIR read drops the line"
        );
        for b in b"0123456789abcdef" {
            pio_dispatch_write(&uart, &rtc, COM1_PORT, *b);
        }
        assert_eq!(
            line.edges.load(Ordering::SeqCst),
            2,
            "the THR writes raise a second edge"
        );
    }

    // The kernel's i8042 reset waits for the input buffer to empty before each
    // command. A full one costs the whole poll before every try.
    #[test]
    fn i8042_takes_its_reset_command_at_once() {
        let uart = Mutex::new(Uart16550::new());
        let rtc = Mutex::new(RtcCmos::new());
        let status = pio_dispatch_read(&uart, &rtc, I8042_COMMAND_PORT);
        assert_eq!(status & 0x02, 0, "input buffer empty");
        assert_eq!(status & 0x01, 0x01, "a probe's first flush still fails");
        assert!(matches!(
            pio_stop(I8042_COMMAND_PORT, &[I8042_RESET_CPU]),
            Some(Stop::SystemReset)
        ));
        assert!(pio_stop(I8042_COMMAND_PORT, &[0xaa]).is_none());
        assert!(pio_stop(0x60, &[I8042_RESET_CPU]).is_none());
        // A wider access is not the command, whatever its bytes.
        assert!(pio_stop(I8042_COMMAND_PORT, &[0x00, I8042_RESET_CPU]).is_none());
    }

    #[test]
    fn pm_offset_covers_the_acpi_registers_only() {
        assert_eq!(pm_offset(ACPI_PM_PORT), Some(0));
        assert_eq!(
            pm_offset(ACPI_PM_PORT + PM_REGISTERS_LEN - 1),
            Some(PM_REGISTERS_LEN - 1)
        );
        assert_eq!(pm_offset(ACPI_PM_PORT - 1), None);
        assert_eq!(pm_offset(ACPI_PM_PORT + PM_REGISTERS_LEN), None);
    }

    /// A line that holds its level and counts the times it rose.
    #[derive(Default)]
    struct EdgeCounter {
        /// The level the line was last set to.
        high: AtomicBool,
        /// The number of times the line rose.
        edges: AtomicU32,
    }

    impl IrqLine for EdgeCounter {
        fn set_level(&self, level: bool) -> std::io::Result<()> {
            if level && !self.high.swap(level, Ordering::SeqCst) {
                self.edges.fetch_add(1, Ordering::SeqCst);
            }
            self.high.store(level, Ordering::SeqCst);
            Ok(())
        }
    }
}

#[cfg(test)]
mod profile_tests {
    use super::{cpu_ident, set_apic_id};
    use kvm_bindings::kvm_cpuid_entry2;

    fn leaf(function: u32, eax: u32, ebx: u32, ecx: u32, edx: u32) -> kvm_cpuid_entry2 {
        kvm_cpuid_entry2 {
            function,
            eax,
            ebx,
            ecx,
            edx,
            ..Default::default()
        }
    }

    /// Returns leaf 0 for `vendor`, whose twelve bytes CPUID spreads over
    /// EBX, EDX and ECX in that order.
    fn vendor_leaf(vendor: &[u8; 12]) -> kvm_cpuid_entry2 {
        let word =
            |i: usize| u32::from_le_bytes([vendor[i], vendor[i + 1], vendor[i + 2], vendor[i + 3]]);
        leaf(0, 0x10, word(0), word(8), word(4))
    }

    // KVM hands back the APIC ID of the host CPU the boot thread ran on. Two
    // boots on different host CPUs must still give the guest, and the profile,
    // the same table, and each vCPU must read its own ID.
    #[test]
    fn each_vcpu_reads_its_own_apic_id_whatever_host_cpu_booted_it() {
        let host = |apic: u32| {
            vec![
                leaf(1, 0x0005_0657, (apic << 24) | 0x0040_0800, 0x7ffa_fbff, 0),
                kvm_cpuid_entry2 {
                    index: 1,
                    ..leaf(0xb, 1, 2, 0x201, apic)
                },
                leaf(7, 0, 0x1234, 0, 0),
            ]
        };
        let (mut a, mut b) = (host(0x55), host(0x72));
        set_apic_id(&mut a, 0);
        set_apic_id(&mut b, 0);
        assert_eq!(a, b);
        assert_eq!(a[0].ebx, 0x0040_0800, "only the APIC ID byte changes");
        let mut cpu3 = host(0x55);
        set_apic_id(&mut cpu3, 3);
        assert_eq!(cpu3[0].ebx >> 24, 3);
        assert_eq!(cpu3[1].edx, 3);
        assert_eq!(cpu3[2], a[2]);
    }

    // The display model folds in the extended model for families 6 and 15,
    // and the display family the extended family for 15 alone. A Skylake
    // server reports 0x50657: family 6, model 0x55, stepping 7.
    #[test]
    fn the_identity_is_vendor_family_model_stepping() {
        let table = [vendor_leaf(b"GenuineIntel"), leaf(1, 0x0005_0657, 0, 0, 0)];
        assert_eq!(
            cpu_ident(&table).as_deref(),
            Some("GenuineIntel family 0x6 model 0x55 stepping 0x7")
        );
        let amd = [vendor_leaf(b"AuthenticAMD"), leaf(1, 0x00a0_0f11, 0, 0, 0)];
        assert_eq!(
            cpu_ident(&amd).as_deref(),
            Some("AuthenticAMD family 0x19 model 0x1 stepping 0x1")
        );
        assert_eq!(cpu_ident(&table[..1]), None);
    }
}

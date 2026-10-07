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
//! The x86 counterpart of `aarch64::kvm`. KVM gives us an in-kernel LAPIC +
//! IOAPIC + PIT (`create_irq_chip`/`create_pit2`), so SMP is just: enter the
//! BSP in long mode and run every vCPU thread — the guest brings up APs with
//! INIT-SIPI-SIPI, handled in-kernel. We build the initial long-mode state
//! (identity page tables, flat 64-bit segments, CR0/CR3/CR4/EFER), load the
//! bzImage or vmlinux and write `boot_params` (see `super::loader`), and enter
//! at the 64-bit entry with RSI -> the zero page.
//!
//! Devices are the shared virtio-mmio blk/net/vsock (serviced on
//! `KVM_EXIT_MMIO`) plus a 16550 serial on port I/O (`KVM_EXIT_IO`).
//! A plugin, if the caller supplied one, sees CR3 as the walk root.
//!
//! Verified on a live KVM host (x86-64): boots an Ubuntu 6.8 kernel to
//! userspace, with **virtio-blk** (mount + read real data), **virtio-net**
//! (eth0 + ICMP round-trip via the built-in stack) and KASLR (RDRAND-backed).
//! The pieces a hand-rolled
//! boot must get right and that took debugging: KVM's `set_tss_address` +
//! identity map (Intel VMX needs them even for a long-mode entry), `set_cpuid2`
//! (the guest reads CPUID for feature detection — without it early boot
//! triple-faults), and advertising RDRAND in that CPUID (else the KASLR entropy
//! path stalls). Set `HVI_X86_TRACE=1` for exit/register tracing. SMP AP
//! bringup is asserted by the boot-x86 CI job, which boots with `--cpus 2`.
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this
// VMM's own.
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use kvm_bindings::{kvm_dtable, kvm_pit_config, kvm_segment};
use kvm_ioctls::{Cap, Kvm, VcpuExit, VcpuFd};

use crate::arch::x86_64::layout::{
    BOOT_STACK, COM1_GSI, COM1_PORT, GDT_ADDR, HIGH_RAM_BASE, MMIO_GAP_START, MPTABLE_ADDR,
    PDPT_ADDR, PML4_ADDR, RAM_BASE, VIRTIO_BLK_BASE, VIRTIO_BLK_GSI, VIRTIO_NET_BASE,
    VIRTIO_NET_GSI, VIRTIO_SIZE, VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_GSI,
};
use crate::arch::x86_64::loader::LoadedKernel;
use crate::arch::x86_64::mptable;
use crate::config::{BootConfig, Stop};
use crate::devices::legacy::rtc_cmos::{RtcCmos, RTC_DATA_PORT, RTC_INDEX_PORT};
use crate::devices::legacy::uart16550::Uart16550;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::net::{self, VirtioNet};
use crate::devices::virtio::tap;
use crate::devices::virtio::vsock::VirtioVsock;
use crate::events::{CapturedEvent, Emitter};
use crate::hypervisor::guest::{Guest, VcpuRegs};
use crate::hypervisor::kvm::{
    kick_handle, run_guest, run_vcpu, start_io_threads, Kicker, KvmIrqLine,
};
use crate::hypervisor::vcpus::{Kick, Vcpus};
use crate::io_threads::NetSource;
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::{GuestArch, Plugin, RamRegion, RegsView};
use crate::sandbox::confine_io_thread;
use crate::signal::install_kick_handler;
use crate::sync::lock_or_recover;
use crate::LOG_PREFIX;

// Long-mode control-register values (Firecracker's boot values).
const CR0_PE_PG: u64 = 0x8005_0033; // PE|MP|ET|NE|WP|AM|PG
const CR4_PAE: u64 = 0x0000_0020; // PAE
const EFER_LME_LMA: u64 = 0x0000_0500; // LME|LMA
const PDE64_PRESENT_RW_PS: u64 = 0x83; // present | writable | page-size (1 GiB)
const PDE64_PRESENT_RW: u64 = 0x03; // present | writable (table)

/// State shared across the vCPU threads.
#[derive(Clone)]
struct Shared {
    /// The guest's RAM, virtio devices and vCPUs.
    guest: Arc<Guest<Kicker>>,
    uart: Arc<Mutex<Uart16550>>,
    /// The CMOS RTC: without it a guest hangs in read_persistent_clock64().
    rtc: Arc<Mutex<RtcCmos>>,
    /// Whoever is watching this guest, if anyone.
    plugin: Option<Arc<dyn Plugin>>,
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

/// Boots `cfg` on KVM (x86-64) and runs until the guest powers off.
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
    let num_cpus = cfg.vcpus.max(1);

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

    // Load the kernel, write boot_params and the command line, then place
    // the initrd and the MP table.
    let initrd_len = cfg.initramfs.as_ref().map_or(0, |v| v.len() as u64);
    let kernel = LoadedKernel::load(ram.memory(), &cfg.kernel, &cmdline, initrd_len)?;
    if let (Some(addr), Some(initramfs)) = (kernel.initrd_addr, &cfg.initramfs) {
        ram.write(addr, initramfs)?;
    }
    ram.write(MPTABLE_ADDR, &mptable::build(num_cpus))?;
    write_boot_page_tables(&ram)?;
    write_boot_gdt(&ram)?;
    eprintln!(
        "{LOG_PREFIX} {num_cpus} vCPU(s)  {} entry@{:#x}",
        kernel.format, kernel.entry
    );

    // vCPUs. Each gets KVM's supported CPUID (the guest reads it for feature
    // detection — without it early boot faults). We ensure RDRAND (leaf 1 ECX
    // bit 30) and RDSEED (leaf 7 EBX bit 18) are advertised so the guest's
    // early KASLR/entropy path has a source (the host must support them).
    // The BSP enters in long mode; APs wait for the guest's SIPI.
    let mut cpuid = kvm.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?;
    for e in cpuid.as_mut_slice() {
        match e.function {
            1 => e.ecx |= 1 << 30,                 // RDRAND
            7 if e.index == 0 => e.ebx |= 1 << 18, // RDSEED
            _ => {}
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
            vcpus: Arc::new(Vcpus::new(num_cpus, Kicker::new(num_cpus))),
        }),
        uart: Arc::new(Mutex::new(Uart16550::new())),
        rtc: Arc::new(Mutex::new(RtcCmos::new())),
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
    )?;
    // Debug watchdog: force a register dump on a stuck guest (HVI_X86_TRACE).
    if std::env::var_os("HVI_X86_TRACE").is_some() {
        let guest = Arc::clone(&shared.guest);
        let watch = io_threads.token();
        io_threads.push(
            "trace watchdog",
            std::thread::spawn(move || {
                confine_io_thread();
                for _ in 0..4 {
                    match watch.sleep(std::time::Duration::from_secs(2)) {
                        Ok(true) => guest.vcpus.kicker().kick(0),
                        Ok(false) => break,
                        Err(e) => {
                            eprintln!("{LOG_PREFIX} trace watchdog: {e}; trace watchdog stopped");
                            break;
                        }
                    }
                }
            }),
        );
    }

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
) -> Result<(), Box<dyn std::error::Error>> {
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
fn write_boot_page_tables(ram: &GuestRam) -> Result<(), Box<dyn std::error::Error>> {
    ram.write_u64(PML4_ADDR, PDPT_ADDR | PDE64_PRESENT_RW)?;
    for i in 0..4u64 {
        ram.write_u64(PDPT_ADDR + i * 8, (i << 30) | PDE64_PRESENT_RW_PS)?;
    }
    Ok(())
}

/// A tiny boot GDT (null, 64-bit code, data) matching `seg()` above.
fn write_boot_gdt(ram: &GuestRam) -> Result<(), Box<dyn std::error::Error>> {
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
        |vcpu| {
            match vcpu.run() {
                Ok(VcpuExit::IoIn(port, data)) => {
                    if dbg && n_exit < 80 {
                        eprintln!("[trace] cpu{cpu_id} IoIn {port:#x}");
                        n_exit += 1;
                    }
                    for b in data.iter_mut() {
                        *b = pio_read(&sh, port);
                    }
                }
                Ok(VcpuExit::IoOut(port, data)) => {
                    if dbg && n_exit < 80 {
                        eprintln!(
                            "[trace] cpu{cpu_id} IoOut {port:#x} = {:02x?}",
                            &data[..data.len().min(4)]
                        );
                        n_exit += 1;
                    }
                    for &b in data.iter() {
                        pio_write(&sh, port, b);
                    }
                }
                Ok(VcpuExit::MmioRead(addr, data)) => {
                    if dbg && n_exit < 80 {
                        eprintln!("[trace] cpu{cpu_id} MmioRead {addr:#x}");
                        n_exit += 1;
                    }
                    let val = mmio_read(&sh, addr);
                    let n = data.len().min(8);
                    data[..n].copy_from_slice(&val.to_le_bytes()[..n]);
                }
                Ok(VcpuExit::MmioWrite(addr, data)) => {
                    if dbg && n_exit < 80 {
                        eprintln!("[trace] cpu{cpu_id} MmioWrite {addr:#x}");
                        n_exit += 1;
                    }
                    let mut b = [0u8; 8];
                    let n = data.len().min(8);
                    b[..n].copy_from_slice(&data[..n]);
                    mmio_write(&sh, addr, u64::from_le_bytes(b));
                }
                Ok(VcpuExit::Hlt) => {
                    if dbg {
                        eprintln!("[trace] cpu{cpu_id} HLT");
                    }
                    return false;
                }
                Ok(VcpuExit::Shutdown) => {
                    if dbg {
                        dump_regs(vcpu, &sh.guest.ram, cpu_id, "SHUTDOWN");
                    }
                    sh.guest.vcpus.set_stop_reason(Stop::SystemReset);
                    return false;
                }
                Ok(VcpuExit::Intr) => {
                    if dbg && cpu_id == 0 {
                        dump_regs(vcpu, &sh.guest.ram, cpu_id, "kick");
                    }
                }
                Ok(other) => {
                    eprintln!("{LOG_PREFIX} cpu{cpu_id}: unhandled exit {other:?}");
                    return false;
                }
                Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {
                    if dbg && cpu_id == 0 {
                        dump_regs(vcpu, &sh.guest.ram, cpu_id, "kick(EINTR)");
                    }
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
        // CR3 is the walk root on x86-64; the arm64 registers stay zero.
        RegsView {
            root: self.get_sregs().map(|s| s.cr3).unwrap_or(0),
            pc: self.get_regs().map(|r| r.rip).unwrap_or(0),
            ..RegsView::default()
        }
    }
}

/// Dumps the vCPU's control/state registers + the instruction bytes at RIP
/// (assuming the early kernel is identity-mapped) (debug).
fn dump_regs(vcpu: &VcpuFd, mem: &GuestRam, cpu_id: u32, tag: &str) {
    if let (Ok(r), Ok(s)) = (vcpu.get_regs(), vcpu.get_sregs()) {
        let mut code = [0u8; 16];
        let _ = mem.read(r.rip, &mut code);
        eprintln!(
            "[trace] cpu{cpu_id} {tag}: rip={:#x} rsp={:#x} rflags={:#x} cs.sel={:#x} cs.l={} cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x} code@rip={:02x?}",
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

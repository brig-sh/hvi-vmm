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

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;

use kvm_bindings::{kvm_dtable, kvm_pit_config, kvm_segment};
use kvm_ioctls::{Cap, Kvm, VcpuExit, VcpuFd, VmFd};

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
use crate::devices::virtio::net::{self, GatewayRelay, TapRelay, VirtioNet};
use crate::devices::virtio::tap;
use crate::devices::virtio::vsock::VirtioVsock;
use crate::events::{CapturedEvent, Emitter};
use crate::hypervisor::quiesce::Quiesce;
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::{CpuHandle, GuestArch, IoSink, Plugin, RamRegion, RegsView, VmHandle};
use crate::sandbox::seccomp;
use crate::sync::lock_or_recover;
use crate::teardown::{join_by, StopSource, StopToken, STOP_TIMEOUT};
use crate::terminal;
use crate::LOG_PREFIX;

const KICK_SIGNAL: libc::c_int = libc::SIGUSR1;

// Long-mode control-register values (Firecracker's boot values).
const CR0_PE_PG: u64 = 0x8005_0033; // PE|MP|ET|NE|WP|AM|PG
const CR4_PAE: u64 = 0x0000_0020; // PAE
const EFER_LME_LMA: u64 = 0x0000_0500; // LME|LMA
const PDE64_PRESENT_RW_PS: u64 = 0x83; // present | writable | page-size (1 GiB)
const PDE64_PRESENT_RW: u64 = 0x03; // present | writable (table)

/// State shared across vCPU threads and helper threads.
#[derive(Clone)]
struct Shared {
    vm: Arc<VmFd>,
    mem: Arc<GuestRam>,
    uart: Arc<Mutex<Uart16550>>,
    /// The CMOS RTC: without it a guest hangs in read_persistent_clock64().
    rtc: Arc<Mutex<RtcCmos>>,
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
    let mut kickers = Vec::with_capacity(num_cpus as usize);
    for id in 0..num_cpus {
        let vcpu = vm.create_vcpu(u64::from(id))?;
        vcpu.set_cpuid2(&cpuid)?;
        if id == 0 {
            setup_long_mode(&vcpu, kernel.entry, kernel.zero_page_addr)?;
        }
        kickers.push(kick_handle(&vm, &vcpu)?);
        vcpus.push(vcpu);
    }

    let vm = Arc::new(vm);
    let shared = Shared {
        vm: Arc::clone(&vm),
        mem: ram,
        uart: Arc::new(Mutex::new(Uart16550::new())),
        rtc: Arc::new(Mutex::new(RtcCmos::new())),
        virtio,
        net,
        vsock,
        emit: Arc::new(Mutex::new(Emitter::new(
            cfg.events.as_deref(),
            &cfg.sandbox_id,
        )?)),
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
    let input = {
        let (sh, kick) = (shared.clone(), shared.clone());
        terminal::input::spawn(
            shared.plugin.clone(),
            stop_source.token(),
            move || kick_cpu0(&kick),
            move |byte| {
                let mut u = lock_or_recover(&sh.uart);
                u.push_rx(byte);
                set_line(&sh.vm, COM1_GSI, &u);
            },
        )
    };
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
    // Debug watchdog: force a register dump on a stuck guest (HVI_X86_TRACE).
    if std::env::var_os("HVI_X86_TRACE").is_some() {
        let sh = shared.clone();
        let watch = stop_source.token();
        helpers.push((
            "trace watchdog",
            std::thread::spawn(move || {
                seccomp::install_thread(seccomp::Thread::Vmm);
                for _ in 0..4 {
                    match watch.sleep(std::time::Duration::from_secs(2)) {
                        Ok(true) => kick_cpu0(&sh),
                        Ok(false) => break,
                        Err(e) => {
                            eprintln!("{LOG_PREFIX} trace watchdog: {e}; trace watchdog stopped");
                            break;
                        }
                    }
                }
            }),
        ));
    }
    let _raw = terminal::RawTerm::enable();

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
            eprintln!("{LOG_PREFIX} {e}");
            failure.get_or_insert(e.into());
            stop_all(&shared);
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

    for j in joins {
        let _ = j.join();
    }

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
    lock_or_recover(&shared.emit).flush();
    if let Some(e) = failure {
        return Err(e);
    }

    let stop = shared.stop.lock().unwrap().unwrap_or(Stop::SystemOff);
    Ok(stop)
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

/// Runs one vCPU until the VM stops, servicing its port I/O and MMIO exits.
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
    let dbg = std::env::var_os("HVI_X86_TRACE").is_some();
    let mut n_exit = 0u64;

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
                break;
            }
            Ok(VcpuExit::Shutdown) => {
                if dbg {
                    dump_regs(&vcpu, &sh.mem, cpu_id, "SHUTDOWN");
                }
                *sh.stop.lock().unwrap() = Some(Stop::SystemReset);
                break;
            }
            Ok(VcpuExit::Intr) => {
                if dbg && is_boot {
                    dump_regs(&vcpu, &sh.mem, cpu_id, "kick");
                }
            }
            Ok(other) => {
                eprintln!("{LOG_PREFIX} cpu{cpu_id}: unhandled exit {other:?}");
                break;
            }
            Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {
                if dbg && is_boot {
                    dump_regs(&vcpu, &sh.mem, cpu_id, "kick(EINTR)");
                }
            }
            Err(e) => {
                eprintln!("{LOG_PREFIX} cpu{cpu_id}: KVM_RUN error: {e}");
                break;
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
        eprintln!(
            "[trace] cpu{cpu_id} {tag}: rip={:#x} rsp={:#x} rflags={:#x} cs.sel={:#x} cs.l={} cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x} code@rip={:02x?}",
            r.rip, r.rsp, r.rflags, s.cs.selector, s.cs.l, s.cr0, s.cr3, s.cr4, s.efer, code
        );
    }
}

/// A device whose interrupt line hvi sets as a level after each access.
trait IrqLevel {
    /// Returns whether the device's interrupt line should be asserted now.
    fn irq_level(&self) -> bool;
}

impl IrqLevel for Uart16550 {
    fn irq_level(&self) -> bool {
        Uart16550::irq_level(self)
    }
}

impl IrqLevel for VirtioBlk {
    fn irq_level(&self) -> bool {
        VirtioBlk::irq_level(self)
    }
}

impl IrqLevel for VirtioNet {
    fn irq_level(&self) -> bool {
        VirtioNet::irq_level(self)
    }
}

impl IrqLevel for VirtioVsock {
    fn irq_level(&self) -> bool {
        VirtioVsock::irq_level(self)
    }
}

/// Sets `gsi` to the interrupt level of the device that `dev` guards.
///
/// It takes the lock guard, so the level reaches the line before the lock is
/// released, in the order of the accesses. Two threads that applied their
/// levels out of order could leave the line high with nothing pending. The
/// guest programs every ISA pin as edge-triggered, so it would then miss the
/// device's next interrupt.
fn set_line<D: IrqLevel>(vm: &VmFd, gsi: u32, dev: &MutexGuard<'_, D>) {
    let _ = vm.set_irq_line(gsi, dev.irq_level());
}

/// Routes a port-I/O read to the device behind `port` and returns the value.
///
/// A COM1 access passes the new COM1 interrupt level to `set_com1` with the
/// UART lock still held, for the reason [`set_line`] gives.
///
/// Split from [`pio_read`] so the routing is callable without a live vCPU or a
/// VM to raise the GSI on.
fn pio_dispatch_read(
    uart: &Mutex<Uart16550>,
    rtc: &Mutex<RtcCmos>,
    port: u16,
    set_com1: impl FnOnce(bool),
) -> u8 {
    if (COM1_PORT..COM1_PORT + 8).contains(&port) {
        let mut u = uart.lock().unwrap();
        let v = u.pio_read(port - COM1_PORT);
        set_com1(u.irq_level());
        v
    } else if port == RTC_INDEX_PORT || port == RTC_DATA_PORT {
        rtc.lock().unwrap().pio_read(port)
    } else {
        0xff
    }
}

/// Routes a port-I/O write; the write half of [`pio_dispatch_read`].
fn pio_dispatch_write(
    uart: &Mutex<Uart16550>,
    rtc: &Mutex<RtcCmos>,
    port: u16,
    val: u8,
    set_com1: impl FnOnce(bool),
) {
    if (COM1_PORT..COM1_PORT + 8).contains(&port) {
        let mut u = uart.lock().unwrap();
        u.pio_write(port - COM1_PORT, val);
        set_com1(u.irq_level());
    } else if port == RTC_INDEX_PORT || port == RTC_DATA_PORT {
        rtc.lock().unwrap().pio_write(port, val);
    }
}

fn pio_read(sh: &Shared, port: u16) -> u8 {
    pio_dispatch_read(&sh.uart, &sh.rtc, port, |level| {
        let _ = sh.vm.set_irq_line(COM1_GSI, level);
    })
}

fn pio_write(sh: &Shared, port: u16, val: u8) {
    pio_dispatch_write(&sh.uart, &sh.rtc, port, val, |level| {
        let _ = sh.vm.set_irq_line(COM1_GSI, level);
    });
}

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

fn mmio_write(sh: &Shared, addr: u64, val: u64) {
    if (VIRTIO_BLK_BASE..VIRTIO_BLK_BASE + VIRTIO_SIZE).contains(&addr) {
        blk_write(sh, addr - VIRTIO_BLK_BASE, val);
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        net_write(sh, addr - VIRTIO_NET_BASE, val);
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        vsock_write(sh, addr - VIRTIO_VSOCK_BASE, val);
    }
}

fn drain(sh: &Shared, events: &[CapturedEvent]) {
    if events.is_empty() {
        return;
    }
    let mut e = sh.emit.lock().unwrap();
    for ev in events {
        e.captured(ev);
    }
}

fn blk_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.virtio.as_ref() else {
        return 0;
    };
    let (v, events) = {
        let mut d = dev.lock().unwrap();
        let v = d.mmio(&sh.mem, off, false, 0);
        set_line(&sh.vm, VIRTIO_BLK_GSI, &d);
        (v, d.take_events())
    };
    drain(sh, &events);
    v
}
fn blk_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.virtio.as_ref() else {
        return;
    };
    let events = {
        let mut d = dev.lock().unwrap();
        d.mmio(&sh.mem, off, true, val);
        set_line(&sh.vm, VIRTIO_BLK_GSI, &d);
        d.take_events()
    };
    drain(sh, &events);
}
fn net_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.net.as_ref() else { return 0 };
    let (v, events) = {
        let mut d = dev.lock().unwrap();
        let v = d.mmio(&sh.mem, off, false, 0);
        set_line(&sh.vm, VIRTIO_NET_GSI, &d);
        (v, d.take_events())
    };
    drain(sh, &events);
    v
}
fn net_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.net.as_ref() else { return };
    let events = {
        let mut d = dev.lock().unwrap();
        d.mmio(&sh.mem, off, true, val);
        set_line(&sh.vm, VIRTIO_NET_GSI, &d);
        d.take_events()
    };
    drain(sh, &events);
}
fn vsock_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.vsock.as_ref() else {
        return 0;
    };
    let mut d = dev.lock().unwrap();
    let v = d.mmio(&sh.mem, off, false, 0);
    set_line(&sh.vm, VIRTIO_VSOCK_GSI, &d);
    v
}
fn vsock_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.vsock.as_ref() else { return };
    let mut d = dev.lock().unwrap();
    d.mmio(&sh.mem, off, true, val);
    set_line(&sh.vm, VIRTIO_VSOCK_GSI, &d);
}

/// [`VmHandle`] over the shared VM state: what a plugin gets at attach time.
impl VmHandle for Shared {
    fn arch(&self) -> GuestArch {
        GuestArch::X86_64
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
        // Both halves. Reporting only the low one leaves a plugin mapping
        // less than the guest has and reading nothing above the MMIO hole --
        // which looks like an empty guest, not like a missing region.
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
        GuestArch::X86_64
    }

    fn ram(&self) -> &GuestRam {
        &self.sh.mem
    }

    fn regs(&self) -> RegsView {
        // CR3 is the walk root on x86-64; the arm64 registers stay zero.
        RegsView {
            root: self.vcpu.get_sregs().map(|s| s.cr3).unwrap_or(0),
            pc: self.vcpu.get_regs().map(|r| r.rip).unwrap_or(0),
            ..RegsView::default()
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

/// Bridges the host agent Unix socket to the guest vsock device.
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
                set_line(&vm, VIRTIO_VSOCK_GSI, &d);
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
                        set_line(&vm3, VIRTIO_VSOCK_GSI, &d);
                        break;
                    }
                }
                let mut d = lock_or_recover(&dev3);
                let needed = d.flush_to_host(&mem3, port);
                set_line(&vm3, VIRTIO_VSOCK_GSI, &d);
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
                        set_line(&vm2, VIRTIO_VSOCK_GSI, &d);
                        gate
                    };
                    // `HostGate::wait` says why its result is not needed.
                    if let Some(gate) = gate {
                        gate.wait(|| stop2.keep_waiting(reader.as_fd()));
                    }
                }
                let mut d = lock_or_recover(&dev2);
                d.host_closed(&mem2, port);
                set_line(&vm2, VIRTIO_VSOCK_GSI, &d);
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
            let mut d = lock_or_recover(&dev);
            d.deliver(&mem, frame);
            set_line(&vm, VIRTIO_NET_GSI, &d);
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
            let mut d = lock_or_recover(&dev);
            d.deliver(&mem, frame);
            set_line(&vm, VIRTIO_NET_GSI, &d);
        });
        if let Err(e) = relayed {
            eprintln!("{LOG_PREFIX} virtio-net: {e}; gateway relay stopped");
        }
    })
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
    use std::cell::Cell;

    use super::*;

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
        let no_line = |_| panic!("the RTC drives no interrupt line");
        pio_dispatch_write(&uart, &rtc, RTC_INDEX_PORT, REG_B, no_line);
        let via_ports = pio_dispatch_read(&uart, &rtc, RTC_DATA_PORT, no_line);

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
        let uart = Mutex::new(Uart16550::new());
        let rtc = Mutex::new(RtcCmos::new());
        let line = Cell::new(false);
        let edges = Cell::new(0);
        let set = |level: bool| {
            assert!(uart.try_lock().is_err(), "the line is set under the lock");
            if level && !line.get() {
                edges.set(edges.get() + 1);
            }
            line.set(level);
        };
        const IER: u16 = COM1_PORT + 1;
        const IIR: u16 = COM1_PORT + 2;

        pio_dispatch_write(&uart, &rtc, IER, 0x02, set);
        assert_eq!(edges.get(), 1);
        assert_eq!(pio_dispatch_read(&uart, &rtc, IIR, set), 0xc2);
        assert!(!line.get(), "the IIR read drops the line");
        for b in b"0123456789abcdef" {
            pio_dispatch_write(&uart, &rtc, COM1_PORT, *b, set);
        }
        assert_eq!(edges.get(), 2, "the THR writes raise a second edge");
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
                crate::arch::x86_64::loader::tests::synthetic_bzimage(),
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
            let outcome = boot(config(
                crate::arch::x86_64::loader::tests::spinning_bzimage(),
                None,
            ))
            .map_err(|e| e.to_string());
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

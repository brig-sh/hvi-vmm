//! Boot an x86-64 Linux guest on KVM (Linux host), SMP-capable.
//!
//! The x86 counterpart of `machine_linux`. KVM gives us an in-kernel LAPIC +
//! IOAPIC + PIT (`create_irq_chip`/`create_pit2`), so SMP is just: enter the
//! BSP in long mode and run every vCPU thread — the guest brings up APs with
//! INIT-SIPI-SIPI, handled in-kernel. We build the initial long-mode state
//! (identity page tables, flat 64-bit segments, CR0/CR3/CR4/EFER), load the
//! bzImage + `boot_params` (see `boot_x86`), and enter at the 64-bit entry with
//! RSI -> the zero page.
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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::{kvm_dtable, kvm_pit_config, kvm_segment, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};

use crate::boot_x86::{self, BootPlan};
use crate::config::{BootConfig, Stop};
use crate::events::{CapturedEvent, Emitter};
use crate::guestmem::GuestRam;
use crate::layout_x86::{
    BOOT_STACK, COM1_GSI, COM1_PORT, GDT_ADDR, HIGH_RAM_BASE, MMIO_GAP_START, MPTABLE_ADDR,
    PDPT_ADDR, PML4_ADDR, RAM_BASE, VIRTIO_BLK_BASE, VIRTIO_BLK_GSI, VIRTIO_NET_BASE,
    VIRTIO_NET_GSI, VIRTIO_SIZE, VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_GSI,
};
use crate::mptable;
use crate::plugin::{CpuHandle, GuestArch, IoSink, MemRegion, Plugin, RegsView, VmHandle};
use crate::rtc_cmos::{RtcCmos, RTC_DATA_PORT, RTC_INDEX_PORT};
use crate::uart16550::Uart16550;
use crate::virtio::VirtioBlk;
use crate::virtio_net::VirtioNet;
use crate::virtio_vsock::VirtioVsock;

const KICK_SIGNAL: libc::c_int = libc::SIGUSR1;
const REQUEST_KEY: u8 = 0x1d; // Ctrl-]

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
    threads: Arc<Mutex<Vec<u64>>>,
    stop: Arc<Mutex<Option<Stop>>>,
    /// Parks every vCPU at a safe point so an observation sees a still guest.
    quiesce: Arc<crate::quiesce::Quiesce>,
    /// Whoever is watching this guest, if anyone.
    plugin: Option<Arc<dyn Plugin>>,
    /// Guest RAM's shareable descriptor, and the two halves either side of the
    /// MMIO hole, for a plugin that hands the same pages to another process.
    ram_fd: std::os::fd::RawFd,
    low_bytes: u64,
    high_bytes: u64,
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
pub fn boot(cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error>> {
    if !cfg.fs_shares.is_empty() {
        return Err(
            "--share-ro/--share-rw are currently implemented by the macOS HVI backend only".into(),
        );
    }
    install_kick_handler();
    let num_cpus = cfg.vcpus.max(1);

    let kvm = Kvm::new()?;
    let vm = kvm.create_vm()?;

    // Intel VMX needs a TSS + an identity-map page for guest-mode setup, even
    // though we enter directly in long mode (Firecracker/CH do the same). Set
    // them before creating the irqchip/vCPUs.
    vm.set_tss_address(0xfffb_d000)?;
    vm.set_identity_map_address(0xfffb_c000)?;

    // Guest RAM, split around the sub-4 GiB MMIO hole (see MMIO_GAP_START). The
    // host mapping stays one contiguous object; only the guest-physical view
    // has a gap, so the high half is just the bytes after the low half.
    let size = cfg.mem_bytes as usize;
    let low_bytes = cfg.mem_bytes.min(MMIO_GAP_START);
    let high_bytes = cfg.mem_bytes.saturating_sub(low_bytes);
    // Guest RAM comes from a shareable object (a memfd) rather than an
    // anonymous private mapping, so an out-of-process plugin can map
    // the same pages. KVM only needs a valid host address, so the guest is
    // unaffected.
    let guest_ram = crate::sharedmem::SharedRam::new(size)?;
    let host = guest_ram.as_ptr().cast::<libc::c_void>();
    let region = kvm_userspace_memory_region {
        slot: 0,
        flags: 0, // no dirty tracking
        guest_phys_addr: RAM_BASE,
        memory_size: low_bytes,
        userspace_addr: host as u64,
    };
    // SAFETY: `host` maps `size` bytes and outlives the VM.
    unsafe { vm.set_user_memory_region(region)? };
    if high_bytes > 0 {
        let high = kvm_userspace_memory_region {
            slot: 1,
            flags: 0,
            guest_phys_addr: HIGH_RAM_BASE,
            memory_size: high_bytes,
            userspace_addr: host as u64 + low_bytes,
        };
        // SAFETY: the high half is within the same `size`-byte mapping, at
        // offset `low_bytes`, and outlives the VM.
        unsafe { vm.set_user_memory_region(high)? };
        eprintln!(
            "[hvi/x86] RAM {} MiB: {} MiB at {:#x} + {} MiB at {HIGH_RAM_BASE:#x}",
            cfg.mem_bytes >> 20,
            low_bytes >> 20,
            RAM_BASE,
            high_bytes >> 20
        );
    }
    let ram = Arc::new(GuestRam::new_split(
        host.cast::<u8>(),
        RAM_BASE,
        low_bytes as usize,
        HIGH_RAM_BASE,
        high_bytes as usize,
    ));

    // In-kernel LAPIC + IOAPIC + PIT.
    vm.create_irq_chip()?;
    vm.create_pit2(kvm_pit_config::default())?;

    // Devices.
    let virtio = match &cfg.disk {
        Some(path) => {
            eprintln!("[hvi/x86] virtio-blk: {path}");
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
        eprintln!("[hvi/x86] virtio-net: tap {ifname}");
        net_tap_reader = Some(reader);
        let mut dev = VirtioNet::with_tap(file);
        // The redirect hands us the veth's frames unchanged, so the guest has
        // to answer to the veth's MAC.
        match cfg.net_mac.as_deref().map(crate::tap::parse_mac) {
            Some(Some(mac)) => dev.set_mac(mac),
            Some(None) => {
                eprintln!("[hvi/x86] WARNING: unparsable --net-mac; keeping the default");
            }
            None => {}
        }
        Some(Arc::new(Mutex::new(dev)))
    } else if let Some(sock) = &cfg.net_gateway {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(stream) => match stream.try_clone() {
                Ok(reader) => {
                    eprintln!("[hvi/x86] virtio-net: gvisor-tap gateway relay via {sock}");
                    net_reader = Some(reader);
                    Some(Arc::new(Mutex::new(VirtioNet::with_gateway(stream))))
                }
                Err(_) => None,
            },
            Err(e) => {
                eprintln!("[hvi/x86] WARNING: gateway {sock} unreachable ({e}); built-in stack");
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

    // Parse the bzImage and lay out boot_params/kernel/initrd + MP table.
    let initrd_len = cfg.initramfs.as_ref().map_or(0, |v| v.len() as u64);
    let plan: BootPlan =
        boot_x86::prepare(&cfg.kernel, &cmdline, initrd_len, low_bytes, high_bytes)?;
    ram.write(plan.kernel_load, &plan.kernel_image)?;
    ram.write(plan.zero_page_addr, &plan.zero_page)?;
    ram.write(plan.cmdline_addr, &plan.cmdline)?;
    if let (Some(addr), Some(initramfs)) = (plan.initrd_addr, &cfg.initramfs) {
        ram.write(addr, initramfs)?;
    }
    ram.write(MPTABLE_ADDR, &mptable::build(num_cpus))?;
    write_boot_page_tables(&ram)?;
    write_boot_gdt(&ram)?;
    eprintln!(
        "[hvi/x86] {num_cpus} vCPU(s)  kernel@{:#x} entry@{:#x}",
        plan.kernel_load, plan.entry
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
    for id in 0..num_cpus {
        let vcpu = vm.create_vcpu(u64::from(id))?;
        vcpu.set_cpuid2(&cpuid)?;
        if id == 0 {
            setup_long_mode(&vcpu, plan.entry, plan.zero_page_addr)?;
        }
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
        threads: Arc::new(Mutex::new(vec![0u64; num_cpus as usize])),
        stop: Arc::new(Mutex::new(None)),
        quiesce: Arc::new(crate::quiesce::Quiesce::new()),
        plugin: cfg.plugin.clone(),
        ram_fd: guest_ram.fd(),
        low_bytes,
        high_bytes,
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
    // an error here rather than a SIGSYS inside a device thread later.
    // Nothing is filtered yet: each thread installs its own as it starts
    // (see `seccomp`).
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
    // Debug watchdog: force a register dump on a stuck guest (HVI_X86_TRACE).
    if std::env::var_os("HVI_X86_TRACE").is_some() {
        let sh = shared.clone();
        std::thread::spawn(move || {
            crate::seccomp::install_thread(crate::seccomp::Thread::Vmm);
            for _ in 0..4 {
                std::thread::sleep(std::time::Duration::from_secs(2));
                kick_cpu0(&sh);
            }
        });
    }
    let _raw = RawTerm::enable();

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

/// A single vCPU thread: KVM_RUN loop with PIO (serial) + MMIO (virtio).
fn run_cpu(cpu_id: u32, mut vcpu: VcpuFd, sh: Shared) {
    // The tight filter, installed before this thread touches anything the guest
    // controls: MMIO exits are serviced inline here, so the virtio device
    // models -- the code that parses guest descriptors -- run on this
    // thread.
    crate::seccomp::install_thread(crate::seccomp::Thread::Vcpu);
    // SAFETY: pthread_self is valid on the current thread.
    let tid = unsafe { libc::pthread_self() } as u64;
    if let Ok(mut t) = sh.threads.lock() {
        if (cpu_id as usize) < t.len() {
            t[cpu_id as usize] = tid;
        }
    }
    let is_boot = cpu_id == 0;
    let dbg = std::env::var_os("HVI_X86_TRACE").is_some();
    let mut n_exit = 0u64;

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
                stop_all(&sh);
                break;
            }
            Ok(VcpuExit::Intr) => {
                if dbg && is_boot {
                    dump_regs(&vcpu, &sh.mem, cpu_id, "kick");
                }
            }
            Ok(other) => {
                eprintln!("[hvi/x86] cpu{cpu_id}: unhandled exit {other:?}");
                if is_boot {
                    stop_all(&sh);
                }
                break;
            }
            Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {
                if dbg && is_boot {
                    dump_regs(&vcpu, &sh.mem, cpu_id, "kick(EINTR)");
                }
            }
            Err(e) => {
                eprintln!("[hvi/x86] cpu{cpu_id}: KVM_RUN error: {e}");
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

/// Routes a port-I/O read to the device behind `port`. Returns the value and,
/// for the serial ports, the COM1 interrupt level the caller must apply.
///
/// Split from [`pio_read`] so the routing is callable without a live vCPU or a
/// VM to raise the GSI on: raising it is the only side effect that needs KVM,
/// so it is returned rather than performed.
fn pio_dispatch_read(
    uart: &Mutex<Uart16550>,
    rtc: &Mutex<RtcCmos>,
    port: u16,
) -> (u8, Option<bool>) {
    if (COM1_PORT..COM1_PORT + 8).contains(&port) {
        let mut u = uart.lock().unwrap();
        let v = u.pio_read(port - COM1_PORT);
        (v, Some(u.irq_level()))
    } else if port == RTC_INDEX_PORT || port == RTC_DATA_PORT {
        (rtc.lock().unwrap().pio_read(port), None)
    } else {
        (0xff, None)
    }
}

/// Routes a port-I/O write; the write half of [`pio_dispatch_read`].
fn pio_dispatch_write(
    uart: &Mutex<Uart16550>,
    rtc: &Mutex<RtcCmos>,
    port: u16,
    val: u8,
) -> Option<bool> {
    if (COM1_PORT..COM1_PORT + 8).contains(&port) {
        let mut u = uart.lock().unwrap();
        u.pio_write(port - COM1_PORT, val);
        Some(u.irq_level())
    } else if port == RTC_INDEX_PORT || port == RTC_DATA_PORT {
        rtc.lock().unwrap().pio_write(port, val);
        None
    } else {
        None
    }
}

fn pio_read(sh: &Shared, port: u16) -> u8 {
    let (v, com1_level) = pio_dispatch_read(&sh.uart, &sh.rtc, port);
    if let Some(level) = com1_level {
        let _ = sh.vm.set_irq_line(COM1_GSI, level);
    }
    v
}

fn pio_write(sh: &Shared, port: u16, val: u8) {
    if let Some(level) = pio_dispatch_write(&sh.uart, &sh.rtc, port, val) {
        let _ = sh.vm.set_irq_line(COM1_GSI, level);
    }
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
    let (v, level, events) = {
        let mut d = dev.lock().unwrap();
        let v = d.mmio(&sh.mem, off, false, 0);
        (v, d.irq_level(), d.take_events())
    };
    drain(sh, &events);
    let _ = sh.vm.set_irq_line(VIRTIO_BLK_GSI, level);
    v
}
fn blk_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.virtio.as_ref() else {
        return;
    };
    let (level, events) = {
        let mut d = dev.lock().unwrap();
        d.mmio(&sh.mem, off, true, val);
        (d.irq_level(), d.take_events())
    };
    drain(sh, &events);
    let _ = sh.vm.set_irq_line(VIRTIO_BLK_GSI, level);
}
fn net_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.net.as_ref() else { return 0 };
    let (v, level, events) = {
        let mut d = dev.lock().unwrap();
        let v = d.mmio(&sh.mem, off, false, 0);
        (v, d.irq_level(), d.take_events())
    };
    drain(sh, &events);
    let _ = sh.vm.set_irq_line(VIRTIO_NET_GSI, level);
    v
}
fn net_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.net.as_ref() else { return };
    let (level, events) = {
        let mut d = dev.lock().unwrap();
        d.mmio(&sh.mem, off, true, val);
        (d.irq_level(), d.take_events())
    };
    drain(sh, &events);
    let _ = sh.vm.set_irq_line(VIRTIO_NET_GSI, level);
}
fn vsock_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.vsock.as_ref() else {
        return 0;
    };
    let (v, level) = {
        let mut d = dev.lock().unwrap();
        (d.mmio(&sh.mem, off, false, 0), d.irq_level())
    };
    let _ = sh.vm.set_irq_line(VIRTIO_VSOCK_GSI, level);
    v
}
fn vsock_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.vsock.as_ref() else { return };
    let level = {
        let mut d = dev.lock().unwrap();
        d.mmio(&sh.mem, off, true, val);
        d.irq_level()
    };
    let _ = sh.vm.set_irq_line(VIRTIO_VSOCK_GSI, level);
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

    fn ram_fd(&self) -> std::os::fd::RawFd {
        self.ram_fd
    }

    fn ram_regions(&self) -> Vec<MemRegion> {
        // Both halves. Reporting only the low one leaves a plugin mapping
        // less than the guest has and reading nothing above the MMIO hole --
        // which looks like an empty guest, not like a missing region.
        let mut r = vec![MemRegion {
            gpa: RAM_BASE,
            size: self.low_bytes,
            file_offset: 0,
        }];
        if self.high_bytes > 0 {
            r.push(MemRegion {
                gpa: HIGH_RAM_BASE,
                size: self.high_bytes,
                file_offset: self.low_bytes,
            });
        }
        r
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

fn stop_all(sh: &Shared) {
    sh.running.store(false, Ordering::SeqCst);
    kick_all(sh);
}
fn kick_all(sh: &Shared) {
    if let Ok(t) = sh.threads.lock() {
        for &tid in t.iter() {
            if tid != 0 {
                // SAFETY: pthread_kill to a live handle; no-op handler.
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

fn install_kick_handler() {
    extern "C" fn noop(_: libc::c_int) {}
    // SAFETY: installing a trivial handler at startup (no SA_RESTART -> EINTR).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = noop as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(KICK_SIGNAL, &sa, std::ptr::null_mut());
    }
}

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
                let mut u = sh.uart.lock().unwrap();
                u.push_rx(byte[0]);
                u.irq_level()
            };
            let _ = sh.vm.set_irq_line(COM1_GSI, level);
        }
    });
}

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
                let _ = vm.set_irq_line(VIRTIO_VSOCK_GSI, level);
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
                    let _ = vm2.set_irq_line(VIRTIO_VSOCK_GSI, level);
                }
                let level = {
                    let mut d = dev2.lock().unwrap();
                    d.host_closed(&mem2, port);
                    d.irq_level()
                };
                let _ = vm2.set_irq_line(VIRTIO_VSOCK_GSI, level);
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
            let _ = vm.set_irq_line(VIRTIO_NET_GSI, level);
        }
    });
}

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
            let _ = vm.set_irq_line(VIRTIO_NET_GSI, level);
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
        let level = pio_dispatch_write(&uart, &rtc, RTC_INDEX_PORT, REG_B);
        assert_eq!(level, None, "the RTC drives no interrupt line");
        let (via_ports, level) = pio_dispatch_read(&uart, &rtc, RTC_DATA_PORT);
        assert_eq!(level, None);

        // The same register read straight from a device instance must match:
        // the dispatch adds routing, not behavior.
        let mut direct = RtcCmos::new();
        direct.pio_write(RTC_INDEX_PORT, REG_B);
        assert_eq!(via_ports, direct.pio_read(RTC_DATA_PORT));
        // And status B still reports what the rtc_cmos tests pin: BCD, 24h.
        assert_eq!(via_ports & 0x04, 0, "DM clear means BCD");
        assert_eq!(via_ports & 0x02, 0x02, "24-hour mode");
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

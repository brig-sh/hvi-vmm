//! `hvi` — the VMM, as a command.
//!
//! This binary is a thin CLI over the [`hvi`] library: it parses flags, reads
//! the kernel, and hands a [`hvi::config::BootConfig`] to the active backend.
//! Everything of substance lives in the library, because the VMM is meant to be
//! linked as well as run.
//!
//! `--dump-memory` and `--trace-io` attach the tools in [`hvi::plugins`]
//! through the seam in [`hvi::plugin`]; with neither, nothing is attached and
//! no guest memory is read for any purpose but running the guest. Another crate
//! can link this one and supply its own [`hvi::plugin::Plugin`] the same way
//! -- see `docs/plugins.md`.

use std::sync::Arc;

use hvi::plugins::{Chain, IoTrace, MemoryDump};
use hvi::{config, machine};

#[cfg(target_arch = "aarch64")]
use hvi::{boot, fdt, layout};

/// Hosts with a real VMM backend: aarch64 on macOS (hvf) or Linux (KVM), and
/// x86-64 on Linux (KVM).
#[cfg(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("boot") => boot_guest(&args[2..]),
        Some("--version" | "-V" | "version") => {
            print_version();
            Ok(())
        }
        Some("dump-fdt") => {
            #[cfg(target_arch = "aarch64")]
            {
                dump_fdt(&args[2..])
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                Err("`dump-fdt` builds an arm64 devicetree; not applicable on x86".into())
            }
        }
        // Proves the profile on a host that cannot boot a guest: it needs no
        // hypervisor entitlement, so a hosted macOS runner can still check the
        // confinement. A subcommand rather than a `#[test]` because entering
        // the sandbox is irreversible and process-wide -- inside `cargo test`
        // it would confine every other test sharing the process.
        Some("sandbox-selftest") => {
            #[cfg(target_os = "macos")]
            {
                let bad = hvi::sandbox::selftest()?;
                if bad > 0 {
                    return Err(format!(
                        "{bad} sandbox probe(s) did not behave as the profile says they should"
                    )
                    .into());
                }
                println!("sandbox selftest: every probe matched the profile");
                Ok(())
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err("`sandbox-selftest` exercises Seatbelt; macOS only".into())
            }
        }
        // The Linux counterpart: installs the production seccomp allowlists in
        // child processes and reports which syscalls survived. Needs no
        // hypervisor and no privileges, so a hosted runner can prove the filter
        // even where it cannot boot a guest. Children rather than threads
        // because a denied syscall traps: an in-process probe would end the
        // selftest at the first denial instead of reporting it.
        Some("seccomp-selftest") => {
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            {
                let bad = hvi::seccomp::selftest()?;
                if bad > 0 {
                    return Err(format!(
                        "{bad} seccomp probe(s) did not behave as the filters say they should"
                    )
                    .into());
                }
                println!("seccomp selftest: every probe matched the filters");
                Ok(())
            }
            #[cfg(not(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )))]
            {
                Err("`seccomp-selftest` exercises seccomp-bpf; Linux x86-64/aarch64 only".into())
            }
        }
        Some("smoke") => {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            {
                // `--shm` runs the same test over shared guest memory (the
                // mechanism an out-of-process plugin needs on macOS).
                if args.get(2).map(String::as_str) == Some("--shm") {
                    hvi::smoke::run_shm()
                } else {
                    hvi::smoke::run()
                }
            }
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            {
                Err("`smoke` (M0 hvf test) is macOS / Apple-silicon only".into())
            }
        }
        // Child half of `smoke --shm`: reads the shared object by name from a
        // process that never touched the hypervisor.
        Some("smoke-shm-verify") => {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            {
                let name = args.get(2).ok_or("smoke-shm-verify needs a shm name")?;
                let expect = args
                    .get(3)
                    .ok_or("smoke-shm-verify needs an expected value")?;
                let expect = u64::from_str_radix(expect.trim_start_matches("0x"), 16)?;
                hvi::smoke::verify_shm(name, expect)
            }
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            {
                Err("`smoke-shm-verify` is macOS / Apple-silicon only".into())
            }
        }
        None => {
            eprintln!(
                "hvi — a microVMM\n\nusage: hvi \
                 <boot|dump-fdt|smoke|sandbox-selftest|seccomp-selftest|--version> [args]"
            );
            Ok(())
        }
        Some(other) => Err(format!(
            "unknown subcommand {other:?}; expected `boot`, `dump-fdt`, `smoke` or `--version`"
        )
        .into()),
    }
}

/// Prints the build's identity: its own version and the VMM core it was built
/// against.
///
/// The core is the point. More than one binary is built from this crate — this
/// one, and others that link it and add plugins of their own — and they are all
/// called `hvi`. Two of them reporting the same core ran the same VMM, which is
/// what makes a comparison between them a comparison of plugins rather than of
/// machines that merely resemble each other.
fn print_version() {
    println!(
        "hvi {} (core {})",
        env!("CARGO_PKG_VERSION"),
        hvi::CORE_VERSION
    );
}

/// `dump-fdt --kernel <Image> [--initramfs <cpio>] [--mem-mib N] [--cmdline S]
/// [--out <file>]`: parse the kernel header, compute the guest layout, build
/// the DTB, and print the layout (writing the blob out if `--out` is given).
/// Pure — no hypervisor — so it runs anywhere the binary does.
#[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")))]
fn dump_fdt(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use boot::Arm64Image;
    use layout::{GicLayout, GuestLayout};

    let mut kernel = None;
    let mut initramfs = None;
    let mut mem_mib: u64 = 512;
    let mut cmdline = String::from("earlycon console=ttyAMA0 panic=-1");
    let mut out = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--kernel" => kernel = it.next().cloned(),
            "--initramfs" => initramfs = it.next().cloned(),
            "--mem-mib" => {
                mem_mib = it.next().ok_or("--mem-mib needs a value")?.parse()?;
            }
            "--cmdline" => cmdline = it.next().ok_or("--cmdline needs a value")?.clone(),
            "--out" => out = it.next().cloned(),
            other => return Err(format!("unknown dump-fdt arg {other:?}").into()),
        }
    }

    let kernel_path = kernel.ok_or("dump-fdt needs --kernel <Image>")?;
    let kernel_bytes = std::fs::read(&kernel_path)?;
    let img = Arm64Image::parse(&kernel_bytes)?;
    let kernel_size = img.reserved_size(kernel_bytes.len() as u64);
    let initrd_size = match &initramfs {
        Some(p) => std::fs::metadata(p)?.len(),
        None => 0,
    };

    let ram_size = mem_mib << 20;
    let gic = GicLayout::QEMU_VIRT;

    // Two passes: the DTB's own length feeds the initramfs placement, so build
    // once with a provisional slot, then rebuild at the settled layout.
    let provisional = GuestLayout::new(ram_size, img.text_offset, kernel_size, 0x4000, initrd_size);
    let dtb0 = fdt::build(&provisional, &gic, 1, &cmdline, false, false, false)?;
    let layout = GuestLayout::new(
        ram_size,
        img.text_offset,
        kernel_size,
        dtb0.len() as u64,
        initrd_size,
    );
    let dtb = fdt::build(&layout, &gic, 1, &cmdline, false, false, false)?;
    layout.validate()?;

    println!(
        "kernel {kernel_path}: text_offset={:#x} reserved_size={kernel_size:#x} (file {} bytes)",
        img.text_offset,
        kernel_bytes.len()
    );
    println!("RAM   {:#x} + {mem_mib} MiB", layout.ram_base);
    println!(
        "kernel@{:#x} dtb@{:#x} (+{:#x}) initrd@{:#x} (+{:#x})  top={:#x}",
        layout.kernel_addr,
        layout.dtb_addr,
        dtb.len(),
        layout.initrd_addr,
        initrd_size,
        layout.top()
    );
    println!("cmdline: {cmdline}");
    if let Some(path) = out {
        std::fs::write(&path, &dtb)?;
        println!("wrote {} byte DTB to {path}", dtb.len());
    }
    Ok(())
}

/// `boot --kernel <Image|bzImage> [flags]`: boot a Linux guest on the active
/// backend (hvf/arm64 on macOS, KVM/arm64 or KVM/x86-64 on Linux).
///
/// `--dump-memory <path>` writes guest RAM on the interrupt key (or after
/// `--dump-after <secs>`); `--trace-io <path>` logs every virtio request.
#[cfg(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
))]
fn boot_guest(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = None;
    let mut initramfs = None;
    let mut mem_mib: u64 = 512;
    let mut cmdline = String::from("earlycon console=ttyAMA0 panic=-1");
    let mut disk = None;
    let mut net = false;
    let mut net_gateway = None;
    let mut net_tap = None;
    let mut net_mac = None;
    let mut events = None;
    let mut sandbox_id = String::from("hvi");
    let mut vcpus: u32 = 1;
    let mut agent_sock = None;
    let mut dump_memory = None;
    let mut dump_after = None;
    let mut trace_io = None;
    let mut sandbox = true;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--kernel" => kernel = it.next().cloned(),
            "--initramfs" => initramfs = it.next().cloned(),
            "--mem-mib" => mem_mib = it.next().ok_or("--mem-mib needs a value")?.parse()?,
            "--cmdline" => cmdline = it.next().ok_or("--cmdline needs a value")?.clone(),
            "--disk" => disk = it.next().cloned(),
            "--net" => net = true,
            "--net-gateway" => net_gateway = it.next().cloned(),
            "--net-tap" => net_tap = it.next().cloned(),
            "--net-mac" => net_mac = it.next().cloned(),
            "--events" => events = it.next().cloned(),
            "--sandbox-id" => {
                sandbox_id = it.next().ok_or("--sandbox-id needs a value")?.clone();
            }
            "--cpus" => vcpus = it.next().ok_or("--cpus needs a value")?.parse()?,
            "--agent-sock" => agent_sock = it.next().cloned(),
            "--dump-memory" => dump_memory = it.next().cloned(),
            "--dump-after" => {
                dump_after = Some(it.next().ok_or("--dump-after needs seconds")?.parse()?);
            }
            "--trace-io" => trace_io = it.next().cloned(),
            "--no-sandbox" => sandbox = false,
            other => return Err(format!("unknown boot arg {other:?}").into()),
        }
    }

    if dump_after.is_some() && dump_memory.is_none() {
        return Err("--dump-after needs --dump-memory <path>".into());
    }
    // One boot takes one plugin, so the requested tools are chained.
    let mut tools = Chain::new();
    if let Some(path) = &dump_memory {
        let mut d = MemoryDump::new(path);
        if let Some(secs) = dump_after {
            d = d.after(secs);
        }
        tools = tools.with(Arc::new(d));
    }
    if let Some(path) = &trace_io {
        tools = tools.with(Arc::new(IoTrace::new(path)?));
    }

    let kernel_path = kernel.ok_or("boot needs --kernel <Image>")?;
    let cfg = config::BootConfig {
        kernel: std::fs::read(&kernel_path)?,
        initramfs: initramfs.map(std::fs::read).transpose()?,
        mem_bytes: mem_mib << 20,
        cmdline,
        disk,
        net,
        net_gateway,
        net_tap,
        net_mac,
        events,
        sandbox_id,
        vcpus,
        agent_sock,
        sandbox,
        // `None` rather than an empty chain, so with no tools asked for the
        // hooks stay a null check.
        plugin: if tools.is_empty() {
            None
        } else {
            Some(Arc::new(tools))
        },
    };
    eprintln!("booting {kernel_path} with {mem_mib} MiB ...");
    let stop = machine::boot(cfg)?;
    eprintln!("guest stopped: {stop:?}");
    Ok(())
}

fn main() {
    #[cfg(any(
        all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
        all(target_arch = "x86_64", target_os = "linux")
    ))]
    {
        if let Err(e) = run() {
            eprintln!("hvi: {e}");
            std::process::exit(1);
        }
    }

    #[cfg(not(any(
        all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
        all(target_arch = "x86_64", target_os = "linux")
    )))]
    {
        eprintln!(
            "hvi targets aarch64 (macOS Hypervisor.framework or Linux KVM) or \
             x86-64 (Linux KVM); nothing to run on this host."
        );
    }
}

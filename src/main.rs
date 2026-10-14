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

//! `hvi` — the VMM, as a command.
//!
//! This binary is a thin CLI over the [`hvi`] library: it parses flags, reads
//! the kernel, and hands a [`hvi::config::BootConfig`] to the active backend.
//! Everything of substance lives in the library, because the VMM is meant to be
//! linked as well as run.
//!
//! `--dump-memory` and `--trace-io` attach the tools in
//! [`hvi::plugin::builtin`] through the seam in [`hvi::plugin`]; with neither,
//! nothing is attached and no guest memory is read for any purpose but running
//! the guest. Another crate can link this one and supply its own
//! [`hvi::plugin::Plugin`] the same way; see `docs/plugins.md`.

// Share paths given on the command line are resolved once, before any
// guest runs; see clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::io::Write;
use std::sync::Arc;

use hvi::config;
use hvi::devices::virtio::tap;
use hvi::plugin::builtin::{Chain, IoTrace, MemoryDump};
use hvi::signal::StopOnSignals;

#[cfg(target_arch = "aarch64")]
use hvi::arch::aarch64::{fdt, layout, loader};

/// Runs the subcommand named on the command line.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("boot") => boot_guest(&args[2..]),
        Some("--version" | "-V" | "version") => {
            print_version();
            Ok(())
        }
        Some("checkpoint-verify") => {
            let dir = args
                .get(2)
                .ok_or("checkpoint-verify needs the bundle directory")?;
            let verified = hvi::checkpoint::bundle::verify(std::path::Path::new(dir))
                .map_err(|e| format!("{dir}: {e}"))?;
            println!("{verified}");
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
                let bad = hvi::sandbox::seatbelt::selftest()?;
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
            #[cfg(target_os = "linux")]
            {
                let bad = hvi::sandbox::seccomp::selftest()?;
                if bad > 0 {
                    return Err(format!(
                        "{bad} seccomp probe(s) did not behave as the filters say they should"
                    )
                    .into());
                }
                println!("seccomp selftest: every probe matched the filters");
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("`seccomp-selftest` exercises seccomp-bpf; Linux only".into())
            }
        }
        Some("smoke") => {
            #[cfg(target_os = "macos")]
            {
                // `--shm` runs the same test over shared guest memory (the
                // mechanism an out-of-process plugin needs on macOS).
                if args.get(2).map(String::as_str) == Some("--shm") {
                    hvi::arch::aarch64::smoke::run_shm()
                } else {
                    hvi::arch::aarch64::smoke::run()
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err("`smoke` (the Hypervisor.framework test) is macOS only".into())
            }
        }
        // Child half of `smoke --shm`: reads the shared object by name from a
        // process that never touched the hypervisor.
        Some("smoke-shm-verify") => {
            #[cfg(target_os = "macos")]
            {
                let name = args.get(2).ok_or("smoke-shm-verify needs a shm name")?;
                let expect = args
                    .get(3)
                    .ok_or("smoke-shm-verify needs an expected value")?;
                let expect = u64::from_str_radix(expect.trim_start_matches("0x"), 16)?;
                hvi::arch::aarch64::smoke::verify_shm(name, expect)
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err("`smoke-shm-verify` is macOS only".into())
            }
        }
        None => {
            eprintln!(
                "hvi — a microVMM\n\nusage: hvi <boot|checkpoint-verify|dump-fdt|smoke|\
                 sandbox-selftest|seccomp-selftest|--version> [args]"
            );
            Ok(())
        }
        Some(other) => Err(format!(
            "unknown subcommand {other:?}; expected `boot`, `checkpoint-verify`, `dump-fdt`, \
             `smoke`, `sandbox-selftest`, `seccomp-selftest` or `--version`"
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

/// Runs `dump-fdt`, which reads the kernel header, computes the guest layout,
/// builds the DTB and prints the layout.
///
/// `dump-fdt --kernel <Image> [--initramfs <cpio>] [--mem-mib N] [--cmdline S]
/// [--out <file>]`. `--out` also writes the blob. Pure, no hypervisor, so it
/// runs on any arm64 host.
#[cfg(target_arch = "aarch64")]
fn dump_fdt(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use layout::GicLayout;

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
    let initrd_size = match &initramfs {
        Some(p) => std::fs::metadata(p)?.len(),
        None => 0,
    };

    let ram_size = mem_mib << 20;
    let gic = GicLayout::QEMU_VIRT;
    let kernel = loader::LoadedKernel::from_header(&kernel_bytes)?;
    let loader::Plan { layout, dtb } = kernel.plan(
        ram_size,
        initrd_size,
        &gic,
        1,
        &cmdline,
        fdt::VirtioDevices::default(),
    )?;

    println!(
        "kernel {kernel_path}: kernel@{:#x} reserved_size={:#x} (file {} bytes)",
        kernel.addr,
        kernel.size,
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

/// Runs `boot`, which starts a Linux guest on the active backend (hvf/arm64 on
/// macOS, KVM/arm64 or KVM/x86-64 on Linux).
///
/// `boot --kernel <Image|bzImage|vmlinux> [flags]`. `--dump-memory <path>`
/// writes guest RAM on the interrupt key (or after `--dump-after <secs>`);
/// `--trace-io <path>` logs every virtio request.
fn boot_guest(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = None;
    let mut initramfs = None;
    let mut mem_mib: u64 = 512;
    let mut cmdline = String::from("earlycon console=ttyAMA0 panic=-1");
    let mut disk = None;
    let mut fs_uid: u32 = 0;
    let mut fs_gid: u32 = 0;
    let mut fs_shares: Vec<config::FsShare> = Vec::new();
    // The `--share-ro`/`--share-rw` exports, which `--fs-uid`/`--fs-gid` apply
    // to.
    let mut legacy_shares: Vec<usize> = Vec::new();
    let mut fs: Vec<config::FsConfig> = Vec::new();
    let mut net = false;
    let mut net_gateway = None;
    let mut net_tap = None;
    let mut net_mac = None;
    let mut events = None;
    let mut sandbox_id = String::from("hvi");
    let mut vcpus: u32 = 1;
    let mut agent_sock = None;
    let mut profile_out = None;
    let mut control_sock = None;
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
            // The old names of `uid=` and `gid=` on an `--fs path=` export.
            // They apply to every `--share-ro`/`--share-rw` export, which is
            // what they did when the identity was one per process. Kept
            // working, with one line saying where they went.
            "--fs-uid" | "--fs-gid" => {
                let key = &a[5..];
                if cfg!(target_os = "macos") {
                    eprintln!(
                        "[hvi] note: {a} is now {key}= on each --fs export; \
                         the old flag applies to --share-ro/--share-rw exports only"
                    );
                } else {
                    eprintln!(
                        "[hvi] note: {a} has no effect on Linux; the daemon decides \
                         ownership (virtiofsd: --translate-{key})"
                    );
                }
                let id = it
                    .next()
                    .ok_or_else(|| format!("{a} needs a value"))?
                    .parse()?;
                if a == "--fs-uid" {
                    fs_uid = id;
                } else {
                    fs_gid = id;
                }
            }
            // The old form of `--fs tag=<tag>,path=<dir>[,readonly=on]`. Kept
            // working on macOS, with one line saying where it went. The Linux
            // backends refuse it, and their refusal names the `socket=` form.
            "--share-ro" | "--share-rw" => {
                if cfg!(target_os = "macos") {
                    eprintln!(
                        "[hvi] note: {a} <dir> <tag> is now --fs tag=<tag>,path=<dir>{}; \
                         the old form still works",
                        if a == "--share-ro" {
                            ",readonly=on"
                        } else {
                            ""
                        }
                    );
                }
                let mode = if a == "--share-rw" {
                    config::ShareMode::ReadWrite
                } else {
                    config::ShareMode::ReadOnly
                };
                let path = it
                    .next()
                    .ok_or("--share-ro/--share-rw needs a host directory and tag")?;
                let tag = it
                    .next()
                    .ok_or("--share-ro/--share-rw needs a host directory and tag")?;
                if tag.is_empty() || tag.len() > 36 || tag.as_bytes().contains(&0) {
                    return Err("virtio-fs tag must be 1..=36 bytes and contain no NUL".into());
                }
                if tag_taken(&fs_shares, &fs, tag) {
                    return Err(format!("duplicate virtio-fs tag {tag:?}").into());
                }
                // An optional trailing `cache=auto|always|none`; any other
                // token is the next flag and is left to the outer loop.
                let mut cache = config::CachePolicy::Auto;
                if let Some(spec) = it.clone().next().and_then(|s| s.strip_prefix("cache=")) {
                    cache = match spec {
                        "auto" => config::CachePolicy::Auto,
                        "always" => config::CachePolicy::Always,
                        "none" => config::CachePolicy::None,
                        other => {
                            return Err(format!(
                                "unknown cache policy {other:?}; expected auto, always or none"
                            )
                            .into())
                        }
                    };
                    it.next();
                }
                fs_shares.push(config::FsShare {
                    path: export_dir(std::path::Path::new(path))?,
                    tag: tag.clone(),
                    mode,
                    cache,
                    uid: 0,
                    gid: 0,
                });
                legacy_shares.push(fs_shares.len() - 1);
            }
            // One virtio-fs export. `socket=` is Cloud Hypervisor's form, for a
            // daemon the caller runs, which decides what it serves and whether
            // the guest may write it. `path=` is a directory hvi serves itself.
            "--fs" => {
                let spec = it
                    .next()
                    .ok_or_else(|| format!("--fs needs {}", config::FsSpec::SYNTAX))?;
                match config::FsSpec::parse(spec)? {
                    config::FsSpec::Share(mut share) => {
                        if tag_taken(&fs_shares, &fs, &share.tag) {
                            return Err(format!("duplicate virtio-fs tag {:?}", share.tag).into());
                        }
                        share.path = export_dir(&share.path)?;
                        fs_shares.push(share);
                    }
                    config::FsSpec::Socket(socket) => {
                        if tag_taken(&fs_shares, &fs, &socket.tag) {
                            return Err(format!("duplicate virtio-fs tag {:?}", socket.tag).into());
                        }
                        fs.push(socket);
                    }
                }
            }
            "--net-stub" => net = true,
            // The old name. It read as "networking", which is what the flag
            // is not: the stack it selects forwards nothing in either
            // direction. Kept working, with one line saying where it went.
            "--net" => {
                eprintln!("[hvi] note: --net is now --net-stub; the old name still works");
                net = true;
            }
            "--net-gateway" => net_gateway = it.next().cloned(),
            "--net-tap" => net_tap = it.next().cloned(),
            "--net-mac" => {
                let v = it.next().ok_or("--net-mac needs a value")?;
                net_mac = Some(
                    tap::parse_mac(v)
                        .ok_or_else(|| format!("--net-mac is not a MAC address: {v}"))?,
                );
            }
            "--events" => events = it.next().cloned(),
            "--sandbox-id" => {
                sandbox_id = it.next().ok_or("--sandbox-id needs a value")?.clone();
            }
            "--cpus" => vcpus = it.next().ok_or("--cpus needs a value")?.parse()?,
            "--agent-sock" => agent_sock = it.next().cloned(),
            "--profile-out" => {
                profile_out = Some(it.next().ok_or("--profile-out needs a path")?.clone());
            }
            "--control-sock" => {
                control_sock = Some(it.next().ok_or("--control-sock needs a path")?.clone());
            }
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
    for &index in &legacy_shares {
        fs_shares[index].uid = fs_uid;
        fs_shares[index].gid = fs_gid;
    }

    // A stop signal asks the run to stop, and `finish` ends the process by it.
    let (signals, stop_registration) = StopOnSignals::new()?;
    // A fatal signal restores the terminal before it ends the process.
    hvi::terminal::restore_on_fatal_signals()?;
    let cfg = config::BootConfig {
        kernel: std::fs::read(&kernel_path)?,
        initramfs: initramfs.map(std::fs::read).transpose()?,
        mem_bytes: mem_mib << 20,
        cmdline,
        disk,
        fs_shares,
        fs,
        net,
        net_gateway,
        net_tap,
        net_mac,
        events,
        sandbox_id,
        vcpus,
        agent_sock,
        profile_out,
        control_sock,
        sandbox,
        // `None` rather than an empty chain, so without tools the hooks stay a
        // null check.
        plugin: if tools.is_empty() {
            None
        } else {
            Some(Arc::new(tools))
        },
        stop: Some(stop_registration),
    };
    eprintln!("booting {kernel_path} with {mem_mib} MiB ...");
    signals.finish(hvi::boot(cfg))
}

/// Returns whether an export given so far already carries `tag`.
fn tag_taken(shares: &[config::FsShare], sockets: &[config::FsConfig], tag: &str) -> bool {
    shares.iter().any(|share| share.tag == tag) || sockets.iter().any(|fs| fs.tag == tag)
}

/// Returns the canonical form of `path`, which an export hvi serves needs to
/// be a directory.
///
/// # Errors
///
/// Returns the path and the reason when it does not resolve or is not a
/// directory.
fn export_dir(path: &std::path::Path) -> Result<std::path::PathBuf, String> {
    let resolved = std::fs::canonicalize(path)
        .map_err(|e| format!("virtio-fs export {}: {e}", path.display()))?;
    if !resolved.is_dir() {
        return Err(format!(
            "virtio-fs export is not a directory: {}",
            resolved.display()
        ));
    }
    Ok(resolved)
}

fn main() {
    if let Err(e) = run() {
        // stderr can be a closed pipe, where `eprintln!` would panic, so a
        // failed write is ignored.
        let _ = writeln!(std::io::stderr(), "hvi: {e}");
        std::process::exit(1);
    }
}

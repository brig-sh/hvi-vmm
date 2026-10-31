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

// `boot` resolves its paths once, while the VM is built and before any guest
// request. See clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex, TryLockError};

use applevisor::prelude::{VirtualMachine, VirtualMachineConfig};

use super::gic::{
    gic_config, gic_layout, HvfIrqLine, UART_INTID, VIRTIO_NET_INTID, VIRTIO_VSOCK_INTID,
};
use super::kick::Kicker;
use super::vcpu::{run_cpu, VcpuContext};
use crate::arch::aarch64::fdt;
use crate::arch::aarch64::layout::{
    place_virtio_fs, virtio_blk_base, virtio_blk_spi, DEVICE_WINDOW_END, RAM_BASE, RTC_BASE,
    RTC_SIZE, UART_BASE, UART_SIZE, VIRTIO_NET_BASE, VIRTIO_SIZE, VIRTIO_VSOCK_BASE,
};
use crate::arch::aarch64::loader;
use crate::config::{check_export_overlap, BootConfig, Stop};
use crate::devices::irq::IrqLine;
use crate::devices::legacy::pl011::Pl011;
use crate::devices::legacy::rtc_pl031::Pl031;
use crate::devices::virtio::block;
use crate::devices::virtio::fs::fdlimit;
use crate::devices::virtio::fs::server::{self, VirtioFs};
use crate::devices::virtio::fs::worker::{run_fs_worker, Export, FsWake};
use crate::devices::virtio::net::{self, VirtioNet};
use crate::devices::virtio::vsock::{VirtioVsock, VsockBridge};
use crate::events::Ledger;
use crate::hypervisor::guest::{Disk, Guest, PluginThreads};
use crate::hypervisor::vcpus::Vcpus;
use crate::io_threads::{IoThreads, NetSource};
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
    // Refuse exports that contradict each other, for the same reason.
    check_export_overlap(&cfg.fs_shares)?;
    // This backend serves every export itself, so it refuses a daemon's socket.
    if let Some(export) = cfg.fs.first() {
        return Err(format!(
            "--fs tag={},socket=: vhost-user exports are served on Linux only; \
             use --fs tag=<tag>,path=<dir>",
            export.tag
        )
        .into());
    }
    let num_cpus = cfg.vcpus.max(1);

    let gic = gic_layout()?;
    eprintln!(
        "{LOG_PREFIX} {num_cpus} vCPU(s)  GICD {:#x}+{:#x}  GICR {:#x}+{:#x}  UART {:#x}",
        gic.gicd_base, gic.gicd_size, gic.gicr_base, gic.gicr_size, UART_BASE
    );
    // Every device window has to clear the GIC, and its end is known only here:
    // the framework sizes the redistributor region, and it is far larger than
    // QEMU's. The fixed windows are checked here, and the virtio-fs ones below
    // as each share is placed, because those climb with the share count.
    let gic_end = gic.gicr_base.saturating_add(gic.gicr_size);
    let disk_windows = (0..cfg.disks.len())
        .filter_map(virtio_blk_base)
        .map(|base| ("virtio-blk", base, VIRTIO_SIZE));
    for (name, base, size) in [
        ("UART", UART_BASE, UART_SIZE),
        ("RTC", RTC_BASE, RTC_SIZE),
        ("virtio-net", VIRTIO_NET_BASE, VIRTIO_SIZE),
        ("virtio-vsock", VIRTIO_VSOCK_BASE, VIRTIO_SIZE),
    ]
    .into_iter()
    .chain(disk_windows)
    {
        let end = base.saturating_add(size);
        if base < gic_end || end > DEVICE_WINDOW_END {
            return Err(format!(
                "{name} at {base:#x}..{end:#x} does not fit between the GIC \
                 (ends {gic_end:#x}) and {DEVICE_WINDOW_END:#x}"
            )
            .into());
        }
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

    let disks = Disk::place(block::open_disks(&cfg.disks)?, virtio_blk_base);
    // virtio-net: gateway relay (real egress) when a gateway socket is given,
    // else the built-in user-space stack. `net_reader` carries the gateway read
    // side to the RX reader thread, which starts with the other I/O threads.
    //
    // Tap attach needs /dev/net/tun, which macOS does not have. The flag is
    // refused, because a guest on the wrong network looks like success from the
    // outside.
    if let Some(ifname) = &cfg.net_tap {
        return Err(
            format!("--net-tap {ifname}: no /dev/net/tun on macOS; use --net-gateway").into(),
        );
    }
    let mut net_reader: Option<std::os::unix::net::UnixStream> = None;
    let net_dev = if let Some(sock) = &cfg.net_gateway {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(stream) => match stream.try_clone() {
                Ok(reader) => {
                    eprintln!("{LOG_PREFIX} virtio-net: gvisor-tap gateway relay via {sock} (guest 10.87.0.2, gw/DNS 10.87.0.1)");
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

    let vsock = cfg.agent_sock.as_ref().map(|sock| {
        eprintln!("{LOG_PREFIX} virtio-vsock: agent bridge on {sock} (guest cid 3, port 1024)");
        Arc::new(Mutex::new(VirtioVsock::new()))
    });
    // Bind before Seatbelt is installed. Accepting on this already-open
    // listener remains allowed afterwards; acquiring a new socket does not.
    let bridge = match (&cfg.agent_sock, &vsock) {
        (Some(path), Some(dev)) => {
            Some(VsockBridge::bind(path, Arc::clone(dev), Arc::clone(&ram))?)
        }
        _ => None,
    };
    // The stop source's socket pair is created before Seatbelt for the same
    // reason.
    let stop_source = StopSource::new()?;
    let mut fs = Vec::with_capacity(cfg.fs_shares.len());
    let mut fs_access = Vec::with_capacity(cfg.fs_shares.len());
    let mut fs_tags = std::collections::HashSet::new();
    for (index, share) in cfg.fs_shares.iter().enumerate() {
        if !fs_tags.insert(share.tag.as_str()) {
            return Err(format!("duplicate virtio-fs tag {:?}", share.tag).into());
        }
        // The same two bounds as the fixed windows above.
        let (base, spi) = place_virtio_fs(index, &gic, None)?;
        let root = std::fs::canonicalize(&share.path)?;
        let access = if share.mode.writable() {
            "read-write"
        } else {
            "read-only"
        };
        // Raise the descriptor limit before the first share exists, and log the
        // result. virtio-fs pins one host descriptor per open guest handle.
        // macOS gives a process launched outside a terminal 256, which a build
        // inside the guest exhausts, and the guest then sees I/O errors on
        // unrelated files.
        if index == 0 {
            match fdlimit::raise_open_file_limit() {
                Ok(limit) => eprintln!("{LOG_PREFIX} open-file limit: {limit}"),
                Err(e) => eprintln!(
                    "{LOG_PREFIX} open-file limit: could not raise it ({e}); \
                     a busy guest may see EMFILE as I/O errors"
                ),
            }
        }
        eprintln!(
            "{LOG_PREFIX} virtio-fs[{index}]: {} as {:?} ({access})",
            root.display(),
            share.tag
        );
        fs_access.push((root.clone(), share.mode.writable()));
        fs.push(Export {
            base,
            intid: 32 + spi,
            dev: Arc::new(Mutex::new({
                let mut dev = VirtioFs::new(root, &share.tag, share.mode.writable(), share.cache)?;
                dev.set_guest_ids(server::GuestIds {
                    uid: share.uid,
                    gid: share.gid,
                });
                dev
            })),
            wake: Arc::new(FsWake::new()),
        });
    }
    let has_net = net.is_some();
    let has_vsock = vsock.is_some();
    let fdt_devices = fdt::VirtioDevices {
        blk_count: disks.len(),
        net: has_net,
        vsock: has_vsock,
        fs_count: fs.len(),
    };

    let ledger = Ledger::new(cfg.events.as_deref(), &cfg.sandbox_id)?;
    if ledger.is_enabled() {
        eprintln!(
            "{LOG_PREFIX} event ledger: {}",
            cfg.events.as_deref().unwrap_or("")
        );
    }

    let layout = loader::Payload {
        kernel: &cfg.kernel,
        initramfs: cfg.initramfs.as_deref(),
        cmdline: &cfg.cmdline,
    }
    .load(ram.memory(), cfg.mem_bytes, &gic, num_cpus, fdt_devices)?;

    let kicker = Kicker::new(vm.clone(), num_cpus);

    let context = VcpuContext {
        vm: vm.clone(),
        guest: Arc::new(Guest {
            arch: GuestArch::Aarch64,
            sandbox_id: cfg.sandbox_id.clone(),
            ram,
            shared_ram,
            ledger: Arc::new(ledger),
            disks,
            net,
            vsock,
            vcpus: Arc::new(Vcpus::new(num_cpus, kicker, cfg.take_stop_handle()?)),
            plugin_threads: PluginThreads::new(),
        }),
        pl011: Arc::new(Mutex::new(Pl011::new())),
        rtc: Arc::new(Mutex::new(Pl031::new())),
        fs,
        kernel_addr: layout.kernel_addr,
        dtb_addr: layout.dtb_addr,
        plugin: cfg.plugin.clone(),
    };

    let line = |intid, kick: bool| -> Arc<dyn IrqLine> {
        Arc::new(HvfIrqLine::new(
            vm.clone(),
            intid,
            kick.then(|| Arc::clone(&context.guest.vcpus)),
        ))
    };
    context
        .pl011
        .lock()
        .unwrap()
        .connect_irq(line(UART_INTID, false));
    context.guest.connect_irqs(
        // `open_disks` refused more disks than there are SPIs.
        |index| {
            line(
                32 + virtio_blk_spi(index).expect("every disk should have an SPI"),
                true,
            )
        },
        line(VIRTIO_NET_INTID, true),
        line(VIRTIO_VSOCK_INTID, true),
    );
    for fs in &context.fs {
        fs.dev.lock().unwrap().connect_irq(line(fs.intid, true));
    }

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
        seatbelt::enter_with_shares(&fs_access)
            .map_err(|e| format!("{e}; re-run with --no-sandbox to boot unconfined"))?;
        stderrln!("{LOG_PREFIX} seatbelt: on (deny default)");
    } else {
        stderrln!("{LOG_PREFIX} seatbelt: OFF (--no-sandbox); the VMM keeps full host authority");
    }

    // The I/O threads, which are joined after the vCPUs. `teardown` describes
    // the stop.
    install_kick_handler();
    let mut io_threads = IoThreads::start(
        stop_source,
        &context.guest,
        context.plugin.clone(),
        {
            let pl011 = Arc::clone(&context.pl011);
            move |byte| pl011.lock().unwrap().push_rx(byte)
        },
        bridge,
        net_reader.map(NetSource::Gateway),
        plugin_threads,
    );
    // Each virtio-fs device gets its own worker thread, which serves the
    // requests a vCPU leaves past its inline budget. See `run_fs_worker`.
    for fs in &context.fs {
        let (dev, ram, wake) = (
            Arc::clone(&fs.dev),
            Arc::clone(&context.guest.ram),
            Arc::clone(&fs.wake),
        );
        io_threads.spawn("virtio-fs worker", move |_| {
            run_fs_worker(&dev, &ram, &wake);
        });
        let wake = Arc::clone(&fs.wake);
        io_threads.on_stop(move || wake.stop());
        let (workers, stop) = fs.dev.lock().unwrap().readahead_workers();
        for worker in workers {
            io_threads.spawn("virtio-fs readahead", move |_| worker());
        }
        io_threads.on_stop(move || stop.stop());
    }

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
    for (index, fs) in context.fs.iter().enumerate() {
        report_fs_usage(index, &fs.dev);
    }

    // `boot` keeps the run's claim when it sees a `LeftRunning` error, so the
    // error goes back as `run_to_stop` returned it.
    result
}

/// Prints the peak handle count, the operation counts and times, and the
/// readahead counts of virtio-fs device `index`.
///
/// A worker left running at the stop deadline can still hold the device, stuck
/// in a host call, so the lock is only tried. When the device is held, or a
/// panic poisoned its lock, one line says so and the statistics are skipped.
fn report_fs_usage(index: usize, dev: &Mutex<VirtioFs>) {
    let dev = match dev.try_lock() {
        Ok(dev) => dev,
        Err(TryLockError::Poisoned(_)) => {
            stderrln!("{LOG_PREFIX} virtio-fs[{index}]: statistics skipped after a panic");
            return;
        }
        Err(TryLockError::WouldBlock) => {
            stderrln!(
                "{LOG_PREFIX} virtio-fs[{index}]: statistics skipped, the device is still in use"
            );
            return;
        }
    };
    stderrln!(
        "{LOG_PREFIX} virtio-fs[{index}]: peak {} of {} guest handles",
        dev.peak_handles(),
        dev.handle_limit()
    );
    let hist: Vec<String> = dev
        .op_stats()
        .into_iter()
        .map(|(o, c, n)| {
            format!(
                "{}({})={}/{:.1}ms",
                server::opcode_name(o),
                o,
                c,
                n as f64 / 1e6
            )
        })
        .collect();
    stderrln!("{LOG_PREFIX} virtio-fs[{index}] ops: {}", hist.join(" "));
    let (hits, waits, misses) = dev.readahead_stats();
    stderrln!(
        "{LOG_PREFIX} virtio-fs[{index}] readahead: hits={hits} waits={waits} misses={misses}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CachePolicy;
    use std::time::{Duration, Instant};

    // A worker stuck in a host call holds the device past the stop deadline.
    // The report must not wait for it, or `boot` never returns the error that
    // names the worker.
    #[test]
    fn report_fs_usage_skips_a_device_another_thread_holds() {
        let dir = std::env::temp_dir().join(format!("hvi-fs-usage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();
        let dev = Arc::new(Mutex::new(
            VirtioFs::new(root, "share", false, CachePolicy::Auto).unwrap(),
        ));
        let (held, holding) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let worker = {
            let dev = Arc::clone(&dev);
            std::thread::spawn(move || {
                let _device = dev.lock().unwrap();
                held.send(()).unwrap();
                let _ = released.recv();
            })
        };
        holding.recv().unwrap();
        let report = {
            let dev = Arc::clone(&dev);
            std::thread::spawn(move || report_fs_usage(0, &dev))
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        while !report.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let finished = report.is_finished();
        release.send(()).unwrap();
        worker.join().unwrap();
        report.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(finished, "the report waited for the device");
    }
}

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

//! A complete, minimal hvi extension: counts device I/O, and once a second
//! records where the boot vCPU is.
//!
//! This is the smallest thing that uses every rule a real plugin has to follow,
//! so it is the file to copy from rather than the two in `src/plugins.rs`,
//! which are bigger because they do something useful.
//!
//! Build and run it (macOS / Apple silicon shown; re-sign after every build):
//!
//! ```sh
//! cargo build --release --example watch_guest
//! codesign --sign - --entitlements hvi.entitlements --force \
//!          --options runtime target/release/examples/watch_guest
//! target/release/examples/watch_guest <kernel> [initramfs]
//! ```
//!
//! On Linux the signing step does not apply; the binary needs `/dev/kvm`.
//!
//! The four rules it demonstrates are the four that fail quietly:
//!
//! 1. `safepoint` runs between guest entries, so the nothing-to-do case is one
//!    atomic load and a return.
//! 2. A `pause()` that returns `true` owes exactly one `resume()`, on *every*
//!    path out -- including the error paths.
//! 3. A thread of your own sets its flag and *then* calls
//!    [`VmHandle::kick`](hvi::plugin::VmHandle::kick). An idle guest sits in
//!    WFI or HLT and never reaches `safepoint` on its own.
//! 4. An [`IoSink`](hvi::plugin::IoSink) is called from the vCPU thread with
//!    the device lock held, so it must not block. Count in the sink; do the
//!    writing at the safe point.

#[cfg(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
))]
mod watcher {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    use hvi::config::BootConfig;
    use hvi::plugin::{CpuHandle, IoSink, Plugin, VmHandle};

    /// Counts what crosses the devices. Shared with the vCPU thread, so every
    /// field is an atomic and no method takes a lock.
    #[derive(Default)]
    struct Counters {
        block_requests: AtomicU64,
        block_bytes: AtomicU64,
        net_frames: AtomicU64,
    }

    /// Rule 4: called from the vCPU thread with the device lock held. Two
    /// relaxed adds and nothing else -- no allocation, no `write(2)`, no lock.
    impl IoSink for Counters {
        fn block(&self, _sector: u64, length: u64, _disk_id: u64, _write: bool) {
            self.block_requests.fetch_add(1, Ordering::Relaxed);
            self.block_bytes.fetch_add(length, Ordering::Relaxed);
        }

        fn net(&self, frame: &[u8], _egress: bool) {
            let _ = frame;
            self.net_frames.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// What this plugin writes into the ledger, once per sample.
    #[derive(serde::Serialize)]
    struct Sample {
        pc: u64,
        block_requests: u64,
        block_bytes: u64,
        net_frames: u64,
    }

    pub struct WatchGuest {
        counters: Arc<Counters>,
        /// Set by the timer thread, consumed at the next safe point.
        pending: Arc<AtomicBool>,
    }

    impl WatchGuest {
        pub fn new() -> Self {
            WatchGuest {
                counters: Arc::new(Counters::default()),
                pending: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl Plugin for WatchGuest {
        /// Called once, before any vCPU runs.
        fn attach(&self, vmm: Arc<dyn VmHandle>) -> std::io::Result<()> {
            eprintln!(
                "[watch] attached to sandbox {:?}, guest arch {:?}, {} RAM region(s)",
                vmm.sandbox_id(),
                vmm.arch(),
                vmm.ram_regions().len()
            );

            // Installing a sink on a device that is not there is a no-op, so
            // asking first is only to keep the log honest.
            if vmm.has_block() {
                vmm.set_block_sink(Arc::clone(&self.counters) as Arc<dyn IoSink>);
            }
            if vmm.has_net() {
                vmm.set_net_sink(Arc::clone(&self.counters) as Arc<dyn IoSink>);
            }

            // Rule 3: flag, then kick. Reversing these two lines is the bug
            // that only shows up against an idle guest.
            let pending = Arc::clone(&self.pending);
            let vmm = Arc::clone(&vmm);
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                pending.store(true, Ordering::SeqCst);
                vmm.kick();
            });
            Ok(())
        }

        /// Called on the boot vCPU between guest entries.
        fn safepoint(&self, cpu: &dyn CpuHandle) {
            // Rule 1: the hot path is one atomic swap and a return.
            if !self.pending.swap(false, Ordering::SeqCst) {
                return;
            }

            // Rule 2: from here to the matching resume(), every path out owes
            // exactly one resume() -- so take it before anything that can fail.
            if !cpu.pause() {
                // A failed pause has already released the quiesce. Nothing
                // owed.
                return;
            }
            let sample = Sample {
                pc: cpu.regs().pc,
                block_requests: self.counters.block_requests.load(Ordering::Relaxed),
                block_bytes: self.counters.block_bytes.load(Ordering::Relaxed),
                net_frames: self.counters.net_frames.load(Ordering::Relaxed),
            };
            cpu.resume();

            // Deliberately after the resume: the guest does not need to stay
            // parked while a record is serialised and written.
            if let Ok(mut ledger) = cpu.ledger().lock() {
                ledger.emit_payload("boundary", "watch-guest", &sample);
            }
            eprintln!(
                "[watch] pc={:#x} blk={} ({} bytes) net={}",
                sample.pc, sample.block_requests, sample.block_bytes, sample.net_frames
            );
        }

        /// The console's interrupt key (Ctrl-]) reached us. Same flag; the VMM
        /// is already at a safe point, so this one needs no kick.
        fn request(&self) {
            self.pending.store(true, Ordering::SeqCst);
        }
    }

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = std::env::args().collect();
        let Some(kernel) = args.get(1) else {
            return Err(format!("usage: {} <kernel> [initramfs]", args[0]).into());
        };

        let cfg = BootConfig {
            kernel: std::fs::read(kernel)?,
            initramfs: args.get(2).map(std::fs::read).transpose()?,
            mem_bytes: 512 << 20,
            cmdline: String::from("earlycon console=ttyAMA0 panic=-1"),
            disk: None,
            fs_shares: Vec::new(),
            net: true,
            net_gateway: None,
            net_tap: None,
            net_mac: None,
            events: None,
            sandbox_id: String::from("watch-guest"),
            vcpus: 1,
            agent_sock: None,
            plugin: Some(Arc::new(WatchGuest::new())),
            sandbox: true,
        };

        let stop = hvi::machine::boot(cfg)?;
        eprintln!("[watch] guest stopped: {stop:?}");
        Ok(())
    }
}

#[cfg(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
))]
fn main() {
    if let Err(e) = watcher::main() {
        eprintln!("watch_guest: {e}");
        std::process::exit(1);
    }
}

// hvi compiles to a backend-less stub on every other host, so this example has
// no `machine::boot` to call there. It still has to build, because
// `cargo clippy --all-targets` reaches examples on every target CI lints.
#[cfg(not(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
)))]
fn main() {
    eprintln!("watch_guest needs a host with a VMM backend: aarch64 macOS/Linux, or x86-64 Linux.");
}

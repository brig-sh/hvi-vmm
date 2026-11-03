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

//! The exports of the macOS virtio-fs devices, as [`attach`] builds them.
//!
//! Each device has a worker thread, which serves the requests a vCPU leaves
//! past its inline budget, a wake signal the worker parks on, and a transport
//! on the bus.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, TryLockError};
use std::time::{Duration, Instant};

use super::fdlimit;
use super::server::{self, VirtioFs};
use crate::config::{FsShare, Stop};
use crate::devices::bus::{self, fill_le_bytes, u64_from_le_bytes};
use crate::devices::virtio::mmio;
use crate::io_threads::HostWork;
use crate::memory::GuestRam;
use crate::LOG_PREFIX;

/// How many virtio-fs chains a vCPU services in its own exit before handing the
/// rest to the device's worker thread.
///
/// A single guest syscall's requests stay on the vCPU, and a deep queue goes to
/// the worker.
const FS_INLINE_BUDGET: u16 = 8;

/// One virtio-fs export as the macOS backend wires it.
pub(crate) struct Export {
    /// The device behind the transport.
    pub(crate) dev: Arc<Mutex<VirtioFs>>,
    /// The wake signal of the device's worker thread.
    pub(crate) wake: Arc<FsWake>,
    /// The host directory the device serves.
    pub(crate) root: PathBuf,
    /// Whether the guest may write it.
    pub(crate) writable: bool,
}

/// Builds an export for each of `shares`, in order.
///
/// The open-file limit is raised before the first export, since an export holds
/// a host descriptor for each handle the guest has open. macOS gives a process
/// launched outside a terminal 256, which a build inside the guest exhausts,
/// and the guest then sees I/O errors on unrelated files.
///
/// # Errors
///
/// Errors if a share's directory does not resolve, or its device cannot be
/// made.
// An export's root is resolved once, before any guest request; see clippy.toml.
#[allow(clippy::disallowed_methods)]
pub(crate) fn attach(shares: &[FsShare]) -> io::Result<Vec<Export>> {
    if !shares.is_empty() {
        match fdlimit::raise_open_file_limit() {
            Ok(limit) => eprintln!("{LOG_PREFIX} open-file limit: {limit}"),
            Err(e) => eprintln!(
                "{LOG_PREFIX} open-file limit: could not raise it ({e}); \
                 a busy guest may see EMFILE as I/O errors"
            ),
        }
    }
    let mut exports = Vec::with_capacity(shares.len());
    for (index, share) in shares.iter().enumerate() {
        let root = std::fs::canonicalize(&share.path)?;
        let writable = share.mode.writable();
        eprintln!(
            "{LOG_PREFIX} virtio-fs[{index}]: {} as {:?} ({})",
            root.display(),
            share.tag,
            if writable { "read-write" } else { "read-only" }
        );
        let mut dev = VirtioFs::new(root.clone(), &share.tag, writable, share.cache)?;
        dev.set_guest_ids(server::GuestIds {
            uid: share.uid,
            gid: share.gid,
        });
        exports.push(Export {
            dev: Arc::new(Mutex::new(dev)),
            wake: Arc::new(FsWake::new()),
            root,
            writable,
        });
    }
    Ok(exports)
}

impl Export {
    /// Queues in `host` the device's worker thread and its readahead workers,
    /// with the stop actions that end them.
    ///
    /// The worker serves the requests a vCPU leaves past its inline budget; see
    /// [`run_fs_worker`]. Its queues are in `ram`.
    pub(crate) fn queue_threads(&self, ram: &Arc<GuestRam>, host: &mut HostWork) {
        let (dev, ram, wake) = (
            Arc::clone(&self.dev),
            Arc::clone(ram),
            Arc::clone(&self.wake),
        );
        host.spawn("virtio-fs worker", move |_| {
            run_fs_worker(&dev, &ram, &wake)
        });
        let wake = Arc::clone(&self.wake);
        host.on_io_stop(move || wake.stop());
        let (workers, stop) = self.dev.lock().unwrap().readahead_workers();
        for worker in workers {
            host.spawn("virtio-fs readahead", move |_| worker());
        }
        host.on_io_stop(move || stop.stop());
    }

    /// Prints the peak handle count, the operation counts and times, and the
    /// readahead counts of the device, as export `index`.
    ///
    /// A worker left running at the stop deadline can still hold the device,
    /// stuck in a host call, so the lock is only tried. When the device is
    /// held, or a panic poisoned its lock, one line says so and the statistics
    /// are skipped.
    pub(crate) fn report_usage(&self, index: usize) {
        let dev = match self.dev.try_lock() {
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
}

/// A virtio-fs device as a bus reaches it, with what a register access needs
/// beyond the device.
pub(crate) struct FsTransport {
    /// The device.
    device: Arc<Mutex<VirtioFs>>,
    /// The wake signal of the device's worker thread.
    wake: Arc<FsWake>,
    /// The guest RAM its queues are in.
    ram: Arc<GuestRam>,
}

impl FsTransport {
    /// Returns the transport of `export`.
    pub(crate) fn new(export: &Export, ram: &Arc<GuestRam>) -> Self {
        Self {
            device: Arc::clone(&export.dev),
            wake: Arc::clone(&export.wake),
            ram: Arc::clone(ram),
        }
    }
}

impl bus::Device for FsTransport {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let value = self
            .device
            .lock()
            .unwrap()
            .mmio(&self.ram, offset, false, 0);
        fill_le_bytes(data, value);
    }

    /// Applies the write, and on a `QUEUE_NOTIFY` serves a shallow queue at
    /// once and wakes the device's worker thread, `run_fs_worker`, for the
    /// rest.
    ///
    /// `mmio` only records the queue index of a notify. Waking the worker takes
    /// longer than the host work of a small request, and a deep queue goes to
    /// the worker so the vCPU can run the guest while the worker drains it. The
    /// vCPU is held for the host calls the shallow queue's requests make, so no
    /// request may make one that blocks.
    fn write(&self, offset: u64, data: &[u8]) -> Option<Stop> {
        let remaining = {
            let mut device = self.device.lock().unwrap();
            device.mmio(&self.ram, offset, true, u64_from_le_bytes(data));
            offset == mmio::QUEUE_NOTIFY
                && device.drain_notified_bounded(&self.ram, FS_INLINE_BUDGET)
        };
        if remaining {
            self.wake.wake();
        }
        None
    }
}

/// A virtio-fs device's coalescing wake signal, which its worker thread parks
/// on.
///
/// [`FsWake::park`] checks a predicate under a `Condvar`, so a wake that lands
/// between the worker's last drain and its park is seen. [`run_fs_worker`] has
/// the full argument.
pub(crate) struct FsWake {
    /// The wake and stop flags.
    state: Mutex<FsWakeState>,
    /// The condition variable notified when the flags change.
    ready: Condvar,
}

/// The flags behind [`FsWake`].
#[derive(Default)]
struct FsWakeState {
    /// Whether a notify arrived since the worker last drained.
    woken: bool,
    /// Whether the stop has been requested.
    stopped: bool,
}

impl FsWake {
    /// Returns a signal with no wake or stop pending.
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(FsWakeState::default()),
            ready: Condvar::new(),
        }
    }

    /// Signals the worker.
    ///
    /// It can be called whether or not the worker is parked. The worker picks
    /// up a signal that arrives mid-drain on its next pass.
    pub(crate) fn wake(&self) {
        let mut state = self.state.lock().unwrap();
        state.woken = true;
        self.ready.notify_one();
    }

    /// Requests that the worker exit at its next pass.
    pub(crate) fn stop(&self) {
        let mut state = self.state.lock().unwrap();
        state.stopped = true;
        self.ready.notify_one();
    }

    /// Blocks until the next [`FsWake::wake`] or [`FsWake::stop`].
    ///
    /// Clears the wake flag on return and returns `false` once stopped. Must
    /// not be called with the virtio-fs device mutex held.
    fn park(&self) -> bool {
        self.park_until(None)
    }

    /// Blocks like [`FsWake::park`], and also returns at `timeout`, as if
    /// woken.
    fn park_for(&self, timeout: Duration) -> bool {
        self.park_until(Some(Instant::now() + timeout))
    }

    /// Blocks like [`FsWake::park`], and also returns at `deadline`, if any.
    fn park_until(&self, deadline: Option<Instant>) -> bool {
        let mut state = self.state.lock().unwrap();
        while !state.woken && !state.stopped {
            match deadline {
                None => state = self.ready.wait(state).unwrap(),
                Some(deadline) => {
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                        break;
                    };
                    state = self.ready.wait_timeout(state, left).unwrap().0;
                }
            }
        }
        state.woken = false;
        !state.stopped
    }
}

/// How often the worker retries the SETLKW requests parked on the device
/// (`LockWaiter` in the server), while any is parked.
///
/// A guest holder's unlock retries them in its own drain, so this only bounds
/// the wait on a lock a host process holds. A tick costs one non-blocking lock
/// call per waiter.
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// Runs a virtio-fs device's FUSE servicing on the calling thread, the device's
/// worker thread.
///
/// It makes every host syscall the requests it drains need, so a deep queue
/// never holds a vCPU on the host filesystem, and the guest can keep more than
/// one request in flight. A lock another holder has parks its request on the
/// device instead of blocking, and this thread retries the parked ones every
/// `LOCK_RETRY_INTERVAL` until none is left.
///
/// Each device has one worker, since a single mutex guards all of its
/// `VirtioFs` state. A pass under that mutex raises the line and kicks the
/// vCPUs at most once, however many requests it served.
///
/// `wake.park()` waits on a predicate and a `Condvar` (see `FsWake`). A notify
/// that races the loop is either served by the drain in progress, since both
/// sides take the device mutex, or seen by the next `park()`. The mutex is held
/// only for the drain, never across `park()`.
///
/// [`FsWake::stop`] ends the loop at the next `park`.
pub(crate) fn run_fs_worker(dev: &Mutex<VirtioFs>, mem: &GuestRam, wake: &FsWake) {
    let mut waiting = false;
    loop {
        let alive = if waiting {
            wake.park_for(LOCK_RETRY_INTERVAL)
        } else {
            wake.park()
        };
        if !alive {
            break;
        }
        let mut d = dev.lock().unwrap();
        d.drain_notified(mem);
        waiting = d.has_lock_waiters();
    }
    // A wake that arrived with the stop was cleared by that last `park`, and
    // the chains it announced are still in the ring, so one unbounded pass
    // drains them. A vCPU left running at its join deadline that is still in
    // `FsTransport::write` can leave chains past its inline budget after this
    // pass, with no worker to serve them. Only a run that already fails does
    // that.
    dev.lock().unwrap().drain_notified(mem);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CachePolicy;

    // A worker stuck in a host call holds the device past the stop deadline.
    // The report must not wait for it, or `boot` never returns the error that
    // names the worker.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn usage_report_skips_a_device_another_thread_holds() {
        let dir = std::env::temp_dir().join(format!("hvi-fs-usage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();
        let export = Arc::new(Export {
            dev: Arc::new(Mutex::new(
                VirtioFs::new(root.clone(), "share", false, CachePolicy::Auto).unwrap(),
            )),
            wake: Arc::new(FsWake::new()),
            root,
            writable: false,
        });
        let (held, holding) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let worker = {
            let dev = Arc::clone(&export.dev);
            std::thread::spawn(move || {
                let _device = dev.lock().unwrap();
                held.send(()).unwrap();
                let _ = released.recv();
            })
        };
        holding.recv().unwrap();
        let report = {
            let export = Arc::clone(&export);
            std::thread::spawn(move || export.report_usage(0))
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

    #[test]
    fn timed_park_ends_at_its_deadline_or_at_a_wake_or_a_stop() {
        let wake = FsWake::new();
        let start = Instant::now();
        assert!(
            wake.park_for(Duration::from_millis(20)),
            "a deadline is not a stop"
        );
        assert!(start.elapsed() >= Duration::from_millis(20));

        wake.wake();
        let start = Instant::now();
        assert!(wake.park_for(Duration::from_secs(10)));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a pending wake ends the park at once"
        );
        assert!(!wake.state.lock().unwrap().woken, "the park took the wake");

        wake.stop();
        assert!(
            !wake.park_for(Duration::from_secs(10)),
            "a stop ends the park and says so"
        );
    }
}

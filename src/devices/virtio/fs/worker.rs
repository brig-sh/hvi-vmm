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
//! past its inline budget, and a wake the worker waits on.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, TryLockError};
use std::task::Waker;
use std::time::Duration;

use super::fdlimit;
use super::server::{self, VirtioFs};
use crate::config::FsShare;
use crate::devices::virtio::wake::WorkerWake;
use crate::io_threads::HostWork;
use crate::memory::GuestRam;
use crate::sandbox::Thread;
use crate::teardown::StopToken;
use crate::LOG_PREFIX;

/// One virtio-fs export as the macOS backend wires it.
pub(crate) struct Export {
    /// The device behind the transport.
    pub(crate) dev: Arc<Mutex<VirtioFs>>,
    /// What wakes the device's worker thread.
    pub(crate) wake: Arc<WorkerWake>,
    /// The host directory the device serves.
    pub(crate) root: PathBuf,
    /// Whether the guest may write it.
    pub(crate) writable: bool,
}

/// Builds an export for each of `shares`, in order, for a VM that has an
/// agent bridge if `agent`.
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
pub(crate) fn attach(shares: &[FsShare], agent: bool) -> io::Result<Vec<Export>> {
    // What the rest of the VM may hold beside the exports' budget.
    let reserve = fdlimit::vmm_reserve(shares.len(), agent);
    if !shares.is_empty() {
        match fdlimit::raise_open_file_limit() {
            Ok(limit) => eprintln!("{LOG_PREFIX} open-file limit: {limit}"),
            Err(e) => eprintln!(
                "{LOG_PREFIX} open-file limit: could not raise it ({e}); \
                 a busy guest may see EMFILE as I/O errors"
            ),
        }
        // Checked after the raise whether or not it worked: a process that
        // could not raise its limit is the one most likely to be short.
        let limit = fdlimit::usable_limit();
        if limit < reserve.saturating_add(fdlimit::MIN_BUDGET as u64) {
            eprintln!(
                "{LOG_PREFIX} open-file limit: {limit} leaves no room for the \
                 {reserve} the VMM holds beside the shares; the guest gets \
                 {} anyway, so a busy guest can make the host refuse the VMM",
                fdlimit::MIN_BUDGET
            );
        }
    }
    // One budget for every export: the descriptor table they draw on is the
    // process's, and one process is one VM.
    let budget = server::DescriptorBudget::new(fdlimit::guest_handle_budget(reserve));
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
        dev.join_budget(&budget);
        dev.set_guest_ids(server::GuestIds {
            uid: share.uid,
            gid: share.gid,
        });
        let wake = Arc::new(WorkerWake::new()?);
        dev.set_waker(Waker::from(Arc::clone(&wake)));
        exports.push(Export {
            dev: Arc::new(Mutex::new(dev)),
            wake,
            root,
            writable,
        });
    }
    Ok(exports)
}

impl Export {
    /// Queues in `host` the device's worker thread and its readahead workers,
    /// with the stop action that ends the readahead workers.
    ///
    /// The worker serves the requests a vCPU leaves past its inline budget; see
    /// [`run_fs_worker`]. Its queues are in `ram`.
    pub(crate) fn queue_threads(&self, ram: &Arc<GuestRam>, host: &mut HostWork) {
        let (dev, ram, wake) = (
            Arc::clone(&self.dev),
            Arc::clone(ram),
            Arc::clone(&self.wake),
        );
        host.spawn("virtio-fs worker", Thread::Vmm, move |stop| {
            run_fs_worker(&dev, &ram, &wake, &stop)
        });
        let (workers, stop) = self.dev.lock().unwrap().readahead_workers();
        for worker in workers {
            host.spawn("virtio-fs readahead", Thread::Vmm, move |_| worker());
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
            "{LOG_PREFIX} virtio-fs[{index}]: peak {} of the VM's {} guest handles",
            dev.peak_handles(),
            dev.descriptor_budget()
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
/// `VirtioFs` state.
///
/// The worker waits on `wake` (see [`WorkerWake`]). A notify that races the
/// loop is either served by the drain in progress, since both sides take the
/// device mutex, or seen by the next wait. The mutex is held only for the
/// drain, never across a wait.
///
/// A stop requested through `stop` ends the loop at the next wait.
pub(crate) fn run_fs_worker(
    dev: &Mutex<VirtioFs>,
    mem: &GuestRam,
    wake: &WorkerWake,
    stop: &StopToken,
) {
    let mut waiting = false;
    loop {
        let alive = if waiting {
            wake.wait_timeout(stop, LOCK_RETRY_INTERVAL)
        } else {
            wake.wait(stop)
        };
        if !alive {
            break;
        }
        let mut d = dev.lock().unwrap();
        d.drain_notified(mem);
        waiting = d.has_lock_waiters();
    }
    // A signal that arrived with the stop is left unserved by the loop, and the
    // chains it announced are still in the ring, so one unbounded pass drains
    // them. A vCPU left running at its join deadline that is still in the
    // device's `notify` can leave chains past its inline budget after this
    // pass, with no worker to serve them. Only a run that already fails does
    // that.
    dev.lock().unwrap().drain_notified(mem);
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

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
            wake: Arc::new(WorkerWake::new().unwrap()),
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
}

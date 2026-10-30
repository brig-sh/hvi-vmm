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

//! The worker thread of a virtio-fs device on macOS, which serves the requests
//! a vCPU leaves past its inline budget, and the wake signal it parks on.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::server::VirtioFs;
use crate::memory::GuestRam;

/// One virtio-fs export as the macOS backend wires it.
#[derive(Clone)]
pub(crate) struct Export {
    /// Guest-physical base of the transport's MMIO window.
    pub(crate) base: u64,
    /// The INTID the device raises.
    pub(crate) intid: u32,
    /// The device behind the transport.
    pub(crate) dev: Arc<Mutex<VirtioFs>>,
    /// The wake signal of the device's worker thread.
    pub(crate) wake: Arc<FsWake>,
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
    // `service_fs` can leave chains past its inline budget after this pass,
    // with no worker to serve them. Only a run that already fails does that.
    dev.lock().unwrap().drain_notified(mem);
}

#[cfg(test)]
mod tests {
    use super::*;

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

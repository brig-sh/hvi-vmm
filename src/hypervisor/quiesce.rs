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

//! Stopping every vCPU at a safe point, so an observation sees a still guest.
//!
//! Without this, reaching a safe point only guarantees that *the vCPU that
//! reached it* is out of guest context. On an SMP guest the others keep
//! executing while a reader walks memory, so it can observe a structure
//! mid-update. Nothing crashes — a reader is expected to bounds-check — but
//! the result is not trustworthy.
//!
//! The shape is a request flag plus a parked counter. Every vCPU calls
//! [`Quiesce::checkpoint`](crate::hypervisor::quiesce::Quiesce::checkpoint) at
//! a safe point in its run loop (between guest entries, where its registers are
//! stable); the requester raises the flag, kicks the vCPUs out of the
//! hypervisor so they reach that point promptly, and waits for the expected
//! number of them to park.
//!
//! The requester is itself a vCPU thread in the in-VMM path: cpu0 takes the
//! snapshot. It therefore waits for `num_cpus - 1` parked threads and never
//! parks itself, which is why
//! [`Quiesce::wait_for`](crate::hypervisor::quiesce::Quiesce::wait_for) takes
//! an explicit count rather than assuming "all of them". An external requester
//! (a control thread) waits for all of them instead.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// How long a requester waits for the vCPUs to park before giving up. A vCPU
/// that is wedged in the hypervisor must not deadlock the whole VMM, so the
/// wait is bounded and the caller decides what a timeout means (the in-VMM
/// snapshot proceeds anyway, degraded, rather than hanging the guest).
const PARK_TIMEOUT: Duration = Duration::from_millis(500);

/// The barrier itself. Cheap to check: the fast path is one relaxed atomic load
/// per guest entry.
#[derive(Default)]
pub struct Quiesce {
    /// Set while a quiesce is in effect.
    requested: AtomicBool,
    /// Number of vCPUs currently parked in [`Quiesce::checkpoint`].
    parked: Mutex<u32>,
    /// Signals both "a vCPU parked" (to the requester) and "quiesce released"
    /// (to the parked vCPUs).
    cv: Condvar,
}

impl Quiesce {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Safe point for a vCPU thread. Returns immediately unless a quiesce is in
    /// effect, in which case it parks until the requester releases it.
    ///
    /// Must be called where the calling vCPU is *out* of guest context, so its
    /// registers and the memory it has written are stable for the plugin.
    pub fn checkpoint(&self) {
        // Fast path: no quiesce pending, no lock taken.
        if !self.requested.load(Ordering::Acquire) {
            return;
        }
        let mut parked = self.parked.lock().unwrap();
        *parked += 1;
        // Wake a requester that is waiting for this thread to park.
        self.cv.notify_all();
        while self.requested.load(Ordering::Acquire) {
            parked = self.cv.wait(parked).unwrap();
        }
        *parked -= 1;
    }

    /// Raises the request. The caller must then kick the vCPUs so they leave
    /// the hypervisor and reach their next
    /// [`checkpoint`](Self::checkpoint).
    pub fn request(&self) {
        self.requested.store(true, Ordering::Release);
    }

    /// Waits until `n` vCPUs have parked, for at most `PARK_TIMEOUT`.
    ///
    /// Returns `false` on timeout, meaning the guest is *not* fully quiesced
    /// and any snapshot taken now is best-effort.
    pub fn wait_for(&self, n: u32) -> bool {
        self.wait_for_within(n, PARK_TIMEOUT)
    }

    /// Waits until `n` vCPUs have parked, for at most `timeout`.
    fn wait_for_within(&self, n: u32, timeout: Duration) -> bool {
        if n == 0 {
            return true;
        }
        let parked = self.parked.lock().unwrap();
        // One deadline covers the whole wait. Each vCPU that parks notifies,
        // and those wakeups must not extend it.
        let (parked, _) = self
            .cv
            .wait_timeout_while(parked, timeout, |parked| *parked < n)
            .unwrap();
        *parked >= n
    }

    /// Releases the quiesce and wakes every parked vCPU.
    pub fn release(&self) {
        self.requested.store(false, Ordering::Release);
        // Take the lock so a vCPU cannot be between its flag check and its
        // wait.
        let _guard = self.parked.lock().unwrap();
        self.cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    /// A quiesce with nothing to wait for completes immediately.
    #[test]
    fn wait_for_zero_is_immediate() {
        let q = Quiesce::new();
        q.request();
        assert!(q.wait_for(0));
        q.release();
    }

    /// The fast path must not block when no quiesce is pending.
    #[test]
    fn checkpoint_is_free_when_idle() {
        let q = Quiesce::new();
        q.checkpoint();
        q.checkpoint();
    }

    /// The real contract: worker threads park, the requester observes exactly
    /// that many parked, and release lets them all continue.
    #[test]
    fn parks_and_releases_workers() {
        let q = Arc::new(Quiesce::new());
        let done = Arc::new(AtomicBool::new(false));
        q.request();

        let workers: Vec<_> = (0..3)
            .map(|_| {
                let q = Arc::clone(&q);
                let done = Arc::clone(&done);
                std::thread::spawn(move || {
                    q.checkpoint();
                    // Only reachable once the requester released the quiesce.
                    done.store(true, Ordering::SeqCst);
                })
            })
            .collect();

        assert!(q.wait_for(3), "workers did not park");
        assert!(
            !done.load(Ordering::SeqCst),
            "a worker ran on past the barrier while it was still held"
        );

        q.release();
        for w in workers {
            w.join().unwrap();
        }
        assert!(done.load(Ordering::SeqCst));
        assert_eq!(*q.parked.lock().unwrap(), 0, "parked count did not unwind");
    }

    /// A requester must not hang forever when a vCPU never reaches its
    /// checkpoint; it reports the failure instead.
    #[test]
    fn wait_for_times_out_when_nobody_parks() {
        let q = Quiesce::new();
        q.request();
        assert!(!q.wait_for(1), "expected a timeout with no parked threads");
        q.release();
    }

    // Each vCPU that parks wakes the requester, and a timeout taken per wakeup
    // starts again at each one. The wakeups here come every 5 ms, so such a
    // wait lasts until they stop.
    #[test]
    fn wait_for_keeps_one_deadline_across_wakeups() {
        let q = Arc::new(Quiesce::new());
        q.request();
        let stop = Arc::new(AtomicBool::new(false));
        let waker = {
            let (q, stop) = (Arc::clone(&q), Arc::clone(&stop));
            std::thread::spawn(move || {
                let started = Instant::now();
                while !stop.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(2) {
                    drop(q.parked.lock().unwrap());
                    q.cv.notify_all();
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
        };

        let started = Instant::now();
        let parked = q.wait_for_within(1, Duration::from_millis(100));
        let waited = started.elapsed();
        stop.store(true, Ordering::SeqCst);
        waker.join().unwrap();
        q.release();

        assert!(!parked, "expected a timeout with no parked threads");
        assert!(waited < Duration::from_secs(1), "the wait took {waited:?}");
    }
}

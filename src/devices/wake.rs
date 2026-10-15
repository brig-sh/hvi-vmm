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

//! The wake signal a device's worker thread parks on.
//!
//! A vCPU that finds work for a device's worker calls [`Wake::wake`], and the
//! worker waits for it in [`Wake::park`]. The signal coalesces: any number of
//! wakes before the worker looks again cost it one pass. The flag is checked
//! under a `Condvar`, so a wake that lands between the worker's last pass and
//! its park is seen rather than lost.

use std::sync::{Condvar, Mutex};

use crate::sync::lock_or_recover;

/// A coalescing wake signal, with the stop that ends the worker.
pub(crate) struct Wake {
    state: Mutex<WakeState>,
    ready: Condvar,
}

/// The flags behind [`Wake`].
#[derive(Default)]
struct WakeState {
    /// A wake arrived since the worker last parked.
    woken: bool,
    /// The stop has been requested.
    stopped: bool,
}

impl Wake {
    /// Returns a signal with no wake and no stop.
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(WakeState::default()),
            ready: Condvar::new(),
        }
    }

    /// Signals the worker. Safe to call whether or not it is currently
    /// parked -- a signal that arrives mid-pass is simply picked up on the
    /// worker's next pass, never lost.
    pub(crate) fn wake(&self) {
        let mut state = lock_or_recover(&self.state);
        state.woken = true;
        self.ready.notify_one();
    }

    /// Requests that the worker exit at its next pass.
    pub(crate) fn stop(&self) {
        let mut state = lock_or_recover(&self.state);
        state.stopped = true;
        self.ready.notify_one();
    }

    /// Returns whether the stop has been requested.
    pub(crate) fn is_stopped(&self) -> bool {
        lock_or_recover(&self.state).stopped
    }

    /// Blocks until the next [`Wake::wake`] or [`Wake::stop`].
    ///
    /// Clears the wake flag on return and returns `false` once stopped. Must
    /// not be called with the device's mutex held.
    pub(crate) fn park(&self) -> bool {
        let mut state = lock_or_recover(&self.state);
        while !state.woken && !state.stopped {
            state = self.ready.wait(state).unwrap_or_else(|p| p.into_inner());
        }
        state.woken = false;
        !state.stopped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_wake_before_the_park_is_not_lost() {
        let wake = Wake::new();
        wake.wake();
        wake.wake();
        assert!(wake.park(), "the wake that came first is seen");
    }

    #[test]
    fn the_stop_ends_a_parked_worker() {
        let wake = Arc::new(Wake::new());
        let worker = {
            let wake = Arc::clone(&wake);
            std::thread::spawn(move || wake.park())
        };
        wake.stop();
        assert!(!worker.join().unwrap());
        assert!(wake.is_stopped());
    }
}

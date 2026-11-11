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

//! What wakes a device's worker thread.

use std::io;
#[cfg(target_os = "macos")]
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::fd::{AsFd, AsRawFd};
#[cfg(target_os = "macos")]
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::task::Wake;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use vmm_sys_util::eventfd::EventFd;

use crate::teardown::StopToken;
#[cfg(target_os = "macos")]
use crate::teardown::{poll, pollfd};

/// What wakes a device's worker thread.
///
/// Signals that arrive before the worker waits count as one.
///
/// On Linux it is an eventfd. KVM can signal it for a guest's notification with
/// no exit to hvi, and the worker waits on it beside the I/O threads' stop
/// token.
#[cfg(target_os = "linux")]
pub(crate) struct WorkerWake(EventFd);

/// What wakes a device's worker thread.
///
/// Signals that arrive before the worker waits count as one.
///
/// macOS has no eventfd, so it is a pipe. The worker waits on its read end
/// beside the I/O threads' stop token.
#[cfg(target_os = "macos")]
pub(crate) struct WorkerWake {
    /// The end the worker polls and drains.
    read: io::PipeReader,
    /// The end a signal writes one byte to.
    write: io::PipeWriter,
}

#[cfg(target_os = "linux")]
impl WorkerWake {
    /// Returns a wake with no signal pending.
    ///
    /// # Errors
    ///
    /// Errors if the eventfd cannot be created.
    pub(crate) fn new() -> io::Result<Self> {
        EventFd::new(libc::EFD_NONBLOCK).map(Self)
    }

    /// Returns the eventfd, which a write signals.
    pub(crate) fn eventfd(&self) -> &EventFd {
        &self.0
    }

    /// Wakes the worker.
    ///
    /// It can be called whether or not the worker waits. A worker that is not
    /// waiting returns from its next wait at once.
    pub(crate) fn signal(&self) {
        // A write fails only when the count would overflow, and the worker is
        // woken then anyway.
        let _ = self.0.write(1);
    }

    /// Blocks until the next signal.
    ///
    /// It returns `false` once `stop` is requested.
    ///
    /// # Panics
    ///
    /// Panics if the wait fails, since the device would no longer be served.
    pub(crate) fn wait(&self, stop: &StopToken) -> bool {
        use std::os::fd::{AsRawFd, BorrowedFd};
        // SAFETY: the eventfd is open for as long as `self` lives, which spans
        // the call.
        let fd = unsafe { BorrowedFd::borrow_raw(self.0.as_raw_fd()) };
        let signaled = stop
            .wait(fd)
            .unwrap_or_else(|e| panic!("waiting for a worker's wake: {e}"));
        if signaled {
            // The read clears the count, so the signals that arrived before it
            // wake the worker once.
            let _ = self.0.read();
        }
        signaled
    }
}

#[cfg(target_os = "macos")]
impl WorkerWake {
    /// Returns a wake with no signal pending.
    ///
    /// # Errors
    ///
    /// Errors if the pipe cannot be created or its write end cannot be made
    /// nonblocking.
    pub(crate) fn new() -> io::Result<Self> {
        let (read, write) = io::pipe()?;
        let fd = write.as_raw_fd();
        // SAFETY: `fd` is the open write end `write` owns, and `F_GETFL` and
        // `F_SETFL` only read and set its status flags.
        let set = unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0
        };
        if !set {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { read, write })
    }

    /// Wakes the worker.
    ///
    /// It can be called whether or not the worker waits. A worker that is not
    /// waiting returns from its next wait at once.
    pub(crate) fn signal(&self) {
        // A full pipe already holds a signal, so the write's error is dropped.
        let _ = (&self.write).write(&[1]);
    }

    /// Blocks until the next signal.
    ///
    /// It returns `false` once `stop` is requested.
    ///
    /// # Panics
    ///
    /// Panics if the wait fails, since the device would no longer be served.
    pub(crate) fn wait(&self, stop: &StopToken) -> bool {
        let signaled = stop
            .wait(self.read.as_fd())
            .unwrap_or_else(|e| panic!("waiting for a worker's wake: {e}"));
        if signaled {
            self.drain();
        }
        signaled
    }

    /// Blocks like [`wait`](Self::wait), for at most `timeout`.
    ///
    /// When the timeout passes, it returns as if signaled.
    ///
    /// # Panics
    ///
    /// Panics if the wait fails, since the device would no longer be served.
    pub(crate) fn wait_timeout(&self, stop: &StopToken, timeout: Duration) -> bool {
        let mut fds = [
            pollfd(self.read.as_raw_fd()),
            pollfd(stop.as_fd().as_raw_fd()),
        ];
        poll(&mut fds, Some(Instant::now() + timeout))
            .unwrap_or_else(|e| panic!("waiting for a worker's wake: {e}"));
        if fds[1].revents != 0 {
            return false;
        }
        if fds[0].revents != 0 {
            self.drain();
        }
        true
    }

    /// Takes the signals that arrived, so they wake the worker once.
    fn drain(&self) {
        let mut signals = [0u8; 512];
        let _ = (&self.read).read(&mut signals);
    }
}

#[cfg(target_os = "macos")]
impl Wake for WorkerWake {
    fn wake(self: Arc<Self>) {
        self.signal();
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::teardown::StopSource;

    #[test]
    fn timed_wait_ends_at_its_deadline_or_at_a_signal_or_a_stop() {
        let wake = WorkerWake::new().unwrap();
        let source = StopSource::new().unwrap();
        let stop = source.token();
        let start = Instant::now();
        assert!(
            wake.wait_timeout(&stop, Duration::from_millis(20)),
            "a deadline is not a stop"
        );
        assert!(start.elapsed() >= Duration::from_millis(20));

        wake.signal();
        wake.signal();
        let start = Instant::now();
        assert!(wake.wait_timeout(&stop, Duration::from_secs(10)));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a pending signal ends the wait at once"
        );
        let start = Instant::now();
        assert!(wake.wait_timeout(&stop, Duration::from_millis(20)));
        assert!(
            start.elapsed() >= Duration::from_millis(20),
            "the wait took both signals"
        );

        source.request_stop();
        assert!(
            !wake.wait_timeout(&stop, Duration::from_secs(10)),
            "a stop ends the timed wait and says so"
        );
        assert!(!wake.wait(&stop), "a stop ends the wait and says so");
    }
}

// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

//! The stop request a caller makes on a run, over a pipe that wakes the loop
//! that owns the stop.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::teardown::{poll, pollfd};

/// A handle that asks a run to stop.
///
/// Clones share one request. See the [module documentation](crate::run).
#[derive(Clone)]
pub struct StopHandle(Arc<Inner>);

/// The half of a stop pair that a run takes, through
/// [`BootConfig::stop`](crate::config::BootConfig::stop).
///
/// It is not `Clone`, and `boot` takes it by value, so it serves one run.
pub struct StopRegistration(Arc<Inner>);

impl StopRegistration {
    /// Returns a handle on the stop the registration belongs to.
    pub(crate) fn into_handle(self) -> StopHandle {
        StopHandle(self.0)
    }

    /// Returns a handle on the stop the registration belongs to, and keeps the
    /// registration.
    pub(crate) fn handle(&self) -> StopHandle {
        StopHandle(Arc::clone(&self.0))
    }
}

/// What [`Inner::first`] holds when a request without a signal came first.
const NO_SIGNAL: libc::c_int = -1;

/// The state a [`StopHandle`], its clones and its [`StopRegistration`] share.
struct Inner {
    /// The pipe that wakes the loop that owns the run's stop.
    waker: Waker,
    /// What asked for the stop first: a signal, [`NO_SIGNAL`] for a request
    /// without one, or 0 before any request.
    first: AtomicI32,
    /// The first stop signal that asked, whatever asked before it, or 0.
    signal: AtomicI32,
}

impl StopHandle {
    /// Returns a handle with no stop requested, and the registration a run
    /// takes to be stopped by it.
    ///
    /// # Errors
    ///
    /// Errors if the pipe the request is written to cannot be created.
    pub fn new_pair() -> io::Result<(StopHandle, StopRegistration)> {
        let inner = Arc::new(Inner {
            waker: Waker::new()?,
            first: AtomicI32::new(0),
            signal: AtomicI32::new(0),
        });
        Ok((StopHandle(Arc::clone(&inner)), StopRegistration(inner)))
    }

    /// Asks the run to stop.
    ///
    /// The run stops whatever the guest is doing. A request before `boot` stops
    /// the run as soon as it starts, and a request after `boot` has returned
    /// has no effect.
    pub fn request_stop(&self) {
        self.request(NO_SIGNAL);
    }

    /// Asks the run to stop on behalf of `signal`, which
    /// [`signal`](Self::signal) then returns, unless another signal asked
    /// earlier.
    pub(crate) fn request_stop_by(&self, signal: libc::c_int) {
        self.request(signal);
    }

    /// Records `by` as the stop signal when it is the first one, records it as
    /// what asked for the stop, unless an earlier request came first, and
    /// requests the stop.
    fn request(&self, by: libc::c_int) {
        // The stop signal is recorded before the request, so whoever sees the
        // request also finds the signal that made it.
        if by != NO_SIGNAL {
            let _ = self
                .0
                .signal
                .compare_exchange(0, by, Ordering::SeqCst, Ordering::SeqCst);
        }
        let _ = self
            .0
            .first
            .compare_exchange(0, by, Ordering::SeqCst, Ordering::SeqCst);
        self.0.waker.wake();
    }

    /// Returns the first stop signal that asked the run to stop, or `None` when
    /// none did.
    ///
    /// A signal that asked after another request still counts, so a binary ends
    /// by the signal it received.
    #[must_use]
    pub fn signal(&self) -> Option<libc::c_int> {
        match self.0.signal.load(Ordering::SeqCst) {
            0 => None,
            signal => Some(signal),
        }
    }

    /// Returns the signal that asked for the stop first, or `None` when a
    /// request without a signal came first or none came.
    pub(crate) fn first_signal(&self) -> Option<libc::c_int> {
        match self.0.first.load(Ordering::SeqCst) {
            0 | NO_SIGNAL => None,
            signal => Some(signal),
        }
    }

    /// Returns whether a stop has been requested.
    pub(crate) fn is_stop_requested(&self) -> bool {
        self.0.first.load(Ordering::SeqCst) != 0
    }

    /// Returns how many handles and registrations share this handle's stop.
    #[cfg(test)]
    pub(crate) fn holders(&self) -> usize {
        Arc::strong_count(&self.0)
    }

    /// Waits up to `timeout` for a stop request, and returns whether one came.
    #[cfg(test)]
    pub(crate) fn wait_for_request(&self, timeout: std::time::Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while !self.is_stop_requested() && Instant::now() < deadline {
            let _ = self.wait(Some(deadline));
        }
        self.is_stop_requested()
    }

    /// Wakes the loop without requesting a stop.
    pub(crate) fn wake(&self) {
        self.0.waker.wake();
    }

    /// Blocks until the loop is woken or `deadline` passes, with no limit when
    /// `deadline` is `None`.
    pub(crate) fn wait(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.0.waker.wait(deadline)
    }
}

/// The pipe that wakes the loop that owns the run's stop.
///
/// Its write end is nonblocking, so a wake never blocks the thread that writes
/// it.
struct Waker {
    /// The end the loop polls and drains.
    read: io::PipeReader,
    /// The end a thread with something to report writes one byte to.
    write: io::PipeWriter,
}

impl Waker {
    /// Creates the pipe, with no wake pending.
    ///
    /// It has to be created before the calling thread is filtered, since
    /// neither allowlist carries `pipe2`.
    ///
    /// # Errors
    ///
    /// Errors if the pipe cannot be created or its write end cannot be made
    /// nonblocking.
    fn new() -> io::Result<Self> {
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

    /// Wakes the loop.
    ///
    /// A full pipe already holds a wake, so the write's error is dropped.
    fn wake(&self) {
        let _ = (&self.write).write(&[1]);
    }

    /// Blocks until a wake is pending or `deadline` passes, with no limit when
    /// `deadline` is `None`.
    ///
    /// It drains a pending wake before it returns.
    ///
    /// # Errors
    ///
    /// Errors if `poll` or the read fails for a reason other than a signal.
    fn wait(&self, deadline: Option<Instant>) -> io::Result<()> {
        let mut fds = [pollfd(self.read.as_raw_fd())];
        poll(&mut fds, deadline)?;
        if fds[0].revents == 0 {
            return Ok(());
        }
        let mut drained = [0u8; 64];
        match (&self.read).read(&mut drained) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn registration_handle_shares_its_stop() {
        let (handle, registration) = StopHandle::new_pair().unwrap();
        registration.handle().request_stop();
        assert!(handle.is_stop_requested());
    }

    #[test]
    fn request_wakes_a_waiter_and_marks_the_handle() {
        let (handle, _registration) = StopHandle::new_pair().unwrap();
        let waiter = {
            let handle = handle.clone();
            std::thread::spawn(move || handle.wait(None))
        };
        handle.request_stop();
        waiter.join().unwrap().unwrap();
        assert!(handle.is_stop_requested());
        assert_eq!(handle.signal(), None);
    }

    // A request made before the run starts reaches it through the registration.
    #[test]
    fn request_before_the_run_reaches_the_registration() {
        let (handle, registration) = StopHandle::new_pair().unwrap();
        handle.request_stop();
        assert!(registration.into_handle().is_stop_requested());
    }

    #[test]
    fn signal_after_a_request_still_counts() {
        let (handle, _registration) = StopHandle::new_pair().unwrap();
        handle.request_stop();
        handle.request_stop_by(libc::SIGTERM);
        assert!(handle.is_stop_requested());
        assert_eq!(handle.signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn signal_after_a_request_does_not_ask_first() {
        let (handle, _registration) = StopHandle::new_pair().unwrap();
        handle.request_stop();
        handle.request_stop_by(libc::SIGTERM);
        assert_eq!(handle.first_signal(), None);
        let (handle, _registration) = StopHandle::new_pair().unwrap();
        handle.request_stop_by(libc::SIGTERM);
        handle.request_stop();
        assert_eq!(handle.first_signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn first_of_two_signals_counts() {
        let (handle, _registration) = StopHandle::new_pair().unwrap();
        handle.request_stop_by(libc::SIGTERM);
        handle.request_stop_by(libc::SIGINT);
        handle.request_stop();
        assert_eq!(handle.signal(), Some(libc::SIGTERM));
        assert_eq!(handle.first_signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn wake_ends_a_wait() {
        let waker = std::sync::Arc::new(Waker::new().unwrap());
        let waiter = {
            let waker = std::sync::Arc::clone(&waker);
            std::thread::spawn(move || waker.wait(None))
        };
        waker.wake();
        waiter.join().unwrap().unwrap();
    }

    // A wake written before the wait starts must stay pending, or the loop
    // would miss the exit of the only vCPU.
    #[test]
    fn wake_before_the_wait_is_kept() {
        let waker = Waker::new().unwrap();
        waker.wake();
        waker.wait(None).unwrap();
    }

    #[test]
    fn wait_with_a_deadline_returns_without_a_wake() {
        let waker = Waker::new().unwrap();
        let start = Instant::now();
        waker.wait(Some(start + Duration::from_millis(20))).unwrap();
        assert!(start.elapsed() >= Duration::from_millis(20));
    }

    // A thread that wakes the loop must not wait on it, so a write to a full
    // pipe returns.
    #[test]
    fn wake_on_a_full_pipe_returns() {
        let waker = Waker::new().unwrap();
        let writer = std::thread::spawn(move || {
            for _ in 0..(1 << 20) {
                waker.wake();
            }
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !writer.is_finished() {
            assert!(Instant::now() < deadline, "a wake blocked on a full pipe");
            std::thread::sleep(Duration::from_millis(1));
        }
        writer.join().unwrap();
    }
}

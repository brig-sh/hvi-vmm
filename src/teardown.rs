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

//! Shutdown of the host-side helper threads when the run stops.
//!
//! `IoThreads` starts threads that block on host descriptors: the console, the
//! agent listener and its connections, the gateway socket, the tap. Each polls
//! its own descriptor beside a [`StopToken`]. `IoThreads::stop` requests the
//! stop through its [`StopSource`] once the vCPU threads have exited or been
//! left running, every poll returns, and it joins the threads before `boot`
//! returns. Some helpers need more than the poll. A macOS virtio-fs device's
//! worker and readahead workers wait on no descriptor; each parks on a
//! condition variable, and a stop action that `IoThreads::stop` runs wakes it.
//! The console reader reads stdin, which the whole process shares, so a byte
//! another reader took between the poll and the read would leave it blocked;
//! `IoThreads::stop` sends it the kick signal until it has finished, with
//! `IoThread::kick_until_finished`.
//!
//! Every join is bounded by [`STOP_TIMEOUT`]. A helper that has not exited by
//! the deadline is left running and `boot` returns an error naming it, since a
//! wait `boot` cannot interrupt must not keep `boot` from returning. Each I/O
//! thread notes on a `FinishCount` as it ends, so `IoThreads::stop` waits until
//! the last one has or the deadline passes.
//!
//! The request shuts down the write half of a socket pair, which leaves the
//! read half readable for every token from then on. Dropping the `StopSource`
//! closes the write half with the same effect, so a token also reports the stop
//! when `boot` unwinds past it.
//!
//! `poll` is the wake primitive on every backend. Both Linux `vmm` seccomp
//! allowlists carry it (as `ppoll` on aarch64, which is what glibc's `poll`
//! calls there), and the pair is created before any filter installs.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long the stop waits for the vCPU threads, then for the helper threads,
/// and then for the ledger, after it is requested.
///
/// The waits the stop cannot interrupt are a plugin blocking in `on_request`,
/// in `on_safepoint` or on a thread it started with `VmHandle::spawn`, a
/// virtio-fs worker waiting on a host file lock, and a ledger write that blocks
/// in the kernel.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(1);

/// A count of the helper threads that have finished.
#[derive(Default)]
pub(crate) struct FinishCount {
    /// The number of threads that have noted they finished.
    count: Mutex<u32>,
    /// The condition variable notified at each note.
    changed: Condvar,
}

impl FinishCount {
    /// Records that one more thread has finished.
    pub(crate) fn note(&self) {
        *self.count.lock().unwrap() += 1;
        self.changed.notify_all();
    }

    /// Returns the number of threads that have finished.
    pub(crate) fn finished(&self) -> u32 {
        *self.count.lock().unwrap()
    }

    /// Returns whether `count` threads have finished by `deadline`.
    ///
    /// It blocks until they have or until `deadline` passes.
    pub(crate) fn wait_for(&self, count: u32, deadline: Instant) -> bool {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let noted = self.count.lock().unwrap();
        let (noted, _) = self
            .changed
            .wait_timeout_while(noted, timeout, |noted| *noted < count)
            .unwrap();
        *noted >= count
    }
}

/// A guard that marks its thread finished when it is dropped.
///
/// The drop sets the thread's own flag and then notes on the [`FinishCount`]
/// the threads share. It runs on a panic as on a return, so a thread that
/// panics is counted too.
pub(crate) struct FinishGuard {
    /// The flag of the thread that holds the guard.
    pub(crate) finished: Arc<AtomicBool>,
    /// The count the threads share.
    pub(crate) count: Arc<FinishCount>,
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::SeqCst);
        self.count.note();
    }
}

/// The requesting end of a stop.
pub struct StopSource {
    write: UnixStream,
    read: Arc<UnixStream>,
}

impl StopSource {
    /// Creates the pair, with no stop requested.
    ///
    /// # Errors
    ///
    /// Errors if the socket pair cannot be created.
    pub fn new() -> io::Result<Self> {
        let (write, read) = UnixStream::pair()?;
        Ok(Self {
            write,
            read: Arc::new(read),
        })
    }

    /// Returns a token for a helper thread.
    #[must_use]
    pub fn token(&self) -> StopToken {
        StopToken(Arc::clone(&self.read))
    }

    /// Requests the stop, so every [`StopToken::wait`] returns `false` from now
    /// on.
    pub fn request_stop(&self) {
        let _ = self.write.shutdown(std::net::Shutdown::Write);
    }
}

/// A helper thread's view of a [`StopSource`].
///
/// Its descriptor becomes readable when the stop is requested and stays
/// readable, so a thread can add it to a `poll` set beside its own descriptors.
/// Every token of a run shares the descriptor, so a thread polls it and neither
/// reads it nor shuts it down.
#[derive(Clone)]
pub struct StopToken(Arc<UnixStream>);

impl AsFd for StopToken {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl StopToken {
    /// Blocks until `fd` is readable or the stop is requested.
    ///
    /// Returns `true` when `fd` has data or a hangup to read and no stop is
    /// requested. A hangup counts as readable because a stream socket reports
    /// it with bytes still queued, and the read that follows returns them, then
    /// zero. A descriptor error is not waited out, since `poll` would report it
    /// again at once.
    ///
    /// # Errors
    ///
    /// Errors if `poll` fails for a reason other than a signal, or if the
    /// descriptor reports an error or is not open.
    pub fn wait(&self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        let mut fds = [pollfd(fd.as_raw_fd()), pollfd(self.0.as_raw_fd())];
        poll(&mut fds, None)?;
        if fds[1].revents != 0 {
            return Ok(false);
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            Ok(true)
        } else {
            Err(io::Error::other("cannot be read anymore"))
        }
    }

    /// Blocks until `fd` takes a write or the stop is requested.
    ///
    /// Returns `true` when `fd` is writable, or reports a hangup or an error,
    /// and no stop is requested. A write that follows a hangup or an error
    /// returns that error.
    ///
    /// # Errors
    ///
    /// Errors if `poll` fails for a reason other than a signal.
    pub fn wait_writable(&self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        let mut out = pollfd(fd.as_raw_fd());
        out.events = libc::POLLOUT;
        let mut fds = [out, pollfd(self.0.as_raw_fd())];
        poll(&mut fds, None)?;
        Ok(fds[1].revents == 0)
    }

    /// Returns whether a helper that waits on something other than `fd` should
    /// keep waiting.
    ///
    /// It returns `false` once the stop is requested, or once `fd` reports a
    /// hangup or an error, and it does not block. The helper calls it at
    /// intervals, so it notices both without polling `fd` for data.
    #[must_use]
    pub fn keep_waiting(&self, fd: BorrowedFd<'_>) -> bool {
        let mut fds = [pollfd(fd.as_raw_fd()), pollfd(self.0.as_raw_fd())];
        if poll(&mut fds, Some(Instant::now())).is_err() {
            return false;
        }
        fds[1].revents == 0 && fds[0].revents & HANGUP == 0
    }

    /// Sleeps for `duration` unless the stop is requested first.
    ///
    /// Returns `true` when the whole duration passed and `false` when the stop
    /// ended the sleep.
    ///
    /// # Errors
    ///
    /// Errors if `poll` fails for a reason other than a signal.
    pub fn sleep(&self, duration: Duration) -> io::Result<bool> {
        let mut fds = [pollfd(self.0.as_raw_fd())];
        poll(&mut fds, Instant::now().checked_add(duration))?;
        Ok(fds[0].revents == 0)
    }
}

/// The `revents` bits that say a descriptor has hung up or failed.
pub(crate) const HANGUP: libc::c_short = libc::POLLHUP | libc::POLLERR | libc::POLLNVAL;

/// Builds a `pollfd` that waits for `fd` to become readable.
pub(crate) fn pollfd(fd: libc::c_int) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Polls `fds` until one of them is ready or `deadline` passes, with no limit
/// when `deadline` is `None`.
///
/// Each call waits only for the time left, rounded up to whole milliseconds, so
/// a signal that interrupts the call does not extend the wait, and a wait
/// shorter than a millisecond still sleeps.
pub(crate) fn poll(fds: &mut [libc::pollfd], deadline: Option<Instant>) -> io::Result<()> {
    loop {
        let timeout_millis = deadline.map_or(-1, |deadline| {
            let left = deadline.saturating_duration_since(Instant::now());
            libc::c_int::try_from(left.as_micros().div_ceil(1000)).unwrap_or(libc::c_int::MAX)
        });
        // SAFETY: `fds` is a live slice of `pollfd` and the length matches.
        let ret =
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_millis) };
        // A timeout short of the deadline is waited out by the next call.
        if ret > 0 || (ret == 0 && timeout_millis == 0) {
            return Ok(());
        }
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

/// Sleeps for 1 ms, or until `deadline` when that comes sooner.
///
/// It sleeps in `poll`, which both seccomp allowlists allow, so a vCPU thread
/// can call it. `clock_nanosleep` is in the `vmm` allowlist only.
pub(crate) fn sleep_step(deadline: Instant) {
    let next = (Instant::now() + Duration::from_millis(1)).min(deadline);
    let _ = poll(&mut [], Some(next));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn stop_wakes_waiter_on_idle_descriptor() {
        let source = StopSource::new().expect("pair");
        let token = source.token();
        let (_idle_peer, idle) = UnixStream::pair().expect("pair");
        let waiter = std::thread::spawn(move || token.wait(idle.as_fd()).expect("poll"));
        source.request_stop();
        assert!(!waiter.join().expect("thread"));
    }

    // `poll` takes whole milliseconds, so a shorter sleep is rounded up, not
    // down to no wait at all.
    #[test]
    fn sleep_shorter_than_a_millisecond_still_sleeps() {
        let source = StopSource::new().expect("pair");
        let start = Instant::now();
        assert!(source
            .token()
            .sleep(Duration::from_micros(500))
            .expect("poll"));
        assert!(start.elapsed() >= Duration::from_micros(500));
    }

    #[test]
    fn readable_descriptor_is_reported_before_stop() {
        let source = StopSource::new().expect("pair");
        let (mut peer, ready) = UnixStream::pair().expect("pair");
        peer.write_all(b"x").expect("write");
        assert!(source.token().wait(ready.as_fd()).expect("poll"));
    }

    // A pipe whose writer has gone reports the hangup alone, with no data bit.
    // That is stdin at end of file when the console is a pipe.
    #[test]
    fn hung_up_descriptor_is_readable() {
        let source = StopSource::new().expect("pair");
        let (reader, writer) = std::io::pipe().expect("pipe");
        drop(writer);
        assert!(source.token().wait(reader.as_fd()).expect("poll"));
    }

    // A peer that wrote and then closed leaves data and a hangup together. The
    // vsock bridge reader relies on seeing the hangup, so it stops waiting for
    // the guest and reads the rest of the socket.
    #[test]
    fn keep_waiting_ends_on_hangup_and_on_stop() {
        let source = StopSource::new().expect("pair");
        let token = source.token();
        let (mut peer, idle) = UnixStream::pair().expect("pair");
        assert!(token.keep_waiting(idle.as_fd()), "idle socket");
        peer.write_all(b"x").expect("write");
        assert!(token.keep_waiting(idle.as_fd()), "data alone is no hangup");
        drop(peer);
        assert!(!token.keep_waiting(idle.as_fd()), "the peer closed");

        let (_peer, idle) = UnixStream::pair().expect("pair");
        source.request_stop();
        assert!(!token.keep_waiting(idle.as_fd()), "the stop was requested");
    }

    #[test]
    fn wait_writable_reports_room_and_stop() {
        let source = StopSource::new().expect("pair");
        let token = source.token();
        let (_peer, ours) = UnixStream::pair().expect("pair");
        assert!(token.wait_writable(ours.as_fd()).expect("poll"));
        source.request_stop();
        assert!(!token.wait_writable(ours.as_fd()).expect("poll"));
    }

    // Dropping the source must stop the tokens, so `boot` unwinding past its
    // own `request_stop` call still stops the helpers.
    #[test]
    fn dropping_source_stops_tokens() {
        let source = StopSource::new().expect("pair");
        let token = source.token();
        drop(source);
        let (_idle_peer, idle) = UnixStream::pair().expect("pair");
        assert!(!token.wait(idle.as_fd()).expect("poll"));
    }

    #[test]
    fn stop_stays_requested_for_every_token() {
        let source = StopSource::new().expect("pair");
        let first = source.token();
        let second = source.token();
        source.request_stop();
        let (_idle_peer, idle) = UnixStream::pair().expect("pair");
        assert!(!first.wait(idle.as_fd()).expect("poll"));
        assert!(!second.wait(idle.as_fd()).expect("poll"));
        assert!(!first.wait(idle.as_fd()).expect("poll"));
    }

    #[test]
    fn sleep_ends_when_stopped() {
        let source = StopSource::new().expect("pair");
        let token = source.token();
        let sleeper = std::thread::spawn(move || token.sleep(Duration::from_secs(30)));
        source.request_stop();
        assert!(!sleeper.join().expect("thread").expect("poll"));
    }

    #[test]
    fn sleep_runs_to_the_end_when_not_stopped() {
        let source = StopSource::new().expect("pair");
        assert!(source
            .token()
            .sleep(Duration::from_millis(10))
            .expect("poll"));
    }
}

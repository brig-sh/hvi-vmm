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

//! Ending the host-side helper threads when the guest stops.
//!
//! `boot` spawns threads that block on host descriptors: the console, the agent
//! listener and its connections, the gateway socket, the tap. Each polls its
//! own descriptor beside a [`StopToken`](crate::teardown::StopToken). `boot`
//! requests the stop through its [`StopSource`](crate::teardown::StopSource)
//! once the vCPU threads have exited, every poll returns, and `boot` joins the
//! threads before it returns. Two helpers need more than the poll. The macOS
//! virtio-fs worker waits on no descriptor; it parks on a condition variable
//! and is stopped through it. The console reader reads stdin, which the whole
//! process shares, so a byte another reader took between the poll and the read
//! would leave it blocked; `boot` sends it the kick signal until it has exited.
//!
//! Every join is bounded by [`STOP_TIMEOUT`](crate::teardown::STOP_TIMEOUT). A
//! helper that has not exited by the deadline is left running and `boot`
//! returns an error naming it, since a wait `boot` cannot interrupt must not
//! keep `boot` from returning.
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
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long `boot` waits for its helper threads after requesting the stop.
///
/// The waits `boot` cannot interrupt are a plugin blocking in `request` and a
/// virtio-fs worker waiting on a host file lock.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(1);

/// Joins `thread` if it exits before `deadline`.
///
/// A thread that has not exited by the deadline is left running.
///
/// # Errors
///
/// Errors when the thread has not exited by the deadline.
pub fn join_by(name: &str, thread: JoinHandle<()>, deadline: Instant) -> io::Result<()> {
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "{name} did not stop within {}s",
                STOP_TIMEOUT.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let _ = thread.join();
    Ok(())
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
#[derive(Clone)]
pub struct StopToken(Arc<UnixStream>);

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
        poll(&mut fds, -1)?;
        if fds[1].revents != 0 {
            return Ok(false);
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            Ok(true)
        } else {
            Err(io::Error::other("cannot be read any more"))
        }
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
        let millis = libc::c_int::try_from(duration.as_millis()).unwrap_or(libc::c_int::MAX);
        let mut fds = [pollfd(self.0.as_raw_fd())];
        poll(&mut fds, millis)?;
        Ok(fds[0].revents == 0)
    }
}

/// Builds a `pollfd` that waits for `fd` to become readable.
fn pollfd(fd: libc::c_int) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Polls `fds`, retrying when a signal interrupts the call.
fn poll(fds: &mut [libc::pollfd], timeout_millis: libc::c_int) -> io::Result<()> {
    loop {
        // SAFETY: `fds` is a live slice of `pollfd` and the length matches.
        let ret =
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_millis) };
        if ret >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;

    #[test]
    fn stop_wakes_waiter_on_idle_descriptor() {
        let source = StopSource::new().expect("pair");
        let token = source.token();
        let (_idle_peer, idle) = UnixStream::pair().expect("pair");
        let waiter = std::thread::spawn(move || token.wait(idle.as_fd()).expect("poll"));
        source.request_stop();
        assert!(!waiter.join().expect("thread"));
    }

    #[test]
    fn readable_descriptor_reported_before_stop() {
        let source = StopSource::new().expect("pair");
        let (mut peer, ready) = UnixStream::pair().expect("pair");
        peer.write_all(b"x").expect("write");
        assert!(source.token().wait(ready.as_fd()).expect("poll"));
    }

    // A pipe whose writer has gone reports the hangup alone, with no data bit,
    // which is stdin at end of file when the console is a pipe.
    #[test]
    fn hung_up_descriptor_is_readable() {
        let source = StopSource::new().expect("pair");
        let (reader, writer) = std::io::pipe().expect("pipe");
        drop(writer);
        assert!(source.token().wait(reader.as_fd()).expect("poll"));
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
    fn sleep_runs_to_the_end_unstopped() {
        let source = StopSource::new().expect("pair");
        assert!(source
            .token()
            .sleep(Duration::from_millis(10))
            .expect("poll"));
    }
}

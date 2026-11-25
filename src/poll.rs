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

//! The wait a thread makes on its descriptors.
//!
//! A thread builds a [`Poll`] before each wait, from the descriptors it can use
//! at that moment, and reads what the wait found from the [`Ready`] it returns.
//! A descriptor the thread has no use for yet is left out.
//!
//! The wait is level-triggered: a descriptor that stays ready is reported by
//! every wait that asks for it.
//!
//! `poll(2)` is the primitive on every backend. Every Linux seccomp allowlist
//! carries it (as `ppoll` on aarch64, which is what glibc's `poll` calls
//! there).

use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::time::Instant;

use crate::teardown::StopToken;

/// The most descriptors a poll holds, the stop among them.
const CAPACITY: usize = 8;

/// What a thread waits for on a descriptor.
///
/// Interests combine with `|`, for a descriptor the thread waits on for more
/// than one of them.
#[derive(Clone, Copy)]
pub(crate) struct Interest(libc::c_short);

impl Interest {
    /// The descriptor has data or a hangup to read.
    pub(crate) const READABLE: Self = Self(libc::POLLIN);
    /// The descriptor takes a write.
    pub(crate) const WRITABLE: Self = Self(libc::POLLOUT);
    /// The peer of the descriptor hung up. Data that arrives does not end the
    /// wait.
    ///
    /// Alone, it is for a wait that does not block. A blocking `poll(2)` on
    /// macOS that asks for the hangup alone misses one that arrives while the
    /// descriptor has data unread.
    ///
    /// The hangup is asked for by name. Linux reports one whatever is asked,
    /// and macOS reports none for an entry that asks for no event.
    pub(crate) const HANGUP: Self = Self(libc::POLLHUP);
}

impl std::ops::BitOr for Interest {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// A descriptor in a [`Poll`], by which the wait's [`Ready`] is asked about it.
#[derive(Clone, Copy)]
pub(crate) struct Token(usize);

/// The descriptors one wait covers.
///
/// A descriptor is added once, with every interest the thread has in it. On
/// macOS, `poll(2)` does not report each of two entries for one descriptor when
/// both wait on its read side.
pub(crate) struct Poll<'a> {
    /// The entries `poll(2)` takes, of which the first `len` are in use.
    fds: [libc::pollfd; CAPACITY],
    /// The number of entries in use.
    len: usize,
    /// Whether the first entry is the stop of the run.
    has_stop: bool,
    /// The borrow of the descriptors, which keeps them open while the poll
    /// names them.
    descriptors: PhantomData<BorrowedFd<'a>>,
}

impl<'a> Poll<'a> {
    /// Returns a poll with no descriptor.
    pub(crate) fn new() -> Self {
        let unused = libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        };
        Self {
            fds: [unused; CAPACITY],
            len: 0,
            has_stop: false,
            descriptors: PhantomData,
        }
    }

    /// Returns a poll whose wait also ends when `stop` is requested.
    pub(crate) fn with_stop(stop: &'a StopToken) -> Self {
        let mut poll = Self::new();
        poll.add(stop.as_fd(), Interest::READABLE);
        poll.has_stop = true;
        poll
    }

    /// Adds `fd`, to wait for `interest` on it.
    ///
    /// # Panics
    ///
    /// Panics if the poll is full or already holds `fd`.
    pub(crate) fn add(&mut self, fd: BorrowedFd<'a>, interest: Interest) -> Token {
        let fd = fd.as_raw_fd();
        assert!(
            self.len < CAPACITY,
            "a poll should have room for another descriptor"
        );
        assert!(
            self.fds[..self.len].iter().all(|entry| entry.fd != fd),
            "a descriptor should be added to a poll once"
        );
        self.fds[self.len] = libc::pollfd {
            fd,
            events: interest.0,
            revents: 0,
        };
        self.len += 1;
        Token(self.len - 1)
    }

    /// Blocks until a descriptor is ready or the stop is requested.
    ///
    /// A signal that interrupts the wait does not end it.
    ///
    /// # Errors
    ///
    /// Errors if `poll(2)` fails for a reason other than a signal.
    pub(crate) fn wait(self) -> io::Result<Ready> {
        self.wait_until(None)
    }

    /// Blocks like [`wait`](Self::wait), until `deadline` at the latest.
    ///
    /// A signal that interrupts the wait does not extend it past `deadline`.
    ///
    /// # Errors
    ///
    /// Errors if `poll(2)` fails for a reason other than a signal.
    pub(crate) fn wait_deadline(self, deadline: Instant) -> io::Result<Ready> {
        self.wait_until(Some(deadline))
    }

    /// Blocks until a descriptor is ready, the stop is requested or `deadline`
    /// passes, with no limit when `deadline` is `None`.
    ///
    /// # Errors
    ///
    /// Errors if `poll(2)` fails for a reason other than a signal.
    pub(crate) fn wait_until(mut self, deadline: Option<Instant>) -> io::Result<Ready> {
        let fds = &mut self.fds[..self.len];
        loop {
            // The time left is rounded up to whole milliseconds, so a wait
            // shorter than one still sleeps.
            let timeout_millis = deadline.map_or(-1, |deadline| {
                let left = deadline.saturating_duration_since(Instant::now());
                libc::c_int::try_from(left.as_micros().div_ceil(1000)).unwrap_or(libc::c_int::MAX)
            });
            // SAFETY: `fds` is a live slice of `pollfd` and the length matches.
            let ret =
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_millis) };
            // A timeout short of the deadline is waited out by the next call.
            if ret > 0 || (ret == 0 && timeout_millis == 0) {
                break;
            }
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
        let mut revents = [0; CAPACITY];
        for (found, fd) in revents.iter_mut().zip(fds.iter()) {
            *found = fd.revents;
        }
        Ok(Ready {
            revents,
            has_stop: self.has_stop,
        })
    }
}

/// What a wait found on each descriptor of its [`Poll`].
pub(crate) struct Ready {
    /// What `poll(2)` reported for each entry.
    revents: [libc::c_short; CAPACITY],
    /// Whether the first entry is the stop of the run.
    has_stop: bool,
}

impl Ready {
    /// Returns whether the stop of the run is requested.
    pub(crate) fn is_stopped(&self) -> bool {
        self.has_stop && self.revents[0] != 0
    }

    /// Returns whether the descriptor of `token` has data or a hangup to read.
    ///
    /// A hangup counts because a stream socket reports it with bytes still
    /// queued, and the read that follows returns them, then zero.
    pub(crate) fn is_readable(&self, token: Token) -> bool {
        self.revents[token.0] & (libc::POLLIN | libc::POLLHUP) != 0
    }

    /// Returns whether the peer of the descriptor of `token` hung up.
    pub(crate) fn is_hung_up(&self, token: Token) -> bool {
        self.revents[token.0] & libc::POLLHUP != 0
    }

    /// Returns whether the descriptor of `token` reported an error or is not
    /// open.
    ///
    /// A wait does not wait such a descriptor out: `poll(2)` reports it again
    /// at once.
    pub(crate) fn is_error(&self, token: Token) -> bool {
        self.revents[token.0] & (libc::POLLERR | libc::POLLNVAL) != 0
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use super::*;
    use crate::teardown::StopSource;

    /// Returns a deadline a test's wait reaches only when it finds nothing.
    fn soon() -> Instant {
        Instant::now() + Duration::from_millis(20)
    }

    #[test]
    fn stop_is_reported_beside_a_ready_descriptor() {
        let source = StopSource::new().unwrap();
        let stop = source.token();
        let (mut peer, ours) = UnixStream::pair().unwrap();
        peer.write_all(b"x").unwrap();

        let mut poll = Poll::with_stop(&stop);
        let incoming = poll.add(ours.as_fd(), Interest::READABLE);
        let ready = poll.wait().unwrap();
        assert!(!ready.is_stopped());
        assert!(ready.is_readable(incoming));

        source.request_stop();
        let mut poll = Poll::with_stop(&stop);
        let incoming = poll.add(ours.as_fd(), Interest::READABLE);
        let ready = poll.wait().unwrap();
        assert!(ready.is_stopped());
        assert!(
            ready.is_readable(incoming),
            "the descriptor is reported too"
        );
    }

    // The socket takes a write, which ends the wait well before its deadline,
    // and the wait reports that it has nothing to read.
    #[test]
    fn wait_ends_for_either_of_combined_interests() {
        let (mut peer, ours) = UnixStream::pair().unwrap();
        let deadline = || Instant::now() + Duration::from_secs(10);
        let mut poll = Poll::new();
        let socket = poll.add(ours.as_fd(), Interest::READABLE | Interest::WRITABLE);
        let start = Instant::now();
        let ready = poll.wait_deadline(deadline()).unwrap();
        assert!(start.elapsed() < Duration::from_secs(5), "room to write");
        assert!(!ready.is_readable(socket), "nothing was sent yet");

        peer.write_all(b"x").unwrap();
        let mut poll = Poll::new();
        let socket = poll.add(ours.as_fd(), Interest::READABLE | Interest::WRITABLE);
        let ready = poll.wait_deadline(deadline()).unwrap();
        assert!(ready.is_readable(socket));
    }

    #[test]
    #[should_panic(expected = "added to a poll once")]
    fn descriptor_added_twice_is_refused() {
        let (_peer, ours) = UnixStream::pair().unwrap();
        let mut poll = Poll::new();
        poll.add(ours.as_fd(), Interest::READABLE);
        poll.add(ours.as_fd(), Interest::HANGUP);
    }

    // The waits do not block, which is the use the interest is for alone.
    #[test]
    fn hangup_interest_reports_a_hangup_and_not_data() {
        let (mut peer, ours) = UnixStream::pair().unwrap();
        peer.write_all(b"x").unwrap();
        let mut poll = Poll::new();
        let watched = poll.add(ours.as_fd(), Interest::HANGUP);
        let ready = poll.wait_deadline(Instant::now()).unwrap();
        assert!(!ready.is_readable(watched), "unread data is not reported");
        assert!(!ready.is_hung_up(watched));

        drop(peer);
        let mut poll = Poll::new();
        let watched = poll.add(ours.as_fd(), Interest::HANGUP);
        let ready = poll.wait_deadline(Instant::now()).unwrap();
        assert!(ready.is_hung_up(watched));
    }

    // Whether a peer that shut down only its write half is a hangup differs by
    // host: it is one on macOS and none on Linux. Asking for the hangup alone
    // finds what asking for data finds.
    #[test]
    fn hangup_interest_agrees_with_readable_on_a_half_closed_peer() {
        let (peer, ours) = UnixStream::pair().unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();

        let mut poll = Poll::new();
        let incoming = poll.add(ours.as_fd(), Interest::READABLE);
        let ready = poll.wait_deadline(Instant::now()).unwrap();
        assert!(ready.is_readable(incoming), "the end of the stream");
        let hung_up = ready.is_hung_up(incoming);

        let mut poll = Poll::new();
        let watched = poll.add(ours.as_fd(), Interest::HANGUP);
        let ready = poll.wait_deadline(Instant::now()).unwrap();
        assert_eq!(ready.is_hung_up(watched), hung_up);
    }

    #[test]
    fn deadline_ends_a_wait_that_finds_nothing() {
        let source = StopSource::new().unwrap();
        let stop = source.token();
        let (_peer, ours) = UnixStream::pair().unwrap();
        let mut poll = Poll::with_stop(&stop);
        let incoming = poll.add(ours.as_fd(), Interest::READABLE);
        let start = Instant::now();
        let ready = poll.wait_deadline(soon()).unwrap();
        assert!(start.elapsed() >= Duration::from_millis(20));
        assert!(!ready.is_stopped());
        assert!(!ready.is_readable(incoming));
        assert!(!ready.is_error(incoming));
    }

    // A pipe whose reader has gone takes no write.
    #[test]
    fn descriptor_whose_peer_is_gone_is_an_error_or_hung_up() {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let mut poll = Poll::new();
        let room = poll.add(writer.as_fd(), Interest::WRITABLE);
        let ready = poll.wait().unwrap();
        assert!(ready.is_error(room) || ready.is_hung_up(room));
    }
}

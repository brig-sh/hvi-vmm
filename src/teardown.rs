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
//!
//! The same source carries a [`PauseGate`], which holds the helpers back from
//! the guest's devices while the control socket pauses the VM. A helper passes
//! the gate, with [`StopToken::enter`], around each piece of work that takes a
//! device mutex or writes guest RAM, and nowhere else. A helper that waits in a
//! `poll` or on a condition variable is outside the gate already, so a pause
//! does not wait for traffic to reach it.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::sync::lock_or_recover;

/// How long the stop waits for the vCPU threads, then for the helper threads,
/// and then for the ledger, after it is requested.
///
/// The waits the stop cannot interrupt are a plugin blocking in `request`, in
/// `safepoint` or on a thread it started with `VmHandle::spawn`, and a
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
        *lock_or_recover(&self.count) += 1;
        self.changed.notify_all();
    }

    /// Returns the number of threads that have finished.
    pub(crate) fn finished(&self) -> u32 {
        *lock_or_recover(&self.count)
    }

    /// Returns whether `count` threads have finished by `deadline`.
    ///
    /// It blocks until they have or until `deadline` passes.
    pub(crate) fn wait_for(&self, count: u32, deadline: Instant) -> bool {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let noted = lock_or_recover(&self.count);
        let (noted, _) = self
            .changed
            .wait_timeout_while(noted, timeout, |noted| *noted < count)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

/// The gate that holds the helper threads back from the guest's devices while
/// the VM is paused.
///
/// A helper passes it with [`enter`](Self::enter) before it takes a device
/// mutex or writes guest RAM, and leaves when the returned [`Admission`]
/// drops. [`pause`](Self::pause) closes the gate and waits until no helper is
/// inside, and a helper that comes to the gate while it is closed waits there
/// holding nothing. A helper never waits for its descriptor while inside, so a
/// pause waits at most for the work in progress and not for traffic.
///
/// The fast path of [`enter`](Self::enter) is two atomic operations and takes
/// no lock, since the network relay passes it once per frame.
///
/// A pause does not yet hold everything a checkpoint needs. The agent
/// bridge's reader reads inside the gate, so its bytes are either still in
/// the socket or already in the device. The console reader and the network
/// relays read first and enter the gate to deliver, so a pause can find one
/// console byte, one tap frame, or the gateway relay's buffered stream taken
/// off the host and not yet in the device. Pause and resume on one host lose
/// nothing, but a checkpoint taken then would drop it; capture has to take
/// those buffers too, or move those reads inside the gate. The console cannot
/// simply move: stdin is a shared terminal, which this does not make
/// non-blocking.
#[derive(Default)]
pub struct PauseGate {
    /// Set while a pause holds the gate closed.
    paused: AtomicBool,
    /// Set once the stop is requested, after which the gate admits everyone.
    stopped: AtomicBool,
    /// The number of helpers inside the gate.
    inside: AtomicU32,
    /// The lock the condition variable waits under.
    lock: Mutex<()>,
    /// Signals both "a helper left" (to the pause) and "the gate opened" (to
    /// the helpers waiting at it).
    cv: Condvar,
}

/// A helper's pass through a [`PauseGate`], held while it touches the guest's
/// devices. Dropping it leaves the gate.
#[must_use = "the helper is outside the gate once the admission drops"]
pub struct Admission<'a>(&'a PauseGate);

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        self.0.leave();
    }
}

impl PauseGate {
    /// Returns an open gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Passes the gate, first waiting while a pause holds it closed.
    ///
    /// The caller must hold no device mutex, since the pause that keeps it
    /// waiting may itself need one. Once the stop is requested the gate admits
    /// at once, so a helper waiting here sees the stop instead of keeping the
    /// join waiting.
    pub fn enter(&self) -> Admission<'_> {
        loop {
            // Raised before the flag is read, and both sequentially
            // consistent, as `pause` stores the flag before it reads the
            // count. One of the two sees the other.
            self.inside.fetch_add(1, Ordering::SeqCst);
            if !self.paused.load(Ordering::SeqCst) || self.stopped.load(Ordering::SeqCst) {
                return Admission(self);
            }
            self.leave();
            let mut guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            while self.paused.load(Ordering::SeqCst) && !self.stopped.load(Ordering::SeqCst) {
                guard = self.cv.wait(guard).unwrap_or_else(|p| p.into_inner());
            }
        }
    }

    /// Leaves the gate, waking a pause that waits for the last helper out.
    fn leave(&self) {
        if self.inside.fetch_sub(1, Ordering::SeqCst) == 1 && self.paused.load(Ordering::SeqCst) {
            // Under the lock, so the pause cannot be between its check of the
            // count and its wait.
            let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            self.cv.notify_all();
        }
    }

    /// Closes the gate and waits, for at most `timeout`, until no helper is
    /// inside.
    ///
    /// The stop ends the wait too, since the join of the helpers, this
    /// caller's thread among them, has a shorter deadline than a pause.
    ///
    /// # Errors
    ///
    /// Errors with the number of helpers still inside at the deadline or at
    /// the stop. The gate is open again by then, since a pause that leaves a
    /// helper running is no pause, and a gate left closed would hold back
    /// every helper for nothing.
    pub fn pause(&self, timeout: Duration) -> Result<(), u32> {
        self.paused.store(true, Ordering::SeqCst);
        let guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let (guard, result) = self
            .cv
            .wait_timeout_while(guard, timeout, |_| {
                self.inside.load(Ordering::SeqCst) != 0 && !self.stopped.load(Ordering::SeqCst)
            })
            .unwrap_or_else(|p| p.into_inner());
        drop(guard);
        if result.timed_out() || self.stopped.load(Ordering::SeqCst) {
            let inside = self.inside.load(Ordering::SeqCst);
            self.unpause();
            return Err(inside);
        }
        Ok(())
    }

    /// Opens the gate and wakes every helper waiting at it.
    pub fn unpause(&self) {
        self.paused.store(false, Ordering::SeqCst);
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        self.cv.notify_all();
    }

    /// Returns whether a pause holds the gate closed.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Opens the gate for good, for the stop.
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        self.cv.notify_all();
    }
}

/// The requesting end of a stop.
pub struct StopSource {
    write: UnixStream,
    read: Arc<UnixStream>,
    /// The gate every token passes, opened for good by the stop.
    gate: Arc<PauseGate>,
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
            gate: Arc::new(PauseGate::new()),
        })
    }

    /// Returns a token for a helper thread.
    #[must_use]
    pub fn token(&self) -> StopToken {
        StopToken {
            read: Arc::clone(&self.read),
            gate: Arc::clone(&self.gate),
        }
    }

    /// Returns the gate the tokens pass, which a pause closes.
    #[must_use]
    pub fn gate(&self) -> &Arc<PauseGate> {
        &self.gate
    }

    /// Requests the stop, so every [`StopToken::wait`] returns `false` from now
    /// on and the gate admits every helper.
    pub fn request_stop(&self) {
        let _ = self.write.shutdown(std::net::Shutdown::Write);
        self.gate.stop();
    }
}

impl Drop for StopSource {
    // Dropping the write half reports the stop to every poll. A helper waiting
    // at a closed gate polls nothing, so the drop opens the gate too, or a
    // `boot` that unwound during a pause would leave it waiting for good.
    fn drop(&mut self) {
        self.gate.stop();
    }
}

/// A helper thread's view of a [`StopSource`].
///
/// Its descriptor becomes readable when the stop is requested and stays
/// readable, so a thread can add it to a `poll` set beside its own descriptors.
/// Every token of a run shares the descriptor, so a thread polls it and neither
/// reads it nor shuts it down.
#[derive(Clone)]
pub struct StopToken {
    /// The read half of the pair, readable once the stop is requested.
    read: Arc<UnixStream>,
    /// The gate the helper passes before it touches the guest's devices.
    gate: Arc<PauseGate>,
}

impl AsFd for StopToken {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.read.as_fd()
    }
}

impl StopToken {
    /// Passes the source's [`PauseGate`], waiting while a pause holds it
    /// closed. See [`PauseGate::enter`].
    pub fn enter(&self) -> Admission<'_> {
        self.gate.enter()
    }

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
        let mut fds = [pollfd(fd.as_raw_fd()), pollfd(self.read.as_raw_fd())];
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
        let mut fds = [out, pollfd(self.read.as_raw_fd())];
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
        let mut fds = [pollfd(fd.as_raw_fd()), pollfd(self.read.as_raw_fd())];
        if poll(&mut fds, Some(Instant::now())).is_err() {
            return false;
        }
        let gone = libc::POLLHUP | libc::POLLERR | libc::POLLNVAL;
        fds[1].revents == 0 && fds[0].revents & gone == 0
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
        let mut fds = [pollfd(self.read.as_raw_fd())];
        poll(&mut fds, Instant::now().checked_add(duration))?;
        Ok(fds[0].revents == 0)
    }
}

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

    /// Spawns a helper that passes the gate, signals that it is inside, and
    /// stays inside until `leave` receives.
    fn inside_helper(
        token: StopToken,
    ) -> (
        JoinHandle<()>,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (leave, leave_rx) = std::sync::mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _in = token.enter();
            entered_tx.send(()).unwrap();
            let _ = leave_rx.recv();
        });
        (helper, entered, leave)
    }

    // A pause that returned with a helper still inside would let it write a
    // receive buffer into guest RAM under a checkpoint that thinks the RAM is
    // still.
    #[test]
    fn pause_waits_for_the_helper_inside() {
        let source = StopSource::new().expect("pair");
        let (helper, entered, leave) = inside_helper(source.token());
        entered.recv().unwrap();
        let gate = Arc::clone(source.gate());
        let pause = std::thread::spawn(move || gate.pause(Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !pause.is_finished(),
            "the pause returned with a helper inside"
        );
        leave.send(()).unwrap();
        assert_eq!(pause.join().unwrap(), Ok(()));
        helper.join().unwrap();
        assert!(source.gate().is_paused());
    }

    #[test]
    fn helper_waits_at_a_closed_gate_until_unpause() {
        let source = StopSource::new().expect("pair");
        source.gate().pause(Duration::from_secs(1)).unwrap();
        let token = source.token();
        let passed = Arc::new(AtomicBool::new(false));
        let helper = {
            let passed = Arc::clone(&passed);
            std::thread::spawn(move || {
                let _in = token.enter();
                passed.store(true, Ordering::SeqCst);
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !passed.load(Ordering::SeqCst),
            "a helper passed a closed gate"
        );
        source.gate().unpause();
        helper.join().unwrap();
        assert!(passed.load(Ordering::SeqCst));
    }

    // Helpers blocked in a poll on an idle descriptor are outside the gate, so
    // a pause must not wait for traffic that may never come.
    #[test]
    fn pause_does_not_wait_for_helpers_blocked_in_a_poll() {
        let source = StopSource::new().expect("pair");
        let mut peers = Vec::new();
        let mut helpers = Vec::new();
        for _ in 0..3 {
            let (peer, idle) = UnixStream::pair().expect("pair");
            peers.push(peer);
            let token = source.token();
            helpers.push(std::thread::spawn(move || {
                while token.wait(idle.as_fd()).expect("poll") {
                    let _in = token.enter();
                }
            }));
        }
        std::thread::sleep(Duration::from_millis(20));
        let started = Instant::now();
        assert_eq!(source.gate().pause(Duration::from_secs(5)), Ok(()));
        assert!(started.elapsed() < Duration::from_millis(100));
        // Traffic that arrives during the pause waits at the gate.
        peers[0].write_all(b"x").expect("write");
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(source.gate().inside.load(Ordering::SeqCst), 0);
        source.gate().unpause();
        source.request_stop();
        for helper in helpers {
            helper.join().unwrap();
        }
    }

    #[test]
    fn pause_that_times_out_opens_the_gate_again() {
        let source = StopSource::new().expect("pair");
        let (helper, entered, leave) = inside_helper(source.token());
        entered.recv().unwrap();
        assert_eq!(source.gate().pause(Duration::from_millis(50)), Err(1));
        assert!(!source.gate().is_paused());
        // Another helper passes at once.
        drop(source.token().enter());
        leave.send(()).unwrap();
        helper.join().unwrap();
    }

    // A pause that waited out its own deadline after the stop would keep the
    // control thread past the join's shorter one.
    #[test]
    fn stop_ends_a_pause_waiting_for_a_helper() {
        let source = StopSource::new().expect("pair");
        let (helper, entered, leave) = inside_helper(source.token());
        entered.recv().unwrap();
        let gate = Arc::clone(source.gate());
        let pause = std::thread::spawn(move || gate.pause(Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(20));
        source.request_stop();
        let deadline = Instant::now() + STOP_TIMEOUT;
        while !pause.is_finished() {
            assert!(Instant::now() < deadline, "the pause outlived the stop");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pause.join().unwrap(), Err(1));
        leave.send(()).unwrap();
        helper.join().unwrap();
    }

    // A helper waiting at a closed gate polls nothing, so the stop has to open
    // the gate or the join of the helpers runs out its deadline.
    #[test]
    fn stop_admits_a_helper_waiting_at_a_closed_gate() {
        let source = StopSource::new().expect("pair");
        source.gate().pause(Duration::from_secs(1)).unwrap();
        let token = source.token();
        let helper = std::thread::spawn(move || drop(token.enter()));
        std::thread::sleep(Duration::from_millis(20));
        source.request_stop();
        assert!(join_by("helper", helper, Instant::now() + STOP_TIMEOUT).is_ok());
    }

    #[test]
    fn dropping_source_admits_a_helper_waiting_at_a_closed_gate() {
        let source = StopSource::new().expect("pair");
        source.gate().pause(Duration::from_secs(1)).unwrap();
        let token = source.token();
        let helper = std::thread::spawn(move || drop(token.enter()));
        std::thread::sleep(Duration::from_millis(20));
        drop(source);
        assert!(join_by("helper", helper, Instant::now() + STOP_TIMEOUT).is_ok());
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

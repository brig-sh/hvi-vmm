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

//! The loop that owns the stop of a run.
//!
//! Once the vCPU threads are spawned, the thread that called `boot` waits on a
//! [`Waker`]. A vCPU thread reports how its loop ended and writes the wake as
//! it exits. [`run_to_stop`] then stops the VM, joins the vCPU threads and the
//! I/O threads by their deadlines, writes out the ledger tail and returns how
//! the run ended. No vCPU thread stops the VM itself, so the order of the stop
//! and the reason it reports are decided in one place.
//!
//! The wake is a pipe, and `write` and `read` are on both seccomp allowlists.
//! The write end is nonblocking, so a full pipe means a wake is already pending
//! and the write returns.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::time::Instant;

use crate::config::Stop;
use crate::hypervisor::guest::Guest;
use crate::hypervisor::vcpus::{Kick, Outcome, VcpuThreads};
use crate::io_threads::IoThreads;
use crate::sync::try_lock_until;
use crate::teardown::{poll, pollfd, STOP_TIMEOUT};
use crate::LOG_PREFIX;

/// The channel that wakes the loop in [`run_to_stop`].
pub(crate) struct Waker {
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

    /// Wakes the loop.
    ///
    /// A full pipe already holds a wake, so the write's error is dropped.
    pub(crate) fn wake(&self) {
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
    pub(crate) fn wait(&self, deadline: Option<Instant>) -> io::Result<()> {
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

/// Runs the guest from its spawned vCPU threads to its stop.
///
/// It returns how the run ended. `failure` is a failure the caller met as it
/// started the run, from the spawn of the vCPU threads on. Without one, the
/// calling thread waits until a vCPU thread exits. It then stops the VM, joins
/// the vCPU threads and stops `io_threads`, each by [`STOP_TIMEOUT`], and
/// writes out the ledger tail, which the flush cadence alone would leave in the
/// buffer. A thread left running may hold the ledger, so the flush waits for it
/// for at most [`STOP_TIMEOUT`] and is skipped when it is still held.
///
/// # Errors
///
/// Errors with `failure`, else with the failure a vCPU reported, else with a
/// thread that did not stop in time. A thread left running is named after the
/// failure, or reported with how the guest stopped, since the error takes the
/// place of that stop.
pub(crate) fn run_to_stop<K: Kick>(
    guest: &Guest<K>,
    threads: VcpuThreads,
    mut failure: Option<Box<dyn std::error::Error>>,
    io_threads: IoThreads,
) -> Result<Stop, Box<dyn std::error::Error>> {
    if failure.is_none() {
        if let Err(e) = guest.vcpus.wait_for_exit() {
            failure = Some(format!("waiting for the vCPUs: {e}").into());
        }
    }
    guest.vcpus.stop();
    let mut left_running = threads.join_timeout(&guest.vcpus, STOP_TIMEOUT).err();

    // The I/O threads stop once the vCPUs have exited or been left running; see
    // `teardown`.
    if let Err(e) = io_threads.stop() {
        left_running.get_or_insert(e);
    }
    let ledger = try_lock_until(&guest.ledger, Instant::now() + STOP_TIMEOUT);
    match ledger {
        Some(mut ledger) => ledger.flush(),
        None => {
            stderrln!("{LOG_PREFIX} the ledger is still locked; its tail is not written");
        }
    }

    let outcome = guest.vcpus.outcome();
    if let Some(e) = failure {
        // `failure` is the one returned, so a vCPU failure behind it is
        // printed.
        if let Outcome::Failed(text) = outcome {
            stderrln!("{LOG_PREFIX} {text}");
        }
        return Err(match left_running {
            Some(left) => format!("{e}, and {left}").into(),
            None => e,
        });
    }
    match (outcome, left_running) {
        (outcome, None) => outcome.into_result(),
        (Outcome::Failed(text), Some(e)) => Err(format!("{text}, and {e}").into()),
        (Outcome::Stopped(stop), Some(e)) => {
            Err(format!("{e}, after the guest stopped with {stop:?}").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::events::Emitter;
    use crate::hypervisor::vcpus::Vcpus;
    use crate::memory::{GuestRam, RamRegion, SharedRam};
    use crate::plugin::GuestArch;

    /// A kicker that reaches no thread.
    struct NoopKicker;

    impl Kick for NoopKicker {
        fn kick(&self, _cpu: u32) {}

        fn kick_all(&self) {}
    }

    /// The code a test vCPU thread runs.
    type Body = Box<dyn FnOnce() + Send>;

    /// Returns a guest with `count` vCPUs, one megabyte of RAM, no devices and
    /// a ledger that writes nowhere.
    fn guest(count: u32) -> Guest<NoopKicker> {
        let shared_ram = SharedRam::new(RamRegion::ALIGN as usize).unwrap();
        let ram = GuestRam::new(&shared_ram, &[shared_ram.region_at(0)]).unwrap();
        Guest {
            arch: GuestArch::X86_64,
            sandbox_id: String::new(),
            ram: Arc::new(ram),
            shared_ram,
            ledger: Arc::new(Mutex::new(Emitter::new(None, "test").unwrap())),
            block: None,
            net: None,
            vsock: None,
            vcpus: Arc::new(Vcpus::new(
                count,
                NoopKicker,
                Arc::new(Waker::new().unwrap()),
            )),
        }
    }

    /// Runs `bodies` on the vCPU threads of `guest`, then runs the guest to its
    /// stop with `failure` as the caller's.
    ///
    /// The stop sends the kick signal to the console reader, so the handler is
    /// installed first, as `boot` installs it.
    fn run(
        guest: &Guest<NoopKicker>,
        bodies: Vec<Body>,
        failure: Option<&str>,
    ) -> Result<Stop, String> {
        crate::signal::install_kick_handler();
        let (threads, spawned) = guest.vcpus.spawn(bodies, |_, body| body());
        spawned.unwrap();
        run_to_stop(guest, threads, failure.map(Into::into), IoThreads::idle())
            .map_err(|e| e.to_string())
    }

    #[test]
    fn vcpu_exit_ends_the_run_with_its_stop() {
        let guest = guest(2);
        let vcpus = Arc::clone(&guest.vcpus);
        let reset: Body = Box::new(move || vcpus.report(Outcome::Stopped(Stop::SystemReset)));
        // The second vCPU runs until the stop.
        let vcpus = Arc::clone(&guest.vcpus);
        let running: Body = Box::new(move || {
            while vcpus.is_running() {
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let start = Instant::now();
        let result = run(&guest, vec![reset, running], None);
        assert!(matches!(result, Ok(Stop::SystemReset)), "{result:?}");
        assert!(start.elapsed() < STOP_TIMEOUT);
    }

    #[test]
    fn caller_failure_is_returned_over_a_vcpu_failure() {
        let guest = guest(1);
        let vcpus = Arc::clone(&guest.vcpus);
        let failed: Body = Box::new(move || vcpus.report(Outcome::Failed("vcpu0: failed".into())));
        let result = run(&guest, vec![failed], Some("the filter did not install"));
        assert_eq!(result.unwrap_err(), "the filter did not install");
    }

    // The error names the vCPU thread still running, not the one that exited,
    // and the stop it takes the place of.
    #[test]
    fn thread_left_running_fails_the_run_after_its_stop() {
        let guest = guest(2);
        let vcpus = Arc::clone(&guest.vcpus);
        let off: Body = Box::new(move || vcpus.report(Outcome::Stopped(Stop::SystemOff)));
        let (release, released) = mpsc::channel::<()>();
        let stuck: Body = Box::new(move || {
            let _ = released.recv();
        });
        let result = run(&guest, vec![off, stuck], None);
        release.send(()).unwrap();
        assert_eq!(
            result.unwrap_err(),
            format!(
                "vcpu1 did not stop within {STOP_TIMEOUT:?}, after the guest stopped with SystemOff"
            )
        );
    }

    #[test]
    fn thread_left_running_is_named_after_a_vcpu_failure() {
        let guest = guest(2);
        let vcpus = Arc::clone(&guest.vcpus);
        let failed: Body = Box::new(move || vcpus.report(Outcome::Failed("vcpu0: failed".into())));
        let (release, released) = mpsc::channel::<()>();
        let stuck: Body = Box::new(move || {
            let _ = released.recv();
        });
        let result = run(&guest, vec![failed, stuck], None);
        release.send(()).unwrap();
        assert_eq!(
            result.unwrap_err(),
            format!("vcpu0: failed, and vcpu1 did not stop within {STOP_TIMEOUT:?}")
        );
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

    // A full pipe already holds a wake, so a wake written to it must return
    // rather than block the vCPU thread that exits.
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

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
//! Once the vCPU threads are spawned, the thread that called `boot` waits on
//! the run's [`StopHandle`]. A vCPU thread reports how its loop ended and wakes
//! the handle as it exits. [`run_to_stop`] then stops the VM and tears the run
//! down. Only this loop stops the VM after the spawn, so the order of the stop
//! and the reason it reports are decided in one place. The one exception is the
//! panic hook of a binary that aborts, which stops the vCPUs and records the
//! failure through [`CURRENT_RUN`].
//!
//! [`StopHandle`]: crate::run::StopHandle

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::Instant;

use serde::Serialize;

use crate::config::Stop;
use crate::events::{Batch, Ledger};
use crate::hypervisor::guest::Guest;
use crate::hypervisor::vcpus::{Kick, Outcome, StopVcpus, VcpuThreads};
use crate::io_threads::IoThreads;
use crate::plugin::GuestArch;
use crate::teardown::STOP_TIMEOUT;
use crate::LOG_PREFIX;

/// The slot every run of this process claims.
pub(crate) static RUN_SLOT: RunSlot = RunSlot::new();

/// What a [`RunSlot`] holds: no run.
const FREE: u8 = 0;
/// What a [`RunSlot`] holds: a run in progress.
const HELD: u8 = 1;
/// What a [`RunSlot`] holds: a run that left something behind, for good.
const KEPT: u8 = 2;

/// The one run a process has at a time.
///
/// Runs that overlap share stdin, the terminal settings, the stop signals and
/// the seccomp state, so a run claims the slot as `boot` starts and releases it
/// as `boot` returns. A run that left a thread running, or whose `boot` unwound
/// from a panic, keeps the slot for the life of the process, since what it left
/// behind still shares all of that.
pub(crate) struct RunSlot(AtomicU8);

impl RunSlot {
    /// Returns a free slot.
    pub(crate) const fn new() -> Self {
        RunSlot(AtomicU8::new(FREE))
    }

    /// Claims the slot for a run.
    ///
    /// # Errors
    ///
    /// Errors while another run holds the slot, and once a run has kept it.
    pub(crate) fn claim(&self) -> Result<RunClaim<'_>, &'static str> {
        match self
            .0
            .compare_exchange(FREE, HELD, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => Ok(RunClaim {
                slot: self,
                keep: false,
            }),
            Err(KEPT) => Err(
                "an earlier run left a thread running or panicked, so this process cannot start another",
            ),
            Err(_) => Err("another run is in progress, and a process runs one guest at a time"),
        }
    }
}

/// A run's hold on a [`RunSlot`], which dropping it releases.
pub(crate) struct RunClaim<'a> {
    /// The slot this claim holds.
    slot: &'a RunSlot,
    /// Whether the run left a thread running.
    keep: bool,
}

impl RunClaim<'_> {
    /// Keeps the slot held after the run, which left a thread running.
    pub(crate) fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for RunClaim<'_> {
    fn drop(&mut self) {
        let state = if self.keep || std::thread::panicking() {
            KEPT
        } else {
            FREE
        };
        self.slot.0.store(state, Ordering::SeqCst);
    }
}

/// The process's [`CurrentRun`].
pub(crate) static CURRENT_RUN: CurrentRun = CurrentRun::new();

/// A slot for the run in progress.
pub(crate) struct CurrentRun(Mutex<Option<Current>>);

/// What [`CurrentRun`] holds of the run in progress.
#[derive(Clone)]
struct Current {
    /// The run's ledger.
    ledger: Arc<Ledger>,
    /// The run's vCPUs.
    vcpus: Arc<dyn StopVcpus>,
}

impl CurrentRun {
    /// Returns a slot with no run in it.
    pub(crate) const fn new() -> Self {
        CurrentRun(Mutex::new(None))
    }

    /// Makes the run of `ledger` and `vcpus` current once `f` has run, and
    /// until the returned guard drops.
    ///
    /// `f` runs with the slot held, so a panic on another thread does not find
    /// the run current before `f` returns.
    pub(crate) fn enter(
        &self,
        ledger: &Arc<Ledger>,
        vcpus: Arc<dyn StopVcpus>,
        f: impl FnOnce(),
    ) -> EnterGuard<'_> {
        let mut current = self.0.lock().unwrap();
        f();
        *current = Some(Current {
            ledger: Arc::clone(ledger),
            vcpus,
        });
        EnterGuard(self)
    }

    /// Stops the vCPUs of the current run with `failure` as how it ended,
    /// without waiting for them, unless another thread holds the slot.
    pub(crate) fn stop_vcpus(&self, failure: &str) {
        if let Ok(current) = self.0.try_lock() {
            if let Some(current) = current.as_ref() {
                current.vcpus.stop_without_blocking(failure);
            }
        }
    }

    /// Writes a `vmm.stop` record with `reason` `failed` and `error` as the
    /// last record of the current run's ledger.
    ///
    /// It stops the vCPUs first, with `error` as how the run ended, and waits
    /// for them to exit. It waits at most [`STOP_TIMEOUT`] in all, for the
    /// slot, the vCPUs and the ledger's writer. The vCPUs get the first half.
    /// The ledger is then closed whether or not they have exited, and the
    /// writer gets the rest. It returns whether the record was written.
    ///
    /// It writes nothing when no run is current. When the ledger is already
    /// closed, by the run's own `vmm.stop` record or another panic's, it writes
    /// nothing and waits for that record until the deadline. On a ledger's
    /// writer thread it does not wait, since it cannot wait for its own write.
    pub(crate) fn record_failure(&self, error: &str) -> bool {
        let start = Instant::now();
        let deadline = start + STOP_TIMEOUT;
        // No thread holds the slot for long, so it is tried until the deadline.
        // A panic on a thread that holds the slot then gives up at the deadline
        // instead of waiting for itself.
        let current = loop {
            match self.0.try_lock() {
                Ok(current) => break current,
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    crate::teardown::sleep_step(deadline);
                }
                Err(_) => return false,
            }
        };
        let Some(Current { ledger, vcpus }) = current.clone() else {
            return false;
        };
        drop(current);
        // Every `block` and `net` record comes from a vCPU thread, so once the
        // vCPUs have exited, the closed ledger drops none of them.
        vcpus.stop_without_blocking(error);
        vcpus.wait_for_exits_until(start + STOP_TIMEOUT / 2);
        let stop = StopRecord {
            reason: "failed",
            signal: None,
            error: Some(error),
            dropped: ledger.dropped(),
        };
        let deadline = if crate::events::is_writer_thread() {
            Instant::now()
        } else {
            deadline
        };
        ledger
            .close_with(deadline, |batch| {
                batch.emit_payload("vmm", "vmm.stop", &stop);
            })
            .is_ok()
    }
}

/// A guard that keeps a run current, from [`CurrentRun::enter`] until it drops.
#[must_use]
pub(crate) struct EnterGuard<'a>(&'a CurrentRun);

impl Drop for EnterGuard<'_> {
    fn drop(&mut self) {
        // The ledger is dropped once the slot is released, since dropping its
        // last handle can wait for the writer.
        let current = self.0 .0.lock().unwrap().take();
        drop(current);
    }
}

/// The error of a run that left a thread running.
///
/// It keeps the error that failed the run as it was, beside the thread left
/// running, so [`BootError::get_ref`](crate::config::BootError::get_ref)
/// returns the former. It reads as the error, then the thread.
/// [`boot`](crate::boot) keeps the run's [`RunClaim`] when it sees one.
#[derive(Debug)]
pub(crate) struct LeftRunning {
    /// The error that failed the run.
    pub(crate) error: Box<dyn std::error::Error + Send + Sync>,
    /// The thread left running, when `error` does not already name it.
    pub(crate) left: Option<io::Error>,
}

impl fmt::Display for LeftRunning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.left {
            Some(left) => write!(f, "{}, and {left}", self.error),
            None => fmt::Display::fmt(&self.error, f),
        }
    }
}

impl std::error::Error for LeftRunning {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

/// A guard that stops the VM if the thread that owns the stop unwinds from a
/// panic.
///
/// The I/O threads stop as the run's `IoThreads` drops in the same unwind.
struct StopOnUnwind<'a, K: Kick> {
    /// The vCPUs the guard stops.
    vcpus: &'a crate::hypervisor::vcpus::Vcpus<K>,
}

impl<K: Kick> Drop for StopOnUnwind<'_, K> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.vcpus.stop();
        }
    }
}

/// Writes the run's `vmm.start` record to the ledger.
///
/// `confined` says whether the run's confinement is on. Call it before the vCPU
/// threads are spawned, so the record comes before any record the VMM writes
/// for the run. A plugin can write earlier, from `on_attach` or from a thread
/// it started there.
///
/// The run is the [`CURRENT_RUN`] from that record on, until the returned guard
/// drops. Hold the guard until [`run_to_stop`] returns.
///
/// The call waits for the ledger's writer for at most [`STOP_TIMEOUT`], and not
/// at all while the ledger's writes fail. A record not written by then stays
/// buffered.
pub(crate) fn record_start<K: Kick + 'static>(
    guest: &Guest<K>,
    confined: bool,
) -> EnterGuard<'static> {
    let start = StartRecord {
        arch: match guest.arch {
            GuestArch::Aarch64 => "aarch64",
            GuestArch::X86_64 => "x86_64",
        },
        vcpus: guest.vcpus.count(),
        mem_bytes: guest.ram.regions().iter().map(|region| region.size).sum(),
        confined,
        core_version: crate::CORE_VERSION,
    };
    // The start record is added as the run becomes current, so a panic writes
    // the run's `vmm.stop` record only after it. It is added without waiting,
    // since the slot is held, and then waited for.
    let mut added = Ok(());
    let current = CURRENT_RUN.enter(&guest.ledger, Arc::clone(&guest.vcpus) as _, || {
        added = guest.ledger.batch_until(Instant::now(), |batch| {
            batch.emit_payload("vmm", "vmm.start", &start);
        });
    });
    let written = match added {
        Err(e) if e.kind() != io::ErrorKind::TimedOut => Err(e),
        _ => guest
            .ledger
            .batch_until(Instant::now() + STOP_TIMEOUT, |_| {}),
    };
    if let Err(e) = written {
        stderrln!("{LOG_PREFIX} writing the start record: {e}");
    }
    current
}

/// Runs the guest from its spawned vCPU threads to its stop.
///
/// It returns how the run ended. `failure` is a failure the caller met as it
/// started the run, from the spawn of the vCPU threads on. Without one, the
/// calling thread waits until a vCPU thread exits or a stop is requested. It
/// then stops the VM, joins the vCPU threads and stops `io_threads`, each by
/// [`STOP_TIMEOUT`].
///
/// The loop writes the rest of the run's lifecycle to the ledger, after the
/// record of [`record_start`]: a `vmm.vcpu_started` record for each vCPU that
/// enters its run loop, and last a `vmm.stop` record with how the run ended. It
/// adds a `vmm.vcpu_started` record without waiting for the ledger's writer.
/// The `vmm.stop` record closes the ledger, and the loop waits for the writer
/// to write it for at most [`STOP_TIMEOUT`].
///
/// # Errors
///
/// Errors with the first of these that applies: `failure`, the failure a thread
/// reported, or a thread that did not stop in time. A thread left running is
/// named after the failure. Alone, its error also names how the run stopped,
/// since it takes the place of that stop.
pub(crate) fn run_to_stop<K: Kick>(
    guest: &Guest<K>,
    threads: VcpuThreads,
    mut failure: Option<Box<dyn std::error::Error + Send + Sync>>,
    io_threads: IoThreads<K>,
) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    // A panic from here on stops the VM, and the I/O threads as `io_threads`
    // drops, so the guest does not run on with nothing left to stop it.
    let _unwind = StopOnUnwind {
        vcpus: &guest.vcpus,
    };
    let mut announced = 0;
    if failure.is_none() {
        let waited = guest.vcpus.wait_for_stop(|| {
            let started = guest.vcpus.started_after(announced);
            if !started.is_empty() {
                let _ = guest.ledger.batch_until(Instant::now(), |batch| {
                    record_vcpus_started(batch, &started);
                });
                announced += started.len();
            }
        });
        if let Err(e) = waited {
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

    let result: Result<Stop, Box<dyn std::error::Error + Send + Sync>> =
        match (failure, guest.vcpus.outcome(), left_running) {
            (Some(e), outcome, left_running) => {
                // `failure` is the one returned, so a thread's failure behind
                // it is printed.
                if let Outcome::Failed(text) = outcome {
                    stderrln!("{LOG_PREFIX} {text}");
                }
                match left_running {
                    Some(left) => Err(Box::new(LeftRunning {
                        error: e,
                        left: Some(left),
                    })),
                    None => Err(e),
                }
            }
            (None, outcome, None) => outcome.into_result(),
            (None, Outcome::Failed(text), Some(e)) => Err(Box::new(LeftRunning {
                error: text.into(),
                left: Some(e),
            })),
            (None, Outcome::Stopped(stop), Some(e)) => Err(Box::new(LeftRunning {
                error: format!("{e}, after the run stopped with {stop:?}").into(),
                left: None,
            })),
        };
    let error = result.as_ref().err().map(ToString::to_string);
    let stop = StopRecord {
        reason: match &result {
            Ok(Stop::SystemOff) => "system_off",
            Ok(Stop::SystemReset) => "system_reset",
            Ok(Stop::Requested) => "requested",
            Err(_) => "failed",
        },
        // A signal is the cause only when it asked first and the run stopped on
        // the request.
        signal: match &result {
            Ok(Stop::Requested) => guest
                .vcpus
                .stop_handle()
                .first_signal()
                .and_then(signal_hook::low_level::signal_name),
            _ => None,
        },
        error: error.as_deref(),
        dropped: guest.ledger.dropped(),
    };
    let written = guest
        .ledger
        .close_with(Instant::now() + STOP_TIMEOUT, |batch| {
            // A vCPU that started after the last wake is recorded before the
            // stop.
            record_vcpus_started(batch, &guest.vcpus.started_after(announced));
            batch.emit_payload("vmm", "vmm.stop", &stop);
        });
    if let Err(e) = written {
        stderrln!("{LOG_PREFIX} writing the stop record: {e}");
    }
    result
}

/// Adds a `vmm.vcpu_started` record for each of `cpus` to `batch`.
fn record_vcpus_started(batch: &mut Batch, cpus: &[u32]) {
    for &cpu in cpus {
        batch.emit_payload("vmm", "vmm.vcpu_started", &VcpuStartedRecord { vcpu: cpu });
    }
}

/// The payload of the `vmm.start` record.
#[derive(Serialize)]
struct StartRecord {
    /// The guest architecture, `aarch64` or `x86_64`.
    arch: &'static str,
    /// The number of vCPUs.
    vcpus: u32,
    /// The size of guest RAM in bytes.
    mem_bytes: u64,
    /// Whether the run's confinement is on.
    confined: bool,
    /// The version of this crate, the VMM core.
    core_version: &'static str,
}

/// The payload of a `vmm.vcpu_started` record.
#[derive(Serialize)]
struct VcpuStartedRecord {
    /// The id of the vCPU that entered its run loop.
    vcpu: u32,
}

/// The payload of the `vmm.stop` record.
#[derive(Serialize)]
struct StopRecord<'a> {
    /// How the run ended, one of `system_off`, `system_reset`, `requested` or
    /// `failed`.
    reason: &'static str,
    /// The name of the signal that asked first, such as `SIGTERM`, when the run
    /// stopped on its request.
    #[serde(skip_serializing_if = "Option::is_none")]
    signal: Option<&'static str>,
    /// The error `boot` returns, when the run failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    /// The number of `block` and `net` records the ledger dropped because its
    /// buffer was full, when it dropped any.
    #[serde(skip_serializing_if = "is_zero")]
    dropped: u64,
}

/// Returns whether `count` is zero.
fn is_zero(count: &u64) -> bool {
    *count == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::events::{CapturedEvent, Ledger};

    use crate::hypervisor::guest::tests::{guest, NoopKicker};
    use crate::run::StopHandle;

    /// The code a test vCPU thread runs.
    type Body = Box<dyn FnOnce() + Send>;

    #[test]
    fn stop_record_carries_dropped_only_when_records_were_dropped() {
        let stop = |dropped| {
            serde_json::to_string(&StopRecord {
                reason: "requested",
                signal: None,
                error: None,
                dropped,
            })
            .unwrap()
        };
        assert_eq!(stop(0), r#"{"reason":"requested"}"#);
        assert_eq!(stop(670), r#"{"reason":"requested","dropped":670}"#);
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
        run_to_stop(
            guest,
            threads,
            failure.map(Into::into),
            IoThreads::idle(Arc::clone(&guest.vcpus)),
        )
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
    fn request_ends_the_run() {
        let guest = guest(1);
        let vcpus = Arc::clone(&guest.vcpus);
        let running: Body = Box::new(move || {
            while vcpus.is_running() {
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        guest.vcpus.stop_handle().request_stop();
        let start = Instant::now();
        let result = run(&guest, vec![running], None);
        assert!(matches!(result, Ok(Stop::Requested)), "{result:?}");
        assert!(start.elapsed() < STOP_TIMEOUT);
    }

    #[test]
    fn vcpu_failure_is_returned_over_a_request() {
        let guest = guest(1);
        let vcpus = Arc::clone(&guest.vcpus);
        let failed: Body = Box::new(move || vcpus.report(Outcome::Failed("vcpu0: failed".into())));
        guest.vcpus.stop_handle().request_stop();
        assert_eq!(
            run(&guest, vec![failed], None).unwrap_err(),
            "vcpu0: failed"
        );
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
                "vcpu1 did not stop within {STOP_TIMEOUT:?}, after the run stopped with SystemOff"
            )
        );
    }

    // The writer's writes block while the vCPUs start and the guest stops. The
    // second vCPU enters its run loop only after it sees the stop, which comes
    // after the loop's last wake, so the closing batch records it. The writer
    // resumes once that vCPU has entered its run loop. The host-path ban in
    // clippy.toml is aimed at the virtio-fs device, where every component of a
    // path comes from the guest. This test reads the ledger file it made.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn vcpus_started_while_the_writer_stalls_are_recorded_before_the_stop() {
        let path = std::env::temp_dir().join(format!("hvi-run-{}.ndjson", std::process::id()));
        let mut guest = guest(2);
        guest.ledger = Arc::new(Ledger::new(Some(path.to_str().unwrap()), "test").unwrap());
        guest.ledger.set_paused(true);
        let (stopped, has_stopped) = mpsc::channel::<()>();
        let ledger = Arc::clone(&guest.ledger);
        let resumer = std::thread::spawn(move || {
            has_stopped.recv().unwrap();
            ledger.set_paused(false);
        });

        let vcpus = Arc::clone(&guest.vcpus);
        let off: Body = Box::new(move || {
            vcpus.mark_started(0);
            vcpus.report(Outcome::Stopped(Stop::SystemOff));
        });
        let vcpus = Arc::clone(&guest.vcpus);
        let running: Body = Box::new(move || {
            while vcpus.is_running() {
                std::thread::sleep(Duration::from_millis(1));
            }
            vcpus.mark_started(1);
            stopped.send(()).unwrap();
        });
        let start = Instant::now();
        let result = run(&guest, vec![off, running], None);
        assert!(start.elapsed() < STOP_TIMEOUT);
        resumer.join().unwrap();
        assert!(matches!(result, Ok(Stop::SystemOff)), "{result:?}");

        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let records: Vec<(String, serde_json::Value)> = text
            .lines()
            .map(|line| {
                let record: serde_json::Value = serde_json::from_str(line).unwrap();
                (
                    record["source"].as_str().unwrap().to_string(),
                    record["payload"].clone(),
                )
            })
            .collect();
        let mut started: Vec<_> = records
            .iter()
            .filter(|(source, _)| source == "vmm.vcpu_started")
            .map(|(_, payload)| payload["vcpu"].as_u64().unwrap())
            .collect();
        // The two vCPUs start in either order.
        started.sort_unstable();
        assert_eq!(started, [0, 1]);
        assert_eq!(records.last().unwrap().0, "vmm.stop");
    }

    /// Returns the `vmm.stop` payload of a one-vCPU guest run to the stop
    /// `request` asks for on its handle.
    ///
    /// The ledger is a file named after `name`.
    // The host-path ban in clippy.toml is aimed at the virtio-fs device, where
    // every component of a path comes from the guest. This test helper reads
    // the ledger file it made.
    #[allow(clippy::disallowed_methods)]
    fn stop_payload(name: &str, request: impl FnOnce(&StopHandle)) -> serde_json::Value {
        let path =
            std::env::temp_dir().join(format!("hvi-run-{name}-{}.ndjson", std::process::id()));
        let mut guest = guest(1);
        guest.ledger = Arc::new(Ledger::new(Some(path.to_str().unwrap()), "test").unwrap());
        let vcpus = Arc::clone(&guest.vcpus);
        let running: Body = Box::new(move || {
            while vcpus.is_running() {
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        request(guest.vcpus.stop_handle());
        let result = run(&guest, vec![running], None);
        assert!(matches!(result, Ok(Stop::Requested)), "{result:?}");

        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(last["source"], "vmm.stop");
        last["payload"].clone()
    }

    #[test]
    fn stop_record_names_a_signal_that_asked_first() {
        let payload = stop_payload("signal-first", |handle| {
            handle.request_stop_by(libc::SIGTERM);
            handle.request_stop();
        });
        assert_eq!(payload["reason"], "requested");
        assert_eq!(payload["signal"], "SIGTERM");
    }

    #[test]
    fn stop_record_names_no_signal_after_another_request() {
        let payload = stop_payload("request-first", |handle| {
            handle.request_stop();
            handle.request_stop_by(libc::SIGTERM);
        });
        assert_eq!(payload["reason"], "requested");
        assert_eq!(payload["signal"], serde_json::Value::Null);
    }

    // The host-path ban in clippy.toml is aimed at the virtio-fs device, where
    // every component of a path comes from the guest. This test reads the
    // ledger file it made.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn current_run_ends_when_its_guard_drops() {
        let path =
            std::env::temp_dir().join(format!("hvi-run-current-{}.ndjson", std::process::id()));
        let ledger = Arc::new(Ledger::new(path.to_str(), "test").unwrap());
        let current = CurrentRun::new();
        drop(current.enter(&ledger, Arc::clone(&guest(1).vcpus) as _, || {}));
        assert!(!current.record_failure("vcpu0: panicked (boom)"));
        assert!(ledger
            .close_with(Instant::now() + STOP_TIMEOUT, |_| {})
            .is_ok());
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(text, "");
    }

    // The host-path ban in clippy.toml is aimed at the virtio-fs device, where
    // every component of a path comes from the guest. This test reads the
    // ledger file it made.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn failure_record_closes_the_ledger() {
        let path =
            std::env::temp_dir().join(format!("hvi-run-failure-{}.ndjson", std::process::id()));
        let ledger = Arc::new(Ledger::new(path.to_str(), "test").unwrap());
        let current = CurrentRun::new();
        let block = || CapturedEvent::Block {
            disk: "disk0".into(),
            lba: 8,
            len: 4096,
            write: true,
        };
        let _entered = current.enter(&ledger, Arc::clone(&guest(1).vcpus) as _, || {});
        ledger.captured(&[block()]);
        assert!(current.record_failure("vcpu0: panicked (boom)"));
        assert!(!current.record_failure("vcpu1: panicked (bang)"));
        ledger.captured(&[block()]);
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["source"], "block");
        assert_eq!(records[1]["source"], "vmm.stop");
        assert_eq!(records[1]["payload"]["reason"], "failed");
        assert_eq!(records[1]["payload"]["error"], "vcpu0: panicked (boom)");
    }

    // The vCPUs exit before the ledger closes, so the closed ledger drops no
    // `block` record a vCPU adds. The host-path ban in clippy.toml is aimed at
    // the virtio-fs device, where every component of a path comes from the
    // guest. This test reads the ledger file it made.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn failure_record_follows_the_exit_of_the_vcpus() {
        let path =
            std::env::temp_dir().join(format!("hvi-run-exits-{}.ndjson", std::process::id()));
        let mut guest = guest(2);
        guest.ledger = Arc::new(Ledger::new(path.to_str(), "test").unwrap());
        let bodies: Vec<Body> = (0..2)
            .map(|_| {
                let vcpus = Arc::clone(&guest.vcpus);
                let ledger = Arc::clone(&guest.ledger);
                Box::new(move || {
                    while vcpus.is_running() {
                        ledger.captured(&[CapturedEvent::Block {
                            disk: "disk0".into(),
                            lba: 8,
                            len: 4096,
                            write: true,
                        }]);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }) as Body
            })
            .collect();
        let (threads, spawned) = guest.vcpus.spawn(bodies, |_, body| body());
        spawned.unwrap();
        let current = CurrentRun::new();
        let _entered = current.enter(&guest.ledger, Arc::clone(&guest.vcpus) as _, || {});
        assert!(current.record_failure("vcpu0: panicked (boom)"));
        assert!(threads.join_timeout(&guest.vcpus, Duration::ZERO).is_ok());
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(last["source"], "vmm.stop");
    }

    // A vCPU that never exits, as one blocked on a lock the panicking vCPU
    // holds, uses up only the vCPUs' half of `STOP_TIMEOUT`, and the record is
    // written in the writer's half. The host-path ban in clippy.toml is aimed
    // at the virtio-fs device, where every component of a path comes from the
    // guest. This test reads the ledger file it made.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn failure_record_is_written_while_a_vcpu_stays() {
        let path =
            std::env::temp_dir().join(format!("hvi-run-stays-{}.ndjson", std::process::id()));
        let mut guest = guest(1);
        guest.ledger = Arc::new(Ledger::new(path.to_str(), "test").unwrap());
        let held = Arc::new(std::sync::Mutex::new(()));
        let holding = held.lock().unwrap();
        let blocked = Arc::clone(&held);
        let body: Body = Box::new(move || drop(blocked.lock().unwrap()));
        let (threads, spawned) = guest.vcpus.spawn(vec![body], |_, body| body());
        spawned.unwrap();
        let current = CurrentRun::new();
        let _entered = current.enter(&guest.ledger, Arc::clone(&guest.vcpus) as _, || {});
        assert!(current.record_failure("vcpu1: panicked (boom)"));
        drop(holding);
        threads
            .join_timeout(&guest.vcpus, Duration::from_secs(5))
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(last["source"], "vmm.stop");
    }

    // A panic on a thread the stop does not wait for, such as an embedder's,
    // stops the vCPUs, and their exits end the run with the panic's failure.
    #[test]
    fn panic_stop_ends_the_run_with_its_failure() {
        let guest = guest(1);
        let vcpus = Arc::clone(&guest.vcpus);
        let running: Body = Box::new(move || {
            while vcpus.is_running() {
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let vcpus = Arc::clone(&guest.vcpus);
        let panicked = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            vcpus.stop_without_blocking("main: panicked (boom)");
        });
        let result = run(&guest, vec![running], None);
        panicked.join().unwrap();
        assert_eq!(result.unwrap_err(), "main: panicked (boom)");
    }

    #[test]
    fn run_slot_refuses_an_overlapping_run() {
        let slot = RunSlot::new();
        let first = slot.claim().unwrap();
        assert!(slot.claim().is_err());
        drop(first);
        drop(slot.claim().unwrap());
    }

    #[test]
    fn run_slot_stays_held_after_a_run_left_a_thread_running() {
        let slot = RunSlot::new();
        slot.claim().unwrap().keep();
        let error = slot
            .claim()
            .err()
            .expect("a run after one left a thread running");
        assert!(error.contains("left a thread running"), "{error}");
    }

    #[test]
    fn run_slot_stays_held_after_a_run_panicked() {
        let slot = std::sync::Arc::new(RunSlot::new());
        let claimed = std::sync::Arc::clone(&slot);
        let panicked = std::thread::spawn(move || {
            let _claim = claimed.claim().unwrap();
            panic!("the run panicked");
        })
        .join();
        assert!(panicked.is_err());
        assert!(slot.claim().is_err());
    }

    #[test]
    fn unwind_stops_the_vcpus() {
        let guest = guest(1);
        let vcpus = Arc::clone(&guest.vcpus);
        let unwound = std::thread::spawn(move || {
            let _unwind = StopOnUnwind { vcpus: &vcpus };
            panic!("the loop panicked");
        })
        .join();
        assert!(unwound.is_err());
        assert!(!guest.vcpus.is_running());
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
}

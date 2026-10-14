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
//! and the reason it reports are decided in one place.
//!
//! [`StopHandle`]: crate::stop::StopHandle

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

use serde::Serialize;

use crate::config::Stop;
use crate::events::Emitter;
use crate::hypervisor::guest::Guest;
use crate::hypervisor::vcpus::{Kick, Outcome, VcpuThreads};
use crate::io_threads::IoThreads;
use crate::plugin::GuestArch;
use crate::sync::try_lock_until;
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
/// for the run. A plugin can write earlier, from `attach` or from a thread it
/// started there. Such a thread can also hold the ledger, so the call waits for
/// it for at most [`STOP_TIMEOUT`] and skips the record when it is still held.
pub(crate) fn record_start<K: Kick>(guest: &Guest<K>, confined: bool) {
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
    let Some(mut ledger) = try_lock_until(&guest.ledger, Instant::now() + STOP_TIMEOUT) else {
        stderrln!("{LOG_PREFIX} the ledger is still locked; the start is not recorded");
        return;
    };
    ledger.emit_payload("vmm", "vmm.start", &start);
}

/// Runs the guest from its spawned vCPU threads to its stop.
///
/// It returns how the run ended. `failure` is a failure the caller met as it
/// started the run, from the spawn of the vCPU threads on. Without one, the
/// calling thread waits until a vCPU thread exits or a stop is requested. It
/// then stops the VM, joins the vCPU threads and stops `io_threads`, each by
/// [`STOP_TIMEOUT`], and writes out the ledger tail, which the flush cadence
/// alone would leave in the buffer.
///
/// The loop writes the rest of the run's lifecycle to the ledger, after the
/// record of [`record_start`]: a `vmm.vcpu_started` record for each vCPU that
/// enters its run loop, and, before the last flush, a `vmm.stop` record with
/// how the run ended. A thread left running may hold the ledger, so after the
/// joins the loop waits for it for at most [`STOP_TIMEOUT`], and writes neither
/// the records nor the tail when it is still held.
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
            // The ledger is only tried, so a thread that holds it does not keep
            // the loop from a failure or a stop request. A record it cannot
            // write now is written after the joins.
            let started = guest.vcpus.started_after(announced);
            if started.is_empty() {
                return;
            }
            if let Some(mut ledger) = try_lock_until(&guest.ledger, Instant::now()) {
                record_vcpus_started(&mut ledger, &started);
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

    let ledger = try_lock_until(&guest.ledger, Instant::now() + STOP_TIMEOUT);
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
    let Some(mut ledger) = ledger else {
        stderrln!(
            "{LOG_PREFIX} the ledger is still locked; the stop record and the tail are not written"
        );
        return result;
    };
    // A vCPU that started after the last wake is recorded before the stop.
    record_vcpus_started(&mut ledger, &guest.vcpus.started_after(announced));
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
    };
    ledger.emit_payload("vmm", "vmm.stop", &stop);
    ledger.flush();
    result
}

/// Writes a `vmm.vcpu_started` record for each of `cpus`.
fn record_vcpus_started(ledger: &mut Emitter, cpus: &[u32]) {
    for &cpu in cpus {
        ledger.emit_payload("vmm", "vmm.vcpu_started", &VcpuStartedRecord { vcpu: cpu });
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::hypervisor::guest::PluginThreads;
    use crate::hypervisor::vcpus::Vcpus;
    use crate::memory::{GuestRam, RamRegion, SharedRam};
    use crate::plugin::GuestArch;
    use crate::stop::StopHandle;

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
            plugin_threads: PluginThreads::new(),
            vcpus: Arc::new(Vcpus::new(
                count,
                NoopKicker,
                StopHandle::new_pair().unwrap().0,
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

    // A thread holds the ledger while the vCPUs start and the guest stops, so
    // the loop cannot record the starts as they come. The holder lets go once
    // the second vCPU sees the stop, after the loop's last wake. The host-path
    // ban in clippy.toml is aimed at the virtio-fs device, where every
    // component of a path comes from the guest. This test reads the ledger file
    // it made.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn vcpus_started_while_the_ledger_is_held_are_recorded_before_the_stop() {
        let path = std::env::temp_dir().join(format!("hvi-run-{}.ndjson", std::process::id()));
        let mut guest = guest(2);
        guest.ledger = Arc::new(Mutex::new(
            Emitter::new(Some(path.to_str().unwrap()), "test").unwrap(),
        ));
        let (held, is_held) = mpsc::channel::<()>();
        let (stopped, has_stopped) = mpsc::channel::<()>();
        let ledger = Arc::clone(&guest.ledger);
        let holder = std::thread::spawn(move || {
            let _held = ledger.lock().unwrap();
            held.send(()).unwrap();
            has_stopped.recv().unwrap();
        });
        is_held.recv().unwrap();

        let vcpus = Arc::clone(&guest.vcpus);
        let off: Body = Box::new(move || {
            vcpus.mark_started(0);
            vcpus.report(Outcome::Stopped(Stop::SystemOff));
        });
        // The VM stops only after the loop's last wake, so once this vCPU sees
        // the stop, the loop records the starts after the joins or not at all.
        let vcpus = Arc::clone(&guest.vcpus);
        let running: Body = Box::new(move || {
            vcpus.mark_started(1);
            while vcpus.is_running() {
                std::thread::sleep(Duration::from_millis(1));
            }
            stopped.send(()).unwrap();
        });
        let result = run(&guest, vec![off, running], None);
        holder.join().unwrap();
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

    /// Runs a guest with one vCPU to the stop `request` asks for on its handle,
    /// with its ledger in a file named after `name`, and returns the payload of
    /// the `vmm.stop` record.
    // This test helper reads the ledger file it made, which the host-path ban
    // in clippy.toml does not aim at.
    #[allow(clippy::disallowed_methods)]
    fn stop_payload(name: &str, request: impl FnOnce(&StopHandle)) -> serde_json::Value {
        let path =
            std::env::temp_dir().join(format!("hvi-run-{name}-{}.ndjson", std::process::id()));
        let mut guest = guest(1);
        guest.ledger = Arc::new(Mutex::new(
            Emitter::new(Some(path.to_str().unwrap()), "test").unwrap(),
        ));
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

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

use std::time::Instant;

use crate::config::Stop;
use crate::hypervisor::guest::Guest;
use crate::hypervisor::vcpus::{Kick, Outcome, VcpuThreads};
use crate::io_threads::IoThreads;
use crate::sync::try_lock_until;
use crate::teardown::STOP_TIMEOUT;
use crate::LOG_PREFIX;

/// Runs the guest from its spawned vCPU threads to its stop.
///
/// It returns how the run ended. `failure` is a failure the caller met as it
/// started the run, from the spawn of the vCPU threads on. Without one, the
/// calling thread waits until a vCPU thread exits or a stop is requested. It
/// then stops the VM, joins the vCPU threads and stops `io_threads`, each by
/// [`STOP_TIMEOUT`], and writes out the ledger tail, which the flush cadence
/// alone would leave in the buffer. A thread left running may hold the ledger,
/// so the flush waits for it for at most [`STOP_TIMEOUT`] and is skipped when
/// it is still held.
///
/// # Errors
///
/// Errors with `failure`, else with the failure a thread reported, else with a
/// thread that did not stop in time. A thread left running is named after the
/// failure, or reported with how the run stopped, since the error takes the
/// place of that stop.
pub(crate) fn run_to_stop<K: Kick>(
    guest: &Guest<K>,
    threads: VcpuThreads,
    mut failure: Option<Box<dyn std::error::Error>>,
    io_threads: IoThreads,
) -> Result<Stop, Box<dyn std::error::Error>> {
    if failure.is_none() {
        if let Err(e) = guest.vcpus.wait_for_stop() {
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
        // `failure` is the one returned, so a thread's failure behind it is
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
            Err(format!("{e}, after the run stopped with {stop:?}").into())
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

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

//! `hvi restore`: the parts every backend's restore shares.
//!
//! [`import`] loads a bundle's vCPUs and interrupt controller into vCPUs
//! that a backend has created and parked, in three steps, each one posted to
//! every vCPU and waited for before the next:
//!
//! 1. each vCPU loads its registers and its timer;
//! 2. vCPU 0 loads the interrupt controller, once every vCPU exists and none
//!    has run, as `hv_gic_set_state` requires;
//! 3. each vCPU loads its own part of the interrupt controller, its CPU
//!    interface, which step 2 reset.
//!
//! The waits between the steps are the barriers. The guest runs only once a
//! client sends `resume`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::checkpoint::cpu::{ImportPlan, ImportStep, Power, VcpuState};
use crate::hypervisor::vcpus::{Kick, Vcpus, WorkResult};

/// The import steps, in the order [`import`] posts them.
// The HVF restore is the caller; until it exists, only the tests are.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const IMPORT_STEPS: [ImportStep; 3] =
    [ImportStep::Vcpu, ImportStep::Platform, ImportStep::IrqCpu];

/// Returns whether `state` is of a vCPU that starts on its own at a restore,
/// and so takes part in the import: one that ran, or one whose `CPU_ON` the
/// guest had sent. One that is off waits for the guest, as at boot.
// See `IMPORT_STEPS`.
#[cfg_attr(not(test), allow(dead_code))]
fn starts(state: &VcpuState) -> bool {
    match state {
        VcpuState::Aarch64(v) => v.power != Power::Off,
        VcpuState::X86_64(_) => true,
    }
}

/// Loads `plan` into the vCPUs, in the three steps of [`IMPORT_STEPS`].
///
/// The caller holds the vCPUs paused from the control socket, so each one
/// parks at its first checkpoint, before it enters the guest. Every vCPU that
/// [`starts`] must have started within `timeout`, and each step must finish
/// within `timeout` of its post.
///
/// # Errors
///
/// Errors, naming the vCPU and the step, when a vCPU did not start, did not
/// finish a step in time, or could not load its part; or when the VM stopped.
// See `IMPORT_STEPS`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn import<K: Kick>(
    vcpus: &Vcpus<K>,
    plan: &Arc<ImportPlan>,
    timeout: Duration,
) -> Result<(), String> {
    let expected = plan.vcpus.iter().filter(|v| starts(v)).count() as u32;
    let deadline = Instant::now() + timeout;
    while vcpus.started() < expected {
        if !vcpus.is_running() {
            return Err("the run ended before the vCPUs started".to_string());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{} of {expected} vCPUs started in time",
                vcpus.started()
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    for step in IMPORT_STEPS {
        vcpus.request_import(step, Arc::clone(plan));
        let waited = vcpus.wait_work(timeout);
        let results = vcpus.end_work();
        waited.map_err(|e| format!("{step:?} step: {e}"))?;
        for (cpu, (result, state)) in results.iter().zip(&plan.vcpus).enumerate() {
            match result {
                WorkResult::Done(_) => {}
                WorkResult::Failed(why) => {
                    return Err(format!("vCPU {cpu}, {step:?} step: {why}"));
                }
                WorkResult::NotStarted if starts(state) => {
                    return Err(format!("vCPU {cpu}, {step:?} step: it did not take part"));
                }
                WorkResult::NotStarted => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::checkpoint::cpu::{Output, Work};
    use crate::checkpoint::platform::PlatformState;
    use crate::plugin::GuestArch;
    use std::sync::Mutex;
    use std::thread::JoinHandle;

    /// A kicker that reaches no thread; the fake vCPUs poll.
    #[derive(Default)]
    pub(crate) struct NoKick;

    impl Kick for NoKick {
        fn kick(&self, _cpu: u32) {}
        fn kick_all(&self) {}
    }

    /// What each fake vCPU did, in the order they did it.
    pub(crate) type Log = Arc<Mutex<Vec<(u32, ImportStep)>>>;

    /// Spawns fake vCPU `cpu`, which starts, parks at every checkpoint and
    /// logs each import step it carries out on its own state. vCPU 0 alone
    /// logs the platform step, as only it loads the controller. It exports
    /// the plugin register view, so a capture of it works.
    pub(crate) fn importing_vcpu<K: Kick + 'static>(
        vcpus: &Arc<Vcpus<K>>,
        cpu: u32,
        log: &Log,
        fail: Option<ImportStep>,
    ) -> JoinHandle<()> {
        let (vcpus, log) = (Arc::clone(vcpus), Arc::clone(log));
        std::thread::spawn(move || {
            vcpus.mark_started();
            while vcpus.is_running() {
                vcpus.checkpoint_with(cpu, |work| match work {
                    Work::Import(step, _) if Some(step) == fail => {
                        Err(std::io::Error::other("the hypervisor refused it"))
                    }
                    Work::Import(ImportStep::Platform, _) if cpu != 0 => Ok(None),
                    Work::Import(step, plan) => {
                        assert_eq!(plan.vcpus[cpu as usize].id(), cpu);
                        log.lock().unwrap().push((cpu, step));
                        Ok(None)
                    }
                    Work::Export => Ok(Some(Output::Vcpu {
                        state: VcpuState::from_regs_view(
                            GuestArch::Aarch64,
                            "hvf",
                            cpu,
                            &crate::plugin::RegsView::default(),
                        ),
                        irq: None,
                    })),
                    Work::ExportPlatform => Ok(None),
                });
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    }

    /// A plan of `on` vCPUs that ran and `off` ones that never did.
    pub(crate) fn plan(on: u32, off: u32) -> Arc<ImportPlan> {
        let arch = GuestArch::Aarch64;
        Arc::new(ImportPlan {
            vcpus: (0..on + off)
                .map(|cpu| {
                    let state = VcpuState::powered_off(arch, "hvf", cpu);
                    match state {
                        VcpuState::Aarch64(mut v) if cpu < on => {
                            v.power = Power::On;
                            VcpuState::Aarch64(v)
                        }
                        other => other,
                    }
                })
                .collect(),
            platform: PlatformState::not_captured(arch, "hvf"),
        })
    }

    /// Checks that every vCPU finished each step before any began the next.
    pub(crate) fn assert_barriers(log: &[(u32, ImportStep)], vcpus: u32) {
        let n = vcpus as usize;
        assert_eq!(log.len(), 2 * n + 1, "{log:?}");
        let sorted = |part: &[(u32, ImportStep)]| {
            let mut part = part.to_vec();
            part.sort_unstable_by_key(|(cpu, _)| *cpu);
            part
        };
        let every = |step| (0..vcpus).map(|cpu| (cpu, step)).collect::<Vec<_>>();
        assert_eq!(sorted(&log[..n]), every(ImportStep::Vcpu), "{log:?}");
        assert_eq!(log[n], (0, ImportStep::Platform), "{log:?}");
        assert_eq!(sorted(&log[n + 1..]), every(ImportStep::IrqCpu), "{log:?}");
    }

    #[test]
    fn the_steps_run_in_order_with_a_barrier_between_each() {
        let vcpus = Arc::new(Vcpus::new(3, NoKick));
        vcpus.pause_from_control(Duration::ZERO).unwrap();
        let log = Log::default();
        let threads: Vec<_> = (0..2)
            .map(|cpu| importing_vcpu(&vcpus, cpu, &log, None))
            .collect();
        // vCPU 2 was off, and its thread waits for the guest, as at boot.
        import(&vcpus, &plan(2, 1), Duration::from_secs(5)).unwrap();
        assert_barriers(&log.lock().unwrap(), 2);
        assert_eq!(vcpus.parked(), 2, "a vCPU left its park during the import");
        vcpus.stop();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn a_step_that_fails_ends_the_import_naming_the_vcpu() {
        let vcpus = Arc::new(Vcpus::new(2, NoKick));
        vcpus.pause_from_control(Duration::ZERO).unwrap();
        let log = Log::default();
        let threads = [
            importing_vcpu(&vcpus, 0, &log, None),
            importing_vcpu(&vcpus, 1, &log, Some(ImportStep::IrqCpu)),
        ];
        let err = import(&vcpus, &plan(2, 0), Duration::from_secs(5)).unwrap_err();
        assert_eq!(err, "vCPU 1, IrqCpu step: the hypervisor refused it");
        vcpus.stop();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn a_vcpu_that_never_starts_times_the_import_out() {
        let vcpus = Arc::new(Vcpus::new(2, NoKick));
        vcpus.pause_from_control(Duration::ZERO).unwrap();
        let log = Log::default();
        let thread = importing_vcpu(&vcpus, 0, &log, None);
        let started = Instant::now();
        let err = import(&vcpus, &plan(2, 0), Duration::from_millis(100)).unwrap_err();
        assert_eq!(err, "1 of 2 vCPUs started in time");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(log.lock().unwrap().is_empty(), "a step ran without vCPU 1");
        vcpus.stop();
        thread.join().unwrap();
        // The stop ends a wait for a vCPU that never comes.
        let stopped = Vcpus::new(1, NoKick);
        stopped.stop();
        assert_eq!(
            import(&stopped, &plan(1, 0), Duration::from_secs(5)).unwrap_err(),
            "the run ended before the vCPUs started"
        );
    }
}

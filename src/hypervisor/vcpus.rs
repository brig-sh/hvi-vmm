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

//! The vCPU threads of a VM, from their spawn to their join.
//!
//! [`Vcpus`] holds what every backend keeps about its vCPU threads: whether the
//! VM still runs, the quiesce that parks them for a plugin, how the run ended,
//! how many there are and how many have exited. Each vCPU thread checks the
//! first two at the top of its run loop, between guest entries. A vCPU thread
//! that exits reports it and wakes the loop in
//! [`run_to_stop`](crate::run::run_to_stop), which calls [`stop`](Vcpus::stop).
//! The stop clears the running flag, kicks every vCPU out of the hypervisor and
//! then releases the quiesce, so each one sees the stop at its next check.
//!
//! How a kick reaches a vCPU depends on the hypervisor, so [`Vcpus`] takes it
//! from a [`Kick`] implementation that owns the table of vCPU threads.
//!
//! Two requesters can pause the vCPUs: a plugin on cpu0, through
//! [`Vcpus::pause`], and the control socket's thread, through
//! [`Vcpus::pause_from_control`]. They share one quiesce, so whichever holds it
//! keeps the other out until it releases. Without that, a plugin's `resume`
//! would let the guest run under a control pause that still reports it paused.
//!
//! The control socket's thread can also hand the parked vCPUs work that only
//! each vCPU's own thread can do, since only that thread may read or write
//! its registers: [`Vcpus::request_export`] and [`Vcpus::request_import`].
//! Each vCPU does it at its checkpoint, parked and out of the guest, through
//! the closure its backend passes to [`Vcpus::checkpoint_with`], and then
//! stays parked.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::checkpoint::cpu::{ImportPlan, ImportStep, Output, Work};
use crate::config::Stop;
use crate::hypervisor::quiesce::Quiesce;
use crate::run::StopHandle;
use crate::sync::lock_or_recover;
use crate::LOG_PREFIX;

/// How the hypervisor ends a vCPU's run.
///
/// A kick from a vCPU's own thread is dropped: it would end that thread's next
/// run before the guest ran.
pub(crate) trait Kick: Send + Sync {
    /// Ends the current or next run of vCPU `cpu`.
    fn kick(&self, cpu: u32);

    /// Ends the current or next run of every vCPU but the caller's own.
    fn kick_all(&self);

    /// Returns the start a vCPU that has not started was asked for and has
    /// not taken, as its entry point and context argument.
    ///
    /// An arm64 secondary waits outside the hypervisor for the guest's PSCI
    /// `CPU_ON`, and the request waits in a mailbox until its thread takes it.
    /// A backend whose vCPUs all start at once has no such request.
    fn pending_start(&self, _cpu: u32) -> Option<(u64, u64)> {
        None
    }

    /// Wakes the vCPUs that wait outside the hypervisor for the guest to start
    /// them.
    fn kick_halted(&self) {}
}

/// The vCPUs of one VM, with the state their threads share.
pub(crate) struct Vcpus<K> {
    /// Whether the VM still runs, until [`stop`](Self::stop) clears it.
    running: AtomicBool,
    /// The barrier that parks the vCPUs for a pause.
    quiesce: Quiesce,
    /// Which requester holds the quiesce: [`FREE`], [`PLUGIN`] or [`CONTROL`].
    holder: AtomicU8,
    /// How the run ended, from the first report or a failure after a stop.
    outcome: Mutex<Option<Outcome>>,
    /// The number of vCPUs.
    count: u32,
    /// The number of vCPUs that have entered their run loop.
    ///
    /// It counts the vCPUs `started_ids` lists, and is kept apart so a pause
    /// can read it inside the quiesce wait without a second lock.
    started: AtomicU32,
    /// The ids of the vCPUs that have entered their run loop, in the order they
    /// did.
    started_ids: Mutex<Vec<u32>>,
    /// The number of vCPU threads that have exited.
    exited: AtomicU32,
    /// The run's stop handle, which also wakes the loop.
    stop_handle: StopHandle,
    /// The [`Kick`] implementation that kicks the vCPUs.
    kicker: K,
    /// The work the control thread has posted, and each vCPU's result.
    work: Mutex<WorkTable>,
    /// Signals a result to the control thread waiting for them.
    work_done: Condvar,
    /// Per vCPU, whether work is posted that it has not taken. Read at every
    /// checkpoint of a pause, so it is an atomic and not the table's lock.
    work_due: Vec<AtomicBool>,
}

/// The work posted to the vCPUs, and where each one is with it.
#[derive(Default)]
struct WorkTable {
    /// What is asked, while something is.
    request: Option<WorkRequest>,
    /// Counts the requests, so a result for an ended request is dropped.
    generation: u64,
    /// Each vCPU's result, by index, once it has one.
    results: Vec<Option<WorkResult>>,
}

/// What the control thread asks of every vCPU.
#[derive(Clone)]
// Only the HVF restore posts `Import` so far.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
enum WorkRequest {
    /// Each vCPU writes its state.
    Export,
    /// vCPU 0 reads the platform, once every vCPU has exported.
    ExportPlatform,
    /// Each vCPU carries out one step of a restore from the plan.
    Import(ImportStep, Arc<ImportPlan>),
}

/// What one vCPU made of a work request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkResult {
    /// It did the work, and this is what it handed back, if anything.
    Done(Option<Box<Output>>),
    /// It could not, and this says why.
    Failed(String),
    /// It never took the request: the guest has not started it, so it has no
    /// thread in its run loop.
    NotStarted,
}

impl<K: Kick> Vcpus<K> {
    /// Returns the state of `count` vCPUs that `kicker` kicks, whose run stops
    /// on a request through `stop`.
    pub(crate) fn new(count: u32, kicker: K, stop: StopHandle) -> Self {
        Self {
            running: AtomicBool::new(true),
            quiesce: Quiesce::new(),
            holder: AtomicU8::new(FREE),
            outcome: Mutex::new(None),
            count,
            started: AtomicU32::new(0),
            started_ids: Mutex::new(Vec::new()),
            exited: AtomicU32::new(0),
            stop_handle: stop,
            kicker,
            work: Mutex::new(WorkTable::default()),
            work_done: Condvar::new(),
            work_due: (0..count).map(|_| AtomicBool::new(false)).collect(),
        }
    }

    /// Returns the number of vCPUs.
    pub(crate) fn count(&self) -> u32 {
        self.count
    }

    /// Returns the [`Kick`] implementation that kicks the vCPUs.
    pub(crate) fn kicker(&self) -> &K {
        &self.kicker
    }

    /// Returns whether the VM still runs.
    pub(crate) fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Records that vCPU `cpu`, the calling one, entered its run loop.
    ///
    /// It wakes the caller of [`wait_for_stop`](Self::wait_for_stop). A vCPU
    /// calls it once, before its first checkpoint.
    pub(crate) fn mark_started(&self, cpu: u32) {
        self.started.fetch_add(1, Ordering::SeqCst);
        lock_or_recover(&self.started_ids).push(cpu);
        self.stop_handle.wake();
    }

    /// Returns the ids of the vCPUs that entered their run loop after the first
    /// `seen`, in the order they did.
    pub(crate) fn started_after(&self, seen: usize) -> Vec<u32> {
        lock_or_recover(&self.started_ids)
            .get(seen..)
            .unwrap_or_default()
            .to_vec()
    }

    /// Parks the calling thread while a quiesce is in effect, for the tests'
    /// fake vCPUs, which serve no work.
    ///
    /// Returns how long it stayed parked, zero when it did not park.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn checkpoint(&self) -> Duration {
        self.quiesce.checkpoint()
    }

    /// Parks the calling vCPU thread, `cpu`, while a quiesce is in effect,
    /// and carries out through `serve` any work posted to it meanwhile.
    ///
    /// A vCPU thread calls it between guest entries, where its registers and
    /// the memory it has written are stable. `serve` is the backend's: it
    /// runs on this thread, so it may read and write this vCPU's registers.
    /// Work posted before the vCPU parks is done before it waits, and work
    /// posted while it waits wakes it, so the requester finds every parked
    /// vCPU done whichever came first. Returns how long the vCPU stayed
    /// parked, the work included, zero when it did not park.
    #[must_use]
    pub(crate) fn checkpoint_with(
        &self,
        cpu: u32,
        mut serve: impl FnMut(Work<'_>) -> io::Result<Option<Output>>,
    ) -> Duration {
        let Some(due) = self.work_due.get(cpu as usize) else {
            return self.quiesce.checkpoint();
        };
        self.quiesce.checkpoint_serving(
            || due.load(Ordering::SeqCst),
            || self.serve(cpu, due, &mut serve),
        )
    }

    /// Carries out the work due on vCPU `cpu` and records its result.
    fn serve(
        &self,
        cpu: u32,
        due: &AtomicBool,
        serve: &mut impl FnMut(Work<'_>) -> io::Result<Option<Output>>,
    ) {
        if !due.swap(false, Ordering::SeqCst) {
            return;
        }
        let (request, generation) = {
            let table = lock_or_recover(&self.work);
            (table.request.clone(), table.generation)
        };
        let outcome = match &request {
            None => return,
            Some(WorkRequest::Export) => serve(Work::Export),
            Some(WorkRequest::ExportPlatform) => serve(Work::ExportPlatform),
            Some(WorkRequest::Import(step, plan)) => {
                if plan.vcpus.get(cpu as usize).is_some() {
                    serve(Work::Import(*step, plan))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("no state for vCPU {cpu}"),
                    ))
                }
            }
        };
        let result = match outcome {
            Ok(state) => WorkResult::Done(state.map(Box::new)),
            Err(e) => WorkResult::Failed(e.to_string()),
        };
        let mut table = lock_or_recover(&self.work);
        if table.generation == generation {
            if let Some(slot) = table.results.get_mut(cpu as usize) {
                *slot = Some(result);
            }
            self.work_done.notify_all();
        }
    }

    /// Asks every vCPU to export its state at its checkpoint, and wakes the
    /// ones parked already.
    ///
    /// The caller holds the vCPUs paused, or is about to, and collects the
    /// states with [`wait_work`](Self::wait_work) and
    /// [`end_work`](Self::end_work).
    pub(crate) fn request_export(&self) {
        self.post(WorkRequest::Export);
    }

    /// Asks vCPU 0 to read the platform at its checkpoint, and every other
    /// vCPU to report that it has nothing to add.
    ///
    /// The caller posts it once every vCPU has exported, so the interrupt
    /// controller vCPU 0 reads holds what the others' exports left in it.
    pub(crate) fn request_platform(&self) {
        self.post(WorkRequest::ExportPlatform);
    }

    /// Asks every vCPU to carry out `step` of a restore from `plan`, its
    /// own state by index, at its checkpoint, and wakes the ones parked
    /// already.
    // Only the HVF restore calls it so far.
    #[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
    pub(crate) fn request_import(&self, step: ImportStep, plan: Arc<ImportPlan>) {
        self.post(WorkRequest::Import(step, plan));
    }

    /// Posts `request` to every vCPU and wakes the parked ones.
    fn post(&self, request: WorkRequest) {
        {
            let mut table = lock_or_recover(&self.work);
            table.request = Some(request);
            table.generation += 1;
            table.results = vec![None; self.count as usize];
        }
        for due in &self.work_due {
            due.store(true, Ordering::SeqCst);
        }
        self.quiesce.wake();
    }

    /// Waits until every started vCPU has a result for the posted work.
    ///
    /// The number of started vCPUs is read again as each result comes in, so
    /// a secondary that starts during the wait is waited for too. A vCPU that
    /// has not started has no result, and [`end_work`](Self::end_work) says
    /// so.
    ///
    /// # Errors
    ///
    /// Errors when the VM stops or the results are not all in by `timeout`.
    pub(crate) fn wait_work(&self, timeout: Duration) -> Result<(), PauseError> {
        let deadline = Instant::now() + timeout;
        let mut table = lock_or_recover(&self.work);
        loop {
            if !self.is_running() {
                return Err(PauseError::Stopped);
            }
            let done = table.results.iter().filter(|r| r.is_some()).count() as u32;
            let expected = self.started();
            if done >= expected {
                return Ok(());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(PauseError::Timeout {
                    parked: done,
                    expected,
                });
            }
            // A stop notifies no one here, so the wait is cut into slices.
            table = self
                .work_done
                .wait_timeout(table, left.min(Duration::from_millis(50)))
                .map_or_else(|e| e.into_inner().0, |(table, _)| table);
        }
    }

    /// Ends the posted work and returns each vCPU's result, by index.
    ///
    /// A vCPU that had not taken the work by now is reported
    /// [`NotStarted`](WorkResult::NotStarted), and a result it records later
    /// is dropped.
    pub(crate) fn end_work(&self) -> Vec<WorkResult> {
        for due in &self.work_due {
            due.store(false, Ordering::SeqCst);
        }
        let mut table = lock_or_recover(&self.work);
        table.request = None;
        table.generation += 1;
        std::mem::take(&mut table.results)
            .into_iter()
            .map(|r| r.unwrap_or(WorkResult::NotStarted))
            .collect()
    }

    /// Parks every started vCPU but the calling one at its next checkpoint.
    ///
    /// The caller is a vCPU thread and does not park itself. Only the vCPUs
    /// that have called [`mark_started`](Self::mark_started) are waited for.
    /// One that has not, such as a secondary that waits outside the hypervisor
    /// for the guest to start it, cannot touch guest state. One that starts
    /// during the wait is waited for too, and parks at its first checkpoint,
    /// before it enters the guest. Returns `false` when they did not all park
    /// in time, when the VM stopped during the wait, or when the control socket
    /// holds the quiesce. The quiesce is then released already or not this
    /// caller's, and the caller must not call [`resume`](Self::resume).
    pub(crate) fn pause(&self) -> bool {
        if !self.claim(PLUGIN) {
            return false;
        }
        self.quiesce.request();
        self.kicker.kick_all();
        // Read as each vCPU parks, since one that started after a single read
        // would park in place of one still in the guest. A stopped VM needs no
        // more vCPUs to park, since a vCPU that has left its loop never parks.
        // The stop releases the quiesce, which wakes the wait.
        let others = || {
            if self.is_running() {
                self.started.load(Ordering::SeqCst).saturating_sub(1)
            } else {
                0
            }
        };
        if self.quiesce.wait_for_with(others) && self.is_running() {
            true
        } else {
            self.release_held(PLUGIN);
            false
        }
    }

    /// Releases the vCPUs a successful [`pause`](Self::pause) parked.
    ///
    /// It does nothing while the control socket holds the quiesce, so a plugin
    /// that calls it after a failed pause cannot end a control pause.
    pub(crate) fn resume(&self) {
        self.release_held(PLUGIN);
    }

    /// Parks every started vCPU at its next checkpoint, for a requester that
    /// is not a vCPU thread.
    ///
    /// The caller does not run a vCPU, so it waits for all of the started
    /// vCPUs rather than all but one. The wait has one deadline, `timeout`
    /// from the request. A pause that misses it is released before this
    /// returns, so the guest runs again and no caller ever acts on a guest
    /// that is only partly still. Returns the number of vCPUs parked.
    ///
    /// # Errors
    ///
    /// Errors when the VM has stopped, when a plugin or an earlier control
    /// pause holds the quiesce, or when the vCPUs did not all park in time.
    pub(crate) fn pause_from_control(&self, timeout: Duration) -> Result<u32, PauseError> {
        if !self.is_running() {
            return Err(PauseError::Stopped);
        }
        if !self.claim(CONTROL) {
            return Err(PauseError::Busy);
        }
        self.quiesce.request();
        self.kicker.kick_all();
        // Once the VM stops the target drops to zero, so the wait ends with
        // the stop. Waiting out the deadline would keep the control thread
        // past the shorter one the join of the I/O threads has.
        let target = || {
            if self.is_running() {
                self.started.load(Ordering::SeqCst)
            } else {
                0
            }
        };
        if !self.quiesce.wait_for_within(target, timeout) {
            let parked = self.quiesce.parked();
            let expected = self.started();
            self.release_held(CONTROL);
            return Err(PauseError::Timeout { parked, expected });
        }
        // A stop during the wait released the quiesce, and the vCPUs it
        // parked are on their way out of the run loop.
        if !self.is_running() {
            self.release_held(CONTROL);
            return Err(PauseError::Stopped);
        }
        Ok(self.quiesce.parked())
    }

    /// Releases the vCPUs a successful
    /// [`pause_from_control`](Self::pause_from_control) parked.
    ///
    /// # Errors
    ///
    /// Errors when the control socket does not hold the quiesce, which leaves
    /// a plugin's pause in place.
    pub(crate) fn resume_from_control(&self) -> Result<(), PauseError> {
        if self.release_held(CONTROL) {
            Ok(())
        } else {
            Err(PauseError::NotPaused)
        }
    }

    /// Returns the number of vCPUs parked at a checkpoint right now.
    pub(crate) fn parked(&self) -> u32 {
        self.quiesce.parked()
    }

    /// Returns the number of vCPUs that have entered their run loop.
    pub(crate) fn started(&self) -> u32 {
        self.started.load(Ordering::SeqCst)
    }

    /// Makes `who` the holder of the quiesce, if no one holds it.
    fn claim(&self, who: u8) -> bool {
        self.holder
            .compare_exchange(FREE, who, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Releases the quiesce if `who` holds it, and returns whether it did.
    ///
    /// The quiesce is released before the holder is cleared, so a requester
    /// that claims it next starts from a released barrier.
    fn release_held(&self, who: u8) -> bool {
        if self.holder.load(Ordering::SeqCst) != who {
            return false;
        }
        self.quiesce.release();
        self.holder.store(FREE, Ordering::SeqCst);
        true
    }

    /// Ends the VM.
    ///
    /// Clears the running flag, kicks every vCPU, including the ones waiting
    /// for the guest to start them, and then releases the quiesce so no vCPU
    /// stays parked at a checkpoint. Only the first call kicks; a later one
    /// just releases the quiesce again.
    pub(crate) fn stop(&self) {
        let was_running = self.running.swap(false, Ordering::SeqCst);
        // One round of kicks is enough. The kick reaches a vCPU that has not
        // entered its run yet, and one that registers after the round reads the
        // flag before its first run.
        if was_running {
            self.kicker.kick_all();
            self.kicker.kick_halted();
        }
        // A vCPU parked at a checkpoint waits on a condition variable that no
        // kick ends. The release comes after the kicks, so the run it goes on
        // to ends at once and it reads the flag without entering the guest. The
        // release runs on every call, since a pause can request the quiesce
        // again after the first one.
        self.quiesce.release();
    }

    /// Blocks until a vCPU thread has exited or a stop is requested.
    ///
    /// It calls `on_wake` before the first wait and again after each wake.
    ///
    /// # Errors
    ///
    /// Errors if the wake cannot be waited on.
    pub(crate) fn wait_for_stop(&self, mut on_wake: impl FnMut()) -> io::Result<()> {
        // A request is stored, and an exit is counted, before its wake. So one
        // that lands after the check leaves a wake pending and ends the wait.
        loop {
            on_wake();
            if self.exited.load(Ordering::SeqCst) > 0 || self.stop_handle.is_stop_requested() {
                return Ok(());
            }
            self.stop_handle.wait(None)?;
        }
    }

    /// Returns whether `count` vCPU threads exit before `deadline`.
    ///
    /// It blocks until they have exited or the deadline passes.
    ///
    /// # Errors
    ///
    /// Errors if the wake cannot be waited on.
    fn wait_for_exits(&self, count: u32, deadline: Instant) -> io::Result<bool> {
        // An exit is counted before its wake, so one that lands after the check
        // leaves a wake pending.
        while self.exited.load(Ordering::SeqCst) < count {
            if Instant::now() >= deadline {
                return Ok(false);
            }
            self.stop_handle.wait(Some(deadline))?;
        }
        Ok(true)
    }

    /// Records how the run ended.
    ///
    /// The first report is kept, except that a failure replaces an earlier
    /// stop, so a vCPU that fails while the guest powers off ends the run with
    /// its failure. A failure that is not kept is printed. The vCPUs a stop
    /// kicks leave their loops without a report, so a later report comes from a
    /// thread that stopped or failed on its own at the same time. A report can
    /// come from a thread that unwinds from a panic, where a second panic
    /// aborts the process.
    pub(crate) fn report(&self, outcome: Outcome) {
        let mut kept = lock_or_recover(&self.outcome);
        let replaces = matches!(
            (kept.as_ref(), &outcome),
            (None, _) | (Some(Outcome::Stopped(_)), Outcome::Failed(_))
        );
        if replaces {
            *kept = Some(outcome);
        } else if let Outcome::Failed(text) = outcome {
            drop(kept);
            stderrln!("{LOG_PREFIX} {text}");
        }
    }

    /// Returns how the run ended.
    ///
    /// A report wins over a stop request, so a failure a thread reports, or a
    /// guest stop a vCPU reports, before `boot` reads how the run ended is the
    /// outcome returned. Every failure is reported. A run with neither a report
    /// nor a request is one in which the guest stopped without saying how, and
    /// its outcome is [`Stop::SystemOff`].
    pub(crate) fn outcome(&self) -> Outcome {
        let reported = lock_or_recover(&self.outcome).clone();
        reported.unwrap_or(Outcome::Stopped(if self.stop_handle.is_stop_requested() {
            Stop::Requested
        } else {
            Stop::SystemOff
        }))
    }

    /// Returns the handle that asks this run to stop.
    pub(crate) fn stop_handle(&self) -> &StopHandle {
        &self.stop_handle
    }

    /// Spawns one thread per vCPU, each running `run` with its id and the item
    /// of `per_vcpu` at that position.
    ///
    /// Each thread is named after its vCPU, so a panic report says which one
    /// panicked. Each holds an [`ExitGuard`] for its whole run, so every way
    /// out of it, a panic included, reports the exit and wakes the loop in
    /// [`run_to_stop`](crate::run::run_to_stop). A panic that leaves `run` is
    /// reported first, as that vCPU's failure with its message. A failed spawn
    /// stops the VM and spawns no further thread. The threads spawned before it
    /// are returned beside the error, so the caller can join them. `per_vcpu`
    /// must yield one item per vCPU. When it does not, the VM is stopped and no
    /// thread is spawned.
    pub(crate) fn spawn<T, I>(
        self: &Arc<Self>,
        per_vcpu: I,
        run: fn(u32, T),
    ) -> (VcpuThreads, io::Result<()>)
    where
        K: 'static,
        T: Send + 'static,
        I: IntoIterator<Item = T>,
        I::IntoIter: ExactSizeIterator,
    {
        let per_vcpu = per_vcpu.into_iter();
        if per_vcpu.len() != self.count as usize {
            self.stop();
            let e = io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} items for {} vCPUs", per_vcpu.len(), self.count),
            );
            return (VcpuThreads(Vec::new()), Err(e));
        }
        let mut threads = Vec::new();
        for (id, item) in (0..self.count).zip(per_vcpu) {
            let vcpus = Arc::clone(self);
            let exited = Arc::new(AtomicBool::new(false));
            let guard_exited = Arc::clone(&exited);
            // The guard is made on the thread, since a closure that fails to
            // spawn is dropped and its guard would count an exit.
            let spawned = std::thread::Builder::new()
                .name(format!("vcpu{id}"))
                .spawn(move || {
                    let exit = ExitGuard {
                        vcpus,
                        exited: guard_exited,
                    };
                    let unwound =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(id, item)));
                    if let Err(payload) = unwound {
                        exit.vcpus.report(Outcome::Failed(format!(
                            "vcpu{id}: panicked ({})",
                            crate::panic_message(payload.as_ref())
                        )));
                    }
                });
            match spawned {
                Ok(handle) => threads.push(VcpuThread { handle, exited }),
                Err(e) => {
                    self.stop();
                    let e = io::Error::new(e.kind(), format!("spawning the vcpu{id} thread: {e}"));
                    return (VcpuThreads(threads), Err(e));
                }
            }
        }
        (VcpuThreads(threads), Ok(()))
    }
}

/// No requester holds the quiesce.
const FREE: u8 = 0;
/// A plugin on cpu0 holds the quiesce, through [`Vcpus::pause`].
const PLUGIN: u8 = 1;
/// The control socket holds the quiesce, through [`Vcpus::pause_from_control`].
const CONTROL: u8 = 2;

/// Why a pause or resume from the control socket did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PauseError {
    /// The VM has stopped.
    Stopped,
    /// A plugin, or an earlier control pause, holds the quiesce.
    Busy,
    /// Only `parked` of the `expected` vCPUs parked before the deadline.
    Timeout {
        /// The vCPUs parked at the deadline.
        parked: u32,
        /// The vCPUs that had started.
        expected: u32,
    },
    /// The control socket holds no pause to release.
    NotPaused,
}

impl std::fmt::Display for PauseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => f.write_str("the VM has stopped"),
            Self::Busy => f.write_str("another pause holds the vCPUs"),
            Self::Timeout { parked, expected } => {
                write!(f, "{parked} of {expected} vCPUs parked in time")
            }
            Self::NotPaused => f.write_str("the vCPUs are not paused from the control socket"),
        }
    }
}

/// How a run ended.
#[derive(Clone, Debug)]
pub(crate) enum Outcome {
    /// The run stopped, as the guest or the host asked.
    Stopped(Stop),
    /// A vCPU or an I/O thread failed, with the text that says how.
    Failed(String),
}

impl Outcome {
    /// Returns the stop, or the failure as an error.
    pub(crate) fn into_result(self) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Outcome::Stopped(stop) => Ok(stop),
            Outcome::Failed(text) => Err(text.into()),
        }
    }
}

/// A guard that reports a vCPU thread's exit when dropped, held by each thread
/// [`Vcpus::spawn`] starts.
///
/// The drop marks the thread exited, counts the exit and wakes the loop in
/// [`run_to_stop`](crate::run::run_to_stop). It takes no lock, so it cannot
/// block on one the thread left held.
struct ExitGuard<K: Kick> {
    /// The vCPUs of the exiting thread's VM.
    vcpus: Arc<Vcpus<K>>,
    /// Whether the thread has exited, which the drop sets.
    exited: Arc<AtomicBool>,
}

impl<K: Kick> Drop for ExitGuard<K> {
    fn drop(&mut self) {
        // The flag is set before the count, so a thread the count includes
        // reads as exited.
        self.exited.store(true, Ordering::SeqCst);
        self.vcpus.exited.fetch_add(1, Ordering::SeqCst);
        self.vcpus.stop_handle.wake();
    }
}

/// The vCPU threads [`Vcpus::spawn`] started.
pub(crate) struct VcpuThreads(Vec<VcpuThread>);

/// A vCPU thread [`Vcpus::spawn`] started.
struct VcpuThread {
    /// The thread, which carries its name.
    handle: JoinHandle<()>,
    /// Whether the thread has exited, set by its [`ExitGuard`].
    exited: Arc<AtomicBool>,
}

impl VcpuThreads {
    /// Joins every vCPU thread of `vcpus` that exits within `timeout`.
    ///
    /// The wait ends when the last thread reports its exit. A thread still
    /// running after `timeout` is left running and reported on stderr, as is a
    /// wait that fails.
    ///
    /// # Errors
    ///
    /// Errors with the first thread that did not exit in time.
    pub(crate) fn join_timeout<K: Kick>(
        self,
        vcpus: &Vcpus<K>,
        timeout: Duration,
    ) -> io::Result<()> {
        let count = u32::try_from(self.0.len()).unwrap_or(u32::MAX);
        if let Err(e) = vcpus.wait_for_exits(count, Instant::now() + timeout) {
            stderrln!("{LOG_PREFIX} waiting for the vCPU threads: {e}");
        }
        let mut failure = None;
        for thread in self.0 {
            // A thread marks its exit from its last drop, so the join returns
            // at once.
            if thread.exited.load(Ordering::SeqCst) {
                let _ = thread.handle.join();
                continue;
            }
            let name = thread.handle.thread().name().unwrap_or("vCPU");
            let e = io::Error::other(format!("{name} did not stop within {timeout:?}"));
            stderrln!("{LOG_PREFIX} {e}; left running");
            failure.get_or_insert(e);
        }
        failure.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::cpu::VcpuState;
    use crate::checkpoint::platform::PlatformState;
    use std::os::unix::thread::JoinHandleExt;

    use crate::signal::{install_kick_handler, kick_signal};

    /// A kicker that counts its calls and reaches no thread.
    #[derive(Default)]
    struct CountingKicker {
        /// The number of calls to `kick_all`.
        all: AtomicU32,
        /// The number of calls to `kick_halted`.
        halted: AtomicU32,
    }

    impl Kick for CountingKicker {
        fn kick(&self, _cpu: u32) {}

        fn kick_all(&self) {
            self.all.fetch_add(1, Ordering::SeqCst);
        }

        fn kick_halted(&self) {
            self.halted.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A kicker that records, at the stop's last kick, whether a vCPU parked
    /// for a pause had resumed.
    struct ResumedAtKick {
        /// Whether the vCPU has left a checkpoint since the test cleared it.
        resumed: Arc<AtomicBool>,
        /// The value `resumed` had at the stop's last kick.
        seen: Mutex<Option<bool>>,
    }

    impl Kick for ResumedAtKick {
        fn kick(&self, _cpu: u32) {}

        fn kick_all(&self) {}

        fn kick_halted(&self) {
            // If the stop released the quiesce before kicking, give the vCPU
            // time to leave its checkpoint.
            std::thread::sleep(Duration::from_millis(50));
            *self.seen.lock().unwrap() = Some(self.resumed.load(Ordering::SeqCst));
        }
    }

    /// Returns the state of `count` vCPUs that `kicker` kicks, with a wake of
    /// their own.
    fn test_vcpus<K: Kick>(count: u32, kicker: K) -> Vcpus<K> {
        Vcpus::new(count, kicker, StopHandle::new_pair().unwrap().0)
    }

    /// Waits up to five seconds for `thread` to exit.
    fn exits<T>(thread: &JoinHandle<T>) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !thread.is_finished() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }

    #[test]
    fn stop_kicks_only_once() {
        let vcpus = test_vcpus(2, CountingKicker::default());
        vcpus.stop();
        vcpus.stop();
        assert!(!vcpus.is_running());
        assert_eq!(vcpus.kicker().all.load(Ordering::SeqCst), 1);
        assert_eq!(vcpus.kicker().halted.load(Ordering::SeqCst), 1);
    }

    // A vCPU parked for a pause waits on a condition variable no kick ends, so
    // a stop that left the quiesce held would keep its thread, and the join of
    // the vCPU threads, waiting forever.
    #[test]
    fn stop_releases_a_vcpu_parked_for_a_pause() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        vcpus.mark_started(0);
        vcpus.mark_started(1);
        let secondary = {
            let vcpus = Arc::clone(&vcpus);
            std::thread::spawn(move || {
                while vcpus.is_running() {
                    let _ = vcpus.checkpoint();
                    std::thread::yield_now();
                }
            })
        };
        assert!(vcpus.pause(), "the secondary did not park");
        vcpus.stop();
        assert!(exits(&secondary), "the parked vCPU stayed parked");
    }

    // A parked vCPU released before its kick could enter the guest again while
    // the plugin that paused it still reads guest memory.
    #[test]
    fn stop_kicks_a_parked_vcpu_before_releasing_it() {
        let resumed = Arc::new(AtomicBool::new(false));
        let kicker = ResumedAtKick {
            resumed: Arc::clone(&resumed),
            seen: Mutex::new(None),
        };
        let vcpus = Arc::new(test_vcpus(2, kicker));
        vcpus.mark_started(0);
        vcpus.mark_started(1);
        let secondary = {
            let (vcpus, resumed) = (Arc::clone(&vcpus), Arc::clone(&resumed));
            std::thread::spawn(move || {
                while vcpus.is_running() {
                    let _ = vcpus.checkpoint();
                    resumed.store(true, Ordering::SeqCst);
                    std::thread::yield_now();
                }
            })
        };
        assert!(vcpus.pause(), "the secondary did not park");
        resumed.store(false, Ordering::SeqCst);
        vcpus.stop();
        assert!(exits(&secondary), "the parked vCPU stayed parked");
        assert_eq!(
            *vcpus.kicker().seen.lock().unwrap(),
            Some(false),
            "the stop released the vCPU before it kicked"
        );
    }

    // A secondary the guest never brings up never reaches a checkpoint, so a
    // pause that waited for it would always time out.
    #[test]
    fn pause_waits_only_for_started_vcpus() {
        let vcpus = Arc::new(test_vcpus(3, CountingKicker::default()));
        vcpus.mark_started(0);
        let (parking, parked) = std::sync::mpsc::channel();
        let secondary = {
            let vcpus = Arc::clone(&vcpus);
            std::thread::spawn(move || {
                vcpus.mark_started(1);
                parking.send(()).unwrap();
                while vcpus.is_running() {
                    let _ = vcpus.checkpoint();
                    std::thread::yield_now();
                }
            })
        };
        parked.recv().unwrap();
        assert!(vcpus.pause(), "the started secondary did not park");
        vcpus.resume();
        vcpus.stop();
        assert!(exits(&secondary));
    }

    // The guest brings a secondary up just as a pause begins, while another
    // started vCPU stays in the guest. A count read once at the start would let
    // the new secondary park in place of the running one.
    #[test]
    fn pause_waits_for_a_vcpu_that_starts_while_it_waits() {
        let vcpus = Arc::new(test_vcpus(3, CountingKicker::default()));
        vcpus.mark_started(0);
        vcpus.mark_started(1);
        let late = {
            let vcpus = Arc::clone(&vcpus);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                vcpus.mark_started(2);
                while vcpus.is_running() {
                    let _ = vcpus.checkpoint();
                    std::thread::yield_now();
                }
            })
        };
        assert!(!vcpus.pause(), "the pause returned while a vCPU ran");
        vcpus.stop();
        assert!(exits(&late));
    }

    // A started vCPU that leaves its loop during the wait never parks.
    #[test]
    fn pause_ends_when_the_vm_stops_during_the_wait() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        vcpus.mark_started(0);
        vcpus.mark_started(1);
        let stopper = {
            let vcpus = Arc::clone(&vcpus);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                vcpus.stop();
            })
        };
        let start = Instant::now();
        assert!(!vcpus.pause(), "the pause succeeded on a stopped VM");
        assert!(
            start.elapsed() < Duration::from_millis(250),
            "the pause waited {:?} after the stop",
            start.elapsed()
        );
        stopper.join().unwrap();
    }

    #[test]
    fn pause_that_times_out_releases_the_quiesce() {
        let vcpus = test_vcpus(2, CountingKicker::default());
        vcpus.mark_started(0);
        vcpus.mark_started(1);
        assert!(!vcpus.pause(), "the second vCPU never reaches a checkpoint");
        let checkpoint = std::thread::spawn(move || vcpus.checkpoint());
        assert!(exits(&checkpoint), "the quiesce stayed requested");
        assert!(
            checkpoint.join().unwrap().is_zero(),
            "parked after the quiesce ended"
        );
    }

    /// Spawns a fake vCPU that has started and parks at every checkpoint
    /// until the VM stops.
    fn parking_vcpu(vcpus: &Arc<Vcpus<CountingKicker>>) -> JoinHandle<()> {
        vcpus.mark_started(vcpus.started());
        let vcpus = Arc::clone(vcpus);
        std::thread::spawn(move || {
            while vcpus.is_running() {
                let _ = vcpus.checkpoint();
                std::thread::yield_now();
            }
        })
    }

    /// Waits up to five seconds for `n` vCPUs to be parked.
    fn parked(vcpus: &Vcpus<CountingKicker>, n: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while vcpus.parked() != n {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }

    // The control thread runs no vCPU. A wait for all but one, as a vCPU
    // requester does, would return with one vCPU still in the guest.
    #[test]
    fn control_pause_waits_for_every_started_vcpu() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        let first = parking_vcpu(&vcpus);
        let second = parking_vcpu(&vcpus);
        assert_eq!(vcpus.pause_from_control(Duration::from_secs(5)), Ok(2));
        assert_eq!(vcpus.kicker().all.load(Ordering::SeqCst), 1);
        assert_eq!(vcpus.parked(), 2, "a vCPU left while the pause held");
        vcpus.resume_from_control().unwrap();
        assert!(parked(&vcpus, 0), "the resume left a vCPU parked");
        vcpus.stop();
        assert!(exits(&first) && exits(&second));
    }

    // A checkpoint taken over a guest whose vCPUs did not all park would be
    // torn, so a missed deadline is an error, and the vCPUs that did park run
    // again rather than stay parked behind a pause nobody holds.
    #[test]
    fn control_pause_that_times_out_releases_and_fails() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        let running = parking_vcpu(&vcpus);
        // Started, and never reaches a checkpoint.
        vcpus.mark_started(vcpus.started());
        let started = Instant::now();
        let paused = vcpus.pause_from_control(Duration::from_millis(100));
        assert_eq!(
            paused,
            Err(PauseError::Timeout {
                parked: 1,
                expected: 2
            })
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(parked(&vcpus, 0), "the failed pause left a vCPU parked");
        assert_eq!(vcpus.resume_from_control(), Err(PauseError::NotPaused));
        // The failed pause gave the quiesce back.
        assert!(vcpus.pause());
        vcpus.resume();
        vcpus.stop();
        assert!(exits(&running));
    }

    // cpu0 may be inside a plugin's safepoint when the control pause lands.
    // The plugin's resume must not let the guest run under the control pause.
    #[test]
    fn plugin_cannot_pause_or_resume_under_a_control_pause() {
        let vcpus = Arc::new(test_vcpus(1, CountingKicker::default()));
        let vcpu = parking_vcpu(&vcpus);
        assert_eq!(vcpus.pause_from_control(Duration::from_secs(5)), Ok(1));
        assert!(!vcpus.pause(), "the plugin paused under a control pause");
        vcpus.resume();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(vcpus.parked(), 1, "the plugin's resume released the vCPU");
        vcpus.resume_from_control().unwrap();
        assert!(parked(&vcpus, 0));
        vcpus.stop();
        assert!(exits(&vcpu));
    }

    // The reverse: a control pause that released the quiesce on its way out
    // would end a plugin's pause in the middle of its dump.
    #[test]
    fn control_pause_is_refused_while_a_plugin_holds_the_vcpus() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        // The calling thread is cpu0, inside its safepoint.
        vcpus.mark_started(vcpus.started());
        let secondary = parking_vcpu(&vcpus);
        assert!(vcpus.pause(), "the secondary did not park");
        assert_eq!(
            vcpus.pause_from_control(Duration::from_secs(5)),
            Err(PauseError::Busy)
        );
        assert_eq!(vcpus.resume_from_control(), Err(PauseError::NotPaused));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(vcpus.parked(), 1, "the refused pause released the vCPU");
        vcpus.resume();
        assert!(parked(&vcpus, 0));
        vcpus.stop();
        assert!(exits(&secondary));
    }

    // The stop releases the quiesce and notifies the wait, which must then
    // end at once rather than at its deadline.
    #[test]
    fn control_pause_ends_with_a_stop_during_its_wait() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        let running = parking_vcpu(&vcpus);
        // Started, and never reaches a checkpoint.
        vcpus.mark_started(vcpus.started());
        let pause = {
            let vcpus = Arc::clone(&vcpus);
            std::thread::spawn(move || vcpus.pause_from_control(Duration::from_secs(30)))
        };
        assert!(parked(&vcpus, 1));
        vcpus.stop();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !pause.is_finished() {
            assert!(Instant::now() < deadline, "the pause outlived the stop");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pause.join().unwrap(), Err(PauseError::Stopped));
        assert!(exits(&running));
    }

    #[test]
    fn control_pause_after_the_stop_is_refused() {
        let vcpus = test_vcpus(1, CountingKicker::default());
        vcpus.mark_started(vcpus.started());
        vcpus.stop();
        assert_eq!(
            vcpus.pause_from_control(Duration::from_millis(10)),
            Err(PauseError::Stopped)
        );
    }

    /// Spawns fake vCPU `cpu`, started, which parks at every checkpoint
    /// and serves work with `serve`.
    fn serving_vcpu(
        vcpus: &Arc<Vcpus<CountingKicker>>,
        cpu: u32,
        serve: fn(u32, Work<'_>) -> io::Result<Option<Output>>,
    ) -> JoinHandle<()> {
        vcpus.mark_started(vcpus.started());
        let vcpus = Arc::clone(vcpus);
        std::thread::spawn(move || {
            while vcpus.is_running() {
                let _ = vcpus.checkpoint_with(cpu, |work| serve(cpu, work));
                std::thread::yield_now();
            }
        })
    }

    fn export(cpu: u32, work: Work<'_>) -> io::Result<Option<Output>> {
        use crate::plugin::{GuestArch, RegsView};
        let view = RegsView {
            pc: 0x1000 + u64::from(cpu),
            ..RegsView::default()
        };
        match work {
            Work::Export => Ok(Some(Output::Vcpu {
                state: VcpuState::from_regs_view(GuestArch::Aarch64, "test", cpu, &view),
                irq: None,
            })),
            Work::ExportPlatform if cpu == 0 => Ok(Some(Output::Platform {
                platform: PlatformState::not_captured(GuestArch::Aarch64, "test"),
                capabilities: vec!["test-v1".into()],
            })),
            Work::ExportPlatform => Ok(None),
            Work::Import(_, plan) if plan.vcpus[cpu as usize].id() == cpu => Ok(None),
            Work::Import(_, plan) => Err(io::Error::other(format!(
                "vCPU {cpu} was handed the state of vCPU {}",
                plan.vcpus[cpu as usize].id()
            ))),
        }
    }

    fn exported(results: &[WorkResult]) -> Vec<u32> {
        results
            .iter()
            .map(|r| match r {
                WorkResult::Done(Some(out)) => match &**out {
                    Output::Vcpu { state, .. } => state.id(),
                    other => panic!("not a vCPU export: {other:?}"),
                },
                other => panic!("not an export: {other:?}"),
            })
            .collect()
    }

    // The platform is read by vCPU 0 alone, in a request of its own, so the
    // vCPUs' exports are all done by then.
    #[test]
    fn only_vcpu_0_reads_the_platform() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        let threads = [
            serving_vcpu(&vcpus, 0, export),
            serving_vcpu(&vcpus, 1, export),
        ];
        vcpus.pause_from_control(Duration::from_secs(5)).unwrap();
        vcpus.request_export();
        vcpus.wait_work(Duration::from_secs(5)).unwrap();
        assert_eq!(exported(&vcpus.end_work()), [0, 1]);
        vcpus.request_platform();
        vcpus.wait_work(Duration::from_secs(5)).unwrap();
        let results = vcpus.end_work();
        assert!(
            matches!(&results[0], WorkResult::Done(Some(out))
                if matches!(&**out, Output::Platform { capabilities, .. } if capabilities == &["test-v1"])),
            "{results:?}"
        );
        assert_eq!(results[1], WorkResult::Done(None));
        vcpus.stop();
        for thread in threads {
            assert!(exits(&thread));
        }
    }

    // pauses and then checkpoints. Work checked only on the way into a park
    // would never reach them.
    #[test]
    fn parked_vcpus_export_when_asked() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        let threads = [
            serving_vcpu(&vcpus, 0, export),
            serving_vcpu(&vcpus, 1, export),
        ];
        vcpus.pause_from_control(Duration::from_secs(5)).unwrap();
        vcpus.request_export();
        vcpus.wait_work(Duration::from_secs(5)).unwrap();
        assert_eq!(exported(&vcpus.end_work()), [0, 1]);
        assert_eq!(vcpus.parked(), 2, "a vCPU left its park to export");
        vcpus.resume_from_control().unwrap();
        vcpus.stop();
        for thread in threads {
            assert!(exits(&thread));
        }
    }

    // The export is asked for first and the vCPUs park afterwards, each
    // exporting on its way in.
    #[test]
    fn vcpus_export_as_they_park() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        let threads = [
            serving_vcpu(&vcpus, 0, export),
            serving_vcpu(&vcpus, 1, export),
        ];
        vcpus.request_export();
        vcpus.pause_from_control(Duration::from_secs(5)).unwrap();
        vcpus.wait_work(Duration::from_secs(5)).unwrap();
        assert_eq!(exported(&vcpus.end_work()), [0, 1]);
        vcpus.resume_from_control().unwrap();
        vcpus.stop();
        for thread in threads {
            assert!(exits(&thread));
        }
    }

    // A secondary the guest has not brought up has no thread at a checkpoint,
    // so the wait must not wait for it, and it is reported as such.
    #[test]
    fn a_vcpu_that_never_started_is_reported_not_started() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        let first = serving_vcpu(&vcpus, 0, export);
        vcpus.pause_from_control(Duration::from_secs(5)).unwrap();
        vcpus.request_export();
        vcpus.wait_work(Duration::from_secs(5)).unwrap();
        let results = vcpus.end_work();
        assert_eq!(exported(&results[..1]), [0]);
        assert_eq!(results[1], WorkResult::NotStarted);
        vcpus.stop();
        assert!(exits(&first));
    }

    #[test]
    fn each_vcpu_imports_its_own_state() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        let threads = [
            serving_vcpu(&vcpus, 0, export),
            serving_vcpu(&vcpus, 1, export),
        ];
        vcpus.pause_from_control(Duration::from_secs(5)).unwrap();
        let states = (0..2)
            .map(|cpu| VcpuState::powered_off(crate::plugin::GuestArch::Aarch64, "test", cpu))
            .collect();
        let plan = Arc::new(ImportPlan {
            vcpus: states,
            platform: PlatformState::not_captured(crate::plugin::GuestArch::Aarch64, "test"),
        });
        vcpus.request_import(ImportStep::Vcpu, plan);
        vcpus.wait_work(Duration::from_secs(5)).unwrap();
        assert_eq!(
            vcpus.end_work(),
            [WorkResult::Done(None), WorkResult::Done(None)]
        );
        vcpus.stop();
        for thread in threads {
            assert!(exits(&thread));
        }
    }

    #[test]
    fn a_failed_export_is_reported_with_its_reason() {
        fn refuse(_: u32, _: Work<'_>) -> io::Result<Option<Output>> {
            Err(io::Error::other("register read failed"))
        }
        let vcpus = Arc::new(test_vcpus(1, CountingKicker::default()));
        let vcpu = serving_vcpu(&vcpus, 0, refuse);
        vcpus.pause_from_control(Duration::from_secs(5)).unwrap();
        vcpus.request_export();
        vcpus.wait_work(Duration::from_secs(5)).unwrap();
        assert_eq!(
            vcpus.end_work(),
            [WorkResult::Failed("register read failed".into())]
        );
        vcpus.stop();
        assert!(exits(&vcpu));
    }

    // A started vCPU that never reaches a checkpoint never exports, and the
    // wait must say so in time rather than hang the control thread.
    #[test]
    fn the_wait_for_work_times_out() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        let first = serving_vcpu(&vcpus, 0, export);
        vcpus.mark_started(vcpus.started());
        vcpus.request_export();
        let started = Instant::now();
        assert_eq!(
            vcpus.wait_work(Duration::from_millis(100)),
            Err(PauseError::Timeout {
                parked: 0,
                expected: 2
            })
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        vcpus.end_work();
        vcpus.stop();
        assert!(exits(&first));
    }

    #[test]
    fn exit_guard_reports_only_the_exit_on_a_return() {
        let vcpus = Arc::new(test_vcpus(1, CountingKicker::default()));
        drop(ExitGuard {
            vcpus: Arc::clone(&vcpus),
            exited: Arc::default(),
        });
        vcpus.wait_for_stop(|| {}).unwrap();
        assert!(vcpus.is_running(), "the guard stopped the VM itself");
        assert!(matches!(vcpus.outcome(), Outcome::Stopped(Stop::SystemOff)));
    }

    // The loop waits for an exit on another thread than the vCPU's. An exit
    // after the wait began has to end it.
    #[test]
    fn wait_for_stop_ends_when_a_vcpu_thread_exits() {
        let vcpus = Arc::new(test_vcpus(1, CountingKicker::default()));
        let waiter = {
            let vcpus = Arc::clone(&vcpus);
            std::thread::spawn(move || vcpus.wait_for_stop(|| {}).unwrap())
        };
        std::thread::sleep(Duration::from_millis(20));
        assert!(!waiter.is_finished(), "the wait ended with no exit");
        let (threads, spawned) = vcpus.spawn([()], |_, ()| {});
        spawned.unwrap();
        assert!(exits(&waiter), "the exit did not end the wait");
        waiter.join().unwrap();
        threads
            .join_timeout(&vcpus, Duration::from_secs(5))
            .unwrap();
    }

    // A thread that panics reports the panic as the run's failure, since the
    // guard is held by the spawn and not by the code that panicked.
    #[test]
    fn spawned_thread_that_panics_reports_the_failure() {
        let vcpus = Arc::new(test_vcpus(1, CountingKicker::default()));
        let (threads, spawned) = vcpus.spawn([()], |_, ()| panic!("the vCPU loop panicked"));
        spawned.unwrap();
        threads
            .join_timeout(&vcpus, Duration::from_secs(5))
            .unwrap();
        assert!(matches!(
            vcpus.outcome(),
            Outcome::Failed(text) if text == "vcpu0: panicked (the vCPU loop panicked)"
        ));
    }

    #[test]
    fn wait_for_stop_ends_on_a_request() {
        let vcpus = Arc::new(test_vcpus(1, CountingKicker::default()));
        let waiter = {
            let vcpus = Arc::clone(&vcpus);
            std::thread::spawn(move || vcpus.wait_for_stop(|| {}).unwrap())
        };
        vcpus.stop_handle().request_stop();
        assert!(exits(&waiter), "the request did not end the wait");
        waiter.join().unwrap();
        assert!(matches!(vcpus.outcome(), Outcome::Stopped(Stop::Requested)));
    }

    // A vCPU that fails before the loop acts on a request is the failure the
    // run returns.
    #[test]
    fn report_wins_over_a_request() {
        let vcpus = test_vcpus(1, CountingKicker::default());
        vcpus.report(Outcome::Failed("vcpu0: KVM internal error".to_string()));
        vcpus.stop_handle().request_stop();
        assert!(matches!(vcpus.outcome(), Outcome::Failed(_)));
    }

    // The error names the thread still running, not the one beside it that
    // exited.
    #[test]
    fn join_timeout_leaves_a_thread_that_does_not_exit() {
        let vcpus = Arc::new(test_vcpus(2, CountingKicker::default()));
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (threads, spawned) = vcpus.spawn([None, Some(Mutex::new(released))], |_, released| {
            if let Some(released) = released {
                let _ = released.lock().unwrap().recv();
            }
        });
        spawned.unwrap();
        let error = threads
            .join_timeout(&vcpus, Duration::from_millis(500))
            .expect_err("a running thread was joined");
        assert!(
            error.to_string().starts_with("vcpu1 did not stop"),
            "{error}"
        );
        release.send(()).unwrap();
    }

    // A signal that interrupts the wait does not extend it, so a wait that
    // signals keep interrupting still ends at its deadline.
    #[test]
    fn interrupted_wait_for_exits_ends_at_its_deadline() {
        install_kick_handler();
        let vcpus = Arc::new(test_vcpus(1, CountingKicker::default()));
        let deadline = Instant::now() + Duration::from_millis(500);
        let waiter = {
            let vcpus = Arc::clone(&vcpus);
            std::thread::spawn(move || vcpus.wait_for_exits(1, deadline))
        };
        while !waiter.is_finished() {
            // SAFETY: a signal to a thread of this process that is not joined
            // yet, for which `install_kick_handler` installed a handler that
            // does nothing.
            unsafe { libc::pthread_kill(waiter.as_pthread_t() as libc::pthread_t, kick_signal()) };
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                Instant::now() < deadline + Duration::from_secs(5),
                "the signals kept the wait from its deadline"
            );
        }
        assert!(!waiter.join().unwrap().unwrap(), "no vCPU thread exited");
        assert!(Instant::now() >= deadline);
    }

    #[test]
    fn spawn_runs_each_vcpu_on_a_thread_named_after_it() {
        let vcpus = Arc::new(test_vcpus(3, CountingKicker::default()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (threads, spawned) = vcpus.spawn(
            (0..3).map(|n| (Arc::clone(&seen), n * 10)),
            |id, (seen, item)| {
                let name = std::thread::current().name().map(String::from);
                seen.lock().unwrap().push((id, item, name));
            },
        );
        spawned.unwrap();
        threads
            .join_timeout(&vcpus, Duration::from_secs(5))
            .unwrap();
        let mut seen = seen.lock().unwrap().clone();
        seen.sort();
        assert_eq!(
            seen,
            [
                (0, 0, Some("vcpu0".to_string())),
                (1, 10, Some("vcpu1".to_string())),
                (2, 20, Some("vcpu2".to_string())),
            ]
        );
    }

    #[test]
    fn spawn_rejects_items_for_another_number_of_vcpus() {
        let vcpus = Arc::new(test_vcpus(3, CountingKicker::default()));
        let (threads, spawned) = vcpus.spawn(0..2, |_, _: i32| {});
        threads
            .join_timeout(&vcpus, Duration::from_secs(5))
            .unwrap();
        assert_eq!(spawned.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(!vcpus.is_running());
    }

    #[test]
    fn outcome_is_system_off_until_a_vcpu_reports_one() {
        let vcpus = test_vcpus(1, CountingKicker::default());
        assert!(matches!(vcpus.outcome(), Outcome::Stopped(Stop::SystemOff)));
        vcpus.report(Outcome::Stopped(Stop::SystemReset));
        assert!(matches!(
            vcpus.outcome(),
            Outcome::Stopped(Stop::SystemReset)
        ));
    }

    // A failure on one vCPU stops the VM, and a vCPU that then stops on its own
    // must not replace the failure with a clean stop.
    #[test]
    fn first_report_is_the_outcome() {
        let vcpus = test_vcpus(2, CountingKicker::default());
        vcpus.report(Outcome::Failed("vcpu1: KVM internal error".to_string()));
        vcpus.report(Outcome::Stopped(Stop::SystemOff));
        assert!(
            matches!(vcpus.outcome(), Outcome::Failed(text) if text == "vcpu1: KVM internal error")
        );
    }

    #[test]
    fn failure_takes_the_place_of_an_earlier_stop() {
        let vcpus = test_vcpus(2, CountingKicker::default());
        vcpus.report(Outcome::Stopped(Stop::SystemOff));
        vcpus.report(Outcome::Failed("vcpu1: failed".into()));
        vcpus.report(Outcome::Failed("vcpu0: failed".into()));
        vcpus.report(Outcome::Stopped(Stop::SystemReset));
        assert!(matches!(vcpus.outcome(), Outcome::Failed(text) if text == "vcpu1: failed"));
    }
}

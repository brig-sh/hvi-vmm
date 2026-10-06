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
//! VM still runs, the quiesce that parks them for a plugin, the reason the
//! guest stopped and how many there are. Each vCPU thread checks the first two
//! at the top of its run loop, between guest entries. The stop clears the
//! running flag, kicks every vCPU out of the hypervisor and then releases the
//! quiesce, so each one sees the stop at its next check.
//!
//! How a kick reaches a vCPU depends on the hypervisor, so [`Vcpus`] takes it
//! from a [`Kick`] implementation that owns the table of vCPU threads.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread::JoinHandle;

use crate::config::Stop;
use crate::hypervisor::quiesce::Quiesce;
use crate::sync::lock_or_recover;

/// How the hypervisor ends a vCPU's run.
pub(crate) trait Kick: Send + Sync {
    /// Ends the current or next run of every vCPU but the caller's own.
    ///
    /// A kick from a vCPU's own thread is dropped: it would end that thread's
    /// next run before the guest ran.
    fn kick_all(&self);

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
    /// How the guest asked to stop, once it has.
    stop: Mutex<Option<Stop>>,
    /// The number of vCPUs.
    count: u32,
    /// The [`Kick`] implementation that kicks the vCPUs.
    kicker: K,
}

impl<K: Kick> Vcpus<K> {
    /// Returns the state of `count` vCPUs that `kicker` kicks.
    pub(crate) fn new(count: u32, kicker: K) -> Self {
        Self {
            running: AtomicBool::new(true),
            quiesce: Quiesce::new(),
            stop: Mutex::new(None),
            count,
            kicker,
        }
    }

    /// Returns the [`Kick`] implementation that kicks the vCPUs.
    pub(crate) fn kicker(&self) -> &K {
        &self.kicker
    }

    /// Returns whether the VM still runs.
    pub(crate) fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Parks the calling vCPU thread while a quiesce is in effect.
    ///
    /// A vCPU thread calls it between guest entries, where its registers and
    /// the memory it has written are stable.
    pub(crate) fn checkpoint(&self) {
        self.quiesce.checkpoint();
    }

    /// Parks every vCPU but the calling one at its next checkpoint.
    ///
    /// The caller is a vCPU thread and does not park itself. Returns `false`
    /// when they did not all park in time. The quiesce is then released
    /// already, and the caller must not call [`resume`](Self::resume).
    pub(crate) fn pause(&self) -> bool {
        self.quiesce.request();
        self.kicker.kick_all();
        if self.quiesce.wait_for(self.count.saturating_sub(1)) {
            true
        } else {
            self.quiesce.release();
            false
        }
    }

    /// Releases the vCPUs a successful [`pause`](Self::pause) parked.
    pub(crate) fn resume(&self) {
        self.quiesce.release();
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

    /// Returns a guard that ends the VM when dropped, on a panic as on a
    /// return.
    pub(crate) fn stop_on_drop(&self) -> StopOnDrop<'_, K> {
        StopOnDrop { vcpus: self }
    }

    /// Records how the guest asked to stop.
    pub(crate) fn set_stop_reason(&self, stop: Stop) {
        *lock_or_recover(&self.stop) = Some(stop);
    }

    /// Returns how the guest asked to stop, or [`Stop::SystemOff`] when it did
    /// not say.
    pub(crate) fn stop_reason(&self) -> Stop {
        lock_or_recover(&self.stop).unwrap_or(Stop::SystemOff)
    }

    /// Spawns one thread per vCPU, each running `run` with its id and the item
    /// of `per_vcpu` at that position.
    ///
    /// Each thread is named after its vCPU, so a panic report says which one
    /// panicked. A failed spawn stops the VM and spawns no further thread. The
    /// threads spawned before it are returned beside the error, so the caller
    /// can join them. `per_vcpu` must yield one item per vCPU. When it does
    /// not, the VM is stopped and no thread is spawned.
    pub(crate) fn spawn<T, I>(&self, per_vcpu: I, run: fn(u32, T)) -> (VcpuThreads, io::Result<()>)
    where
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
            let spawned = std::thread::Builder::new()
                .name(format!("cpu{id}"))
                .spawn(move || run(id, item));
            match spawned {
                Ok(thread) => threads.push(thread),
                Err(e) => {
                    self.stop();
                    let e = io::Error::new(e.kind(), format!("spawning the cpu{id} thread: {e}"));
                    return (VcpuThreads(threads), Err(e));
                }
            }
        }
        (VcpuThreads(threads), Ok(()))
    }
}

/// A guard that ends the VM when dropped, from [`Vcpus::stop_on_drop`].
pub(crate) struct StopOnDrop<'a, K: Kick> {
    /// The vCPUs whose VM the drop ends.
    vcpus: &'a Vcpus<K>,
}

impl<K: Kick> Drop for StopOnDrop<'_, K> {
    fn drop(&mut self) {
        self.vcpus.stop();
    }
}

/// The vCPU threads [`Vcpus::spawn`] started.
pub(crate) struct VcpuThreads(Vec<JoinHandle<()>>);

impl VcpuThreads {
    /// Waits for every vCPU thread to exit.
    pub(crate) fn join(self) {
        for thread in self.0 {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// A kicker that counts its calls and reaches no thread.
    #[derive(Default)]
    struct CountingKicker {
        /// The number of calls to `kick_all`.
        all: AtomicU32,
        /// The number of calls to `kick_halted`.
        halted: AtomicU32,
    }

    impl Kick for CountingKicker {
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
        fn kick_all(&self) {}

        fn kick_halted(&self) {
            // If the stop released the quiesce before kicking, give the vCPU
            // time to leave its checkpoint.
            std::thread::sleep(Duration::from_millis(50));
            *self.seen.lock().unwrap() = Some(self.resumed.load(Ordering::SeqCst));
        }
    }

    /// Waits up to five seconds for `thread` to exit.
    fn exits(thread: &JoinHandle<()>) -> bool {
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
        let vcpus = Vcpus::new(2, CountingKicker::default());
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
        let vcpus = Arc::new(Vcpus::new(2, CountingKicker::default()));
        let secondary = {
            let vcpus = Arc::clone(&vcpus);
            std::thread::spawn(move || {
                while vcpus.is_running() {
                    vcpus.checkpoint();
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
        let vcpus = Arc::new(Vcpus::new(2, kicker));
        let secondary = {
            let (vcpus, resumed) = (Arc::clone(&vcpus), Arc::clone(&resumed));
            std::thread::spawn(move || {
                while vcpus.is_running() {
                    vcpus.checkpoint();
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

    #[test]
    fn pause_that_times_out_releases_the_quiesce() {
        let vcpus = Vcpus::new(2, CountingKicker::default());
        assert!(!vcpus.pause(), "no second vCPU exists to park");
        let checkpoint = std::thread::spawn(move || vcpus.checkpoint());
        assert!(exits(&checkpoint), "the quiesce stayed requested");
    }

    #[test]
    fn stop_on_drop_ends_the_vm_on_a_panic() {
        let vcpus = Vcpus::new(1, CountingKicker::default());
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _stop = vcpus.stop_on_drop();
            panic!("the run loop panicked");
        }));
        assert!(unwound.is_err());
        assert!(!vcpus.is_running());
    }

    #[test]
    fn spawn_runs_each_vcpu_on_a_thread_named_after_it() {
        let vcpus = Vcpus::new(3, CountingKicker::default());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (threads, spawned) = vcpus.spawn(
            (0..3).map(|n| (Arc::clone(&seen), n * 10)),
            |id, (seen, item)| {
                let name = std::thread::current().name().map(String::from);
                seen.lock().unwrap().push((id, item, name));
            },
        );
        spawned.unwrap();
        threads.join();
        let mut seen = seen.lock().unwrap().clone();
        seen.sort();
        assert_eq!(
            seen,
            [
                (0, 0, Some("cpu0".to_string())),
                (1, 10, Some("cpu1".to_string())),
                (2, 20, Some("cpu2".to_string())),
            ]
        );
    }

    #[test]
    fn spawn_rejects_items_for_another_number_of_vcpus() {
        let vcpus = Vcpus::new(3, CountingKicker::default());
        let (threads, spawned) = vcpus.spawn(0..2, |_, _: i32| {});
        threads.join();
        assert_eq!(spawned.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(!vcpus.is_running());
    }

    #[test]
    fn stop_reason_is_system_off_until_the_guest_names_one() {
        let vcpus = Vcpus::new(1, CountingKicker::default());
        assert!(matches!(vcpus.stop_reason(), Stop::SystemOff));
        vcpus.set_stop_reason(Stop::SystemReset);
        assert!(matches!(vcpus.stop_reason(), Stop::SystemReset));
    }
}

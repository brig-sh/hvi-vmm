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

//! The host-side I/O threads a backend runs beside its vCPUs.
//!
//! [`IoThreads`] starts the console reader, the threads a plugin asked for in
//! `on_attach`, and the threads that serve the guest from the host, such as the
//! agent bridge and the network relay, which each device queues in a
//! [`HostWork`]. Each thread polls a stop token beside its own descriptor. Once
//! the vCPUs have exited or been left running, [`IoThreads::stop`] requests the
//! stop and joins every thread, as `teardown` describes.

use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::hypervisor::guest::{Guest, PluginThread};
use crate::hypervisor::vcpus::{Kick, Outcome, Vcpus};
use crate::plugin::Plugin;
use crate::run::LeftRunning;
use crate::sandbox::confine_io_thread;
use crate::signal::kick_signal;
use crate::teardown::{FinishCount, FinishGuard, StopSource, StopToken, STOP_TIMEOUT};
use crate::terminal;
use crate::LOG_PREFIX;

/// The threads and stop actions that serve the guest from the host, held until
/// the I/O threads start.
///
/// A thread spawned before the seccomp filters are armed would run unfiltered,
/// so a device or the backend queues its threads here and [`IoThreads::start`]
/// spawns them.
#[derive(Default)]
pub(crate) struct HostWork {
    /// The threads, each with its name and what it runs.
    threads: Vec<PluginThread>,
    /// The actions the I/O threads' stop runs, for a thread that waits on
    /// something a stop token cannot reach.
    io_stops: Vec<Box<dyn FnOnce() + Send>>,
    /// The hooks the vCPUs' stop runs, for a vCPU that waits outside the
    /// hypervisor.
    vcpu_stops: Vec<Box<dyn Fn() + Send + Sync>>,
}

impl HostWork {
    /// Queues a thread named `name` that runs `run` with a stop token.
    ///
    /// The I/O threads' stop only joins the thread, so `run` has to return on
    /// its own: it watches the token, or an action queued with
    /// [`on_io_stop`](Self::on_io_stop) ends it. A panic in the thread fails
    /// the run and asks it to stop.
    pub(crate) fn spawn(
        &mut self,
        name: &'static str,
        run: impl FnOnce(StopToken) + Send + 'static,
    ) {
        self.threads.push(PluginThread {
            name,
            run: Box::new(run),
        });
    }

    /// Queues `action` for the I/O threads' stop, which runs it before it joins
    /// the threads.
    ///
    /// It is for a thread that waits on something a stop token cannot reach,
    /// such as a condition variable. The action must return at once.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn on_io_stop(&mut self, action: impl FnOnce() + Send + 'static) {
        self.io_stops.push(Box::new(action));
    }

    /// Queues `hook` for the vCPUs' stop, as [`Vcpus::on_stop`] describes.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn on_vcpu_stop(&mut self, hook: impl Fn() + Send + Sync + 'static) {
        self.vcpu_stops.push(Box::new(hook));
    }
}

/// A guard that, when its I/O thread panics, reports the run failed and asks it
/// to stop.
struct StopOnPanic<K: Kick> {
    /// The vCPUs of the run.
    vcpus: Arc<Vcpus<K>>,
    /// The name of the thread that holds the guard.
    name: &'static str,
}

impl<K: Kick> Drop for StopOnPanic<K> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.vcpus
                .report(Outcome::Failed(format!("{}: panicked", self.name)));
            self.vcpus.stop_handle().request_stop();
        }
    }
}

/// The I/O threads of one VM and the stop that ends them.
///
/// They serve the guest's devices from the host, beside any thread the backend
/// queued in its [`HostWork`], such as the x86 trace watchdog.
pub(crate) struct IoThreads<K: Kick> {
    /// The vCPUs of the run, which a thread that panics stops.
    vcpus: Arc<Vcpus<K>>,
    /// The stop the threads poll, and the actions it runs.
    stop: StopPlan,
    /// The console reader, which the stop also has to signal.
    console: IoThread,
    /// Every other thread.
    threads: Vec<IoThread>,
    /// The count each thread notes on as it ends.
    finish_count: Arc<FinishCount>,
}

/// The stop of a run's I/O threads: the stop they poll, and the actions for the
/// threads that wait on something else.
///
/// Dropping it runs it, so the threads also stop when the `IoThreads` that
/// holds it drops without a [`stop`](IoThreads::stop), as in an unwind.
struct StopPlan {
    /// The stop the threads poll.
    source: StopSource,
    /// The actions that run after the request, in the order they were added.
    actions: Vec<Box<dyn FnOnce() + Send>>,
}

impl StopPlan {
    /// Requests the stop and runs the actions not yet run.
    fn run(&mut self) {
        self.source.request_stop();
        for action in std::mem::take(&mut self.actions) {
            action();
        }
    }
}

impl Drop for StopPlan {
    fn drop(&mut self) {
        self.run();
    }
}

impl<K: Kick> IoThreads<K> {
    /// Starts the console reader, adds the stop actions and hooks `host` holds,
    /// then starts `plugin_threads` and the devices' threads in `host`.
    ///
    /// `deliver` hands a console byte to the guest's UART. The console's
    /// request key asks `plugin` for an observation and kicks the boot vCPU,
    /// which runs it.
    ///
    /// # Errors
    ///
    /// Errors when a thread cannot be started. The threads already started are
    /// then stopped and joined, and one that does not stop makes the error a
    /// [`LeftRunning`].
    pub(crate) fn start(
        source: StopSource,
        guest: &Arc<Guest<K>>,
        plugin: Option<Arc<dyn Plugin>>,
        deliver: impl FnMut(u8) + Send + 'static,
        plugin_threads: Vec<PluginThread>,
        host: HostWork,
    ) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        K: 'static,
    {
        let vcpus = Arc::clone(&guest.vcpus);
        let finish_count = Arc::new(FinishCount::default());
        let console = IoThread::spawn(
            "console reader",
            source.token(),
            &finish_count,
            Arc::clone(&guest.vcpus),
            move |stop| {
                terminal::input::run(plugin, &stop, move || vcpus.kicker().kick(0), deliver);
            },
        )?;
        let mut io_threads = Self {
            vcpus: Arc::clone(&guest.vcpus),
            stop: StopPlan {
                source,
                actions: Vec::new(),
            },
            console,
            threads: Vec::new(),
            finish_count,
        };
        let HostWork {
            threads,
            io_stops,
            vcpu_stops,
        } = host;
        // The stop actions and hooks are added before the plugin's and the
        // devices' threads start, so the stop after a failed start still ends
        // the threads already started.
        io_threads.stop.actions.extend(io_stops);
        for hook in vcpu_stops {
            guest.vcpus.on_stop(hook);
        }
        io_threads.spawn_all(plugin_threads.into_iter().chain(threads))
    }

    /// Starts each of `threads` in order, to be joined with the others.
    ///
    /// It has to be called from a thread with no seccomp filter, since naming
    /// a new thread calls `prctl`, which neither allowlist has.
    ///
    /// # Errors
    ///
    /// Errors when a thread cannot be started, after stopping the others as
    /// [`start`](Self::start) describes.
    fn spawn_all(
        mut self,
        threads: impl IntoIterator<Item = PluginThread>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        K: 'static,
    {
        for PluginThread { name, run } in threads {
            let spawned = IoThread::spawn(
                name,
                self.stop.source.token(),
                &self.finish_count,
                Arc::clone(&self.vcpus),
                run,
            );
            match spawned {
                Ok(thread) => self.threads.push(thread),
                Err(e) => return Err(LeftRunning::wrap(e.into(), self.stop().err())),
            }
        }
        Ok(self)
    }

    /// Requests the stop and joins every thread.
    ///
    /// The stop actions run after the request, in the order they were added.
    /// The console reader also gets the kick signal until it has finished,
    /// since a read of stdin is where the stop token cannot reach it. The wait
    /// for the threads ends when the last one has finished, or [`STOP_TIMEOUT`]
    /// after the stop actions have run. A thread still running then is left
    /// running and reported on stderr.
    ///
    /// # Errors
    ///
    /// Errors with the first thread that did not stop in time.
    pub(crate) fn stop(mut self) -> std::io::Result<()> {
        self.stop.run();
        let deadline = Instant::now() + STOP_TIMEOUT;
        self.console
            .kick_until_finished(&self.finish_count, deadline);
        let count = u32::try_from(self.threads.len() + 1).unwrap_or(u32::MAX);
        let _ = self.finish_count.wait_for(count, deadline);
        let mut failure = None;
        for thread in std::iter::once(self.console).chain(self.threads) {
            if let Err(e) = thread.try_join() {
                stderrln!("{LOG_PREFIX} {e}; left running");
                failure.get_or_insert(e);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
impl<K: Kick + 'static> IoThreads<K> {
    /// Returns the I/O threads of a run of `vcpus` with no devices, whose
    /// console reader returns at once.
    pub(crate) fn idle(vcpus: Arc<Vcpus<K>>) -> Self {
        let source = StopSource::new().expect("stop pair");
        let finish_count = Arc::new(FinishCount::default());
        let console = IoThread::spawn(
            "console reader",
            source.token(),
            &finish_count,
            Arc::clone(&vcpus),
            |_| {},
        )
        .expect("the console reader should start");
        Self {
            vcpus,
            stop: StopPlan {
                source,
                actions: Vec::new(),
            },
            console,
            threads: Vec::new(),
            finish_count,
        }
    }
}

/// An I/O thread, with the flag it sets as it ends.
struct IoThread {
    /// The thread, which carries its name.
    handle: JoinHandle<()>,
    /// Whether the thread has finished, set by its [`FinishGuard`].
    finished: Arc<AtomicBool>,
}

/// Returns the builder of the I/O thread `name`.
///
/// In a test, the thread named in `tests::REFUSED` asks for a 256 TiB stack.
/// That is at least the address range a mapping gets by default on x86-64,
/// arm64 Linux and macOS, so the OS refuses it whatever the overcommit setting.
fn thread_builder(name: &'static str) -> std::thread::Builder {
    let builder = std::thread::Builder::new().name(name.to_string());
    #[cfg(test)]
    if tests::REFUSED.get() == Some(name) {
        return builder.stack_size(1 << 48);
    }
    builder
}

impl IoThread {
    /// Starts a thread named `name` that confines itself and then runs `body`
    /// with `stop`.
    ///
    /// The thread holds a [`FinishGuard`] that notes on `count`, and a
    /// [`StopOnPanic`] that fails and stops the run of `vcpus` if it panics.
    ///
    /// # Errors
    ///
    /// Errors with the thread's name when the thread cannot be created.
    fn spawn<K: Kick + 'static>(
        name: &'static str,
        stop: StopToken,
        count: &Arc<FinishCount>,
        vcpus: Arc<Vcpus<K>>,
        body: impl FnOnce(StopToken) + Send + 'static,
    ) -> io::Result<Self> {
        let finished = Arc::new(AtomicBool::new(false));
        // The guard is built on the thread, so a thread that is never created
        // notes nothing.
        let (flag, count) = (Arc::clone(&finished), Arc::clone(count));
        let handle = thread_builder(name)
            .spawn(move || {
                let _finished = FinishGuard {
                    finished: flag,
                    count,
                };
                let _panic = StopOnPanic { vcpus, name };
                confine_io_thread();
                body(stop);
            })
            .map_err(|e| io::Error::new(e.kind(), format!("spawning the {name} thread: {e}")))?;
        Ok(Self { handle, finished })
    }

    /// Sends the kick signal to the thread until its flag is set, or until
    /// `deadline` passes.
    ///
    /// The signal ends a blocking read on the thread with `EINTR`. It is sent
    /// again after each wait, since a signal sent before the read blocks is
    /// lost. Between two kicks the loop waits on `count` for at most a
    /// millisecond. A note from any thread, this one included, ends that wait
    /// sooner. The loop stops at the deadline when the signal cannot end the
    /// read.
    fn kick_until_finished(&self, count: &FinishCount, deadline: Instant) {
        use std::os::unix::thread::JoinHandleExt;
        loop {
            // The count is read before the flag, so a note that lands after the
            // check ends the wait below at once.
            let finished = count.finished();
            if self.finished.load(Ordering::SeqCst) || Instant::now() >= deadline {
                return;
            }
            // SAFETY: the handle has not been joined, so its thread id is live;
            // the handler is a no-op. The cast is for musl, where std and libc
            // spell `pthread_t` differently.
            unsafe {
                libc::pthread_kill(self.handle.as_pthread_t() as libc::pthread_t, kick_signal())
            };
            let _ = count.wait_for(
                finished + 1,
                (Instant::now() + Duration::from_millis(1)).min(deadline),
            );
        }
    }

    /// Joins the thread if it has finished.
    ///
    /// A thread that has set its flag has left its body, so the join returns at
    /// once.
    ///
    /// # Errors
    ///
    /// Errors with the thread's name when it has not finished.
    fn try_join(self) -> std::io::Result<()> {
        if self.finished.load(Ordering::SeqCst) {
            let _ = self.handle.join();
            return Ok(());
        }
        let name = self.handle.thread().name().unwrap_or("an I/O thread");
        Err(std::io::Error::other(format!(
            "{name} did not stop within {STOP_TIMEOUT:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Mutex;

    use super::*;
    use crate::run::StopHandle;

    thread_local! {
        /// The name of the I/O thread whose start fails, for a test that runs on
        /// this thread.
        pub(super) static REFUSED: Cell<Option<&'static str>> = const { Cell::new(None) };
    }

    /// A kicker that reaches no thread.
    struct NoopKicker;

    impl Kick for NoopKicker {
        fn kick(&self, _cpu: u32) {}

        fn kick_all(&self) {}

        fn try_kick_all(&self) -> bool {
            true
        }
    }

    /// Returns the vCPUs of a run with one vCPU and no threads.
    fn vcpus() -> Arc<Vcpus<NoopKicker>> {
        Arc::new(Vcpus::new(1, NoopKicker, StopHandle::new_pair().unwrap().0))
    }

    /// Starts a thread that runs `body`, notes on `count` and stops the run of
    /// `vcpus` if it panics.
    fn spawn(
        count: &Arc<FinishCount>,
        vcpus: &Arc<Vcpus<NoopKicker>>,
        body: impl FnOnce() + Send + 'static,
    ) -> IoThread {
        let source = StopSource::new().unwrap();
        IoThread::spawn(
            "test",
            source.token(),
            count,
            Arc::clone(vcpus),
            move |_| body(),
        )
        .unwrap()
    }

    // The OS refuses the third thread. The two started before it are stopped
    // and joined before the error returns, and the fourth never starts.
    #[test]
    fn refused_thread_stops_the_threads_started_before_it() {
        // The stop kicks the console reader, so the kick signal needs its
        // handler.
        crate::signal::install_kick_handler();
        let ran = Arc::new(Mutex::new(Vec::new()));
        let thread = |name: &'static str| {
            let ran = Arc::clone(&ran);
            PluginThread {
                name,
                run: Box::new(move |stop: StopToken| {
                    let _ = stop.sleep(Duration::from_secs(5));
                    ran.lock().unwrap().push(name);
                }),
            }
        };
        let threads = [
            thread("first"),
            thread("second"),
            thread("third"),
            thread("fourth"),
        ];
        REFUSED.set(Some("third"));
        let started = IoThreads::idle(vcpus()).spawn_all(threads);
        REFUSED.set(None);
        let error = started.err().expect("the third thread should be refused");
        assert!(
            error.to_string().starts_with("spawning the third thread: "),
            "{error}"
        );
        let mut ran = ran.lock().unwrap().clone();
        ran.sort_unstable();
        assert_eq!(ran, ["first", "second"]);
    }

    // An unwind drops the threads without `stop`. They are still asked to stop,
    // and the actions for the threads a token does not reach still run.
    #[test]
    fn dropping_the_threads_runs_their_stop() {
        let mut threads = IoThreads::idle(vcpus());
        let (ran, has_run) = std::sync::mpsc::channel();
        threads
            .stop
            .actions
            .push(Box::new(move || ran.send(()).unwrap()));
        let token = threads.stop.source.token();
        drop(threads);
        assert!(has_run.try_recv().is_ok(), "the stop action did not run");
        assert!(!token.sleep(Duration::from_secs(5)).unwrap());
    }

    #[test]
    fn thread_that_exits_is_noted_and_joined() {
        let count = Arc::new(FinishCount::default());
        let thread = spawn(&count, &vcpus(), || {});
        assert!(count.wait_for(1, Instant::now() + Duration::from_secs(5)));
        thread.try_join().unwrap();
    }

    #[test]
    fn thread_that_panics_fails_the_run_and_stops_it() {
        let (count, vcpus) = (Arc::new(FinishCount::default()), vcpus());
        let thread = spawn(&count, &vcpus, || panic!("a test panic"));
        assert!(count.wait_for(1, Instant::now() + Duration::from_secs(5)));
        thread.try_join().unwrap();
        assert!(vcpus.stop_handle().is_stop_requested());
        assert!(
            matches!(vcpus.outcome(), Outcome::Failed(text) if text == "test: panicked"),
            "{:?}",
            vcpus.outcome()
        );
    }

    // A thread stuck in a call the stop cannot interrupt must be reported once
    // the wait ends, or `boot` would not return. The thread beside it that
    // finished is still joined.
    #[test]
    fn thread_that_does_not_exit_is_reported() {
        let count = Arc::new(FinishCount::default());
        let (release, released) = std::sync::mpsc::channel::<()>();
        let vcpus = vcpus();
        let stuck = spawn(&count, &vcpus, move || {
            let _ = released.recv();
        });
        let quick = spawn(&count, &vcpus, || {});
        assert!(count.wait_for(1, Instant::now() + Duration::from_secs(5)));
        quick.try_join().unwrap();
        assert!(!count.wait_for(2, Instant::now() + Duration::from_millis(50)));
        let error = stuck.try_join().expect_err("a running thread was joined");
        assert!(
            error.to_string().starts_with("test did not stop"),
            "{error}"
        );
        release.send(()).unwrap();
    }

    // The thread blocks in a read until a kick ends it with `EINTR`, so the
    // loop ends early only if its kick reaches the read.
    #[test]
    fn kick_loop_ends_once_a_kick_ends_the_read() {
        crate::signal::install_kick_handler();
        let (mut read, _write) = std::io::pipe().unwrap();
        let count = Arc::new(FinishCount::default());
        let thread = spawn(&count, &vcpus(), move || {
            let mut byte = [0u8; 1];
            let _ = std::io::Read::read(&mut read, &mut byte);
        });
        let start = Instant::now();
        thread.kick_until_finished(&count, Instant::now() + Duration::from_secs(5));
        assert!(start.elapsed() < Duration::from_secs(1));
        thread.try_join().unwrap();
    }
}

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
//! [`IoThreads`] starts the threads that serve the guest's devices from the
//! host: the console reader, the agent bridge, and the relay from a gateway or
//! a tap. Each polls a stop token beside its own descriptor. [`IoThreads`] also
//! starts the threads a plugin asked for in `attach`. A backend starts the
//! threads only it has with [`IoThreads::spawn`]. Once the vCPUs have exited or
//! been left running, [`IoThreads::stop`] requests the stop and joins every
//! thread, as `teardown` describes.
//!
//! Each thread passes the token's pause gate around the work that touches a
//! device or guest RAM, so a pause of the gate holds all of them back. The
//! console's bytes are delivered inside the gate, and the relays receive and
//! deliver their frames inside it. The control socket's thread, when there is
//! one, is the one that closes it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::checkpoint::server::ControlSocket;
use crate::devices::virtio::net::GatewayRelay;
#[cfg(target_os = "linux")]
use crate::devices::virtio::net::TapRelay;
use crate::devices::virtio::vsock::VsockBridge;
use crate::hypervisor::guest::{Guest, PluginThread};
use crate::hypervisor::vcpus::{Kick, Outcome, Vcpus};
use crate::plugin::Plugin;
use crate::sandbox::{confine_control_thread, confine_io_thread};
use crate::signal::kick_signal;
use crate::sync::lock_or_recover;
use crate::teardown::{FinishCount, FinishGuard, StopSource, StopToken, STOP_TIMEOUT};
use crate::terminal;
use crate::LOG_PREFIX;

/// Where the network's frames come from, when they come from the host.
pub(crate) enum NetSource {
    /// A gvisor-tap-vsock gateway, over a stream socket.
    Gateway(std::os::unix::net::UnixStream),
    /// A tap device.
    #[cfg(target_os = "linux")]
    Tap(std::fs::File),
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
/// They serve the guest's devices from the host. A backend can start a thread
/// of its own under the same stop, such as the x86 trace watchdog. It can also
/// add a stop action for a thread that waits on something other than a stop
/// token.
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
    /// Starts the console reader, then the agent bridge, the network relay and
    /// the control socket when the guest has them, then `plugin_threads`.
    ///
    /// `deliver` hands a console byte to the guest's UART. The console's
    /// request key asks `plugin` for an observation and kicks the boot vCPU,
    /// which runs it.
    pub(crate) fn start(
        source: StopSource,
        guest: &Arc<Guest<K>>,
        plugin: Option<Arc<dyn Plugin>>,
        deliver: impl FnMut(u8) + Send + 'static,
        bridge: Option<VsockBridge>,
        net: Option<NetSource>,
        control: Option<ControlSocket>,
        plugin_threads: Vec<PluginThread>,
    ) -> Self
    where
        K: 'static,
    {
        let vcpus = Arc::clone(&guest.vcpus);
        let mut deliver = deliver;
        let gate = source.token();
        let finish_count = Arc::new(FinishCount::default());
        let console = IoThread::spawn(
            "console reader",
            source.token(),
            &finish_count,
            Arc::clone(&guest.vcpus),
            move |stop| {
                let gate = stop.clone();
                terminal::input::run(
                    plugin,
                    &stop,
                    move || vcpus.kicker().kick(0),
                    move |byte| {
                        let _in = gate.enter();
                        deliver(byte);
                    },
                );
            },
        );
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
        if let Some(bridge) = bridge {
            io_threads.spawn("agent bridge", move |stop| bridge.run(&stop));
        }
        if let (Some(net), Some(dev)) = (net, &guest.net) {
            let (dev, ram) = (Arc::clone(dev), Arc::clone(&guest.ram));
            // The relay passes the pause gate around each burst it receives
            // and delivers, so `deliver` does not: a second admission inside
            // the first would wait on a pause that waits on the first.
            let deliver = move |frame: &[u8]| {
                lock_or_recover(&dev).deliver(&ram, frame);
            };
            match net {
                NetSource::Gateway(stream) => io_threads.spawn("gateway relay", move |stop| {
                    if let Err(e) = GatewayRelay::new(stream).run(&stop, deliver) {
                        stderrln!("{LOG_PREFIX} virtio-net: {e}; gateway relay stopped");
                    }
                }),
                #[cfg(target_os = "linux")]
                NetSource::Tap(file) => io_threads.spawn("tap relay", move |stop| {
                    if let Err(e) = TapRelay::new(file).run(&stop, deliver) {
                        stderrln!("{LOG_PREFIX} virtio-net: {e}; tap relay stopped");
                    }
                }),
            }
        }
        for PluginThread { name, run } in plugin_threads {
            io_threads.spawn(name, run);
        }
        if let Some(control) = control {
            let (stop, gate) = (io_threads.token(), Arc::clone(io_threads.source.gate()));
            let vcpus = Arc::clone(&guest.vcpus);
            io_threads.push(
                "control socket",
                std::thread::spawn(move || {
                    // Only a run that may write checkpoints gives the thread
                    // the file calls a bundle needs.
                    if control.checkpoint_root().is_some() {
                        confine_control_thread();
                    } else {
                        confine_io_thread();
                    }
                    control.run(&stop, &gate, &vcpus);
                }),
            );
        }
        io_threads
    }

    /// Starts a thread named `name` that runs `body` with a stop token, to be
    /// joined with the others.
    ///
    /// [`stop`](Self::stop) only joins the thread, so `body` has to return on
    /// its own: it watches the token, or an action added with
    /// [`on_stop`](Self::on_stop) ends it. A panic in `body` fails the run and
    /// asks it to stop.
    ///
    /// It has to be called from a thread with no seccomp filter, since naming
    /// the new thread calls `prctl`, which neither allowlist has.
    ///
    /// # Panics
    ///
    /// Panics if the thread cannot be created.
    pub(crate) fn spawn(
        &mut self,
        name: &'static str,
        body: impl FnOnce(StopToken) + Send + 'static,
    ) where
        K: 'static,
    {
        let thread = IoThread::spawn(
            name,
            self.stop.source.token(),
            &self.finish_count,
            Arc::clone(&self.vcpus),
            body,
        );
        self.threads.push(thread);
    }

    /// Adds an action that [`stop`](Self::stop) runs before it joins the
    /// threads.
    ///
    /// It is for a thread that waits on something a stop token cannot reach,
    /// such as a condition variable. The action must return at once.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn on_stop(&mut self, action: impl FnOnce() + Send + 'static) {
        self.stop.actions.push(Box::new(action));
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
        );
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

impl IoThread {
    /// Starts a thread named `name` that confines itself and then runs `body`
    /// with `stop`.
    ///
    /// The thread holds a [`FinishGuard`] that notes on `count`, and a
    /// [`StopOnPanic`] that fails and stops the run of `vcpus` if it panics.
    ///
    /// # Panics
    ///
    /// Panics if the thread cannot be created.
    fn spawn<K: Kick + 'static>(
        name: &'static str,
        stop: StopToken,
        count: &Arc<FinishCount>,
        vcpus: Arc<Vcpus<K>>,
        body: impl FnOnce(StopToken) + Send + 'static,
    ) -> Self {
        let finished = Arc::new(AtomicBool::new(false));
        // The guard is built on the thread, so a thread that is never created
        // notes nothing.
        let (flag, count) = (Arc::clone(&finished), Arc::clone(count));
        let handle = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                let _finished = FinishGuard {
                    finished: flag,
                    count,
                };
                let _panic = StopOnPanic { vcpus, name };
                confine_io_thread();
                body(stop);
            })
            .unwrap_or_else(|e| panic!("spawning the {name} thread: {e}"));
        Self { handle, finished }
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
    use super::*;
    use crate::run::StopHandle;

    /// A kicker that reaches no thread.
    struct NoopKicker;

    impl Kick for NoopKicker {
        fn kick(&self, _cpu: u32) {}

        fn kick_all(&self) {}
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
    }

    // An unwind drops the threads without `stop`. They are still asked to stop,
    // and the actions for the threads a token does not reach still run.
    #[test]
    fn dropping_the_threads_runs_their_stop() {
        let mut threads = IoThreads::idle(vcpus());
        let (ran, has_run) = std::sync::mpsc::channel();
        threads.on_stop(move || ran.send(()).unwrap());
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

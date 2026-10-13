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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::devices::virtio::net::GatewayRelay;
#[cfg(target_os = "linux")]
use crate::devices::virtio::net::TapRelay;
use crate::devices::virtio::vsock::VsockBridge;
use crate::hypervisor::guest::{Guest, PluginThread};
use crate::hypervisor::vcpus::{Kick, Outcome, Vcpus};
use crate::plugin::Plugin;
use crate::sandbox::confine_io_thread;
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

/// A guard that, when its thread panics, reports the run failed and asks it to
/// stop.
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
pub(crate) struct IoThreads {
    /// The stop the threads poll.
    source: StopSource,
    /// The console reader, which the stop also has to signal.
    console: IoThread,
    /// Every other thread.
    threads: Vec<IoThread>,
    /// The count each thread notes on as it ends.
    finish_count: Arc<FinishCount>,
    /// The actions the stop runs before it joins the threads.
    stop_actions: Vec<Box<dyn FnOnce() + Send>>,
}

impl IoThreads {
    /// Starts the console reader, then the agent bridge and the network relay
    /// when the guest has them, then `plugin_threads`.
    ///
    /// `deliver` hands a console byte to the guest's UART. The console's
    /// request key asks `plugin` for an observation and kicks the boot vCPU,
    /// which runs it.
    pub(crate) fn start<K: Kick + 'static>(
        source: StopSource,
        guest: &Arc<Guest<K>>,
        plugin: Option<Arc<dyn Plugin>>,
        deliver: impl FnMut(u8) + Send + 'static,
        bridge: Option<VsockBridge>,
        net: Option<NetSource>,
        plugin_threads: Vec<PluginThread>,
    ) -> Self {
        let vcpus = Arc::clone(&guest.vcpus);
        let finish_count = Arc::new(FinishCount::default());
        let console = IoThread::spawn(
            "console reader",
            source.token(),
            &finish_count,
            move |stop| {
                terminal::input::run(plugin, &stop, move || vcpus.kicker().kick(0), deliver);
            },
        );
        let mut io_threads = Self {
            source,
            console,
            threads: Vec::new(),
            finish_count,
            stop_actions: Vec::new(),
        };
        if let Some(bridge) = bridge {
            io_threads.spawn("agent bridge", move |stop| bridge.run(&stop));
        }
        if let (Some(net), Some(dev)) = (net, &guest.net) {
            let (dev, ram) = (Arc::clone(dev), Arc::clone(&guest.ram));
            let deliver = move |frame: &[u8]| lock_or_recover(&dev).deliver(&ram, frame);
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
            let vcpus = Arc::clone(&guest.vcpus);
            io_threads.spawn(name, move |stop| {
                let _panic = StopOnPanic { vcpus, name };
                run(stop);
            });
        }
        io_threads
    }

    /// Starts a thread named `name` that runs `body` with a stop token, to be
    /// joined with the others.
    ///
    /// [`stop`](Self::stop) only joins the thread, so `body` has to return on
    /// its own: it watches the token, or an action added with
    /// [`on_stop`](Self::on_stop) ends it.
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
    ) {
        let thread = IoThread::spawn(name, self.source.token(), &self.finish_count, body);
        self.threads.push(thread);
    }

    /// Adds an action that [`stop`](Self::stop) runs before it joins the
    /// threads.
    ///
    /// It is for a thread that waits on something a stop token cannot reach,
    /// such as a condition variable. The action must return at once.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn on_stop(&mut self, action: impl FnOnce() + Send + 'static) {
        self.stop_actions.push(Box::new(action));
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
    pub(crate) fn stop(self) -> std::io::Result<()> {
        self.source.request_stop();
        for action in self.stop_actions {
            action();
        }
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
impl IoThreads {
    /// Returns the I/O threads of a run with no devices, whose console reader
    /// returns at once.
    pub(crate) fn idle() -> Self {
        let source = StopSource::new().expect("stop pair");
        let finish_count = Arc::new(FinishCount::default());
        let console = IoThread::spawn("console reader", source.token(), &finish_count, |_| {});
        Self {
            source,
            console,
            threads: Vec::new(),
            finish_count,
            stop_actions: Vec::new(),
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
    /// The thread holds a [`FinishGuard`] that notes on `count`.
    ///
    /// # Panics
    ///
    /// Panics if the thread cannot be created.
    fn spawn(
        name: &'static str,
        stop: StopToken,
        count: &Arc<FinishCount>,
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

    /// Starts a thread that runs `body` and notes on `count`.
    fn spawn(count: &Arc<FinishCount>, body: impl FnOnce() + Send + 'static) -> IoThread {
        let source = StopSource::new().unwrap();
        IoThread::spawn("test", source.token(), count, move |_| body())
    }

    #[test]
    fn thread_that_exits_is_noted_and_joined() {
        let count = Arc::new(FinishCount::default());
        let thread = spawn(&count, || {});
        assert!(count.wait_for(1, Instant::now() + Duration::from_secs(5)));
        thread.try_join().unwrap();
    }

    // A thread stuck in a call the stop cannot interrupt must be reported once
    // the wait ends, or `boot` would not return. The thread beside it that
    // finished is still joined.
    #[test]
    fn thread_that_does_not_exit_is_reported() {
        let count = Arc::new(FinishCount::default());
        let (release, released) = std::sync::mpsc::channel::<()>();
        let stuck = spawn(&count, move || {
            let _ = released.recv();
        });
        let quick = spawn(&count, || {});
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
        let thread = spawn(&count, move || {
            let mut byte = [0u8; 1];
            let _ = std::io::Read::read(&mut read, &mut byte);
        });
        let start = Instant::now();
        thread.kick_until_finished(&count, Instant::now() + Duration::from_secs(5));
        assert!(start.elapsed() < Duration::from_secs(1));
        thread.try_join().unwrap();
    }
}

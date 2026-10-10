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
//! a tap. Each polls a stop token beside its own descriptor. A backend starts
//! the threads only it has with [`IoThreads::spawn`]. Once the vCPUs have
//! exited or been left running, [`IoThreads::stop`] requests the stop and joins
//! every thread, as `teardown` describes.

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

use crate::devices::virtio::net::GatewayRelay;
#[cfg(target_os = "linux")]
use crate::devices::virtio::net::TapRelay;
use crate::devices::virtio::vsock::VsockBridge;
use crate::hypervisor::guest::Guest;
use crate::hypervisor::vcpus::Kick;
use crate::plugin::Plugin;
use crate::sandbox::confine_io_thread;
use crate::sync::lock_or_recover;
use crate::teardown::{join_by, kick_until_finished, StopSource, StopToken, STOP_TIMEOUT};
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
    console: JoinHandle<()>,
    /// Every other thread.
    threads: Vec<JoinHandle<()>>,
    /// The actions the stop runs before it joins the threads.
    stop_actions: Vec<Box<dyn FnOnce() + Send>>,
}

impl IoThreads {
    /// Starts the console reader, then the agent bridge and the network relay
    /// when the guest has them.
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
    ) -> Self {
        let vcpus = Arc::clone(&guest.vcpus);
        let console = spawn_thread("console reader", source.token(), move |stop| {
            terminal::input::run(plugin, &stop, move || vcpus.kicker().kick(0), deliver);
        });
        let mut io_threads = Self {
            source,
            console,
            threads: Vec::new(),
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
                        eprintln!("{LOG_PREFIX} virtio-net: {e}; gateway relay stopped");
                    }
                }),
                #[cfg(target_os = "linux")]
                NetSource::Tap(file) => io_threads.spawn("tap relay", move |stop| {
                    if let Err(e) = TapRelay::new(file).run(&stop, deliver) {
                        eprintln!("{LOG_PREFIX} virtio-net: {e}; tap relay stopped");
                    }
                }),
            }
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
        let thread = spawn_thread(name, self.source.token(), body);
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
    /// The console reader also gets the kick signal until it exits, since a
    /// read of stdin is where the stop token cannot reach it. Every join shares
    /// one deadline, [`STOP_TIMEOUT`] after the stop actions have run. A thread
    /// still running at the deadline is left running and reported on stderr.
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
        kick_until_finished(&self.console, deadline);
        let mut failure = None;
        for thread in std::iter::once(self.console).chain(self.threads) {
            if let Err(e) = join_by(thread, deadline) {
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
        let console = spawn_thread("console reader", source.token(), |_| {});
        Self {
            source,
            console,
            threads: Vec::new(),
            stop_actions: Vec::new(),
        }
    }
}

/// Starts a thread named `name` that confines itself and then runs `body` with
/// `stop`.
///
/// # Panics
///
/// Panics if the thread cannot be created.
fn spawn_thread(
    name: &'static str,
    stop: StopToken,
    body: impl FnOnce(StopToken) + Send + 'static,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            confine_io_thread();
            body(stop);
        })
        .unwrap_or_else(|e| panic!("spawning the {name} thread: {e}"))
}

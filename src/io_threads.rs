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
//! a tap. Each polls a stop token beside its own descriptor. A backend adds the
//! threads only it has with [`IoThreads::push`]. Once the vCPUs have exited,
//! [`IoThreads::stop`] requests the stop and joins every thread, as `teardown`
//! describes.

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
/// They serve the guest's devices from the host. A backend can add a thread of
/// its own to the same stop, such as the x86 trace watchdog.
pub(crate) struct IoThreads {
    /// The stop the threads poll.
    source: StopSource,
    /// The console reader, which the stop also has to signal.
    console: JoinHandle<()>,
    /// Every other thread, with the name a report of it uses.
    threads: Vec<(&'static str, JoinHandle<()>)>,
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
        let console = terminal::input::spawn(
            plugin,
            source.token(),
            move || vcpus.kicker().kick(0),
            deliver,
        );
        let mut io_threads = Self {
            source,
            console,
            threads: Vec::new(),
        };
        if let Some(bridge) = bridge {
            let stop = io_threads.token();
            io_threads.push(
                "agent bridge",
                std::thread::spawn(move || {
                    confine_io_thread();
                    bridge.run(&stop);
                }),
            );
        }
        if let (Some(net), Some(dev)) = (net, &guest.net) {
            let (dev, ram, stop) = (Arc::clone(dev), Arc::clone(&guest.ram), io_threads.token());
            let deliver = move |frame: &[u8]| lock_or_recover(&dev).deliver(&ram, frame);
            let (name, relay) = match net {
                NetSource::Gateway(stream) => (
                    "gateway relay",
                    std::thread::spawn(move || {
                        confine_io_thread();
                        if let Err(e) = GatewayRelay::new(stream).run(&stop, deliver) {
                            eprintln!("{LOG_PREFIX} virtio-net: {e}; gateway relay stopped");
                        }
                    }),
                ),
                #[cfg(target_os = "linux")]
                NetSource::Tap(file) => (
                    "tap relay",
                    std::thread::spawn(move || {
                        confine_io_thread();
                        if let Err(e) = TapRelay::new(file).run(&stop, deliver) {
                            eprintln!("{LOG_PREFIX} virtio-net: {e}; tap relay stopped");
                        }
                    }),
                ),
            };
            io_threads.push(name, relay);
        }
        io_threads
    }

    /// Returns a stop token for a thread the backend starts itself.
    pub(crate) fn token(&self) -> StopToken {
        self.source.token()
    }

    /// Adds a thread the backend started, to be joined with the others.
    ///
    /// [`stop`](Self::stop) only joins it, so the thread has to end on its own:
    /// it watches a stop [`token`](Self::token), or the backend stops it before
    /// calling `stop`.
    pub(crate) fn push(&mut self, name: &'static str, thread: JoinHandle<()>) {
        self.threads.push((name, thread));
    }

    /// Requests the stop and joins every thread.
    ///
    /// The console reader also gets the kick signal until it exits, since a
    /// read of stdin is where the stop token cannot reach it. Every join shares
    /// one deadline, [`STOP_TIMEOUT`] from the request. A thread still running
    /// at the deadline is left running and reported on stderr.
    ///
    /// # Errors
    ///
    /// Errors with the first thread that did not stop in time.
    pub(crate) fn stop(self) -> std::io::Result<()> {
        self.source.request_stop();
        let deadline = Instant::now() + STOP_TIMEOUT;
        kick_until_finished(&self.console, deadline);
        let mut failure = None;
        for (name, thread) in std::iter::once(("console reader", self.console)).chain(self.threads)
        {
            if let Err(e) = join_by(name, thread, deadline) {
                eprintln!("{LOG_PREFIX} {e}; left running");
                failure.get_or_insert(e);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

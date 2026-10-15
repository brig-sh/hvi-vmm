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
//! host: the console reader, the virtio-blk worker, the agent bridge, and the
//! relay from a gateway or a tap. Each polls a stop token beside its own
//! descriptor, except the virtio-blk worker, which parks on its device's wake
//! signal and is ended through it. A backend adds the threads only it has
//! with [`IoThreads::push`]. Once the vCPUs have exited, [`IoThreads::stop`]
//! requests the stop and joins every thread, as `teardown` describes.
//!
//! Each thread passes the token's pause gate around the work that touches a
//! device or guest RAM, so a pause of the gate holds all of them back. The
//! console's bytes are delivered inside the gate, the relays receive and
//! deliver their frames inside it, and the virtio-blk worker takes, runs and
//! returns each request inside it. The control socket's thread, when there
//! is one, is the one that closes it.

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::checkpoint::server::ControlSocket;
use crate::devices::virtio::block;
use crate::devices::virtio::net::GatewayRelay;
#[cfg(target_os = "linux")]
use crate::devices::virtio::net::TapRelay;
use crate::devices::virtio::vsock::VsockBridge;
use crate::devices::wake::Wake;
use crate::hypervisor::guest::Guest;
use crate::hypervisor::vcpus::Kick;
use crate::plugin::Plugin;
use crate::sandbox::{confine_control_thread, confine_io_thread};
use crate::sync::lock_or_recover;
use crate::teardown::{
    join_within, kick_until_finished, StopSource, StopToken, DISK_STOP_TIMEOUT, STOP_TIMEOUT,
};
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
    /// Every other thread, with the name a report of it uses and how long
    /// after the stop's request its join waits.
    threads: Vec<(&'static str, JoinHandle<()>, Duration)>,
    /// What ends the threads that watch no stop token, called first.
    enders: Vec<Box<dyn FnOnce() + Send>>,
}

impl IoThreads {
    /// Starts the console reader, then the virtio-blk worker, the agent
    /// bridge, the network relay and the control socket when the guest has
    /// them.
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
        control: Option<ControlSocket>,
    ) -> Self {
        let vcpus = Arc::clone(&guest.vcpus);
        let mut deliver = deliver;
        let gate = source.token();
        let console = terminal::input::spawn(
            plugin,
            source.token(),
            move || vcpus.kicker().kick(0),
            move |byte| {
                let _in = gate.enter();
                deliver(byte);
            },
        );
        let mut io_threads = Self {
            source,
            console,
            threads: Vec::new(),
            enders: Vec::new(),
        };
        if let Some(dev) = &guest.block {
            // A notify only wakes this thread, which makes the disk calls the
            // vCPU's exit used to make. See `block::serve`.
            let wake = Arc::new(Wake::new());
            lock_or_recover(dev).connect_worker(Arc::clone(&wake));
            let (dev, ram, ledger) = (
                Arc::clone(dev),
                Arc::clone(&guest.ram),
                Arc::clone(&guest.ledger),
            );
            let (stop, signal) = (io_threads.token(), Arc::clone(&wake));
            let worker = std::thread::spawn(move || {
                confine_io_thread();
                block::serve(&dev, &ram, &signal, &stop, |events| {
                    let mut ledger = lock_or_recover(&ledger);
                    for event in events {
                        ledger.captured(event);
                    }
                });
            });
            io_threads
                .threads
                .push(("virtio-blk worker", worker, DISK_STOP_TIMEOUT));
            io_threads.enders.push(Box::new(move || wake.stop()));
        }
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
            // The relay passes the pause gate around each burst it receives
            // and delivers, so `deliver` does not: a second admission inside
            // the first would wait on a pause that waits on the first.
            let deliver = move |frame: &[u8]| {
                lock_or_recover(&dev).deliver(&ram, frame);
            };
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
        if let Some(control) = control {
            let (stop, gate) = (io_threads.token(), Arc::clone(io_threads.source.gate()));
            let vcpus = Arc::clone(&guest.vcpus);
            let capture = control.capture_of(guest);
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
                    control.run(&stop, &gate, &vcpus, capture);
                }),
            );
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
        self.threads.push((name, thread, STOP_TIMEOUT));
    }

    /// Adds a thread the backend started that watches no stop token, with
    /// `end`, which ends it. [`stop`](Self::stop) calls `end` before it
    /// joins.
    // Only the arm64 backends start such a thread, for `hvi-time`.
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    pub(crate) fn push_ended_by(
        &mut self,
        name: &'static str,
        thread: JoinHandle<()>,
        end: impl FnOnce() + Send + 'static,
    ) {
        self.threads.push((name, thread, STOP_TIMEOUT));
        self.enders.push(Box::new(end));
    }

    /// Requests the stop and joins every thread.
    ///
    /// The console reader also gets the kick signal until it exits, since a
    /// read of stdin is where the stop token cannot reach it. Every join but
    /// one shares one deadline, [`STOP_TIMEOUT`] from the request. The
    /// virtio-blk worker's is [`DISK_STOP_TIMEOUT`] from it, since a disk
    /// call in flight cannot be cut short. A thread still running at its
    /// deadline is left running and reported on stderr.
    ///
    /// # Errors
    ///
    /// Errors with the first thread that did not stop in time.
    pub(crate) fn stop(self) -> std::io::Result<()> {
        self.source.request_stop();
        for end in self.enders {
            end();
        }
        let requested = Instant::now();
        kick_until_finished(&self.console, requested + STOP_TIMEOUT);
        let mut failure = None;
        for (name, thread, within) in
            std::iter::once(("console reader", self.console, STOP_TIMEOUT)).chain(self.threads)
        {
            if let Err(e) = join_within(name, thread, requested + within, within) {
                eprintln!("{LOG_PREFIX} {e}; left running");
                failure.get_or_insert(e);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

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

//! virtio-fs for the Linux backends, served by an out-of-process vhost-user
//! daemon.
//!
//! The macOS backend implements the FUSE server itself, in `server` beside
//! this module. That module is compiled only on macOS, so this is not an
//! intra-doc link: the link would dangle on every other target.
//!
//! On Linux an export is served by a vhost-user daemon the caller runs, such as
//! `virtiofsd`. The daemon maps guest RAM through the memfd that backs it and
//! walks the virtqueues in its own process. What stays here is the device the
//! virtio-mmio transport serves: the features the daemon offers, the
//! configuration space, and the handshake that hands the rings to the daemon.
//!
//! The split costs one thing. A request the daemon serves never crosses this
//! process, so the file-level events the macOS device captures have no
//! counterpart here. The block and network boundaries are unaffected.

/// Length of the tag field in the virtio-fs config space.
pub const TAG_LEN: usize = 36;

/// Size of the virtio-fs config space, the tag and the request-queue count.
pub const CONFIG_LEN: usize = TAG_LEN + 4;

/// Feature bits the guest may negotiate, before intersecting with what the
/// daemon offers.
///
/// Bit 28 is `VIRTIO_RING_F_INDIRECT_DESC` and bit 29
/// `VIRTIO_RING_F_EVENT_IDX`, which the daemon serves, since it walks the
/// rings.
pub const GUEST_FEATURES: u64 = (1 << 28) | (1 << 29);

/// Returns the virtio-fs config space for `tag`, which is the NUL-padded
/// mount tag followed by the request-queue count.
///
/// A tag longer than [`TAG_LEN`] is truncated. The guest mounts what it reads
/// here, so a truncated tag is still a usable one.
#[must_use]
pub fn config_space(tag: &str, request_queues: u32) -> Vec<u8> {
    let mut out = vec![0u8; CONFIG_LEN];
    let bytes = tag.as_bytes();
    let len = bytes.len().min(TAG_LEN);
    out[..len].copy_from_slice(&bytes[..len]);
    out[TAG_LEN..].copy_from_slice(&request_queues.to_le_bytes());
    out
}

/// Returns the virtqueue count for a device with `request_queues` request
/// queues, counting the hiprio queue the spec puts first.
#[must_use]
pub fn queue_count(request_queues: usize) -> usize {
    request_queues + 1
}

// The device needs the `vhost` crate, which only the Linux build has.
#[cfg(target_os = "linux")]
pub use self::device::{
    attach, connect_waiting, shut_down, Export, ShutdownFds, VhostUserFs, SOCKET_WAIT,
};

#[cfg(target_os = "linux")]
mod device {
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
    use vhost::vhost_user::{Frontend, VhostUserFrontend};
    use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
    use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
    use vmm_sys_util::eventfd::EventFd;

    use crate::config::FsConfig;
    use crate::devices::virtio::mmio::Interrupt;
    use crate::devices::virtio::{self, read_config_bytes, Queue};
    use crate::io_threads::HostWork;
    use crate::memory::GuestRam;
    use crate::teardown::StopToken;
    use crate::LOG_PREFIX;

    use super::{config_space, queue_count, GUEST_FEATURES};

    /// What a shutdown needs from a device, taken once while it is being
    /// built.
    ///
    /// See [`VhostUserFs::shutdown_fds`] for why a shutdown does not go
    /// through the device itself.
    #[derive(Clone, Debug)]
    pub struct ShutdownFds {
        /// The vhost-user socket to the daemon.
        connection: RawFd,
    }

    impl ShutdownFds {
        /// Closes the connection to the daemon.
        ///
        /// Shutting the socket down is what makes the daemon exit, and it is
        /// what a blocked vhost-user read needs to return. The device stays
        /// alive; only its connection ends, so a caller that still holds the
        /// device sees failed messages rather than a use-after-free.
        pub fn shutdown(&self) {
            // SAFETY: the descriptor is owned by a device that outlives this
            // handle, and the call reads and writes no memory.
            unsafe {
                libc::shutdown(self.connection, libc::SHUT_RDWR);
            }
        }
    }

    /// How long [`VhostUserFs::connect`] waits for a daemon's socket, so a
    /// daemon started beside hvi has time to listen.
    pub const SOCKET_WAIT: Duration = Duration::from_secs(60);

    /// How long [`connect_waiting`] sleeps between two attempts.
    const SOCKET_RETRY_INTERVAL: Duration = Duration::from_millis(100);

    /// Connects to `socket`, retrying for up to `wait` while it is missing or
    /// refuses the connection.
    ///
    /// A caller that runs its own daemon can start it and the VMM at once, as
    /// urunc does, so the socket may not exist yet, or may not listen yet,
    /// when the VMM boots. Any other error ends the wait at once.
    ///
    /// # Errors
    ///
    /// Errors with the last failure once `wait` has passed, or with the first
    /// failure that a retry would not change.
    pub fn connect_waiting(socket: &Path, wait: Duration) -> io::Result<UnixStream> {
        let deadline = Instant::now() + wait;
        loop {
            match UnixStream::connect(socket) {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    let later = matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    );
                    if !later || Instant::now() >= deadline {
                        let waited = if later {
                            format!(" (waited {}s)", wait.as_secs())
                        } else {
                            String::new()
                        };
                        return Err(io::Error::new(
                            e.kind(),
                            format!(
                                "vhost-user: connecting to {}: {e}{waited}",
                                socket.display()
                            ),
                        ));
                    }
                }
            }
            std::thread::sleep(SOCKET_RETRY_INTERVAL);
        }
    }

    /// The vhost-user connection to the daemon, and whether it can carry
    /// another message.
    struct Peer {
        /// The frontend end of the vhost-user protocol.
        frontend: Frontend,
        /// Whether a message failed on the socket.
        ///
        /// Such a failure can leave a message half sent or a reply unread, so
        /// the daemon would read the next message out of step. Nothing is sent
        /// once this is set, and a device reset does not clear it.
        broken: bool,
    }

    impl Peer {
        /// Sends one message through `send` and returns its reply, or returns
        /// an error without sending when the connection is broken.
        ///
        /// `request` names the message in the error.
        fn send<T>(
            &mut self,
            request: &str,
            send: impl FnOnce(&mut Frontend) -> vhost::Result<T>,
        ) -> io::Result<T> {
            if self.broken {
                return Err(io::Error::other(format!(
                    "{request} not sent: an earlier message failed on the connection"
                )));
            }
            send(&mut self.frontend).map_err(|e| {
                if breaks_connection(&e) {
                    self.broken = true;
                }
                io::Error::other(format!("{request}: {e}"))
            })
        }
    }

    /// Returns whether `e` came from the socket, which is every failure except
    /// an argument the frontend refused before sending anything.
    fn breaks_connection(e: &vhost::Error) -> bool {
        use vhost::vhost_user::Error as Protocol;
        !matches!(
            e,
            vhost::Error::VhostUserProtocol(
                Protocol::InvalidParam
                    | Protocol::InactiveFeature(_)
                    | Protocol::InactiveOperation(_)
            )
        )
    }

    /// One virtio-fs device behind the virtio-mmio transport, holding the
    /// vhost-user connection to the daemon that serves its queues.
    ///
    /// A message waits on the daemon until it answers. A daemon that stops
    /// answering holds the thread that sent the message until
    /// [`ShutdownFds::shutdown`] ends the connection.
    pub struct VhostUserFs {
        /// The mount tag, for log lines and errors.
        tag: String,
        /// The connection to the daemon.
        peer: Peer,
        /// The memfd behind guest RAM, which the daemon maps.
        ram_fd: RawFd,
        /// Whether the daemon was sent each queue, the hiprio queue first.
        ///
        /// A queue counts as sent from its first message on, including one
        /// whose handover failed partway.
        handed_over: Vec<bool>,
        /// The eventfd per queue that a queue notification writes for the
        /// daemon.
        kick: Vec<EventFd>,
        /// The eventfd per queue the daemon writes once it has used a buffer.
        call: Vec<EventFd>,
        /// The device config space, which [`config_space`] builds.
        config: Vec<u8>,
        /// What the daemon offers, already intersected with [`GUEST_FEATURES`].
        device_features: u64,
        /// The largest size of each queue, the hiprio queue first.
        queue_max_sizes: Vec<u16>,
        /// Whether the peer offered `VHOST_USER_F_PROTOCOL_FEATURES`.
        protocol_features_offered: bool,
    }

    impl VhostUserFs {
        /// Connects to the daemon listening on `socket` and prepares a device
        /// that mounts under `tag`.
        ///
        /// The connect waits up to [`SOCKET_WAIT`] for the daemon, as
        /// [`connect_waiting`] describes. The handshake up to `SET_FEATURES`
        /// happens here, before the VMM installs its seccomp filters.
        /// Connecting a Unix socket is not on the allowlist, and the messages
        /// that follow are sendmsg and recvmsg, which are.
        ///
        /// # Errors
        ///
        /// Errors if the socket cannot be reached in time, if the daemon does
        /// not offer `VIRTIO_F_VERSION_1` or refuses the feature handshake, or
        /// if it serves fewer queues than `request_queues` needs.
        pub fn connect(
            socket: &Path,
            tag: &str,
            request_queues: usize,
            queue_size: u16,
            ram_fd: RawFd,
        ) -> io::Result<Self> {
            let stream = connect_waiting(socket, SOCKET_WAIT)?;
            Self::from_stream(stream, tag, request_queues, queue_size, ram_fd)
        }

        /// Prepares a device over an already connected vhost-user socket,
        /// with `request_queues` request queues of up to `queue_size` entries
        /// each.
        ///
        /// # Errors
        ///
        /// Errors if the daemon does not offer `VIRTIO_F_VERSION_1` or refuses
        /// the feature handshake, or if it serves fewer queues than
        /// `request_queues` needs.
        pub fn from_stream(
            stream: UnixStream,
            tag: &str,
            request_queues: usize,
            queue_size: u16,
            ram_fd: RawFd,
        ) -> io::Result<Self> {
            let queues = queue_count(request_queues);
            let frontend = Frontend::from_stream(stream, queues as u64);
            Self::over(frontend, tag, request_queues, queue_size, ram_fd)
        }

        /// Runs the feature handshake and builds the device around
        /// `frontend`.
        fn over(
            mut frontend: Frontend,
            tag: &str,
            request_queues: usize,
            queue_size: u16,
            ram_fd: RawFd,
        ) -> io::Result<Self> {
            let queues = queue_count(request_queues);
            frontend
                .set_owner()
                .map_err(|e| io::Error::other(format!("vhost-user: SET_OWNER: {e}")))?;
            let offered = frontend
                .get_features()
                .map_err(|e| io::Error::other(format!("vhost-user: GET_FEATURES: {e}")))?;
            // The transport offers `VIRTIO_F_VERSION_1` to every driver, so a
            // daemon without it cannot serve the guest.
            if offered & (1 << VIRTIO_F_VERSION_1) == 0 {
                return Err(io::Error::other(format!(
                    "virtio-fs {tag:?}: the daemon does not offer VIRTIO_F_VERSION_1"
                )));
            }

            // Protocol features are a vhost-user negotiation, not a virtio
            // one. MQ is the only one we need, for GET_QUEUE_NUM. Acking
            // VHOST_USER_F_PROTOCOL_FEATURES itself is what makes the daemon
            // start every ring disabled, until SET_VRING_ENABLE.
            let mut protocol_features = VhostUserProtocolFeatures::empty();
            let protocol_features_offered =
                offered & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0;
            if protocol_features_offered {
                let available = frontend.get_protocol_features().map_err(|e| {
                    io::Error::other(format!("vhost-user: GET_PROTOCOL_FEATURES: {e}"))
                })?;
                protocol_features = available & VhostUserProtocolFeatures::MQ;
                frontend
                    .set_protocol_features(protocol_features)
                    .map_err(|e| {
                        io::Error::other(format!("vhost-user: SET_PROTOCOL_FEATURES: {e}"))
                    })?;
            }
            // Only a daemon with MQ says how many queues it serves. One
            // without it is taken to serve the hiprio queue and one request
            // queue, which is all virtio-fs needs.
            let served = if protocol_features.contains(VhostUserProtocolFeatures::MQ) {
                let served = frontend
                    .get_queue_num()
                    .map_err(|e| io::Error::other(format!("vhost-user: GET_QUEUE_NUM: {e}")))?;
                usize::try_from(served).unwrap_or(usize::MAX)
            } else {
                queue_count(1)
            };
            if queues > served {
                return Err(io::Error::other(format!(
                    "virtio-fs {tag:?}: num_queues={request_queues} needs {queues} queues, \
                     and the daemon serves {served}"
                )));
            }

            let mut kick = Vec::with_capacity(queues);
            let mut call = Vec::with_capacity(queues);
            for _ in 0..queues {
                // The kick side is only written, from the vCPU thread that
                // passes the device a queue notification. The call side is read
                // by a thread per queue, which blocks on it.
                kick.push(EventFd::new(libc::EFD_NONBLOCK)?);
                call.push(EventFd::new(0)?);
            }

            Ok(Self {
                tag: tag.to_string(),
                peer: Peer {
                    frontend,
                    broken: false,
                },
                ram_fd,
                handed_over: vec![false; queues],
                kick,
                call,
                config: config_space(tag, request_queues as u32),
                device_features: offered & GUEST_FEATURES,
                queue_max_sizes: vec![queue_size; queues],
                protocol_features_offered,
            })
        }

        /// Returns the mount tag the guest reads from the config space.
        #[must_use]
        pub fn tag(&self) -> &str {
            &self.tag
        }

        /// Returns the number of virtqueues, which is how many call
        /// descriptors a caller has to wait on.
        #[must_use]
        pub fn queues(&self) -> usize {
            self.queue_max_sizes.len()
        }

        /// Returns a duplicate of the call descriptor for queue `index`, or
        /// `None` when there is no such queue.
        ///
        /// # Errors
        ///
        /// Errors if the descriptor cannot be duplicated.
        pub fn call_fd(&self, index: usize) -> Option<io::Result<EventFd>> {
            self.call.get(index).map(EventFd::try_clone)
        }

        /// Returns the call descriptors of every queue, duplicated.
        ///
        /// A caller waits on these to learn that the daemon has used buffers;
        /// see `serve_interrupts`.
        ///
        /// # Errors
        ///
        /// Errors if a descriptor cannot be duplicated.
        pub fn call_fds(&self) -> io::Result<Vec<EventFd>> {
            self.call.iter().map(EventFd::try_clone).collect()
        }

        /// Returns the descriptors a shutdown needs, which it uses without
        /// taking the device lock.
        ///
        /// A handover that is waiting on an unresponsive daemon holds that
        /// lock, and the shutdown that has to rescue it cannot then be asked
        /// to acquire it. The descriptors are copies of what the device holds
        /// and stay valid for as long as it does.
        #[must_use]
        pub fn shutdown_fds(&self) -> ShutdownFds {
            ShutdownFds {
                connection: self.peer.frontend.as_raw_fd(),
            }
        }

        /// Takes every ring back from the daemon.
        ///
        /// `SET_VRING_ENABLE(false)` stops it serving, and `GET_VRING_BASE` is
        /// what the protocol defines as the point the backend stops using a
        /// ring. Both are best-effort, and a reset goes ahead whatever the
        /// daemon answers, so the guest can initialize the device again. A
        /// broken connection is sent neither; see [`Peer::broken`].
        fn stop_rings(&mut self) {
            for index in 0..self.handed_over.len() {
                if self.peer.broken {
                    return;
                }
                if !self.handed_over[index] {
                    continue;
                }
                if self.protocol_features_offered {
                    let off = self
                        .peer
                        .send("SET_VRING_ENABLE off", |f| f.set_vring_enable(index, false));
                    if let Err(e) = off {
                        stderrln!("{LOG_PREFIX} virtio-fs {}: {e}", self.tag);
                    }
                }
                if let Err(e) = self
                    .peer
                    .send("GET_VRING_BASE", |f| f.get_vring_base(index))
                {
                    stderrln!("{LOG_PREFIX} virtio-fs {}: {e}", self.tag);
                }
            }
        }

        /// Hands the features the driver accepted, `driver_features`, guest RAM
        /// and the ready `queues` to the daemon.
        ///
        /// Each ready queue has a size and aligned rings in guest RAM, which
        /// [`QueueConfig::set_ready`](crate::devices::virtio::QueueConfig::set_ready)
        /// checks. A queue that is not ready is left disabled, which the guest
        /// sees as a queue that does not answer.
        ///
        /// It returns `Ok` once the daemon has read every message it was sent.
        fn hand_over(
            &mut self,
            mem: &GuestRam,
            driver_features: u64,
            queues: &[Option<Queue>],
        ) -> io::Result<()> {
            let mut features = driver_features;
            if self.protocol_features_offered {
                features |= VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            }
            self.peer
                .send("SET_FEATURES", |f| f.set_features(features))?;

            let regions = self.memory_table(mem)?;
            self.peer
                .send("SET_MEM_TABLE", |f| f.set_mem_table(&regions))?;

            for (index, queue) in queues.iter().enumerate() {
                let Some(queue) = queue else {
                    stderrln!(
                        "{LOG_PREFIX} virtio-fs {}: queue {index} is not ready; leaving it disabled",
                        self.tag
                    );
                    continue;
                };
                // The daemon is sent each ring's address in this process, which
                // its memory table maps.
                let [desc, avail, used] = queue
                    .ring_extents()
                    .map(|(address, len)| host_addr(mem, address, len));
                let config = VringConfigData {
                    queue_max_size: self.queue_max_sizes[index],
                    queue_size: queue.size(),
                    flags: 0,
                    desc_table_addr: desc?,
                    used_ring_addr: used?,
                    avail_ring_addr: avail?,
                    log_addr: None,
                };
                self.handed_over[index] = true;
                self.peer
                    .send("SET_VRING_NUM", |f| f.set_vring_num(index, queue.size()))?;
                self.peer
                    .send("SET_VRING_ADDR", |f| f.set_vring_addr(index, &config))?;
                self.peer
                    .send("SET_VRING_BASE", |f| f.set_vring_base(index, 0))?;
                self.peer.send("SET_VRING_CALL", |f| {
                    f.set_vring_call(index, &self.call[index])
                })?;
                self.peer.send("SET_VRING_KICK", |f| {
                    f.set_vring_kick(index, &self.kick[index])
                })?;
            }

            // Once VHOST_USER_F_PROTOCOL_FEATURES is negotiated, a ring starts
            // disabled and SET_VRING_ENABLE turns it on. Without it, the daemon
            // starts serving on SET_VRING_KICK.
            if self.protocol_features_offered {
                for index in 0..self.handed_over.len() {
                    if !self.handed_over[index] {
                        continue;
                    }
                    self.peer
                        .send("SET_VRING_ENABLE", |f| f.set_vring_enable(index, true))?;
                }
            }
            // None of the messages above has a reply, so without a wait the
            // driver can notify a ring before the daemon has read them. A
            // daemon drops a notification it reads on a ring it has not
            // enabled. Without protocol features a ring is enabled before
            // SET_VRING_KICK starts it, and a daemon that watches notifications
            // before it marks the ring ready can lose one that is already
            // pending. The daemon answers its requests in order, so the reply
            // to GET_FEATURES says it has read them all.
            self.peer.send("GET_FEATURES", |f| f.get_features())?;
            Ok(())
        }

        /// Describes guest RAM to the daemon, region by region.
        ///
        /// The daemon maps the same memfd this process did, so a region needs
        /// its offset in that object alongside the address it has here. The
        /// ring addresses we send are addresses in our own address space, and
        /// the daemon translates them through this table.
        fn memory_table(&self, mem: &GuestRam) -> io::Result<Vec<VhostUserMemoryRegionInfo>> {
            mem.regions()
                .into_iter()
                .map(|region| {
                    Ok(VhostUserMemoryRegionInfo {
                        guest_phys_addr: region.gpa,
                        memory_size: region.size,
                        userspace_addr: host_addr(mem, region.gpa, 1)?,
                        mmap_offset: region.file_offset,
                        mmap_handle: self.ram_fd,
                    })
                })
                .collect()
        }
    }

    impl virtio::Device for VhostUserFs {
        fn device_type(&self) -> u32 {
            virtio_bindings::virtio_ids::VIRTIO_ID_FS
        }

        fn features(&self) -> u64 {
            self.device_features
        }

        fn queue_max_sizes(&self) -> &[u16] {
            &self.queue_max_sizes
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            read_config_bytes(&self.config, offset, data);
        }

        fn activate(
            &mut self,
            ram: &GuestRam,
            driver_features: u64,
            queues: Vec<Option<Queue>>,
            _interrupt: Arc<Interrupt>,
        ) -> io::Result<()> {
            if let Err(e) = self.hand_over(ram, driver_features, &queues) {
                // The daemon may already serve the queues sent before the
                // failure.
                virtio::Device::reset(self);
                return Err(io::Error::other(format!("virtio-fs {}: {e}", self.tag)));
            }
            Ok(())
        }

        fn notify(&mut self, _ram: &GuestRam, queue: u16) {
            let queue = usize::from(queue);
            if self.handed_over.get(queue) == Some(&true) {
                if let Some(fd) = self.kick.get(queue) {
                    let _ = fd.write(1);
                }
            }
        }

        // The daemon walks the rings in its own process. Left enabled on rings
        // the driver has released, it would write used entries into pages the
        // guest has given to something else.
        fn reset(&mut self) {
            self.stop_rings();
            self.handed_over.fill(false);
        }
    }

    /// Raises `interrupt` each time the daemon signals `call`, until `stop` is
    /// requested.
    ///
    /// The daemon walks the rings in its own process, so the only thing left
    /// for this side is delivery. A signal on a queue's call descriptor says
    /// buffers were used, and the guest learns it from the interrupt status. It
    /// takes neither the device lock nor the transport lock, so a reset that
    /// waits on the daemon does not delay a delivery.
    pub(crate) fn serve_interrupts(interrupt: &Interrupt, call: &EventFd, stop: &StopToken) {
        // SAFETY: `call` stays open for the whole call, which outlives the
        // borrow.
        let fd = unsafe { BorrowedFd::borrow_raw(call.as_raw_fd()) };
        loop {
            match stop.wait(fd) {
                Ok(true) => {}
                Ok(false) => return,
                Err(e) => {
                    stderrln!("{LOG_PREFIX} virtio-fs: queue interrupts stopped: {e}");
                    return;
                }
            }
            if let Err(e) = call.read() {
                stderrln!("{LOG_PREFIX} virtio-fs: queue interrupts stopped: {e}");
                return;
            }
            interrupt.signal_used_buffer();
        }
    }

    /// One export as a backend wires it: the device, the range its transport
    /// answers in, and the interrupt it raises.
    #[derive(Clone)]
    pub struct Export {
        /// The device behind the transport.
        pub dev: Arc<Mutex<VhostUserFs>>,
        /// The descriptors a shutdown uses, so it never has to take `dev`.
        pub stop: ShutdownFds,
    }

    /// Connects one export per socket and returns them in order.
    ///
    /// Each export is attached to the daemon listening on its socket, which the
    /// caller started. The connect and the handshake happen here, before the
    /// seccomp filters go in.
    ///
    /// # Errors
    ///
    /// Errors if a socket cannot be reached in time, or if a daemon does not
    /// offer `VIRTIO_F_VERSION_1` or refuses the vhost-user handshake.
    pub fn attach(sockets: &[FsConfig], ram_fd: RawFd) -> io::Result<Vec<Export>> {
        let mut exports = Vec::with_capacity(sockets.len());
        for (index, export) in sockets.iter().enumerate() {
            // The directory and the mode are the daemon's, which hvi never
            // sees, so the line names the socket alone.
            stderrln!(
                "{LOG_PREFIX} virtio-fs[{index}]: {:?} on {}",
                export.tag,
                export.socket.display()
            );
            let dev = VhostUserFs::connect(
                &export.socket,
                &export.tag,
                export.num_queues,
                export.queue_size,
                ram_fd,
            )?;
            exports.push(Export {
                stop: dev.shutdown_fds(),
                dev: Arc::new(Mutex::new(dev)),
            });
        }
        Ok(exports)
    }

    impl Export {
        /// Queues in `host` a [`serve_interrupts`] thread on `interrupt` for
        /// each queue of the export.
        ///
        /// A thread ends when the I/O threads stop. An export whose call
        /// descriptors cannot be duplicated gets no thread, so its guest never
        /// sees a used buffer, and the boot says so on stderr.
        pub(crate) fn queue_interrupts(&self, interrupt: &Arc<Interrupt>, host: &mut HostWork) {
            let calls = match self.dev.lock().unwrap().call_fds() {
                Ok(calls) => calls,
                Err(e) => {
                    stderrln!("{LOG_PREFIX} virtio-fs: queue interrupts unavailable: {e}");
                    return;
                }
            };
            for call in calls {
                let interrupt = Arc::clone(interrupt);
                host.spawn("virtio-fs interrupts", move |stop| {
                    serve_interrupts(&interrupt, &call, &stop);
                });
            }
        }
    }

    /// Ends the daemon connection of every export.
    ///
    /// Ending a connection is what lets its daemon exit, and what frees a
    /// vhost-user read that is still waiting on it. It does not take the
    /// device lock, which a handover waiting on an unresponsive daemon would
    /// be holding.
    pub fn shut_down(exports: &[Export]) {
        for export in exports {
            export.stop.shutdown();
        }
    }

    /// Returns the address `gpa` has in this process, once `len` bytes from it
    /// are known to be backed by guest RAM.
    fn host_addr(mem: &GuestRam, gpa: u64, len: u64) -> io::Result<u64> {
        let len = usize::try_from(len).map_err(io::Error::other)?;
        mem.host_ptr(gpa, len).map(|p| p as u64)
    }

    #[cfg(test)]
    #[allow(clippy::disallowed_methods)]
    mod tests {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::sync::{mpsc, Arc, Mutex};
        use std::thread::JoinHandle;
        use std::time::Duration;

        use vhost::vhost_user::message::{
            FrontendReq, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
        };
        use virtio_bindings::virtio_config::{
            VIRTIO_CONFIG_S_FAILED as FAILED, VIRTIO_CONFIG_S_NEEDS_RESET as NEEDS_RESET,
            VIRTIO_F_VERSION_1,
        };

        use super::{connect_waiting, serve_interrupts, VhostUserFs};
        use crate::devices::virtio::mmio::testing::{self, Driver, Rings};
        use crate::devices::virtio::mmio::{QUEUE_NUM_MAX, QUEUE_READY, QUEUE_SEL, STATUS};
        use crate::memory::{GuestRam, RamRegion, SharedRam};
        use crate::teardown::StopSource;

        /// Guest-physical address of the RAM the tests map.
        const BASE: u64 = 0x4000_0000;

        /// The features a daemon offers by default, `VIRTIO_F_VERSION_1` and
        /// `VHOST_USER_F_PROTOCOL_FEATURES`.
        const OFFERED: u64 =
            (1 << VIRTIO_F_VERSION_1) | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        /// The `handover_delay` of a stand-in that lags, far longer than a
        /// DRIVER_OK that does not wait for the daemon takes to return.
        const HANDOVER_DELAY: Duration = Duration::from_millis(50);

        /// The requests a stand-in daemon answers.
        #[derive(Clone, Copy)]
        enum ReplyPolicy {
            /// Every request that has a reply. `GET_VRING_BASE` gets the ring's
            /// index and a base of 0.
            All,
            /// As `All`, except that the first `GET_VRING_BASE` gets a reply to
            /// `GET_FEATURES`, which the frontend rejects.
            WrongReplyFirst,
            /// As `All`, except `GET_VRING_BASE`.
            NoVringBase,
            /// The requests of the attach, and none from the first
            /// `SET_FEATURES` on, which starts a handover.
            AttachOnly,
        }

        /// What a stand-in daemon offers and how it answers.
        #[derive(Clone, Copy)]
        struct DaemonConfig {
            /// The features it offers.
            features: u64,
            /// The protocol features it offers.
            protocol_features: VhostUserProtocolFeatures,
            /// The requests it answers.
            replies: ReplyPolicy,
            /// How long it waits after it reads `SET_FEATURES`, before it reads
            /// the rest of the handover.
            handover_delay: Duration,
        }

        impl Default for DaemonConfig {
            fn default() -> Self {
                Self {
                    features: OFFERED,
                    protocol_features: VhostUserProtocolFeatures::MQ,
                    replies: ReplyPolicy::All,
                    handover_delay: Duration::ZERO,
                }
            }
        }

        impl DaemonConfig {
            /// Returns a running stand-in with this configuration, and the
            /// frontend's end of its socket.
            fn spawn(self) -> (Daemon, UnixStream) {
                let (ours, theirs) = UnixStream::pair().expect("socket pair");
                let seen = Arc::new(Mutex::new(Vec::new()));
                let thread = std::thread::spawn({
                    let seen = Arc::clone(&seen);
                    move || serve(theirs, self, &seen)
                });
                (Daemon { thread, seen }, ours)
            }
        }

        /// A vhost-user daemon stand-in on one end of a socket pair.
        struct Daemon {
            /// The thread that answers the requests.
            thread: JoinHandle<()>,
            /// The requests it has read.
            seen: Arc<Mutex<Vec<FrontendReq>>>,
        }

        impl Daemon {
            /// Returns a running stand-in that answers as `replies` says, and
            /// the frontend's end of its socket.
            fn spawn(replies: ReplyPolicy) -> (Self, UnixStream) {
                DaemonConfig {
                    replies,
                    ..DaemonConfig::default()
                }
                .spawn()
            }

            /// Returns the requests the stand-in has read so far.
            fn requests(&self) -> Vec<FrontendReq> {
                self.seen.lock().unwrap().clone()
            }

            /// Returns the requests the stand-in read, once the frontend's end
            /// has closed.
            fn join(self) -> Vec<FrontendReq> {
                let Self { thread, seen } = self;
                thread.join().expect("the stand-in daemon");
                let seen = seen.lock().unwrap();
                seen.clone()
            }
        }

        /// Answers the requests on `socket` until it closes, as a daemon of two
        /// queues with `config`.
        ///
        /// It records each request in `seen` before it answers.
        fn serve(mut socket: UnixStream, config: DaemonConfig, seen: &Mutex<Vec<FrontendReq>>) {
            let DaemonConfig {
                features,
                protocol_features,
                replies,
                handover_delay,
            } = config;
            let mut wrong_reply_sent = false;
            let mut handing_over = false;
            let mut header = [0u8; 12];
            while socket.read_exact(&mut header).is_ok() {
                let word =
                    |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().expect("a word"));
                let request = FrontendReq::try_from(word(0)).expect("a known request");
                let mut body = vec![0u8; word(8) as usize];
                if socket.read_exact(&mut body).is_err() {
                    break;
                }
                seen.lock().unwrap().push(request);
                if request == FrontendReq::SET_FEATURES {
                    handing_over = true;
                    std::thread::sleep(handover_delay);
                }
                let reply = match request {
                    _ if handing_over && matches!(replies, ReplyPolicy::AttachOnly) => None,
                    FrontendReq::GET_FEATURES => Some((request, features.to_le_bytes().to_vec())),
                    FrontendReq::GET_PROTOCOL_FEATURES => {
                        Some((request, protocol_features.bits().to_le_bytes().to_vec()))
                    }
                    // virtiofsd's count: the hiprio queue and one request
                    // queue.
                    FrontendReq::GET_QUEUE_NUM => Some((request, 2u64.to_le_bytes().to_vec())),
                    FrontendReq::GET_VRING_BASE => match replies {
                        ReplyPolicy::NoVringBase => None,
                        ReplyPolicy::WrongReplyFirst if !wrong_reply_sent => {
                            wrong_reply_sent = true;
                            Some((FrontendReq::GET_FEATURES, vec![0; 8]))
                        }
                        ReplyPolicy::All
                        | ReplyPolicy::WrongReplyFirst
                        | ReplyPolicy::AttachOnly => {
                            Some((request, [&body[..4], &[0u8; 4][..]].concat()))
                        }
                    },
                    _ => None,
                };
                if let Some((code, payload)) = reply {
                    let mut message = Vec::with_capacity(12 + payload.len());
                    message.extend_from_slice(&u32::from(code).to_le_bytes());
                    // Version 1, with the reply bit set.
                    message.extend_from_slice(&0x5u32.to_le_bytes());
                    message.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                    message.extend_from_slice(&payload);
                    if socket.write_all(&message).is_err() {
                        break;
                    }
                }
            }
        }

        /// Returns 1 MiB of shareable guest RAM, mapped at [`BASE`].
        fn guest_ram() -> (SharedRam, Arc<GuestRam>) {
            let ram = SharedRam::new(RamRegion::ALIGN as usize).expect("allocate");
            let mem = GuestRam::new(&ram, &[ram.region_at(BASE)]).expect("map");
            (ram, Arc::new(mem))
        }

        /// Returns a ring of 8 descriptors at `at`.
        fn rings(at: u64) -> Rings {
            Rings {
                size: 8,
                desc_table: at,
                avail_ring: at + 0x100,
                used_ring: at + 0x200,
            }
        }

        /// Returns a driver of an export over `stream`, with one request queue
        /// of up to 1024 entries, whose daemon maps guest RAM through `ram_fd`.
        fn driver(stream: UnixStream, mem: &Arc<GuestRam>, ram_fd: i32) -> Driver<VhostUserFs> {
            let dev = VhostUserFs::from_stream(stream, "t", 1, 1024, ram_fd).expect("handshake");
            Driver::new(dev, mem)
        }

        // A reply to another request leaves the frontend unable to say which
        // message the daemon is answering.
        #[test]
        fn connection_that_failed_is_sent_nothing_more() {
            let (daemon, stream) = Daemon::spawn(ReplyPolicy::WrongReplyFirst);
            let (ram, mem) = guest_ram();
            let driver = driver(stream, &mem, ram.as_raw_fd());
            driver.start(&[rings(BASE), rings(BASE + 0x1000)]);
            // The reset reads the wrong reply to queue 0's GET_VRING_BASE.
            driver.reset();
            driver.start(&[rings(BASE)]);
            drop(driver);

            let seen = daemon.join();
            let failed = seen
                .iter()
                .position(|&r| r == FrontendReq::GET_VRING_BASE)
                .expect("a GET_VRING_BASE");
            let kicks = seen[..failed]
                .iter()
                .filter(|&&r| r == FrontendReq::SET_VRING_KICK)
                .count();
            assert_eq!(kicks, 2, "the first handover did not complete: {seen:?}");
            assert!(
                seen[failed + 1..].is_empty(),
                "sent after the failure: {seen:?}"
            );
        }

        // A memory table with no descriptor behind it is refused by the
        // frontend before it sends anything, after SET_FEATURES went out, so
        // the handover fails partway on a connection that is still sound. A
        // driver marks a device failed by adding FAILED to the status it reads
        // back. No ring was sent, so the reset takes none back.
        #[test]
        fn failed_handover_is_not_run_again_before_a_reset() {
            let (daemon, stream) = Daemon::spawn(ReplyPolicy::All);
            let (_ram, mem) = guest_ram();
            let driver = driver(stream, &mem, -1);
            driver.start(&[rings(BASE)]);
            assert_ne!(driver.read(STATUS) & NEEDS_RESET, 0, "NEEDS_RESET is set");
            driver.write(STATUS, driver.read(STATUS) | FAILED);
            driver.driver_ok();
            driver.reset();
            drop(driver);

            assert_eq!(
                daemon.join(),
                [
                    FrontendReq::SET_OWNER,
                    FrontendReq::GET_FEATURES,
                    FrontendReq::GET_PROTOCOL_FEATURES,
                    FrontendReq::SET_PROTOCOL_FEATURES,
                    FrontendReq::GET_QUEUE_NUM,
                    FrontendReq::SET_FEATURES,
                ]
            );
        }

        #[test]
        fn daemon_without_version_1_is_refused_at_attach() {
            let (daemon, stream) = DaemonConfig {
                features: VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
                ..DaemonConfig::default()
            }
            .spawn();
            let (ram, _mem) = guest_ram();
            let error = VhostUserFs::from_stream(stream, "t", 1, 1024, ram.as_raw_fd())
                .err()
                .expect("the attach should fail");
            assert!(error.to_string().contains("VIRTIO_F_VERSION_1"), "{error}");
            assert_eq!(
                daemon.join(),
                [FrontendReq::SET_OWNER, FrontendReq::GET_FEATURES]
            );
        }

        #[test]
        fn common_registers_follow_virtio_1_2() {
            let (daemon, stream) = Daemon::spawn(ReplyPolicy::All);
            let (ram, mem) = guest_ram();
            let dev =
                VhostUserFs::from_stream(stream, "t", 1, 1024, ram.as_raw_fd()).expect("handshake");
            testing::assert_common_registers(dev, &mem, rings(BASE));
            daemon.join();
        }

        #[test]
        fn more_request_queues_than_the_daemon_serves_are_refused() {
            let (daemon, stream) = Daemon::spawn(ReplyPolicy::All);
            let (ram, _mem) = guest_ram();
            let err = VhostUserFs::from_stream(stream, "t", 2, 1024, ram.as_raw_fd())
                .err()
                .expect("three queues from a daemon that serves two");
            assert!(
                err.to_string()
                    .contains("num_queues=2 needs 3 queues, and the daemon serves 2"),
                "{err}"
            );
            daemon.join();
        }

        #[test]
        fn queue_num_max_is_the_exports_queue_size() {
            let (daemon, stream) = Daemon::spawn(ReplyPolicy::All);
            let (ram, mem) = guest_ram();
            let dev =
                VhostUserFs::from_stream(stream, "t", 1, 256, ram.as_raw_fd()).expect("handshake");
            let driver = Driver::new(dev, &mem);
            assert_eq!(driver.read(QUEUE_NUM_MAX), 256);
            drop(driver);
            daemon.join();
        }

        #[test]
        fn shutdown_frees_a_reset_waiting_on_a_silent_daemon() {
            let (daemon, stream) = Daemon::spawn(ReplyPolicy::NoVringBase);
            let (ram, mem) = guest_ram();
            let driver = driver(stream, &mem, ram.as_raw_fd());
            driver.start(&[rings(BASE)]);
            let stop = driver.device.lock().unwrap().shutdown_fds();

            let (tx, rx) = mpsc::channel();
            let resetting = std::thread::spawn(move || {
                driver.reset();
                tx.send(()).expect("the test is waiting");
                driver
            });
            assert!(
                rx.recv_timeout(Duration::from_millis(500)).is_err(),
                "the reset returned with no answer from the daemon"
            );
            stop.shutdown();
            rx.recv_timeout(Duration::from_secs(5))
                .expect("the shutdown freed the reset");
            drop(resetting.join().expect("the resetting thread"));
            daemon.join();
        }

        // A reset that waits on the daemon holds the device, and the guest
        // still learns of the buffers the daemon used.
        #[test]
        fn used_buffer_raises_the_interrupt_while_the_device_is_held() {
            let (daemon, stream) = Daemon::spawn(ReplyPolicy::All);
            let (ram, _mem) = guest_ram();
            let dev = Arc::new(Mutex::new(
                VhostUserFs::from_stream(stream, "t", 1, 1024, ram.as_raw_fd()).expect("handshake"),
            ));
            let call = dev
                .lock()
                .expect("the device")
                .call_fd(0)
                .expect("queue 0")
                .expect("a call descriptor");
            let (interrupt, line) = testing::enabled_interrupt();
            let stop = StopSource::new().expect("a stop pair");
            let serving = {
                let (call, token) = (call.try_clone().unwrap(), stop.token());
                std::thread::spawn(move || serve_interrupts(&interrupt, &call, &token))
            };

            let held = dev.lock().expect("the device");
            call.write(1).expect("signal a used buffer");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !line.is_high() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(held);
            assert!(line.is_high(), "a used buffer left the line low");

            stop.request_stop();
            serving.join().expect("the stop ended the thread");
            drop(dev);
            daemon.join();
        }

        /// Returns a path for a socket in a fresh directory of its own.
        fn socket_path(name: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir().join(format!("hvi-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("a scratch directory");
            dir.join("vhost.sock")
        }

        // urunc starts its virtiofsd and the VMM at once, so the socket can
        // appear only after the VMM asks for it.
        #[test]
        fn connect_waits_for_a_socket_that_appears_late() {
            let path = socket_path("late");
            let binder = {
                let path = path.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(300));
                    std::os::unix::net::UnixListener::bind(&path).expect("bind")
                })
            };
            let stream = connect_waiting(&path, Duration::from_secs(5));
            let listener = binder.join().expect("the binder");
            stream.expect("the connect waited for the socket");
            drop(listener);
        }

        #[test]
        fn connect_gives_up_on_a_socket_that_never_appears() {
            let path = socket_path("never");
            let err = connect_waiting(&path, Duration::from_millis(250)).expect_err("no socket");
            assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
            let text = err.to_string();
            assert!(text.contains(&path.display().to_string()), "{text}");
            assert!(text.contains("waited"), "{text}");
        }

        // A daemon that is restarting leaves its socket file behind, and a
        // connect to it is refused until the new one listens.
        #[test]
        fn connect_waits_on_a_stale_socket_until_it_listens() {
            let path = socket_path("stale");
            drop(std::os::unix::net::UnixListener::bind(&path).expect("bind"));
            let binder = {
                let path = path.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(300));
                    std::fs::remove_file(&path).expect("the stale file");
                    std::os::unix::net::UnixListener::bind(&path).expect("bind")
                })
            };
            let stream = connect_waiting(&path, Duration::from_secs(5));
            let listener = binder.join().expect("the binder");
            stream.expect("the connect waited for the listener");
            drop(listener);
        }

        #[test]
        fn connect_does_not_wait_out_an_error_a_retry_cannot_change() {
            let file = socket_path("notdir");
            std::fs::write(&file, b"").expect("a plain file");
            let path = file.join("vhost.sock");
            let started = std::time::Instant::now();
            let err = connect_waiting(&path, Duration::from_secs(30)).expect_err("not a directory");
            assert!(started.elapsed() < Duration::from_secs(5), "{err}");
            assert!(!err.to_string().contains("waited"), "{err}");
        }

        #[test]
        fn reset_takes_back_a_ring_the_guest_cleared_after_driver_ok() {
            let (daemon, stream) = Daemon::spawn(ReplyPolicy::All);
            let (ram, mem) = guest_ram();
            let driver = driver(stream, &mem, ram.as_raw_fd());
            driver.start(&[rings(BASE), rings(BASE + 0x1000)]);
            driver.write(QUEUE_SEL, 1);
            driver.write(QUEUE_READY, 0);
            driver.reset();
            drop(driver);

            let seen = daemon.join();
            let taken_back = seen
                .iter()
                .filter(|&&r| r == FrontendReq::GET_VRING_BASE)
                .count();
            assert_eq!(
                taken_back, 2,
                "a ring the daemon serves was left with it: {seen:?}"
            );
        }

        // The stand-in lags once the handover starts, so a DRIVER_OK that does
        // not wait for it returns before the stand-in has read the enables.
        #[test]
        fn driver_ok_waits_for_the_daemon_to_enable_the_rings() {
            let (daemon, stream) = DaemonConfig {
                handover_delay: HANDOVER_DELAY,
                ..DaemonConfig::default()
            }
            .spawn();
            let (ram, mem) = guest_ram();
            let driver = driver(stream, &mem, ram.as_raw_fd());
            driver.start(&[rings(BASE), rings(BASE + 0x1000)]);
            let seen = daemon.requests();
            let enabled = seen
                .iter()
                .filter(|&&r| r == FrontendReq::SET_VRING_ENABLE)
                .count();
            assert_eq!(enabled, 2, "DRIVER_OK returned first: {seen:?}");
            drop(driver);
            daemon.join();
        }

        // Without protocol features a ring starts, already enabled, on
        // SET_VRING_KICK, so the wait has to cover the last SET_VRING_KICK.
        #[test]
        fn driver_ok_waits_for_a_daemon_without_protocol_features_to_start_the_rings() {
            let (daemon, stream) = DaemonConfig {
                features: 1 << VIRTIO_F_VERSION_1,
                protocol_features: VhostUserProtocolFeatures::empty(),
                handover_delay: HANDOVER_DELAY,
                ..DaemonConfig::default()
            }
            .spawn();
            let (ram, mem) = guest_ram();
            let driver = driver(stream, &mem, ram.as_raw_fd());
            driver.start(&[rings(BASE), rings(BASE + 0x1000)]);
            let seen = daemon.requests();
            let started = seen
                .iter()
                .filter(|&&r| r == FrontendReq::SET_VRING_KICK)
                .count();
            assert_eq!(started, 2, "DRIVER_OK returned first: {seen:?}");
            drop(driver);
            daemon.join();
        }

        #[test]
        fn shutdown_frees_a_driver_ok_waiting_on_a_silent_daemon() {
            let (daemon, stream) = Daemon::spawn(ReplyPolicy::AttachOnly);
            let (ram, mem) = guest_ram();
            let driver = driver(stream, &mem, ram.as_raw_fd());
            let stop = driver.device.lock().unwrap().shutdown_fds();

            let (tx, rx) = mpsc::channel();
            let starting = std::thread::spawn(move || {
                driver.start(&[rings(BASE)]);
                tx.send(()).expect("the test is waiting");
                driver
            });
            assert!(
                rx.recv_timeout(Duration::from_millis(500)).is_err(),
                "DRIVER_OK returned with no answer from the daemon"
            );
            stop.shutdown();
            rx.recv_timeout(Duration::from_secs(5))
                .expect("the shutdown freed DRIVER_OK");
            drop(starting.join().expect("the starting thread"));
            daemon.join();
        }

        // The transport refuses a ring outside guest RAM at QUEUE_READY, so the
        // handover sends none of it, and the daemon has nothing to enable and
        // nothing to give back.
        #[test]
        fn refused_ring_is_neither_enabled_nor_taken_back() {
            let (daemon, stream) = Daemon::spawn(ReplyPolicy::All);
            let (ram, mem) = guest_ram();
            let driver = driver(stream, &mem, ram.as_raw_fd());
            driver.start(&[rings(BASE), rings(BASE + 0x20_0000)]);
            driver.reset();
            drop(driver);

            assert_eq!(
                daemon.join(),
                [
                    FrontendReq::SET_OWNER,
                    FrontendReq::GET_FEATURES,
                    FrontendReq::GET_PROTOCOL_FEATURES,
                    FrontendReq::SET_PROTOCOL_FEATURES,
                    FrontendReq::GET_QUEUE_NUM,
                    FrontendReq::SET_FEATURES,
                    FrontendReq::SET_MEM_TABLE,
                    FrontendReq::SET_VRING_NUM,
                    FrontendReq::SET_VRING_ADDR,
                    FrontendReq::SET_VRING_BASE,
                    FrontendReq::SET_VRING_CALL,
                    FrontendReq::SET_VRING_KICK,
                    FrontendReq::SET_VRING_ENABLE,
                    FrontendReq::GET_FEATURES,
                    FrontendReq::SET_VRING_ENABLE,
                    FrontendReq::GET_VRING_BASE,
                ]
            );
        }

        // Negotiating VHOST_USER_F_PROTOCOL_FEATURES leaves every ring
        // disabled until SET_VRING_ENABLE, with or without MQ. A daemon that
        // offers protocol features but not MQ used to get no enable, and the
        // guest's first request hung.
        #[test]
        fn rings_are_enabled_on_a_daemon_without_mq() {
            let (daemon, stream) = DaemonConfig {
                protocol_features: VhostUserProtocolFeatures::empty(),
                ..DaemonConfig::default()
            }
            .spawn();
            let (ram, mem) = guest_ram();
            let driver = driver(stream, &mem, ram.as_raw_fd());
            driver.start(&[rings(BASE)]);
            driver.reset();
            drop(driver);

            assert_eq!(
                daemon.join(),
                [
                    FrontendReq::SET_OWNER,
                    FrontendReq::GET_FEATURES,
                    FrontendReq::GET_PROTOCOL_FEATURES,
                    FrontendReq::SET_PROTOCOL_FEATURES,
                    FrontendReq::SET_FEATURES,
                    FrontendReq::SET_MEM_TABLE,
                    FrontendReq::SET_VRING_NUM,
                    FrontendReq::SET_VRING_ADDR,
                    FrontendReq::SET_VRING_BASE,
                    FrontendReq::SET_VRING_CALL,
                    FrontendReq::SET_VRING_KICK,
                    FrontendReq::SET_VRING_ENABLE,
                    FrontendReq::GET_FEATURES,
                    FrontendReq::SET_VRING_ENABLE,
                    FrontendReq::GET_VRING_BASE,
                ]
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_space_carries_the_tag_and_the_queue_count() {
        let config = config_space("shared", 1);
        assert_eq!(config.len(), CONFIG_LEN);
        assert_eq!(&config[..6], b"shared");
        assert!(config[6..TAG_LEN].iter().all(|&b| b == 0));
        assert_eq!(&config[TAG_LEN..], &1u32.to_le_bytes());
    }

    // A tag the guest can still mount beats a config space that runs past its
    // own length.
    #[test]
    fn overlong_tag_is_truncated() {
        let tag = "t".repeat(TAG_LEN + 10);
        let config = config_space(&tag, 1);
        assert_eq!(config.len(), CONFIG_LEN);
        assert!(config[..TAG_LEN].iter().all(|&b| b == b't'));
    }

    #[test]
    fn the_hiprio_queue_is_counted() {
        assert_eq!(queue_count(1), 2);
        assert_eq!(queue_count(4), 5);
    }
}

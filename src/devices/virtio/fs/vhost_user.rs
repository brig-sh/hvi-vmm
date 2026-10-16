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
//! walks the virtqueues in its own process. What stays here is the part the
//! guest talks to -- the virtio-mmio register file, feature negotiation, and
//! the handshake that hands the rings to the daemon.
//!
//! The split costs one thing. A request the daemon serves never crosses this
//! process, so the file-level events the macOS device captures have no
//! counterpart here. The block and network boundaries are unaffected.

/// Length of the tag field in the virtio-fs config space.
pub const TAG_LEN: usize = 36;

/// Size of the virtio-fs config space, the tag and the request-queue count.
pub const CONFIG_LEN: usize = TAG_LEN + 4;

/// Largest ring a split virtqueue can have, and so the largest queue size an
/// export can be given.
///
/// Named for the value rather than for the register, because
/// `virtio::QUEUE_NUM_MAX` is a different number for a different device.
pub const MAX_QUEUE_SIZE: u16 = crate::config::FsConfig::MAX_QUEUE_SIZE;

/// Feature bits the guest may negotiate, before intersecting with what the
/// daemon offers.
///
/// Bit 32 is `VIRTIO_F_VERSION_1`, bit 28 `VIRTIO_RING_F_INDIRECT_DESC` and
/// bit 29 `VIRTIO_RING_F_EVENT_IDX`. The rings belong to the daemon, so how
/// it walks them is its business.
pub const TRANSPORT_FEATURES: u64 = (1 << 32) | (1 << 28) | (1 << 29);

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

/// Returns the feature word to record when the driver writes `value` with
/// `select` in `DRIVER_FEATURES_SEL`, masked to what the device offered.
///
/// The driver may write any bit. What reaches the daemon has to be a subset
/// of what was advertised, because the daemon acts on bits this transport
/// never implemented: `VHOST_F_LOG_ALL` asks it to log writes to a region no
/// `SET_LOG_BASE` ever named.
#[must_use]
pub fn ack_features(current: u64, value: u32, select: u32, offered: u64) -> u64 {
    let word = u64::from(value) << (32 * u64::from(select & 1));
    current | (word & offered)
}

/// Returns the byte extents of the three rings of a virtqueue of `size`
/// descriptors, in descriptor, available and used order, or `None` when `size`
/// is not a legal queue size.
///
/// The layout is the split-virtqueue one: 16 bytes per descriptor, and two
/// rings that carry a flags and an index field, `size` entries and an event
/// suppression field. A size that is zero, above `max` or not a power of two
/// is not a queue, and the extents of one are what says whether the addresses
/// the driver programmed are backed by guest RAM.
#[must_use]
pub fn ring_extents(size: u16, max: u16) -> Option<(usize, usize, usize)> {
    if size == 0 || size > max || !size.is_power_of_two() {
        return None;
    }
    let size = usize::from(size);
    Some((16 * size, 6 + 2 * size, 6 + 8 * size))
}

/// Returns the virtqueue count for a device with `request_queues` request
/// queues, counting the hiprio queue the spec puts first.
#[must_use]
pub fn queue_count(request_queues: usize) -> usize {
    request_queues + 1
}

// The device needs the `vhost` crate and the I/O threads, which exist only for
// the Linux backends.
#[cfg(target_os = "linux")]
pub(crate) use self::device::start_interrupt_threads;
#[cfg(target_os = "linux")]
pub use self::device::{
    attach, connect_waiting, export_at, serve_interrupts, serve_mmio, shut_down, Export,
    ShutdownFds, VhostUserFs, SOCKET_WAIT,
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
    use vmm_sys_util::eventfd::EventFd;

    use crate::config::FsConfig;
    use crate::devices::irq::{Irq, IrqLine};
    use crate::devices::virtio::mmio;
    use crate::hypervisor::vcpus::Kick;
    use crate::io_threads::IoThreads;
    use crate::memory::GuestRam;
    use crate::sync::lock_or_recover;
    use crate::teardown::StopToken;
    use crate::LOG_PREFIX;

    use super::{ack_features, config_space, queue_count, ring_extents, TRANSPORT_FEATURES};

    const MAGIC_VALUE: u64 = 0x7472_6976; // "virt"
    const VENDOR: u64 = 0x4649_4f4e; // "NOIF"
    const VIRTIO_FS_ID: u64 = virtio_bindings::virtio_ids::VIRTIO_ID_FS as u64;

    /// `VIRTIO_CONFIG_S_DRIVER_OK`, the status bit that says the rings are
    /// programmed and the guest is ready to use the device.
    const STATUS_DRIVER_OK: u32 = 4;

    /// Ring addresses and size as the guest programmed them.
    #[derive(Default, Clone, Copy)]
    struct Ring {
        /// Number of descriptors, from `QUEUE_NUM`.
        size: u16,
        /// Whether the guest has set `QUEUE_READY`.
        ready: bool,
        /// Guest-physical address of the descriptor table.
        desc: u64,
        /// Guest-physical address of the available ring.
        avail: u64,
        /// Guest-physical address of the used ring.
        used: u64,
        /// Whether the daemon was sent this ring, set before its first
        /// message.
        ///
        /// A reset takes back the rings that have it set. `ready` is the
        /// guest's, and the guest can change it after `DRIVER_OK`.
        handed_over: bool,
    }

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

    /// How long [`VhostUserFs::connect`] waits for a daemon's socket, which is
    /// what Cloud Hypervisor waits.
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

    /// One virtio-fs device, holding the guest's virtio-mmio transport and the
    /// vhost-user connection to the daemon that serves it.
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
        /// One entry per queue, the hiprio queue first.
        rings: Vec<Ring>,
        /// The eventfd per queue that a `QUEUE_NOTIFY` writes for the daemon.
        kick: Vec<EventFd>,
        /// The eventfd per queue the daemon writes once it has used a buffer.
        call: Vec<EventFd>,
        /// The device config space, which [`config_space`] builds.
        config: Vec<u8>,
        /// What the daemon offers, already intersected with
        /// [`TRANSPORT_FEATURES`].
        device_features: u64,
        /// What the guest has written to `DRIVER_FEATURES`.
        acked_features: u64,
        /// The largest ring the guest may program, which `QUEUE_NUM_MAX`
        /// reads.
        queue_size: u16,
        /// Whether the peer offered `VHOST_USER_F_PROTOCOL_FEATURES`, which
        /// [`hand_over`](Self::hand_over) then acknowledges.
        ///
        /// Acknowledging it to a peer that did not offer it is what
        /// [`super::ack_features`] stops the guest doing in the other
        /// direction. With it acknowledged, every ring starts disabled until
        /// `SET_VRING_ENABLE`. virtiofsd and QEMU always offer it; a peer
        /// named with `--fs` is whatever the caller runs.
        protocol_features_offered: bool,
        /// The `DEVICE_FEATURES_SEL` word the guest selected.
        dev_feat_sel: u32,
        /// The `DRIVER_FEATURES_SEL` word the guest selected.
        drv_feat_sel: u32,
        /// The queue the guest selected through `QUEUE_SEL`.
        queue_sel: u32,
        /// The device status the guest wrote, zero after a reset.
        status: u32,
        /// The pending `INTERRUPT_STATUS` bits.
        interrupt_status: u32,
        /// The interrupt line the device drives.
        irq: Irq,
        /// Whether a `DRIVER_OK` has started a handover since the last reset.
        ///
        /// It is set before the first message, so a handover that failed
        /// partway counts too, and the next one waits for a reset.
        handover_attempted: bool,
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
        /// Errors if the socket cannot be reached in time, if the daemon
        /// refuses the feature handshake, or if it serves fewer queues than
        /// `request_queues` needs.
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
        /// Errors if the daemon refuses the feature handshake, or if it serves
        /// fewer queues than `request_queues` needs.
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
                // The kick side is only written, from the vCPU thread
                // servicing a QUEUE_NOTIFY. The call side is read by a thread
                // per queue, which blocks on it.
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
                rings: vec![Ring::default(); queues],
                kick,
                call,
                config: config_space(tag, request_queues as u32),
                device_features: offered & TRANSPORT_FEATURES,
                acked_features: 0,
                queue_size,
                protocol_features_offered,
                dev_feat_sel: 0,
                drv_feat_sel: 0,
                queue_sel: 0,
                status: 0,
                interrupt_status: 0,
                irq: Irq::default(),
                handover_attempted: false,
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
            self.rings.len()
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
        /// see [`serve_interrupts`].
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

        /// Records that the daemon has used buffers, so the guest's next read
        /// of `INTERRUPT_STATUS` sees a used-buffer notification, and raises
        /// the line.
        pub fn signal_used(&mut self) {
            self.interrupt_status |= 1;
            self.sync_irq();
        }

        /// Returns whether the device's interrupt line is asserted.
        #[must_use]
        pub fn irq_level(&self) -> bool {
            self.interrupt_status != 0
        }

        /// Connects the device to the interrupt line it raises.
        pub(crate) fn connect_irq(&mut self, line: Arc<dyn IrqLine>) {
            self.irq.connect(line);
        }

        /// Sets the interrupt line to the device's level.
        fn sync_irq(&mut self) {
            self.irq.set(self.irq_level());
        }

        /// Services one virtio-mmio register access, sets the line to the
        /// level it leaves, and returns the value a read takes.
        pub fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
            let v = value as u32;
            let read = if is_write {
                self.write_reg(mem, offset, v);
                0
            } else {
                self.read_reg(offset)
            };
            self.sync_irq();
            read
        }

        fn write_reg(&mut self, mem: &GuestRam, offset: u64, v: u32) {
            match offset {
                mmio::DEVICE_FEATURES_SEL => self.dev_feat_sel = v,
                mmio::DRIVER_FEATURES_SEL => self.drv_feat_sel = v,
                mmio::DRIVER_FEATURES => {
                    self.acked_features = ack_features(
                        self.acked_features,
                        v,
                        self.drv_feat_sel,
                        self.device_features,
                    );
                }
                mmio::QUEUE_SEL => self.queue_sel = v,
                mmio::QUEUE_NUM => self.ring_mut(|r| r.size = v as u16),
                mmio::QUEUE_READY => self.ring_mut(|r| r.ready = v & 1 != 0),
                mmio::QUEUE_NOTIFY => self.kick_queue(v as usize),
                mmio::INTERRUPT_ACK => self.interrupt_status &= !v,
                mmio::STATUS if v == 0 => self.reset(),
                mmio::STATUS => {
                    self.status = v;
                    if v & STATUS_DRIVER_OK != 0 && !self.handover_attempted {
                        self.start(mem);
                    }
                }
                mmio::QUEUE_DESC_LOW => self.ring_mut(|r| r.desc = set_lo(r.desc, v)),
                mmio::QUEUE_DESC_HIGH => self.ring_mut(|r| r.desc = set_hi(r.desc, v)),
                mmio::QUEUE_DRIVER_LOW => self.ring_mut(|r| r.avail = set_lo(r.avail, v)),
                mmio::QUEUE_DRIVER_HIGH => self.ring_mut(|r| r.avail = set_hi(r.avail, v)),
                mmio::QUEUE_DEVICE_LOW => self.ring_mut(|r| r.used = set_lo(r.used, v)),
                mmio::QUEUE_DEVICE_HIGH => self.ring_mut(|r| r.used = set_hi(r.used, v)),
                _ => {}
            }
        }

        fn read_reg(&self, offset: u64) -> u64 {
            match offset {
                mmio::MAGIC => MAGIC_VALUE,
                mmio::VERSION => 2,
                mmio::DEVICE_ID => VIRTIO_FS_ID,
                mmio::VENDOR_ID => VENDOR,
                mmio::DEVICE_FEATURES => {
                    let shift = 32 * u64::from(self.dev_feat_sel & 1);
                    (self.device_features >> shift) & 0xffff_ffff
                }
                mmio::QUEUE_NUM_MAX => u64::from(self.queue_size),
                mmio::QUEUE_READY => u64::from(self.ring().is_some_and(|r| r.ready)),
                // The device has no shared memory region, which virtio 1.2
                // reads as all ones. A guest built with FUSE_DAX fails its
                // probe on a zero length.
                mmio::SHM_LEN_LOW
                | mmio::SHM_LEN_HIGH
                | mmio::SHM_BASE_LOW
                | mmio::SHM_BASE_HIGH => 0xffff_ffff,
                mmio::INTERRUPT_STATUS => u64::from(self.interrupt_status),
                mmio::STATUS => u64::from(self.status),
                _ if offset >= mmio::CONFIG => {
                    let field = (offset - mmio::CONFIG) as usize;
                    let mut word = [0u8; 8];
                    for (i, b) in word.iter_mut().enumerate() {
                        if let Some(&c) = self.config.get(field + i) {
                            *b = c;
                        }
                    }
                    u64::from_le_bytes(word)
                }
                _ => 0,
            }
        }

        fn ring(&self) -> Option<&Ring> {
            self.rings.get(self.queue_sel as usize)
        }

        fn ring_mut(&mut self, edit: impl FnOnce(&mut Ring)) {
            if let Some(ring) = self.rings.get_mut(self.queue_sel as usize) {
                edit(ring);
            }
        }

        fn kick_queue(&self, index: usize) {
            if let Some(fd) = self.kick.get(index) {
                let _ = fd.write(1);
            }
        }

        /// Resets the device, as a write of 0 to STATUS requests.
        ///
        /// The daemon is told first. It walks the rings in its own process, so
        /// a reset that only cleared this side would leave it enabled on ring
        /// addresses the driver has released, writing used entries into pages
        /// the guest has given to something else.
        fn reset(&mut self) {
            // The flag is set before a handover's first message, so one that
            // failed partway still has the queues it got through taken back.
            if self.handover_attempted {
                self.stop_rings();
            }
            for ring in &mut self.rings {
                *ring = Ring::default();
            }
            self.interrupt_status = 0;
            self.status = 0;
            self.acked_features = 0;
            self.dev_feat_sel = 0;
            self.drv_feat_sel = 0;
            self.handover_attempted = false;
        }

        /// Takes every ring back from the daemon.
        ///
        /// `SET_VRING_ENABLE(false)` stops it serving, and `GET_VRING_BASE` is
        /// what the protocol defines as the point the backend stops using a
        /// ring. Both are best-effort, and a reset goes ahead whatever the
        /// daemon answers, so the guest can initialize the device again. A
        /// broken connection is sent neither; see [`Peer::broken`].
        fn stop_rings(&mut self) {
            for index in 0..self.rings.len() {
                if self.peer.broken {
                    return;
                }
                if !self.rings[index].handed_over {
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

        /// Hands the programmed rings and guest RAM to the daemon.
        ///
        /// A failure here leaves the device without a backend, so the mount
        /// the guest is about to attempt fails. The boot continues: an export
        /// that cannot be served is not a reason to take the guest down.
        fn start(&mut self, mem: &GuestRam) {
            self.handover_attempted = true;
            if let Err(e) = self.hand_over(mem) {
                stderrln!("{LOG_PREFIX} virtio-fs {}: {e}", self.tag);
            }
        }

        fn hand_over(&mut self, mem: &GuestRam) -> io::Result<()> {
            let mut features = self.acked_features;
            if self.protocol_features_offered {
                features |= VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            }
            self.peer
                .send("SET_FEATURES", |f| f.set_features(features))?;

            let regions = self.memory_table(mem)?;
            self.peer
                .send("SET_MEM_TABLE", |f| f.set_mem_table(&regions))?;

            for index in 0..self.rings.len() {
                let ring = self.rings[index];
                if !ring.ready {
                    continue;
                }
                // The addresses and the size are the driver's, and the daemon
                // walks them in its own process against a memory table it maps
                // itself. A ring that is not backed by guest RAM for its whole
                // extent, or whose size is not a queue size, is refused here
                // and left un-enabled, which the guest sees as a device that
                // does not answer.
                let Some((desc_len, avail_len, used_len)) =
                    ring_extents(ring.size, self.queue_size)
                else {
                    stderrln!(
                        "{LOG_PREFIX} virtio-fs {}: queue {index} has size {}, which is not a \
                         queue size; leaving it disabled",
                        self.tag,
                        ring.size
                    );
                    continue;
                };
                let (desc, avail, used) = match (
                    host_addr(mem, ring.desc, desc_len),
                    host_addr(mem, ring.avail, avail_len),
                    host_addr(mem, ring.used, used_len),
                ) {
                    (Ok(desc), Ok(avail), Ok(used)) => (desc, avail, used),
                    _ => {
                        stderrln!(
                            "{LOG_PREFIX} virtio-fs {}: queue {index} is programmed outside guest \
                             RAM; leaving it disabled",
                            self.tag
                        );
                        continue;
                    }
                };
                let config = VringConfigData {
                    queue_max_size: self.queue_size,
                    queue_size: ring.size,
                    flags: 0,
                    desc_table_addr: desc,
                    used_ring_addr: used,
                    avail_ring_addr: avail,
                    log_addr: None,
                };
                self.rings[index].handed_over = true;
                self.peer
                    .send("SET_VRING_NUM", |f| f.set_vring_num(index, ring.size))?;
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
                for index in 0..self.rings.len() {
                    if !self.rings[index].handed_over {
                        continue;
                    }
                    self.peer
                        .send("SET_VRING_ENABLE", |f| f.set_vring_enable(index, true))?;
                }
            }
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

    /// Services one register access on `dev` and returns the value a read
    /// takes.
    ///
    /// The device sets its line under the lock the access holds, as it does
    /// for [`serve_interrupts`].
    pub fn serve_mmio(
        dev: &Mutex<VhostUserFs>,
        mem: &GuestRam,
        offset: u64,
        is_write: bool,
        value: u64,
    ) -> u64 {
        lock_or_recover(dev).mmio(mem, offset, is_write, value)
    }

    /// Raises the guest's interrupt for `dev` each time the daemon signals
    /// `call`, until `stop` is requested.
    ///
    /// The daemon walks the rings in its own process, so the only thing left
    /// for this side is delivery. A signal on a queue's call descriptor says
    /// buffers were used, and the guest learns it from the device's interrupt
    /// status. The device raises its line under its lock, so a register access
    /// that lowers the line cannot interleave with the raise.
    pub fn serve_interrupts(dev: &Mutex<VhostUserFs>, call: &EventFd, stop: &StopToken) {
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
            lock_or_recover(dev).signal_used();
        }
    }

    /// One export as a backend wires it: the device, the window its transport
    /// answers in, and the interrupt it raises.
    #[derive(Clone)]
    pub struct Export {
        /// Guest-physical base of the transport's MMIO window.
        pub base: u64,
        /// The interrupt the backend raises for this export, a GSI on x86 and
        /// an SPI on arm64.
        pub irq: u32,
        /// The device behind the transport.
        pub dev: Arc<Mutex<VhostUserFs>>,
        /// The descriptors a shutdown uses, so it never has to take `dev`.
        pub stop: ShutdownFds,
    }

    /// Connects one export per socket and returns them in order.
    ///
    /// `place` returns the window base and the interrupt of export `index`,
    /// or an error when the machine has none left. Each export is attached to
    /// the daemon listening on its socket, which the caller started. The
    /// connect and the handshake happen here, before the seccomp filters go
    /// in. Every export is placed before any is connected, so a machine with
    /// too few windows is refused before a daemon sees a connection.
    ///
    /// # Errors
    ///
    /// Errors if `place` does, if a socket cannot be reached in time, or if a
    /// daemon refuses the vhost-user handshake.
    pub fn attach(
        sockets: &[FsConfig],
        ram_fd: RawFd,
        place: impl FnMut(usize) -> io::Result<(u64, u32)>,
    ) -> io::Result<Vec<Export>> {
        let placed = (0..sockets.len())
            .map(place)
            .collect::<io::Result<Vec<_>>>()?;
        let mut exports = Vec::with_capacity(sockets.len());
        for (index, (export, (base, irq))) in sockets.iter().zip(placed).enumerate() {
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
                base,
                irq,
                stop: dev.shutdown_fds(),
                dev: Arc::new(Mutex::new(dev)),
            });
        }
        Ok(exports)
    }

    /// Returns the export whose window of `size` bytes holds `addr`, or `None`
    /// when no export's window does.
    #[must_use]
    pub fn export_at(exports: &[Export], addr: u64, size: u64) -> Option<&Export> {
        exports
            .iter()
            .find(|export| (export.base..export.base + size).contains(&addr))
    }

    /// Starts one [`serve_interrupts`] thread per queue of every export under
    /// `io_threads`.
    ///
    /// A thread ends when the I/O threads stop. An export whose call
    /// descriptors cannot be duplicated gets no thread, so its guest never
    /// sees a used buffer, and the boot says so on stderr.
    ///
    /// It has to be called from a thread with no seccomp filter, as
    /// [`IoThreads::spawn`] says.
    pub(crate) fn start_interrupt_threads<K: Kick + 'static>(
        exports: &[Export],
        io_threads: &mut IoThreads<K>,
    ) {
        for export in exports {
            let calls = match lock_or_recover(&export.dev).call_fds() {
                Ok(calls) => calls,
                Err(e) => {
                    stderrln!("{LOG_PREFIX} virtio-fs: queue interrupts unavailable: {e}");
                    continue;
                }
            };
            for call in calls {
                let dev = Arc::clone(&export.dev);
                io_threads.spawn("virtio-fs interrupts", move |stop| {
                    serve_interrupts(&dev, &call, &stop);
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
    fn host_addr(mem: &GuestRam, gpa: u64, len: usize) -> io::Result<u64> {
        mem.host_ptr(gpa, len).map(|p| p as u64)
    }

    /// Returns `current` with its low 32 bits replaced by `v`.
    fn set_lo(current: u64, v: u32) -> u64 {
        (current & 0xffff_ffff_0000_0000) | u64::from(v)
    }

    /// Returns `current` with its high 32 bits replaced by `v`.
    fn set_hi(current: u64, v: u32) -> u64 {
        (current & 0xffff_ffff) | (u64::from(v) << 32)
    }

    #[cfg(test)]
    #[allow(clippy::disallowed_methods)]
    mod tests {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::sync::{mpsc, Arc, Mutex, OnceLock, Weak};
        use std::thread::JoinHandle;
        use std::time::Duration;

        use vhost::vhost_user::message::{
            FrontendReq, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
        };

        use super::{connect_waiting, serve_interrupts, serve_mmio, set_hi, set_lo, VhostUserFs};
        use crate::devices::irq::IrqLine;
        use crate::devices::virtio::mmio;
        use crate::memory::{GuestRam, RamRegion, SharedRam};
        use crate::teardown::StopSource;

        /// Guest-physical address of the RAM the tests map.
        const BASE: u64 = 0x4000_0000;

        /// `ACKNOWLEDGE | DRIVER | DRIVER_OK | FEATURES_OK`, which a driver
        /// writes once its rings are programmed.
        const STATUS_LIVE: u64 = 0xf;

        /// How the stand-in daemon answers `GET_VRING_BASE`.
        #[derive(Clone, Copy)]
        enum VringBase {
            /// With the ring's index and a base of 0.
            Answer,
            /// First with a reply to `GET_FEATURES`, which the frontend
            /// rejects, and after that as `Answer` does.
            WrongReplyFirst,
            /// Never.
            Silent,
        }

        /// A vhost-user daemon stand-in on one end of a socket pair.
        struct Daemon(JoinHandle<Vec<FrontendReq>>);

        impl Daemon {
            /// Starts the stand-in and returns it with the frontend's end.
            fn spawn(vring_base: VringBase) -> (Self, UnixStream) {
                Self::spawn_offering(vring_base, VhostUserProtocolFeatures::MQ)
            }

            /// Starts a stand-in that offers `protocol` as its protocol
            /// features, and returns it with the frontend's end.
            fn spawn_offering(
                vring_base: VringBase,
                protocol: VhostUserProtocolFeatures,
            ) -> (Self, UnixStream) {
                let (ours, theirs) = UnixStream::pair().expect("socket pair");
                let thread = std::thread::spawn(move || serve(theirs, vring_base, protocol));
                (Self(thread), ours)
            }

            /// Returns the requests the stand-in read, once the frontend's end
            /// has closed.
            fn requests(self) -> Vec<FrontendReq> {
                self.0.join().expect("the stand-in daemon")
            }
        }

        /// Reads requests from `socket` until it closes, answers them as a
        /// daemon that offers `VERSION_1` and the `protocol` features and
        /// serves two queues, and returns them.
        fn serve(
            mut socket: UnixStream,
            vring_base: VringBase,
            protocol: VhostUserProtocolFeatures,
        ) -> Vec<FrontendReq> {
            let mut seen = Vec::new();
            let mut wrong_reply_sent = false;
            let mut header = [0u8; 12];
            while socket.read_exact(&mut header).is_ok() {
                let word =
                    |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().expect("a word"));
                let request = FrontendReq::try_from(word(0)).expect("a known request");
                let mut body = vec![0u8; word(8) as usize];
                if socket.read_exact(&mut body).is_err() {
                    break;
                }
                seen.push(request);
                let reply = match request {
                    FrontendReq::GET_FEATURES => {
                        let offered =
                            (1u64 << 32) | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
                        Some((request, offered.to_le_bytes().to_vec()))
                    }
                    FrontendReq::GET_PROTOCOL_FEATURES => {
                        Some((request, protocol.bits().to_le_bytes().to_vec()))
                    }
                    // virtiofsd's count: the hiprio queue and one request
                    // queue.
                    FrontendReq::GET_QUEUE_NUM => Some((request, 2u64.to_le_bytes().to_vec())),
                    FrontendReq::GET_VRING_BASE => match vring_base {
                        VringBase::Silent => None,
                        VringBase::WrongReplyFirst if !wrong_reply_sent => {
                            wrong_reply_sent = true;
                            Some((FrontendReq::GET_FEATURES, vec![0; 8]))
                        }
                        VringBase::Answer | VringBase::WrongReplyFirst => {
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
            seen
        }

        /// Returns 1 MiB of shareable guest RAM, mapped at [`BASE`].
        fn guest_ram() -> (SharedRam, GuestRam) {
            let ram = SharedRam::new(RamRegion::ALIGN as usize).expect("allocate");
            let mem = GuestRam::new(&ram, &[ram.region_at(BASE)]).expect("map");
            (ram, mem)
        }

        /// Programs queue `index` with a ring of 8 descriptors at `at`, as a
        /// driver does before it writes `DRIVER_OK`.
        fn program_queue(dev: &mut VhostUserFs, mem: &GuestRam, index: u64, at: u64) {
            for (offset, value) in [
                (mmio::QUEUE_SEL, index),
                (mmio::QUEUE_NUM, 8),
                (mmio::QUEUE_DESC_LOW, at),
                (mmio::QUEUE_DRIVER_LOW, at + 0x100),
                (mmio::QUEUE_DEVICE_LOW, at + 0x200),
                (mmio::QUEUE_READY, 1),
            ] {
                dev.mmio(mem, offset, true, value);
            }
        }

        #[test]
        fn ring_address_is_assembled_from_two_writes() {
            let addr = set_hi(set_lo(0, 0x1000_2000), 0xff);
            assert_eq!(addr, 0x0000_00ff_1000_2000);
            assert_eq!(set_lo(addr, 0), 0x0000_00ff_0000_0000);
        }

        // A reply to another request leaves the frontend unable to say which
        // message the daemon is answering.
        #[test]
        fn connection_that_failed_is_sent_nothing_more() {
            let (daemon, stream) = Daemon::spawn(VringBase::WrongReplyFirst);
            let (ram, mem) = guest_ram();
            let mut dev =
                VhostUserFs::from_stream(stream, "t", 1, 1024, ram.as_raw_fd()).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            program_queue(&mut dev, &mem, 1, BASE + 0x1000);
            dev.mmio(&mem, mmio::STATUS, true, STATUS_LIVE);
            // The reset reads the wrong reply to queue 0's GET_VRING_BASE.
            dev.mmio(&mem, mmio::STATUS, true, 0);
            program_queue(&mut dev, &mem, 0, BASE);
            dev.mmio(&mem, mmio::STATUS, true, STATUS_LIVE);
            drop(dev);

            let seen = daemon.requests();
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
        // back, which keeps DRIVER_OK set. No ring was sent, so the reset
        // takes none back.
        #[test]
        fn failed_handover_is_not_run_again_before_a_reset() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (_ram, mem) = guest_ram();
            let mut dev = VhostUserFs::from_stream(stream, "t", 1, 1024, -1).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            dev.mmio(&mem, mmio::STATUS, true, STATUS_LIVE);
            dev.mmio(&mem, mmio::STATUS, true, STATUS_LIVE | 0x80);
            dev.mmio(&mem, mmio::STATUS, true, 0);
            drop(dev);

            assert_eq!(
                daemon.requests(),
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
        fn more_request_queues_than_the_daemon_serves_are_refused() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (ram, _mem) = guest_ram();
            let err = VhostUserFs::from_stream(stream, "t", 2, 1024, ram.as_raw_fd())
                .err()
                .expect("three queues from a daemon that serves two");
            assert!(
                err.to_string()
                    .contains("num_queues=2 needs 3 queues, and the daemon serves 2"),
                "{err}"
            );
            daemon.requests();
        }

        #[test]
        fn queue_num_max_is_the_exports_queue_size() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (ram, mem) = guest_ram();
            let mut dev =
                VhostUserFs::from_stream(stream, "t", 1, 256, ram.as_raw_fd()).expect("handshake");
            assert_eq!(dev.mmio(&mem, mmio::QUEUE_NUM_MAX, false, 0), 256);
            drop(dev);
            daemon.requests();
        }

        #[test]
        fn shutdown_frees_a_reset_waiting_on_a_silent_daemon() {
            let (daemon, stream) = Daemon::spawn(VringBase::Silent);
            let (ram, mem) = guest_ram();
            let mut dev =
                VhostUserFs::from_stream(stream, "t", 1, 1024, ram.as_raw_fd()).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            dev.mmio(&mem, mmio::STATUS, true, STATUS_LIVE);
            let stop = dev.shutdown_fds();

            let (tx, rx) = mpsc::channel();
            let resetting = std::thread::spawn(move || {
                dev.mmio(&mem, mmio::STATUS, true, 0);
                tx.send(()).expect("the test is waiting");
                dev
            });
            assert!(
                rx.recv_timeout(Duration::from_millis(500)).is_err(),
                "the reset returned with no answer from the daemon"
            );
            stop.shutdown();
            rx.recv_timeout(Duration::from_secs(5))
                .expect("the shutdown freed the reset");
            drop(resetting.join().expect("the resetting thread"));
            daemon.requests();
        }

        /// A line that sends each level it is set to, with whether its device
        /// was locked at the time.
        struct ProbeLine {
            /// The device, set once it exists.
            dev: OnceLock<Weak<Mutex<VhostUserFs>>>,
            /// Where each level goes.
            seen: Mutex<mpsc::Sender<(bool, bool)>>,
        }

        impl IrqLine for ProbeLine {
            fn set_level(&self, level: bool) -> std::io::Result<()> {
                let locked = self
                    .dev
                    .get()
                    .and_then(Weak::upgrade)
                    .is_some_and(|dev| dev.try_lock().is_err());
                let _ = self.seen.lock().expect("the sender").send((level, locked));
                Ok(())
            }
        }

        /// Returns a device on `stream` connected to a [`ProbeLine`], and the
        /// receiving end of the line.
        fn probed(
            stream: UnixStream,
            ram: &SharedRam,
        ) -> (Arc<Mutex<VhostUserFs>>, mpsc::Receiver<(bool, bool)>) {
            let (tx, rx) = mpsc::channel();
            let line = Arc::new(ProbeLine {
                dev: OnceLock::new(),
                seen: Mutex::new(tx),
            });
            let mut dev =
                VhostUserFs::from_stream(stream, "t", 1, 1024, ram.as_raw_fd()).expect("handshake");
            dev.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
            let dev = Arc::new(Mutex::new(dev));
            let _ = line.dev.set(Arc::downgrade(&dev));
            (dev, rx)
        }

        #[test]
        fn register_access_sets_the_line_under_the_device_lock() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (ram, mem) = guest_ram();
            let (dev, rx) = probed(stream, &ram);
            dev.lock().expect("the device").signal_used();
            assert_eq!(rx.recv().expect("the raise"), (true, true));
            serve_mmio(&dev, &mem, mmio::INTERRUPT_ACK, true, 1);
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(5))
                    .expect("the access lowered the line"),
                (false, true),
                "the line was lowered after the lock was released"
            );
            drop(dev);
            daemon.requests();
        }

        #[test]
        fn used_buffer_raises_the_line_under_the_device_lock() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (ram, _mem) = guest_ram();
            let (dev, rx) = probed(stream, &ram);
            let call = dev
                .lock()
                .expect("the device")
                .call_fd(0)
                .expect("queue 0")
                .expect("a call descriptor");
            let stop = StopSource::new().expect("a stop pair");
            let serving = {
                let (dev, call, token) =
                    (Arc::clone(&dev), call.try_clone().unwrap(), stop.token());
                std::thread::spawn(move || serve_interrupts(&dev, &call, &token))
            };

            call.write(1).expect("signal a used buffer");
            let (level, locked) = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the line was raised");
            assert!(level, "a used buffer left the line low");
            assert!(locked, "the line was raised after the lock was released");

            stop.request_stop();
            serving.join().expect("the stop ended the thread");
            drop(dev);
            daemon.requests();
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
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (ram, mem) = guest_ram();
            let mut dev =
                VhostUserFs::from_stream(stream, "t", 1, 1024, ram.as_raw_fd()).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            program_queue(&mut dev, &mem, 1, BASE + 0x1000);
            dev.mmio(&mem, mmio::STATUS, true, STATUS_LIVE);
            dev.mmio(&mem, mmio::QUEUE_SEL, true, 1);
            dev.mmio(&mem, mmio::QUEUE_READY, true, 0);
            dev.mmio(&mem, mmio::STATUS, true, 0);
            drop(dev);

            let seen = daemon.requests();
            let taken_back = seen
                .iter()
                .filter(|&&r| r == FrontendReq::GET_VRING_BASE)
                .count();
            assert_eq!(
                taken_back, 2,
                "a ring the daemon serves was left with it: {seen:?}"
            );
        }

        // The handover refuses a ring outside guest RAM before sending any of
        // it, so the daemon has nothing to enable and nothing to give back.
        #[test]
        fn refused_ring_is_neither_enabled_nor_taken_back() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (ram, mem) = guest_ram();
            let mut dev =
                VhostUserFs::from_stream(stream, "t", 1, 1024, ram.as_raw_fd()).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            program_queue(&mut dev, &mem, 1, BASE + 0x20_0000);
            dev.mmio(&mem, mmio::STATUS, true, STATUS_LIVE);
            dev.mmio(&mem, mmio::STATUS, true, 0);
            drop(dev);

            assert_eq!(
                daemon.requests(),
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
            let (daemon, stream) =
                Daemon::spawn_offering(VringBase::Answer, VhostUserProtocolFeatures::empty());
            let (ram, mem) = guest_ram();
            let mut dev =
                VhostUserFs::from_stream(stream, "t", 1, 1024, ram.as_raw_fd()).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            dev.mmio(&mem, mmio::STATUS, true, STATUS_LIVE);
            dev.mmio(&mem, mmio::STATUS, true, 0);
            drop(dev);

            assert_eq!(
                daemon.requests(),
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

    // A driver may write any bit; what reaches the daemon may not be one the
    // device never offered, such as VHOST_F_LOG_ALL with no log region.
    #[test]
    fn unoffered_feature_bit_is_not_acked() {
        let offered = TRANSPORT_FEATURES;
        let acked = ack_features(0, 0xffff_ffff, 1, offered);
        assert_eq!(acked, offered & 0xffff_ffff_0000_0000);
        let acked = ack_features(acked, 0xffff_ffff, 0, offered);
        assert_eq!(acked, offered);
        assert_eq!(acked & (1 << 26), 0, "VHOST_F_LOG_ALL reached the daemon");
    }

    #[test]
    fn each_feature_word_lands_where_its_selector_says() {
        assert_eq!(ack_features(0, 1 << 0, 1, 1 << 32), 1 << 32);
        assert_eq!(ack_features(0, 1 << 28, 0, 1 << 28), 1 << 28);
    }

    #[test]
    fn ring_size_that_is_not_a_queue_size_has_no_extents() {
        assert_eq!(ring_extents(0, 1024), None);
        assert_eq!(ring_extents(3, 1024), None);
        assert_eq!(ring_extents(2048, 1024), None);
        assert_eq!(
            ring_extents(512, 256),
            None,
            "above the export's queue size"
        );
    }

    #[test]
    fn ring_extents_cover_the_whole_split_virtqueue() {
        assert_eq!(ring_extents(1, 1024), Some((16, 8, 14)));
        assert_eq!(ring_extents(256, 1024), Some((4096, 518, 2054)));
        let (desc, avail, used) =
            ring_extents(MAX_QUEUE_SIZE, MAX_QUEUE_SIZE).expect("a queue size");
        assert_eq!(desc, 16 * 32768);
        assert_eq!(avail, 6 + 2 * 32768);
        assert_eq!(used, 6 + 8 * 32768);
    }

    #[test]
    fn version_1_is_offered() {
        assert_ne!(TRANSPORT_FEATURES & (1 << 32), 0);
    }
}

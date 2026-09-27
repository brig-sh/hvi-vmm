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
//! The macOS backend implements the FUSE server itself, in the `virtio_fs`
//! module. That module is compiled only on macOS, so this is not an intra-doc
//! link: the link would dangle on every other target.
//!
//! On Linux the same export is served by `virtiofsd`, which speaks vhost-user:
//! it maps guest RAM through the memfd that backs it and walks the virtqueues
//! in its own process. What stays here is the part the guest talks to -- the
//! virtio-mmio register file, feature negotiation, and the handshake that
//! hands the rings to the daemon.
//!
//! The split costs one thing. A request the daemon serves never crosses this
//! process, so the file-level events the macOS device captures have no
//! counterpart here. The block and network boundaries are unaffected.

/// Length of the tag field in the virtio-fs config space.
pub const TAG_LEN: usize = 36;

/// Size of the virtio-fs config space, the tag and the request-queue count.
pub const CONFIG_LEN: usize = TAG_LEN + 4;

/// Largest ring the transport advertises, matching what `virtiofsd` accepts.
///
/// Named for the value rather than for the register, because
/// `virtio::QUEUE_NUM_MAX` is a different number for a different device.
pub const MAX_QUEUE_SIZE: u32 = 1024;

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

/// Byte extents of the three rings of a virtqueue of `size` descriptors, in
/// descriptor, available and used order, or `None` when `size` is not a legal
/// queue size.
///
/// The layout is the split-virtqueue one: 16 bytes per descriptor, and two
/// rings that carry a flags and an index field, `size` entries and an event
/// suppression field. A size that is zero, above [`MAX_QUEUE_SIZE`] or not a
/// power of two is not a queue, and the extents of one are what says whether
/// the addresses the driver programmed are backed by guest RAM.
#[must_use]
pub fn ring_extents(size: u16) -> Option<(usize, usize, usize)> {
    if size == 0 || u32::from(size) > MAX_QUEUE_SIZE || !size.is_power_of_two() {
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

/// Request queues per device, beside the hiprio queue, which both Linux
/// backends build their devices with.
///
/// One is what the guest needs to make progress, and the daemon serves it on
/// its own threads.
pub const REQUEST_QUEUES: usize = 1;

// The device needs the seccomp filters and the daemon launcher, which exist
// only for the Linux backends.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use self::device::{
    attach, export_at, serve_all_interrupts, serve_interrupts, serve_mmio, shut_down, Export,
    ShutdownFds, VhostUserFs,
};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod device {
    use std::io;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
    use vhost::vhost_user::{Frontend, VhostUserFrontend};
    use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
    use vmm_sys_util::eventfd::EventFd;

    use crate::config::FsShare;
    use crate::guestmem::GuestRam;
    use crate::virtio::reg;
    use crate::virtiofsd::Daemon;

    use super::{ack_features, config_space, queue_count, ring_extents, MAX_QUEUE_SIZE};
    use super::{REQUEST_QUEUES, TRANSPORT_FEATURES};

    const MAGIC_VALUE: u64 = 0x7472_6976; // "virt"
    const VENDOR: u64 = 0x4649_4f4e; // "NOIF"
    const VIRTIO_FS_ID: u64 = virtio_bindings::virtio_ids::VIRTIO_ID_FS as u64;

    /// Shared-memory region registers, from `linux/virtio_mmio.h`.
    ///
    /// They are not in the `virtio-bindings` version this crate pins, so the
    /// offsets are written out here.
    const SHM_LEN_LOW: u64 = 0x0b0;
    const SHM_LEN_HIGH: u64 = 0x0b4;

    /// `VIRTIO_CONFIG_S_DRIVER_OK`, the status bit that says the rings are
    /// programmed and the guest is ready to use the device.
    const STATUS_DRIVER_OK: u32 = 4;

    /// Ring addresses and size as the guest programmed them.
    #[derive(Default, Clone, Copy)]
    struct Ring {
        size: u16,
        ready: bool,
        desc: u64,
        avail: u64,
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
        connection: RawFd,
        calls: Vec<RawFd>,
    }

    impl ShutdownFds {
        /// Closes the connection to the daemon and wakes every thread waiting
        /// on a call descriptor.
        ///
        /// Shutting the socket down is what makes the daemon exit, and it is
        /// what a blocked vhost-user read needs to return. The device stays
        /// alive; only its connection ends, so a caller that still holds the
        /// device sees failed messages rather than a use-after-free.
        pub fn shutdown(&self) {
            // SAFETY: both descriptors are owned by a device that outlives
            // this handle, and neither call reads or writes caller memory.
            unsafe {
                libc::shutdown(self.connection, libc::SHUT_RDWR);
                for &call in &self.calls {
                    let one = 1u64;
                    libc::write(call, std::ptr::addr_of!(one).cast(), 8);
                }
            }
        }
    }

    /// The vhost-user connection to the daemon, and whether it can carry
    /// another message.
    struct Peer {
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
        tag: String,
        peer: Peer,
        ram_fd: RawFd,
        rings: Vec<Ring>,
        kick: Vec<EventFd>,
        call: Vec<EventFd>,
        config: Vec<u8>,
        /// What the daemon offers, already intersected with
        /// [`TRANSPORT_FEATURES`].
        device_features: u64,
        /// What the guest has written to `DRIVER_FEATURES`.
        acked_features: u64,
        /// The vhost-user protocol features in force, which the guest never
        /// sees.
        protocol_features: VhostUserProtocolFeatures,
        /// Whether the peer offered `VHOST_USER_F_PROTOCOL_FEATURES` at all.
        ///
        /// Acknowledging it to a peer that did not offer it is what
        /// [`super::ack_features`] stops the guest doing in the other
        /// direction. virtiofsd and QEMU always offer it; a `--share-sock`
        /// peer is whatever the caller runs.
        protocol_features_offered: bool,
        dev_feat_sel: u32,
        drv_feat_sel: u32,
        queue_sel: u32,
        status: u32,
        interrupt_status: u32,
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
        /// The handshake up to `SET_FEATURES` happens here, before the VMM
        /// installs its seccomp filters. Connecting a Unix socket is not on
        /// the allowlist, and the messages that follow are sendmsg and
        /// recvmsg, which are.
        ///
        /// # Errors
        ///
        /// Errors if the socket cannot be reached, or if the daemon refuses
        /// the feature handshake.
        pub fn connect(
            socket: &Path,
            tag: &str,
            request_queues: usize,
            ram_fd: RawFd,
        ) -> io::Result<Self> {
            let stream = UnixStream::connect(socket).map_err(|e| {
                io::Error::other(format!(
                    "vhost-user: connecting to {}: {e}",
                    socket.display()
                ))
            })?;
            Self::from_stream(stream, tag, request_queues, ram_fd)
        }

        /// Prepares a device over an already connected vhost-user socket,
        /// which is what [`crate::virtiofsd::spawn`] hands back.
        ///
        /// # Errors
        ///
        /// Errors if the daemon refuses the feature handshake.
        pub fn from_stream(
            stream: UnixStream,
            tag: &str,
            request_queues: usize,
            ram_fd: RawFd,
        ) -> io::Result<Self> {
            let queues = queue_count(request_queues);
            let frontend = Frontend::from_stream(stream, queues as u64);
            Self::over(frontend, tag, request_queues, ram_fd)
        }

        /// Runs the feature handshake and builds the device around
        /// `frontend`.
        fn over(
            mut frontend: Frontend,
            tag: &str,
            request_queues: usize,
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
            // one. MQ is the only one we need: SET_VRING_ENABLE is defined
            // only once it is in place, and virtio-fs always has a hiprio
            // queue beside its request queues.
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
                protocol_features,
                protocol_features_offered,
                dev_feat_sel: 0,
                drv_feat_sel: 0,
                queue_sel: 0,
                status: 0,
                interrupt_status: 0,
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
                calls: self.call.iter().map(AsRawFd::as_raw_fd).collect(),
            }
        }

        /// Records that the daemon has used buffers, so the guest's next read
        /// of `INTERRUPT_STATUS` sees a used-buffer notification.
        pub fn signal_used(&mut self) {
            self.interrupt_status |= 1;
        }

        /// Returns whether the device's interrupt line is asserted.
        #[must_use]
        pub fn irq_level(&self) -> bool {
            self.interrupt_status != 0
        }

        /// Services one virtio-mmio register access and returns the value a
        /// read takes.
        pub fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
            let v = value as u32;
            if is_write {
                self.write_reg(mem, offset, v);
                0
            } else {
                self.read_reg(offset)
            }
        }

        fn write_reg(&mut self, mem: &GuestRam, offset: u64, v: u32) {
            match offset {
                reg::DEVICE_FEATURES_SEL => self.dev_feat_sel = v,
                reg::DRIVER_FEATURES_SEL => self.drv_feat_sel = v,
                reg::DRIVER_FEATURES => {
                    self.acked_features = ack_features(
                        self.acked_features,
                        v,
                        self.drv_feat_sel,
                        self.device_features,
                    );
                }
                reg::QUEUE_SEL => self.queue_sel = v,
                reg::QUEUE_NUM => self.ring_mut(|r| r.size = v as u16),
                reg::QUEUE_READY => self.ring_mut(|r| r.ready = v & 1 != 0),
                reg::QUEUE_NOTIFY => self.kick_queue(v as usize),
                reg::INTERRUPT_ACK => self.interrupt_status &= !v,
                reg::STATUS if v == 0 => self.reset(),
                reg::STATUS => {
                    self.status = v;
                    if v & STATUS_DRIVER_OK != 0 && !self.handover_attempted {
                        self.start(mem);
                    }
                }
                reg::QUEUE_DESC_LOW => self.ring_mut(|r| r.desc = set_lo(r.desc, v)),
                reg::QUEUE_DESC_HIGH => self.ring_mut(|r| r.desc = set_hi(r.desc, v)),
                reg::QUEUE_DRIVER_LOW => self.ring_mut(|r| r.avail = set_lo(r.avail, v)),
                reg::QUEUE_DRIVER_HIGH => self.ring_mut(|r| r.avail = set_hi(r.avail, v)),
                reg::QUEUE_DEVICE_LOW => self.ring_mut(|r| r.used = set_lo(r.used, v)),
                reg::QUEUE_DEVICE_HIGH => self.ring_mut(|r| r.used = set_hi(r.used, v)),
                _ => {}
            }
        }

        fn read_reg(&self, offset: u64) -> u64 {
            match offset {
                reg::MAGIC => MAGIC_VALUE,
                reg::VERSION => 2,
                reg::DEVICE_ID => VIRTIO_FS_ID,
                reg::VENDOR_ID => VENDOR,
                reg::DEVICE_FEATURES => {
                    let shift = 32 * u64::from(self.dev_feat_sel & 1);
                    (self.device_features >> shift) & 0xffff_ffff
                }
                reg::QUEUE_NUM_MAX => u64::from(MAX_QUEUE_SIZE),
                reg::QUEUE_READY => u64::from(self.ring().is_some_and(|r| r.ready)),
                // A length of all-ones is how a device says it has no shared
                // memory region. Answering zero instead describes a region of
                // no length at address zero, and the guest's virtio-fs driver
                // then fails to reserve it and gives up on the device with
                // EBUSY. This device has no DAX window.
                SHM_LEN_LOW | SHM_LEN_HIGH => 0xffff_ffff,
                reg::INTERRUPT_STATUS => u64::from(self.interrupt_status),
                reg::STATUS => u64::from(self.status),
                _ if offset >= reg::CONFIG => {
                    let field = (offset - reg::CONFIG) as usize;
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
            let mq = self
                .protocol_features
                .contains(VhostUserProtocolFeatures::MQ);
            for index in 0..self.rings.len() {
                if self.peer.broken {
                    return;
                }
                if !self.rings[index].handed_over {
                    continue;
                }
                if mq {
                    let off = self
                        .peer
                        .send("SET_VRING_ENABLE off", |f| f.set_vring_enable(index, false));
                    if let Err(e) = off {
                        eprintln!("[hvi] virtio-fs {}: {e}", self.tag);
                    }
                }
                if let Err(e) = self
                    .peer
                    .send("GET_VRING_BASE", |f| f.get_vring_base(index))
                {
                    eprintln!("[hvi] virtio-fs {}: {e}", self.tag);
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
                eprintln!("[hvi] virtio-fs {}: {e}", self.tag);
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
                let Some((desc_len, avail_len, used_len)) = ring_extents(ring.size) else {
                    eprintln!(
                        "[hvi] virtio-fs {}: queue {index} has size {}, which is not a \
                         queue size; leaving it disabled",
                        self.tag, ring.size
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
                        eprintln!(
                            "[hvi] virtio-fs {}: queue {index} is programmed outside guest \
                             RAM; leaving it disabled",
                            self.tag
                        );
                        continue;
                    }
                };
                let config = VringConfigData {
                    queue_max_size: MAX_QUEUE_SIZE as u16,
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

            // SET_VRING_ENABLE is defined only under the MQ protocol feature.
            // A daemon without it starts serving on SET_VRING_KICK.
            if self
                .protocol_features
                .contains(VhostUserProtocolFeatures::MQ)
            {
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

    /// Services one register access on `dev`, sets its interrupt line through
    /// `set_line` under the same lock, and returns the value a read takes.
    ///
    /// [`serve_interrupts`] raises the same line under the same lock, so the
    /// level applied last is the device's current one.
    pub fn serve_mmio(
        dev: &Mutex<VhostUserFs>,
        mem: &GuestRam,
        offset: u64,
        is_write: bool,
        value: u64,
        set_line: impl FnOnce(bool),
    ) -> u64 {
        let mut d = dev.lock().expect("a live device");
        let v = d.mmio(mem, offset, is_write, value);
        set_line(d.irq_level());
        v
    }

    /// Raises the guest's interrupt for `dev` as the daemon signals it, one
    /// thread per queue.
    ///
    /// The daemon walks the rings in its own process, so the only thing left
    /// for this side is delivery: a call descriptor says buffers were used,
    /// and the guest learns it from the device's interrupt status. `raise` is
    /// how the backend asserts the line, which is the only part of this that
    /// differs between them. It runs with the device locked, for the reason
    /// [`serve_mmio`] gives.
    ///
    /// Each thread runs until `running` clears, which it notices when
    /// something completes its read; [`ShutdownFds::shutdown`] is what a
    /// shutdown uses to do that.
    pub fn serve_interrupts(
        dev: &Arc<Mutex<VhostUserFs>>,
        running: &Arc<AtomicBool>,
        raise: impl Fn(bool) + Send + Clone + 'static,
    ) {
        let calls = match dev.lock().expect("a live device").call_fds() {
            Ok(calls) => calls,
            Err(e) => {
                eprintln!("[hvi] virtio-fs: queue interrupts unavailable: {e}");
                return;
            }
        };
        for call in calls {
            let dev = Arc::clone(dev);
            let running = Arc::clone(running);
            let raise = raise.clone();
            std::thread::spawn(move || {
                crate::seccomp::install_thread(crate::seccomp::Thread::Vmm);
                while running.load(Ordering::SeqCst) {
                    if call.read().is_err() {
                        break;
                    }
                    let mut d = dev.lock().expect("a live device");
                    d.signal_used();
                    raise(d.irq_level());
                }
            });
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

    /// Builds one export per share and returns the daemons started for them
    /// beside the exports.
    ///
    /// `place` returns the window base and the interrupt of export `index`,
    /// or an error when the machine has none left. A share with a socket is
    /// attached to the daemon already listening there. Every other share gets
    /// a daemon of its own, found through `virtiofsd` and started here, before
    /// the seccomp filters go in. `log` is the backend's log prefix.
    ///
    /// Bind the result as `(daemons, exports)`. The exports are then dropped
    /// first, which closes their connections, so each daemon's `Drop` reaps a
    /// process that has already been told to exit.
    ///
    /// # Errors
    ///
    /// Errors if `place` does, if no daemon can be found or started, or if a
    /// daemon refuses the vhost-user handshake.
    pub fn attach(
        shares: &[FsShare],
        virtiofsd: Option<&Path>,
        ram_fd: RawFd,
        log: &str,
        mut place: impl FnMut(usize) -> io::Result<(u64, u32)>,
    ) -> io::Result<(Vec<Daemon>, Vec<Export>)> {
        let mut daemons = Vec::with_capacity(shares.len());
        let mut exports = Vec::with_capacity(shares.len());
        for (index, share) in shares.iter().enumerate() {
            let (base, irq) = place(index)?;
            let access = if share.mode.writable() {
                "read-write"
            } else {
                "read-only"
            };
            let dev = match &share.socket {
                // The directory is the daemon's own --shared-dir, which hvi
                // never sees, so the line names the socket alone.
                Some(socket) => {
                    eprintln!(
                        "[{log}] virtio-fs[{index}]: {:?} ({access}) on {}",
                        share.tag,
                        socket.display()
                    );
                    crate::virtiofsd::warn_foreign_readonly(share);
                    VhostUserFs::connect(socket, &share.tag, REQUEST_QUEUES, ram_fd)?
                }
                None => {
                    let binary = crate::virtiofsd::find(virtiofsd)?;
                    let (daemon, stream) = crate::virtiofsd::spawn(&binary, share, index)?;
                    eprintln!(
                        "[{log}] virtio-fs[{index}]: {} as {:?} ({access}) via {} pid {}",
                        share.path.display(),
                        share.tag,
                        binary.display(),
                        daemon.pid()
                    );
                    daemons.push(daemon);
                    VhostUserFs::from_stream(stream, &share.tag, REQUEST_QUEUES, ram_fd)?
                }
            };
            exports.push(Export {
                base,
                irq,
                stop: dev.shutdown_fds(),
                dev: Arc::new(Mutex::new(dev)),
            });
        }
        Ok((daemons, exports))
    }

    /// Returns the export whose window of `size` bytes holds `addr`, or `None`
    /// when no export's window does.
    #[must_use]
    pub fn export_at(exports: &[Export], addr: u64, size: u64) -> Option<&Export> {
        exports
            .iter()
            .find(|export| (export.base..export.base + size).contains(&addr))
    }

    /// Starts the interrupt threads of every export, with `raise` setting the
    /// line of the export whose interrupt it is given.
    ///
    /// The threads are [`serve_interrupts`]'s, and nothing joins them. Each
    /// blocks in a read only its daemon completes, and [`shut_down`] ends the
    /// connection that frees it.
    pub fn serve_all_interrupts(
        exports: &[Export],
        running: &Arc<AtomicBool>,
        raise: impl Fn(u32, bool) + Send + Clone + 'static,
    ) {
        for export in exports {
            let raise = raise.clone();
            let irq = export.irq;
            serve_interrupts(&export.dev, running, move |level| raise(irq, level));
        }
    }

    /// Ends the daemon connection of every export.
    ///
    /// Ending a connection is what lets its daemon exit, what frees a
    /// vhost-user read that is still waiting on it, and what wakes the
    /// interrupt threads, which are blocked in a read only the daemon
    /// completes. None of it takes the device lock, which a handover waiting
    /// on an unresponsive daemon would be holding.
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

    fn set_lo(current: u64, v: u32) -> u64 {
        (current & 0xffff_ffff_0000_0000) | u64::from(v)
    }

    fn set_hi(current: u64, v: u32) -> u64 {
        (current & 0xffff_ffff) | (u64::from(v) << 32)
    }

    #[cfg(test)]
    mod tests {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{mpsc, Arc, Mutex};
        use std::thread::JoinHandle;
        use std::time::Duration;

        use vhost::vhost_user::message::{
            FrontendReq, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
        };

        use super::{serve_interrupts, serve_mmio, set_hi, set_lo, VhostUserFs};
        use crate::guestmem::{GuestRam, MemRegion};
        use crate::sharedmem::SharedRam;
        use crate::virtio::reg;

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
                let (ours, theirs) = UnixStream::pair().expect("socket pair");
                let thread = std::thread::spawn(move || serve(theirs, vring_base));
                (Self(thread), ours)
            }

            /// Returns the requests the stand-in read, once the frontend's end
            /// has closed.
            fn requests(self) -> Vec<FrontendReq> {
                self.0.join().expect("the stand-in daemon")
            }
        }

        /// Reads requests from `socket` until it closes, answers them as a
        /// daemon that offers `VERSION_1` and the MQ protocol feature, and
        /// returns them.
        fn serve(mut socket: UnixStream, vring_base: VringBase) -> Vec<FrontendReq> {
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
                        let offered = VhostUserProtocolFeatures::MQ.bits();
                        Some((request, offered.to_le_bytes().to_vec()))
                    }
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
            let ram = SharedRam::new(MemRegion::ALIGN as usize).expect("allocate");
            let mem = GuestRam::new(&ram, &[ram.region_at(BASE)]).expect("map");
            (ram, mem)
        }

        /// Programs queue `index` with a ring of 8 descriptors at `at`, as a
        /// driver does before it writes `DRIVER_OK`.
        fn program_queue(dev: &mut VhostUserFs, mem: &GuestRam, index: u64, at: u64) {
            for (offset, value) in [
                (reg::QUEUE_SEL, index),
                (reg::QUEUE_NUM, 8),
                (reg::QUEUE_DESC_LOW, at),
                (reg::QUEUE_DRIVER_LOW, at + 0x100),
                (reg::QUEUE_DEVICE_LOW, at + 0x200),
                (reg::QUEUE_READY, 1),
            ] {
                dev.mmio(mem, offset, true, value);
            }
        }

        #[test]
        fn a_ring_address_is_assembled_from_two_writes() {
            let addr = set_hi(set_lo(0, 0x1000_2000), 0xff);
            assert_eq!(addr, 0x0000_00ff_1000_2000);
            assert_eq!(set_lo(addr, 0), 0x0000_00ff_0000_0000);
        }

        // A reply to another request leaves the frontend unable to say which
        // message the daemon is answering.
        #[test]
        fn a_connection_that_failed_is_sent_nothing_more() {
            let (daemon, stream) = Daemon::spawn(VringBase::WrongReplyFirst);
            let (ram, mem) = guest_ram();
            let mut dev = VhostUserFs::from_stream(stream, "t", 1, ram.fd()).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            program_queue(&mut dev, &mem, 1, BASE + 0x1000);
            dev.mmio(&mem, reg::STATUS, true, STATUS_LIVE);
            // The reset reads the wrong reply to queue 0's GET_VRING_BASE.
            dev.mmio(&mem, reg::STATUS, true, 0);
            program_queue(&mut dev, &mem, 0, BASE);
            dev.mmio(&mem, reg::STATUS, true, STATUS_LIVE);
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
        fn a_failed_handover_is_not_run_again_before_a_reset() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (_ram, mem) = guest_ram();
            let mut dev = VhostUserFs::from_stream(stream, "t", 1, -1).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            dev.mmio(&mem, reg::STATUS, true, STATUS_LIVE);
            dev.mmio(&mem, reg::STATUS, true, STATUS_LIVE | 0x80);
            dev.mmio(&mem, reg::STATUS, true, 0);
            drop(dev);

            assert_eq!(
                daemon.requests(),
                [
                    FrontendReq::SET_OWNER,
                    FrontendReq::GET_FEATURES,
                    FrontendReq::GET_PROTOCOL_FEATURES,
                    FrontendReq::SET_PROTOCOL_FEATURES,
                    FrontendReq::SET_FEATURES,
                ]
            );
        }

        #[test]
        fn a_shutdown_frees_a_reset_waiting_on_a_silent_daemon() {
            let (daemon, stream) = Daemon::spawn(VringBase::Silent);
            let (ram, mem) = guest_ram();
            let mut dev = VhostUserFs::from_stream(stream, "t", 1, ram.fd()).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            dev.mmio(&mem, reg::STATUS, true, STATUS_LIVE);
            let stop = dev.shutdown_fds();

            let (tx, rx) = mpsc::channel();
            let resetting = std::thread::spawn(move || {
                dev.mmio(&mem, reg::STATUS, true, 0);
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

        #[test]
        fn a_register_access_sets_the_line_under_the_device_lock() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (ram, mem) = guest_ram();
            let dev =
                Mutex::new(VhostUserFs::from_stream(stream, "t", 1, ram.fd()).expect("handshake"));
            let mut locked = None;
            serve_mmio(&dev, &mem, reg::INTERRUPT_STATUS, false, 0, |_| {
                locked = Some(dev.try_lock().is_err());
            });
            assert_eq!(
                locked,
                Some(true),
                "the line was set after the lock was released"
            );
            drop(dev);
            daemon.requests();
        }

        #[test]
        fn a_used_buffer_raises_the_line_under_the_device_lock() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (ram, _mem) = guest_ram();
            let dev = Arc::new(Mutex::new(
                VhostUserFs::from_stream(stream, "t", 1, ram.fd()).expect("handshake"),
            ));
            let running = Arc::new(AtomicBool::new(true));
            let (tx, rx) = mpsc::channel();
            let probe = Arc::clone(&dev);
            serve_interrupts(&dev, &running, move |level| {
                let _ = tx.send((level, probe.try_lock().is_err()));
            });

            let call = dev
                .lock()
                .expect("the device")
                .call_fd(0)
                .expect("queue 0")
                .expect("a call descriptor");
            call.write(1).expect("signal a used buffer");
            let (level, locked) = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the line was raised");
            assert!(level, "a used buffer left the line low");
            assert!(locked, "the line was raised after the lock was released");

            running.store(false, Ordering::SeqCst);
            let stop = dev.lock().expect("the device").shutdown_fds();
            stop.shutdown();
            daemon.requests();
        }

        #[test]
        fn a_reset_takes_back_a_ring_the_guest_cleared_after_driver_ok() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (ram, mem) = guest_ram();
            let mut dev = VhostUserFs::from_stream(stream, "t", 1, ram.fd()).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            program_queue(&mut dev, &mem, 1, BASE + 0x1000);
            dev.mmio(&mem, reg::STATUS, true, STATUS_LIVE);
            dev.mmio(&mem, reg::QUEUE_SEL, true, 1);
            dev.mmio(&mem, reg::QUEUE_READY, true, 0);
            dev.mmio(&mem, reg::STATUS, true, 0);
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
        fn a_refused_ring_is_neither_enabled_nor_taken_back() {
            let (daemon, stream) = Daemon::spawn(VringBase::Answer);
            let (ram, mem) = guest_ram();
            let mut dev = VhostUserFs::from_stream(stream, "t", 1, ram.fd()).expect("handshake");
            program_queue(&mut dev, &mem, 0, BASE);
            program_queue(&mut dev, &mem, 1, BASE + 0x20_0000);
            dev.mmio(&mem, reg::STATUS, true, STATUS_LIVE);
            dev.mmio(&mem, reg::STATUS, true, 0);
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
    fn an_overlong_tag_is_truncated() {
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
    fn an_unoffered_feature_bit_is_not_acked() {
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
    fn a_ring_size_that_is_not_a_queue_size_has_no_extents() {
        assert_eq!(ring_extents(0), None);
        assert_eq!(ring_extents(3), None);
        assert_eq!(ring_extents(2048), None);
    }

    #[test]
    fn ring_extents_cover_the_whole_split_virtqueue() {
        assert_eq!(ring_extents(1), Some((16, 8, 14)));
        assert_eq!(ring_extents(256), Some((4096, 518, 2054)));
        let (desc, avail, used) = ring_extents(MAX_QUEUE_SIZE as u16).expect("a queue size");
        assert_eq!(desc, 16 * 1024);
        assert_eq!(avail, 6 + 2 * 1024);
        assert_eq!(used, 6 + 8 * 1024);
    }

    #[test]
    fn version_1_is_offered() {
        assert_ne!(TRANSPORT_FEATURES & (1 << 32), 0);
    }
}

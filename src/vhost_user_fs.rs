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

#[cfg(target_os = "linux")]
pub use self::device::{serve_interrupts, ShutdownFds, VhostUserFs};

#[cfg(target_os = "linux")]
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

    use crate::guestmem::GuestRam;
    use crate::virtio::reg;

    use super::TRANSPORT_FEATURES;
    use super::{ack_features, config_space, queue_count, ring_extents, MAX_QUEUE_SIZE};

    const MAGIC_VALUE: u64 = 0x7472_6976; // "virt"
    const VENDOR: u64 = 0x4649_4f4e; // "NOIF"
    const VIRTIO_FS_ID: u64 = virtio_bindings::virtio_ids::VIRTIO_ID_FS as u64;

    /// Shared-memory region registers, from `linux/virtio_mmio.h`.
    ///
    /// They are not in the `virtio-bindings` version this crate pins, so the
    /// offsets are written out here.
    const SHM_LEN_LOW: u64 = 0x0b0;
    const SHM_LEN_HIGH: u64 = 0x0b4;

    /// How long a vhost-user message waits for the daemon.
    ///
    /// The handover runs on the vCPU thread servicing the guest's `DRIVER_OK`
    /// write, with the device locked, so a peer that accepts the connection
    /// and then stops answering would hold that vCPU and every shutdown path
    /// that needs the same lock. A deadline turns that into a failed handover
    /// and a device the guest sees as unresponsive, which is recoverable.
    const PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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

    /// One virtio-fs device, holding the guest's virtio-mmio transport and the
    /// vhost-user connection to the daemon that serves it.
    pub struct VhostUserFs {
        tag: String,
        frontend: Frontend,
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
        started: bool,
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
            stream.set_read_timeout(Some(PEER_TIMEOUT))?;
            stream.set_write_timeout(Some(PEER_TIMEOUT))?;
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
                frontend,
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
                started: false,
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
                connection: self.frontend.as_raw_fd(),
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

        /// Returns the events captured since the last call, which for this
        /// device is always none.
        ///
        /// The daemon serves the guest's file requests in its own process, so
        /// nothing here observes them.
        pub fn take_events(&mut self) -> Vec<crate::events::CapturedEvent> {
            Vec::new()
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
                    if v & STATUS_DRIVER_OK != 0 && !self.started {
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
            // Not gated on `started`: a handover that failed partway has
            // already kicked the queues it got through, and that is the case
            // where the daemon is most likely to be left holding a ring.
            // `stop_rings` skips what was never ready and tolerates errors.
            self.stop_rings();
            for ring in &mut self.rings {
                *ring = Ring::default();
            }
            self.interrupt_status = 0;
            self.status = 0;
            self.acked_features = 0;
            self.dev_feat_sel = 0;
            self.drv_feat_sel = 0;
            self.started = false;
        }

        /// Takes every ring back from the daemon.
        ///
        /// `SET_VRING_ENABLE(false)` stops it serving, and `GET_VRING_BASE` is
        /// what the protocol defines as the point the backend stops using a
        /// ring. Both are best-effort: a reset carries on whatever the daemon
        /// answers, because the alternative is a device the guest cannot
        /// re-initialize.
        fn stop_rings(&mut self) {
            let mq = self
                .protocol_features
                .contains(VhostUserProtocolFeatures::MQ);
            for index in 0..self.rings.len() {
                if !self.rings[index].ready {
                    continue;
                }
                if mq {
                    if let Err(e) = self.frontend.set_vring_enable(index, false) {
                        eprintln!("[hvi] virtio-fs {}: SET_VRING_ENABLE off: {e}", self.tag);
                    }
                }
                if let Err(e) = self.frontend.get_vring_base(index) {
                    eprintln!("[hvi] virtio-fs {}: GET_VRING_BASE: {e}", self.tag);
                }
            }
        }

        /// Hands the programmed rings and guest RAM to the daemon.
        ///
        /// A failure here leaves the device without a backend, so the mount
        /// the guest is about to attempt fails. The boot continues: an export
        /// that cannot be served is not a reason to take the guest down.
        fn start(&mut self, mem: &GuestRam) {
            if let Err(e) = self.hand_over(mem) {
                eprintln!("[hvi] virtio-fs {}: {e}", self.tag);
                return;
            }
            self.started = true;
        }

        fn hand_over(&mut self, mem: &GuestRam) -> io::Result<()> {
            let mut features = self.acked_features;
            if self.protocol_features_offered {
                features |= VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            }
            self.frontend
                .set_features(features)
                .map_err(|e| io::Error::other(format!("SET_FEATURES: {e}")))?;

            let regions = self.memory_table(mem)?;
            self.frontend
                .set_mem_table(&regions)
                .map_err(|e| io::Error::other(format!("SET_MEM_TABLE: {e}")))?;

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
                self.frontend
                    .set_vring_num(index, ring.size)
                    .map_err(|e| io::Error::other(format!("SET_VRING_NUM: {e}")))?;
                self.frontend
                    .set_vring_addr(index, &config)
                    .map_err(|e| io::Error::other(format!("SET_VRING_ADDR: {e}")))?;
                self.frontend
                    .set_vring_base(index, 0)
                    .map_err(|e| io::Error::other(format!("SET_VRING_BASE: {e}")))?;
                self.frontend
                    .set_vring_call(index, &self.call[index])
                    .map_err(|e| io::Error::other(format!("SET_VRING_CALL: {e}")))?;
                self.frontend
                    .set_vring_kick(index, &self.kick[index])
                    .map_err(|e| io::Error::other(format!("SET_VRING_KICK: {e}")))?;
            }

            // SET_VRING_ENABLE is defined only under the MQ protocol feature.
            // A daemon without it starts serving on SET_VRING_KICK.
            if self
                .protocol_features
                .contains(VhostUserProtocolFeatures::MQ)
            {
                for index in 0..self.rings.len() {
                    let ring = self.rings[index];
                    if !ring.ready || ring_extents(ring.size).is_none() {
                        continue;
                    }
                    self.frontend
                        .set_vring_enable(index, true)
                        .map_err(|e| io::Error::other(format!("SET_VRING_ENABLE: {e}")))?;
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

    /// Raises the guest's interrupt for `dev` as the daemon signals it, one
    /// thread per queue.
    ///
    /// The daemon walks the rings in its own process, so the only thing left
    /// for this side is delivery: a call descriptor says buffers were used,
    /// and the guest learns it from the device's interrupt status. `raise` is
    /// how the backend asserts the line, which is the only part of this that
    /// differs between them.
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
                    let level = {
                        let mut d = dev.lock().expect("a live device");
                        d.signal_used();
                        d.irq_level()
                    };
                    raise(level);
                }
            });
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
        use super::{set_hi, set_lo};

        #[test]
        fn a_ring_address_is_assembled_from_two_writes() {
            let addr = set_hi(set_lo(0, 0x1000_2000), 0xff);
            assert_eq!(addr, 0x0000_00ff_1000_2000);
            assert_eq!(set_lo(addr, 0), 0x0000_00ff_0000_0000);
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

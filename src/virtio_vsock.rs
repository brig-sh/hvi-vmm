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

//! virtio-vsock over virtio-mmio, bridged to a host Unix socket -- the
//! transport an `exec`-style command needs.
//!
//! The convention this implements: an in-guest agent serves sessions on guest
//! vsock port 1024, and a host-side caller dials a Unix socket that the VMM
//! bridges to that port. This device implements enough virtio-vsock (STREAM)
//! for that: a host `UnixListener` accepts connections, each becomes a vsock
//! stream the device opens to the guest (host CID 2 -> guest CID 3, port 1024),
//! and bytes relay both ways.
//!
//! The device never waits on a host socket, since it runs under the device
//! lock on a vCPU thread. Each session's socket is non-blocking. What the
//! socket does not take waits in the session's backlog for the session's
//! [`HostWriter`](crate::virtio_vsock::HostWriter). The `fwd_cnt` the device
//! advertises counts only the bytes a socket took, so a backlog never holds
//! more than `OUR_BUF_ALLOC`. A guest that sends past that credit has its
//! session reset.
//!
//! The device does not track the guest's own credit (#112). Host data is
//! buffered until the guest accepts the connection.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};

use crate::guestmem::GuestRam;
use crate::sync::lock_or_recover;
use crate::virtio::{reg, Queue, QUEUE_NUM_MAX, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

const VIRTIO_VSOCK_ID: u64 = virtio_bindings::virtio_ids::VIRTIO_ID_VSOCK as u64;
/// `VIRTIO_F_VERSION_1` is feature bit 32, so bit 0 of the high word.
const F_VERSION_1_HI: u32 = 1 << (virtio_bindings::virtio_config::VIRTIO_F_VERSION_1 - 32);

pub const HOST_CID: u64 = 2;
pub const GUEST_CID: u64 = 3;
pub const AGENT_PORT: u32 = 1024;

const RX_QUEUE: u16 = 0; // device -> guest
const TX_QUEUE: u16 = 1; // guest -> device
/// The event queue (index 2) exists in the config but we never post to it.
#[allow(dead_code)]
const EVENT_QUEUE: u16 = 2;

/// virtio_vsock_hdr, 44 bytes, little-endian.
const HDR_LEN: usize = 44;
const TYPE_STREAM: u16 = 1;
const OP_REQUEST: u16 = 1;
const OP_RESPONSE: u16 = 2;
const OP_RST: u16 = 3;
const OP_SHUTDOWN: u16 = 4;
const OP_RW: u16 = 5;
const OP_CREDIT_UPDATE: u16 = 6;
const OP_CREDIT_REQUEST: u16 = 7;

/// Device to guest: the credit we advertise, so the most guest data one session
/// may hold before its host socket takes it.
///
/// It bounds each session's backlog. A guest that sends past it has the
/// session reset.
const OUR_BUF_ALLOC: u32 = 256 * 1024;
/// Device to guest: how many forwarded bytes the device lets build up before it
/// sends a credit update, unless the backlog empties first.
///
/// This is `VIRTIO_VSOCK_MAX_PKT_BUF_SIZE`, the most a Linux guest sends in one
/// packet. A guest that ran out of credit hears back once a whole packet fits
/// again.
const CREDIT_UPDATE_STEP: u32 = 64 * 1024;
/// Host side: the most one [`HostWriter`] write takes from the backlog.
const WRITE_CHUNK: usize = 64 * 1024;
/// Device to guest: the most payload we frame into one RW packet before
/// handing it to `fill_rx`.
///
/// This is `VIRTIO_VSOCK_DEFAULT_RX_BUF_SIZE`, the payload a Linux guest's
/// receive buffer holds, so a packet framed here lands in one of them whole.
/// `fill_rx` still splits, because a guest is free to post something smaller
/// and pre-6.4 guests split the header off into its own descriptor, but it is
/// the fallback rather than the rule.
const MAX_RW: usize = 4096;
/// Guest to device: ceiling on the packet a transmit chain may assemble.
///
/// Descriptor lengths are guest-controlled, so without a ceiling the guest
/// decides how much the host allocates and zeroes for one packet.
///
/// The bound is the guest's own per-packet limit, which Linux spells
/// `VIRTIO_VSOCK_MAX_PKT_BUF_SIZE`, and not one of the two constants above:
/// those govern what this device sends, and a ceiling taken from either of
/// them would reject ordinary traffic.
/// A guest with credit to spare legitimately sends 64 KiB at a time, and
/// `process_tx` completes a descriptor whether or not `read_tx` returned a
/// packet, so a packet refused here would look to the guest like a write that
/// succeeded.
const MAX_TX_PACKET: usize = HDR_LEN + 64 * 1024;

#[derive(Clone, Copy, Default)]
struct Hdr {
    src_cid: u64,
    dst_cid: u64,
    src_port: u32,
    dst_port: u32,
    len: u32,
    typ: u16,
    op: u16,
    flags: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
}

impl Hdr {
    fn parse(b: &[u8]) -> Option<Hdr> {
        if b.len() < HDR_LEN {
            return None;
        }
        let u64a = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u32a = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u16a = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
        Some(Hdr {
            src_cid: u64a(0),
            dst_cid: u64a(8),
            src_port: u32a(16),
            dst_port: u32a(20),
            len: u32a(24),
            typ: u16a(28),
            op: u16a(30),
            flags: u32a(32),
            buf_alloc: u32a(36),
            fwd_cnt: u32a(40),
        })
    }
    fn to_bytes(self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..30].copy_from_slice(&self.typ.to_le_bytes());
        b[30..32].copy_from_slice(&self.op.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }
}

/// Where a session is in the handshake we drove.
///
/// A real vsock stack demultiplexes by port and tracks connection state in the
/// kernel; this device is the whole stack, so it has to do that itself. The
/// guest may only advance a session we actually offered it, and only in order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ConnState {
    /// Registered by the host bridge; the guest has not been told about it.
    New,
    /// We sent `OP_REQUEST`; waiting for the guest's `OP_RESPONSE`.
    Offered,
    /// The guest accepted. Bytes may flow.
    Connected,
}

/// One exec session: a host Unix stream mapped to a guest vsock stream.
struct Conn {
    /// The host socket and the guest bytes it has not taken yet.
    host: Arc<HostSide>,
    state: ConnState,
    /// Bytes received from the guest.
    rx_cnt: u32,
    /// Bytes the host socket took, which is the `fwd_cnt` the device
    /// advertises.
    fwd_cnt: u32,
    /// The `fwd_cnt` in the last header queued for the guest.
    fwd_told: u32,
    pending_out: Vec<u8>, // host bytes buffered until the guest accepts
}

/// The host end of one session, shared by the device and the session's
/// [`HostWriter`].
struct HostSide {
    /// The host socket. The session's reader thread reads a clone of it, so
    /// ending a session takes `shutdown`. A drop alone leaves the clone and the
    /// peer open.
    stream: UnixStream,
    /// The guest bytes the socket has not taken yet.
    backlog: Mutex<Backlog>,
    /// Signaled when bytes are queued or the session ends.
    wake: Condvar,
}

/// Guest -> host bytes that wait for the host socket.
#[derive(Default)]
struct Backlog {
    /// The bytes, in order. The credit check in `guest_data` keeps them within
    /// [`OUR_BUF_ALLOC`].
    bytes: VecDeque<u8>,
    /// Set once the device lets go of the session.
    end: Option<End>,
}

/// What is left to do for a session the device has let go of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum End {
    /// Bytes are still queued. The writer sends them, then shuts the socket
    /// down.
    Flush,
    /// The socket is shut down and nothing is queued.
    Closed,
}

impl HostSide {
    /// Writes `data` to the host socket without blocking, queues what the
    /// socket does not take, and returns the number of bytes it took.
    ///
    /// The bytes go straight to the socket only when nothing is queued, so
    /// they never overtake queued ones. A write that fails for good means the
    /// socket has no reader left, so the bytes are dropped and count as taken.
    fn send(&self, data: &[u8]) -> usize {
        let mut backlog = lock_or_recover(&self.backlog);
        let took = if backlog.bytes.is_empty() {
            match (&self.stream).write(data) {
                Ok(n) => n,
                Err(e) if is_transient(&e) => 0,
                Err(_) => data.len(),
            }
        } else {
            0
        };
        if took < data.len() {
            backlog.bytes.extend(&data[took..]);
            self.wake.notify_one();
        }
        took
    }

    /// Ends the host side of a session the device has let go of.
    ///
    /// With `flush` set and bytes still queued, the writer sends them and then
    /// shuts the socket down. Otherwise the queue is dropped and the socket is
    /// shut down here.
    fn end(&self, flush: bool) {
        let mut backlog = lock_or_recover(&self.backlog);
        let end = if flush && !backlog.bytes.is_empty() {
            End::Flush
        } else {
            backlog.bytes.clear();
            End::Closed
        };
        backlog.end = Some(end);
        drop(backlog);
        self.wake.notify_one();
        if end == End::Closed {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
    }
}

/// Moves one session's backlog to its host socket.
///
/// [`VirtioVsock::add_conn`] returns it. The backend runs it on a thread of its
/// own beside the session's reader.
pub struct HostWriter(Arc<HostSide>);

#[cfg(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
))]
impl HostWriter {
    /// Writes the session's backlog to the host socket until the session ends
    /// or the stop is requested.
    ///
    /// It waits for the socket to take bytes beside the stop token, so a host
    /// peer that stops reading holds up this thread and no other. `took` gets
    /// the count of every write the socket accepted, for the caller to pass to
    /// [`VirtioVsock::host_took`] under the device lock. Once the device lets
    /// go of the session, the writer sends what is still queued and shuts the
    /// socket down.
    pub fn run(&self, stop: &crate::teardown::StopToken, mut took: impl FnMut(u32)) {
        use std::os::fd::AsFd;
        use std::sync::PoisonError;
        let host = &*self.0;
        let mut chunk = vec![0u8; WRITE_CHUNK];
        loop {
            let n = {
                let mut backlog = lock_or_recover(&host.backlog);
                while backlog.bytes.is_empty() && backlog.end.is_none() {
                    backlog = host
                        .wake
                        .wait(backlog)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                if backlog.bytes.is_empty() {
                    if backlog.end == Some(End::Flush) {
                        let _ = host.stream.shutdown(Shutdown::Both);
                    }
                    return;
                }
                let n = backlog.bytes.len().min(chunk.len());
                for (to, from) in chunk.iter_mut().zip(&backlog.bytes) {
                    *to = *from;
                }
                n
            };
            match stop.wait_writable(host.stream.as_fd()) {
                Ok(true) => {}
                Ok(false) => return,
                Err(e) => {
                    eprintln!("[hvi] vsock bridge: {e}; no longer writing to the host");
                    return;
                }
            }
            let sent = match (&host.stream).write(&chunk[..n]) {
                Ok(sent) => sent,
                Err(e) if is_transient(&e) => continue,
                // As in `HostSide::send`, the socket has no reader left.
                Err(_) => n,
            };
            // A session that ended during the write may have cleared the queue
            // already.
            let mut backlog = lock_or_recover(&host.backlog);
            let queued = backlog.bytes.len();
            backlog.bytes.drain(..sent.min(queued));
            drop(backlog);
            took(sent as u32);
        }
    }
}

/// Returns whether a write that failed with `e` may succeed later.
fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// A virtio-vsock device bridged to a host Unix socket.
pub struct VirtioVsock {
    status: u32,
    dev_feat_sel: u32,
    queue_sel: u32,
    queues: [Queue; 3],
    interrupt_status: u32,
    /// host -> guest packets awaiting an RX buffer.
    pending: VecDeque<Vec<u8>>,
    /// active connections, keyed by host (local) port.
    conns: HashMap<u32, Conn>,
    next_port: u32,
    /// Whether a guest has already sent past its credit, so only the first
    /// reset is reported.
    overrun_reported: bool,
}

impl VirtioVsock {
    #[must_use]
    pub fn new() -> Self {
        VirtioVsock {
            status: 0,
            dev_feat_sel: 0,
            queue_sel: 0,
            queues: [Queue::default(), Queue::default(), Queue::default()],
            interrupt_status: 0,
            pending: VecDeque::new(),
            conns: HashMap::new(),
            next_port: 40000,
            overrun_reported: false,
        }
    }

    #[must_use]
    pub fn irq_level(&self) -> bool {
        self.interrupt_status != 0
    }

    fn queue(&mut self) -> &mut Queue {
        &mut self.queues[(self.queue_sel % 3) as usize]
    }

    /// Resets the device, as a write of 0 to STATUS requests.
    ///
    /// Every session is dropped with the queues, since the guest agent that
    /// initializes the device again has never seen their `OP_REQUEST`.
    fn reset(&mut self) {
        for queue in &mut self.queues {
            queue.reset();
        }
        self.interrupt_status = 0;
        self.status = 0;
        self.dev_feat_sel = 0;
        self.queue_sel = 0;
        self.pending.clear();
        for (_, conn) in self.conns.drain() {
            conn.host.end(false);
        }
    }

    /// Registers a new host connection and returns its assigned local port and
    /// the writer that moves the guest's bytes to it.
    ///
    /// The socket goes into non-blocking mode, which its clones share, so no
    /// write the device makes under its lock waits on the host peer.
    ///
    /// # Errors
    ///
    /// Errors when the socket cannot be made non-blocking.
    pub fn add_conn(&mut self, stream: UnixStream) -> io::Result<(u32, HostWriter)> {
        stream.set_nonblocking(true)?;
        let port = self.next_port;
        self.next_port += 1;
        let host = Arc::new(HostSide {
            stream,
            backlog: Mutex::default(),
            wake: Condvar::new(),
        });
        self.conns.insert(
            port,
            Conn {
                host: Arc::clone(&host),
                state: ConnState::New,
                rx_cnt: 0,
                fwd_cnt: 0,
                fwd_told: 0,
                pending_out: Vec::new(),
            },
        );
        Ok((port, HostWriter(host)))
    }

    /// Queues a connection REQUEST to the guest agent and delivers it.
    pub fn connect(&mut self, mem: &GuestRam, host_port: u32) {
        match self.conns.get_mut(&host_port) {
            Some(conn) => conn.state = ConnState::Offered,
            None => return, // nothing to offer
        }
        let hdr = Hdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: host_port,
            dst_port: AGENT_PORT,
            typ: TYPE_STREAM,
            op: OP_REQUEST,
            buf_alloc: OUR_BUF_ALLOC,
            ..Hdr::default()
        };
        self.pending.push_back(hdr.to_bytes().to_vec());
        self.fill_rx(mem);
    }

    /// Queues host bytes for the guest (buffered until the connection is up).
    pub fn host_data(&mut self, mem: &GuestRam, host_port: u32, data: &[u8]) {
        match self.conns.get_mut(&host_port) {
            Some(conn) if conn.state == ConnState::Connected => {}
            Some(conn) => {
                conn.pending_out.extend_from_slice(data);
                return;
            }
            None => return,
        }
        self.enqueue_rw(host_port, data);
        self.fill_rx(mem);
    }

    /// Records that the host socket of session `host_port` took `n` more of the
    /// guest's bytes, and sends a credit update when that frees enough.
    ///
    /// The update goes out once the backlog is empty, or once 64 KiB
    /// (`CREDIT_UPDATE_STEP`) have been forwarded since the guest last heard
    /// the count.
    pub fn host_took(&mut self, mem: &GuestRam, host_port: u32, n: u32) {
        let Some(conn) = self.conns.get_mut(&host_port) else {
            return;
        };
        conn.fwd_cnt = conn.fwd_cnt.wrapping_add(n);
        let untold = conn.fwd_cnt.wrapping_sub(conn.fwd_told);
        if untold > 0 && (conn.fwd_cnt == conn.rx_cnt || untold >= CREDIT_UPDATE_STEP) {
            self.enqueue_credit(host_port);
            self.fill_rx(mem);
        }
    }

    /// Signals the guest that the host end closed.
    ///
    /// The host peer may have closed only its sending half, so what the
    /// session's backlog holds is still written before the socket shuts down.
    pub fn host_closed(&mut self, mem: &GuestRam, host_port: u32) {
        if let Some(conn) = self.conns.remove(&host_port) {
            conn.host.end(true);
            let hdr = Hdr {
                src_cid: HOST_CID,
                dst_cid: GUEST_CID,
                src_port: host_port,
                dst_port: AGENT_PORT,
                typ: TYPE_STREAM,
                op: OP_SHUTDOWN,
                flags: 3, // both directions
                buf_alloc: OUR_BUF_ALLOC,
                ..Hdr::default()
            };
            self.pending.push_back(hdr.to_bytes().to_vec());
            self.fill_rx(mem);
        }
    }

    /// Returns the `fwd_cnt` to put in the next header for session `host_port`
    /// and records it as told, or `None` when there is no such session.
    fn tell_fwd_cnt(&mut self, host_port: u32) -> Option<u32> {
        let conn = self.conns.get_mut(&host_port)?;
        conn.fwd_told = conn.fwd_cnt;
        Some(conn.fwd_cnt)
    }

    /// Frames RW packet(s) for `data` into the pending queue.
    fn enqueue_rw(&mut self, host_port: u32, data: &[u8]) {
        let Some(fwd_cnt) = self.tell_fwd_cnt(host_port) else {
            return;
        };
        for chunk in data.chunks(MAX_RW) {
            let hdr = Hdr {
                src_cid: HOST_CID,
                dst_cid: GUEST_CID,
                src_port: host_port,
                dst_port: AGENT_PORT,
                len: chunk.len() as u32,
                typ: TYPE_STREAM,
                op: OP_RW,
                buf_alloc: OUR_BUF_ALLOC,
                fwd_cnt,
                ..Hdr::default()
            };
            let mut pkt = hdr.to_bytes().to_vec();
            pkt.extend_from_slice(chunk);
            self.pending.push_back(pkt);
        }
    }

    /// Services one MMIO access.
    pub fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        let v = value as u32;
        if is_write {
            match offset {
                reg::DEVICE_FEATURES_SEL => self.dev_feat_sel = v,
                reg::DRIVER_FEATURES_SEL | reg::DRIVER_FEATURES => {}
                reg::QUEUE_SEL => self.queue_sel = v,
                reg::QUEUE_NUM => self.queue().set_num(v),
                reg::QUEUE_READY => self.queue().set_ready(v, mem),
                reg::QUEUE_NOTIFY => match v as u16 {
                    TX_QUEUE => self.process_tx(mem),
                    RX_QUEUE => self.fill_rx(mem),
                    _ => {}
                },
                reg::INTERRUPT_ACK => self.interrupt_status &= !v,
                reg::STATUS if v == 0 => self.reset(),
                reg::STATUS => self.status = v,
                reg::QUEUE_DESC_LOW => self.queue().set_desc_lo(v),
                reg::QUEUE_DESC_HIGH => self.queue().set_desc_hi(v),
                reg::QUEUE_DRIVER_LOW => self.queue().set_avail_lo(v),
                reg::QUEUE_DRIVER_HIGH => self.queue().set_avail_hi(v),
                reg::QUEUE_DEVICE_LOW => self.queue().set_used_lo(v),
                reg::QUEUE_DEVICE_HIGH => self.queue().set_used_hi(v),
                _ => {}
            }
            0
        } else {
            match offset {
                reg::MAGIC => 0x7472_6976,
                reg::VERSION => 2,
                reg::DEVICE_ID => VIRTIO_VSOCK_ID,
                reg::VENDOR_ID => 0x4649_4f4e,
                reg::DEVICE_FEATURES if self.dev_feat_sel == 1 => u64::from(F_VERSION_1_HI),
                reg::QUEUE_NUM_MAX => u64::from(QUEUE_NUM_MAX),
                reg::QUEUE_READY => {
                    u64::from(self.queues[(self.queue_sel % 3) as usize].is_ready())
                }
                reg::INTERRUPT_STATUS => u64::from(self.interrupt_status),
                reg::STATUS => u64::from(self.status),
                // Config space: guest CID (u64) at offset 0.
                _ if offset >= reg::CONFIG => {
                    let f = (offset - reg::CONFIG) as usize;
                    let cid = GUEST_CID.to_le_bytes();
                    cid.get(f).map_or(0, |&b| u64::from(b))
                }
                _ => 0,
            }
        }
    }

    /// Drains the guest's transmit queue: connection responses, RW data
    /// (written to the host socket), credit, and shutdowns.
    fn process_tx(&mut self, mem: &GuestRam) {
        let tx = &self.queues[TX_QUEUE as usize];
        if !tx.is_ready() {
            return;
        }
        let Some(pending) = tx.pending(mem) else {
            return;
        };
        let mut last = tx.last_avail();
        for _ in 0..pending {
            let Some(slot) = self.queues[TX_QUEUE as usize].avail_slot(last) else {
                break;
            };
            let Ok(head) = mem.read_u16(slot) else {
                break;
            };
            if let Some(pkt) = self.read_tx(mem, head) {
                self.handle_pkt(mem, &pkt);
            }
            self.queues[TX_QUEUE as usize].push_used(mem, head, 0);
            last = last.wrapping_add(1);
            self.interrupt_status |= 1;
        }
        self.queues[TX_QUEUE as usize].set_last_avail(last);
    }

    /// Reads one packet (header + payload) from a TX descriptor chain.
    fn read_tx(&self, mem: &GuestRam, head: u16) -> Option<Vec<u8>> {
        let q = &self.queues[TX_QUEUE as usize];
        let mut buf = Vec::new();
        let mut d = head;
        for _ in 0..q.size() {
            let da = q.desc_addr(d)?;
            let (addr, len, flags, next) = (
                mem.read_u64(da).ok()?,
                mem.read_u32(da + 8).ok()?,
                mem.read_u16(da + 12).ok()?,
                mem.read_u16(da + 14).ok()?,
            );
            if flags & VIRTQ_DESC_F_WRITE == 0 {
                // The length comes from the guest, so it is checked against
                // the ceiling before it is allowed to size an allocation, and
                // the bytes are read straight into the packet rather than
                // through a segment buffer the guest also sized.
                let len = len as usize;
                let start = buf.len();
                if start.checked_add(len)? > MAX_TX_PACKET {
                    return None;
                }
                buf.resize(start + len, 0);
                mem.read(addr, &mut buf[start..]).ok()?;
            }
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            d = next;
        }
        (buf.len() >= HDR_LEN).then_some(buf)
    }

    /// Every packet we act on must be a stream packet the guest agent sent to
    /// us. The guest chooses all of these fields, so this is where a forged one
    /// is dropped rather than routed.
    fn addressed_to_us(h: &Hdr) -> bool {
        h.typ == TYPE_STREAM && h.dst_cid == HOST_CID && h.src_cid == GUEST_CID
    }

    /// Acts on one guest -> host packet.
    fn handle_pkt(&mut self, mem: &GuestRam, pkt: &[u8]) {
        let Some(h) = Hdr::parse(pkt) else {
            return;
        };
        if !Self::addressed_to_us(&h) {
            return;
        }
        // Everything below addresses an existing session, and the guest half of
        // one is always the agent: a packet claiming another source port is not
        // part of a session we opened.
        let port = h.dst_port; // our (host) local port
        if h.op != OP_REQUEST && h.src_port != AGENT_PORT {
            return;
        }
        match h.op {
            OP_RESPONSE => {
                // Only a session we actually offered may be accepted, and only
                // once. Otherwise the guest could mark any port connected and
                // then write to it.
                let queued = match self.conns.get_mut(&port) {
                    Some(c) if c.state == ConnState::Offered => {
                        c.state = ConnState::Connected;
                        Some(std::mem::take(&mut c.pending_out))
                    }
                    _ => None,
                };
                if let Some(data) = queued {
                    if !data.is_empty() {
                        self.enqueue_rw(port, &data);
                        self.fill_rx(mem);
                    }
                }
            }
            OP_RW => {
                let end = HDR_LEN + (h.len as usize).min(pkt.len() - HDR_LEN);
                self.guest_data(mem, port, &pkt[HDR_LEN..end]);
            }
            // Only a session the guest was offered may be torn down by it. The
            // guard is equivalent to testing inside the arm, since the fallback
            // arm does nothing. What the guest sent before it closed still
            // reaches the host.
            OP_SHUTDOWN | OP_RST
                if self
                    .conns
                    .get(&port)
                    .is_some_and(|c| c.state != ConnState::New) =>
            {
                if let Some(conn) = self.conns.remove(&port) {
                    conn.host.end(true);
                }
            }
            OP_REQUEST => {
                // Guest-initiated connect: not supported here — reset it.
                let hdr = Hdr {
                    src_cid: HOST_CID,
                    dst_cid: GUEST_CID,
                    src_port: h.dst_port,
                    dst_port: h.src_port,
                    typ: TYPE_STREAM,
                    op: OP_RST,
                    ..Hdr::default()
                };
                self.pending.push_back(hdr.to_bytes().to_vec());
                self.fill_rx(mem);
            }
            // Only answer for a live session, so credit updates cannot be used to
            // probe which host ports exist.
            OP_CREDIT_REQUEST
                if self
                    .conns
                    .get(&port)
                    .is_some_and(|c| c.state == ConnState::Connected) =>
            {
                self.enqueue_credit(port);
            }
            OP_CREDIT_UPDATE => {}
            _ => {}
        }
    }

    /// Relays guest bytes for session `port` to its host socket.
    ///
    /// Only a completed handshake may carry data. The write never blocks, and
    /// what the socket does not take waits in the session's backlog. A guest
    /// that sends past the credit it was given has the session reset, which
    /// keeps the backlog within [`OUR_BUF_ALLOC`].
    fn guest_data(&mut self, mem: &GuestRam, port: u32, data: &[u8]) {
        let Some(conn) = self
            .conns
            .get_mut(&port)
            .filter(|c| c.state == ConnState::Connected)
        else {
            return;
        };
        // The guest may have `OUR_BUF_ALLOC` bytes outstanding past the
        // `fwd_cnt` it was last told. It cannot have seen a larger one, so a
        // conforming guest stays within this. `fwd_cnt` is never behind
        // `fwd_told`, so the backlog stays within it too.
        let outstanding = conn.rx_cnt.wrapping_sub(conn.fwd_told) as usize;
        if outstanding + data.len() > OUR_BUF_ALLOC as usize {
            self.reset_session(mem, port);
            return;
        }
        conn.rx_cnt = conn.rx_cnt.wrapping_add(data.len() as u32);
        let took = conn.host.send(data);
        self.host_took(mem, port, took as u32);
    }

    /// Resets session `port` because its guest sent past its credit.
    ///
    /// The backlog is dropped, the host socket shuts down, and the guest gets
    /// `OP_RST`.
    fn reset_session(&mut self, mem: &GuestRam, port: u32) {
        let Some(conn) = self.conns.remove(&port) else {
            return;
        };
        conn.host.end(false);
        if !self.overrun_reported {
            self.overrun_reported = true;
            eprintln!(
                "[hvi] virtio-vsock: the guest sent past the credit the device advertised; the \
                 session is reset"
            );
        }
        let hdr = Hdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: port,
            dst_port: AGENT_PORT,
            typ: TYPE_STREAM,
            op: OP_RST,
            ..Hdr::default()
        };
        self.pending.push_back(hdr.to_bytes().to_vec());
        self.fill_rx(mem);
    }

    fn enqueue_credit(&mut self, host_port: u32) {
        let Some(fwd_cnt) = self.tell_fwd_cnt(host_port) else {
            return;
        };
        let hdr = Hdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: host_port,
            dst_port: AGENT_PORT,
            typ: TYPE_STREAM,
            op: OP_CREDIT_UPDATE,
            buf_alloc: OUR_BUF_ALLOC,
            fwd_cnt,
            ..Hdr::default()
        };
        self.pending.push_back(hdr.to_bytes().to_vec());
    }

    /// Returns the writable segments of RX descriptor chain `head`, in order,
    /// or `None` when the chain does not end within the queue's size.
    ///
    /// Linux posts one buffer per packet today, but the chained form is just as
    /// legal: older guests split the header off into its own descriptor, and a
    /// device that reads only the head silently drops the body.
    fn rx_chain(&self, mem: &GuestRam, head: u16) -> Option<Vec<(u64, u32)>> {
        let q = &self.queues[RX_QUEUE as usize];
        let mut segs = Vec::new();
        let mut d = head;
        for _ in 0..q.size() {
            let da = q.desc_addr(d)?;
            let (addr, len, flags, next) = (
                mem.read_u64(da).ok()?,
                mem.read_u32(da + 8).ok()?,
                mem.read_u16(da + 12).ok()?,
                mem.read_u16(da + 14).ok()?,
            );
            if flags & VIRTQ_DESC_F_WRITE != 0 {
                segs.push((addr, len));
            }
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                return Some(segs);
            }
            d = next;
        }
        // A chain that never clears NEXT within the queue's own size is a
        // cycle. Walking it to the budget would return the same descriptor
        // many times over, and the caller would size a packet from capacity
        // that does not exist and then write every copy onto one buffer.
        None
    }

    /// Trims `pkt` to the `cap` bytes the guest's buffer holds and re-queues
    /// the rest as the next RW packet.
    ///
    /// A stream connection carries bytes, not messages, so cutting one RW
    /// packet into two is invisible to the guest. What it must never see is a
    /// header promising more payload than the buffer received. Only RW packets
    /// carry a payload, so nothing else can outgrow a buffer that holds a
    /// header at all.
    fn split_pending(&mut self, pkt: Vec<u8>, cap: usize) -> Vec<u8> {
        let keep = cap - HDR_LEN;
        // Every producer of `pending` frames its packet with `Hdr::to_bytes`,
        // and `fill_rx` reaches this only for a packet longer than a buffer
        // that already holds a header, so the parse cannot fail. Saying so
        // here keeps a silent short write from ever standing in for it.
        let mut h = Hdr::parse(&pkt).expect("a pending packet always carries a header");
        let mut tail_hdr = h;
        tail_hdr.len = (pkt.len() - HDR_LEN - keep) as u32;
        let mut tail = tail_hdr.to_bytes().to_vec();
        tail.extend_from_slice(&pkt[HDR_LEN + keep..]);
        self.pending.push_front(tail);

        h.len = keep as u32;
        let mut head = pkt;
        head.truncate(HDR_LEN + keep);
        head[..HDR_LEN].copy_from_slice(&h.to_bytes());
        head
    }

    /// Delivers pending host -> guest packets into the guest's RX buffers.
    fn fill_rx(&mut self, mem: &GuestRam) {
        if !self.queues[RX_QUEUE as usize].is_ready() {
            return;
        }
        while !self.pending.is_empty() {
            let rx = &self.queues[RX_QUEUE as usize];
            let last = rx.last_avail();
            match rx.pending(mem) {
                Some(0) | None => return, // no guest RX buffer; keep it pending
                Some(_) => {}
            }
            let Some(slot) = rx.avail_slot(last) else {
                return;
            };
            let Ok(head) = mem.read_u16(slot) else {
                return;
            };
            // A chain this walk refuses is malformed, so the guest cannot
            // repost its way out of it: this head stays at the front of the
            // ring and the RX queue stops for that guest. Completing it with a
            // used length of zero would keep the queue moving; only a guest
            // that posted a cycle reaches it.
            let Some(segs) = self.rx_chain(mem, head) else {
                return;
            };
            let cap: usize = segs.iter().map(|&(_, l)| l as usize).sum();
            let waiting = self.pending.front().map_or(0, Vec::len);
            // A buffer too small for a header cannot carry any packet, and one
            // that holds exactly a header cannot carry a payload: splitting
            // there would hand the guest a zero-payload RW packet and push the
            // whole of the original back, consuming every buffer it posts
            // without moving a byte. As in `virtio_net::inject_rx`, a head
            // that can never hold what is waiting blocks the packets behind it
            // until the guest reposts one that can; leave the queue alone
            // rather than complete it with a partial packet.
            if cap < HDR_LEN || (waiting > cap && cap == HDR_LEN) {
                return;
            }
            let pkt = self.pending.pop_front().unwrap();
            let pkt = if pkt.len() > cap {
                self.split_pending(pkt, cap)
            } else {
                pkt
            };
            let mut off = 0usize;
            for (addr, len) in segs {
                if off == pkt.len() {
                    break;
                }
                let n = (pkt.len() - off).min(len as usize);
                if mem.write(addr, &pkt[off..off + n]).is_err() {
                    return;
                }
                off += n;
            }
            self.queues[RX_QUEUE as usize].push_used(mem, head, off as u32);
            self.queues[RX_QUEUE as usize].set_last_avail(last.wrapping_add(1));
            self.interrupt_status |= 1;
        }
    }
}

impl Default for VirtioVsock {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads from a host connection until EOF (helper for the reader thread).
pub fn read_host(stream: &mut UnixStream, buf: &mut [u8]) -> std::io::Result<usize> {
    stream.read(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdr_roundtrip() {
        let h = Hdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: 40000,
            dst_port: AGENT_PORT,
            len: 7,
            typ: TYPE_STREAM,
            op: OP_RW,
            buf_alloc: OUR_BUF_ALLOC,
            fwd_cnt: 3,
            flags: 0,
        };
        let p = Hdr::parse(&h.to_bytes()).unwrap();
        assert_eq!(p.dst_port, AGENT_PORT);
        assert_eq!(p.op, OP_RW);
        assert_eq!(p.len, 7);
        assert_eq!(p.buf_alloc, OUR_BUF_ALLOC);
    }

    #[test]
    fn silences_unused_ops() {
        // Keep the event constant referenced. The credit-request one is
        // exercised for real by `credit_request_answers_only_a_live_session`.
        assert_eq!(EVENT_QUEUE, 2);
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use crate::virtio::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

    fn mem_of(len: usize) -> GuestRam {
        GuestRam::from_ranges(&[(0x4000_0000, len)])
    }

    /// A well-formed packet from the guest agent to host port `dst_port`.
    fn pkt(op: u16, dst_port: u32, body: &[u8]) -> Vec<u8> {
        let h = Hdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: AGENT_PORT,
            dst_port,
            len: body.len() as u32,
            typ: TYPE_STREAM,
            op,
            ..Hdr::default()
        };
        let mut p = h.to_bytes().to_vec();
        p.extend_from_slice(body);
        p
    }

    /// Programs `queue` the way the Linux virtio-mmio driver does: select,
    /// size, the three ring addresses, then READY last.
    fn program_queue(
        dev: &mut VirtioVsock,
        mem: &GuestRam,
        queue: u16,
        desc: u64,
        avail: u64,
        used: u64,
    ) {
        dev.mmio(mem, reg::QUEUE_SEL, true, u64::from(queue));
        dev.mmio(mem, reg::QUEUE_NUM, true, 8);
        dev.mmio(mem, reg::QUEUE_DESC_LOW, true, desc & 0xffff_ffff);
        dev.mmio(mem, reg::QUEUE_DESC_HIGH, true, desc >> 32);
        dev.mmio(mem, reg::QUEUE_DRIVER_LOW, true, avail & 0xffff_ffff);
        dev.mmio(mem, reg::QUEUE_DRIVER_HIGH, true, avail >> 32);
        dev.mmio(mem, reg::QUEUE_DEVICE_LOW, true, used & 0xffff_ffff);
        dev.mmio(mem, reg::QUEUE_DEVICE_HIGH, true, used >> 32);
        dev.mmio(mem, reg::QUEUE_READY, true, 1);
    }

    /// Posts descriptor `idx`, a 64-byte writable buffer at `buffer`, as the
    /// next entry of an 8-entry avail ring.
    fn post_rx_buffer(mem: &GuestRam, desc: u64, avail: u64, idx: u16, buffer: u64) {
        let descriptor = desc + u64::from(idx) * 16;
        mem.write_u64(descriptor, buffer).unwrap();
        mem.write_u32(descriptor + 8, 64).unwrap();
        mem.write_u16(descriptor + 12, VIRTQ_DESC_F_WRITE).unwrap();
        mem.write_u16(descriptor + 14, 0).unwrap();
        let avail_idx = mem.read_u16(avail + 2).unwrap();
        mem.write_u16(avail + 4 + u64::from(avail_idx % 8) * 2, idx)
            .unwrap();
        mem.write_u16(avail + 2, avail_idx.wrapping_add(1)).unwrap();
    }

    // A packet queued before the reset must not reach the ring the guest
    // programs after it.
    #[test]
    fn status_reset_drops_the_sessions_and_closes_their_host_ends() {
        const BASE: u64 = 0x4000_0000;
        let mem = mem_of(0x8000);
        let mut dev = VirtioVsock::new();
        program_queue(&mut dev, &mem, RX_QUEUE, BASE, BASE + 0x1000, BASE + 0x2000);
        post_rx_buffer(&mem, BASE, BASE + 0x1000, 0, BASE + 0x3000);

        let (first, mut first_peer) = UnixStream::pair().unwrap();
        let (second, mut second_peer) = UnixStream::pair().unwrap();
        // The clones stand in for the reader thread's copies of the sockets.
        // Timeouts are set before the reset, since macOS refuses the option on
        // a socket whose peer has shut down.
        let mut first_reader = first.try_clone().unwrap();
        let mut second_reader = second.try_clone().unwrap();
        for socket in [&first_peer, &second_peer, &first_reader, &second_reader] {
            socket
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
        }
        let first_port = dev.add_conn(first).unwrap().0;
        dev.connect(&mem, first_port);
        assert_eq!(
            mem.read_u16(BASE + 0x2000 + 2).unwrap(),
            1,
            "the first REQUEST took the one RX buffer"
        );
        // No buffer is left, so this REQUEST waits in `pending`.
        let second_port = dev.add_conn(second).unwrap().0;
        dev.connect(&mem, second_port);

        dev.mmio(&mem, reg::STATUS, true, 0);
        for socket in [
            &mut first_reader,
            &mut second_reader,
            &mut first_peer,
            &mut second_peer,
        ] {
            assert_eq!(socket.read(&mut [0u8; 1]).unwrap(), 0, "the socket saw EOF");
        }

        program_queue(
            &mut dev,
            &mem,
            RX_QUEUE,
            BASE + 0x4000,
            BASE + 0x5000,
            BASE + 0x6000,
        );
        post_rx_buffer(&mem, BASE + 0x4000, BASE + 0x5000, 0, BASE + 0x7000);
        post_rx_buffer(&mem, BASE + 0x4000, BASE + 0x5000, 1, BASE + 0x7100);
        dev.mmio(&mem, reg::QUEUE_NOTIFY, true, u64::from(RX_QUEUE));
        dev.host_data(&mem, first_port, b"late");
        assert_eq!(
            mem.read_u16(BASE + 0x6000 + 2).unwrap(),
            0,
            "nothing from before the reset reached the fresh ring"
        );
    }

    fn recv(s: &mut UnixStream, n: usize) -> Option<Vec<u8>> {
        s.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).ok().map(|()| buf)
    }

    /// A descriptor length is guest-controlled, and the transmit path sized an
    /// allocation from it directly. A chain claiming more than the largest
    /// packet this device carries must be refused before anything is
    /// allocated.
    #[test]
    fn oversized_transmit_chain_is_refused() {
        const BASE: u64 = 0x4000_0000;
        let mem = mem_of(0x20000);
        let mut dev = VirtioVsock::new();
        let (desc, avail, used, data) = (BASE, BASE + 0x1000, BASE + 0x2000, BASE + 0x3000);

        program_queue(&mut dev, &mem, TX_QUEUE, desc, avail, used);

        // One byte past the ceiling, and still inside guest RAM, so only the
        // ceiling can reject it.
        let oversized = (MAX_TX_PACKET + 1) as u32;
        mem.write_u64(desc, data).unwrap();
        mem.write_u32(desc + 8, oversized).unwrap();
        mem.write_u16(desc + 12, 0).unwrap();
        mem.write_u16(desc + 14, 0).unwrap();

        assert_eq!(dev.read_tx(&mem, 0), None);
    }

    /// A Linux guest splits a vsock send at `VIRTIO_VSOCK_MAX_PKT_BUF_SIZE`,
    /// 64 KiB, and the credit we advertise lets it fill that. A packet that
    /// size is ordinary traffic and must be carried: `process_tx` completes
    /// the descriptor whether or not `read_tx` returned a packet, so dropping
    /// one here would report a successful write to a guest whose bytes were
    /// discarded.
    #[test]
    fn full_size_guest_packet_is_carried() {
        const BASE: u64 = 0x4000_0000;
        const PAYLOAD: usize = 64 * 1024;
        let mem = mem_of(0x30000);
        let mut dev = VirtioVsock::new();
        let (desc, avail, used, data) = (BASE, BASE + 0x1000, BASE + 0x2000, BASE + 0x3000);

        program_queue(&mut dev, &mem, TX_QUEUE, desc, avail, used);

        let full = pkt(OP_RW, 40000, &vec![0xa5u8; PAYLOAD]);
        assert_eq!(full.len(), HDR_LEN + PAYLOAD);
        mem.write(data, &full).unwrap();
        mem.write_u64(desc, data).unwrap();
        mem.write_u32(desc + 8, full.len() as u32).unwrap();
        mem.write_u16(desc + 12, 0).unwrap();
        mem.write_u16(desc + 14, 0).unwrap();

        assert_eq!(
            dev.read_tx(&mem, 0).map(|p| p.len()),
            Some(HDR_LEN + PAYLOAD)
        );
    }

    /// The same bound on the vsock transmit walker. A cycle of writable
    /// descriptors accumulates nothing, so `MAX_TX_PACKET` cannot end it and
    /// the ring size is all that stands between a hostile ring and a spin.
    #[test]
    fn tx_descriptor_cycle_runs_out_of_budget() {
        const BASE: u64 = 0x4000_0000;
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut dev = VirtioVsock::new();
        program_queue(&mut dev, &mem, TX_QUEUE, BASE, BASE + 0x1000, BASE + 0x2000);

        // desc[0] -> desc[0], writable (bit 1) and F_NEXT (bit 0) set.
        mem.write_u64(BASE, BASE + 0x4000).unwrap();
        mem.write_u32(BASE + 8, 64).unwrap();
        mem.write_u16(BASE + 12, 2 | 1).unwrap();
        mem.write_u16(BASE + 14, 0).unwrap();
        assert_eq!(dev.read_tx(&mem, 0), None);

        // A `next` outside the ring ends the walk. The descriptor one past
        // the ring is a valid readable one carrying a whole header, so an
        // unbounded walk would return a packet instead of None.
        mem.write_u32(BASE + 8, 8).unwrap();
        mem.write_u16(BASE + 12, 1).unwrap();
        mem.write_u16(BASE + 14, 8).unwrap(); // == the ring size
        mem.write_u64(BASE + 128, BASE + 0x5000).unwrap();
        mem.write_u32(BASE + 136, HDR_LEN as u32).unwrap();
        mem.write_u16(BASE + 140, 0).unwrap();
        mem.write_u16(BASE + 142, 0).unwrap();
        assert_eq!(dev.read_tx(&mem, 0), None);
        assert_eq!(dev.read_tx(&mem, 8), None, "an out-of-ring head");
    }

    /// Regression for the cross-session injection: session B is registered and
    /// offered, but the guest never accepted it, so its bytes must not flow.
    #[test]
    fn rw_for_a_session_the_guest_never_accepted_is_dropped() {
        let mem = mem_of(0x1000);
        let mut dev = VirtioVsock::new();

        let (a_dev, _a) = UnixStream::pair().unwrap();
        let (b_dev, mut b_peer) = UnixStream::pair().unwrap();
        let port_a = dev.add_conn(a_dev).unwrap().0;
        let port_b = dev.add_conn(b_dev).unwrap().0;
        dev.connect(&mem, port_a);
        dev.connect(&mem, port_b);

        // The guest accepts only A, then tries to write into B.
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port_a, &[]));
        dev.handle_pkt(&mem, &pkt(OP_RW, port_b, b"STOLEN"));
        assert!(recv(&mut b_peer, 6).is_none(), "nothing reached session B");
    }

    /// The guest cannot mark a session connected by responding to an offer that
    /// was never made to it.
    #[test]
    fn response_for_an_unoffered_session_is_dropped() {
        let mem = mem_of(0x1000);
        let mut dev = VirtioVsock::new();

        let (dev_side, mut peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side).unwrap().0; // registered but never
                                                      // offered
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));
        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"STOLEN"));
        assert!(
            recv(&mut peer, 6).is_none(),
            "the forged accept was refused"
        );
    }

    /// Bogus CIDs, the wrong type, or a source port that is not the agent are
    /// all dropped, even on an otherwise live session.
    #[test]
    fn packets_not_addressed_to_us_are_dropped() {
        let mem = mem_of(0x1000);
        let mut dev = VirtioVsock::new();
        let (dev_side, mut peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side).unwrap().0;
        dev.connect(&mem, port);
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));

        let mut forged = |mutate: fn(&mut Hdr)| {
            let mut h = Hdr {
                src_cid: GUEST_CID,
                dst_cid: HOST_CID,
                src_port: AGENT_PORT,
                dst_port: port,
                len: 6,
                typ: TYPE_STREAM,
                op: OP_RW,
                ..Hdr::default()
            };
            mutate(&mut h);
            let mut p = h.to_bytes().to_vec();
            p.extend_from_slice(b"STOLEN");
            dev.handle_pkt(&mem, &p);
        };
        forged(|h| h.dst_cid = 0xbeef);
        forged(|h| h.src_cid = 0xdead);
        forged(|h| h.typ = 0);
        forged(|h| h.src_port = 9999);
        assert!(
            recv(&mut peer, 6).is_none(),
            "every forged header was dropped"
        );

        // The same packet, unmutated, still works -- the checks are not
        // blanket.
        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"STOLEN"));
        assert_eq!(recv(&mut peer, 6).as_deref(), Some(&b"STOLEN"[..]));
    }

    /// A credit request is answered only for a session the guest accepted.
    ///
    /// The reply is what makes this interesting: it names a host port, so a
    /// guest that got an answer for a port it was never offered would learn
    /// that the port exists. New, Offered and absent ports must therefore all
    /// stay silent, and only a Connected one gets its credit update.
    #[test]
    fn credit_request_answers_only_a_live_session() {
        let mem = mem_of(0x1000);
        let mut dev = VirtioVsock::new();

        // One session in each state the guest can observe.
        let (new_dev, _new_peer) = UnixStream::pair().unwrap();
        let new_port = dev.add_conn(new_dev).unwrap().0; // registered, never
                                                         // offered
        let (offered_dev, _offered_peer) = UnixStream::pair().unwrap();
        let offered_port = dev.add_conn(offered_dev).unwrap().0;
        dev.connect(&mem, offered_port); // offered, never accepted
        let (live_dev, _live_peer) = UnixStream::pair().unwrap();
        let live_port = dev.add_conn(live_dev).unwrap().0;
        dev.connect(&mem, live_port);
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, live_port, &[]));

        // The two offers are pending packets in their own right. Drop them, so
        // whatever is pending after this point came from a credit request.
        dev.pending.clear();

        let absent_port = live_port + 1000;
        assert!(!dev.conns.contains_key(&absent_port));
        for port in [new_port, offered_port, absent_port] {
            dev.handle_pkt(&mem, &pkt(OP_CREDIT_REQUEST, port, &[]));
        }
        assert!(
            dev.pending.is_empty(),
            "a credit request was answered for a session the guest never accepted"
        );

        // The live session still gets its answer, so the gate is not a blanket
        // refusal.
        dev.handle_pkt(&mem, &pkt(OP_CREDIT_REQUEST, live_port, &[]));
        let reply = dev
            .pending
            .pop_front()
            .expect("the connected session got no credit update");
        let hdr = Hdr::parse(&reply).expect("the reply parses");
        assert_eq!(hdr.op, OP_CREDIT_UPDATE);
        assert_eq!(hdr.src_port, live_port);
        assert_eq!(hdr.dst_port, AGENT_PORT);
        assert_eq!(hdr.buf_alloc, OUR_BUF_ALLOC);
        assert!(dev.pending.is_empty(), "exactly one reply");
    }

    /// A session the guest was never offered cannot be torn down by it.
    #[test]
    fn shutdown_of_an_unoffered_session_is_dropped() {
        let mem = mem_of(0x1000);
        let mut dev = VirtioVsock::new();
        let (dev_side, _peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side).unwrap().0;

        dev.handle_pkt(&mem, &pkt(OP_SHUTDOWN, port, &[]));
        assert!(dev.conns.contains_key(&port), "the session survived");

        dev.connect(&mem, port);
        dev.handle_pkt(&mem, &pkt(OP_SHUTDOWN, port, &[]));
        assert!(!dev.conns.contains_key(&port), "its own session closes");
    }

    // The clone stands in for the reader thread's copy of the socket, which
    // must see EOF too.
    #[test]
    fn guest_close_shuts_down_the_host_end() {
        let mem = mem_of(0x1000);
        let mut dev = VirtioVsock::new();
        let (dev_side, mut peer) = UnixStream::pair().unwrap();
        let mut reader = dev_side.try_clone().unwrap();
        for socket in [&peer, &reader] {
            socket
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
        }
        let port = dev.add_conn(dev_side).unwrap().0;
        dev.connect(&mem, port);
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));

        dev.handle_pkt(&mem, &pkt(OP_SHUTDOWN, port, &[]));
        assert!(!dev.conns.contains_key(&port));
        for socket in [&mut reader, &mut peer] {
            assert_eq!(socket.read(&mut [0u8; 1]).unwrap(), 0, "the socket saw EOF");
        }
    }

    /// The happy path is intact: offer, accept, relay both ways.
    #[test]
    fn an_accepted_session_still_relays() {
        let mem = mem_of(0x1000);
        let mut dev = VirtioVsock::new();
        let (dev_side, mut peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side).unwrap().0;

        dev.connect(&mem, port);
        assert_eq!(dev.conns[&port].state, ConnState::Offered);
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));
        assert_eq!(dev.conns[&port].state, ConnState::Connected);

        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"hello"));
        assert_eq!(recv(&mut peer, 5).as_deref(), Some(&b"hello"[..]));
        assert_eq!(dev.conns[&port].rx_cnt, 5, "credit accounted");
        assert_eq!(dev.conns[&port].fwd_cnt, 5, "and returned");
    }

    /// Shrinks the send buffer of `s`, so a few KiB fill it on every host.
    fn shrink_send_buffer(s: &UnixStream) {
        let size: libc::c_int = 4096;
        // SAFETY: a live socket and an option value of the stated size.
        let rc = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::from_ref(&size).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    }

    /// Returns `n` bytes of the guest's stream starting at offset `from`, in a
    /// pattern that shows a lost or reordered chunk.
    fn stream_bytes(from: usize, n: usize) -> Vec<u8> {
        (from..from + n).map(|i| (i % 251) as u8).collect()
    }

    /// Sends `n` bytes of the guest's stream, from offset `from`, to session
    /// `port` in RW packets of up to 64 KiB.
    fn guest_sends(dev: &mut VirtioVsock, mem: &GuestRam, port: u32, from: usize, n: usize) {
        for start in (from..from + n).step_by(64 * 1024) {
            let len = (from + n - start).min(64 * 1024);
            dev.handle_pkt(mem, &pkt(OP_RW, port, &stream_bytes(start, len)));
        }
    }

    /// Sends `n` guest bytes to session `port` on another thread and returns
    /// the device when it is done, or `None` when it has not finished within
    /// five seconds.
    fn guest_sends_in_time(
        mut dev: VirtioVsock,
        mem: GuestRam,
        port: u32,
        n: usize,
    ) -> Option<(VirtioVsock, GuestRam)> {
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            guest_sends(&mut dev, &mem, port, 0, n);
            let _ = done.send((dev, mem));
        });
        finished.recv_timeout(Duration::from_secs(5)).ok()
    }

    /// Reads what `s` holds until nothing more arrives for 200 ms.
    fn read_available(s: &mut UnixStream) -> Vec<u8> {
        s.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n @ 1..) = s.read(&mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
        got
    }

    // The device used to hand guest bytes to the host socket with a blocking
    // `write_all`, on the vCPU thread and under the device lock. A host peer
    // that stopped reading then froze the vCPU and every other session.
    #[test]
    fn a_host_peer_that_stops_reading_does_not_block_the_device() {
        let mem = mem_of(0x1000);
        let mut dev = VirtioVsock::new();
        let (dev_side, mut peer) = UnixStream::pair().unwrap();
        shrink_send_buffer(&dev_side);
        let port = dev.add_conn(dev_side).unwrap().0;
        dev.connect(&mem, port);
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));

        let total = OUR_BUF_ALLOC as usize;
        let (dev, _mem) = guest_sends_in_time(dev, mem, port, total)
            .expect("the device blocked on a host peer that does not read");
        assert!(dev.conns.contains_key(&port), "a guest within its credit");

        let taken = read_available(&mut peer);
        assert!(taken.len() < total, "the socket took only part of it");
        assert!(taken == stream_bytes(0, taken.len()));
        for queued in &dev.pending {
            let fwd_cnt = Hdr::parse(queued).unwrap().fwd_cnt as usize;
            assert!(
                fwd_cnt <= taken.len(),
                "no header counts bytes still queued"
            );
        }
    }

    #[test]
    fn a_guest_that_sends_past_its_credit_is_reset() {
        let mem = mem_of(0x1000);
        let mut dev = VirtioVsock::new();
        let (dev_side, mut peer) = UnixStream::pair().unwrap();
        shrink_send_buffer(&dev_side);
        // macOS refuses the option once the device has shut its end down.
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let port = dev.add_conn(dev_side).unwrap().0;
        dev.connect(&mem, port);
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));

        let total = OUR_BUF_ALLOC as usize + 1;
        let (dev, _mem) = guest_sends_in_time(dev, mem, port, total)
            .expect("the device blocked on a host peer that does not read");
        assert!(!dev.conns.contains_key(&port), "the session was reset");
        let reset = Hdr::parse(dev.pending.back().unwrap()).unwrap();
        assert_eq!(
            (reset.op, reset.src_port, reset.dst_port),
            (OP_RST, port, AGENT_PORT)
        );

        // The host peer gets what the socket took, then EOF.
        let mut got = Vec::new();
        peer.read_to_end(&mut got).unwrap();
        assert!(got.len() < total);
        assert!(got == stream_bytes(0, got.len()));
    }

    #[cfg(any(
        all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
        all(target_arch = "x86_64", target_os = "linux")
    ))]
    mod writer {
        use super::*;
        use std::sync::{Arc, Mutex};
        use std::thread::JoinHandle;
        use std::time::Instant;

        use crate::teardown::{join_by, StopSource, StopToken};

        /// One connected session, with the device shared the way the backends
        /// share it.
        struct Session {
            dev: Arc<Mutex<VirtioVsock>>,
            mem: Arc<GuestRam>,
            port: u32,
            writer: Option<HostWriter>,
            peer: UnixStream,
        }

        /// Returns a connected session whose host socket fills after a few KiB.
        fn session() -> Session {
            let mem = mem_of(0x1000);
            let mut dev = VirtioVsock::new();
            let (dev_side, peer) = UnixStream::pair().unwrap();
            shrink_send_buffer(&dev_side);
            // macOS refuses the option once the device has shut its end down.
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let (port, writer) = dev.add_conn(dev_side).unwrap();
            dev.connect(&mem, port);
            dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));
            Session {
                dev: Arc::new(Mutex::new(dev)),
                mem: Arc::new(mem),
                port,
                writer: Some(writer),
                peer,
            }
        }

        impl Session {
            /// Sends `n` bytes of the guest's stream, from offset `from`.
            fn guest_sends(&self, from: usize, n: usize) {
                let mut dev = lock_or_recover(&self.dev);
                guest_sends(&mut dev, &self.mem, self.port, from, n);
            }

            /// Returns the session's `fwd_cnt`.
            fn fwd_cnt(&self) -> u32 {
                lock_or_recover(&self.dev).conns[&self.port].fwd_cnt
            }

            /// Runs the session's writer on a thread, and hands what the socket
            /// took to the device, as the backends do.
            fn spawn_writer(&mut self, stop: StopToken) -> JoinHandle<()> {
                let writer = self.writer.take().unwrap();
                let (dev, mem, port) = (Arc::clone(&self.dev), Arc::clone(&self.mem), self.port);
                std::thread::spawn(move || {
                    writer.run(&stop, |n| lock_or_recover(&dev).host_took(&mem, port, n));
                })
            }
        }

        /// Returns the deadline these tests give a thread to finish.
        fn soon() -> Instant {
            Instant::now() + Duration::from_secs(5)
        }

        #[test]
        fn the_writer_drains_the_backlog_and_returns_the_credit() {
            let source = StopSource::new().unwrap();
            let mut s = session();
            let window = OUR_BUF_ALLOC as usize;
            s.guest_sends(0, window);
            assert!(
                (s.fwd_cnt() as usize) < window,
                "part of it waits in the backlog"
            );

            let writer = s.spawn_writer(source.token());
            let mut got = vec![0u8; window];
            s.peer.read_exact(&mut got).unwrap();
            assert!(got == stream_bytes(0, window));

            // The writer reports a write after the peer may already have read
            // it.
            let deadline = soon();
            while s.fwd_cnt() as usize != window {
                assert!(Instant::now() < deadline, "the writer never reported");
                std::thread::sleep(Duration::from_millis(1));
            }
            let update = lock_or_recover(&s.dev)
                .pending
                .iter()
                .map(|p| Hdr::parse(p).unwrap())
                .rfind(|h| h.op == OP_CREDIT_UPDATE)
                .expect("the guest heard nothing");
            assert_eq!(update.fwd_cnt as usize, window);

            // The returned credit covers a second window.
            s.guest_sends(window, window);
            s.peer.read_exact(&mut got).unwrap();
            assert!(got == stream_bytes(window, window));
            assert!(lock_or_recover(&s.dev).conns.contains_key(&s.port));

            lock_or_recover(&s.dev).host_closed(&s.mem, s.port);
            join_by("writer", writer, soon()).unwrap();
        }

        #[test]
        fn a_guest_close_still_delivers_the_backlog() {
            let source = StopSource::new().unwrap();
            let mut s = session();
            let window = OUR_BUF_ALLOC as usize;
            s.guest_sends(0, window);
            lock_or_recover(&s.dev).handle_pkt(&s.mem, &pkt(OP_SHUTDOWN, s.port, &[]));
            assert!(!lock_or_recover(&s.dev).conns.contains_key(&s.port));

            let writer = s.spawn_writer(source.token());
            let mut got = Vec::new();
            s.peer.read_to_end(&mut got).unwrap();
            assert!(
                got == stream_bytes(0, window),
                "the host got the whole backlog"
            );
            join_by("writer", writer, soon()).unwrap();
        }

        #[test]
        fn the_writer_returns_when_stopped_with_a_full_socket() {
            let source = StopSource::new().unwrap();
            let mut s = session();
            s.guest_sends(0, OUR_BUF_ALLOC as usize);
            let writer = s.spawn_writer(source.token());
            source.request_stop();
            join_by("writer", writer, soon()).unwrap();
        }

        #[test]
        fn a_device_reset_drops_the_backlog_and_ends_the_writer() {
            let source = StopSource::new().unwrap();
            let mut s = session();
            let window = OUR_BUF_ALLOC as usize;
            s.guest_sends(0, window);
            let writer = s.spawn_writer(source.token());
            lock_or_recover(&s.dev).mmio(&s.mem, reg::STATUS, true, 0);
            join_by("writer", writer, soon()).unwrap();

            let mut got = Vec::new();
            s.peer.read_to_end(&mut got).unwrap();
            assert!(got.len() < window, "the backlog was dropped");
        }
    }

    /// Programs the RX queue with `n` buffers of `size` bytes each, the way a
    /// guest driver publishes receive buffers.
    fn program_rx_buffers(
        dev: &mut VirtioVsock,
        mem: &GuestRam,
        rings: (u64, u64, u64, u64),
        n: u16,
        size: u32,
    ) {
        let (desc, avail, used, data) = rings;
        for i in 0..u64::from(n) {
            let d = desc + i * 16;
            mem.write_u64(d, data + i * u64::from(size)).unwrap();
            mem.write_u32(d + 8, size).unwrap();
            mem.write_u16(d + 12, VIRTQ_DESC_F_WRITE).unwrap();
            mem.write_u16(d + 14, 0).unwrap();
            mem.write_u16(avail + 4 + i * 2, i as u16).unwrap();
        }
        mem.write_u16(avail + 2, n).unwrap(); // avail.idx
        program_queue(dev, mem, RX_QUEUE, desc, avail, used);
    }

    /// Reads back the packet the device wrote into RX buffer `i`, using the
    /// length it reported in used slot `u`.
    fn delivered(mem: &GuestRam, used: u64, u: u64, data: u64, size: u32) -> (Hdr, Vec<u8>) {
        let entry = used + 4 + u * 8;
        let id = u64::from(mem.read_u32(entry).unwrap());
        let written = mem.read_u32(entry + 4).unwrap() as usize;
        let mut buf = vec![0u8; written];
        mem.read(data + id * u64::from(size), &mut buf).unwrap();
        let h = Hdr::parse(&buf).unwrap();
        (h, buf[HDR_LEN..].to_vec())
    }

    // A host write larger than the guest's receive buffer is split across
    // buffers instead of being cut to the first one. The tail used to be
    // dropped with no error anywhere, taking the frame that closes stdin with
    // it, so a guest command waited on a stdin that never ended.
    //
    // The buffers are deliberately smaller than a framed packet. At the
    // guest's usual 44 + 4096 they are exactly as large as one, so nothing
    // would be longer than a buffer and `split_pending` would never run: the
    // test would pass against a device that truncates.
    #[test]
    fn host_data_larger_than_one_rx_buffer_is_split_not_truncated() {
        const BASE: u64 = 0x4000_0000;
        // Under `MAX_RW` + `HDR_LEN`, so every framed packet has to be split.
        const RXBUF: u32 = 2048;
        const PAYLOAD: usize = 5000;
        const BUFFERS: u16 = 8;

        let mem = mem_of(0x8000);
        let mut dev = VirtioVsock::new();
        let (desc, avail, used, data) = (BASE, BASE + 0x200, BASE + 0x400, BASE + 0x1000);
        program_rx_buffers(&mut dev, &mem, (desc, avail, used, data), BUFFERS, RXBUF);

        let (dev_side, _peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side).unwrap().0;
        dev.connect(&mem, port); // REQUEST takes used slot 0
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));

        dev.host_data(&mem, port, &vec![b'x'; PAYLOAD]);

        let completed = mem.read_u16(used + 2).unwrap();
        assert!(
            completed > 3,
            "{PAYLOAD} bytes over {RXBUF}-byte buffers took {completed} \
             completions, so nothing was split"
        );
        let mut carried = Vec::new();
        for slot in 1..u64::from(completed) {
            let (hdr, body) = delivered(&mem, used, slot, data, RXBUF);
            assert_eq!(hdr.op, OP_RW);
            assert_eq!(
                hdr.len as usize,
                body.len(),
                "the header of packet {slot} describes {} bytes but {} landed",
                hdr.len,
                body.len()
            );
            assert!(body.len() <= RXBUF as usize - HDR_LEN);
            carried.extend_from_slice(&body);
        }
        assert_eq!(
            carried.len(),
            PAYLOAD,
            "every byte the host wrote reached the guest"
        );
        assert!(carried.iter().all(|&b| b == b'x'));
    }

    // An RX chain that never clears NEXT is refused rather than walked to the
    // queue's size. The walk used to end on the budget and hand back the
    // segments it had collected, so one self-referencing descriptor became
    // `q.size()` copies of the same buffer: a capacity far larger than the
    // guest posted, no split for a packet that needed one, and every copy
    // written over the same bytes with a used length the buffer could not hold.
    #[test]
    fn rx_descriptor_cycle_is_refused() {
        const BASE: u64 = 0x4000_0000;
        let mem = mem_of(0x8000);
        let mut dev = VirtioVsock::new();
        program_queue(&mut dev, &mem, RX_QUEUE, BASE, BASE + 0x1000, BASE + 0x2000);

        // desc[0] -> desc[0], writable and carrying NEXT.
        mem.write_u64(BASE, BASE + 0x4000).unwrap();
        mem.write_u32(BASE + 8, 4140).unwrap();
        mem.write_u16(BASE + 12, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT)
            .unwrap();
        mem.write_u16(BASE + 14, 0).unwrap();
        assert_eq!(dev.rx_chain(&mem, 0), None, "a cycle yields no segments");

        // The same descriptor with NEXT clear is an ordinary one-buffer chain.
        mem.write_u16(BASE + 12, VIRTQ_DESC_F_WRITE).unwrap();
        assert_eq!(dev.rx_chain(&mem, 0), Some(vec![(BASE + 0x4000, 4140)]));
    }

    // A buffer with room for a header and nothing else is left for the guest to
    // repost, rather than split into a packet that carries no payload.
    // `split_pending` would take `keep = 0`, deliver an RW header describing an
    // empty payload and push the whole of the original back to the front of the
    // queue, so every buffer the guest posted would be consumed and not one
    // payload byte would move.
    #[test]
    fn buffer_that_holds_only_a_header_carries_no_payload() {
        const BASE: u64 = 0x4000_0000;
        let mem = mem_of(0x8000);
        let mut dev = VirtioVsock::new();
        let (desc, avail, used, data) = (BASE, BASE + 0x200, BASE + 0x400, BASE + 0x1000);
        program_rx_buffers(&mut dev, &mem, (desc, avail, used, data), 4, HDR_LEN as u32);

        let (dev_side, _peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side).unwrap().0;
        dev.connect(&mem, port); // REQUEST is header-only and fits exactly
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));
        assert_eq!(mem.read_u16(used + 2).unwrap(), 1, "the REQUEST landed");

        dev.host_data(&mem, port, b"payload");
        assert_eq!(
            mem.read_u16(used + 2).unwrap(),
            1,
            "no buffer is completed for a packet none of them can carry"
        );
        assert_eq!(
            dev.pending.len(),
            1,
            "the packet waits for a buffer with room for a payload"
        );
    }

    // A guest that splits the header off into its own descriptor still gets the
    // whole packet: the RX walker follows the chain the way the transmit walker
    // always has.
    #[test]
    fn chained_rx_buffer_receives_the_whole_packet() {
        const BASE: u64 = 0x4000_0000;
        const BODY: usize = 900;

        let mem = mem_of(0x8000);
        let mut dev = VirtioVsock::new();
        let (desc, avail, used, data) = (BASE, BASE + 0x200, BASE + 0x400, BASE + 0x1000);

        // Two chains of two descriptors each: a 44-byte header buffer and a
        // 4096-byte body buffer, as pre-6.4 Linux posts them.
        for i in 0..2u64 {
            let (hd, bd) = (desc + i * 32, desc + i * 32 + 16);
            let base = data + i * 0x2000;
            mem.write_u64(hd, base).unwrap();
            mem.write_u32(hd + 8, HDR_LEN as u32).unwrap();
            mem.write_u16(hd + 12, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT)
                .unwrap();
            mem.write_u16(hd + 14, (i * 2 + 1) as u16).unwrap();
            mem.write_u64(bd, base + HDR_LEN as u64).unwrap();
            mem.write_u32(bd + 8, 4096).unwrap();
            mem.write_u16(bd + 12, 2).unwrap();
            mem.write_u16(bd + 14, 0).unwrap();
            mem.write_u16(avail + 4 + i * 2, (i * 2) as u16).unwrap();
        }
        mem.write_u16(avail + 2, 2).unwrap();
        program_queue(&mut dev, &mem, RX_QUEUE, desc, avail, used);

        let (dev_side, _peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side).unwrap().0;
        dev.connect(&mem, port); // REQUEST takes the first chain
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));
        dev.host_data(&mem, port, &vec![b'y'; BODY]);

        let entry = used + 4 + 8;
        assert_eq!(mem.read_u32(entry).unwrap(), 2, "the second chain was used");
        assert_eq!(
            mem.read_u32(entry + 4).unwrap() as usize,
            HDR_LEN + BODY,
            "header and body both landed"
        );
        let mut buf = vec![0u8; HDR_LEN + BODY];
        mem.read(data + 0x2000, &mut buf).unwrap();
        let h = Hdr::parse(&buf).unwrap();
        assert_eq!((h.op, h.len as usize), (OP_RW, BODY));
        assert!(buf[HDR_LEN..].iter().all(|&b| b == b'y'));
    }
}

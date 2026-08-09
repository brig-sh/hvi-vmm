//! virtio-vsock over virtio-mmio, bridged to a host Unix socket — the
//! transport an `exec`-style command needs.
//!
//! The convention this implements: an in-guest agent serves sessions on guest
//! vsock port 1024, and a host-side caller dials a Unix socket that the VMM
//! bridges to that port. This device implements enough virtio-vsock (STREAM)
//! for that: a host `UnixListener` accepts connections, each becomes a vsock
//! stream the device opens to the guest (host CID 2 -> guest CID 3, port 1024),
//! and bytes relay both ways.
//!
//! Simplifications (interactive exec, low volume): credit is advertised
//! generously and tracked loosely; out-of-order host data is buffered until the
//! guest accepts the connection. NOT boot-tested.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use crate::guestmem::GuestRam;
use crate::virtio::{reg, Queue, QUEUE_NUM_MAX};

const VIRTIO_VSOCK_ID: u64 = 19;
const F_VERSION_1_HI: u32 = 1;

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

/// Credit we advertise to the guest (our RX buffer).
const OUR_BUF_ALLOC: u32 = 256 * 1024;
/// Max payload per RW packet to the guest.
const MAX_RW: usize = 16 * 1024;

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
    stream: UnixStream, // write half (guest -> host); reader thread clones it
    state: ConnState,
    rx_cnt: u32,          // bytes we've received from the guest (our fwd_cnt)
    pending_out: Vec<u8>, // host bytes buffered until the guest accepts
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
        }
    }

    #[must_use]
    pub fn irq_level(&self) -> bool {
        self.interrupt_status != 0
    }

    fn queue(&mut self) -> &mut Queue {
        &mut self.queues[(self.queue_sel % 3) as usize]
    }

    /// Registers a new host connection, returning its assigned local port.
    pub fn add_conn(&mut self, stream: UnixStream) -> u32 {
        let port = self.next_port;
        self.next_port += 1;
        self.conns.insert(
            port,
            Conn {
                stream,
                state: ConnState::New,
                rx_cnt: 0,
                pending_out: Vec::new(),
            },
        );
        port
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
        let rx_cnt = match self.conns.get_mut(&host_port) {
            Some(conn) if conn.state == ConnState::Connected => conn.rx_cnt,
            Some(conn) => {
                conn.pending_out.extend_from_slice(data);
                return;
            }
            None => return,
        };
        self.enqueue_rw(host_port, data, rx_cnt);
        self.fill_rx(mem);
    }

    /// Signals the guest that the host end closed.
    pub fn host_closed(&mut self, mem: &GuestRam, host_port: u32) {
        if self.conns.remove(&host_port).is_some() {
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

    /// Frames RW packet(s) for `data` into the pending queue.
    fn enqueue_rw(&mut self, host_port: u32, data: &[u8], fwd_cnt: u32) {
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
            if flags & 2 == 0 {
                let mut seg = vec![0u8; len as usize];
                mem.read(addr, &mut seg).ok()?;
                buf.extend_from_slice(&seg);
            }
            if flags & 1 == 0 {
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
                        Some((std::mem::take(&mut c.pending_out), c.rx_cnt))
                    }
                    _ => None,
                };
                if let Some((data, rx)) = queued {
                    if !data.is_empty() {
                        self.enqueue_rw(port, &data, rx);
                        self.fill_rx(mem);
                    }
                }
            }
            OP_RW => {
                let end = HDR_LEN + (h.len as usize).min(pkt.len() - HDR_LEN);
                // Relay guest->host bytes and compute the returned credit,
                // dropping the connection borrow before touching the RX side.
                // Only a completed handshake may carry data.
                let rx = match self.conns.get_mut(&port) {
                    Some(c) if c.state == ConnState::Connected => {
                        let _ = c.stream.write_all(&pkt[HDR_LEN..end]);
                        c.rx_cnt = c.rx_cnt.wrapping_add((end - HDR_LEN) as u32);
                        Some(c.rx_cnt)
                    }
                    _ => None,
                };
                if let Some(rx) = rx {
                    self.enqueue_credit(port, rx);
                    self.fill_rx(mem);
                }
            }
            // Only a session the guest was offered may be torn down by it. The
            // guard is equivalent to testing inside the arm, since the fallback
            // arm does nothing.
            OP_SHUTDOWN | OP_RST
                if self
                    .conns
                    .get(&port)
                    .is_some_and(|c| c.state != ConnState::New) =>
            {
                self.conns.remove(&port);
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
            OP_CREDIT_REQUEST => {
                // Only answer for a live session, so credit updates cannot be
                // used to probe which host ports exist.
                if let Some(rx) = self
                    .conns
                    .get(&port)
                    .filter(|c| c.state == ConnState::Connected)
                    .map(|c| c.rx_cnt)
                {
                    self.enqueue_credit(port, rx);
                }
            }
            OP_CREDIT_UPDATE => {}
            _ => {}
        }
    }

    fn enqueue_credit(&mut self, host_port: u32, fwd_cnt: u32) {
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
            let Some(da) = rx.desc_addr(head) else {
                return;
            };
            let (Ok(addr), Ok(len)) = (mem.read_u64(da), mem.read_u32(da + 8)) else {
                return;
            };
            let pkt = self.pending.pop_front().unwrap();
            let n = pkt.len().min(len as usize);
            if mem.write(addr, &pkt[..n]).is_err() {
                return;
            }
            self.queues[RX_QUEUE as usize].push_used(mem, head, n as u32);
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
        // Keep the credit-request/event constants referenced.
        assert_ne!(OP_CREDIT_REQUEST, OP_RW);
        assert_eq!(EVENT_QUEUE, 2);
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use std::io::Read;
    use std::time::Duration;

    fn mem_of(backing: &mut Vec<u8>) -> GuestRam {
        GuestRam::new(backing.as_mut_ptr(), 0x4000_0000, backing.len())
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

    fn recv(s: &mut UnixStream, n: usize) -> Option<Vec<u8>> {
        s.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).ok().map(|()| buf)
    }

    /// Regression for the cross-session injection: session B is registered and
    /// offered, but the guest never accepted it, so its bytes must not flow.
    #[test]
    fn rw_for_a_session_the_guest_never_accepted_is_dropped() {
        let mut backing = vec![0u8; 0x1000];
        let mem = mem_of(&mut backing);
        let mut dev = VirtioVsock::new();

        let (a_dev, _a) = UnixStream::pair().unwrap();
        let (b_dev, mut b_peer) = UnixStream::pair().unwrap();
        let port_a = dev.add_conn(a_dev);
        let port_b = dev.add_conn(b_dev);
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
        let mut backing = vec![0u8; 0x1000];
        let mem = mem_of(&mut backing);
        let mut dev = VirtioVsock::new();

        let (dev_side, mut peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side); // registered but never offered
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
        let mut backing = vec![0u8; 0x1000];
        let mem = mem_of(&mut backing);
        let mut dev = VirtioVsock::new();
        let (dev_side, mut peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side);
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

        // The same packet, unmutated, still works -- the checks are not blanket.
        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"STOLEN"));
        assert_eq!(recv(&mut peer, 6).as_deref(), Some(&b"STOLEN"[..]));
    }

    /// A session the guest was never offered cannot be torn down by it.
    #[test]
    fn shutdown_of_an_unoffered_session_is_dropped() {
        let mut backing = vec![0u8; 0x1000];
        let mem = mem_of(&mut backing);
        let mut dev = VirtioVsock::new();
        let (dev_side, _peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side);

        dev.handle_pkt(&mem, &pkt(OP_SHUTDOWN, port, &[]));
        assert!(dev.conns.contains_key(&port), "the session survived");

        dev.connect(&mem, port);
        dev.handle_pkt(&mem, &pkt(OP_SHUTDOWN, port, &[]));
        assert!(!dev.conns.contains_key(&port), "its own session closes");
    }

    /// The happy path is intact: offer, accept, relay both ways.
    #[test]
    fn an_accepted_session_still_relays() {
        let mut backing = vec![0u8; 0x1000];
        let mem = mem_of(&mut backing);
        let mut dev = VirtioVsock::new();
        let (dev_side, mut peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side);

        dev.connect(&mem, port);
        assert_eq!(dev.conns[&port].state, ConnState::Offered);
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));
        assert_eq!(dev.conns[&port].state, ConnState::Connected);

        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"hello"));
        assert_eq!(recv(&mut peer, 5).as_deref(), Some(&b"hello"[..]));
        assert_eq!(dev.conns[&port].rx_cnt, 5, "credit accounted");
    }
}

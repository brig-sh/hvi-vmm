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
//! Host bytes for the guest wait in a per-connection backlog. They go out only
//! while the guest has credit for them, which is its advertised `buf_alloc`
//! minus what we sent and it has not yet consumed (`fwd_cnt`). A Linux guest
//! resets a connection that overruns its receive buffer. A full backlog stops
//! the bridge from reading the host socket (see
//! [`HostGate`]), so a slow guest
//! blocks the host writer and the backlog stays bounded.
//!
//! Guest bytes for the host go out with a non-blocking send, so a vCPU never
//! waits on a host reader. What the socket does not take waits in a
//! per-connection buffer as large as the credit we advertise, and a writer
//! thread sends it once the socket drains. Our `fwd_cnt` counts only the bytes
//! the socket took, so a slow host reader holds back the guest's writes. A
//! guest that overruns that credit gets `OP_RST`. A guest that writes to a host
//! that has gone gets `OP_SHUTDOWN` for its sends, and `OP_RST` after the last
//! host byte.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::devices::irq::{Irq, IrqLine};
use crate::devices::state::{check_version, invalid};
use crate::devices::virtio::{
    mmio, Queue, QueueState, VirtioCommonState, QUEUE_NUM_MAX, VIRTQ_DESC_F_NEXT,
    VIRTQ_DESC_F_WRITE,
};
use crate::memory::GuestRam;
use crate::teardown::StopToken;
use crate::LOG_PREFIX;

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
/// `OP_SHUTDOWN` flag: the sender takes no more bytes.
const SHUTDOWN_RCV: u32 = 1;
/// `OP_SHUTDOWN` flag: the sender sends no more bytes.
const SHUTDOWN_SEND: u32 = 2;

/// Device to guest: the credit we advertise, so how many guest bytes may wait
/// for the host socket on one connection.
///
/// Firecracker and Cloud Hypervisor buffer the same 64 KiB per connection.
const OUR_BUF_ALLOC: u32 = 64 * 1024;
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
/// Host to guest: the backlog size at which the bridge stops reading the host
/// socket for a connection.
///
/// The bridge reads 8 KiB at a time, so a backlog grows past this by at most
/// one read. A host that hung up lifts the limit. It writes nothing more, so
/// the rest of its socket goes into the backlog, bounded by the socket's
/// receive buffer.
const HOST_BACKLOG_MAX: usize = 64 * 1024;
/// Guest to device: the waiting packets past which a guest-started connect
/// gets no `OP_RST`.
///
/// The reset needs no connection, so a guest that connects in a loop while it
/// posts no RX buffer would otherwise grow `pending` without bound, and a
/// restore would refuse its checkpoint, see [`RESTORE_MAX_PENDING`]. A connect
/// that gets no answer times out in the guest instead of failing at once.
const REFUSALS_PENDING_MAX: usize = 1024;
/// How often [`HostGate::wait`] checks whether its reader should stop
/// waiting, for a stop or a host hangup.
const GATE_POLL: Duration = Duration::from_millis(100);

/// The [`VsockState`] format this build writes and reads.
pub const VSOCK_STATE_VERSION: u32 = 1;
/// The most connections a restore accepts.
///
/// The device has no limit of its own, one connection per host client, so
/// this bounds what a checkpoint file may make the host allocate and is not
/// a bound the device keeps. An agent serves a handful of sessions at a time.
/// A device holding more is refused by [`VsockState::check`], which the
/// capture runs before it writes anything, so the checkpoint fails and the
/// guest runs on.
pub const RESTORE_MAX_CONNS: usize = 1024;
/// The most host-to-guest packets a restore accepts waiting for an RX buffer.
///
/// Packets wait only while the guest posts no RX buffer. What the guest can
/// add to them is bounded: backlog is framed only while nothing waits, so at
/// most one RW packet, or its two halves, is among them; a connection's
/// credit updates are merged rather than queued; and only so many guest
/// connects are refused, see `REFUSALS_PENDING_MAX`. The host is not
/// bounded: one that keeps opening and closing connections to a guest that
/// reads none of them adds two packets each time. As with
/// [`RESTORE_MAX_CONNS`], the capture refuses a device past this.
pub const RESTORE_MAX_PENDING: usize = 16 * 1024;
/// The most bytes the waiting packets may hold together on restore.
pub const RESTORE_MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;
/// The most host bytes one connection's backlog may hold on restore.
///
/// A live host's backlog stops near its 64 KiB gate plus one bridge read.
/// A host that hung up lifts that gate, and the reader drains the rest of the
/// socket into the backlog, bounded by the socket's buffer, which a client
/// can raise past this. As with [`RESTORE_MAX_CONNS`], the capture refuses a
/// device past this.
pub const RESTORE_MAX_BACKLOG: usize = 1024 * 1024;

/// Where a connection is in the handshake, as a checkpoint names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VsockConnPhase {
    /// Registered by the host bridge; the guest has not been told about it.
    New,
    /// `OP_REQUEST` went to the guest, which has not answered.
    Offered,
    /// The guest accepted.
    Connected,
}

/// What a checkpoint keeps of one connection: everything but its host
/// socket and the gates its bridge threads waited on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VsockConnState {
    /// The host port, which keys the connection.
    pub port: u32,
    /// Where the connection is in the handshake.
    pub state: VsockConnPhase,
    /// The guest bytes the host socket took, our `fwd_cnt`.
    pub rx_cnt: u32,
    /// Guest bytes the host socket had not taken.
    pub to_host: Vec<u8>,
    /// Host bytes not yet framed for the guest.
    pub backlog: Vec<u8>,
    /// Whether the host end had closed.
    pub host_closed: bool,
    /// Whether the host end had gone.
    pub host_gone: bool,
    /// Whether the guest had closed its end.
    pub guest_closed: bool,
    /// Whether the guest had closed with `OP_RST`.
    pub guest_reset: bool,
    /// Whether the guest had closed both directions.
    pub guest_full_close: bool,
    /// Whether the guest had been told the host end is done.
    pub guest_told: bool,
    /// Whether we had sent the guest `OP_RST`.
    pub reset_sent: bool,
    /// The guest's receive buffer size, from its last header.
    pub peer_buf_alloc: u32,
    /// The bytes the guest had consumed, from its last header.
    pub peer_fwd_cnt: u32,
    /// The bytes we had framed for the guest.
    pub tx_cnt: u32,
}

/// What a checkpoint keeps of a virtio-vsock device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VsockState {
    /// [`VSOCK_STATE_VERSION`] when written by this build.
    pub version: u32,
    /// The transport registers.
    pub common: VirtioCommonState,
    /// The RX, TX and event queues, in that order.
    pub queues: [QueueState; 3],
    /// Host-to-guest packets waiting for an RX buffer, header first, in
    /// order.
    pub pending: Vec<Vec<u8>>,
    /// The host port the next connection gets.
    pub next_port: u32,
    /// The port whose backlog is framed first.
    pub next_turn: u32,
    /// The connections, by ascending port, so one device state has one
    /// encoding.
    pub conns: Vec<VsockConnState>,
}

impl VsockState {
    /// Refuses a state this build could not restore over `mem`, without
    /// building the device or touching guest RAM.
    ///
    /// [`VirtioVsock::restore`] runs it first. The capture runs it too, before
    /// it writes anything: the device itself does not keep within
    /// [`RESTORE_MAX_CONNS`], [`RESTORE_MAX_PENDING`] or
    /// [`RESTORE_MAX_BACKLOG`], and a checkpoint refused there fails while the
    /// guest can still run on, rather than at a restore after the source has
    /// stopped for good.
    ///
    /// # Errors
    ///
    /// Errors when the state is of another version, has a queue the transport
    /// would not have accepted or interrupt bits the device never sets, or
    /// holds packets, connections or buffers this device would never have
    /// held, see [`RESTORE_MAX_CONNS`] and the other limits.
    pub fn check(&self, mem: &GuestRam) -> std::io::Result<()> {
        check_version("virtio-vsock", self.version, VSOCK_STATE_VERSION)?;
        self.common.check("virtio-vsock")?;
        for queue in &self.queues {
            queue.check(mem)?;
        }
        VirtioVsock::check_pending(&self.pending)?;
        if self.conns.len() > RESTORE_MAX_CONNS {
            return Err(invalid(format_args!(
                "virtio-vsock holds {} connections, a restore takes at most {RESTORE_MAX_CONNS}",
                self.conns.len()
            )));
        }
        let mut ports = HashSet::with_capacity(self.conns.len());
        for c in &self.conns {
            VirtioVsock::check_conn(c, self.next_port)?;
            if !ports.insert(c.port) {
                return Err(invalid(format_args!(
                    "virtio-vsock holds port {} twice",
                    c.port
                )));
            }
        }
        Ok(())
    }
}

impl From<ConnState> for VsockConnPhase {
    fn from(state: ConnState) -> Self {
        match state {
            ConnState::New => VsockConnPhase::New,
            ConnState::Offered => VsockConnPhase::Offered,
            ConnState::Connected => VsockConnPhase::Connected,
        }
    }
}

impl From<VsockConnPhase> for ConnState {
    fn from(phase: VsockConnPhase) -> Self {
        match phase {
            VsockConnPhase::New => ConnState::New,
            VsockConnPhase::Offered => ConnState::Offered,
            VsockConnPhase::Connected => ConnState::Connected,
        }
    }
}

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

/// A wait a bridge thread does without the device lock, which the vCPU needs
/// to move the connection along.
///
/// Each connection has two. The reader's gate closes when the backlog reaches
/// `HOST_BACKLOG_MAX`, and opens when the guest has taken enough of it. The
/// writer's gate is open while guest bytes wait for the host socket. Dropping
/// the connection opens both.
#[derive(Default)]
pub struct HostGate {
    /// Whether the thread has to wait.
    closed: Mutex<bool>,
    /// The condition a waiting thread sleeps on until the gate opens.
    opened: Condvar,
}

impl HostGate {
    fn new_closed() -> Self {
        HostGate {
            closed: Mutex::new(true),
            opened: Condvar::new(),
        }
    }

    fn close(&self) {
        *self.closed.lock().unwrap() = true;
    }

    fn open(&self) {
        let mut closed = self.closed.lock().unwrap();
        if *closed {
            *closed = false;
            self.opened.notify_all();
        }
    }

    /// Blocks until the gate opens, and returns `false` if `running` returns
    /// `false` first.
    ///
    /// `running` is called on entry and then every `GATE_POLL` while the gate
    /// stays closed.
    ///
    /// The bridge readers pass `StopToken::keep_waiting` on their host socket,
    /// which turns `false` on a stop or a host hangup. They ignore the result
    /// and go back to the socket, whose poll tells the two apart. A stop ends
    /// the reader. After a hangup the reader drains what the peer left and
    /// reads EOF.
    pub fn wait(&self, mut running: impl FnMut() -> bool) -> bool {
        loop {
            if !*self.closed.lock().unwrap() {
                return true;
            }
            if !running() {
                return false;
            }
            let closed = self.closed.lock().unwrap();
            if *closed {
                let _ = self.opened.wait_timeout(closed, GATE_POLL);
            }
        }
    }

    /// Blocks until the gate opens, with no timeout.
    ///
    /// The bridge writers wait here. Dropping the connection opens the gate,
    /// and so does the bridge when it stops.
    pub fn wait_open(&self) {
        let mut closed = self.closed.lock().unwrap();
        while *closed {
            closed = self.opened.wait(closed).unwrap();
        }
    }
}

/// The gates of a [`VsockBridge`]'s writers, which open when the list drops.
///
/// The bridge holds the list while it accepts connections, so its writers wake
/// whether the bridge returns or unwinds. It unwinds when a panic has poisoned
/// the device lock.
struct WriterGates(Vec<Arc<HostGate>>);

impl Drop for WriterGates {
    fn drop(&mut self) {
        for gate in &self.0 {
            gate.open();
        }
    }
}

/// One exec session: a host Unix stream mapped to a guest vsock stream.
struct Conn {
    /// The host stream, written with guest bytes, or `None` for a connection
    /// restored from a checkpoint, whose host end stayed on the source host.
    ///
    /// A clone of it is read elsewhere, so `Drop` shuts the stream down. A
    /// drop alone would leave the clone and the peer open.
    stream: Option<UnixStream>,
    /// Where the session is in the handshake.
    state: ConnState,
    /// The guest bytes the host socket has taken, which is our `fwd_cnt`.
    rx_cnt: u32,
    /// Guest bytes the host socket has not taken yet.
    to_host: VecDeque<u8>,
    /// Host bytes not yet framed for the guest.
    backlog: VecDeque<u8>,
    /// Whether the host end closed, so `OP_SHUTDOWN` follows the backlog.
    host_closed: bool,
    /// Whether a send to the host failed because the host has gone.
    ///
    /// The guest then gets `OP_SHUTDOWN` with only the receive flag, so its
    /// sends fail. Guest bytes already on their way are credited and dropped,
    /// and `OP_RST` takes the place of the `OP_SHUTDOWN` that follows the
    /// backlog.
    host_gone: bool,
    /// Whether the guest closed its end, so host bytes are dropped.
    guest_closed: bool,
    /// Whether the guest closed with `OP_RST`, so nothing more goes to it.
    guest_reset: bool,
    /// Whether the guest closed both directions, with `OP_RST` or with
    /// `OP_SHUTDOWN` carrying both flags, as `close` sends it.
    guest_full_close: bool,
    /// Whether the guest has been told that the host end is done.
    guest_told: bool,
    /// Whether we sent the guest `OP_RST`.
    reset_sent: bool,
    /// The guest's receive buffer size, from the last header it sent.
    peer_buf_alloc: u32,
    /// The bytes the guest has consumed, from the last header it sent.
    peer_fwd_cnt: u32,
    /// The bytes we have framed for the guest.
    tx_cnt: u32,
    /// The gate the bridge reader waits on while the backlog is full.
    reader_gate: Arc<HostGate>,
    /// The gate the bridge writer waits on until `to_host` has bytes.
    writer_gate: Arc<HostGate>,
}

impl Conn {
    /// Returns how many more bytes the guest has room for.
    ///
    /// The counters wrap, as in Linux. A `fwd_cnt` ahead of `tx_cnt` makes the
    /// in-flight count wrap to a huge value, so a guest that reports bytes it
    /// was never sent gets no credit.
    fn credit(&self) -> u32 {
        let in_flight = self.tx_cnt.wrapping_sub(self.peer_fwd_cnt);
        self.peer_buf_alloc.saturating_sub(in_flight)
    }
}

impl Drop for Conn {
    // The bridge threads still waiting on this connection go back to its
    // socket, which is shut down here, and end.
    fn drop(&mut self) {
        if let Some(stream) = &self.stream {
            let _ = stream.shutdown(Shutdown::Both);
        }
        self.reader_gate.open();
        self.writer_gate.open();
    }
}

/// A virtio-vsock device bridged to a host Unix socket.
pub struct VirtioVsock {
    /// The device status the driver last wrote.
    status: u32,
    /// The device feature word the driver selected.
    dev_feat_sel: u32,
    /// The queue the driver selected.
    queue_sel: u32,
    /// The RX, TX and event queues, in that order.
    queues: [Queue; 3],
    /// The interrupt bits the driver has not acknowledged yet.
    interrupt_status: u32,
    /// The interrupt line the device drives.
    irq: Irq,
    /// Host-to-guest packets waiting for an RX buffer.
    pending: VecDeque<Vec<u8>>,
    /// The live connections, keyed by host port.
    conns: HashMap<u32, Conn>,
    /// The host port the next connection gets.
    next_port: u32,
    /// The port whose backlog `frame_backlog` serves first, so connections
    /// take turns.
    next_turn: u32,
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
            irq: Irq::default(),
            pending: VecDeque::new(),
            conns: HashMap::new(),
            next_port: 40000,
            next_turn: 0,
        }
    }

    #[must_use]
    pub fn irq_level(&self) -> bool {
        self.interrupt_status != 0
    }

    /// Connects the device to the interrupt line it raises, and sets the line
    /// to the device's level.
    ///
    /// A device built at boot has nothing pending, so the line stays low. A
    /// restored one may hold an interrupt the driver has not acknowledged, and
    /// it has to reach the guest, see [`VirtioVsock::restore`].
    pub(crate) fn connect_irq(&mut self, line: Arc<dyn IrqLine>) {
        self.irq.connect(line);
        self.sync_irq();
    }

    /// Sets the interrupt line to the device's level.
    fn sync_irq(&mut self) {
        self.irq.set(self.irq_level());
    }

    /// Sets the interrupt line to the device's level, whatever it was last
    /// set to, after a restore loaded the interrupt controller. See
    /// `Irq::redrive`.
    // The x86-64 restore does not exist yet.
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    pub(crate) fn redrive_irq(&mut self) {
        self.irq.redrive(self.irq_level());
    }

    fn queue(&mut self) -> &mut Queue {
        &mut self.queues[(self.queue_sel % 3) as usize]
    }

    /// Returns what a checkpoint keeps of the device.
    #[must_use]
    pub fn state(&self) -> VsockState {
        let mut conns: Vec<VsockConnState> = self
            .conns
            .iter()
            .map(|(&port, c)| VsockConnState {
                port,
                state: c.state.into(),
                rx_cnt: c.rx_cnt,
                to_host: c.to_host.iter().copied().collect(),
                backlog: c.backlog.iter().copied().collect(),
                host_closed: c.host_closed,
                host_gone: c.host_gone,
                guest_closed: c.guest_closed,
                guest_reset: c.guest_reset,
                guest_full_close: c.guest_full_close,
                guest_told: c.guest_told,
                reset_sent: c.reset_sent,
                peer_buf_alloc: c.peer_buf_alloc,
                peer_fwd_cnt: c.peer_fwd_cnt,
                tx_cnt: c.tx_cnt,
            })
            .collect();
        // A map iterates in no fixed order, and a state that encodes two ways
        // hashes two ways.
        conns.sort_by_key(|c| c.port);
        VsockState {
            version: VSOCK_STATE_VERSION,
            common: VirtioCommonState {
                status: self.status,
                dev_feat_sel: self.dev_feat_sel,
                queue_sel: self.queue_sel,
                interrupt_status: self.interrupt_status,
            },
            queues: [
                self.queues[0].state(),
                self.queues[1].state(),
                self.queues[2].state(),
            ],
            pending: self.pending.iter().cloned().collect(),
            next_port: self.next_port,
            next_turn: self.next_turn,
            conns,
        }
    }

    /// Rebuilds the device a checkpoint describes over the restored guest RAM
    /// `mem`, connections and all.
    ///
    /// Nothing is written to guest RAM, so a restore that fails at a later
    /// device leaves RAM as the checkpoint has it. The connections come back
    /// with no host end, and [`VirtioVsock::end_restored_conns`] has to end
    /// them once every device is built. The interrupt line is connected
    /// afterwards, as at boot, and connecting it asserts it when the guest has
    /// an unacknowledged interrupt.
    ///
    /// # Errors
    ///
    /// Errors when [`VsockState::check`] refuses the state.
    pub fn restore(mem: &GuestRam, state: &VsockState) -> std::io::Result<Self> {
        state.check(mem)?;
        let queues = [
            Queue::from_state(mem, &state.queues[0])?,
            Queue::from_state(mem, &state.queues[1])?,
            Queue::from_state(mem, &state.queues[2])?,
        ];
        let conns = state
            .conns
            .iter()
            .map(|c| {
                let conn = Conn {
                    stream: None,
                    state: c.state.into(),
                    rx_cnt: c.rx_cnt,
                    to_host: c.to_host.iter().copied().collect(),
                    backlog: c.backlog.iter().copied().collect(),
                    host_closed: c.host_closed,
                    host_gone: c.host_gone,
                    guest_closed: c.guest_closed,
                    guest_reset: c.guest_reset,
                    guest_full_close: c.guest_full_close,
                    guest_told: c.guest_told,
                    reset_sent: c.reset_sent,
                    peer_buf_alloc: c.peer_buf_alloc,
                    peer_fwd_cnt: c.peer_fwd_cnt,
                    tx_cnt: c.tx_cnt,
                    // No bridge thread waits on a restored connection, so the
                    // gates start as `add_conn` leaves them.
                    reader_gate: Arc::default(),
                    writer_gate: Arc::new(HostGate::new_closed()),
                };
                (c.port, conn)
            })
            .collect();
        Ok(VirtioVsock {
            status: state.common.status,
            dev_feat_sel: state.common.dev_feat_sel,
            queue_sel: state.common.queue_sel,
            queues,
            interrupt_status: state.common.interrupt_status,
            irq: Irq::default(),
            pending: state.pending.iter().cloned().collect(),
            conns,
            next_port: state.next_port,
            next_turn: state.next_turn,
        })
    }

    /// Ends every connection a restore brought back.
    ///
    /// The host end of each connection was a socket on the source host, and
    /// nothing on this host is its peer. So each one ends the way a host that
    /// went away ends it at runtime, through [`VirtioVsock::host_gone`] and
    /// [`VirtioVsock::host_closed`]: the guest's sends fail, the host bytes
    /// the device already held still reach the guest, and then the guest gets
    /// `OP_RST` and the connection is dropped. A connection the guest was
    /// never offered is dropped without a word, since the guest has nothing to
    /// end. Those packets go into the guest's RX buffers now if it posted any,
    /// so a guest blocked on a read is woken rather than left waiting for a
    /// host that is not coming back.
    ///
    /// It writes guest RAM, so the restore calls it only once every device is
    /// built and nothing is left to refuse the checkpoint. It is not
    /// optional: a connection left as restored has no host end, so a guest
    /// send to it ends it, but a guest blocked on a read waits for good.
    /// Called before the interrupt line is connected, it leaves the line to
    /// `VirtioVsock::connect_irq`.
    pub fn end_restored_conns(&mut self, mem: &GuestRam) {
        let mut ports: Vec<u32> = self.conns.keys().copied().collect();
        ports.sort_unstable();
        for port in ports {
            if self.conns.get(&port).map(|c| c.state) == Some(ConnState::New) {
                self.conns.remove(&port);
                continue;
            }
            self.host_gone(mem, port);
            self.host_closed(mem, port);
        }
    }

    /// Refuses waiting packets the device could not have framed.
    ///
    /// `fill_rx` takes the front packet's header on trust, and `split_pending`
    /// cuts a packet by the length in it, so a packet shorter than a header,
    /// or one whose header promises another length than it carries, would
    /// stop the device or hand the guest a short packet.
    fn check_pending(pending: &[Vec<u8>]) -> std::io::Result<()> {
        if pending.len() > RESTORE_MAX_PENDING {
            return Err(invalid(format_args!(
                "virtio-vsock holds {} waiting packets, a restore takes at most \
                 {RESTORE_MAX_PENDING}",
                pending.len()
            )));
        }
        let mut bytes = 0usize;
        for pkt in pending {
            bytes += pkt.len();
            if bytes > RESTORE_MAX_PENDING_BYTES {
                return Err(invalid(format_args!(
                    "virtio-vsock waiting packets exceed {RESTORE_MAX_PENDING_BYTES} bytes"
                )));
            }
            let Some(h) = Hdr::parse(pkt).filter(|_| pkt.len() <= HDR_LEN + MAX_RW) else {
                return Err(invalid(format_args!(
                    "virtio-vsock waiting packet of {} bytes, not {HDR_LEN} to {}",
                    pkt.len(),
                    HDR_LEN + MAX_RW
                )));
            };
            if h.len as usize != pkt.len() - HDR_LEN {
                return Err(invalid(format_args!(
                    "virtio-vsock waiting packet says {} payload bytes and carries {}",
                    h.len,
                    pkt.len() - HDR_LEN
                )));
            }
        }
        Ok(())
    }

    /// Refuses a connection the device could not have held.
    fn check_conn(c: &VsockConnState, next_port: u32) -> std::io::Result<()> {
        // A port at or past `next_port` is one `add_conn` hands out again, and
        // the new connection would replace this one in the map.
        if c.port >= next_port {
            return Err(invalid(format_args!(
                "virtio-vsock port {} is not below the next port {next_port}",
                c.port
            )));
        }
        // `process_tx` resets a guest that overruns the credit we advertise,
        // so more than that never waits for the host.
        if c.to_host.len() > OUR_BUF_ALLOC as usize {
            return Err(invalid(format_args!(
                "virtio-vsock port {} holds {} guest bytes, more than the {OUR_BUF_ALLOC} \
                 it advertised",
                c.port,
                c.to_host.len()
            )));
        }
        if c.backlog.len() > RESTORE_MAX_BACKLOG {
            return Err(invalid(format_args!(
                "virtio-vsock port {} holds {} host bytes, a restore takes at most \
                 {RESTORE_MAX_BACKLOG}",
                c.port,
                c.backlog.len()
            )));
        }
        Ok(())
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
        self.conns.clear();
    }

    /// Registers a new host connection, returning its assigned local port.
    ///
    /// The stream goes into non-blocking mode, so a send from a vCPU never
    /// waits on the host reader. `MSG_DONTWAIT` alone does not make a
    /// Unix-socket send non-blocking on macOS.
    ///
    /// # Errors
    ///
    /// Errors if the host ports have run out or the stream refuses
    /// non-blocking mode. The connection is not registered then.
    pub fn add_conn(&mut self, stream: UnixStream) -> std::io::Result<u32> {
        let port = self.next_port;
        // Ports are never reused, so the counter only climbs. One that wrapped
        // would hand out a low port again, and `insert` would give a new host
        // client the session of a connection still at that port.
        let Some(next_port) = port.checked_add(1) else {
            return Err(std::io::Error::other("virtio-vsock has no host port left"));
        };
        // Every live port is below `next_port`, as a restore checks too, so
        // this does not happen. If it did, the new client would take over the
        // guest's session at that port.
        if self.conns.contains_key(&port) {
            return Err(std::io::Error::other(format!(
                "virtio-vsock host port {port} is still in use"
            )));
        }
        stream.set_nonblocking(true)?;
        self.next_port = next_port;
        self.conns.insert(
            port,
            Conn {
                stream: Some(stream),
                state: ConnState::New,
                rx_cnt: 0,
                to_host: VecDeque::new(),
                backlog: VecDeque::new(),
                host_closed: false,
                host_gone: false,
                guest_closed: false,
                guest_reset: false,
                guest_full_close: false,
                guest_told: false,
                reset_sent: false,
                peer_buf_alloc: 0,
                peer_fwd_cnt: 0,
                tx_cnt: 0,
                reader_gate: Arc::default(),
                writer_gate: Arc::new(HostGate::new_closed()),
            },
        );
        Ok(port)
    }

    /// Drops every connection, which ends their bridge threads.
    ///
    /// The bridge calls it once it stops accepting. Each drop shuts the host
    /// stream down and opens both gates.
    pub fn drop_conns(&mut self) {
        self.conns.clear();
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

    /// Queues host bytes for the guest, and returns the gate to wait on when
    /// the connection's backlog is full.
    ///
    /// The bytes go out as the guest's credit and receive buffers allow, and
    /// not before the guest accepts the connection. The caller should not
    /// read more from the host socket until the returned gate opens.
    pub fn host_data(
        &mut self,
        mem: &GuestRam,
        host_port: u32,
        data: &[u8],
    ) -> Option<Arc<HostGate>> {
        let conn = self.conns.get_mut(&host_port)?;
        if conn.guest_closed {
            return None;
        }
        conn.backlog.extend(data);
        self.fill_rx(mem);
        let conn = self.conns.get(&host_port)?;
        if conn.backlog.len() < HOST_BACKLOG_MAX {
            return None;
        }
        conn.reader_gate.close();
        Some(Arc::clone(&conn.reader_gate))
    }

    /// Signals the guest that the host end closed, once the guest has the
    /// connection's backlog.
    ///
    /// A connection the guest has not accepted yet keeps its backlog too, so
    /// a client that writes and closes before the accept loses nothing. The
    /// guest's `OP_RESPONSE` or `OP_RST` settles it, and a device reset drops
    /// it. An accepted connection with a backlog waits for the guest to read
    /// it or close. Guest bytes the host socket has not taken still go out
    /// before the connection is dropped.
    pub fn host_closed(&mut self, mem: &GuestRam, host_port: u32) {
        let Some(conn) = self.conns.get_mut(&host_port) else {
            return;
        };
        conn.host_closed = true;
        self.settle(host_port);
        self.fill_rx(mem);
    }

    /// Ends what is finished of connection `host_port`.
    ///
    /// Once the host end closed and the guest has every host byte, the guest
    /// gets `OP_SHUTDOWN`, or `OP_RST` when the host has gone. The connection
    /// is dropped once the guest was told or closed its end, and the host
    /// socket has taken every guest byte. Neither direction loses bytes to a
    /// close of the other.
    ///
    /// A guest that closed with a full `OP_SHUTDOWN` gets `OP_RST` when the
    /// connection is dropped. Linux holds a closed socket until the peer's
    /// reset arrives, and resets it on its own only after 8 s. A guest that
    /// shut down only its sends gets no reset: hvi ends both directions of
    /// such a connection anyway, and the reset would end the guest's read in
    /// an EOF that looks like a complete reply.
    fn settle(&mut self, host_port: u32) {
        let Some(conn) = self.conns.get_mut(&host_port) else {
            return;
        };
        if conn.host_closed && conn.backlog.is_empty() && !conn.guest_told && !conn.guest_closed {
            conn.guest_told = true;
            let pkt = if conn.host_gone {
                conn.reset_sent = true;
                Self::control_pkt(host_port, OP_RST, 0)
            } else {
                Self::shutdown_pkt(host_port)
            };
            self.pending.push_back(pkt);
        }
        if (conn.guest_told || conn.guest_closed) && conn.to_host.is_empty() {
            if conn.guest_full_close && !conn.guest_reset && !conn.reset_sent {
                self.pending
                    .push_back(Self::control_pkt(host_port, OP_RST, 0));
            }
            self.conns.remove(&host_port);
        }
    }

    /// Records that the host end of `host_port` has gone, as a failed send or
    /// a failed wait for the socket shows.
    ///
    /// The guest bytes waiting for the host are dropped, and so are the ones
    /// already on their way. All of them go back to the guest as credit, so
    /// the guest can still read the backlog the host left. An `OP_SHUTDOWN`
    /// with only the receive flag makes the guest's later sends fail with
    /// EPIPE, and its reads go on. The guest gets `OP_RST` after the last host
    /// byte.
    pub fn host_gone(&mut self, mem: &GuestRam, host_port: u32) {
        let Some(conn) = self.conns.get_mut(&host_port) else {
            return;
        };
        if conn.host_gone {
            return;
        }
        conn.host_gone = true;
        if !conn.guest_closed && !conn.guest_told {
            self.pending
                .push_back(Self::control_pkt(host_port, OP_SHUTDOWN, SHUTDOWN_RCV));
        }
        let dropped = conn.to_host.len();
        conn.to_host.clear();
        conn.writer_gate.close();
        conn.rx_cnt = conn.rx_cnt.wrapping_add(dropped as u32);
        let rx = conn.rx_cnt;
        if dropped > 0 && !conn.guest_closed {
            self.enqueue_credit(host_port, rx);
        }
        self.settle(host_port);
        self.fill_rx(mem);
    }

    /// Returns a header-only packet from host port `host_port` to the agent.
    fn control_pkt(host_port: u32, op: u16, flags: u32) -> Vec<u8> {
        let hdr = Hdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: host_port,
            dst_port: AGENT_PORT,
            typ: TYPE_STREAM,
            op,
            flags,
            buf_alloc: OUR_BUF_ALLOC,
            ..Hdr::default()
        };
        hdr.to_bytes().to_vec()
    }

    /// Returns the `OP_SHUTDOWN` for both directions of `host_port`.
    fn shutdown_pkt(host_port: u32) -> Vec<u8> {
        Self::control_pkt(host_port, OP_SHUTDOWN, SHUTDOWN_RCV | SHUTDOWN_SEND)
    }

    /// Returns the writer gate of `host_port`, or `None` when there is no such
    /// connection.
    ///
    /// The gate is open while guest bytes wait for the host socket. A bridge
    /// writer waits on it, then for the socket to take bytes, then calls
    /// [`VirtioVsock::flush_to_host`].
    #[must_use]
    pub fn writer_gate(&self, host_port: u32) -> Option<Arc<HostGate>> {
        self.conns
            .get(&host_port)
            .map(|c| Arc::clone(&c.writer_gate))
    }

    /// Sends what the host socket takes of the guest bytes waiting for it, and
    /// returns whether the connection still needs its bridge writer.
    ///
    /// The send never blocks. The bytes the socket took go back to the guest
    /// as credit. A send that fails for any reason but a full socket means the
    /// host has gone, see [`VirtioVsock::host_gone`].
    pub fn flush_to_host(&mut self, mem: &GuestRam, host_port: u32) -> bool {
        let Some(conn) = self.conns.get_mut(&host_port) else {
            return false;
        };
        let mut sent = 0usize;
        let mut gone = false;
        while !conn.to_host.is_empty() {
            // A connection with no host end has nowhere to send, which is a
            // host that has gone.
            let Some(mut stream) = conn.stream.as_ref() else {
                gone = true;
                break;
            };
            match stream.write(conn.to_host.as_slices().0) {
                Ok(0) => break,
                Ok(n) => {
                    conn.to_host.drain(..n);
                    sent += n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    gone = true;
                    break;
                }
            }
        }
        if gone {
            self.host_gone(mem, host_port);
            return false;
        }
        if conn.to_host.is_empty() {
            conn.writer_gate.close();
        } else {
            conn.writer_gate.open();
        }
        // A guest that closed has no socket left to take credit, and Linux
        // answers a packet for it with `OP_RST`.
        if sent > 0 && !conn.guest_closed {
            conn.rx_cnt = conn.rx_cnt.wrapping_add(sent as u32);
            let rx = conn.rx_cnt;
            self.enqueue_credit(host_port, rx);
        }
        self.settle(host_port);
        self.fill_rx(mem);
        self.conns.contains_key(&host_port)
    }

    /// Frames one RW packet from a connection's backlog into `pending`, and
    /// returns whether it queued anything.
    ///
    /// Connections take turns, and a packet never exceeds the guest's credit.
    /// A connection whose host end closed gets its `OP_SHUTDOWN` right after
    /// its last byte, see [`VirtioVsock::settle`].
    fn frame_backlog(&mut self) -> bool {
        let turn = self.next_turn;
        let Some(port) = self
            .conns
            .iter()
            .filter(|(_, c)| {
                c.state == ConnState::Connected && !c.backlog.is_empty() && c.credit() > 0
            })
            .map(|(&port, _)| port)
            .min_by_key(|&port| port.wrapping_sub(turn))
        else {
            return false;
        };
        self.next_turn = port.wrapping_add(1);
        let conn = self.conns.get_mut(&port).unwrap();
        let n = conn.backlog.len().min(MAX_RW).min(conn.credit() as usize);
        let hdr = Hdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: port,
            dst_port: AGENT_PORT,
            len: n as u32,
            typ: TYPE_STREAM,
            op: OP_RW,
            buf_alloc: OUR_BUF_ALLOC,
            fwd_cnt: conn.rx_cnt,
            ..Hdr::default()
        };
        let mut pkt = hdr.to_bytes().to_vec();
        // `Vec::extend` copies a `VecDeque` drain one byte at a time.
        let (front, back) = conn.backlog.as_slices();
        let from_front = n.min(front.len());
        pkt.extend_from_slice(&front[..from_front]);
        pkt.extend_from_slice(&back[..n - from_front]);
        conn.backlog.drain(..n);
        conn.tx_cnt = conn.tx_cnt.wrapping_add(n as u32);
        if conn.backlog.len() < HOST_BACKLOG_MAX {
            conn.reader_gate.open();
        }
        self.pending.push_back(pkt);
        self.settle(port);
        true
    }

    /// The device features this device offers, both words: what the machine
    /// profile records, since a restored driver has negotiated against them.
    pub const FEATURES: u64 = (F_VERSION_1_HI as u64) << 32;

    /// Services one MMIO access.
    pub fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        let read = self.serve_mmio(mem, offset, is_write, value);
        self.sync_irq();
        read
    }

    /// Reads or writes register `offset`, running a queue the write notifies.
    fn serve_mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        let v = value as u32;
        if is_write {
            match offset {
                mmio::DEVICE_FEATURES_SEL => self.dev_feat_sel = v,
                mmio::DRIVER_FEATURES_SEL | mmio::DRIVER_FEATURES => {}
                mmio::QUEUE_SEL => self.queue_sel = v,
                mmio::QUEUE_NUM => self.queue().set_num(v),
                mmio::QUEUE_READY => self.queue().set_ready(v, mem),
                mmio::QUEUE_NOTIFY => match v as u16 {
                    TX_QUEUE => self.process_tx(mem),
                    RX_QUEUE => self.fill_rx(mem),
                    _ => {}
                },
                mmio::INTERRUPT_ACK => self.interrupt_status &= !v,
                mmio::STATUS if v == 0 => self.reset(),
                mmio::STATUS => self.status = v,
                mmio::QUEUE_DESC_LOW => self.queue().set_desc_lo(v),
                mmio::QUEUE_DESC_HIGH => self.queue().set_desc_hi(v),
                mmio::QUEUE_DRIVER_LOW => self.queue().set_avail_lo(v),
                mmio::QUEUE_DRIVER_HIGH => self.queue().set_avail_hi(v),
                mmio::QUEUE_DEVICE_LOW => self.queue().set_used_lo(v),
                mmio::QUEUE_DEVICE_HIGH => self.queue().set_used_hi(v),
                _ => {}
            }
            0
        } else {
            match offset {
                mmio::MAGIC => 0x7472_6976,
                mmio::VERSION => 2,
                mmio::DEVICE_ID => VIRTIO_VSOCK_ID,
                mmio::VENDOR_ID => 0x4649_4f4e,
                mmio::DEVICE_FEATURES if self.dev_feat_sel == 1 => u64::from(F_VERSION_1_HI),
                mmio::QUEUE_NUM_MAX => u64::from(QUEUE_NUM_MAX),
                mmio::QUEUE_READY => {
                    u64::from(self.queues[(self.queue_sel % 3) as usize].is_ready())
                }
                mmio::INTERRUPT_STATUS => u64::from(self.interrupt_status),
                mmio::STATUS => u64::from(self.status),
                // Config space: guest CID (u64) at offset 0.
                _ if offset >= mmio::CONFIG => {
                    let f = (offset - mmio::CONFIG) as usize;
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
        // Every header the guest sends carries its credit, as in Linux's
        // `virtio_transport_space_update`. A session the guest was never
        // offered has no credit to update.
        if h.op != OP_REQUEST {
            if let Some(c) = self
                .conns
                .get_mut(&port)
                .filter(|c| c.state != ConnState::New)
            {
                c.peer_buf_alloc = h.buf_alloc;
                c.peer_fwd_cnt = h.fwd_cnt;
            }
        }
        match h.op {
            OP_RESPONSE => {
                // Only a session we actually offered may be accepted, and only
                // once. Otherwise the guest could mark any port connected and
                // then write to it.
                if let Some(c) = self
                    .conns
                    .get_mut(&port)
                    .filter(|c| c.state == ConnState::Offered)
                {
                    c.state = ConnState::Connected;
                }
            }
            OP_RW => {
                let end = HDR_LEN + (h.len as usize).min(pkt.len() - HDR_LEN);
                let body = &pkt[HDR_LEN..end];
                enum Relay {
                    Send,
                    Drop(u32),
                    Overrun,
                }
                // Only a completed handshake may carry data, and only within
                // the credit we advertised.
                let relay = match self.conns.get_mut(&port) {
                    Some(c) if c.state == ConnState::Connected && !c.guest_closed => {
                        if c.host_gone {
                            c.rx_cnt = c.rx_cnt.wrapping_add(body.len() as u32);
                            Relay::Drop(c.rx_cnt)
                        } else if c.to_host.len() + body.len() > OUR_BUF_ALLOC as usize {
                            Relay::Overrun
                        } else {
                            c.to_host.extend(body);
                            Relay::Send
                        }
                    }
                    _ => return,
                };
                match relay {
                    Relay::Send => {
                        self.flush_to_host(mem, port);
                    }
                    Relay::Drop(rx) => self.enqueue_credit(port, rx),
                    Relay::Overrun => {
                        self.conns.remove(&port);
                        self.pending.push_back(Self::control_pkt(port, OP_RST, 0));
                    }
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
                // The host still gets the guest bytes waiting for it, after an
                // `OP_RST` too: Linux answers our full shutdown with one, and
                // ends its own close with one after 8 s. The guest reads
                // nothing more, so host bytes are dropped.
                if let Some(c) = self.conns.get_mut(&port) {
                    let both = SHUTDOWN_RCV | SHUTDOWN_SEND;
                    c.guest_closed = true;
                    c.guest_reset |= h.op == OP_RST;
                    c.guest_full_close |= h.op == OP_RST || h.flags & both == both;
                    c.backlog.clear();
                    c.reader_gate.open();
                    self.settle(port);
                }
            }
            // Enough waits for the guest already, see `REFUSALS_PENDING_MAX`.
            OP_REQUEST if self.pending.len() >= REFUSALS_PENDING_MAX => {}
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
            // The credit itself was taken above.
            _ => {}
        }
        // A reply may be waiting, and an accept or new credit may let backlog
        // out.
        self.fill_rx(mem);
    }

    /// Queues an `OP_CREDIT_UPDATE` for `host_port` carrying `fwd_cnt`.
    ///
    /// A credit update still waiting as the last packet from `host_port` is
    /// brought up to `fwd_cnt` instead of followed by another. The guest keeps
    /// only the newest count, and no packet of that connection behind it
    /// carries an older one, so it loses nothing. Without this, a guest that
    /// posts no RX buffer grows `pending` by one packet per credit request,
    /// and a restore refuses its checkpoint, see [`RESTORE_MAX_PENDING`].
    fn enqueue_credit(&mut self, host_port: u32, fwd_cnt: u32) {
        let last = self
            .pending
            .iter_mut()
            .rev()
            .find(|p| Hdr::parse(p).is_some_and(|h| h.src_port == host_port));
        if let Some(last) = last {
            if let Some(mut h) = Hdr::parse(last).filter(|h| h.op == OP_CREDIT_UPDATE) {
                h.fwd_cnt = fwd_cnt;
                last[..HDR_LEN].copy_from_slice(&h.to_bytes());
                return;
            }
        }
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
    ///
    /// Packets in `pending` go out in order. Backlog is framed one packet at a
    /// time, only when `pending` is empty, so at most one RW packet waits for
    /// an RX buffer.
    fn fill_rx(&mut self, mem: &GuestRam) {
        self.fill_rx_buffers(mem);
        self.sync_irq();
    }

    /// Moves pending packets into the guest's RX buffers while both last.
    fn fill_rx_buffers(&mut self, mem: &GuestRam) {
        if !self.queues[RX_QUEUE as usize].is_ready() {
            return;
        }
        loop {
            if self.pending.is_empty() && !self.frame_backlog() {
                return;
            }
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
            // without moving a byte. As in `net::inject_rx`, a head that can
            // never hold what is waiting blocks the packets behind it until the
            // guest reposts one that can; leave the queue alone rather than
            // complete it with a partial packet.
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

/// The agent bridge, which relays the connections on the host's agent socket to
/// the vsock device.
///
/// Each connection accepted on the socket is opened to the guest agent (host
/// CID 2 to guest CID 3, port 1024) and relayed both ways. A reader thread per
/// connection hands the host's bytes to the device, and a writer thread sends
/// the guest's bytes the vCPU could not.
pub(crate) struct VsockBridge {
    /// The agent socket, non-blocking.
    listener: UnixListener,
    /// The device the connections are relayed to.
    dev: Arc<Mutex<VirtioVsock>>,
    /// Guest RAM, which the device's queues are in.
    mem: Arc<GuestRam>,
}

impl VsockBridge {
    /// Binds the agent socket at `path` for `dev`, first removing a stale
    /// socket a previous run left, which would make `bind` fail with
    /// `EADDRINUSE`.
    ///
    /// The listener is non-blocking, so the accept loop can poll it beside the
    /// stop token and then accept without blocking. It must be bound before the
    /// seccomp filters go in, since they allow accepting on a listener already
    /// held but not creating one.
    ///
    /// # Errors
    ///
    /// Errors if the socket cannot be bound.
    // The host-path ban in clippy.toml is aimed at the virtio-fs device, where
    // every component of a path comes from the guest. This path is the
    // operator's.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn bind(
        path: &str,
        dev: Arc<Mutex<VirtioVsock>>,
        mem: Arc<GuestRam>,
    ) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("cannot bind Unix socket {path}: {e}"))
        })?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, dev, mem })
    }

    /// Accepts and relays agent connections until `stop` is requested.
    ///
    /// The per-connection threads poll the same token, and this thread joins
    /// the ones still running before it returns. On Linux they inherit the
    /// seccomp filter of the thread that runs this. Every call into the device
    /// passes the token's pause gate first, and no wait happens inside it, so a
    /// pause holds all of these threads back without waiting for traffic.
    pub(crate) fn run(self, stop: &StopToken) {
        let Self { listener, dev, mem } = self;
        let mut relays: Vec<JoinHandle<()>> = Vec::new();
        // A client that retries a refused connect would otherwise fill the
        // log with the same line.
        let mut refusal_logged = false;
        let mut gates = WriterGates(Vec::new());
        loop {
            match stop.wait(listener.as_fd()) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    stderrln!("{LOG_PREFIX} vsock bridge: {e}; no longer accepting");
                    break;
                }
            }
            let Ok((stream, _)) = listener.accept() else {
                continue;
            };
            let Ok(reader) = stream.try_clone() else {
                continue;
            };
            let Ok(writer) = stream.try_clone() else {
                continue;
            };
            // Register the connection and send the guest agent a REQUEST.
            let (port, writer_gate) = {
                let _in = stop.enter();
                let mut d = dev.lock().unwrap();
                let port = match d.add_conn(stream) {
                    Ok(port) => port,
                    Err(e) => {
                        if !refusal_logged {
                            eprintln!("{LOG_PREFIX} vsock bridge: {e}; connection refused");
                            refusal_logged = true;
                        }
                        continue;
                    }
                };
                d.connect(&mem, port);
                (port, d.writer_gate(port))
            };
            let Some(writer_gate) = writer_gate else {
                continue;
            };
            relays.retain(|handle| !handle.is_finished());
            // A gate only this list holds belongs to a connection that is gone.
            gates.0.retain(|gate| Arc::strong_count(gate) > 1);
            gates.0.push(Arc::clone(&writer_gate));
            relays.push(Self::spawn_writer(
                &dev,
                &mem,
                stop,
                port,
                writer,
                writer_gate,
            ));
            relays.push(Self::spawn_reader(&dev, &mem, stop, port, reader));
        }
        // Dropping the connections shuts their sockets down and opens their
        // gates, so every reader and writer ends. The loop can end on an error
        // as well as on the stop, so this passes the pause gate too.
        drop(gates);
        {
            let _in = stop.enter();
            dev.lock().unwrap().drop_conns();
        }
        for relay in relays {
            let _ = relay.join();
        }
    }

    /// Spawns the thread that sends connection `port` the guest's bytes the
    /// vCPU could not. It waits for the socket to take them, without the device
    /// lock.
    fn spawn_writer(
        dev: &Arc<Mutex<VirtioVsock>>,
        mem: &Arc<GuestRam>,
        stop: &StopToken,
        port: u32,
        writer: UnixStream,
        gate: Arc<HostGate>,
    ) -> JoinHandle<()> {
        let (dev, mem, stop) = (Arc::clone(dev), Arc::clone(mem), stop.clone());
        std::thread::spawn(move || loop {
            gate.wait_open();
            match stop.wait_writable(writer.as_fd()) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    stderrln!("{LOG_PREFIX} vsock bridge: {e}; guest bytes dropped");
                    let _in = stop.enter();
                    dev.lock().unwrap().host_gone(&mem, port);
                    break;
                }
            }
            let _in = stop.enter();
            if !dev.lock().unwrap().flush_to_host(&mem, port) {
                break;
            }
        })
    }

    /// Spawns the thread that hands connection `port`'s bytes from the host to
    /// the device.
    fn spawn_reader(
        dev: &Arc<Mutex<VirtioVsock>>,
        mem: &Arc<GuestRam>,
        stop: &StopToken,
        port: u32,
        mut reader: UnixStream,
    ) -> JoinHandle<()> {
        let (dev, mem, stop) = (Arc::clone(dev), Arc::clone(mem), stop.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match stop.wait(reader.as_fd()) {
                    Ok(true) => {}
                    // A stop ends the connection like a peer close, so the
                    // device releases it.
                    Ok(false) => break,
                    Err(e) => {
                        stderrln!("{LOG_PREFIX} vsock bridge: {e}; connection closed");
                        break;
                    }
                }
                // The read is inside the pause gate with the delivery, so a
                // pause never finds bytes taken off the socket that the device
                // does not hold yet; a checkpoint would lose them. `add_conn`
                // makes the socket non-blocking, so the read never waits inside
                // the gate, and it can find nothing even after the poll.
                let gate = {
                    let _in = stop.enter();
                    let n = match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) if retry_read(&e) => continue,
                        Err(_) => break,
                    };
                    dev.lock().unwrap().host_data(&mem, port, &buf[..n])
                };
                // Outside the pause gate, since the guest's credit may come
                // only after a resume. `HostGate::wait` says why its result is
                // not needed.
                if let Some(gate) = gate {
                    gate.wait(|| stop.keep_waiting(reader.as_fd()));
                }
            }
            let _in = stop.enter();
            dev.lock().unwrap().host_closed(&mem, port);
        })
    }
}

/// Returns whether a bridge read that failed with `e` should poll again.
///
/// The host socket is non-blocking, so a read after a poll that reported it
/// readable can still find nothing.
#[must_use]
pub fn retry_read(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
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
    fn features_are_the_two_pages_the_window_offers() {
        let mem = GuestRam::from_ranges(&[(0x4000_0000, 0x1000)]);
        let mut dev = VirtioVsock::new();
        let mut page = |sel| {
            dev.mmio(&mem, mmio::DEVICE_FEATURES_SEL, true, sel);
            dev.mmio(&mem, mmio::DEVICE_FEATURES, false, 0)
        };
        assert_eq!((page(1) << 32) | page(0), VirtioVsock::FEATURES);
    }

    /// Returns the number of bytes waiting to be read on `socket`.
    fn unread(socket: &UnixStream) -> i32 {
        use std::os::fd::AsRawFd;
        let mut n: libc::c_int = 0;
        // SAFETY: FIONREAD writes one int through the pointer, which lives
        // for the call.
        let rc = unsafe { libc::ioctl(socket.as_raw_fd(), libc::FIONREAD, &mut n) };
        assert_eq!(rc, 0, "FIONREAD");
        n
    }

    // A reader that took bytes off the socket and then waited at a closed
    // gate would hold them where a checkpoint cannot see them. Under a pause
    // they must stay in the socket.
    #[test]
    fn a_paused_reader_leaves_the_bytes_in_the_socket() {
        use std::io::Write;
        use std::time::{Duration, Instant};

        let source = crate::teardown::StopSource::new().unwrap();
        let dev = Arc::new(Mutex::new(VirtioVsock::new()));
        let mem = Arc::new(GuestRam::from_ranges(&[(0x4000_0000, 0x1000)]));
        let (ours, mut peer) = UnixStream::pair().unwrap();
        let watch = ours.try_clone().unwrap();
        let port = dev
            .lock()
            .unwrap()
            .add_conn(ours.try_clone().unwrap())
            .unwrap();
        source.gate().pause(Duration::from_secs(1)).unwrap();
        let reader = VsockBridge::spawn_reader(&dev, &mem, &source.token(), port, ours);
        peer.write_all(b"agent bytes").unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(unread(&watch), 11, "the reader took bytes under a pause");
        source.gate().unpause();
        let deadline = Instant::now() + Duration::from_secs(5);
        while unread(&watch) != 0 {
            assert!(
                Instant::now() < deadline,
                "the reader never read after the resume"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        source.request_stop();
        reader.join().unwrap();
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
    use std::time::{Duration, Instant};

    use crate::devices::virtio::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

    fn mem_of(len: usize) -> GuestRam {
        GuestRam::from_ranges(&[(0x4000_0000, len)])
    }

    /// The receive buffer a Linux guest advertises by default.
    const GUEST_BUF_ALLOC: u32 = 256 * 1024;

    /// Returns a well-formed packet from the guest agent to host port
    /// `dst_port`, advertising `GUEST_BUF_ALLOC` and nothing consumed.
    fn pkt(op: u16, dst_port: u32, body: &[u8]) -> Vec<u8> {
        guest_pkt(op, dst_port, (GUEST_BUF_ALLOC, 0), body)
    }

    /// Returns a header-only packet from the guest agent advertising
    /// `buf_alloc` and `fwd_cnt`.
    fn credit_pkt(op: u16, dst_port: u32, buf_alloc: u32, fwd_cnt: u32) -> Vec<u8> {
        guest_pkt(op, dst_port, (buf_alloc, fwd_cnt), &[])
    }

    /// Returns a packet from the guest agent to host port `dst_port` that
    /// carries `body` and advertises `credit` as `(buf_alloc, fwd_cnt)`.
    fn guest_pkt(op: u16, dst_port: u32, credit: (u32, u32), body: &[u8]) -> Vec<u8> {
        let h = Hdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: AGENT_PORT,
            dst_port,
            len: body.len() as u32,
            typ: TYPE_STREAM,
            op,
            buf_alloc: credit.0,
            fwd_cnt: credit.1,
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
        dev.mmio(mem, mmio::QUEUE_SEL, true, u64::from(queue));
        dev.mmio(mem, mmio::QUEUE_NUM, true, 8);
        dev.mmio(mem, mmio::QUEUE_DESC_LOW, true, desc & 0xffff_ffff);
        dev.mmio(mem, mmio::QUEUE_DESC_HIGH, true, desc >> 32);
        dev.mmio(mem, mmio::QUEUE_DRIVER_LOW, true, avail & 0xffff_ffff);
        dev.mmio(mem, mmio::QUEUE_DRIVER_HIGH, true, avail >> 32);
        dev.mmio(mem, mmio::QUEUE_DEVICE_LOW, true, used & 0xffff_ffff);
        dev.mmio(mem, mmio::QUEUE_DEVICE_HIGH, true, used >> 32);
        dev.mmio(mem, mmio::QUEUE_READY, true, 1);
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
        let first_port = dev.add_conn(first).unwrap();
        dev.connect(&mem, first_port);
        assert_eq!(
            mem.read_u16(BASE + 0x2000 + 2).unwrap(),
            1,
            "the first REQUEST took the one RX buffer"
        );
        // No buffer is left, so this REQUEST waits in `pending`.
        let second_port = dev.add_conn(second).unwrap();
        dev.connect(&mem, second_port);

        dev.mmio(&mem, mmio::STATUS, true, 0);
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
        dev.mmio(&mem, mmio::QUEUE_NOTIFY, true, u64::from(RX_QUEUE));
        dev.host_data(&mem, first_port, b"late");
        assert_eq!(
            mem.read_u16(BASE + 0x6000 + 2).unwrap(),
            0,
            "nothing from before the reset reached the fresh ring"
        );
    }

    fn recv(s: &mut UnixStream, n: usize) -> Option<Vec<u8>> {
        // macOS refuses the timeout on a socket whose peer has shut down, and
        // a read on that socket does not block anyway.
        let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
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
        let port_a = dev.add_conn(a_dev).unwrap();
        let port_b = dev.add_conn(b_dev).unwrap();
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
        let port = dev.add_conn(dev_side).unwrap(); // registered but never
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
        let port = dev.add_conn(dev_side).unwrap();
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
        let new_port = dev.add_conn(new_dev).unwrap(); // registered, never
                                                       // offered
        let (offered_dev, _offered_peer) = UnixStream::pair().unwrap();
        let offered_port = dev.add_conn(offered_dev).unwrap();
        dev.connect(&mem, offered_port); // offered, never accepted
        let (live_dev, _live_peer) = UnixStream::pair().unwrap();
        let live_port = dev.add_conn(live_dev).unwrap();
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
        let port = dev.add_conn(dev_side).unwrap();

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
        let port = dev.add_conn(dev_side).unwrap();
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
        let port = dev.add_conn(dev_side).unwrap();

        dev.connect(&mem, port);
        assert_eq!(dev.conns[&port].state, ConnState::Offered);
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));
        assert_eq!(dev.conns[&port].state, ConnState::Connected);

        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"hello"));
        assert_eq!(recv(&mut peer, 5).as_deref(), Some(&b"hello"[..]));
        assert_eq!(dev.conns[&port].rx_cnt, 5, "credit accounted");
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
        let port = dev.add_conn(dev_side).unwrap();
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
        let port = dev.add_conn(dev_side).unwrap();
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
        let port = dev.add_conn(dev_side).unwrap();
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

    const BASE: u64 = 0x4000_0000;
    /// A receive buffer the size a Linux guest posts.
    const RXBUF: u32 = (HDR_LEN + MAX_RW) as u32;
    /// The descriptor, avail, used and data addresses `accepted` programs.
    const RINGS: (u64, u64, u64, u64) = (BASE, BASE + 0x200, BASE + 0x400, BASE + 0x1000);

    /// Returns a device with eight `RXBUF` receive buffers posted and one
    /// session the guest accepted with `buf_alloc` of credit.
    ///
    /// The REQUEST takes used slot 0.
    fn accepted(mem: &GuestRam, buf_alloc: u32) -> (VirtioVsock, u32, UnixStream) {
        let mut dev = VirtioVsock::new();
        program_rx_buffers(&mut dev, mem, RINGS, 8, RXBUF);
        let (dev_side, peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side).unwrap();
        dev.connect(mem, port);
        dev.handle_pkt(mem, &credit_pkt(OP_RESPONSE, port, buf_alloc, 0));
        (dev, port, peer)
    }

    /// Feeds `port` host bytes 8 KiB at a time, the way the bridge reads them,
    /// and returns the gate `host_data` hands back.
    ///
    /// # Panics
    ///
    /// Panics once more than `HOST_BACKLOG_MAX` went in without a gate.
    fn fill_until_gated(dev: &mut VirtioVsock, mem: &GuestRam, port: u32) -> Arc<HostGate> {
        let mut queued = 0;
        loop {
            assert!(queued < HOST_BACKLOG_MAX, "the backlog has no bound");
            queued += 8192;
            if let Some(gate) = dev.host_data(mem, port, &[0u8; 8192]) {
                return gate;
            }
        }
    }

    /// Returns the headers of the packets in used slots `1..`.
    fn delivered_hdrs(mem: &GuestRam) -> Vec<Hdr> {
        let (_, _, used, data) = RINGS;
        let completed = mem.read_u16(used + 2).unwrap();
        (1..u64::from(completed))
            .map(|slot| delivered(mem, used, slot, data, RXBUF).0)
            .collect()
    }

    /// Returns the packets in used slots `1..` as `(op, payload length)`.
    fn delivered_since_request(mem: &GuestRam) -> Vec<(u16, usize)> {
        let (_, _, used, data) = RINGS;
        let completed = mem.read_u16(used + 2).unwrap();
        (1..u64::from(completed))
            .map(|slot| {
                let (hdr, body) = delivered(mem, used, slot, data, RXBUF);
                (hdr.op, body.len())
            })
            .collect()
    }

    // A Linux guest resets a connection whose RW packets overrun its
    // buf_alloc. The guest then sees ENOBUFS and the host EPIPE.
    #[test]
    fn host_data_waits_for_the_guests_credit() {
        let mem = mem_of(0x10000);
        let (mut dev, port, _peer) = accepted(&mem, 8192);

        assert!(dev.host_data(&mem, port, &[b'z'; 12000]).is_none());
        assert_eq!(
            delivered_since_request(&mem),
            [(OP_RW, 4096), (OP_RW, 4096)],
            "only the 8 KiB the guest has room for went out"
        );

        // The guest consumed those 8 KiB.
        dev.handle_pkt(&mem, &credit_pkt(OP_CREDIT_UPDATE, port, 8192, 8192));
        assert_eq!(
            delivered_since_request(&mem),
            [(OP_RW, 4096), (OP_RW, 4096), (OP_RW, 12000 - 8192)]
        );
    }

    // Without the gate a guest that grants no credit makes hvi buffer all that
    // the host writes.
    #[test]
    fn full_backlog_closes_the_gate_until_the_guest_takes_bytes() {
        let mem = mem_of(0x10000);
        let (mut dev, port, _peer) = accepted(&mem, 0);

        let gate = fill_until_gated(&mut dev, &mem, port);
        assert!(delivered_since_request(&mem).is_empty());
        let mut polls = 0;
        assert!(
            !gate.wait(|| {
                polls += 1;
                polls < 2
            }),
            "the gate opened without credit"
        );

        dev.handle_pkt(
            &mem,
            &credit_pkt(OP_CREDIT_UPDATE, port, GUEST_BUF_ALLOC, 0),
        );
        assert!(!delivered_since_request(&mem).is_empty());
        assert!(gate.wait(|| false), "taking backlog left the gate closed");
    }

    // The bridge reader passes a predicate that turns false on a host hangup.
    // Checked only after the first timeout, every 8 KiB the reader drains
    // after the hangup would cost a full `GATE_POLL`.
    #[test]
    fn gate_wait_checks_its_predicate_before_sleeping() {
        let gate = HostGate::default();
        gate.close();
        let start = std::time::Instant::now();
        let mut calls = 0;
        assert!(!gate.wait(|| {
            calls += 1;
            false
        }));
        assert_eq!(calls, 1);
        assert!(start.elapsed() < GATE_POLL, "the wait slept first");
    }

    #[test]
    fn ending_a_session_opens_its_gate() {
        let mem = mem_of(0x10000);
        let (mut dev, port, _peer) = accepted(&mem, 0);
        let gate = fill_until_gated(&mut dev, &mem, port);

        dev.handle_pkt(&mem, &pkt(OP_RST, port, &[]));
        assert!(gate.wait(|| false), "the reader would wait forever");
    }

    // The host closing its end must not drop the bytes the guest has no credit
    // for yet.
    #[test]
    fn host_close_delivers_the_backlog_before_the_shutdown() {
        let mem = mem_of(0x10000);
        let (mut dev, port, _peer) = accepted(&mem, 4096);

        assert!(dev.host_data(&mem, port, &[b'q'; 6000]).is_none());
        dev.host_closed(&mem, port);
        assert!(dev.conns.contains_key(&port));
        assert_eq!(delivered_since_request(&mem), [(OP_RW, 4096)]);

        dev.handle_pkt(&mem, &credit_pkt(OP_CREDIT_UPDATE, port, 4096, 4096));
        assert_eq!(
            delivered_since_request(&mem),
            [(OP_RW, 4096), (OP_RW, 6000 - 4096), (OP_SHUTDOWN, 0)]
        );
        assert!(!dev.conns.contains_key(&port));
    }

    #[test]
    fn credit_survives_counter_wrap_and_refuses_a_bogus_fwd_cnt() {
        let mut dev = VirtioVsock::new();
        let (dev_side, _peer) = UnixStream::pair().unwrap();
        let port = dev.add_conn(dev_side).unwrap();
        let conn = dev.conns.get_mut(&port).unwrap();
        conn.peer_buf_alloc = 4096;
        conn.tx_cnt = 10;
        conn.peer_fwd_cnt = u32::MAX - 5; // 16 bytes in flight across the wrap
        assert_eq!(conn.credit(), 4096 - 16);

        // The guest reports one byte more than it was ever sent.
        conn.peer_fwd_cnt = 11;
        assert_eq!(conn.credit(), 0);
    }

    /// Returns a device with one accepted session whose host socket is full,
    /// with the socket's peer and the number of bytes that filled it.
    ///
    /// No RX queue is programmed, so what the device queues for the guest
    /// stays in `pending`, which starts out empty.
    fn host_socket_full() -> (VirtioVsock, u32, UnixStream, usize) {
        use std::io::Write;
        let mem = mem_of(0x1000);
        let mut dev = VirtioVsock::new();
        let (dev_side, peer) = UnixStream::pair().unwrap();
        let mut filler = dev_side.try_clone().unwrap();
        let port = dev.add_conn(dev_side).unwrap();
        dev.connect(&mem, port);
        dev.handle_pkt(&mem, &pkt(OP_RESPONSE, port, &[]));
        dev.pending.clear();

        // A blocking socket would hang the fill below, and a vCPU in a send.
        // SAFETY: F_GETFL reads the flags of a descriptor `filler` owns.
        let flags = unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&filler), libc::F_GETFL) };
        assert!(
            flags & libc::O_NONBLOCK != 0,
            "add_conn left the host socket blocking"
        );
        let mut filled = 0;
        loop {
            match filler.write(&[0u8; 4096]) {
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("filling the host socket: {e}"),
            }
        }
        (dev, port, peer, filled)
    }

    // The vCPU used to write guest bytes to the host with a blocking write
    // under the device lock. A host client that wrote before it read then
    // stopped the vCPU, and with it the guest.
    #[test]
    fn guest_bytes_wait_for_a_full_host_socket_and_hold_back_credit() {
        let mem = mem_of(0x1000);
        let (mut dev, port, mut peer, filled) = host_socket_full();
        let gate = dev.writer_gate(port).unwrap();
        assert!(!gate.wait(|| false), "the writer gate starts closed");

        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"held"));
        assert_eq!(dev.conns[&port].rx_cnt, 0, "credit for bytes not sent");
        assert!(dev.pending.is_empty(), "a credit update went out");
        assert!(gate.wait(|| false), "the writer was not woken");

        // The host reads what filled its socket, and the writer flushes.
        assert!(recv(&mut peer, filled).is_some());
        assert!(dev.flush_to_host(&mem, port));
        assert_eq!(recv(&mut peer, 4).as_deref(), Some(&b"held"[..]));
        let update = Hdr::parse(&dev.pending.pop_front().unwrap()).unwrap();
        assert_eq!((update.op, update.fwd_cnt), (OP_CREDIT_UPDATE, 4));
        assert!(!gate.wait(|| false), "the writer gate stayed open");
    }

    #[test]
    fn guest_overrunning_our_credit_is_reset() {
        let mem = mem_of(0x1000);
        let (mut dev, port, _peer, _) = host_socket_full();
        let full = vec![0u8; OUR_BUF_ALLOC as usize];
        dev.handle_pkt(&mem, &pkt(OP_RW, port, &full));
        assert!(
            dev.conns.contains_key(&port),
            "the credit itself was refused"
        );
        assert!(dev.pending.is_empty());

        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"x"));
        assert!(!dev.conns.contains_key(&port));
        let rst = Hdr::parse(&dev.pending.pop_front().unwrap()).unwrap();
        assert_eq!((rst.op, rst.src_port), (OP_RST, port));
    }

    // Guest writes after the host client had gone used to be credited and
    // dropped, so the guest went on writing into nothing. A shutdown of the
    // guest's sends stops that at once. The reset waits for the reader's EOF,
    // since the socket may still hold host bytes.
    #[test]
    fn guest_write_to_a_closed_host_shuts_down_the_guests_sends() {
        let mem = mem_of(0x10000);
        let (mut dev, port, peer) = accepted(&mem, GUEST_BUF_ALLOC);
        drop(peer);

        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"late"));
        let hdrs = delivered_hdrs(&mem);
        assert_eq!(
            hdrs.iter().map(|h| (h.op, h.flags)).collect::<Vec<_>>(),
            [(OP_SHUTDOWN, SHUTDOWN_RCV), (OP_CREDIT_UPDATE, 0)],
            "the guest can still send"
        );

        // A second failed send changes nothing.
        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"more"));
        dev.host_closed(&mem, port);
        assert!(!dev.conns.contains_key(&port));
        assert_eq!(
            delivered_since_request(&mem),
            [
                (OP_SHUTDOWN, 0),
                (OP_CREDIT_UPDATE, 0),
                (OP_CREDIT_UPDATE, 0),
                (OP_RST, 0)
            ]
        );
    }

    // A guest write after a full host close used to reset the connection
    // while host bytes still waited for the guest, which then read a short
    // input and a plain EOF.
    #[test]
    fn guest_write_after_the_host_has_gone_keeps_the_backlog() {
        let mem = mem_of(0x10000);
        let (mut dev, port, peer) = accepted(&mem, 4096);
        assert!(dev.host_data(&mem, port, &[b'q'; 6000]).is_none());
        drop(peer);

        // The guest still advertises its 4 KiB, so the write grants nothing.
        dev.handle_pkt(&mem, &guest_pkt(OP_RW, port, (4096, 0), b"echo"));
        dev.host_closed(&mem, port);
        assert!(dev.conns.contains_key(&port), "the backlog was dropped");

        // The guest consumed the first 4 KiB.
        dev.handle_pkt(&mem, &credit_pkt(OP_CREDIT_UPDATE, port, 4096, 4096));
        let got = delivered_since_request(&mem);
        let host_bytes: usize = got
            .iter()
            .filter(|&&(op, _)| op == OP_RW)
            .map(|&(_, n)| n)
            .sum();
        assert_eq!(host_bytes, 6000);
        assert_eq!(got.last(), Some(&(OP_RST, 0)));
        assert!(!dev.conns.contains_key(&port));
    }

    // A guest that wrote and closed used to lose what the host socket had not
    // taken yet, and the host read a clean EOF.
    #[test]
    fn guest_close_waits_for_the_host_to_take_its_bytes() {
        let mem = mem_of(0x1000);
        let (mut dev, port, mut peer, filled) = host_socket_full();
        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"tail"));
        dev.handle_pkt(&mem, &pkt(OP_SHUTDOWN, port, &[]));
        assert!(
            dev.conns.contains_key(&port),
            "the guest's tail was dropped"
        );

        assert!(recv(&mut peer, filled).is_some());
        assert!(!dev.flush_to_host(&mem, port), "the writer is still needed");
        assert!(!dev.conns.contains_key(&port));
        assert_eq!(recv(&mut peer, 4).as_deref(), Some(&b"tail"[..]));
        assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0, "the host saw EOF");
    }

    #[test]
    fn host_close_keeps_guest_bytes_the_host_has_not_taken() {
        let mem = mem_of(0x1000);
        let (mut dev, port, mut peer, filled) = host_socket_full();
        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"reply"));
        dev.host_closed(&mem, port);
        let shutdown = Hdr::parse(&dev.pending.pop_front().unwrap()).unwrap();
        assert_eq!(shutdown.op, OP_SHUTDOWN);
        // A Linux guest with nothing left to read answers a full shutdown
        // with OP_RST at once.
        dev.handle_pkt(&mem, &pkt(OP_RST, port, &[]));
        assert!(
            dev.conns.contains_key(&port),
            "the guest's reply was dropped"
        );

        assert!(recv(&mut peer, filled).is_some());
        assert!(!dev.flush_to_host(&mem, port));
        assert_eq!(recv(&mut peer, 5).as_deref(), Some(&b"reply"[..]));
        assert!(!dev.conns.contains_key(&port));
    }

    // A guest that resets after its 8 s close timeout used to take what the
    // host socket had not taken yet with it.
    #[test]
    fn guest_reset_keeps_bytes_the_host_has_not_taken() {
        let mem = mem_of(0x1000);
        let (mut dev, port, mut peer, filled) = host_socket_full();
        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"tail"));
        dev.handle_pkt(&mem, &pkt(OP_RST, port, &[]));
        assert!(
            dev.conns.contains_key(&port),
            "the guest's tail was dropped"
        );

        assert!(recv(&mut peer, filled).is_some());
        assert!(!dev.flush_to_host(&mem, port));
        assert_eq!(recv(&mut peer, 4).as_deref(), Some(&b"tail"[..]));
        assert!(
            dev.pending.is_empty(),
            "a credit update or a reset went back to a guest that reset"
        );
    }

    // Without our reset a Linux guest holds its closed socket for 8 s, then
    // resets it on its own.
    #[test]
    fn guest_close_gets_a_reset_once_its_bytes_are_out() {
        let mem = mem_of(0x10000);
        let (mut dev, port, mut peer) = accepted(&mem, GUEST_BUF_ALLOC);
        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"bye"));
        dev.handle_pkt(
            &mem,
            &shutdown_from_guest(port, SHUTDOWN_RCV | SHUTDOWN_SEND),
        );
        assert!(!dev.conns.contains_key(&port));
        assert_eq!(recv(&mut peer, 3).as_deref(), Some(&b"bye"[..]));
        assert_eq!(delivered_since_request(&mem).last(), Some(&(OP_RST, 0)));
    }

    // hvi still ends both directions when the guest shuts down only its
    // sends. A reset would turn the reply the guest waits for into an EOF
    // that looks complete.
    #[test]
    fn guest_half_close_gets_no_reset() {
        let mem = mem_of(0x10000);
        let (mut dev, port, mut peer) = accepted(&mem, GUEST_BUF_ALLOC);
        dev.handle_pkt(&mem, &pkt(OP_RW, port, b"req"));
        dev.handle_pkt(&mem, &shutdown_from_guest(port, SHUTDOWN_SEND));
        assert_eq!(recv(&mut peer, 3).as_deref(), Some(&b"req"[..]));
        assert!(
            delivered_since_request(&mem)
                .iter()
                .all(|&(op, _)| op != OP_RST),
            "a half-closed guest was reset"
        );
    }

    /// Returns an `OP_SHUTDOWN` from the guest agent carrying `flags`.
    fn shutdown_from_guest(port: u32, flags: u32) -> Vec<u8> {
        let mut h = Hdr::parse(&pkt(OP_SHUTDOWN, port, &[])).unwrap();
        h.flags = flags;
        h.to_bytes().to_vec()
    }

    #[test]
    fn writer_gate_wait_open_returns_once_opened() {
        let gate = Arc::new(HostGate::new_closed());
        let opener = Arc::clone(&gate);
        let waiter = std::thread::spawn(move || gate.wait_open());
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiter.is_finished(),
            "a closed gate let the writer through"
        );
        opener.open();
        waiter.join().unwrap();
    }

    #[test]
    fn writer_gates_open_as_they_drop() {
        let gate = Arc::new(HostGate::new_closed());
        let gates = WriterGates(vec![Arc::clone(&gate)]);
        let waiter = std::thread::spawn(move || gate.wait_open());
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiter.is_finished(),
            "a closed gate let the writer through"
        );
        drop(gates);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !waiter.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(waiter.is_finished(), "a dropped list left its gate closed");
        waiter.join().unwrap();
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;
    use crate::devices::irq::test_line::LevelLine;

    const BASE: u64 = 0x4000_0000;
    const RX_DESC: u64 = BASE;
    const RX_AVAIL: u64 = BASE + 0x1000;
    const RX_USED: u64 = BASE + 0x2000;
    /// Where the RX buffers posted by `post_rx` start, 0x100 apart.
    const RX_BUFS: u64 = BASE + 0x8000;

    fn mem() -> GuestRam {
        GuestRam::from_ranges(&[(BASE, 0x10000)])
    }

    /// Programs `queue` as a driver does, with 8 entries.
    fn program(dev: &mut VirtioVsock, mem: &GuestRam, queue: u16, rings: u64) {
        dev.mmio(mem, mmio::QUEUE_SEL, true, u64::from(queue));
        dev.mmio(mem, mmio::QUEUE_NUM, true, 8);
        dev.mmio(mem, mmio::QUEUE_DESC_LOW, true, rings);
        dev.mmio(mem, mmio::QUEUE_DRIVER_LOW, true, rings + 0x1000);
        dev.mmio(mem, mmio::QUEUE_DEVICE_LOW, true, rings + 0x2000);
        dev.mmio(mem, mmio::QUEUE_READY, true, 1);
    }

    /// Posts `n` RX buffers of 0x100 bytes each.
    fn post_rx(mem: &GuestRam, n: u16) {
        for i in 0..n {
            let d = RX_DESC + u64::from(i) * 16;
            mem.write_u64(d, RX_BUFS + u64::from(i) * 0x100).unwrap();
            mem.write_u32(d + 8, 0x100).unwrap();
            mem.write_u16(d + 12, VIRTQ_DESC_F_WRITE).unwrap();
            mem.write_u16(RX_AVAIL + 4 + u64::from(i) * 2, i).unwrap();
        }
        mem.write_u16(RX_AVAIL + 2, n).unwrap();
    }

    /// Returns the op and payload of every packet the device put in the RX
    /// buffers `post_rx` posted.
    fn received(mem: &GuestRam) -> Vec<(u16, Vec<u8>)> {
        let used = mem.read_u16(RX_USED + 2).unwrap();
        (0..used)
            .map(|i| {
                let mut b = vec![0u8; 0x100];
                mem.read(RX_BUFS + u64::from(i) * 0x100, &mut b).unwrap();
                let h = Hdr::parse(&b).unwrap();
                (h.op, b[HDR_LEN..HDR_LEN + h.len as usize].to_vec())
            })
            .collect()
    }

    /// A guest-to-host packet from the agent to `port`.
    fn from_guest(op: u16, port: u32, body: &[u8]) -> Vec<u8> {
        let mut p = Hdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: AGENT_PORT,
            dst_port: port,
            len: body.len() as u32,
            typ: TYPE_STREAM,
            op,
            buf_alloc: 256 * 1024,
            ..Hdr::default()
        }
        .to_bytes()
        .to_vec();
        p.extend_from_slice(body);
        p
    }

    /// A device with ready queues and no RX buffer posted, holding one
    /// connection the guest accepted and whose host sent bytes, one the guest
    /// was only offered, and the `OP_REQUEST` for each still waiting.
    fn busy(mem: &GuestRam) -> (VirtioVsock, [UnixStream; 2]) {
        let mut dev = VirtioVsock::new();
        dev.mmio(mem, mmio::STATUS, true, 0xf);
        program(&mut dev, mem, RX_QUEUE, RX_DESC);
        program(&mut dev, mem, TX_QUEUE, BASE + 0x3000);
        let (a, a_peer) = UnixStream::pair().unwrap();
        let (b, b_peer) = UnixStream::pair().unwrap();
        let accepted = dev.add_conn(a).unwrap();
        dev.connect(mem, accepted);
        let offered = dev.add_conn(b).unwrap();
        dev.connect(mem, offered);
        dev.handle_pkt(mem, &from_guest(OP_RESPONSE, accepted, &[]));
        dev.host_data(mem, accepted, b"from the host");
        (dev, [a_peer, b_peer])
    }

    #[test]
    fn state_round_trips_through_json_and_a_restored_device() {
        let mem = mem();
        let (dev, _peers) = busy(&mem);
        let state = dev.state();
        assert_eq!(state.pending.len(), 2, "both requests wait for a buffer");
        assert_eq!(state.conns.len(), 2);
        assert!(state.conns.windows(2).all(|w| w[0].port < w[1].port));
        assert_eq!(state.conns[0].state, VsockConnPhase::Connected);
        assert_eq!(state.conns[0].backlog, b"from the host");
        assert_eq!(state.conns[1].state, VsockConnPhase::Offered);

        let json = serde_json::to_string(&state).unwrap();
        let back: VsockState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
        let restored = VirtioVsock::restore(&mem, &back).unwrap();
        assert_eq!(restored.state(), state);
        assert_eq!(serde_json::to_string(&restored.state()).unwrap(), json);
    }

    /// The host end of every connection stayed on the source host, so
    /// `end_restored_conns` ends each one as a host that went away ends it:
    /// the guest gets the host bytes the device held, then `OP_RST`, and the
    /// connection is dropped. Guest bytes that had not reached the host come
    /// back as credit. The restore itself writes nothing to guest RAM.
    #[test]
    fn restored_connections_end_through_the_host_gone_path() {
        let mem = mem();
        let (dev, _peers) = busy(&mem);
        let mut state = dev.state();
        state.conns[0].to_host = b"never sent".to_vec();
        let accepted = state.conns[0].port;
        let rx_before = state.conns[0].rx_cnt;

        // Buffers for everything: the two `OP_REQUEST` packets, then what the
        // restore sends for each connection.
        post_rx(&mem, 8);
        let mut restored = VirtioVsock::restore(&mem, &state).unwrap();
        assert!(received(&mem).is_empty(), "the restore wrote guest RAM");
        restored.end_restored_conns(&mem);
        let got = received(&mem);
        let ops: Vec<u16> = got.iter().map(|(op, _)| *op).collect();
        assert_eq!(
            ops,
            [
                OP_REQUEST,
                OP_REQUEST,
                OP_SHUTDOWN,
                OP_CREDIT_UPDATE,
                OP_RW,
                OP_RST,
                OP_SHUTDOWN,
                OP_RST,
            ]
        );
        assert_eq!(got[4].1, b"from the host", "the held host bytes arrive");
        let credit = Hdr::parse(&{
            let mut b = vec![0u8; HDR_LEN];
            mem.read(RX_BUFS + 3 * 0x100, &mut b).unwrap();
            b
        })
        .unwrap();
        assert_eq!(credit.src_port, accepted);
        assert_eq!(
            credit.fwd_cnt,
            rx_before + b"never sent".len() as u32,
            "the dropped guest bytes are credited back"
        );
        let after = restored.state();
        assert!(after.conns.is_empty(), "every connection was dropped");
        assert!(after.pending.is_empty());
        assert_eq!(
            after.next_port, state.next_port,
            "new ports do not reuse old"
        );

        let line = Arc::new(LevelLine::default());
        restored.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
        assert!(line.is_high(), "the delivered packets raise the line");
        assert_eq!(line.raises(), 1);
    }

    /// The guest never heard of a connection still `New`, so it gets nothing.
    #[test]
    fn a_restored_connection_the_guest_was_never_offered_ends_silently() {
        let mem = mem();
        let mut dev = VirtioVsock::new();
        program(&mut dev, &mem, RX_QUEUE, RX_DESC);
        let (a, _peer) = UnixStream::pair().unwrap();
        dev.add_conn(a).unwrap();
        let state = dev.state();
        assert_eq!(state.conns[0].state, VsockConnPhase::New);

        post_rx(&mem, 2);
        let mut restored = VirtioVsock::restore(&mem, &state).unwrap();
        restored.end_restored_conns(&mem);
        assert!(received(&mem).is_empty());
        assert!(restored.state().conns.is_empty());
        assert_eq!(restored.state().common.interrupt_status, 0);
    }

    #[test]
    fn connecting_a_quiet_restored_device_leaves_its_line_alone() {
        let mem = mem();
        let mut restored = VirtioVsock::restore(&mem, &VirtioVsock::new().state()).unwrap();
        let line = Arc::new(LevelLine::default());
        restored.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
        assert_eq!(line.sets(), 0);
    }

    /// Returns the error kind `restore` refuses `state` with, or `None`, and
    /// checks that `VsockState::check` agrees.
    fn refused(state: &VsockState) -> Option<std::io::ErrorKind> {
        let mem = mem();
        let kind = VirtioVsock::restore(&mem, state).err().map(|e| e.kind());
        assert_eq!(state.check(&mem).err().map(|e| e.kind()), kind);
        kind
    }

    /// A waiting packet the device could not have framed is refused: one
    /// shorter than a header would stop `fill_rx` on its `expect`, one past
    /// the largest RW the device frames or with a header length it does not
    /// carry would hand the guest a packet it cannot trust.
    #[test]
    fn waiting_packets_the_device_never_frames_are_refused() {
        let good = VirtioVsock::new().state();
        let rw = |len: u32, body: usize| {
            let mut p = Hdr {
                len,
                op: OP_RW,
                ..Hdr::default()
            }
            .to_bytes()
            .to_vec();
            p.resize(HDR_LEN + body, 0);
            p
        };
        let largest = rw(MAX_RW as u32, MAX_RW);
        assert_eq!(
            refused(&VsockState {
                pending: vec![largest],
                ..good.clone()
            }),
            None,
            "the largest RW the device frames is fine"
        );
        for pending in [
            vec![vec![0u8; HDR_LEN - 1]],
            vec![rw(MAX_RW as u32 + 1, MAX_RW + 1)],
            vec![rw(10, 9)],
            vec![rw(0, 0); RESTORE_MAX_PENDING + 1],
            vec![rw(MAX_RW as u32, MAX_RW); RESTORE_MAX_PENDING_BYTES / (HDR_LEN + MAX_RW) + 1],
        ] {
            let state = VsockState {
                pending,
                ..good.clone()
            };
            assert_eq!(refused(&state), Some(std::io::ErrorKind::InvalidData));
        }
    }

    #[test]
    fn connections_the_device_could_not_have_held_are_refused() {
        let mem = mem();
        let (dev, _peers) = busy(&mem);
        let good = dev.state();
        let conn = good.conns[0].clone();
        let with = |conns: Vec<VsockConnState>| VsockState {
            conns,
            ..good.clone()
        };
        let backlog = |len: usize| VsockConnState {
            backlog: vec![0; len],
            ..conn.clone()
        };
        // A host that hung up drains its socket past the live gate.
        assert_eq!(refused(&with(vec![backlog(HOST_BACKLOG_MAX + 1)])), None);
        assert_eq!(refused(&with(vec![backlog(RESTORE_MAX_BACKLOG)])), None);
        let to_host = |len: usize| VsockConnState {
            to_host: vec![0; len],
            ..conn.clone()
        };
        assert_eq!(refused(&with(vec![to_host(OUR_BUF_ALLOC as usize)])), None);

        let port = |port: u32| VsockConnState {
            port,
            ..conn.clone()
        };
        let many: Vec<VsockConnState> = (0..=RESTORE_MAX_CONNS as u32).map(port).collect();
        for bad in [
            with(vec![backlog(RESTORE_MAX_BACKLOG + 1)]),
            with(vec![to_host(OUR_BUF_ALLOC as usize + 1)]),
            with(vec![conn.clone(), conn.clone()]),
            with(vec![port(good.next_port)]),
            with(many),
        ] {
            assert_eq!(refused(&bad), Some(std::io::ErrorKind::InvalidData));
        }
    }

    /// A restored counter near the end of the port space runs out the way a
    /// device that climbed there would: the last port is handed out, and the
    /// next client is refused rather than given a port that wrapped.
    #[test]
    fn a_device_out_of_host_ports_refuses_a_new_connection() {
        let mut state = VirtioVsock::new().state();
        state.next_port = u32::MAX - 1;
        let mut dev = VirtioVsock::restore(&mem(), &state).unwrap();
        let (a, _a_peer) = UnixStream::pair().unwrap();
        let (b, _b_peer) = UnixStream::pair().unwrap();
        assert_eq!(dev.add_conn(a).unwrap(), u32::MAX - 1);
        assert!(dev.add_conn(b).is_err(), "the port counter wrapped");
        assert_eq!(dev.state().conns.len(), 1);

        state.next_port = u32::MAX;
        assert_eq!(refused(&state), None, "a device that ran out restores");
    }

    /// A new client never takes over a session at a port still in use.
    #[test]
    fn a_new_connection_never_replaces_a_live_one() {
        let mem = mem();
        let (mut dev, _peers) = busy(&mem);
        let live = dev.state().conns[0].port;
        dev.next_port = live;
        let (c, _c_peer) = UnixStream::pair().unwrap();
        assert!(dev.add_conn(c).is_err());
        let after = dev.state();
        assert_eq!(after.conns[0].port, live);
        assert_eq!(after.conns[0].state, VsockConnPhase::Connected);
        assert_eq!(after.next_port, live, "a refused client takes no port");
    }

    /// A guest that posts no RX buffer and floods credit requests gets one
    /// credit update waiting, kept up to date, and its device can still be
    /// checkpointed.
    #[test]
    fn a_credit_flood_leaves_one_update_waiting() {
        let mem = mem();
        let (mut dev, _peers) = busy(&mem);
        let accepted = dev.state().conns[0].port;
        for _ in 0..RESTORE_MAX_PENDING + 10 {
            dev.handle_pkt(&mem, &from_guest(OP_CREDIT_REQUEST, accepted, &[]));
        }
        assert_eq!(dev.state().pending.len(), 3, "two requests, one update");

        // A host that went away turns every guest send into credit.
        dev.host_gone(&mem, accepted);
        let rx_before = dev.state().conns[0].rx_cnt;
        for _ in 0..1000 {
            dev.handle_pkt(&mem, &from_guest(OP_RW, accepted, b"0123456789"));
        }
        let state = dev.state();
        let ops: Vec<u16> = state
            .pending
            .iter()
            .map(|p| Hdr::parse(p).unwrap().op)
            .collect();
        assert_eq!(
            ops,
            [
                OP_REQUEST,
                OP_REQUEST,
                OP_CREDIT_UPDATE,
                OP_SHUTDOWN,
                OP_CREDIT_UPDATE
            ]
        );
        let last = Hdr::parse(state.pending.last().unwrap()).unwrap();
        assert_eq!(
            last.fwd_cnt,
            rx_before + 10_000,
            "the update carries the newest count"
        );
        assert_eq!(refused(&state), None, "the device can be checkpointed");
    }

    /// A guest that connects in a loop without posting an RX buffer stops
    /// getting resets once enough packets wait, so its device can still be
    /// checkpointed.
    #[test]
    fn a_connect_flood_is_answered_only_so_far() {
        let mem = mem();
        let (mut dev, _peers) = busy(&mem);
        for port in 0..RESTORE_MAX_PENDING as u32 + 10 {
            dev.handle_pkt(&mem, &from_guest(OP_REQUEST, port, &[]));
        }
        let state = dev.state();
        assert_eq!(state.pending.len(), REFUSALS_PENDING_MAX);
        assert_eq!(refused(&state), None, "the device can be checkpointed");
    }

    /// A host that keeps opening and closing connections to a guest that reads
    /// none of them grows the waiting packets without bound. The capture's
    /// check refuses that device, so the checkpoint fails while the guest can
    /// still run on, and a restore would refuse it the same way.
    #[test]
    fn a_device_past_the_restore_limits_fails_the_capture_check() {
        let mem = mem();
        let (mut dev, _peers) = busy(&mem);
        for _ in 0..RESTORE_MAX_PENDING / 2 + 1 {
            let (a, _a_peer) = UnixStream::pair().unwrap();
            let port = dev.add_conn(a).unwrap();
            dev.connect(&mem, port);
            dev.host_closed(&mem, port);
        }
        let state = dev.state();
        assert!(state.pending.len() > RESTORE_MAX_PENDING);
        assert_eq!(state.conns.len(), 2, "every churned connection was dropped");
        let err = state.check(&mem).err();
        assert_eq!(err.map(|e| e.kind()), Some(std::io::ErrorKind::InvalidData));
        assert_eq!(refused(&state), Some(std::io::ErrorKind::InvalidData));
    }

    #[test]
    fn a_queue_outside_the_restored_ram_or_another_version_is_refused() {
        let mem = mem();
        let (dev, _peers) = busy(&mem);
        let state = dev.state();
        let small = GuestRam::from_ranges(&[(BASE, 0x1000)]);
        let err = VirtioVsock::restore(&small, &state).err();
        assert_eq!(err.map(|e| e.kind()), Some(std::io::ErrorKind::InvalidData));
        let other = VsockState {
            version: 2,
            ..state
        };
        assert_eq!(refused(&other), Some(std::io::ErrorKind::InvalidData));
    }
}

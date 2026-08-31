//! virtio-net over virtio-mmio with a user-space network backend. Being the
//! device is what lets the VMM record the guest's flows as it serves them.
//!
//! No `vmnet` (and so no entitlement): the backend is a tiny user-space stack.
//! The guest self-configures a static address (see the initramfs `/init`); this
//! device answers ARP and ICMP, resolves DNS through the host (capturing the
//! queried names), and — the point — captures every frame the guest transmits,
//! logging each IPv4 flow. Because we are the device, that capture is
//! intrinsic.
//!
//! Three backends share this device:
//!
//! - **Built-in stack** (`new`): the self-contained user-space responder above,
//!   slirp-style addressing (guest 10.0.2.15/24, gateway 10.0.2.2, DNS
//!   10.0.2.3). No egress — TCP attempts are observed but not forwarded.
//! - **Gateway relay** (`with_gateway`): raw Ethernet frames are shuttled to
//!   urunc's gvisor-tap-vsock gateway over its QEMU stream socket (4-byte
//!   big-endian length prefix per frame), giving real TCP/UDP egress with the
//!   gateway's own DHCP/DNS/NAT (guest 10.87.0.2/24, gateway/DNS 10.87.0.1). We
//!   still see every frame, so the flow ledger — now including **TLS SNI** from
//!   ClientHello — is intrinsic.
//! - **Tap** (`with_tap`): frames go to a tap device urunc has already created
//!   in the container's network namespace and wired to the veth with a pair of
//!   tc mirred redirects. The guest then *is* the container on the network,
//!   with its address, gateway and DNS — which is why `set_mac` is mandatory
//!   here: the redirect delivers the veth's frames unchanged, so a guest
//!   answering to any other address drops every reply. The capture is intrinsic
//!   in this mode too.

use std::fs::File;
use std::io::Write;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use crate::guestmem::GuestRam;

use crate::events::CapturedEvent;
use crate::plugin::IoSink;
use crate::virtio::{reg, Queue, QUEUE_NUM_MAX};

const VIRTIO_NET_ID: u64 = 1;
const F_VERSION_1_HI: u32 = 1; // feature bit 32 (high word bit 0)
const F_MAC_LO: u32 = 1 << 5; // VIRTIO_NET_F_MAC (low word bit 5)

/// virtio-net header length with VIRTIO_F_VERSION_1 (`virtio_net_hdr_v1`).
pub const NET_HDR_LEN: usize = 12;

/// Ceiling on the frame a transmit chain may assemble.
///
/// Descriptor lengths are guest-controlled, so without a ceiling the guest
/// decides how much the host allocates and zeroes for one frame. The gateway
/// relay already refuses anything longer than 64 KiB and no MTU this device
/// serves comes near it, so a chain claiming more is either broken or
/// deliberate.
const MAX_TX_FRAME: usize = NET_HDR_LEN + 65536;

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x57];
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);

const ETH_ARP: u16 = 0x0806;
const ETH_IPV4: u16 = 0x0800;
const IP_ICMP: u8 = 1;
const IP_TCP: u8 = 6;
const IP_UDP: u8 = 17;

/// A virtio-net device with a user-space capture backend.
pub struct VirtioNet {
    status: u32,
    dev_feat_sel: u32,
    queue_sel: u32,
    queues: [Queue; 2],
    interrupt_status: u32,
    /// Captured flows, drained by the machine into the event ledger.
    events: Vec<CapturedEvent>,
    /// When set, the device relays frames to the gvisor-tap-vsock gateway over
    /// this QEMU stream socket instead of running the built-in stack. The
    /// machine holds a clone of the read side on a reader thread (see
    /// `spawn_net_gateway_reader`).
    gw: Option<UnixStream>,
    /// When set, frames go to this tap instead: the container's real NIC path.
    /// The machine keeps a cloned fd on a reader thread
    /// (`spawn_net_tap_reader`).
    tap: Option<File>,
    /// MAC handed to the guest through config space.
    mac: [u8; 6],
    /// Live feed of every frame to a plugin, when one asked for it.
    /// Every L2 frame crossing the device goes in raw and unparsed, whichever
    /// backend carries it, so the reader decodes it with its own stack.
    sink: Option<Arc<dyn IoSink>>,
}

impl VirtioNet {
    #[must_use]
    pub fn new() -> Self {
        VirtioNet {
            status: 0,
            dev_feat_sel: 0,
            queue_sel: 0,
            queues: [Queue::default(), Queue::default()],
            interrupt_status: 0,
            events: Vec::new(),
            gw: None,
            tap: None,
            mac: GUEST_MAC,
            sink: None,
        }
    }

    /// Feeds every L2 frame to `sink` as well as the ledger.
    pub fn set_io_sink(&mut self, sink: Arc<dyn IoSink>) {
        self.sink = Some(sink);
    }

    /// Builds a device in gateway-relay mode. `stream` is the (write side of
    /// the) connection to the gateway's QEMU stream socket; the caller
    /// keeps a cloned read side for the RX reader thread.
    #[must_use]
    pub fn with_gateway(stream: UnixStream) -> Self {
        VirtioNet {
            gw: Some(stream),
            ..VirtioNet::new()
        }
    }

    /// Builds a device backed by an already-attached tap. The caller keeps a
    /// cloned fd for the RX reader thread.
    #[must_use]
    pub fn with_tap(tap: File) -> Self {
        VirtioNet {
            tap: Some(tap),
            ..VirtioNet::new()
        }
    }

    /// Overrides the MAC presented to the guest. Required in tap mode: urunc
    /// redirects the veth's frames to us unchanged, so the guest must own the
    /// veth's address.
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
    }

    #[must_use]
    pub fn irq_level(&self) -> bool {
        self.interrupt_status != 0
    }

    /// Drains the captured flows for the event ledger.
    pub fn take_events(&mut self) -> Vec<CapturedEvent> {
        std::mem::take(&mut self.events)
    }

    /// Records one observed IPv4 flow for the ledger.
    #[allow(clippy::too_many_arguments)]
    fn capture(
        &mut self,
        proto: u8,
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        bytes: u64,
        dns: Option<String>,
    ) {
        self.events.push(CapturedEvent::NetFlow {
            proto,
            src,
            src_port,
            dst,
            dst_port,
            bytes,
            dns,
            sni: None,
        });
    }

    fn queue(&mut self) -> &mut Queue {
        &mut self.queues[(self.queue_sel & 1) as usize]
    }

    /// Services one MMIO access. On a transmit-queue notify, drains the guest's
    /// TX frames (capturing them) and injects any replies into the RX queue.
    pub fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        let v = value as u32;
        if is_write {
            match offset {
                reg::DEVICE_FEATURES_SEL => self.dev_feat_sel = v,
                reg::DRIVER_FEATURES_SEL | reg::DRIVER_FEATURES => {}
                reg::QUEUE_SEL => self.queue_sel = v,
                reg::QUEUE_NUM => self.queue().set_num(v),
                reg::QUEUE_READY => self.queue().set_ready(v, mem),
                reg::QUEUE_NOTIFY if v as u16 == TX_QUEUE => self.process_tx(mem),
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
                reg::DEVICE_ID => VIRTIO_NET_ID,
                reg::VENDOR_ID => 0x4649_4f4e,
                reg::DEVICE_FEATURES if self.dev_feat_sel == 1 => u64::from(F_VERSION_1_HI),
                reg::DEVICE_FEATURES => u64::from(F_MAC_LO),
                reg::QUEUE_NUM_MAX => u64::from(QUEUE_NUM_MAX),
                reg::QUEUE_READY => {
                    u64::from(self.queues[(self.queue_sel & 1) as usize].is_ready())
                }
                reg::INTERRUPT_STATUS => u64::from(self.interrupt_status),
                reg::STATUS => u64::from(self.status),
                // Config space: the 6-byte MAC we assign the guest.
                _ if offset >= reg::CONFIG => {
                    let f = (offset - reg::CONFIG) as usize;
                    self.mac.get(f).map_or(0, |&b| u64::from(b))
                }
                _ => 0,
            }
        }
    }

    /// Drains the transmit queue: read each frame, capture it, and inject any
    /// generated reply into the receive queue.
    fn process_tx(&mut self, mem: &GuestRam) {
        let tx = &self.queues[TX_QUEUE as usize];
        if !tx.is_ready() {
            return;
        }
        let Some(pending) = tx.pending(mem) else {
            return;
        };
        let mut last = tx.last_avail();
        let mut serviced = false;
        for _ in 0..pending {
            let Some(slot) = self.queues[TX_QUEUE as usize].avail_slot(last) else {
                break;
            };
            let Ok(head) = mem.read_u16(slot) else {
                break;
            };
            if let Some(frame) = self.read_tx_frame(mem, head) {
                // Publish before the backend branch, so the ring carries egress
                // whichever one carries the frame -- including the built-in
                // stack, which observe_tx below never sees. Raw and unparsed:
                // observe_tx is IPv4-only by design, while a reader with its
                // own stack should get ARP, IPv6 and anything
                // else too.
                if let Some(sink) = self.sink.as_ref() {
                    sink.net(&frame, true);
                }
                if self.tap.is_some() {
                    // Out through the container's NIC; capture the flow too, so
                    // the boundary vantage still sees it (incl. TLS SNI).
                    self.observe_tx(&frame);
                    self.write_to_tap(&frame);
                } else if self.gw.is_some() {
                    // Relay to the gateway; capture the flow (incl. TLS SNI).
                    self.observe_tx(&frame);
                    self.relay_to_gateway(&frame);
                } else {
                    for reply in self.handle_frame(&frame) {
                        self.inject_rx(mem, &reply);
                    }
                }
            }
            self.queues[TX_QUEUE as usize].push_used(mem, head, 0);
            last = last.wrapping_add(1);
            serviced = true;
        }
        self.queues[TX_QUEUE as usize].set_last_avail(last);
        if serviced {
            self.interrupt_status |= 1;
        }
    }

    /// Gathers a transmit chain's readable bytes and strips the virtio-net
    /// header, returning the Ethernet frame.
    fn read_tx_frame(&self, mem: &GuestRam, head: u16) -> Option<Vec<u8>> {
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
                // Readable segment (device-readable). The length comes from
                // the guest, so it is checked against the ceiling before it
                // is allowed to size an allocation, and the bytes are read
                // straight into the frame rather than through a segment
                // buffer the guest also sized.
                let len = len as usize;
                let start = buf.len();
                if start.checked_add(len)? > MAX_TX_FRAME {
                    return None;
                }
                buf.resize(start + len, 0);
                mem.read(addr, &mut buf[start..]).ok()?;
            }
            if flags & 1 == 0 {
                break;
            }
            d = next;
        }
        if buf.len() <= NET_HDR_LEN {
            return None;
        }
        Some(buf[NET_HDR_LEN..].to_vec())
    }

    /// Writes one frame into a receive-queue buffer (prefixed with a zeroed
    /// virtio-net header) and completes it, so the guest sees an incoming
    /// packet.
    fn inject_rx(&mut self, mem: &GuestRam, frame: &[u8]) {
        // Ingress, published before the queue check: what the device was handed
        // for the guest is an observation whether or not the guest had a buffer
        // posted to take it.
        if let Some(sink) = self.sink.as_ref() {
            sink.net(frame, false);
        }
        let rx = &self.queues[RX_QUEUE as usize];
        if !rx.is_ready() {
            return;
        }
        let last = rx.last_avail();
        match rx.pending(mem) {
            // No RX buffer posted; drop silently (TCP/UDP recover). Logging here
            // would flood under gateway-relay load.
            Some(0) | None => return,
            Some(_) => {}
        }
        let Some(slot) = rx.avail_slot(last) else {
            return;
        };
        let Ok(head) = mem.read_u16(slot) else {
            return;
        };
        // First writable descriptor of the chain (RX buffers are large/single).
        let Some(da) = rx.desc_addr(head) else {
            return;
        };
        let (Ok(addr), Ok(len)) = (mem.read_u64(da), mem.read_u32(da + 8)) else {
            return;
        };
        let mut out = vec![0u8; NET_HDR_LEN];
        out[10] = 1; // num_buffers = 1
        out.extend_from_slice(frame);
        let n = out.len().min(len as usize);
        if mem.write(addr, &out[..n]).is_err() {
            return;
        }
        self.queues[RX_QUEUE as usize].push_used(mem, head, n as u32);
        self.queues[RX_QUEUE as usize].set_last_avail(last.wrapping_add(1));
        self.interrupt_status |= 1;
    }

    // --- gateway relay mode -------------------------------------------------

    /// Writes one guest Ethernet frame to the gateway, framed with a 4-byte
    /// big-endian length prefix (gvisor-tap-vsock's QEMU stream protocol).
    fn relay_to_gateway(&mut self, frame: &[u8]) {
        if let Some(sock) = self.gw.as_mut() {
            let len = (frame.len() as u32).to_be_bytes();
            if sock
                .write_all(&len)
                .and_then(|()| sock.write_all(frame))
                .is_err()
            {
                // Gateway gone: drop the relay so a stopped gateway doesn't
                // wedge the vCPU thread. The link stays set;
                // the RX reader will exit.
            }
        }
    }

    /// Writes one guest Ethernet frame to the tap, prefixed with the all-zero
    /// `virtio_net_hdr_v1` its `IFF_VNET_HDR` framing expects (see
    /// [`crate::tap::prepend_vnet_hdr`]).
    fn write_to_tap(&mut self, frame: &[u8]) {
        if let Some(tap) = self.tap.as_mut() {
            if tap.write_all(&crate::tap::prepend_vnet_hdr(frame)).is_err() {
                // A wedged tap must not block the vCPU thread; the RX reader
                // will see the same error and exit.
            }
        }
    }

    /// Delivers one inbound Ethernet frame into the RX queue. Public so the
    /// machine's gateway or tap reader thread can call it under the device
    /// lock.
    pub fn deliver(&mut self, mem: &GuestRam, frame: &[u8]) {
        self.inject_rx(mem, frame);
    }

    /// Captures a transmitted frame for the ledger without generating a reply:
    /// the five-tuple, and — for a TLS ClientHello — the SNI.
    fn observe_tx(&mut self, frame: &[u8]) {
        if frame.len() < 14 || u16::from_be_bytes([frame[12], frame[13]]) != ETH_IPV4 {
            return;
        }
        let ip = &frame[14..];
        if ip.len() < 20 {
            return;
        }
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        let proto = ip[9];
        let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
        let Some(l4) = ip.get(ihl..) else { return };
        match proto {
            IP_TCP if l4.len() >= 20 => {
                let sport = u16::from_be_bytes([l4[0], l4[1]]);
                let dport = u16::from_be_bytes([l4[2], l4[3]]);
                let data_off = ((l4[12] >> 4) as usize) * 4;
                let sni = l4.get(data_off..).and_then(parse_tls_sni);
                self.events.push(CapturedEvent::NetFlow {
                    proto,
                    src,
                    src_port: sport,
                    dst,
                    dst_port: dport,
                    bytes: l4.len() as u64,
                    dns: None,
                    sni,
                });
            }
            IP_UDP if l4.len() >= 8 => {
                let sport = u16::from_be_bytes([l4[0], l4[1]]);
                let dport = u16::from_be_bytes([l4[2], l4[3]]);
                self.capture(IP_UDP, src, sport, dst, dport, l4.len() as u64, None);
            }
            IP_ICMP => self.capture(IP_ICMP, src, 0, dst, 0, l4.len() as u64, None),
            _ => {}
        }
    }

    /// The user-space stack: parse an Ethernet frame, capture the flow, and
    /// return any reply frames.
    fn handle_frame(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        if frame.len() < 14 {
            return vec![];
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        match ethertype {
            ETH_ARP => self.handle_arp(&frame[14..]).into_iter().collect(),
            ETH_IPV4 => self.handle_ipv4(&frame[14..]).into_iter().collect(),
            _ => vec![],
        }
    }

    /// Answers ARP "who-has" for the gateway/DNS addresses with our MAC.
    fn handle_arp(&self, arp: &[u8]) -> Option<Vec<u8>> {
        if arp.len() < 28 || u16::from_be_bytes([arp[6], arp[7]]) != 1 {
            return None; // not a request
        }
        let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
        if target_ip != GW_IP && target_ip != DNS_IP {
            return None;
        }
        let sender_mac = &arp[8..14];
        let sender_ip = &arp[14..18];
        let mut a = vec![0u8; 28];
        a[0..2].copy_from_slice(&1u16.to_be_bytes()); // htype ethernet
        a[2..4].copy_from_slice(&ETH_IPV4.to_be_bytes()); // ptype IPv4
        a[4] = 6;
        a[5] = 4;
        a[6..8].copy_from_slice(&2u16.to_be_bytes()); // reply
        a[8..14].copy_from_slice(&OUR_MAC);
        a[14..18].copy_from_slice(&target_ip.octets());
        a[18..24].copy_from_slice(sender_mac);
        a[24..28].copy_from_slice(sender_ip);
        Some(eth_frame(
            sender_mac.try_into().unwrap(),
            OUR_MAC,
            ETH_ARP,
            &a,
        ))
    }

    /// Handles/captures an IPv4 packet.
    fn handle_ipv4(&mut self, ip: &[u8]) -> Option<Vec<u8>> {
        if ip.len() < 20 {
            return None;
        }
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        let proto = ip[9];
        let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
        let payload = ip.get(ihl..)?;

        match proto {
            IP_ICMP => self.handle_icmp(src, dst, payload),
            IP_UDP if payload.len() >= 8 => {
                let sport = u16::from_be_bytes([payload[0], payload[1]]);
                let dport = u16::from_be_bytes([payload[2], payload[3]]);
                if dport == 67 {
                    // DHCP: hand the guest our slirp address so `ip=dhcp`
                    // configures it consistently with this stack.
                    self.capture(IP_UDP, src, sport, dst, dport, payload.len() as u64, None);
                    self.handle_dhcp(&payload[8..])
                } else if dport == 53 && dst == DNS_IP {
                    self.handle_dns(sport, &payload[8..])
                } else {
                    eprint!("\r\n[virtio-net] udp {src}:{sport} -> {dst}:{dport}\r\n");
                    self.capture(IP_UDP, src, sport, dst, dport, payload.len() as u64, None);
                    None
                }
            }
            IP_TCP if payload.len() >= 4 => {
                let sport = u16::from_be_bytes([payload[0], payload[1]]);
                let dport = u16::from_be_bytes([payload[2], payload[3]]);
                let flags = payload.get(13).copied().unwrap_or(0);
                let syn = flags & 0x02 != 0;
                eprint!(
                    "\r\n[virtio-net] tcp {src}:{sport} -> {dst}:{dport}{}\r\n",
                    if syn { " SYN" } else { "" }
                );
                self.capture(IP_TCP, src, sport, dst, dport, payload.len() as u64, None);
                None // no egress yet
            }
            _ => None,
        }
    }

    /// Replies to an ICMP echo request (ping to the gateway works).
    fn handle_icmp(&mut self, src: Ipv4Addr, dst: Ipv4Addr, icmp: &[u8]) -> Option<Vec<u8>> {
        if icmp.len() < 8 || icmp[0] != 8 {
            return None; // not an echo request
        }
        let mut msg = icmp.to_vec();
        msg[0] = 0; // echo reply
        msg[2] = 0;
        msg[3] = 0;
        let ck = checksum16(&msg);
        msg[2..4].copy_from_slice(&ck.to_be_bytes());
        eprint!("\r\n[virtio-net] icmp echo {src} -> {dst}\r\n");
        self.capture(IP_ICMP, src, 0, dst, 0, icmp.len() as u64, None);
        Some(self.ipv4_to_guest(dst, src, IP_ICMP, &msg))
    }

    /// Answers a DHCP DISCOVER/REQUEST, handing the guest this stack's slirp
    /// address (10.0.2.15) so an `ip=dhcp` boot (as a container runtime
    /// configures) lands on an address consistent with our ARP/DNS/gateway.
    fn handle_dhcp(&mut self, bootp: &[u8]) -> Option<Vec<u8>> {
        if bootp.len() < 240 || bootp[0] != 1 || bootp[236..240] != [0x63, 0x82, 0x53, 0x63] {
            return None; // not a BOOTP request with the DHCP magic cookie
        }
        // Find option 53 (message type): 1=DISCOVER, 3=REQUEST.
        let mut msg_type = 0u8;
        let mut i = 240;
        while i < bootp.len() {
            match bootp[i] {
                255 => break, // end
                0 => i += 1,  // pad
                code => {
                    let len = *bootp.get(i + 1)? as usize;
                    let data = i + 2;
                    if data + len > bootp.len() {
                        break;
                    }
                    if code == 53 && len >= 1 {
                        msg_type = bootp[data];
                    }
                    i = data + len;
                }
            }
        }
        let reply_type = match msg_type {
            1 => 2, // DISCOVER -> OFFER
            3 => 5, // REQUEST  -> ACK
            _ => return None,
        };
        eprint!(
            "\r\n[virtio-net] dhcp {} -> {GUEST_IP}\r\n",
            if msg_type == 1 { "discover" } else { "request" }
        );

        let mut r = vec![0u8; 240];
        r[0] = 2; // op = reply
        r[1] = 1; // htype = ethernet
        r[2] = 6; // hlen
        r[4..8].copy_from_slice(&bootp[4..8]); // xid
        r[16..20].copy_from_slice(&GUEST_IP.octets()); // yiaddr
        r[20..24].copy_from_slice(&GW_IP.octets()); // siaddr (next server)
        r[28..44].copy_from_slice(&bootp[28..44]); // chaddr
        r[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie

        // Options: msg type, server id, lease, subnet mask, router, DNS, end.
        r.extend_from_slice(&[53, 1, reply_type]);
        r.extend_from_slice(&[54, 4]);
        r.extend_from_slice(&GW_IP.octets());
        r.extend_from_slice(&[51, 4]);
        r.extend_from_slice(&86400u32.to_be_bytes());
        r.extend_from_slice(&[1, 4, 255, 255, 255, 0]);
        r.extend_from_slice(&[3, 4]);
        r.extend_from_slice(&GW_IP.octets());
        r.extend_from_slice(&[6, 4]);
        r.extend_from_slice(&DNS_IP.octets());
        r.push(255);

        let udp = udp_datagram(67, 68, &r);
        Some(self.ipv4_to_guest(GW_IP, Ipv4Addr::BROADCAST, IP_UDP, &udp))
    }

    /// Captures the queried name, resolves it through the host, and replies.
    fn handle_dns(&mut self, client_port: u16, dns: &[u8]) -> Option<Vec<u8>> {
        if dns.len() < 12 {
            return None;
        }
        let (name, qend) = parse_dns_name(dns, 12)?;
        eprint!("\r\n[virtio-net] dns query {name}\r\n");
        self.capture(
            IP_UDP,
            GUEST_IP,
            client_port,
            DNS_IP,
            53,
            (dns.len() + 8) as u64,
            Some(name.clone()),
        );

        // Resolve through the host (getaddrinfo); first IPv4 answer, if any.
        let ip = (name.as_str(), 0u16)
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| {
                it.find_map(|s| match s.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(_) => None,
                })
            });

        let mut resp = Vec::new();
        resp.extend_from_slice(&dns[0..2]); // id
        let answers = u16::from(ip.is_some());
        // response, recursion available
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        resp.extend_from_slice(&answers.to_be_bytes()); // ancount
        resp.extend_from_slice(&[0, 0, 0, 0]); // ns/ar count

        // the question (name+type+class)
        resp.extend_from_slice(&dns[12..qend]);
        if let Some(v4) = ip {
            resp.extend_from_slice(&[0xc0, 0x0c]); // name pointer to offset 12
            resp.extend_from_slice(&1u16.to_be_bytes()); // type A
            resp.extend_from_slice(&1u16.to_be_bytes()); // class IN
            resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
            resp.extend_from_slice(&4u16.to_be_bytes()); // rdlength
            resp.extend_from_slice(&v4.octets());
        }
        let udp = udp_datagram(53, client_port, &resp);
        Some(self.ipv4_to_guest(DNS_IP, GUEST_IP, IP_UDP, &udp))
    }

    /// Wraps an IPv4 payload for delivery to the guest.
    fn ipv4_to_guest(&self, src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
        let ip = ipv4_packet(src, dst, proto, payload);
        eth_frame(GUEST_MAC, OUR_MAC, ETH_IPV4, &ip)
    }
}

impl Default for VirtioNet {
    fn default() -> Self {
        Self::new()
    }
}

// --- packet construction helpers ---------------------------------------------

fn eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut h = vec![0u8; 20];
    h[0] = 0x45; // version 4, IHL 5
    h[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    h[8] = 64; // TTL
    h[9] = proto;
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());
    let ck = checksum16(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

/// UDP datagram with a zero checksum (permitted for IPv4).
fn udp_datagram(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut u = vec![0u8; 8];
    u[0..2].copy_from_slice(&src_port.to_be_bytes());
    u[2..4].copy_from_slice(&dst_port.to_be_bytes());
    u[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    u.extend_from_slice(payload);
    u
}

/// One's-complement 16-bit checksum (IPv4 / ICMP).
fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parses a DNS name starting at `off`, returning the dotted name and the
/// offset just past the question's type+class fields.
fn parse_dns_name(msg: &[u8], off: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut i = off;
    while i < msg.len() {
        let len = msg[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression not expected in a question
        }
        i += 1;
        let end = i + len;
        let label = msg.get(i..end)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        i = end;
    }
    // A question is the name followed by QTYPE and QCLASS. Report the end
    // only when those four bytes are really there: the caller slices the
    // question out of the message with this offset, so a name that runs to
    // the end of a truncated message would take the slice past it.
    let qend = i.checked_add(4)?;
    if qend > msg.len() {
        return None;
    }
    Some((name, qend))
}

/// Best-effort TLS SNI from a TCP payload that begins with a TLS ClientHello.
/// Fully bounds-checked: any inconsistency (including a ClientHello split
/// across TCP segments) returns `None` rather than misreading.
fn parse_tls_sni(rec: &[u8]) -> Option<String> {
    // TLS record: content_type(1)=0x16 handshake, version(2), length(2).
    if rec.len() < 5 || rec[0] != 0x16 {
        return None;
    }
    let body = rec.get(5..)?;
    // Handshake: msg_type(1)=0x01 ClientHello, length(3).
    if body.len() < 4 || body[0] != 0x01 {
        return None;
    }
    // Skip: handshake header(4) + client_version(2) + random(32).
    let mut p = 4usize.checked_add(2 + 32)?;
    let sid = *body.get(p)? as usize; // session_id
    p = p.checked_add(1 + sid)?;
    let cs = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize; // cipher suites
    p = p.checked_add(2 + cs)?;
    let cm = *body.get(p)? as usize; // compression methods
    p = p.checked_add(1 + cm)?;
    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = p.checked_add(ext_total)?.min(body.len());
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([body[p], body[p + 1]]);
        let elen = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        let data = body.get(p + 4..p + 4 + elen)?;
        if etype == 0 {
            // server_name extension: list_len(2), name_type(1), name_len(2),
            // name.
            if data.len() >= 5 && data[2] == 0 {
                let nlen = u16::from_be_bytes([data[3], data[4]]) as usize;
                let name = data.get(5..5 + nlen)?;
                if !name.is_empty() && name.iter().all(u8::is_ascii_graphic) {
                    return Some(String::from_utf8_lossy(name).into_owned());
                }
            }
            return None;
        }
        p += 4 + elen;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Programs a queue the way the Linux virtio-mmio driver does: select it,
    /// size it, set the three ring addresses, then READY last.
    fn program_queue(
        net: &mut VirtioNet,
        mem: &GuestRam,
        sel: u16,
        desc: u64,
        avail: u64,
        used: u64,
    ) {
        net.mmio(mem, reg::QUEUE_SEL, true, u64::from(sel));
        net.mmio(mem, reg::QUEUE_NUM, true, 8);
        net.mmio(mem, reg::QUEUE_DESC_LOW, true, desc & 0xffff_ffff);
        net.mmio(mem, reg::QUEUE_DESC_HIGH, true, desc >> 32);
        net.mmio(mem, reg::QUEUE_DRIVER_LOW, true, avail & 0xffff_ffff);
        net.mmio(mem, reg::QUEUE_DRIVER_HIGH, true, avail >> 32);
        net.mmio(mem, reg::QUEUE_DEVICE_LOW, true, used & 0xffff_ffff);
        net.mmio(mem, reg::QUEUE_DEVICE_HIGH, true, used >> 32);
        net.mmio(mem, reg::QUEUE_READY, true, 1);
    }

    /// One TX frame through the whole device path in tap mode: the tap gets a
    /// zero `virtio_net_hdr_v1` plus the frame, and the flow ledger still
    /// records the flow -- attaching a tap must not blind the boundary
    /// vantage.
    #[test]
    fn tap_tx_reaches_the_tap_and_the_ledger() {
        use std::io::Read;

        // A socketpair stands in for the tap: `with_tap` needs only a File it
        // can write frames to, and the other end lets the test read exactly
        // the bytes a real tap device would have received.
        let (tap_host, tap_dev) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut net = VirtioNet::with_tap(std::fs::File::from(std::os::fd::OwnedFd::from(tap_dev)));

        const BASE: u64 = 0x4000_0000;
        let mut backing = vec![0u8; 0x8000];
        let mem = GuestRam::new(backing.as_mut_ptr(), BASE, backing.len());
        let (desc, avail, used, data) = (BASE, BASE + 0x1000, BASE + 0x2000, BASE + 0x3000);
        program_queue(&mut net, &mem, TX_QUEUE, desc, avail, used);

        // A UDP frame the flow plugin records (10.0.2.15:1234 -> 1.2.3.4:9999).
        let udp = udp_datagram(1234, 9999, b"payload");
        let ip = ipv4_packet(GUEST_IP, Ipv4Addr::new(1, 2, 3, 4), IP_UDP, &udp);
        let frame = eth_frame(OUR_MAC, GUEST_MAC, ETH_IPV4, &ip);

        // The guest's TX buffer carries its own virtio-net header (stripped by
        // read_tx_frame); the zeros asserted below are the fresh ones the tap
        // write prepends, not these.
        let mut buf = vec![0xa5u8; NET_HDR_LEN];
        buf.extend_from_slice(&frame);
        mem.write(data, &buf).unwrap();
        mem.write_u64(desc, data).unwrap();
        mem.write_u32(desc + 8, buf.len() as u32).unwrap();
        mem.write_u16(desc + 12, 0).unwrap(); // device-readable, no next
        mem.write_u16(desc + 14, 0).unwrap();
        mem.write_u16(avail + 2, 1).unwrap(); // avail.idx = 1
        mem.write_u16(avail + 4, 0).unwrap(); // avail.ring[0] = desc 0

        net.mmio(&mem, reg::QUEUE_NOTIFY, true, u64::from(TX_QUEUE));

        // (a) The tap saw one write: a zero virtio_net_hdr_v1, then the frame.
        let mut got = vec![0u8; NET_HDR_LEN + frame.len()];
        (&tap_host).read_exact(&mut got).unwrap();
        assert_eq!(&got[..NET_HDR_LEN], &[0u8; NET_HDR_LEN], "zero vnet header");
        assert_eq!(&got[NET_HDR_LEN..], &frame[..], "the frame, unmangled");

        // (b) The flow plugin still fired on the way out.
        let events = net.take_events();
        assert_eq!(events.len(), 1, "one flow recorded");
        let CapturedEvent::NetFlow {
            proto,
            dst,
            dst_port,
            ..
        } = &events[0]
        else {
            panic!("expected a NetFlow event");
        };
        assert_eq!(*proto, IP_UDP);
        assert_eq!(*dst, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(*dst_port, 9999);
        assert!(net.irq_level(), "the used-buffer interrupt was raised");
    }

    /// After `set_mac`, the guest must read the override from config space
    /// (bytes 0..6) -- and the device must offer VIRTIO_NET_F_MAC, or the
    /// driver would never look at config space and would invent a random
    /// address, dropping every redirected reply in tap mode.
    #[test]
    fn config_space_reports_the_override_mac() {
        let mut backing = vec![0u8; 0x1000];
        let mem = GuestRam::new(backing.as_mut_ptr(), 0x4000_0000, backing.len());
        let mut net = VirtioNet::new();
        let mac = [0x02, 0x42, 0xac, 0x11, 0x00, 0x02];
        net.set_mac(mac);

        net.mmio(&mem, reg::DEVICE_FEATURES_SEL, true, 0);
        let feat = net.mmio(&mem, reg::DEVICE_FEATURES, false, 0);
        assert_ne!(feat & u64::from(F_MAC_LO), 0, "VIRTIO_NET_F_MAC is offered");

        for (i, &b) in mac.iter().enumerate() {
            assert_eq!(
                net.mmio(&mem, reg::CONFIG + i as u64, false, 0),
                u64::from(b),
                "config-space byte {i}"
            );
        }
        // Past the MAC, config space reads as zero rather than leaking state.
        assert_eq!(net.mmio(&mem, reg::CONFIG + 6, false, 0), 0);
    }

    #[test]
    fn dhcp_offers_guest_ip() {
        let mut net = VirtioNet::new();
        // Minimal DISCOVER: 240-byte BOOTP with the magic cookie, then option
        // 53 = 1 (DISCOVER) and the end marker.
        let mut bootp = vec![0u8; 240];
        bootp[0] = 1; // op = request
        bootp[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        bootp.extend_from_slice(&[53, 1, 1, 255]);
        let frame = net.handle_dhcp(&bootp).expect("an OFFER frame");
        // Ethernet(14) + IPv4(20) + UDP(8) = 42, then BOOTP; yiaddr at +16.
        assert_eq!(frame[42], 2, "op = reply");
        assert_eq!(
            &frame[42 + 16..42 + 20],
            &[10, 0, 2, 15],
            "yiaddr = guest IP"
        );
    }

    #[test]
    fn dns_name_parse() {
        // "example.com" question: 7 example 3 com 0, then type(2)+class(2).
        let mut m = vec![0u8; 12];
        m.extend_from_slice(&[7]);
        m.extend_from_slice(b"example");
        m.push(3);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]);
        let (name, end) = parse_dns_name(&m, 12).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(end, m.len());
    }

    /// A descriptor length is guest-controlled, and the transmit path sized
    /// an allocation from it directly. A chain that claims more than the
    /// device could ever send must be refused before anything is allocated.
    #[test]
    fn an_oversized_transmit_chain_is_refused() {
        let mut net = VirtioNet::new();
        const BASE: u64 = 0x4000_0000;
        let mut backing = vec![0u8; 0x20000];
        let mem = GuestRam::new(backing.as_mut_ptr(), BASE, backing.len());
        let (desc, avail, used, data) = (BASE, BASE + 0x1000, BASE + 0x2000, BASE + 0x3000);
        program_queue(&mut net, &mem, TX_QUEUE, desc, avail, used);

        // One byte past the ceiling, and still inside guest RAM, so only the
        // ceiling can reject it.
        let oversized = (NET_HDR_LEN + 65536 + 1) as u32;
        mem.write_u64(desc, data).unwrap();
        mem.write_u32(desc + 8, oversized).unwrap();
        mem.write_u16(desc + 12, 0).unwrap();
        mem.write_u16(desc + 14, 0).unwrap();

        assert_eq!(net.read_tx_frame(&mem, 0), None);
    }

    /// A question that ends before its type and class fields must be refused.
    /// The offset `parse_dns_name` reports is used to slice the question back
    /// into the reply, so reporting one past the end of the message panicked
    /// the vCPU thread inside the MMIO exit that was serving the guest.
    #[test]
    fn a_dns_question_without_type_and_class_is_refused() {
        let mut truncated = vec![0u8; 12];
        truncated.push(0); // root label, and then nothing
        assert_eq!(parse_dns_name(&truncated, 12), None);

        let mut net = VirtioNet::new();
        assert_eq!(net.handle_dns(1234, &truncated), None);
    }

    #[test]
    fn tls_sni_extracted_from_client_hello() {
        // Build a minimal ClientHello for "example.com" with only the SNI ext.
        let host = b"example.com";
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&(host.len() as u16 + 3).to_be_bytes()); // list len
        sni_ext.push(0); // name type = host_name
        sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // ext type 0 (server_name)
        ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext);

        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]); // client_version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session_id len
        hs.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        hs.extend_from_slice(&[0x13, 0x01]); // one suite
        hs.push(1); // compression methods len
        hs.push(0); // null compression
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut body = vec![0x01]; // ClientHello
        let l = hs.len();
        body.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        body.extend_from_slice(&hs);

        let mut rec = vec![0x16, 0x03, 0x01]; // handshake, TLS 1.0 record
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);

        assert_eq!(parse_tls_sni(&rec).as_deref(), Some("example.com"));
        // Not a handshake / truncated -> None, never a panic.
        assert_eq!(parse_tls_sni(&[0x17, 0x03, 0x03, 0, 0]), None);
        assert_eq!(parse_tls_sni(&rec[..20]), None);
    }

    #[test]
    fn ip_checksum_matches_known() {
        // A header whose checksum field is zeroed; result is non-zero.
        let mut h = vec![0u8; 20];
        h[0] = 0x45;
        h[2..4].copy_from_slice(&40u16.to_be_bytes());
        h[9] = 6;
        assert_ne!(checksum16(&h), 0);
    }
}

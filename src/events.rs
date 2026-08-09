//! Emitting the VMM's observations as `RawEvent` NDJSON: one compact JSON
//! object per line, so a reader can `tail -f` it or ingest it a line at a time
//! without a parser for the whole file.
//!
//! Every line is an envelope (`sandbox_id`, `ts`, `provenance`, `source`)
//! around a payload. The VMM writes `block` (disk I/O) and `net` (flows) —
//! what it sees at its own device models — and the shape of both is pinned by
//! the tests below, because a ledger whose format drifts is a ledger nobody can
//! read twice.
//!
//! [`Emitter::emit_payload`](crate::events::Emitter::emit_payload) leaves the
//! stream open to other sources: a plugin (see [`crate::plugin`]) names its
//! own `source` and supplies its own payload, and its records interleave with
//! the VMM's in one ledger. The envelope is this crate's; the payload is not.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// A captured observation a device hands to the emitter (kept transport-free so
/// the devices don't depend on serde or the clock).
pub enum CapturedEvent {
    /// A virtio-blk request: starting sector, data bytes, and direction.
    Block { lba: u64, len: u64, write: bool },
    /// A guest IPv4 flow observed at virtio-net.
    NetFlow {
        proto: u8,
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        bytes: u64,
        dns: Option<String>,
        /// TLS SNI from a ClientHello, when the flow carried one.
        sni: Option<String>,
    },
}

/// The `RawEvent` envelope (v1).
///
/// Generic over the payload, so a record can be built by a caller outside this
/// crate without the envelope enumerating every possible source. Declaration
/// order here *is* the wire order — derived `Serialize` emits fields in
/// order — which is what keeps the bytes identical to the adjacently-tagged
/// shape this replaced. The tests below pin it.
#[derive(Serialize)]
struct RawEvent<'a, P: Serialize> {
    sandbox_id: &'a str,
    ts: i64,
    provenance: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    corroboration: Option<&'a str>,
    source: &'a str,
    payload: P,
}

#[derive(Serialize)]
struct BlockPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    lba: Option<u64>,
    len: u64,
    rw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

#[derive(Serialize)]
struct NetPayload {
    five_tuple: FiveTuple,
    direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_initiated: Option<bool>,
    bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<String>,
}

#[derive(Serialize)]
struct FiveTuple {
    proto: u8,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

/// Writes `RawEvent` NDJSON to a file (one line per event). Disabled unless a
/// path is given, so the stream is a clean ledger separate from the guest
/// console (stdout) and the human-readable capture logs (stderr).
pub struct Emitter {
    sandbox_id: String,
    /// Buffered so a high-rate boundary stream (e.g. per-request block events
    /// under fio) is not one `write(2)` per line. Flushed on each snapshot and
    /// on drop.
    out: Option<BufWriter<File>>,
}

impl Emitter {
    /// Opens the ledger at `path` (truncating), or returns a disabled emitter
    /// when `path` is `None`.
    ///
    /// # Errors
    ///
    /// Errors if the file cannot be created.
    pub fn new(path: Option<&str>, sandbox_id: &str) -> std::io::Result<Self> {
        let out = match path {
            Some(p) => Some(BufWriter::new(File::create(p)?)),
            None => None,
        };
        Ok(Emitter {
            sandbox_id: sandbox_id.to_string(),
            out,
        })
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.out.is_some()
    }

    /// Flushes buffered ledger lines to disk so a reader (a collector, or a
    /// `tail -f`) sees them promptly.
    pub fn flush(&mut self) {
        if let Some(out) = self.out.as_mut() {
            let _ = out.flush();
        }
    }

    /// Writes one `RawEvent` line: the crate's envelope around a caller's
    /// payload, tagged with the caller's `source`.
    ///
    /// This is how an [`crate::plugin::Plugin`] puts its own records in the
    /// same ledger as the VMM's. The VMM guarantees the envelope (`sandbox_id`,
    /// `ts`, `provenance`, `source`) and the NDJSON framing; the meaning of
    /// `payload` is entirely the caller's.
    pub fn emit_payload<P: Serialize>(&mut self, provenance: &str, source: &str, payload: &P) {
        let Some(out) = self.out.as_mut() else {
            return;
        };
        let ev = RawEvent {
            sandbox_id: &self.sandbox_id,
            ts: now_ns(),
            provenance,
            corroboration: None,
            source,
            payload,
        };
        if let Ok(line) = serde_json::to_string(&ev) {
            let _ = writeln!(out, "{line}");
        }
    }

    /// Emits a captured device event with `boundary` provenance (host-observed
    /// at the device — the boundary vantage).
    pub fn captured(&mut self, ev: &CapturedEvent) {
        if !self.enabled() {
            return;
        }
        match ev {
            CapturedEvent::Block { lba, len, write } => self.emit_payload(
                "boundary",
                "block",
                &BlockPayload {
                    lba: Some(*lba),
                    len: *len,
                    rw: if *write { "w" } else { "r" }.to_string(),
                    path: None,
                },
            ),
            CapturedEvent::NetFlow {
                proto,
                src,
                src_port,
                dst,
                dst_port,
                bytes,
                dns,
                sni,
            } => self.emit_payload(
                "boundary",
                "net",
                &NetPayload {
                    five_tuple: FiveTuple {
                        proto: *proto,
                        src_ip: src.to_string(),
                        src_port: *src_port,
                        dst_ip: dst.to_string(),
                        dst_port: *dst_port,
                    },
                    direction: "egress".to_string(),
                    guest_initiated: Some(true),
                    bytes: *bytes,
                    sni: sni.clone(),
                    dns: dns.clone(),
                },
            ),
        }
    }
}

/// Host wall-clock in nanoseconds since the Unix epoch (the envelope's `ts`).
fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serialize an envelope with a fixed ts and assert the exact wire bytes,
    // pinning the RawEvent wire format. These also
    // pin the field order the generic envelope has to reproduce: `source` and
    // `payload` sit where the adjacent tag used to put them.
    fn line<P: Serialize>(provenance: &str, source: &str, payload: P) -> String {
        let ev = RawEvent {
            sandbox_id: "vm1",
            ts: 1,
            provenance,
            corroboration: None,
            source,
            payload,
        };
        serde_json::to_string(&ev).unwrap()
    }

    #[test]
    fn block_write_wire_shape() {
        let s = line(
            "boundary",
            "block",
            BlockPayload {
                lba: Some(2048),
                len: 4096,
                rw: "w".into(),
                path: None,
            },
        );
        assert_eq!(
            s,
            r#"{"sandbox_id":"vm1","ts":1,"provenance":"boundary","source":"block","payload":{"lba":2048,"len":4096,"rw":"w"}}"#
        );
    }

    #[test]
    fn net_dns_wire_shape() {
        let s = line(
            "boundary",
            "net",
            NetPayload {
                five_tuple: FiveTuple {
                    proto: 17,
                    src_ip: "10.0.2.15".into(),
                    src_port: 40000,
                    dst_ip: "10.0.2.3".into(),
                    dst_port: 53,
                },
                direction: "egress".into(),
                guest_initiated: Some(true),
                bytes: 72,
                sni: None,
                dns: Some("example.com".into()),
            },
        );
        assert_eq!(
            s,
            r#"{"sandbox_id":"vm1","ts":1,"provenance":"boundary","source":"net","payload":{"five_tuple":{"proto":17,"src_ip":"10.0.2.15","src_port":40000,"dst_ip":"10.0.2.3","dst_port":53},"direction":"egress","guest_initiated":true,"bytes":72,"dns":"example.com"}}"#
        );
    }

    #[test]
    fn emitter_writes_ndjson_lines() {
        use std::net::Ipv4Addr;

        let path = std::env::temp_dir().join(format!("hvi-{}.ndjson", std::process::id()));
        let p = path.to_str().unwrap();
        {
            let mut e = Emitter::new(Some(p), "vm1").unwrap();
            e.captured(&CapturedEvent::Block {
                lba: 8,
                len: 4096,
                write: true,
            });
            e.captured(&CapturedEvent::NetFlow {
                proto: 17,
                src: Ipv4Addr::new(10, 0, 2, 15),
                src_port: 40000,
                dst: Ipv4Addr::new(10, 0, 2, 3),
                dst_port: 53,
                bytes: 40,
                dns: Some("crates.io".into()),
                sni: None,
            });
        }
        let text = std::fs::read_to_string(p).unwrap();
        let _ = std::fs::remove_file(p);
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line is a valid RawEvent with the expected source and fields.
        let v: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(v[0]["source"], "block");
        assert_eq!(v[0]["payload"]["rw"], "w");
        assert_eq!(v[1]["source"], "net");
        assert_eq!(v[1]["payload"]["dns"], "crates.io");
        assert!(v.iter().all(|e| e["provenance"] == "boundary"));
    }

    // The seam a plugin uses: a payload this crate has never heard of goes
    // into the ledger under the caller's own `source`, in the same envelope.
    #[test]
    fn foreign_payload_shares_the_envelope() {
        #[derive(Serialize)]
        struct Foreign {
            whatever: u32,
        }
        let s = line("rich", "something-else", Foreign { whatever: 7 });
        assert_eq!(
            s,
            r#"{"sandbox_id":"vm1","ts":1,"provenance":"rich","source":"something-else","payload":{"whatever":7}}"#
        );
    }
}

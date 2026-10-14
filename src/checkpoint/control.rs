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

//! The line protocol of the control socket.
//!
//! `--control-sock` is a Unix stream socket that takes one JSON object per
//! line and answers each with one JSON object on a line of its own. Every
//! request and every reply carries `"v":1`. A request names its `op`:
//!
//! | `op` | Effect | Reply beyond `v` and `ok` |
//! |---|---|---|
//! | `profile` | none | `profile`, the [`MachineProfile`] |
//! | `pause` | holds the I/O threads, then parks the vCPUs | `state` |
//! | `resume` | releases the vCPUs, then the I/O threads | `state` |
//! | `status` | none | `state`, `vcpus`, `vcpus_parked` |
//! | `stop` | ends the run, as a guest power-off would | `state` |
//! | `checkpoint` | captures the VM into a bundle directory | `state`, `dir`, `manifest_sha256`, `stats` |
//! | `migrate` | streams the VM on this connection while it runs, then paused | `state`, `manifest_sha256`, `stats` |
//! | `disk-dirty` | reads the disk blocks written since boot or since the last read | `since`, `round`, `block_size`, `blocks`, `dirty`, `generation`, `bitmap_sha256`, `bitmap_b64` |
//! | `disk-blocks` | streams disk blocks, see [`disk`](super::disk) | `round` (for a round), `blocks`, `bytes`, `batches`, `generation`, `max_lock_us`, `sent_sha256` |
//!
//! `migrate` writes a streamed bundle (see [`stream`](super::stream)) on the
//! connection before its reply line: the frames first, the reply after the
//! manifest. A refusal before the first frame, or a failure after it, is a
//! reply line where the next frame header was due.
//!
//! A refusal is `{"v":1,"ok":false,"code":...,"error":...}`, where `code` is
//! one of the [`ErrorCode`] spellings and `error` is prose for a person.
//! Callers branch on `code`, never on `error`.

use serde::Serialize;
use serde_json::Value;

use crate::checkpoint::disk::MAX_REQUEST_BLOCKS;
use crate::checkpoint::migrate::{RoundStats, StopReason};
use crate::checkpoint::profile::MachineProfile;
use crate::devices::virtio::block::DirtySince;

/// The protocol version every request and reply carries as `v`.
pub const PROTOCOL_VERSION: u64 = 1;

/// The longest request line the socket reads, newline excluded. A request is a
/// few dozen bytes; the bound keeps a client from growing the buffer without
/// end.
pub const MAX_LINE: usize = 64 * 1024;

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Report the machine profile.
    Profile,
    /// Pause the VM.
    Pause,
    /// Resume a paused VM.
    Resume,
    /// Report the run state.
    Status,
    /// End the run.
    Stop,
    /// Capture the VM into `dir`.
    Checkpoint {
        /// The directory the bundle is written to.
        dir: String,
        /// What the VM does after a capture that succeeded.
        then: Then,
        /// The caller's transaction id, recorded in `session.json`.
        txid: Option<String>,
        /// The caller's epoch for the sandbox, recorded in `session.json`.
        epoch: u64,
    },
    /// Stream the VM on the connection, then continue or fence it.
    Migrate(Migrate),
    /// Read the disk blocks the guest wrote, and start a round.
    DiskDirty(DirtySince),
    /// Stream the bytes of disk blocks.
    DiskBlocks(BlockSelection),
}

/// The disk blocks a `disk-blocks` request names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockSelection {
    /// These blocks, ascending.
    Blocks(Vec<u64>),
    /// The blocks of this round, which must be the last one `disk-dirty`
    /// read.
    Round(u32),
}

/// A `migrate` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migrate {
    /// What the VM does after a stream that was sealed.
    pub then: Then,
    /// The caller's transaction id, recorded in `session.json`.
    pub txid: Option<String>,
    /// The caller's epoch for the sandbox, recorded in `session.json`.
    pub epoch: u64,
    /// The most rounds taken with the guest running, 1 to
    /// [`MAX_MIGRATE_ROUNDS`], default 5; 1 sends RAM once running and once
    /// paused.
    pub max_rounds: Option<u32>,
    /// The time after which no new round starts with the guest running, in
    /// seconds, 0 to 3600, default 60. It is checked as each round ends, so
    /// a round under way runs to its end.
    pub max_secs: Option<u64>,
}

/// The most rounds a `migrate` may ask for, below the stream's limit.
pub const MAX_MIGRATE_ROUNDS: u32 = 16;

/// What a VM does after a checkpoint that succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Then {
    /// Resume the guest.
    Continue,
    /// Keep the vCPUs parked for good, refusing a later `resume`, until
    /// `stop`. This is the source's side of a move: once the destination runs,
    /// the source must never run again.
    Fence,
}

/// Where the VM is, as `status` and the state-changing ops report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VmState {
    /// The guest runs.
    Running,
    /// The I/O threads are held and the vCPUs parked.
    Paused,
    /// Paused as `hvi restore` leaves a guest it loaded from a bundle: every
    /// vCPU and the interrupt controller hold the bundle's state, and the
    /// guest has not run here yet. `resume` runs it, as from `paused`.
    #[serde(rename = "restored-paused")]
    RestoredPaused,
    /// Paused for good after a checkpoint that fenced it.
    Fenced,
    /// The run is ending.
    Stopping,
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// The line is not a JSON object with a string `op`.
    BadRequest,
    /// `v` is missing or is not [`PROTOCOL_VERSION`].
    UnsupportedVersion,
    /// `op` names no operation.
    UnknownOp,
    /// The line is longer than [`MAX_LINE`].
    TooLong,
    /// The operation exists but this hvi does not implement it yet.
    NotImplemented,
    /// The vCPUs or the I/O threads did not park in time; the VM runs on.
    Timeout,
    /// Another pause, a plugin's, holds the vCPUs.
    Busy,
    /// The run has stopped or is stopping.
    Stopped,
    /// The VM was fenced and will not resume.
    Fenced,
    /// The profile is not complete yet: the boot vCPU has not started.
    NotReady,
    /// The checkpoint cannot be taken as asked: no checkpoint root, a
    /// directory outside it or in use, a guest with virtio-fs shares, or one
    /// of a machine profile no backend checkpoints yet. The VM was not
    /// paused.
    Refused,
    /// The capture failed after the VM was paused; the VM runs on, or stays
    /// paused if it was paused before.
    CaptureFailed,
}

impl ErrorCode {
    /// Returns the spelling the reply carries as `code`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnknownOp => "unknown_op",
            Self::TooLong => "too_long",
            Self::NotImplemented => "not_implemented",
            Self::Timeout => "timeout",
            Self::Busy => "busy",
            Self::Stopped => "stopped",
            Self::Fenced => "fenced",
            Self::NotReady => "not_ready",
            Self::Refused => "refused",
            Self::CaptureFailed => "capture_failed",
        }
    }
}

/// A refusal: its code and a sentence for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// What a caller branches on.
    pub code: ErrorCode,
    /// What a person reads.
    pub message: String,
}

impl Error {
    /// Returns a refusal with `code` and `message`.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// A reply, before it is formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The answer to `profile`.
    Profile(Box<MachineProfile>),
    /// The answer to `pause`, `resume` and `stop`: the state the VM is in now.
    State(VmState),
    /// The answer to `status`.
    Status {
        /// The run state.
        state: VmState,
        /// The vCPUs that have started.
        vcpus: u32,
        /// The vCPUs parked at a checkpoint right now.
        vcpus_parked: u32,
    },
    /// The answer to a `checkpoint` that sealed its bundle.
    Checkpoint {
        /// The state the VM is in now: as before, or `fenced`.
        state: VmState,
        /// The bundle directory.
        dir: String,
        /// The SHA-256 of the bundle's `manifest.json`.
        manifest_sha256: String,
        /// What the capture took.
        stats: CheckpointStats,
    },
    /// The answer to a `migrate` whose stream was sealed.
    Migrate {
        /// The state the VM is in now: as before, or `fenced`.
        state: VmState,
        /// The SHA-256 of the stream's `manifest.json`.
        manifest_sha256: String,
        /// What the move took.
        stats: Box<MigrateStats>,
    },
    /// The answer to `disk-dirty`.
    DiskDirty(DiskDirtyReply),
    /// The answer to a `disk-blocks` that sent every block, after them.
    DiskBlocks(DiskBlocksReply),
    /// A refusal.
    Error(Error),
}

/// What a `migrate` took, as its reply reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrateStats {
    /// Every RAM round, the final one last.
    pub rounds: Vec<RoundStats>,
    /// Why the rounds with the guest running ended.
    pub stop_reason: StopReason,
    /// The dirty set, in bytes, at or below which they would have ended.
    pub threshold_bytes: u64,
    /// From the start of round 0 to the pause, in milliseconds.
    pub precopy_ms: u64,
    /// From the pause to every vCPU parked with its state exported.
    pub pause_ms: u64,
    /// From the pause to the manifest written: the source's part of the
    /// time the guest is stopped.
    pub paused_ms: u64,
    /// The bytes of the final round, sent paused.
    pub final_round_bytes: u64,
    /// The size of guest RAM.
    pub ram_total_bytes: u64,
    /// The bytes of guest RAM that were not zero in round 0.
    pub ram_present_bytes: u64,
    /// The page bytes the rounds carried before compression.
    pub ram_raw_bytes: u64,
    /// The bytes the rounds put on the stream.
    pub ram_stream_bytes: u64,
    /// The whole stream, frame headers and documents included.
    pub stream_bytes: u64,
    /// The bytes one record of the guest's writes covers: the host page on
    /// KVM, the IPA granule on HVF.
    pub write_granule: u64,
    /// The write faults hvi served, on a backend where it serves them.
    pub write_faults: Option<u64>,
    /// The mean host time of one, in nanoseconds.
    pub write_fault_ns: Option<u64>,
    /// When the last round with the guest running was written, in
    /// milliseconds since the Unix epoch.
    pub precopy_end_unix_ms: u64,
    /// When the manifest was written.
    pub sealed_at_unix_ms: u64,
}

/// What `disk-dirty` reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskDirtyReply {
    /// `boot` or `round`, as asked.
    pub since: &'static str,
    /// The round this read started: 0 for `boot`.
    pub round: u32,
    /// The size of a block, 65536.
    pub block_size: u64,
    /// The number of blocks of the disk, the last one maybe short.
    pub blocks: u64,
    /// The number of blocks set in the bitmap.
    pub dirty: u64,
    /// The disk's generation at the read.
    pub generation: u64,
    /// The SHA-256 of the bitmap's bytes, as lowercase hex.
    pub bitmap_sha256: String,
    /// The bitmap, bit `i` of byte `i / 8` (low bit first) for block `i`,
    /// as standard base64.
    pub bitmap_b64: String,
}

/// What `disk-blocks` reports once it has sent every batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskBlocksReply {
    /// The round sent, for `{"round":k}`; absent for a list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round: Option<u32>,
    /// The blocks sent.
    pub blocks: u64,
    /// Their bytes, without the header lines.
    pub bytes: u64,
    /// The batches.
    pub batches: u64,
    /// The disk's generation after the last block was read. Not the
    /// generation a restore checks: that is the `disk-dirty` reply's.
    pub generation: u64,
    /// The longest the disk was held from the guest for one block, in
    /// microseconds.
    pub max_lock_us: u64,
    /// The SHA-256 of the batches' `sha256` texts in order, as lowercase
    /// hex; for a round, `disk.json` records it too.
    pub sent_sha256: String,
}

/// What a checkpoint took, as its reply reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CheckpointStats {
    /// From the request to every vCPU parked with its state exported.
    pub pause_ms: u64,
    /// From then to the bundle sealed: device states, disk sync, RAM and
    /// the files.
    pub capture_ms: u64,
    /// The bytes of guest RAM the bundle holds, the pages that are not zero.
    pub ram_present_bytes: u64,
    /// The size of guest RAM.
    pub ram_total_bytes: u64,
    /// The size of the bundle's files, the manifest included.
    pub bundle_bytes: u64,
}

/// Parses one request line, without its newline.
///
/// # Errors
///
/// Errors with the refusal to send back when the line is not a request this
/// protocol version knows.
pub fn parse_request(line: &str) -> Result<Request, Error> {
    let value: Value = serde_json::from_str(line.trim_end_matches('\r'))
        .map_err(|e| Error::new(ErrorCode::BadRequest, format!("not JSON: {e}")))?;
    let Value::Object(fields) = value else {
        return Err(Error::new(ErrorCode::BadRequest, "not a JSON object"));
    };
    if fields.get("v").and_then(Value::as_u64) != Some(PROTOCOL_VERSION) {
        return Err(Error::new(
            ErrorCode::UnsupportedVersion,
            format!("\"v\" must be {PROTOCOL_VERSION}"),
        ));
    }
    let Some(op) = fields.get("op").and_then(Value::as_str) else {
        return Err(Error::new(ErrorCode::BadRequest, "\"op\" must be a string"));
    };
    Ok(match op {
        "profile" => Request::Profile,
        "pause" => Request::Pause,
        "resume" => Request::Resume,
        "status" => Request::Status,
        "stop" => Request::Stop,
        "migrate" => Request::Migrate(Migrate {
            then: then_of(&fields)?,
            txid: txid_of(&fields)?,
            epoch: epoch_of(&fields)?,
            max_rounds: match fields.get("max_rounds") {
                None => None,
                Some(n) => Some(
                    n.as_u64()
                        .filter(|n| (1..=u64::from(MAX_MIGRATE_ROUNDS)).contains(n))
                        .ok_or_else(|| {
                            Error::new(
                                ErrorCode::BadRequest,
                                format!("\"max_rounds\" must be 1 to {MAX_MIGRATE_ROUNDS}"),
                            )
                        })? as u32,
                ),
            },
            max_secs: match fields.get("max_secs") {
                None => None,
                Some(n) => Some(n.as_u64().filter(|n| *n <= 3600).ok_or_else(|| {
                    Error::new(ErrorCode::BadRequest, "\"max_secs\" must be 0 to 3600")
                })?),
            },
        }),
        "checkpoint" => {
            let dir = fields
                .get("dir")
                .and_then(Value::as_str)
                .filter(|dir| !dir.is_empty())
                .ok_or_else(|| {
                    Error::new(ErrorCode::BadRequest, "checkpoint needs a \"dir\" string")
                })?;
            Request::Checkpoint {
                dir: dir.to_string(),
                then: then_of(&fields)?,
                txid: txid_of(&fields)?,
                epoch: epoch_of(&fields)?,
            }
        }
        "disk-dirty" => Request::DiskDirty(match fields.get("since").and_then(Value::as_str) {
            Some("boot") => DirtySince::Boot,
            Some("round") => DirtySince::Round,
            _ => {
                return Err(Error::new(
                    ErrorCode::BadRequest,
                    "disk-dirty needs \"since\": \"boot\" or \"round\"",
                ))
            }
        }),
        "disk-blocks" => Request::DiskBlocks(parse_selection(&fields)?),
        other => {
            return Err(Error::new(
                ErrorCode::UnknownOp,
                format!("no operation {other:?}"),
            ))
        }
    })
}

/// Returns the request's `then`, `continue` when it gives none.
fn then_of(fields: &serde_json::Map<String, Value>) -> Result<Then, Error> {
    match fields.get("then").map(Value::as_str) {
        None | Some(Some("continue")) => Ok(Then::Continue),
        Some(Some("fence")) => Ok(Then::Fence),
        Some(_) => Err(Error::new(
            ErrorCode::BadRequest,
            "\"then\" must be \"continue\" or \"fence\"",
        )),
    }
}

/// Parses what a `disk-blocks` request names: a `blocks` list of block
/// numbers, or a `round`.
fn parse_selection(fields: &serde_json::Map<String, Value>) -> Result<BlockSelection, Error> {
    let bad = |message: String| Error::new(ErrorCode::BadRequest, message);
    match (fields.get("blocks"), fields.get("round")) {
        (Some(Value::Array(list)), None) => {
            if list.len() > MAX_REQUEST_BLOCKS {
                return Err(bad(format!(
                    "\"blocks\" lists {} blocks, at most {MAX_REQUEST_BLOCKS} per request",
                    list.len()
                )));
            }
            let blocks = list
                .iter()
                .map(Value::as_u64)
                .collect::<Option<Vec<u64>>>()
                .ok_or_else(|| bad("\"blocks\" must list unsigned integers".into()))?;
            Ok(BlockSelection::Blocks(blocks))
        }
        (None, Some(round)) => round
            .as_u64()
            .and_then(|r| u32::try_from(r).ok())
            .map(BlockSelection::Round)
            .ok_or_else(|| bad("\"round\" must be a round number".into())),
        _ => Err(bad(
            "disk-blocks needs a \"blocks\" list or a \"round\", not both".into(),
        )),
    }
}

/// Returns the request's `txid`, if it gives one.
fn txid_of(fields: &serde_json::Map<String, Value>) -> Result<Option<String>, Error> {
    match fields.get("txid") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(txid)) if txid.len() <= 256 => Ok(Some(txid.clone())),
        Some(_) => Err(Error::new(
            ErrorCode::BadRequest,
            "\"txid\" must be a string of at most 256 bytes",
        )),
    }
}

/// Returns the request's `epoch`, 0 when it gives none.
fn epoch_of(fields: &serde_json::Map<String, Value>) -> Result<u64, Error> {
    match fields.get("epoch") {
        None => Ok(0),
        Some(epoch) => epoch.as_u64().ok_or_else(|| {
            Error::new(
                ErrorCode::BadRequest,
                "\"epoch\" must be an unsigned integer",
            )
        }),
    }
}

/// Formats `response` as one line of JSON, without the newline.
#[must_use]
pub fn format_response(response: &Response) -> String {
    // Each reply is its own struct, so the fields come out in this order:
    // `v` first, then `ok`, then the body. serde_json's maps would sort them.
    #[derive(Serialize)]
    struct ProfileReply<'a> {
        v: u64,
        ok: bool,
        profile: &'a MachineProfile,
    }
    #[derive(Serialize)]
    struct StateReply {
        v: u64,
        ok: bool,
        state: VmState,
    }
    #[derive(Serialize)]
    struct StatusReply {
        v: u64,
        ok: bool,
        state: VmState,
        vcpus: u32,
        vcpus_parked: u32,
    }
    #[derive(Serialize)]
    struct CheckpointReply<'a> {
        v: u64,
        ok: bool,
        state: VmState,
        dir: &'a str,
        manifest_sha256: &'a str,
        stats: CheckpointStats,
    }
    #[derive(Serialize)]
    struct MigrateReply<'a> {
        v: u64,
        ok: bool,
        state: VmState,
        manifest_sha256: &'a str,
        stats: &'a MigrateStats,
    }
    #[derive(Serialize)]
    struct BodyReply<'a, T> {
        v: u64,
        ok: bool,
        #[serde(flatten)]
        body: &'a T,
    }
    #[derive(Serialize)]
    struct ErrorReply<'a> {
        v: u64,
        ok: bool,
        code: &'static str,
        error: &'a str,
    }
    let v = PROTOCOL_VERSION;
    let line = match response {
        Response::Profile(profile) => serde_json::to_string(&ProfileReply {
            v,
            ok: true,
            profile,
        }),
        Response::State(state) => serde_json::to_string(&StateReply {
            v,
            ok: true,
            state: *state,
        }),
        Response::Status {
            state,
            vcpus,
            vcpus_parked,
        } => serde_json::to_string(&StatusReply {
            v,
            ok: true,
            state: *state,
            vcpus: *vcpus,
            vcpus_parked: *vcpus_parked,
        }),
        Response::Checkpoint {
            state,
            dir,
            manifest_sha256,
            stats,
        } => serde_json::to_string(&CheckpointReply {
            v,
            ok: true,
            state: *state,
            dir,
            manifest_sha256,
            stats: *stats,
        }),
        Response::Migrate {
            state,
            manifest_sha256,
            stats,
        } => serde_json::to_string(&MigrateReply {
            v,
            ok: true,
            state: *state,
            manifest_sha256,
            stats,
        }),
        Response::DiskDirty(body) => serde_json::to_string(&BodyReply { v, ok: true, body }),
        Response::DiskBlocks(body) => serde_json::to_string(&BodyReply { v, ok: true, body }),
        Response::Error(e) => serde_json::to_string(&ErrorReply {
            v,
            ok: false,
            code: e.code.as_str(),
            error: &e.message,
        }),
    };
    // These structs hold strings, integers and a profile, none of which can
    // fail to serialize.
    line.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(line: &str) -> (ErrorCode, String) {
        let e = parse_request(line).expect_err(line);
        (e.code, e.message)
    }

    #[test]
    fn every_op_parses() {
        for (line, want) in [
            (r#"{"v":1,"op":"profile"}"#, Request::Profile),
            (r#"{"v":1,"op":"pause"}"#, Request::Pause),
            (r#"{"v":1,"op":"resume"}"#, Request::Resume),
            (r#"{"v":1,"op":"status"}"#, Request::Status),
            (r#"{"op":"stop","v":1}"#, Request::Stop),
            (
                r#"{"v":1,"op":"checkpoint","dir":"/tmp/ck"}"#,
                Request::Checkpoint {
                    dir: "/tmp/ck".into(),
                    then: Then::Continue,
                    txid: None,
                    epoch: 0,
                },
            ),
            (
                r#"{"v":1,"op":"migrate","then":"fence","txid":"t2","epoch":3}"#,
                Request::Migrate(Migrate {
                    then: Then::Fence,
                    txid: Some("t2".into()),
                    epoch: 3,
                    max_rounds: None,
                    max_secs: None,
                }),
            ),
            (
                r#"{"v":1,"op":"migrate","max_rounds":2,"max_secs":0}"#,
                Request::Migrate(Migrate {
                    then: Then::Continue,
                    txid: None,
                    epoch: 0,
                    max_rounds: Some(2),
                    max_secs: Some(0),
                }),
            ),
            (
                r#"{"v":1,"op":"checkpoint","dir":"/tmp/ck","then":"fence","txid":"t1","epoch":7}"#,
                Request::Checkpoint {
                    dir: "/tmp/ck".into(),
                    then: Then::Fence,
                    txid: Some("t1".into()),
                    epoch: 7,
                },
            ),
            (
                r#"{"v":1,"op":"disk-dirty","since":"boot"}"#,
                Request::DiskDirty(DirtySince::Boot),
            ),
            (
                r#"{"v":1,"op":"disk-dirty","since":"round"}"#,
                Request::DiskDirty(DirtySince::Round),
            ),
            (
                r#"{"v":1,"op":"disk-blocks","blocks":[0,7,9]}"#,
                Request::DiskBlocks(BlockSelection::Blocks(vec![0, 7, 9])),
            ),
            (
                r#"{"v":1,"op":"disk-blocks","round":3}"#,
                Request::DiskBlocks(BlockSelection::Round(3)),
            ),
        ] {
            assert_eq!(parse_request(line), Ok(want), "{line}");
        }
    }

    #[test]
    fn malformed_disk_requests_are_refused() {
        for line in [
            r#"{"v":1,"op":"disk-dirty"}"#,
            r#"{"v":1,"op":"disk-dirty","since":"now"}"#,
            r#"{"v":1,"op":"disk-blocks"}"#,
            r#"{"v":1,"op":"disk-blocks","blocks":[1],"round":1}"#,
            r#"{"v":1,"op":"disk-blocks","blocks":[-1]}"#,
            r#"{"v":1,"op":"disk-blocks","blocks":[1.5]}"#,
            r#"{"v":1,"op":"disk-blocks","blocks":"1"}"#,
            r#"{"v":1,"op":"disk-blocks","round":4294967296}"#,
        ] {
            assert_eq!(refused(line).0, ErrorCode::BadRequest, "{line}");
        }
        let many = format!(
            r#"{{"v":1,"op":"disk-blocks","blocks":[{}]}}"#,
            vec!["1"; MAX_REQUEST_BLOCKS + 1].join(",")
        );
        assert!(refused(&many).1.contains("at most 4096"));
    }

    // The longest list a request may name fits a request line even with
    // the widest block numbers of a disk under 2^56 bytes, so it is parsed,
    // not cut off as too long.
    #[test]
    fn the_longest_block_list_fits_a_request_line() {
        let widest = ((1u64 << 56) / (64 << 10) - 1).to_string();
        assert_eq!(widest.len(), 13);
        let line = format!(
            r#"{{"v":1,"op":"disk-blocks","blocks":[{}]}}"#,
            vec![widest.as_str(); MAX_REQUEST_BLOCKS].join(",")
        );
        assert!(line.len() <= MAX_LINE, "{} bytes", line.len());
        match parse_request(&line) {
            Ok(Request::DiskBlocks(BlockSelection::Blocks(list))) => {
                assert_eq!(list.len(), MAX_REQUEST_BLOCKS);
            }
            other => panic!("{other:?}"),
        }
    }

    // A client that ends lines with CRLF, as `nc -C` and some libraries do,
    // still speaks the protocol.
    #[test]
    fn a_carriage_return_before_the_newline_is_ignored() {
        assert_eq!(
            parse_request("{\"v\":1,\"op\":\"status\"}\r"),
            Ok(Request::Status)
        );
    }

    #[test]
    fn malformed_requests_are_refused_with_a_code() {
        assert_eq!(refused("pause").0, ErrorCode::BadRequest);
        assert_eq!(
            refused("[1]"),
            (ErrorCode::BadRequest, "not a JSON object".into())
        );
        assert_eq!(
            refused(r#"{"op":"pause"}"#),
            (ErrorCode::UnsupportedVersion, "\"v\" must be 1".into())
        );
        assert_eq!(
            refused(r#"{"v":2,"op":"pause"}"#).0,
            ErrorCode::UnsupportedVersion
        );
        assert_eq!(
            refused(r#"{"v":"1","op":"pause"}"#).0,
            ErrorCode::UnsupportedVersion
        );
        assert_eq!(
            refused(r#"{"v":1,"op":7}"#),
            (ErrorCode::BadRequest, "\"op\" must be a string".into())
        );
        assert_eq!(
            refused(r#"{"v":1,"op":"reboot"}"#),
            (ErrorCode::UnknownOp, "no operation \"reboot\"".into())
        );
        assert_eq!(
            refused(r#"{"v":1,"op":"checkpoint"}"#).0,
            ErrorCode::BadRequest
        );
        assert_eq!(
            refused(r#"{"v":1,"op":"checkpoint","dir":""}"#).0,
            ErrorCode::BadRequest
        );
        assert_eq!(
            refused(r#"{"v":1,"op":"checkpoint","dir":"/d","then":"wait"}"#).0,
            ErrorCode::BadRequest
        );
        assert_eq!(
            refused(r#"{"v":1,"op":"checkpoint","dir":"/d","txid":7}"#).0,
            ErrorCode::BadRequest
        );
        assert_eq!(
            refused(r#"{"v":1,"op":"checkpoint","dir":"/d","epoch":-1}"#).0,
            ErrorCode::BadRequest
        );
        for line in [
            r#"{"v":1,"op":"migrate","then":"later"}"#,
            r#"{"v":1,"op":"migrate","max_rounds":0}"#,
            r#"{"v":1,"op":"migrate","max_rounds":17}"#,
            r#"{"v":1,"op":"migrate","max_secs":3601}"#,
            r#"{"v":1,"op":"migrate","epoch":"1"}"#,
        ] {
            assert_eq!(refused(line).0, ErrorCode::BadRequest, "{line}");
        }
    }

    // The replies are the wire format hull parses, pinned byte for byte so a
    // reordered or renamed field is a deliberate change.
    #[test]
    fn replies_are_pinned() {
        assert_eq!(
            format_response(&Response::State(VmState::Paused)),
            r#"{"v":1,"ok":true,"state":"paused"}"#
        );
        assert_eq!(
            format_response(&Response::State(VmState::Stopping)),
            r#"{"v":1,"ok":true,"state":"stopping"}"#
        );
        assert_eq!(
            format_response(&Response::Status {
                state: VmState::Running,
                vcpus: 2,
                vcpus_parked: 0,
            }),
            r#"{"v":1,"ok":true,"state":"running","vcpus":2,"vcpus_parked":0}"#
        );
        assert_eq!(
            format_response(&Response::Status {
                state: VmState::Fenced,
                vcpus: 4,
                vcpus_parked: 4,
            }),
            r#"{"v":1,"ok":true,"state":"fenced","vcpus":4,"vcpus_parked":4}"#
        );
        assert_eq!(
            format_response(&Response::Error(Error::new(
                ErrorCode::NotImplemented,
                "checkpoint is not implemented"
            ))),
            r#"{"v":1,"ok":false,"code":"not_implemented","error":"checkpoint is not implemented"}"#
        );
        assert_eq!(
            format_response(&Response::Checkpoint {
                state: VmState::Fenced,
                dir: "/ck/1".into(),
                manifest_sha256: "ab".into(),
                stats: CheckpointStats {
                    pause_ms: 3,
                    capture_ms: 900,
                    ram_present_bytes: 4096,
                    ram_total_bytes: 8192,
                    bundle_bytes: 5000,
                },
            }),
            concat!(
                r#"{"v":1,"ok":true,"state":"fenced","dir":"/ck/1","manifest_sha256":"ab","#,
                r#""stats":{"pause_ms":3,"capture_ms":900,"ram_present_bytes":4096,"#,
                r#""ram_total_bytes":8192,"bundle_bytes":5000}}"#
            )
        );
    }

    #[test]
    fn disk_replies_are_pinned() {
        assert_eq!(
            format_response(&Response::DiskDirty(DiskDirtyReply {
                since: "round",
                round: 2,
                block_size: 65536,
                blocks: 10,
                dirty: 2,
                generation: 41,
                bitmap_sha256: "ab".repeat(32),
                bitmap_b64: "AQI=".into(),
            })),
            format!(
                concat!(
                    r#"{{"v":1,"ok":true,"since":"round","round":2,"block_size":65536,"#,
                    r#""blocks":10,"dirty":2,"generation":41,"bitmap_sha256":"{}","#,
                    r#""bitmap_b64":"AQI="}}"#
                ),
                "ab".repeat(32)
            )
        );
        assert_eq!(
            format_response(&Response::DiskBlocks(DiskBlocksReply {
                round: None,
                blocks: 2,
                bytes: 131_072,
                batches: 1,
                generation: 41,
                max_lock_us: 90,
                sent_sha256: "cd".repeat(32),
            })),
            format!(
                concat!(
                    r#"{{"v":1,"ok":true,"blocks":2,"bytes":131072,"batches":1,"#,
                    r#""generation":41,"max_lock_us":90,"sent_sha256":"{}"}}"#
                ),
                "cd".repeat(32)
            )
        );
        let line = format_response(&Response::DiskBlocks(DiskBlocksReply {
            round: Some(3),
            blocks: 0,
            bytes: 0,
            batches: 0,
            generation: 41,
            max_lock_us: 0,
            sent_sha256: "cd".repeat(32),
        }));
        assert!(
            line.starts_with(r#"{"v":1,"ok":true,"round":3,"blocks":0,"#),
            "{line}"
        );
    }

    #[test]
    fn a_profile_reply_carries_the_profile_whole() {
        use crate::checkpoint::profile::{Cpu, Firmware, Host};
        let profile = MachineProfile {
            profile_version: 1,
            arch: "aarch64".into(),
            backend: "kvm".into(),
            hvi_build: crate::checkpoint::profile::this_build(),
            checkpoint_format: 1,
            host: Host {
                os: "linux".into(),
                kernel_or_macos_build: "6.12.25".into(),
            },
            cpu: Cpu {
                ident: Some("0x414fd0b1".into()),
                id_regs: std::collections::BTreeMap::new(),
            },
            counter_freq_hz: 54_000_000,
            gic: None,
            x86: None,
            page_size: 4096,
            ram_regions: Vec::new(),
            vcpus: 1,
            devices: Vec::new(),
            firmware: Firmware {
                psci_version: None,
                dtb_sha256: None,
                boot_params_sha256: None,
            },
            agent_sock: false,
            fs_shares: 0,
            profile: crate::checkpoint::profile::NATIVE.into(),
            baseline: None,
            irq: None,
            time: None,
            disk_base_sha256: None,
        };
        let line = format_response(&Response::Profile(Box::new(profile.clone())));
        let expected = format!(r#"{{"v":1,"ok":true,"profile":{}}}"#, profile.to_json());
        assert_eq!(line, expected);
    }

    // A message with a quote or a newline must stay one line of valid JSON,
    // or a client reading line by line would split the reply.
    #[test]
    fn an_error_message_is_escaped() {
        let line = format_response(&Response::Error(Error::new(
            ErrorCode::BadRequest,
            "not JSON: \"x\"\nat line 1",
        )));
        assert!(!line.contains('\n'));
        let back: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(back["error"], "not JSON: \"x\"\nat line 1");
    }

    #[test]
    fn every_code_has_its_own_spelling() {
        let codes = [
            ErrorCode::BadRequest,
            ErrorCode::UnsupportedVersion,
            ErrorCode::UnknownOp,
            ErrorCode::TooLong,
            ErrorCode::NotImplemented,
            ErrorCode::Timeout,
            ErrorCode::Busy,
            ErrorCode::Stopped,
            ErrorCode::Fenced,
            ErrorCode::NotReady,
            ErrorCode::Refused,
            ErrorCode::CaptureFailed,
        ];
        let spellings: std::collections::BTreeSet<_> = codes.iter().map(|c| c.as_str()).collect();
        assert_eq!(spellings.len(), codes.len());
    }
}

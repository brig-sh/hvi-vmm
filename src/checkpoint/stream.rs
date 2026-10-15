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

//! The streamed bundle, `checkpoint_format` 3 (2 before it carried the
//! disk): a checkpoint as one byte stream instead of a directory, so the
//! destination reads it as the source writes it.
//!
//! The stream is a sequence of frames. Each frame is one line of JSON,
//! [`FrameHeader`], `{"component":NAME,"size":N,"sha256":HEX}`, then exactly
//! `N` bytes whose SHA-256 is `HEX`. The components come in this order:
//!
//! | component | frames | holds |
//! |---|---|---|
//! | `profile.json` | 1 | the source's machine profile |
//! | `disk-round-k`, then `ram-round-k`, for each round `k` taken with the guest running | 1 or more each | the disk's blocks written since the disk round before (round 0: since boot), then guest RAM, see below |
//! | `disk-round-final`, then `ram-round-K` | 1 or more each | the same, taken paused |
//! | `cpu.json`, `platform.json`, `devices.json` | 1 each | as in the directory bundle |
//! | `disk.json` | 1, when the guest has a disk | as in the directory bundle |
//! | `session.json` | 1 | as in the directory bundle |
//! | `manifest.json` | 1 | [`StreamManifest`]: every other component's size, SHA-256 and frame count |
//!
//! A RAM round is cut into frames of about [`FRAME_TARGET`] bytes, so the
//! writer holds one frame, never a whole round, and the reader checks each
//! frame's hash before it applies a byte of it. The manifest gives a round's
//! total size, its frame count and the SHA-256 of all its frames' bytes in
//! order, so a frame dropped, repeated or reordered is refused too.
//!
//! A frame of a RAM round is a sequence of chunks. A chunk covers 1 to
//! [`CHUNK_PAGES`] consecutive 4 KiB pages in one region and is a
//! [`CHUNK_HEADER_LEN`]-byte header, little-endian, then its payload:
//!
//! | bytes | field |
//! |---|---|
//! | 0..8 | the first page, counted from page 0 of the first region across every region in order |
//! | 8..16 | the present bitmap: bit `i` set means page `first + i` is in the payload; clear means it is all zero |
//! | 16..18 | the page count |
//! | 18..20 | flags: bit 0 set means the payload is the pages as they are, clear means LZ4 |
//! | 20..24 | the payload length |
//!
//! The disk rounds are there only when the guest's disk has a base image
//! the destination holds; a stream either has a disk round before every
//! RAM round or none at all. A disk round is a sequence of chunks of up to
//! [`DISK_CHUNK_BLOCKS`] adjacent 64 KiB blocks, in ascending order, each
//! block at most once (see [`DiskRoundWriter`]), which the reader writes
//! into its copy of the base as they arrive, a later round over an earlier
//! one. The manifest lists every disk round as it lists the RAM rounds.
//!
//! The payload is the present pages in order, as one LZ4 block, or as they
//! are when LZ4 would not make them smaller. A page whose bit is clear is
//! zero: round 0 leaves out a chunk whose pages are all zero, since fresh
//! guest RAM is zero, and a later round sends the chunk so the destination
//! zeroes a page that was written and is zero again. A page of a later
//! round overwrites what an earlier round wrote there.
//!
//! The source may end the stream early with a line that is a control
//! reply, `{"v":1,"ok":false,...}`, where a frame header was due. Every
//! limit below is checked before the reader allocates by a number it read.

use std::collections::BTreeSet;
use std::io::{self, BufRead, Read, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::checkpoint::bundle::{hex, Component};
use crate::checkpoint::profile::HviBuild;
use crate::checkpoint::ram::{MAX_REGIONS, PAGE_SIZE};
use crate::devices::virtio::block::{DirtyBlocks, DIRTY_BLOCK_BYTES};
use crate::memory::{DirtyPages, GuestRam};

/// The `checkpoint_format` of a streamed bundle that carries the disk's
/// blocks. One without them is 2, as before them, and the reader takes
/// both.
pub const STREAM_FORMAT: u32 = 3;

/// The longest frame header line the reader takes, newline included.
pub const MAX_HEADER_LINE: usize = 1024;

/// The size at which the writer ends a RAM frame and starts the next.
pub const FRAME_TARGET: usize = 1 << 20;

/// The largest RAM frame the reader takes.
pub const MAX_RAM_FRAME: u64 = 8 << 20;

/// The most pages one chunk covers.
pub const CHUNK_PAGES: u64 = 64;

/// The length of a chunk's header.
pub const CHUNK_HEADER_LEN: usize = 24;

/// The most RAM rounds the reader takes.
pub const MAX_ROUNDS: u32 = 64;

/// The largest manifest the reader takes.
pub const MAX_MANIFEST: u64 = 1 << 20;

/// The largest guest the reader builds RAM for, as the directory bundle's
/// largest `ram.bin`.
pub const MAX_RAM_BYTES: u64 = crate::checkpoint::bundle::MAX_COMPONENT_BYTES;

/// The chunk flag for a payload stored as it is.
const FLAG_RAW: u16 = 1;

/// The name of the manifest component.
pub const MANIFEST: &str = "manifest.json";

/// The largest disk frame the reader takes.
pub const MAX_DISK_FRAME: u64 = 8 << 20;

/// The most blocks one disk chunk covers: 1 MiB of 64 KiB blocks.
pub const DISK_CHUNK_BLOCKS: u64 = 16;

/// The length of a disk chunk's header.
pub const DISK_CHUNK_HEADER_LEN: usize = 24;

/// The name of the disk round taken with the guest paused.
pub const DISK_FINAL: &str = "disk-round-final";

/// The name of RAM round `round`.
#[must_use]
pub fn round_name(round: u32) -> String {
    format!("ram-round-{round}")
}

/// The name of disk round `round`, taken with the guest running.
#[must_use]
pub fn disk_round_name(round: u32) -> String {
    format!("disk-round-{round}")
}

/// Returns the number after `prefix` in `name`: 1 to 3 digits, with no
/// leading zero.
fn number_after(name: &str, prefix: &str) -> Option<u32> {
    let digits = name.strip_prefix(prefix)?;
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    digits.parse().ok()
}

/// Returns the round `name` is the RAM of, if it is one.
fn round_of(name: &str) -> Option<u32> {
    number_after(name, "ram-round-")
}

/// A disk round's place, as its component name gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiskRound {
    /// Round `k`, taken with the guest running, before RAM round `k`.
    Running(u32),
    /// The round taken paused, before the final RAM round.
    Final,
}

/// Returns the disk round `name` is, if it is one.
fn disk_round_of(name: &str) -> Option<DiskRound> {
    if name == DISK_FINAL {
        return Some(DiskRound::Final);
    }
    number_after(name, "disk-round-").map(DiskRound::Running)
}

/// Returns an `InvalidData` error naming `what`.
fn bad(what: &str, why: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{what}: {why}"))
}

/// The line that opens a frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameHeader {
    /// The component the frame belongs to.
    pub component: String,
    /// The length of the frame's bytes.
    pub size: u64,
    /// Their SHA-256, lowercase hex.
    pub sha256: String,
}

/// One component as the manifest lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamComponent {
    /// Its name, as each of its frames gives it.
    pub name: String,
    /// The length of all its frames' bytes.
    pub size: u64,
    /// The SHA-256 of all its frames' bytes, in order.
    pub sha256: String,
    /// Its frames.
    pub frames: u64,
}

/// A region of guest RAM, as the manifest lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRegion {
    /// The guest-physical address it starts at.
    pub gpa: u64,
    /// Its length in bytes.
    pub size: u64,
}

/// What one RAM round carried.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundSummary {
    /// Its number, from 0.
    pub round: u32,
    /// The pages its chunks cover, zero or not.
    pub pages: u64,
    /// The pages it carries bytes for.
    pub data_pages: u64,
    /// The length of its frames' bytes.
    pub bytes: u64,
    /// Whether the source took it paused: the last round always is.
    pub in_pause: bool,
}

/// RAM as the manifest describes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRam {
    /// The page size of the chunks, [`PAGE_SIZE`].
    pub page_size: u64,
    /// The regions, in address order.
    pub regions: Vec<StreamRegion>,
    /// The rounds, in order.
    pub rounds: Vec<RoundSummary>,
}

/// The last component of a stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamManifest {
    /// [`STREAM_FORMAT`].
    pub checkpoint_format: u32,
    /// The hvi that wrote it.
    pub hvi_build: HviBuild,
    /// Every component before the manifest, in stream order.
    pub components: Vec<StreamComponent>,
    /// Guest RAM.
    pub ram: StreamRam,
    /// The SHA-256 of `profile.json`.
    pub profile_sha256: String,
    /// What a restore must be able to load.
    pub capabilities: Vec<String>,
    /// When the source wrote the manifest, in milliseconds since the epoch.
    pub sealed_at_unix_ms: u64,
    /// The disk rounds, when the stream carries the disk's blocks. Absent
    /// otherwise, so a stream without them reads as it did before them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<StreamDisk>,
}

/// The disk rounds as the manifest describes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamDisk {
    /// The size of a block, [`DIRTY_BLOCK_BYTES`].
    pub block_size: u64,
    /// The rounds, in stream order, the paused one last.
    pub rounds: Vec<DiskRoundSummary>,
}

/// What one disk round carried.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskRoundSummary {
    /// Its component name.
    pub name: String,
    /// Whether the source took it paused: only the last one is.
    pub in_pause: bool,
    /// The blocks it carries.
    pub blocks: u64,
    /// Their bytes before compression.
    pub raw_bytes: u64,
    /// The length of its frames' bytes.
    pub bytes: u64,
}

/// Returns whether `s` is a lowercase hex SHA-256.
fn is_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The document components after the RAM rounds, in stream order, with the
/// directory bundle's component of the same document.
pub const DOCS: [(&str, Component); 5] = [
    ("cpu.json", Component::Cpu),
    ("platform.json", Component::Platform),
    ("devices.json", Component::Devices),
    ("disk.json", Component::Disk),
    ("session.json", Component::Session),
];

/// The largest frame the reader takes for `name`, or `None` for a name no
/// stream has.
fn frame_limit(name: &str) -> Option<u64> {
    if name == "profile.json" {
        return Some(Component::Profile.limit());
    }
    if name == MANIFEST {
        return Some(MAX_MANIFEST);
    }
    if round_of(name).is_some() {
        return Some(MAX_RAM_FRAME);
    }
    if disk_round_of(name).is_some() {
        return Some(MAX_DISK_FRAME);
    }
    DOCS.iter()
        .find(|(n, _)| *n == name)
        .map(|(_, c)| c.limit())
}

/// A component as it was written or read: its running hash, size and
/// frame count.
struct Running {
    /// The component's name.
    name: String,
    /// The hash of its frames' bytes so far.
    hasher: Sha256,
    /// Their length so far.
    size: u64,
    /// Its frames so far.
    frames: u64,
}

impl Running {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            hasher: Sha256::new(),
            size: 0,
            frames: 0,
        }
    }

    fn add(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.size += bytes.len() as u64;
        self.frames += 1;
    }

    fn finish(self) -> StreamComponent {
        StreamComponent {
            name: self.name,
            size: self.size,
            sha256: hex(&self.hasher.finalize()),
            frames: self.frames,
        }
    }
}

/// Writes a stream, frame by frame, and keeps what its manifest lists.
pub struct StreamWriter<W> {
    /// Where the frames go.
    out: W,
    /// The components written, in order.
    components: Vec<StreamComponent>,
    /// The rounds written.
    rounds: Vec<RoundSummary>,
    /// The disk rounds written.
    disk_rounds: Vec<DiskRoundSummary>,
    /// Every byte written, headers included.
    written: u64,
}

impl<W: Write> StreamWriter<W> {
    /// Starts a stream on `out`.
    pub fn new(out: W) -> Self {
        Self {
            out,
            components: Vec::new(),
            rounds: Vec::new(),
            disk_rounds: Vec::new(),
            written: 0,
        }
    }

    /// Writes one frame of `name`: its header line, then `bytes`.
    fn frame(&mut self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let header = FrameHeader {
            component: name.to_string(),
            size: bytes.len() as u64,
            sha256: hex(&Sha256::digest(bytes)),
        };
        let mut line = serde_json::to_vec(&header).map_err(io::Error::other)?;
        line.push(b'\n');
        self.out.write_all(&line)?;
        self.out.write_all(bytes)?;
        self.written += (line.len() + bytes.len()) as u64;
        Ok(())
    }

    /// Writes the document `name` as one frame.
    ///
    /// # Errors
    ///
    /// Errors when it is larger than the reader takes, or the write fails.
    pub fn write_doc(&mut self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let limit = frame_limit(name).ok_or_else(|| bad(name, "is not a stream component"))?;
        if bytes.len() as u64 > limit {
            return Err(bad(
                name,
                format!(
                    "would be {} bytes, the reader takes at most {limit}",
                    bytes.len()
                ),
            ));
        }
        self.frame(name, bytes)?;
        let mut running = Running::new(name);
        running.add(bytes);
        self.components.push(running.finish());
        Ok(())
    }

    /// Starts the next RAM round.
    pub fn round(&mut self, in_pause: bool) -> RoundWriter<'_, W> {
        let round = self.rounds.len() as u32;
        RoundWriter {
            name: round_name(round),
            running: Running::new(&round_name(round)),
            summary: RoundSummary {
                round,
                in_pause,
                ..RoundSummary::default()
            },
            frame: Vec::with_capacity(FRAME_TARGET + CHUNK_HEADER_LEN + CHUNK_BYTES),
            stream: self,
        }
    }

    /// Starts the next disk round: the paused one with `in_pause`, else
    /// the next one taken with the guest running.
    pub fn disk_round(&mut self, in_pause: bool) -> DiskRoundWriter<'_, W> {
        let name = if in_pause {
            DISK_FINAL.to_string()
        } else {
            disk_round_name(self.disk_rounds.len() as u32)
        };
        DiskRoundWriter {
            running: Running::new(&name),
            summary: DiskRoundSummary {
                name,
                in_pause,
                ..DiskRoundSummary::default()
            },
            frame: Vec::with_capacity(FRAME_TARGET + DISK_CHUNK_HEADER_LEN + DISK_CHUNK_BYTES),
            stream: self,
        }
    }

    /// Returns the rounds written so far.
    #[must_use]
    pub fn rounds(&self) -> &[RoundSummary] {
        &self.rounds
    }

    /// Returns every byte written so far, headers included.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Writes the manifest, which seals the stream, and returns it with its
    /// SHA-256. `regions` is guest RAM's layout and `profile_sha256` the
    /// hash of the profile written first.
    ///
    /// # Errors
    ///
    /// Errors when the write fails.
    pub fn seal(
        &mut self,
        build: HviBuild,
        regions: Vec<StreamRegion>,
        capabilities: Vec<String>,
        sealed_at_unix_ms: u64,
    ) -> io::Result<(StreamManifest, String)> {
        let profile_sha256 = self
            .components
            .first()
            .filter(|c| c.name == "profile.json")
            .map(|c| c.sha256.clone())
            .ok_or_else(|| bad(MANIFEST, "the stream did not start with profile.json"))?;
        let manifest = StreamManifest {
            // A stream without disk rounds is format 2 as it was, so an
            // hvi from before them still reads it.
            checkpoint_format: if self.disk_rounds.is_empty() {
                2
            } else {
                STREAM_FORMAT
            },
            hvi_build: build,
            components: self.components.clone(),
            ram: StreamRam {
                page_size: PAGE_SIZE,
                regions,
                rounds: self.rounds.clone(),
            },
            profile_sha256,
            capabilities,
            sealed_at_unix_ms,
            disk: (!self.disk_rounds.is_empty()).then(|| StreamDisk {
                block_size: DIRTY_BLOCK_BYTES,
                rounds: self.disk_rounds.clone(),
            }),
        };
        let bytes = serde_json::to_vec(&manifest).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_MANIFEST {
            return Err(bad(MANIFEST, "would be larger than the reader takes"));
        }
        self.frame(MANIFEST, &bytes)?;
        self.out.flush()?;
        Ok((manifest, hex(&Sha256::digest(&bytes))))
    }

    /// Writes `line` and a newline after the frames: the reply that ends a
    /// control connection's stream.
    ///
    /// # Errors
    ///
    /// Errors when the write fails.
    pub fn line(&mut self, line: &str) -> io::Result<()> {
        self.out.write_all(line.as_bytes())?;
        self.out.write_all(b"\n")?;
        self.out.flush()
    }
}

/// The largest uncompressed payload of a chunk.
const CHUNK_BYTES: usize = (CHUNK_PAGES * PAGE_SIZE) as usize;

/// One RAM round being written: chunks gathered into frames of about
/// [`FRAME_TARGET`] bytes.
pub struct RoundWriter<'a, W: Write> {
    /// The round's component name.
    name: String,
    /// Its running hash.
    running: Running,
    /// What it carried.
    summary: RoundSummary,
    /// The frame being filled.
    frame: Vec<u8>,
    /// The stream it belongs to.
    stream: &'a mut StreamWriter<W>,
}

impl<W: Write> RoundWriter<'_, W> {
    /// Adds a chunk of the `count` pages from page `first` (counted across
    /// regions), whose bytes are `pages`, `count` pages long. A page of
    /// zeros is sent as a clear bit. With `skip_empty`, a chunk whose pages
    /// are all zero is left out.
    ///
    /// # Errors
    ///
    /// Errors when `pages` is not `count` pages of 1 to [`CHUNK_PAGES`], or
    /// a write fails.
    pub fn chunk(
        &mut self,
        enc: &mut ChunkEncoder,
        first: u64,
        pages: &[u8],
        skip_empty: bool,
    ) -> io::Result<()> {
        let count = pages.len() as u64 / PAGE_SIZE;
        if count == 0 || count > CHUNK_PAGES || pages.len() as u64 % PAGE_SIZE != 0 {
            return Err(io::Error::other(format!(
                "a chunk of {} bytes is not 1 to {CHUNK_PAGES} pages",
                pages.len()
            )));
        }
        let present = enc.encode(first, pages, &mut self.frame);
        match present {
            None if skip_empty => {}
            None | Some(_) => {
                self.summary.pages += count;
                self.summary.data_pages += u64::from(present.unwrap_or(0).count_ones());
            }
        }
        if present.is_none() && skip_empty {
            enc.unwrite(&mut self.frame);
        }
        if self.frame.len() >= FRAME_TARGET {
            self.flush()?;
        }
        Ok(())
    }

    /// Writes the frame being filled, if it holds anything.
    fn flush(&mut self) -> io::Result<()> {
        if self.frame.is_empty() {
            return Ok(());
        }
        self.stream.frame(&self.name, &self.frame)?;
        self.running.add(&self.frame);
        self.summary.bytes += self.frame.len() as u64;
        self.frame.clear();
        Ok(())
    }

    /// Ends the round and returns what it carried. A round with no chunk is
    /// written as one empty frame, so every round has at least one.
    ///
    /// # Errors
    ///
    /// Errors when the write fails.
    pub fn finish(mut self) -> io::Result<RoundSummary> {
        self.flush()?;
        if self.running.frames == 0 {
            self.stream.frame(&self.name, &[])?;
            self.running.add(&[]);
        }
        let component = std::mem::replace(&mut self.running, Running::new("")).finish();
        self.stream.components.push(component);
        self.stream.rounds.push(self.summary.clone());
        Ok(self.summary.clone())
    }
}

/// The largest uncompressed payload of a disk chunk.
const DISK_CHUNK_BYTES: usize = (DISK_CHUNK_BLOCKS * DIRTY_BLOCK_BYTES) as usize;

/// One disk round being written: chunks of adjacent blocks gathered into
/// frames of about [`FRAME_TARGET`] bytes.
///
/// A disk chunk is a [`DISK_CHUNK_HEADER_LEN`]-byte header, little-endian,
/// then its payload:
///
/// | bytes | field |
/// |---|---|
/// | 0..8 | the first block |
/// | 8..12 | the block count, 1 to [`DISK_CHUNK_BLOCKS`] |
/// | 12..16 | flags: bit 0 set means the payload is the blocks as they are, clear means LZ4 |
/// | 16..20 | the length of the blocks: whole blocks, but the disk's last, which may be short |
/// | 20..24 | the payload length |
pub struct DiskRoundWriter<'a, W: Write> {
    /// Its running hash.
    running: Running,
    /// What it carried.
    summary: DiskRoundSummary,
    /// The frame being filled.
    frame: Vec<u8>,
    /// The stream it belongs to.
    stream: &'a mut StreamWriter<W>,
}

impl<W: Write> DiskRoundWriter<'_, W> {
    /// Adds a chunk of the `count` blocks from block `first`, whose bytes
    /// are `blocks`.
    ///
    /// # Errors
    ///
    /// Errors when `count` is not 1 to [`DISK_CHUNK_BLOCKS`], `blocks` is
    /// not `count` blocks long (the last may be short), or a write fails.
    pub fn chunk(
        &mut self,
        enc: &mut DiskEncoder,
        first: u64,
        count: u64,
        blocks: &[u8],
    ) -> io::Result<()> {
        let len = blocks.len() as u64;
        if count == 0
            || count > DISK_CHUNK_BLOCKS
            || len > count * DIRTY_BLOCK_BYTES
            || len <= (count - 1) * DIRTY_BLOCK_BYTES
        {
            return Err(io::Error::other(format!(
                "a disk chunk of {len} bytes is not {count} blocks"
            )));
        }
        enc.encode(first, count, blocks, &mut self.frame);
        self.summary.blocks += count;
        self.summary.raw_bytes += len;
        if self.frame.len() >= FRAME_TARGET {
            self.flush()?;
        }
        Ok(())
    }

    /// Writes the frame being filled, if it holds anything.
    fn flush(&mut self) -> io::Result<()> {
        if self.frame.is_empty() {
            return Ok(());
        }
        self.stream.frame(&self.summary.name, &self.frame)?;
        self.running.add(&self.frame);
        self.summary.bytes += self.frame.len() as u64;
        self.frame.clear();
        Ok(())
    }

    /// Ends the round and returns what it carried with the SHA-256 of all
    /// its frames' bytes, the digest the manifest lists for it. A round
    /// with no block is written as one empty frame.
    ///
    /// # Errors
    ///
    /// Errors when the write fails.
    pub fn finish(mut self) -> io::Result<(DiskRoundSummary, String)> {
        self.flush()?;
        if self.running.frames == 0 {
            self.stream.frame(&self.summary.name, &[])?;
            self.running.add(&[]);
        }
        let component = std::mem::replace(&mut self.running, Running::new("")).finish();
        let sha256 = component.sha256.clone();
        self.stream.components.push(component);
        self.stream.disk_rounds.push(self.summary.clone());
        Ok((self.summary.clone(), sha256))
    }
}

/// The buffer a disk chunk is compressed into, reused from chunk to chunk.
pub struct DiskEncoder {
    /// The LZ4 block.
    compressed: Vec<u8>,
}

impl Default for DiskEncoder {
    fn default() -> Self {
        Self {
            compressed: vec![0; lz4_flex::block::get_maximum_output_size(DISK_CHUNK_BYTES)],
        }
    }
}

impl DiskEncoder {
    /// Appends the chunk of the `count` blocks from `first`, `blocks`, to
    /// `out`, compressed unless that would make it larger.
    fn encode(&mut self, first: u64, count: u64, blocks: &[u8], out: &mut Vec<u8>) {
        let (flags, payload): (u32, &[u8]) =
            match lz4_flex::block::compress_into(blocks, &mut self.compressed) {
                Ok(n) if n < blocks.len() => (0, &self.compressed[..n]),
                _ => (u32::from(FLAG_RAW), blocks),
            };
        out.extend_from_slice(&first.to_le_bytes());
        out.extend_from_slice(&(count as u32).to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
    }
}

/// The buffers a chunk is encoded in, reused from chunk to chunk.
pub struct ChunkEncoder {
    /// The present pages, packed.
    packed: Vec<u8>,
    /// The LZ4 block.
    compressed: Vec<u8>,
    /// Where the last chunk started in its frame, for `unwrite`.
    last_start: usize,
}

impl Default for ChunkEncoder {
    fn default() -> Self {
        Self {
            packed: Vec::with_capacity(CHUNK_BYTES),
            compressed: vec![0; lz4_flex::block::get_maximum_output_size(CHUNK_BYTES)],
            last_start: 0,
        }
    }
}

impl ChunkEncoder {
    /// Appends the chunk of `pages` from page `first` to `out`, and returns
    /// its present bitmap, or `None` when every page is zero.
    fn encode(&mut self, first: u64, pages: &[u8], out: &mut Vec<u8>) -> Option<u64> {
        self.last_start = out.len();
        self.packed.clear();
        let mut present = 0u64;
        let count = pages.len() / PAGE_SIZE as usize;
        for (i, page) in pages.chunks_exact(PAGE_SIZE as usize).enumerate() {
            if !is_zero(page) {
                present |= 1 << i;
                self.packed.extend_from_slice(page);
            }
        }
        let (flags, payload): (u16, &[u8]) = if present == 0 {
            (0, &[])
        } else {
            match lz4_flex::block::compress_into(&self.packed, &mut self.compressed) {
                Ok(n) if n < self.packed.len() => (0, &self.compressed[..n]),
                _ => (FLAG_RAW, &self.packed),
            }
        };
        out.extend_from_slice(&first.to_le_bytes());
        out.extend_from_slice(&present.to_le_bytes());
        out.extend_from_slice(&(count as u16).to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        (present != 0).then_some(present)
    }

    /// Takes the last chunk back out of `out`.
    fn unwrite(&self, out: &mut Vec<u8>) {
        out.truncate(self.last_start);
    }
}

/// Returns whether every 8-byte word of `page` is zero.
#[must_use]
pub fn is_zero(page: &[u8]) -> bool {
    page.chunks_exact(8)
        .all(|w| u64::from_ne_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]) == 0)
}

/// Guest RAM as a stream addresses it: page numbers counted across the
/// regions in address order.
#[derive(Clone, Debug)]
pub struct PageSpace {
    /// Each region's guest-physical address, first global page and pages.
    regions: Vec<(u64, u64, u64)>,
}

impl PageSpace {
    /// Returns the page space of `regions`, which must be in address order
    /// and whole pages.
    ///
    /// # Errors
    ///
    /// Errors when there are none or more than [`MAX_REGIONS`], one is not
    /// whole pages, they are not in address order or overlap, or together
    /// they are larger than [`MAX_RAM_BYTES`].
    pub fn new(regions: &[StreamRegion]) -> io::Result<Self> {
        if regions.is_empty() || regions.len() > MAX_REGIONS {
            return Err(bad(
                "profile.json",
                format!("{} RAM regions, 1 to {MAX_REGIONS}", regions.len()),
            ));
        }
        let mut out = Vec::with_capacity(regions.len());
        let mut next = 0u64;
        let mut end = 0u64;
        let mut total = 0u64;
        for r in regions {
            if r.size == 0 || r.size % PAGE_SIZE != 0 || r.gpa % PAGE_SIZE != 0 {
                return Err(bad(
                    "profile.json",
                    format!("RAM region {:#x}+{:#x} is not whole pages", r.gpa, r.size),
                ));
            }
            if r.gpa < end {
                return Err(bad(
                    "profile.json",
                    "RAM regions overlap or are out of order",
                ));
            }
            total = total.saturating_add(r.size);
            if total > MAX_RAM_BYTES {
                return Err(bad(
                    "profile.json",
                    format!("more than {MAX_RAM_BYTES} bytes of RAM"),
                ));
            }
            end = r
                .gpa
                .checked_add(r.size)
                .ok_or_else(|| bad("profile.json", "a RAM region wraps"))?;
            out.push((r.gpa, next, r.size / PAGE_SIZE));
            next += r.size / PAGE_SIZE;
        }
        Ok(Self { regions: out })
    }

    /// Returns the global number of page `page` of region `index`.
    #[must_use]
    pub fn global(&self, index: usize, page: u64) -> u64 {
        self.regions[index].1 + page
    }

    /// Returns the region and its page of the `count` pages from global page
    /// `first`, when they lie in one region.
    #[must_use]
    pub fn locate(&self, first: u64, count: u64) -> Option<(usize, u64)> {
        let end = first.checked_add(count)?;
        self.regions
            .iter()
            .enumerate()
            .find(|(_, (_, start, pages))| first >= *start && end <= start + pages)
            .map(|(index, (_, start, _))| (index, first - start))
    }

    /// Returns the guest-physical address of page `page` of region `index`.
    #[must_use]
    pub fn gpa(&self, index: usize, page: u64) -> u64 {
        self.regions[index].0 + page * PAGE_SIZE
    }
}

/// Writes RAM round chunks into guest RAM as they arrive, remembering which
/// pages it wrote so a later zero page is zeroed only where it must be.
pub struct RamApplier {
    /// The page space of the guest.
    space: PageSpace,
    /// The pages written so far.
    touched: DirtyPages,
    /// The decompressed payload of a chunk.
    scratch: Vec<u8>,
}

impl RamApplier {
    /// Returns an applier for `ram`, laid out as `space`.
    #[must_use]
    pub fn new(space: PageSpace, ram: &GuestRam) -> Self {
        Self {
            space,
            touched: DirtyPages::new(&ram.regions()),
            scratch: vec![0; CHUNK_BYTES],
        }
    }

    /// Applies every chunk of one RAM frame to `ram`. Every chunk header is
    /// checked before the first page is written; a payload that does not
    /// decompress to its pages is found as its chunk is applied, and the
    /// chunks before it stay written, so the caller discards the RAM.
    ///
    /// # Errors
    ///
    /// Errors, naming `name`, when a chunk is short, covers pages outside
    /// one region, sets a bit past its count or a flag no writer sets, or
    /// its payload is not exactly its present pages.
    pub fn apply(&mut self, name: &str, frame: &[u8], ram: &GuestRam) -> io::Result<FrameCount> {
        let chunks = self.parse(name, frame)?;
        let mut counted = FrameCount::default();
        for chunk in chunks {
            let present_pages = chunk.present.count_ones() as usize;
            let want = present_pages * PAGE_SIZE as usize;
            let data: &[u8] = if chunk.raw {
                chunk.payload
            } else if want > 0 {
                let n = lz4_flex::block::decompress_into(chunk.payload, &mut self.scratch[..want])
                    .map_err(|e| bad(name, format!("chunk at page {}: {e}", chunk.first)))?;
                if n != want {
                    return Err(bad(
                        name,
                        format!(
                            "chunk at page {} holds {n} bytes, its bitmap {want}",
                            chunk.first
                        ),
                    ));
                }
                &self.scratch[..want]
            } else {
                &[]
            };
            let mut next = 0usize;
            for i in 0..chunk.count {
                let page = chunk.page + i;
                let gpa = self.space.gpa(chunk.region, page);
                if chunk.present & (1 << i) != 0 {
                    ram.write(gpa, &data[next..next + PAGE_SIZE as usize])?;
                    next += PAGE_SIZE as usize;
                    counted.data_pages += 1;
                    self.touched.set_range(chunk.region, page, 1);
                } else if self.touched.contains(chunk.region, page) {
                    ram.write(gpa, &[0; PAGE_SIZE as usize])?;
                }
            }
            counted.pages += chunk.count;
        }
        Ok(counted)
    }

    /// Checks every chunk of `frame` and returns them.
    fn parse<'f>(&self, name: &str, frame: &'f [u8]) -> io::Result<Vec<Chunk<'f>>> {
        let mut chunks = Vec::new();
        let mut rest = frame;
        while !rest.is_empty() {
            if rest.len() < CHUNK_HEADER_LEN {
                return Err(bad(name, "a chunk header is cut short"));
            }
            let (h, tail) = rest.split_at(CHUNK_HEADER_LEN);
            let first = u64::from_le_bytes(h[0..8].try_into().expect("8 bytes"));
            let present = u64::from_le_bytes(h[8..16].try_into().expect("8 bytes"));
            let count = u64::from(u16::from_le_bytes([h[16], h[17]]));
            let flags = u16::from_le_bytes([h[18], h[19]]);
            let len = u32::from_le_bytes(h[20..24].try_into().expect("4 bytes")) as usize;
            if count == 0 || count > CHUNK_PAGES {
                return Err(bad(name, format!("a chunk of {count} pages")));
            }
            if count < 64 && present >> count != 0 {
                return Err(bad(
                    name,
                    format!("chunk at page {first}: a bit past its {count} pages"),
                ));
            }
            if flags & !FLAG_RAW != 0 {
                return Err(bad(
                    name,
                    format!("chunk at page {first}: flags {flags:#x}"),
                ));
            }
            let raw = flags & FLAG_RAW != 0;
            let want = present.count_ones() as usize * PAGE_SIZE as usize;
            let fits = if present == 0 {
                len == 0 && !raw
            } else if raw {
                len == want
            } else {
                len > 0 && len <= lz4_flex::block::get_maximum_output_size(want)
            };
            if !fits || len > tail.len() {
                return Err(bad(
                    name,
                    format!(
                        "chunk at page {first}: a {len}-byte payload for {want} bytes of pages"
                    ),
                ));
            }
            let (region, page) = self.space.locate(first, count).ok_or_else(|| {
                bad(
                    name,
                    format!("pages {first}+{count} are not in one RAM region"),
                )
            })?;
            let (payload, after) = tail.split_at(len);
            chunks.push(Chunk {
                first,
                region,
                page,
                count,
                present,
                raw,
                payload,
            });
            rest = after;
        }
        Ok(chunks)
    }
}

/// The disk a stream's disk rounds are written into.
pub trait DiskTarget {
    /// Makes the disk ready for the first block and returns its size in
    /// bytes. Called once, when the first disk round arrives.
    ///
    /// # Errors
    ///
    /// Errors when the disk cannot take the blocks; the stream is then
    /// refused before a block is written.
    fn begin(&mut self) -> io::Result<u64>;

    /// Writes `bytes` at byte `offset` of the disk.
    ///
    /// # Errors
    ///
    /// Errors as the write does.
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()>;

    /// Called as each disk round ends, `in_pause` for the final one, which
    /// is called before the final RAM round is read.
    ///
    /// # Errors
    ///
    /// Errors when the disk cannot keep what was written.
    fn round_end(&mut self, in_pause: bool) -> io::Result<()>;
}

/// What one disk round wrote, as [`receive`] applied it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedDisk {
    /// Its component name.
    pub name: String,
    /// Whether it is the round taken paused.
    pub in_pause: bool,
    /// The blocks it wrote.
    pub blocks: u64,
    /// Their bytes.
    pub raw_bytes: u64,
    /// The SHA-256 of the bitmap of the blocks it wrote, in the bit order
    /// of `disk-dirty`'s `bitmap_b64`, as lowercase hex.
    pub bitmap_sha256: String,
    /// The SHA-256 of all its frames' bytes, as the manifest lists it.
    pub sha256: String,
}

/// Writes disk round chunks into the disk as they arrive.
struct DiskApplier {
    /// The size of the disk in bytes.
    size: u64,
    /// The decompressed payload of a chunk.
    scratch: Vec<u8>,
    /// The round being applied: its name and whether it is the paused one.
    round: Option<(String, bool)>,
    /// The blocks the round wrote so far.
    bitmap: DirtyBlocks,
    /// The last block it wrote.
    last: Option<u64>,
    /// Its blocks and bytes so far.
    blocks: u64,
    /// Their bytes.
    raw_bytes: u64,
}

impl DiskApplier {
    /// Returns an applier for a disk of `size` bytes.
    fn new(size: u64) -> Self {
        Self {
            size,
            scratch: vec![0; DISK_CHUNK_BYTES],
            round: None,
            bitmap: DirtyBlocks::for_size(size),
            last: None,
            blocks: 0,
            raw_bytes: 0,
        }
    }

    /// Starts the round `name`.
    fn start(&mut self, name: &str, in_pause: bool) {
        self.round = Some((name.to_string(), in_pause));
        self.bitmap = DirtyBlocks::for_size(self.size);
        self.last = None;
        self.blocks = 0;
        self.raw_bytes = 0;
    }

    /// Ends the round and returns what it wrote; `sha256` is its
    /// component's digest.
    fn end(&mut self, sha256: String) -> AppliedDisk {
        let (name, in_pause) = self.round.take().unwrap_or_default();
        AppliedDisk {
            name,
            in_pause,
            blocks: self.blocks,
            raw_bytes: self.raw_bytes,
            bitmap_sha256: hex(&Sha256::digest(self.bitmap.as_bytes())),
            sha256,
        }
    }

    /// Returns the length of block `block`: a whole block, or less for the
    /// last block of a disk that is not whole blocks; `None` past the disk.
    fn block_len(&self, block: u64) -> Option<u64> {
        let start = block.checked_mul(DIRTY_BLOCK_BYTES)?;
        (start < self.size).then(|| (self.size - start).min(DIRTY_BLOCK_BYTES))
    }

    /// Applies every chunk of one disk frame to `target`. Every chunk
    /// header is checked before the first block is written.
    ///
    /// # Errors
    ///
    /// Errors, naming `name`, when a chunk is short, covers blocks past the
    /// disk or not after the round's last one, sets a flag no writer sets,
    /// or its payload is not exactly its blocks.
    fn apply(&mut self, name: &str, frame: &[u8], target: &mut dyn DiskTarget) -> io::Result<()> {
        let mut chunks = Vec::new();
        let mut rest = frame;
        let mut last = self.last;
        while !rest.is_empty() {
            if rest.len() < DISK_CHUNK_HEADER_LEN {
                return Err(bad(name, "a disk chunk header is cut short"));
            }
            let (h, tail) = rest.split_at(DISK_CHUNK_HEADER_LEN);
            let first = u64::from_le_bytes(h[0..8].try_into().expect("8 bytes"));
            let count = u64::from(u32::from_le_bytes(h[8..12].try_into().expect("4 bytes")));
            let flags = u32::from_le_bytes(h[12..16].try_into().expect("4 bytes"));
            let raw_len = u32::from_le_bytes(h[16..20].try_into().expect("4 bytes")) as usize;
            let len = u32::from_le_bytes(h[20..24].try_into().expect("4 bytes")) as usize;
            if count == 0 || count > DISK_CHUNK_BLOCKS {
                return Err(bad(name, format!("a disk chunk of {count} blocks")));
            }
            if flags & !u32::from(FLAG_RAW) != 0 {
                return Err(bad(
                    name,
                    format!("disk chunk at block {first}: flags {flags:#x}"),
                ));
            }
            if last.is_some_and(|l| first <= l) {
                return Err(bad(
                    name,
                    format!(
                        "disk chunk at block {first} is not after block {}",
                        last.unwrap_or_default()
                    ),
                ));
            }
            let end = first
                .checked_add(count - 1)
                .ok_or_else(|| bad(name, "a disk chunk past every disk"))?;
            let mut want = 0u64;
            for block in first..=end {
                want += self.block_len(block).ok_or_else(|| {
                    bad(
                        name,
                        format!(
                            "disk chunk at block {first}: block {block} is past the {}-byte \
                             disk",
                            self.size
                        ),
                    )
                })?;
            }
            let raw = flags & u32::from(FLAG_RAW) != 0;
            let fits = if raw {
                len == raw_len
            } else {
                len > 0 && len <= lz4_flex::block::get_maximum_output_size(raw_len)
            };
            if raw_len as u64 != want || !fits || len > tail.len() {
                return Err(bad(
                    name,
                    format!(
                        "disk chunk at block {first}: {raw_len} bytes of blocks in a {len}-byte \
                         payload, for {count} blocks of {want} bytes"
                    ),
                ));
            }
            let (payload, after) = tail.split_at(len);
            chunks.push((first, count, raw, raw_len, payload));
            last = Some(end);
            rest = after;
        }
        for (first, count, raw, raw_len, payload) in chunks {
            let data: &[u8] = if raw {
                payload
            } else {
                let n = lz4_flex::block::decompress_into(payload, &mut self.scratch[..raw_len])
                    .map_err(|e| bad(name, format!("disk chunk at block {first}: {e}")))?;
                if n != raw_len {
                    return Err(bad(
                        name,
                        format!("disk chunk at block {first} holds {n} bytes, not {raw_len}"),
                    ));
                }
                &self.scratch[..raw_len]
            };
            target.write_at(first * DIRTY_BLOCK_BYTES, data)?;
            self.bitmap.mark(first * DIRTY_BLOCK_BYTES, raw_len as u64);
            self.blocks += count;
            self.raw_bytes += raw_len as u64;
            self.last = Some(first + count - 1);
        }
        Ok(())
    }
}

/// One chunk of a frame, checked.
struct Chunk<'f> {
    /// Its first page, counted across regions.
    first: u64,
    /// The region it is in.
    region: usize,
    /// Its first page in that region.
    page: u64,
    /// Its pages.
    count: u64,
    /// Which of them it carries.
    present: u64,
    /// Whether the payload is stored as it is.
    raw: bool,
    /// The payload.
    payload: &'f [u8],
}

/// What [`RamApplier::apply`] applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameCount {
    /// The pages its chunks covered.
    pub pages: u64,
    /// The pages it wrote bytes into.
    pub data_pages: u64,
}

/// A frame as read: its component and its bytes, hash checked.
pub struct Frame {
    /// The component it belongs to.
    pub name: String,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

/// Reads frames, checking each header against the limits before it reads
/// the bytes and each hash before it returns them, and keeps every
/// component's running hash for the manifest.
pub struct StreamReader<R> {
    /// The stream.
    input: R,
    /// The components read, in order; the last one may still be growing.
    seen: Vec<Running>,
    /// Every byte read, header lines included.
    read: u64,
}

impl<R: BufRead> StreamReader<R> {
    /// Starts reading `input`.
    pub fn new(input: R) -> Self {
        Self {
            input,
            seen: Vec::new(),
            read: 0,
        }
    }

    /// Returns every byte read so far.
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.read
    }

    /// Reads the next frame.
    ///
    /// # Errors
    ///
    /// Errors when the stream ends, the source ended it with a reply, the
    /// header is not one, names a component no stream has or a size over its
    /// limit, or the bytes do not match its hash.
    pub fn next_frame(&mut self) -> io::Result<Frame> {
        let mut line = Vec::with_capacity(256);
        (&mut self.input)
            .take(MAX_HEADER_LINE as u64)
            .read_until(b'\n', &mut line)?;
        self.read += line.len() as u64;
        if line.is_empty() {
            return Err(bad("stream", "it ended before the manifest"));
        }
        if line.last() != Some(&b'\n') {
            return Err(bad(
                "stream",
                if line.len() >= MAX_HEADER_LINE {
                    "a frame header is longer than the reader takes"
                } else {
                    "it ended inside a frame header"
                },
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&line)
            .map_err(|e| bad("stream", format!("a frame header is not JSON: {e}")))?;
        if value.get("component").is_none() && value.get("ok").is_some() {
            let code = value.get("code").and_then(|c| c.as_str()).unwrap_or("?");
            let error = value.get("error").and_then(|c| c.as_str()).unwrap_or("");
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("the source ended the stream: {code}: {error}"),
            ));
        }
        let header: FrameHeader = serde_json::from_value(value)
            .map_err(|e| bad("stream", format!("not a frame header: {e}")))?;
        let limit = frame_limit(&header.component)
            .ok_or_else(|| bad("stream", format!("no component {:?}", header.component)))?;
        if header.size > limit {
            return Err(bad(
                &header.component,
                format!("a {}-byte frame, at most {limit}", header.size),
            ));
        }
        if !is_sha256(&header.sha256) {
            return Err(bad(&header.component, "no lowercase hex SHA-256"));
        }
        let mut bytes = vec![0u8; header.size as usize];
        self.input.read_exact(&mut bytes).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                bad(&header.component, "the stream ended inside the frame")
            } else {
                e
            }
        })?;
        self.read += header.size;
        if hex(&Sha256::digest(&bytes)) != header.sha256 {
            return Err(bad(
                &header.component,
                "SHA-256 does not match the frame header",
            ));
        }
        if header.component != MANIFEST {
            match self.seen.last_mut() {
                Some(last) if last.name == header.component => last.add(&bytes),
                _ => {
                    let mut running = Running::new(&header.component);
                    running.add(&bytes);
                    self.seen.push(running);
                }
            }
        }
        Ok(Frame {
            name: header.component,
            bytes,
        })
    }

    /// Returns the SHA-256 of all the frames read so far of the last
    /// component named `name`.
    fn sha256_of(&self, name: &str) -> Option<String> {
        self.seen
            .iter()
            .rev()
            .find(|c| c.name == name)
            .map(|c| hex(&c.hasher.clone().finalize()))
    }

    /// Returns what was read of every component, for the manifest check.
    fn received(&mut self) -> Vec<StreamComponent> {
        std::mem::take(&mut self.seen)
            .into_iter()
            .map(Running::finish)
            .collect()
    }
}

/// A stream read whole: the documents, and RAM applied as it came.
#[derive(Debug)]
pub struct Received {
    /// `profile.json`, as it came.
    pub profile: Vec<u8>,
    /// The documents after RAM, by name, as they came.
    pub docs: Vec<(String, Vec<u8>)>,
    /// The manifest.
    pub manifest: StreamManifest,
    /// `manifest.json` as it came.
    pub manifest_bytes: Vec<u8>,
    /// Its SHA-256.
    pub manifest_sha256: String,
    /// Every byte read, headers included.
    pub stream_bytes: u64,
    /// The pages the rounds covered, round by round, as applied.
    pub applied: Vec<FrameCount>,
    /// The disk rounds, in order, as applied.
    pub disk: Vec<AppliedDisk>,
}

impl Received {
    /// Returns the document `name`, when the stream had it.
    #[must_use]
    pub fn doc(&self, name: &str) -> Option<&[u8]> {
        self.docs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b.as_slice())
    }
}

/// Reads a whole stream from `reader`. `prepare` gets `profile.json` once it
/// is read and checked, and returns the guest RAM the rounds are applied
/// to, laid out as the profile's regions. `disk` takes the blocks of the
/// disk rounds, when the stream has them; a stream with disk rounds and no
/// `disk` is refused before a block is written.
///
/// Each frame's hash is checked before its bytes are used, the components
/// must come in the order of the module documentation, and the manifest
/// must list exactly the components read, with their sizes, hashes and
/// frame counts, and the rounds read. Nothing runs from what was read until
/// this returns.
///
/// # Errors
///
/// Errors, naming the component, on the first thing that does not hold.
/// Pages and blocks applied before the error stay applied, so the caller
/// discards the RAM and the disk.
#[allow(clippy::too_many_lines)]
pub fn receive<R: BufRead>(
    reader: &mut StreamReader<R>,
    prepare: impl FnOnce(&[u8]) -> io::Result<(PageSpace, std::sync::Arc<GuestRam>)>,
    mut disk: Option<&mut dyn DiskTarget>,
) -> io::Result<Received> {
    let first = reader.next_frame()?;
    if first.name != "profile.json" {
        return Err(bad(
            "stream",
            format!("starts with {}, not profile.json", first.name),
        ));
    }
    let profile = first.bytes;
    let (space, ram) = prepare(&profile)?;
    let mut applier = RamApplier::new(space, &ram);
    let mut applied: Vec<FrameCount> = Vec::new();
    let mut disk_applier: Option<DiskApplier> = None;
    let mut disks: Vec<AppliedDisk> = Vec::new();
    // The disk rounds taken with the guest running, and whether the paused
    // one was read: each RAM round k follows disk round k, and the final
    // RAM round the paused disk round.
    let mut running_disk = 0u32;
    let mut disk_final = false;
    let mut current: Option<String> = None;
    let mut frame = reader.next_frame()?;
    loop {
        let continues = current.as_deref() == Some(frame.name.as_str());
        if !continues {
            // A disk round ends where the next component starts.
            if let (Some(name), Some(d)) = (current.as_deref(), disk_applier.as_mut()) {
                if disk_round_of(name).is_some() {
                    let sha256 = reader.sha256_of(name).unwrap_or_default();
                    disks.push(d.end(sha256));
                    if let Some(target) = disk.as_deref_mut() {
                        target.round_end(name == DISK_FINAL)?;
                    }
                }
            }
        }
        if let Some(round) = round_of(&frame.name) {
            if !continues {
                let expected = applied.len() as u32;
                if round != expected {
                    return Err(bad(
                        &frame.name,
                        format!("came after {} RAM round(s)", applied.len()),
                    ));
                }
                if round >= MAX_ROUNDS {
                    return Err(bad(
                        &frame.name,
                        format!("more than {MAX_ROUNDS} RAM rounds"),
                    ));
                }
                let with_disk = running_disk > 0 || disk_final;
                let disk_ok = if disk_final {
                    round == running_disk
                } else {
                    running_disk == round + 1
                };
                if with_disk && !disk_ok {
                    return Err(bad(
                        &frame.name,
                        if disk_final && round > running_disk {
                            "came after the final RAM round".to_string()
                        } else {
                            format!("came without disk round {round} before it")
                        },
                    ));
                }
                applied.push(FrameCount::default());
                current = Some(frame.name.clone());
            }
            let got = applier.apply(&frame.name, &frame.bytes, &ram)?;
            let last = applied.last_mut().expect("a round was pushed");
            last.pages += got.pages;
            last.data_pages += got.data_pages;
        } else if let Some(round) = disk_round_of(&frame.name) {
            if !continues {
                let k = applied.len() as u32;
                let fits = match round {
                    DiskRound::Running(r) => !disk_final && r == k && r == running_disk,
                    // With no round before it, the stream is the final
                    // round alone: a fenced VM's state sent again.
                    DiskRound::Final => !disk_final && running_disk == k,
                };
                if !fits {
                    return Err(bad(
                        &frame.name,
                        format!(
                            "came after {k} RAM round(s) and {running_disk} disk round(s){}",
                            if disk_final { " and the final one" } else { "" }
                        ),
                    ));
                }
                if disk_applier.is_none() {
                    let target = disk.as_deref_mut().ok_or_else(|| {
                        bad(
                            &frame.name,
                            "the stream carries the disk's blocks, and the restore was given no \
                             disk to write them into",
                        )
                    })?;
                    disk_applier = Some(DiskApplier::new(target.begin()?));
                }
                let in_pause = round == DiskRound::Final;
                if in_pause {
                    disk_final = true;
                } else {
                    running_disk += 1;
                }
                disk_applier
                    .as_mut()
                    .expect("made above")
                    .start(&frame.name, in_pause);
                current = Some(frame.name.clone());
            }
            let target = disk.as_deref_mut().expect("checked at the round's start");
            disk_applier
                .as_mut()
                .expect("made at the round's start")
                .apply(&frame.name, &frame.bytes, target)?;
        } else {
            break;
        }
        frame = reader.next_frame()?;
    }
    if applied.is_empty() {
        return Err(bad(
            "stream",
            format!("{} came before any RAM round", frame.name),
        ));
    }
    if (running_disk > 0 || disk_final) && !(disk_final && applied.len() as u32 == running_disk + 1)
    {
        return Err(bad(
            "stream",
            format!(
                "{} came after {} RAM round(s) and {running_disk} disk round(s), {}",
                frame.name,
                applied.len(),
                if disk_final {
                    "the final one before the last RAM round"
                } else {
                    "but not the final disk round"
                }
            ),
        ));
    }
    let mut docs: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, component) in DOCS {
        if frame.name == name {
            docs.push((frame.name, frame.bytes));
            frame = reader.next_frame()?;
        } else if component.required() {
            return Err(bad(
                "stream",
                format!("{} came where {name} was due", frame.name),
            ));
        }
    }
    if frame.name != MANIFEST {
        return Err(bad(
            "stream",
            format!("{} came where the manifest was due", frame.name),
        ));
    }
    let manifest_bytes = frame.bytes;
    let manifest: StreamManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| bad(MANIFEST, e))?;
    let received = reader.received();
    check_manifest(&manifest, &received, &applied, &disks)?;
    Ok(Received {
        profile,
        docs,
        manifest_sha256: hex(&Sha256::digest(&manifest_bytes)),
        manifest,
        manifest_bytes,
        stream_bytes: reader.bytes_read(),
        applied,
        disk: disks,
    })
}

/// Checks the manifest against what was read.
fn check_manifest(
    manifest: &StreamManifest,
    received: &[StreamComponent],
    applied: &[FrameCount],
    disks: &[AppliedDisk],
) -> io::Result<()> {
    if !(2..=STREAM_FORMAT).contains(&manifest.checkpoint_format) {
        return Err(bad(
            MANIFEST,
            format!(
                "checkpoint_format {}, a stream is 2 to {STREAM_FORMAT}",
                manifest.checkpoint_format
            ),
        ));
    }
    if manifest.components != received {
        let listed: BTreeSet<&str> = manifest
            .components
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        let read: BTreeSet<&str> = received.iter().map(|c| c.name.as_str()).collect();
        let why = if listed == read {
            let differ: Vec<&str> = manifest
                .components
                .iter()
                .zip(received)
                .filter(|(a, b)| a != b)
                .map(|(a, _)| a.name.as_str())
                .collect();
            format!(
                "the size, hash or frames of {} differ from what was read",
                differ.join(", ")
            )
        } else {
            format!(
                "lists {:?}, and the stream held {:?}",
                listed.symmetric_difference(&read).collect::<Vec<_>>(),
                read.difference(&listed).collect::<Vec<_>>()
            )
        };
        return Err(bad(MANIFEST, why));
    }
    if manifest.ram.page_size != PAGE_SIZE {
        return Err(bad(
            MANIFEST,
            format!(
                "page size {}, a stream has {PAGE_SIZE}",
                manifest.ram.page_size
            ),
        ));
    }
    if manifest.ram.rounds.len() != applied.len() {
        return Err(bad(
            MANIFEST,
            format!(
                "lists {} RAM rounds, and the stream held {}",
                manifest.ram.rounds.len(),
                applied.len()
            ),
        ));
    }
    for (index, (round, got)) in manifest.ram.rounds.iter().zip(applied).enumerate() {
        if round.round as usize != index
            || round.pages != got.pages
            || round.data_pages != got.data_pages
        {
            return Err(bad(
                MANIFEST,
                format!(
                    "round {index} lists {} pages ({} with data), and the stream held {} ({})",
                    round.pages, round.data_pages, got.pages, got.data_pages
                ),
            ));
        }
    }
    if !manifest.ram.rounds.last().is_some_and(|r| r.in_pause) {
        return Err(bad(MANIFEST, "the last RAM round was not taken paused"));
    }
    let profile = received.first().map(|c| c.sha256.as_str());
    if profile != Some(manifest.profile_sha256.as_str()) {
        return Err(bad(MANIFEST, "profile_sha256 is not the profile's"));
    }
    check_disk_rounds(manifest, received, disks)
}

/// Checks the manifest's disk rounds against the ones applied.
fn check_disk_rounds(
    manifest: &StreamManifest,
    received: &[StreamComponent],
    disks: &[AppliedDisk],
) -> io::Result<()> {
    let listed = manifest.disk.as_ref().map_or(&[][..], |d| &d.rounds[..]);
    if let Some(d) = &manifest.disk {
        if d.block_size != DIRTY_BLOCK_BYTES || d.rounds.is_empty() {
            return Err(bad(
                MANIFEST,
                format!(
                    "disk lists {} round(s) of {}-byte blocks, and a stream has at least one of \
                     {DIRTY_BLOCK_BYTES}",
                    d.rounds.len(),
                    d.block_size
                ),
            ));
        }
    }
    if listed.len() != disks.len() {
        return Err(bad(
            MANIFEST,
            format!(
                "lists {} disk round(s), and the stream held {}",
                listed.len(),
                disks.len()
            ),
        ));
    }
    for (round, got) in listed.iter().zip(disks) {
        let size = received
            .iter()
            .find(|c| c.name == got.name)
            .map_or(0, |c| c.size);
        if round.name != got.name
            || round.in_pause != got.in_pause
            || round.blocks != got.blocks
            || round.raw_bytes != got.raw_bytes
            || round.bytes != size
        {
            return Err(bad(
                MANIFEST,
                format!(
                    "disk round {} lists {} blocks of {} bytes, and the stream held {} of {} \
                     in {}",
                    round.name, round.blocks, round.raw_bytes, got.blocks, got.raw_bytes, got.name
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::RamRegion;
    use std::sync::Arc;

    const BASE: u64 = 0x4000_0000;
    const PAGES: u64 = 512;

    fn regions() -> Vec<StreamRegion> {
        vec![StreamRegion {
            gpa: BASE,
            size: PAGES * PAGE_SIZE,
        }]
    }

    fn guest() -> Arc<GuestRam> {
        Arc::new(GuestRam::from_ranges(&[(
            BASE,
            (PAGES * PAGE_SIZE) as usize,
        )]))
    }

    fn page_of(byte: u8) -> Vec<u8> {
        let mut page = vec![0u8; PAGE_SIZE as usize];
        for (i, b) in page.iter_mut().enumerate() {
            *b = byte.wrapping_add((i % 7) as u8);
        }
        page
    }

    fn build() -> HviBuild {
        HviBuild {
            version: "0".into(),
            git_sha: "test".into(),
        }
    }

    /// A later round: what the guest writes before it, and the runs of
    /// pages it sends.
    type Later<'a> = (&'a dyn Fn(&GuestRam), Vec<(u64, u64)>);

    /// Writes a stream: round 0 sends `src`'s pages, each later round the
    /// pages it names, read from `src` after its edit ran.
    fn stream(src: &GuestRam, later: &[Later<'_>], docs: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = StreamWriter::new(&mut out);
        w.write_doc("profile.json", b"{\"p\":1}").unwrap();
        let mut enc = ChunkEncoder::default();
        let mut buf = vec![0u8; (CHUNK_PAGES * PAGE_SIZE) as usize];
        let mut send = |w: &mut StreamWriter<&mut Vec<u8>>, runs: &[(u64, u64)], skip, in_pause| {
            let mut round = w.round(in_pause);
            for &(first, count) in runs {
                let bytes = &mut buf[..(count * PAGE_SIZE) as usize];
                src.read(BASE + first * PAGE_SIZE, bytes).unwrap();
                round.chunk(&mut enc, first, bytes, skip).unwrap();
            }
            round.finish().unwrap();
        };
        let all: Vec<(u64, u64)> = (0..PAGES / 64).map(|i| (i * 64, 64)).collect();
        send(&mut w, &all, true, later.is_empty());
        for (i, (edit, runs)) in later.iter().enumerate() {
            edit(src);
            send(&mut w, runs, false, i + 1 == later.len());
        }
        if docs {
            for (name, _) in DOCS {
                if name != "disk.json" {
                    w.write_doc(name, format!("{{\"{name}\":1}}").as_bytes())
                        .unwrap();
                }
            }
        }
        w.seal(build(), regions(), vec![], 1).unwrap();
        w.line("{\"v\":1,\"ok\":true}").unwrap();
        out
    }

    fn read(bytes: &[u8]) -> io::Result<(Received, Arc<GuestRam>)> {
        let ram = guest();
        let mut reader = StreamReader::new(io::BufReader::new(bytes));
        let target = Arc::clone(&ram);
        let got = receive(
            &mut reader,
            |_| Ok((PageSpace::new(&regions())?, target)),
            None,
        )?;
        Ok((got, ram))
    }

    fn same(a: &GuestRam, b: &GuestRam) -> bool {
        let mut x = vec![0u8; (PAGES * PAGE_SIZE) as usize];
        let mut y = x.clone();
        a.read(BASE, &mut x).unwrap();
        b.read(BASE, &mut y).unwrap();
        x == y
    }

    #[test]
    fn rounds_round_trip_and_later_rounds_win() {
        let src = guest();
        src.write(BASE + 3 * PAGE_SIZE, &page_of(1)).unwrap();
        src.write(BASE + 70 * PAGE_SIZE, &page_of(2)).unwrap();
        src.write(BASE + 71 * PAGE_SIZE, &[0xff; 4096]).unwrap();
        // Round 1: page 3 changes and page 70 becomes zero again.
        let edit = |ram: &GuestRam| {
            ram.write(BASE + 3 * PAGE_SIZE, &page_of(9)).unwrap();
            ram.write(BASE + 70 * PAGE_SIZE, &[0; 4096]).unwrap();
        };
        let bytes = stream(&src, &[(&edit, vec![(3, 1), (70, 1)])], true);
        let (got, dst) = read(&bytes).unwrap();
        assert!(
            same(&src, &dst),
            "the destination holds the last round's pages"
        );
        assert_eq!(got.manifest.ram.rounds.len(), 2);
        // Round 0 left out the all-zero chunks: only chunks 0 and 1 went.
        assert_eq!(got.applied[0].pages, 128);
        assert_eq!(got.applied[0].data_pages, 3);
        assert_eq!(
            got.applied[1],
            FrameCount {
                pages: 2,
                data_pages: 1
            }
        );
        assert_eq!(got.doc("cpu.json"), Some(&b"{\"cpu.json\":1}"[..]));
        assert_eq!(got.doc("disk.json"), None);
        // The reply line after the manifest is not read.
        assert!(got.stream_bytes < bytes.len() as u64);
    }

    // A page that is all zero in a later round is zeroed only where an
    // earlier round wrote it: fresh RAM is zero already.
    #[test]
    fn a_zero_page_is_written_only_over_a_page_an_earlier_round_wrote() {
        let src = guest();
        src.write(BASE, &page_of(1)).unwrap();
        let edit = |ram: &GuestRam| ram.write(BASE, &[0; 4096]).unwrap();
        let bytes = stream(&src, &[(&edit, vec![(0, 2)])], true);
        let ram = guest();
        let mut reader = StreamReader::new(io::BufReader::new(&bytes[..]));
        let target = Arc::clone(&ram);
        receive(
            &mut reader,
            |_| Ok((PageSpace::new(&regions())?, target)),
            None,
        )
        .unwrap();
        let mut set = DirtyPages::new(&ram.regions());
        ram.dirty_log().take_into(&mut set).unwrap();
        // Page 0: written by round 0, zeroed by round 1. Page 1: never.
        assert_eq!(set.runs(64), vec![(0, 0, 1)]);
        assert!(same(&src, &ram));
    }

    #[test]
    fn incompressible_pages_go_as_they_are() {
        let src = guest();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut page = vec![0u8; 4096];
        for b in page.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        src.write(BASE, &page).unwrap();
        let bytes = stream(&src, &[], true);
        let (got, dst) = read(&bytes).unwrap();
        assert!(same(&src, &dst));
        // One raw page plus the header: it was not inflated.
        assert_eq!(
            got.manifest.ram.rounds[0].bytes,
            CHUNK_HEADER_LEN as u64 + 4096
        );
    }

    /// Returns the frames of `bytes` as (header line, payload) pairs.
    fn frames(bytes: &[u8]) -> Vec<(FrameHeader, Vec<u8>)> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while let Some(nl) = rest.iter().position(|b| *b == b'\n') {
            let Ok(h) = serde_json::from_slice::<FrameHeader>(&rest[..nl]) else {
                break;
            };
            let body = rest[nl + 1..nl + 1 + h.size as usize].to_vec();
            rest = &rest[nl + 1 + h.size as usize..];
            out.push((h, body));
        }
        out
    }

    fn join(frames: &[(FrameHeader, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (h, body) in frames {
            out.extend(serde_json::to_vec(h).unwrap());
            out.push(b'\n');
            out.extend(body);
        }
        out
    }

    fn refusal(bytes: &[u8]) -> String {
        read(bytes).err().expect("refused").to_string()
    }

    fn sample() -> Vec<(FrameHeader, Vec<u8>)> {
        let src = guest();
        src.write(BASE + 5 * PAGE_SIZE, &page_of(3)).unwrap();
        let edit = |ram: &GuestRam| ram.write(BASE + 6 * PAGE_SIZE, &page_of(4)).unwrap();
        frames(&stream(&src, &[(&edit, vec![(6, 1)])], true))
    }

    #[test]
    fn a_frame_whose_bytes_do_not_match_its_hash_is_refused_by_name() {
        let mut f = sample();
        f[1].1[30] ^= 1;
        assert!(refusal(&join(&f)).contains("ram-round-0: SHA-256 does not match"));
    }

    // Every component frame is covered: one left out, or one whose header
    // and bytes were both changed so the frame checks out, is refused by the
    // manifest.
    #[test]
    fn the_manifest_must_cover_what_was_read() {
        let mut f = sample();
        let platform = f
            .iter()
            .position(|(h, _)| h.component == "platform.json")
            .unwrap();
        f[platform].1 = b"{\"forged\":1}".to_vec();
        f[platform].0.size = f[platform].1.len() as u64;
        f[platform].0.sha256 = hex(&Sha256::digest(&f[platform].1));
        assert!(
            refusal(&join(&f)).contains("platform.json differ"),
            "{}",
            refusal(&join(&f))
        );

        let mut f = sample();
        f.retain(|(h, _)| h.component != "session.json");
        assert!(refusal(&join(&f)).contains("session.json was due"));

        // A RAM round repeated, frame and all.
        let mut f = sample();
        let again = f[2].clone();
        f.insert(3, again);
        let why = refusal(&join(&f));
        assert!(
            why.contains("manifest.json") && why.contains("ram-round-1"),
            "{why}"
        );
    }

    #[test]
    fn rounds_must_come_in_order() {
        let mut f = sample();
        f[2].0.component = "ram-round-2".into();
        assert!(refusal(&join(&f)).contains("ram-round-2: came after 1 RAM round"));
        let mut f = sample();
        f.swap(0, 1);
        assert!(refusal(&join(&f)).contains("starts with ram-round-0"));
    }

    #[test]
    fn the_stream_may_not_end_before_the_manifest() {
        let f = sample();
        let all = join(&f);
        for cut in [0, 10, all.len() / 2, all.len() - 1] {
            let why = refusal(&all[..cut]);
            assert!(
                why.contains("ended") || why.contains("SHA-256") || why.contains("is not JSON"),
                "cut at {cut}: {why}"
            );
        }
    }

    #[test]
    fn a_reply_line_ends_the_stream_with_its_error() {
        let f = sample();
        let mut bytes = join(&f[..2]);
        bytes.extend(b"{\"v\":1,\"ok\":false,\"code\":\"capture_failed\",\"error\":\"boom\"}\n");
        let err = read(&bytes).err().expect("ended");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(err.to_string().contains("capture_failed: boom"));
    }

    #[test]
    fn headers_are_checked_before_anything_is_allocated() {
        let mut f = sample();
        f[1].0.size = MAX_RAM_FRAME + 1;
        assert!(refusal(&join(&f)).contains("at most"));
        let mut f = sample();
        f[0].0.component = "ram.bin".into();
        assert!(refusal(&join(&f)).contains("no component \"ram.bin\""));
        let long = format!(
            "{{\"component\":\"{}\",\"size\":0,\"sha256\":\"\"}}\n",
            "x".repeat(2000)
        );
        assert!(refusal(long.as_bytes()).contains("longer than the reader takes"));
        let mut f = sample();
        f[0].0.sha256 = "ABC".into();
        assert!(refusal(&join(&f)).contains("no lowercase hex"));
    }

    /// Returns a one-chunk frame from its header fields and payload.
    fn chunk(first: u64, present: u64, count: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(first.to_le_bytes());
        out.extend(present.to_le_bytes());
        out.extend(count.to_le_bytes());
        out.extend(flags.to_le_bytes());
        out.extend((payload.len() as u32).to_le_bytes());
        out.extend(payload);
        out
    }

    #[test]
    fn chunk_headers_are_checked_before_a_page_is_written() {
        let ram = guest();
        let mut a = RamApplier::new(PageSpace::new(&regions()).unwrap(), &ram);
        let page = page_of(5);
        let lz = lz4_flex::block::compress(&page);
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (chunk(0, 0, 0, 0, &[]), "a chunk of 0 pages"),
            (chunk(0, 0, 65, 0, &[]), "a chunk of 65 pages"),
            (chunk(0, 0b10, 1, 0, &lz), "a bit past its 1 pages"),
            (chunk(0, 1, 1, 2, &lz), "flags 0x2"),
            (chunk(0, 1, 1, FLAG_RAW, &page[..100]), "payload"),
            (chunk(0, 0, 1, 0, &[1]), "payload"),
            (chunk(PAGES - 1, 1, 2, 0, &lz), "not in one RAM region"),
            (chunk(u64::MAX, 1, 2, 0, &lz), "not in one RAM region"),
            (chunk(0, 1, 1, 0, &lz)[..30].to_vec(), "payload"),
            (chunk(0, 1, 1, 0, &lz)[..10].to_vec(), "cut short"),
        ];
        for (frame, want) in cases {
            // A good chunk first: a bad one after it must stop the whole frame.
            let mut whole = chunk(10, 1, 1, FLAG_RAW, &page);
            whole.extend(&frame);
            let err = a
                .apply("ram-round-0", &whole, &ram)
                .expect_err(want)
                .to_string();
            assert!(err.contains(want), "{want}: {err}");
            assert_eq!(
                ram.read_u64(BASE + 10 * PAGE_SIZE).unwrap(),
                0,
                "{want}: wrote"
            );
        }
        // A payload that decompresses to the wrong length is refused as its
        // chunk is applied.
        let short = chunk(0, 1, 1, 0, &lz4_flex::block::compress(&[7; 100]));
        let err = a
            .apply("ram-round-0", &short, &ram)
            .expect_err("short")
            .to_string();
        assert!(err.contains("holds 100 bytes"), "{err}");
        let got = a
            .apply("ram-round-0", &chunk(1, 1, 1, 0, &lz), &ram)
            .unwrap();
        assert_eq!(
            got,
            FrameCount {
                pages: 1,
                data_pages: 1
            }
        );
        let mut back = vec![0u8; 4096];
        ram.read(BASE + PAGE_SIZE, &mut back).unwrap();
        assert_eq!(back, page);
    }

    #[test]
    fn the_page_space_counts_across_regions() {
        let space = PageSpace::new(&[
            StreamRegion {
                gpa: 0,
                size: 8 * PAGE_SIZE,
            },
            StreamRegion {
                gpa: 1 << 32,
                size: 4 * PAGE_SIZE,
            },
        ])
        .unwrap();
        assert_eq!(space.locate(0, 8), Some((0, 0)));
        assert_eq!(space.locate(7, 2), None, "across the seam");
        assert_eq!(space.locate(8, 4), Some((1, 0)));
        assert_eq!(space.locate(11, 2), None, "past the end");
        assert_eq!(space.gpa(1, 3), (1 << 32) + 3 * PAGE_SIZE);
        assert_eq!(space.global(1, 2), 10);
        for bad in [
            vec![],
            vec![StreamRegion { gpa: 0, size: 100 }],
            vec![
                StreamRegion {
                    gpa: 0,
                    size: 8 * PAGE_SIZE,
                },
                StreamRegion {
                    gpa: 4 * PAGE_SIZE,
                    size: 8 * PAGE_SIZE,
                },
            ],
            vec![StreamRegion {
                gpa: 0,
                size: MAX_RAM_BYTES + PAGE_SIZE,
            }],
        ] {
            assert!(PageSpace::new(&bad).is_err(), "{bad:?}");
        }
        let _ = RamRegion::ALIGN;
    }

    #[test]
    fn round_names_parse_strictly() {
        assert_eq!(round_of("ram-round-0"), Some(0));
        assert_eq!(round_of("ram-round-12"), Some(12));
        for bad in [
            "ram-round-",
            "ram-round-01",
            "ram-round-x",
            "ram-round-1234",
            "ram-round--1",
        ] {
            assert_eq!(round_of(bad), None, "{bad}");
        }
    }

    /// A disk of 20 whole blocks and a short last one.
    const DISK_SIZE: u64 = 20 * DIRTY_BLOCK_BYTES + 1000;

    /// A disk in memory, as the destination's copy of the base.
    struct MemDisk {
        bytes: Vec<u8>,
        begun: u32,
        finished: u32,
        writes: u32,
    }

    impl MemDisk {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                begun: 0,
                finished: 0,
                writes: 0,
            }
        }
    }

    impl DiskTarget for MemDisk {
        fn begin(&mut self) -> io::Result<u64> {
            self.begun += 1;
            Ok(self.bytes.len() as u64)
        }
        fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
            self.writes += 1;
            self.bytes[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
        fn round_end(&mut self, in_pause: bool) -> io::Result<()> {
            if in_pause {
                self.finished += 1;
            }
            Ok(())
        }
    }

    /// Returns the base image the tests' disks start from.
    fn base_disk() -> Vec<u8> {
        (0..DISK_SIZE).map(|i| (i % 251) as u8).collect()
    }

    /// Writes a stream whose rounds each carry a disk round, the last one
    /// paused: round `k` sends the blocks `rounds[k].1` read from the image
    /// `rounds[k].0`. RAM rounds carry nothing.
    fn disk_stream(rounds: &[(&[u8], &[u64])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = StreamWriter::new(&mut out);
        w.write_doc("profile.json", b"{\"p\":1}").unwrap();
        let mut enc = DiskEncoder::default();
        let mut ram = ChunkEncoder::default();
        for (k, (image, blocks)) in rounds.iter().enumerate() {
            let in_pause = k + 1 == rounds.len();
            let mut round = w.disk_round(in_pause);
            for &block in *blocks {
                let start = (block * DIRTY_BLOCK_BYTES) as usize;
                let end = (start + DIRTY_BLOCK_BYTES as usize).min(image.len());
                round.chunk(&mut enc, block, 1, &image[start..end]).unwrap();
            }
            round.finish().unwrap();
            let mut r = w.round(in_pause);
            r.chunk(&mut ram, 0, &page_of(k as u8), false).unwrap();
            r.finish().unwrap();
        }
        for (name, _) in DOCS {
            if name != "disk.json" {
                w.write_doc(name, b"{}").unwrap();
            }
        }
        w.seal(build(), regions(), vec![], 1).unwrap();
        out
    }

    fn read_disk(bytes: &[u8], disk: &mut MemDisk) -> io::Result<Received> {
        let ram = guest();
        let mut reader = StreamReader::new(io::BufReader::new(bytes));
        receive(
            &mut reader,
            |_| Ok((PageSpace::new(&regions())?, ram)),
            Some(disk),
        )
    }

    /// Returns the bitmap digest of `blocks` on a disk of [`DISK_SIZE`].
    fn bitmap_sha(blocks: &[u64]) -> String {
        let mut set = DirtyBlocks::for_size(DISK_SIZE);
        for &b in blocks {
            set.mark(b * DIRTY_BLOCK_BYTES, 1);
        }
        hex(&Sha256::digest(set.as_bytes()))
    }

    /// Three disk rounds over the base: round 0 with blocks 0 to 2, 5 and
    /// the short last one, round 1 block 1 written again, the final block 5
    /// written again; and the source image after each.
    fn three_rounds() -> (Vec<u8>, Vec<u8>) {
        let mut image = base_disk();
        image[..3 * DIRTY_BLOCK_BYTES as usize].fill(7);
        image[(5 * DIRTY_BLOCK_BYTES) as usize] = 9;
        let last = image.len() - 1;
        image[last] = 1;
        let first = image.clone();
        image[(DIRTY_BLOCK_BYTES + 3) as usize] = 0xaa;
        let second = image.clone();
        image[(5 * DIRTY_BLOCK_BYTES + 7) as usize] = 0xbb;
        let bytes = disk_stream(&[(&first, &[0, 1, 2, 5, 20]), (&second, &[1]), (&image, &[5])]);
        (bytes, image)
    }

    #[test]
    fn disk_rounds_round_trip_and_later_rounds_win() {
        let (bytes, image) = three_rounds();
        let mut disk = MemDisk::new(base_disk());
        let got = read_disk(&bytes, &mut disk).unwrap();
        assert!(
            disk.bytes == image,
            "the destination holds the last rounds' blocks"
        );
        assert_eq!((disk.begun, disk.finished), (1, 1));
        let names: Vec<&str> = got.disk.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["disk-round-0", "disk-round-1", DISK_FINAL]);
        assert_eq!(got.disk[0].blocks, 5);
        assert_eq!(got.disk[0].raw_bytes, 4 * DIRTY_BLOCK_BYTES + 1000);
        assert_eq!(got.disk[0].bitmap_sha256, bitmap_sha(&[0, 1, 2, 5, 20]));
        assert_eq!(got.disk[2].bitmap_sha256, bitmap_sha(&[5]));
        assert!(got.disk[2].in_pause && !got.disk[1].in_pause);
        // Each round's digest is its component's, which the manifest lists.
        for d in &got.disk {
            let listed = got.manifest.components.iter().find(|c| c.name == d.name);
            assert_eq!(listed.map(|c| c.sha256.as_str()), Some(d.sha256.as_str()));
        }
        let listed = got
            .manifest
            .disk
            .as_ref()
            .expect("the manifest lists the disk");
        assert_eq!(listed.rounds.len(), 3);
        assert_eq!(listed.block_size, DIRTY_BLOCK_BYTES);
        assert_eq!(got.manifest.checkpoint_format, STREAM_FORMAT);
        // Blocks of one value compress.
        assert!(listed.rounds[0].bytes < listed.rounds[0].raw_bytes / 4);
    }

    #[test]
    fn a_stream_without_disk_rounds_has_no_disk_in_its_manifest() {
        let src = guest();
        let bytes = stream(&src, &[], true);
        let mut disk = MemDisk::new(base_disk());
        let got = read_disk(&bytes, &mut disk).unwrap();
        assert!(got.disk.is_empty() && got.manifest.disk.is_none());
        assert_eq!(got.manifest.checkpoint_format, 2);
        assert_eq!((disk.begun, disk.writes), (0, 0));
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(!text.contains("\"disk\""), "a reader of format 2 takes it");
    }

    fn disk_refusal(bytes: &[u8]) -> String {
        read_disk(bytes, &mut MemDisk::new(base_disk()))
            .expect_err("refused")
            .to_string()
    }

    // Every disk round is covered by the manifest and by the order: one
    // left out, a forged one whose frame checks out, or the paused one
    // missing, is refused.
    #[test]
    fn the_manifest_and_the_order_cover_the_disk_rounds() {
        let (bytes, _) = three_rounds();
        let mut f = frames(&bytes);
        f.retain(|(h, _)| h.component != "disk-round-1");
        let why = disk_refusal(&join(&f));
        assert!(
            why.contains("ram-round-1: came without disk round 1"),
            "{why}"
        );

        let mut f = frames(&bytes);
        f.retain(|(h, _)| h.component != DISK_FINAL);
        let why = disk_refusal(&join(&f));
        assert!(
            why.contains("ram-round-2: came without disk round 2"),
            "{why}"
        );

        // A disk round's bytes replaced by another valid round's, frame
        // header and all: the frame checks out, the manifest does not.
        let mut f = frames(&bytes);
        let one = f
            .iter()
            .position(|(h, _)| h.component == "disk-round-1")
            .unwrap();
        let zero = f
            .iter()
            .position(|(h, _)| h.component == "disk-round-0")
            .unwrap();
        f[one].1 = f[zero].1.clone();
        f[one].0.size = f[one].1.len() as u64;
        f[one].0.sha256 = hex(&Sha256::digest(&f[one].1));
        let why = disk_refusal(&join(&f));
        assert!(why.contains("disk-round-1 differ"), "{why}");

        // A disk round sent twice.
        let mut f = frames(&bytes);
        let again = f[zero].clone();
        f.insert(zero + 1, again);
        let why = disk_refusal(&join(&f));
        assert!(
            why.contains("disk-round-0") && why.contains("not after block"),
            "{why}"
        );

        // The paused disk round after the RAM round it belongs before.
        let mut f = frames(&bytes);
        let fin = f
            .iter()
            .position(|(h, _)| h.component == DISK_FINAL)
            .unwrap();
        f.swap(fin, fin + 1);
        let why = disk_refusal(&join(&f));
        assert!(
            why.contains("ram-round-2: came without disk round 2"),
            "{why}"
        );

        // A RAM round after the final one.
        let mut f = frames(&bytes);
        let extra = f
            .iter()
            .position(|(h, _)| h.component == "ram-round-2")
            .unwrap();
        let mut again = f[extra].clone();
        again.0.component = "ram-round-3".into();
        f.insert(extra + 1, again);
        let why = disk_refusal(&join(&f));
        assert!(
            why.contains("ram-round-3: came after the final RAM round"),
            "{why}"
        );
    }

    // A fenced VM's state sent again is the final round alone.
    #[test]
    fn the_final_disk_round_may_be_the_only_one() {
        let (_, image) = three_rounds();
        let bytes = disk_stream(&[(&image, &[0, 1, 2, 5, 20])]);
        let mut disk = MemDisk::new(base_disk());
        let got = read_disk(&bytes, &mut disk).unwrap();
        assert!(disk.bytes == image);
        assert_eq!(got.disk.len(), 1);
        assert!(got.disk[0].in_pause && got.manifest.ram.rounds[0].in_pause);
    }

    #[test]
    fn disk_rounds_need_a_disk_to_go_into() {
        let (bytes, _) = three_rounds();
        let ram = guest();
        let mut reader = StreamReader::new(io::BufReader::new(&bytes[..]));
        let why = receive(
            &mut reader,
            |_| Ok((PageSpace::new(&regions())?, ram)),
            None,
        )
        .expect_err("refused")
        .to_string();
        assert!(
            why.contains("disk-round-0: the stream carries the disk's blocks"),
            "{why}"
        );
    }

    /// Returns a one-chunk disk frame from its header fields and payload.
    fn disk_chunk(first: u64, count: u32, flags: u32, raw: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(first.to_le_bytes());
        out.extend(count.to_le_bytes());
        out.extend(flags.to_le_bytes());
        out.extend(raw.to_le_bytes());
        out.extend((payload.len() as u32).to_le_bytes());
        out.extend(payload);
        out
    }

    // Every chunk of a frame is checked against the disk before its first
    // block is written: none of the bad frames below writes a byte.
    #[test]
    fn disk_chunks_are_checked_before_a_block_is_written() {
        let whole = vec![3u8; DIRTY_BLOCK_BYTES as usize];
        let good = disk_chunk(0, 1, 1, DIRTY_BLOCK_BYTES as u32, &whole);
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                [good.clone(), disk_chunk(21, 1, 1, 4, &[0; 4])].concat(),
                "past the",
            ),
            (
                [good.clone(), disk_chunk(20, 1, 1, 999, &[0; 999])].concat(),
                "999 bytes",
            ),
            ([good.clone(), good.clone()].concat(), "not after block 0"),
            (
                [good.clone(), disk_chunk(1, 0, 1, 0, &[])].concat(),
                "of 0 blocks",
            ),
            (
                [good.clone(), disk_chunk(1, 17, 1, 0, &[])].concat(),
                "of 17 blocks",
            ),
            (
                [good.clone(), disk_chunk(1, 1, 2, 0, &[])].concat(),
                "flags 0x2",
            ),
            ([good.clone(), good[..20].to_vec()].concat(), "cut short"),
            (
                [good.clone(), disk_chunk(u64::MAX, 2, 1, 0, &[])].concat(),
                "past every disk",
            ),
        ];
        for (frame, want) in cases {
            let mut disk = MemDisk::new(base_disk());
            let mut applier = DiskApplier::new(DISK_SIZE);
            applier.start("disk-round-0", false);
            let why = applier
                .apply("disk-round-0", &frame, &mut disk)
                .expect_err("refused")
                .to_string();
            assert!(why.contains(want), "{want}: {why}");
            assert_eq!(disk.writes, 0, "{want}: nothing written");
        }
        let mut disk = MemDisk::new(base_disk());
        let mut applier = DiskApplier::new(DISK_SIZE);
        applier.start("disk-round-0", false);
        applier.apply("disk-round-0", &good, &mut disk).unwrap();
        assert_eq!(disk.bytes[..DIRTY_BLOCK_BYTES as usize], whole[..]);
    }

    #[test]
    fn disk_round_names_parse_strictly() {
        assert_eq!(disk_round_of("disk-round-0"), Some(DiskRound::Running(0)));
        assert_eq!(disk_round_of(DISK_FINAL), Some(DiskRound::Final));
        for bad in [
            "disk-round-",
            "disk-round-01",
            "disk-round-final2",
            "disk-blocks",
        ] {
            assert_eq!(disk_round_of(bad), None, "{bad}");
        }
        assert_eq!(frame_limit("disk-round-3"), Some(MAX_DISK_FRAME));
    }
}

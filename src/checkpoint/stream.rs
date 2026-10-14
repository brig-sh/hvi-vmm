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

//! The streamed bundle, `checkpoint_format` 2: a checkpoint as one byte
//! stream instead of a directory, so the destination reads it as the source
//! writes it.
//!
//! The stream is a sequence of frames. Each frame is one line of JSON,
//! [`FrameHeader`], `{"component":NAME,"size":N,"sha256":HEX}`, then exactly
//! `N` bytes whose SHA-256 is `HEX`. The components come in this order:
//!
//! | component | frames | holds |
//! |---|---|---|
//! | `profile.json` | 1 | the source's machine profile |
//! | `ram-round-0` .. `ram-round-K` | 1 or more each | guest RAM, see below |
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
use crate::memory::{DirtyPages, GuestRam};

/// The `checkpoint_format` of a streamed bundle.
pub const STREAM_FORMAT: u32 = 2;

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

/// The name of RAM round `round`.
#[must_use]
pub fn round_name(round: u32) -> String {
    format!("ram-round-{round}")
}

/// Returns the round `name` is the RAM of, if it is one.
fn round_of(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("ram-round-")?;
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    digits.parse().ok()
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
            checkpoint_format: STREAM_FORMAT,
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
/// to, laid out as the profile's regions.
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
/// Pages applied before the error stay applied, so the caller discards the
/// RAM.
pub fn receive<R: BufRead>(
    reader: &mut StreamReader<R>,
    prepare: impl FnOnce(&[u8]) -> io::Result<(PageSpace, std::sync::Arc<GuestRam>)>,
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
    let mut frame = reader.next_frame()?;
    // The RAM rounds: 0, then each one either goes on or is the next.
    while let Some(round) = round_of(&frame.name) {
        let expected = applied.len() as u32;
        let continues = expected > 0 && round == expected - 1;
        if !continues && round != expected {
            return Err(bad(
                &frame.name,
                format!("came after {} RAM round(s)", applied.len()),
            ));
        }
        if !continues {
            if round >= MAX_ROUNDS {
                return Err(bad(
                    &frame.name,
                    format!("more than {MAX_ROUNDS} RAM rounds"),
                ));
            }
            applied.push(FrameCount::default());
        }
        let got = applier.apply(&frame.name, &frame.bytes, &ram)?;
        let last = applied.last_mut().expect("a round was pushed");
        last.pages += got.pages;
        last.data_pages += got.data_pages;
        frame = reader.next_frame()?;
    }
    if applied.is_empty() {
        return Err(bad(
            "stream",
            format!("{} came before any RAM round", frame.name),
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
    check_manifest(&manifest, &received, &applied)?;
    Ok(Received {
        profile,
        docs,
        manifest_sha256: hex(&Sha256::digest(&manifest_bytes)),
        manifest,
        manifest_bytes,
        stream_bytes: reader.bytes_read(),
        applied,
    })
}

/// Checks the manifest against what was read.
fn check_manifest(
    manifest: &StreamManifest,
    received: &[StreamComponent],
    applied: &[FrameCount],
) -> io::Result<()> {
    if manifest.checkpoint_format != STREAM_FORMAT {
        return Err(bad(
            MANIFEST,
            format!(
                "checkpoint_format {}, a stream is {STREAM_FORMAT}",
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
        let got = receive(&mut reader, |_| Ok((PageSpace::new(&regions())?, target)))?;
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
        receive(&mut reader, |_| Ok((PageSpace::new(&regions())?, target))).unwrap();
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
}

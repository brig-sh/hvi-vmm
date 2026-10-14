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

//! The disk's blocks as `disk-blocks` streams them on the control socket.
//!
//! A mover that holds the image the guest booted from asks `disk-dirty` for
//! the blocks the guest wrote, then `disk-blocks` for their bytes, and
//! writes them into its copy of the image. The bytes come in batches. Each
//! batch is one line of JSON, the [`BatchHeader`], then `size` bytes: the
//! blocks `first` to `first + count - 1`, which are adjacent on the disk and
//! start at byte `offset`. `sha256` is the digest of those bytes. A batch
//! holds at most [`BATCH_BLOCKS`] blocks, and a line with a `"v"` key, the
//! op's reply, ends the stream.
//!
//! Each block is read with the device's lock held, one block at a time, so
//! the guest's I/O waits for one 64 KiB read at most. A block the guest
//! writes while the export runs may go out with or without that write, and
//! is in the next round either way.

use std::io;
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::devices::virtio::block::{VirtioBlk, DIRTY_BLOCK_BYTES};
use crate::sync::lock_or_recover;

/// The most blocks one batch holds: 1 MiB of 64 KiB blocks.
pub const BATCH_BLOCKS: u64 = 16;

/// The most block numbers one `disk-blocks` request lists. A request line is
/// at most 64 KiB ([`MAX_LINE`](super::control::MAX_LINE)): 4096 numbers of
/// up to 13 digits, every block of a disk under 2^56 bytes, fit in one with
/// their commas and the rest of the request. A mover asks for a longer list
/// in several requests, or names a round, which is the way to send a bulk.
pub const MAX_REQUEST_BLOCKS: usize = 4096;

/// The `component` every batch header carries.
pub const BATCH_COMPONENT: &str = "disk-blocks";

/// The line before each batch's bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchHeader {
    /// Always [`BATCH_COMPONENT`].
    pub component: String,
    /// The batch's number in this stream, from 0.
    pub batch: u64,
    /// The first block.
    pub first: u64,
    /// The number of blocks, all adjacent.
    pub count: u64,
    /// The byte on the disk the first block starts at.
    pub offset: u64,
    /// The number of bytes after the line.
    pub size: u64,
    /// The SHA-256 of those bytes, as lowercase hex.
    pub sha256: String,
}

/// What an export sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Exported {
    /// The blocks.
    pub blocks: u64,
    /// The block bytes, without the header lines.
    pub bytes: u64,
    /// The batches.
    pub batches: u64,
    /// The longest the device's lock was held for one block, in
    /// microseconds, from taking it to releasing it.
    pub max_lock_us: u64,
}

/// Refuses `blocks` unless every block is on a disk of `total` blocks and
/// each is above the one before, so no block is sent twice.
///
/// # Errors
///
/// Errors with a sentence naming the first block that does not hold.
pub fn check_blocks(blocks: &[u64], total: u64) -> Result<(), String> {
    let mut previous = None;
    for &block in blocks {
        if block >= total {
            return Err(format!(
                "block {block} is past the {total} blocks of the disk"
            ));
        }
        if previous.is_some_and(|p| block <= p) {
            return Err(format!(
                "block {block} comes after block {}: list the blocks in ascending order, \
                 each once",
                previous.unwrap_or_default()
            ));
        }
        previous = Some(block);
    }
    Ok(())
}

/// Groups `blocks`, ascending, into batches of adjacent blocks of at most
/// [`BATCH_BLOCKS`] each, as `(first, count)`.
fn batches(blocks: &[u64]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &block in blocks {
        match out.last_mut() {
            Some((first, count)) if *first + *count == block && *count < BATCH_BLOCKS => {
                *count += 1;
            }
            _ => out.push((block, 1)),
        }
    }
    out
}

/// Sends `blocks` of the disk behind `dev`, which [`check_blocks`] passed,
/// to `out` in batches: each batch's header line, then its bytes.
///
/// `out` is called twice per batch, and an error from it ends the export.
///
/// # Errors
///
/// Errors when a block cannot be read or `out` fails.
pub(crate) fn export(
    dev: &Mutex<VirtioBlk>,
    blocks: &[u64],
    out: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<Exported> {
    let mut sent = Exported::default();
    let mut buf = Vec::with_capacity((BATCH_BLOCKS * DIRTY_BLOCK_BYTES) as usize);
    for (number, (first, count)) in (0u64..).zip(batches(blocks)) {
        buf.clear();
        for block in first..first + count {
            let dev = lock_or_recover(dev);
            let held = Instant::now();
            let len = dev.block_len(block).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("block {block} is past the disk"),
                )
            })? as usize;
            let at = buf.len();
            buf.resize(at + len, 0);
            dev.read_block(block, &mut buf[at..])?;
            drop(dev);
            sent.max_lock_us = sent.max_lock_us.max(held.elapsed().as_micros() as u64);
        }
        let header = BatchHeader {
            component: BATCH_COMPONENT.to_string(),
            batch: number,
            first,
            count,
            offset: first * DIRTY_BLOCK_BYTES,
            size: buf.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&buf)),
        };
        let mut line = serde_json::to_vec(&header).map_err(io::Error::other)?;
        line.push(b'\n');
        out(&line)?;
        out(&buf)?;
        sent.blocks += count;
        sent.bytes += buf.len() as u64;
        sent.batches += 1;
    }
    Ok(sent)
}

#[cfg(test)]
// The tests make their disks in the temp dir; the host-path ban in
// clippy.toml is aimed at the virtio-fs device.
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::devices::virtio::block::DirtySince;
    use std::io::BufRead;
    use std::sync::Arc;

    /// Forty whole blocks and one sector: the last block is short.
    const SIZE: u64 = 40 * DIRTY_BLOCK_BYTES + 512;

    /// A disk whose every 8-byte word holds its own offset, removed on drop.
    struct Disk(std::path::PathBuf);

    impl Disk {
        fn new(tag: &str) -> Disk {
            let path = std::env::temp_dir()
                .join(format!("hvi-disk-export-{tag}-{}.img", std::process::id()));
            let bytes: Vec<u8> = (0..SIZE / 8).flat_map(|w| (w * 8).to_le_bytes()).collect();
            std::fs::write(&path, bytes).unwrap();
            Disk(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for Disk {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Reads a stream as a mover does: each header, its bytes checked
    /// against its digest, written at its offset into `image`.
    fn apply(stream: &[u8], image: &mut [u8]) -> Vec<BatchHeader> {
        let mut reader = io::BufReader::new(stream);
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                return headers;
            }
            let header: BatchHeader = serde_json::from_str(&line).unwrap();
            let mut bytes = vec![0u8; header.size as usize];
            io::Read::read_exact(&mut reader, &mut bytes).unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), header.sha256);
            let at = header.offset as usize;
            image[at..at + bytes.len()].copy_from_slice(&bytes);
            headers.push(header);
        }
    }

    // The framing round trip: a mover that applies the stream to a copy of
    // the base image ends with the disk's bytes, the short last block
    // included.
    #[test]
    fn a_stream_applied_to_the_base_gives_the_disk() {
        let disk = Disk::new("rt");
        let dev = Mutex::new(VirtioBlk::open(disk.path()).unwrap());
        let image = std::fs::read(disk.path()).unwrap();
        let blocks: Vec<u64> = vec![
            0, 1, 2, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 40,
        ];
        let mut stream = Vec::new();
        let sent = export(&dev, &blocks, &mut |b| {
            stream.extend_from_slice(b);
            Ok(())
        })
        .unwrap();

        let mut copy = vec![0u8; image.len()];
        let headers = apply(&stream, &mut copy);
        let runs: Vec<(u64, u64)> = headers.iter().map(|h| (h.first, h.count)).collect();
        assert_eq!(runs, [(0, 3), (5, 1), (7, 16), (23, 3), (40, 1)]);
        assert_eq!(
            headers.iter().map(|h| h.batch).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4]
        );
        assert_eq!(headers[4].size, 512);
        assert_eq!(
            sent,
            Exported {
                blocks: 24,
                bytes: 23 * DIRTY_BLOCK_BYTES + 512,
                batches: 5,
                max_lock_us: sent.max_lock_us,
            }
        );
        for block in 0..=40u64 {
            let at = (block * DIRTY_BLOCK_BYTES) as usize;
            let end = (at + DIRTY_BLOCK_BYTES as usize).min(image.len());
            let want: &[u8] = if blocks.contains(&block) {
                &image[at..end]
            } else {
                &vec![0u8; end - at]
            };
            assert!(copy[at..end] == *want, "block {block}");
        }
        // The header line is pinned: hull parses it.
        let first_line = stream.split(|&b| b == b'\n').next().unwrap();
        let pinned = format!(
            concat!(
                r#"{{"component":"disk-blocks","batch":0,"first":0,"count":3,"offset":0,"#,
                r#""size":196608,"sha256":"{}"}}"#
            ),
            headers[0].sha256
        );
        assert_eq!(String::from_utf8_lossy(first_line), pinned);
    }

    #[test]
    fn blocks_off_the_disk_or_out_of_order_are_refused() {
        assert_eq!(check_blocks(&[], 0), Ok(()));
        assert_eq!(check_blocks(&[0, 3, 40], 41), Ok(()));
        let past = check_blocks(&[0, 41], 41).unwrap_err();
        assert_eq!(past, "block 41 is past the 41 blocks of the disk");
        assert!(check_blocks(&[u64::MAX], 41).is_err());
        assert!(check_blocks(&[3, 3], 41).unwrap_err().contains("ascending"));
        assert!(check_blocks(&[4, 3], 41).unwrap_err().contains("ascending"));
        // The export refuses a block past the disk too, before it sends it.
        let disk = Disk::new("past");
        let dev = Mutex::new(VirtioBlk::open(disk.path()).unwrap());
        let mut stream = Vec::new();
        let err = export(&dev, &[41], &mut |b| {
            stream.extend_from_slice(b);
            Ok(())
        })
        .unwrap_err();
        assert!(err.to_string().contains("past the disk"), "{err}");
        assert!(stream.is_empty());
    }

    #[test]
    fn a_failed_send_ends_the_export() {
        let disk = Disk::new("fail");
        let dev = Mutex::new(VirtioBlk::open(disk.path()).unwrap());
        let mut calls = 0;
        let err = export(&dev, &[0, 9, 20], &mut |_| {
            calls += 1;
            if calls == 3 {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(calls, 3);
    }

    // A block the guest writes while the export runs is in the next round,
    // whether or not the export already read it, so a mover that applies
    // every round ends with the disk the guest left.
    #[test]
    fn a_write_during_an_export_lands_in_the_next_round() {
        let disk = Disk::new("race");
        let dev = Arc::new(Mutex::new(VirtioBlk::open(disk.path()).unwrap()));
        let mut base = std::fs::read(disk.path()).unwrap();
        let round0 = lock_or_recover(&dev).read_dirty(DirtySince::Boot).unwrap();
        assert_eq!(round0.dirty.count(), 0);

        // Round 0 is empty, so export blocks 0 and 30 as if they were in it,
        // and write blocks 0 and 30 between the two batches: block 0 went
        // out before its write, block 30 after it.
        let writer = Arc::clone(&dev);
        let mut stream = Vec::new();
        let mut calls = 0;
        export(&dev, &[0, 30], &mut |b| {
            stream.extend_from_slice(b);
            calls += 1;
            if calls == 2 {
                let mut dev = lock_or_recover(&writer);
                for block in [0u64, 30] {
                    dev.write_for_test(block * DIRTY_BLOCK_BYTES + 100, &[0xab; 64]);
                }
            }
            Ok(())
        })
        .unwrap();
        apply(&stream, &mut base);

        let round1 = lock_or_recover(&dev).read_dirty(DirtySince::Round).unwrap();
        assert_eq!(round1.dirty.iter().collect::<Vec<_>>(), [0, 30]);
        let blocks: Vec<u64> = round1.dirty.iter().collect();
        let mut stream = Vec::new();
        export(&dev, &blocks, &mut |b| {
            stream.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        apply(&stream, &mut base);
        assert!(base == std::fs::read(disk.path()).unwrap());
    }
}

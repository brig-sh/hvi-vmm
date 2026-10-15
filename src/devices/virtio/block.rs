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

//! A virtio-blk device over virtio-mmio.
//!
//! Because this VMM implements the device backend, every block request the
//! guest issues passes through our code by construction: servicing the
//! virtqueue and capturing the guest's disk I/O are the same act (see the
//! `[virtio-blk]` log lines).
//!
//! The transport is modern virtio-mmio (version 2), enough for the Linux
//! `virtio_mmio` and `virtio_blk` drivers to negotiate `VIRTIO_F_VERSION_1`,
//! set up one queue, and read and write.
//!
//! The requests are served on a worker thread of their own, `serve`, not
//! in the vCPU's exit: a notify only wakes the worker. A guest flush is an
//! `fdatasync`, and a write can wait on the host's writeback, so a request
//! can take seconds on a busy host disk. On the vCPU's thread that stopped
//! the guest's CPU for as long, and a pause could not park it. The worker
//! makes the disk call without the device's lock, so the vCPU still reads
//! and acknowledges the interrupt meanwhile.
//!
//! The device also keeps the disk's dirty blocks for a move: a bitmap of
//! the 64 KiB blocks the guest wrote since it booted, and one of the blocks
//! it wrote since a mover last read them, see [`DirtyBlocks`] and
//! [`VirtioBlk::read_dirty`]. A mover that holds the image the guest booted
//! from then sends only those blocks.
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this
// VMM's own.
#![allow(clippy::disallowed_methods)]

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::checkpoint::bundle::hex;
use crate::memory::GuestRam;

use crate::devices::irq::{Irq, IrqLine};
use crate::devices::state::{check_version, invalid};
use crate::devices::virtio::{
    mmio, Queue, QueueState, VirtioCommonState, QUEUE_NUM_MAX, VIRTQ_DESC_F_NEXT,
    VIRTQ_DESC_F_WRITE,
};
use crate::devices::wake::Wake;
use crate::events::CapturedEvent;
use crate::plugin::IoSink;
use crate::sync::lock_or_recover;
use crate::teardown::StopToken;
use crate::LOG_PREFIX;

const MAGIC_VALUE: u64 = 0x7472_6976; // "virt" little-endian
const VIRTIO_BLK_ID: u64 = virtio_bindings::virtio_ids::VIRTIO_ID_BLOCK as u64;
const VENDOR: u64 = 0x4649_4f4e; // "NOIF"

/// `VIRTIO_F_VERSION_1` -- required for a modern device. It is feature bit 32,
/// so it lands in bit 0 of the high 32-bit word the driver selects.
const F_VERSION_1_HI: u32 = 1 << (virtio_bindings::virtio_config::VIRTIO_F_VERSION_1 - 32);
/// `VIRTIO_BLK_F_FLUSH` (low word): the guest may issue explicit cache-flush
/// requests. Advertising and honouring it gives correct durability semantics
/// for `fsync`/`end_fsync` workloads instead of the guest guessing.
const F_BLK_FLUSH_LO: u32 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_FLUSH;

/// virtio-blk request types.
const VIRTIO_BLK_T_IN: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_IN; // read disk -> guest
const VIRTIO_BLK_T_OUT: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_OUT; // guest -> write disk
const VIRTIO_BLK_T_FLUSH: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_FLUSH; // flush the cache

/// virtio-blk status byte.
const VIRTIO_BLK_S_OK: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_OK as u8;
const VIRTIO_BLK_S_IOERR: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_IOERR as u8;

const SECTOR: u64 = 512;

/// The [`BlkState`] format this build writes and reads.
pub const BLK_STATE_VERSION: u32 = 1;

/// The size of a block in the dirty bitmaps: 64 KiB, so a 16 GiB disk takes
/// a 32 KiB bitmap and a block is 128 sectors.
pub const DIRTY_BLOCK_BYTES: u64 = 64 << 10;

/// The largest disk whose blocks written since boot a checkpoint records,
/// 4 TiB. Its bitmap is 8 MiB, 11,184,812 characters of base64, which the
/// 12 MiB limit on `disk.json` holds with room for the rest of the document.
/// A disk with a base digest (`--disk-base-sha256`) must be no larger, so a
/// move by its blocks always carries the bitmap on; a larger disk without
/// one is checkpointed without it.
pub const MAX_BITMAP_DISK_BYTES: u64 = 4 << 40;

/// The most rounds [`VirtioBlk::read_dirty`] reads after a round 0, so the
/// list of rounds a device keeps, and `disk.json` records, stays small. A
/// move takes a handful; a mover that needs more starts over at round 0.
pub const MAX_ROUNDS: usize = 1024;

/// A bitmap of a disk's [`DIRTY_BLOCK_BYTES`] blocks.
///
/// Bit `i` is bit `i % 8` of byte `i / 8`, as in a checkpoint's `ram.map`,
/// and block `i` covers bytes `i * 64 KiB` up to the next block or the end
/// of the disk: the last block is short when the disk is not a whole number
/// of blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirtyBlocks {
    bits: Vec<u8>,
    blocks: u64,
}

impl DirtyBlocks {
    /// Returns an empty bitmap for a disk of `size_bytes`.
    #[must_use]
    pub fn for_size(size_bytes: u64) -> Self {
        let blocks = size_bytes.div_ceil(DIRTY_BLOCK_BYTES);
        Self {
            bits: vec![0; Self::len_for(blocks)],
            blocks,
        }
    }

    /// Returns the length in bytes of the bitmap of `blocks` blocks.
    #[must_use]
    pub fn len_for(blocks: u64) -> usize {
        // A disk of 2^64 bytes has 2^48 blocks, a 32 TiB bitmap: the length
        // fits a usize on any host that could hold the bitmap.
        usize::try_from(blocks.div_ceil(8)).unwrap_or(usize::MAX)
    }

    /// Takes `bits` as the bitmap of a disk of `size_bytes`.
    ///
    /// # Errors
    ///
    /// Errors when `bits` is not as long as the disk's bitmap, or sets a
    /// bit past the disk's last block.
    pub fn from_bytes(bits: Vec<u8>, size_bytes: u64) -> std::io::Result<Self> {
        let blocks = size_bytes.div_ceil(DIRTY_BLOCK_BYTES);
        let want = Self::len_for(blocks);
        if bits.len() != want {
            return Err(invalid(format_args!(
                "the dirty bitmap is {} bytes, a disk of {size_bytes} bytes has {want}",
                bits.len()
            )));
        }
        let spare = (want as u64 * 8 - blocks) as u32;
        if spare > 0 && bits.last().is_some_and(|b| b >> (8 - spare) != 0) {
            return Err(invalid(format_args!(
                "the dirty bitmap sets a block past the {blocks} blocks of the disk"
            )));
        }
        Ok(Self { bits, blocks })
    }

    /// Returns the number of blocks the bitmap covers.
    #[must_use]
    pub fn blocks(&self) -> u64 {
        self.blocks
    }

    /// Returns the bitmap's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Marks every block the `len` bytes at `offset` touch. Bytes past the
    /// last block mark nothing.
    pub fn mark(&mut self, offset: u64, len: u64) {
        if len == 0 || self.blocks == 0 {
            return;
        }
        let first = offset / DIRTY_BLOCK_BYTES;
        let last = (offset.saturating_add(len - 1) / DIRTY_BLOCK_BYTES).min(self.blocks - 1);
        for block in first..=last {
            self.bits[(block / 8) as usize] |= 1 << (block % 8);
        }
    }

    /// Returns whether block `block` is marked.
    #[must_use]
    pub fn is_set(&self, block: u64) -> bool {
        block < self.blocks && self.bits[(block / 8) as usize] & (1 << (block % 8)) != 0
    }

    /// Returns the number of marked blocks.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.bits.iter().map(|b| u64::from(b.count_ones())).sum()
    }

    /// Returns the marked blocks in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.bits
            .iter()
            .enumerate()
            .filter(|(_, &bits)| bits != 0)
            .flat_map(|(byte, &bits)| {
                (0..8u64)
                    .filter(move |bit| bits & (1 << bit) != 0)
                    .map(move |bit| byte as u64 * 8 + bit)
            })
    }

    /// Returns the bitmap and leaves this one empty.
    fn take(&mut self) -> Self {
        let empty = vec![0; self.bits.len()];
        Self {
            bits: std::mem::replace(&mut self.bits, empty),
            blocks: self.blocks,
        }
    }
}

/// Which dirty blocks [`VirtioBlk::read_dirty`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirtySince {
    /// Every block the guest wrote since it booted, over every restore of
    /// it. Reading them starts the rounds of a move: this is round 0.
    Boot,
    /// The blocks the guest wrote since the last read, which this read
    /// clears: the next round.
    Round,
}

/// One read of the dirty blocks, as `disk.json` lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskRound {
    /// The round's number: 0 for the blocks since boot, then 1, 2 and on.
    pub round: u32,
    /// The device's generation when the round was read. A write after it
    /// is in a later round.
    pub generation: u64,
    /// The number of blocks the round holds.
    pub blocks: u64,
    /// The SHA-256 of the round's bitmap, the bytes `disk-dirty` returned
    /// as `bitmap_b64`, as lowercase hex: a destination that hashes the
    /// bitmap it applied shows it applied the set the source read.
    #[serde(default)]
    pub bitmap_sha256: Option<String>,
    /// The digest of the round's `disk-blocks` stream, as its reply gives
    /// it in `sent_sha256`, once `{"round":k}` sent the round whole before
    /// the next read; `null` until then, and for a round streamed after
    /// the capture.
    #[serde(default)]
    pub sent_sha256: Option<String>,
}

/// What [`VirtioBlk::read_dirty`] returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirtyRead {
    /// The round this read is.
    pub round: u32,
    /// The device's generation when it was read.
    pub generation: u64,
    /// The blocks.
    pub dirty: DirtyBlocks,
    /// The SHA-256 of the bitmap's bytes, as lowercase hex.
    pub bitmap_sha256: String,
}

/// The dirty blocks a virtio-blk device keeps for a move.
///
/// Neither bitmap is part of the guest's view of the device, so a reset
/// leaves them: a guest that reboots keeps the disk it wrote.
#[derive(Debug)]
struct Dirty {
    /// Every block written since the guest booted.
    since_boot: DirtyBlocks,
    /// Every block written since the last read.
    since_read: DirtyBlocks,
    /// The reads since round 0, in order.
    rounds: Vec<DiskRound>,
    /// The blocks the last read returned, which `disk-blocks` may export by
    /// its round number.
    last: Option<DirtyBlocks>,
}

impl Dirty {
    fn new(size_bytes: u64) -> Self {
        Self {
            since_boot: DirtyBlocks::for_size(size_bytes),
            since_read: DirtyBlocks::for_size(size_bytes),
            rounds: Vec::new(),
            last: None,
        }
    }

    fn mark(&mut self, offset: u64, len: u64) {
        self.since_boot.mark(offset, len);
        self.since_read.mark(offset, len);
    }
}

/// What a checkpoint keeps of a virtio-blk device.
///
/// The disk's bytes are not here: the image travels on its own, and a restore
/// reopens it. Nothing is in flight either: the worker holds the pause gate
/// from the moment it takes a chain until it has returned it, so a capture,
/// which runs with the gate closed, finds every chain taken already
/// returned. The ledger staging, the plugin feed, the inode and the trace
/// switch belong to the host the device runs on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlkState {
    /// [`BLK_STATE_VERSION`] when written by this build.
    pub version: u32,
    /// The transport registers. The device has one queue, so `queue_sel` is
    /// always 0.
    pub common: VirtioCommonState,
    /// The one request queue.
    pub queue: QueueState,
    /// The disk size the guest was told, in 512-byte sectors.
    pub capacity_sectors: u64,
}

impl BlkState {
    /// Refuses a state this build could not restore over `mem`, without
    /// opening the disk or touching guest RAM.
    ///
    /// The disk's size is not checked here, since only the disk knows it;
    /// [`VirtioBlk::restore`] checks it.
    ///
    /// # Errors
    ///
    /// Errors when the state is of another version, has a queue the transport
    /// would not have accepted, or has registers this device never holds.
    pub fn check(&self, mem: &GuestRam) -> std::io::Result<()> {
        check_version("virtio-blk", self.version, BLK_STATE_VERSION)?;
        self.common.check("virtio-blk")?;
        if self.common.queue_sel != 0 {
            return Err(invalid(format_args!(
                "virtio-blk has one queue, state selects queue {}",
                self.common.queue_sel
            )));
        }
        self.queue.check(mem)
    }
}

/// A virtio-blk device behind a virtio-mmio transport.
pub struct VirtioBlk {
    /// The disk, shared with a mover that syncs it without the device's
    /// lock (see [`data_file`](Self::data_file)).
    file: Arc<File>,
    /// A second open of the disk, which holds an exclusive `flock` on it
    /// while this guest may still write it. See [`DiskLock`].
    lock: Option<DiskLock>,
    capacity_sectors: u64,
    status: u32,
    dev_feat_sel: u32,
    queue: Queue,
    interrupt_status: u32,
    /// The interrupt line the device drives.
    irq: Irq,
    /// Captured requests, drained by the hypervisor backend into the event
    /// ledger.
    events: Vec<CapturedEvent>,
    /// Live feed of each request to a plugin, when one asked for it. The
    /// same requests the ledger records, handed over as they happen rather
    /// than drained after the fact.
    sink: Option<Arc<dyn IoSink>>,
    /// Stable id for this backing file, so a reader can tell two disks apart.
    disk_id: u64,
    /// Per-request `[virtio-blk]` console tracing, off by default (it is a
    /// synchronous stderr write per request — ruinous under fio). Enable with
    /// `HVI_BLK_TRACE=1`; the structured ledger still records every request.
    trace: bool,
    /// The writes and flushes served since the guest booted: by this
    /// device, and by every device of earlier processes the guest was
    /// restored from.
    ///
    /// A checkpoint records it, so two captures of one guest can tell
    /// whether the guest changed the disk between them without reading the
    /// image, and a restore carries it on, so it only grows across moves.
    generation: u64,
    /// The blocks the guest wrote, for a move.
    dirty: Dirty,
    /// Counts the resets and queue programmings, so a request taken before
    /// one is not returned on a ring the driver has replaced.
    epoch: u64,
    /// The chains left in the current pass, see
    /// [`take_request`](Self::take_request).
    pass_left: u16,
    /// Whether a request of the current pass was finished without raising
    /// the interrupt, which the pass's end then owes the driver.
    owed_irq: bool,
    /// The worker's wake signal, which a notify sets, once the worker runs.
    wake: Option<Arc<Wake>>,
    /// Set once a fence released the disk: no request is served after it.
    fenced: bool,
    /// Called as each request runs, so a test can hold the worker there.
    #[cfg(test)]
    run_hook: Option<RunHook>,
}

/// A test's hook into [`BlkRequest::run`], called with the request's kind.
#[cfg(test)]
pub(crate) type RunHook = Arc<dyn Fn(&'static str) + Send + Sync>;

/// Size in bytes of whatever is behind `file`.
///
/// `metadata().len()` is the *file* size, and for a block special file that is
/// 0 -- so a disk-image path works and a block device silently advertises a
/// zero-sector virtio-blk. That failure is unpleasant to read: the guest
/// registers `/dev/vda` normally and then fails every read, so the console says
/// "unable to read superblock" rather than anything about a missing disk.
///
/// Container runtimes hand us exactly that. urunc passes the devmapper snapshot
/// of the container's rootfs (`/dev/mapper/...`), not a file. So ask the kernel
/// for the device size when the path is a block device.
fn backing_len(file: &File) -> std::io::Result<u64> {
    let meta = file.metadata()?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::FileTypeExt;
        use std::os::unix::io::AsRawFd;

        if meta.file_type().is_block_device() {
            // The device size in bytes; BLKGETSIZE counts 512-byte sectors.
            // libc declares no BLKGETSIZE64, so the request is built here.
            const BLKGETSIZE64: libc::Ioctl = libc::_IOR::<usize>(0x12, 114);
            let mut size: u64 = 0;
            // SAFETY: `file` is an open block device and `size` is a live u64
            // that the ioctl writes exactly one u64 into.
            let rc = unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64, &mut size) };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            return Ok(size);
        }
    }
    Ok(meta.len())
}

/// An exclusive `flock` on a disk, so a second hvi cannot write it too.
///
/// Two guests writing one image corrupt its filesystem, and a checkpoint
/// bundle can be restored any number of times, so hvi keeps a second
/// process off a disk that one still has as its own. The lock is held on
/// an open of its own, not on the device's file: it is released by closing
/// that open, which needs no system call the sandbox would have to allow
/// after confinement. A `flock` conflicts with every other open of the
/// file, in this process or another, and goes with the process that holds
/// it, however that ends.
///
/// It is advisory: it keeps out another hvi, not a program that writes the
/// image without asking.
#[derive(Debug)]
pub(crate) struct DiskLock {
    /// The open that holds the lock; closing it releases the lock.
    _file: File,
}

impl DiskLock {
    /// Takes the lock on the disk at `path`, whose device file is `disk`.
    ///
    /// A regular file or a block device is locked. Anything else, such as
    /// a character device, is not a disk two guests could share, and a
    /// filesystem that has no `flock` leaves the disk unlocked, as before.
    ///
    /// # Errors
    ///
    /// Errors, as `WouldBlock`, when another open of the disk holds the
    /// lock, or when the path cannot be opened again.
    pub(crate) fn take(path: &str, disk: &File) -> std::io::Result<Option<Self>> {
        use std::os::unix::fs::FileTypeExt;
        use std::os::unix::io::AsRawFd;

        let kind = disk.metadata()?.file_type();
        if !kind.is_file() && !kind.is_block_device() {
            return Ok(None);
        }
        let file = File::open(path)?;
        // SAFETY: flock on a descriptor `file` owns, with valid operations.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(DiskLock { _file: file }));
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EWOULDBLOCK) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!(
                    "virtio-blk: {path} is locked by another process, most likely an hvi \
                     that has it as its disk; two guests writing one image corrupt it"
                ),
            )),
            Some(e) if e == libc::ENOTSUP || e == libc::EOPNOTSUPP || e == libc::ENOLCK => {
                eprintln!(
                    "{LOG_PREFIX} virtio-blk: {path} cannot be locked ({err}); left unlocked"
                );
                Ok(None)
            }
            _ => Err(std::io::Error::new(
                err.kind(),
                format!("virtio-blk: locking {path}: {err}"),
            )),
        }
    }
}

impl VirtioBlk {
    /// Opens `path` read-write as the backing disk, and takes the lock that
    /// keeps another hvi from writing it as well (see `DiskLock`).
    ///
    /// # Errors
    ///
    /// Errors if the file cannot be opened or its length read, or, as
    /// `WouldBlock`, when another process holds the disk's lock.
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let lock = DiskLock::take(path, &file)?;
        let mut dev = Self::from_file(file)?;
        dev.lock = lock;
        Ok(dev)
    }

    /// Opens `path` as [`open`](Self::open) does, for a boot that was given
    /// the digest of the disk's base image when `has_base`. `written`, when
    /// given, is the bitmap of the blocks where the disk already differs
    /// from that base, which start the blocks written since boot.
    ///
    /// # Errors
    ///
    /// Errors as [`open`](Self::open) does, and when `has_base` and the disk
    /// is larger than [`MAX_BITMAP_DISK_BYTES`]: a checkpoint could not
    /// record the blocks it wrote since boot, which a move by its blocks
    /// needs. Errors too when `written` is not the bitmap of this disk.
    pub fn open_with_base(
        path: &str,
        has_base: bool,
        written: Option<&[u8]>,
    ) -> std::io::Result<Self> {
        let mut dev = Self::open(path)?;
        if has_base && dev.size_bytes() > MAX_BITMAP_DISK_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "--disk-base-sha256: {path} is {} bytes, and a move by its blocks takes a \
                     disk of at most 4 TiB",
                    dev.size_bytes()
                ),
            ));
        }
        if let Some(bits) = written {
            dev.dirty.since_boot = DirtyBlocks::from_bytes(bits.to_vec(), dev.size_bytes())
                .map_err(|e| {
                    std::io::Error::new(e.kind(), format!("--disk-written for {path}: {e}"))
                })?;
        }
        Ok(dev)
    }

    /// Releases the disk's lock, so another hvi may open the disk while
    /// this one still has it open, and serves no request from then on.
    /// Returns whether there was a lock.
    ///
    /// A source fenced after a checkpoint calls it: its guest never runs
    /// again, so it never writes the disk again, and the restore that takes
    /// the guest over may start before the source is stopped. The fence runs
    /// with the pause gate closed, so no request is in flight; the worker
    /// passes the gate again once the stop opens it, and then finds nothing
    /// to take, since chains the guest left pending belong to the restore.
    pub fn release_lock(&mut self) -> bool {
        self.fenced = true;
        self.lock.take().is_some()
    }

    /// Gives the device its worker's wake signal, which every notify sets
    /// from then on. See [`serve`].
    pub(crate) fn connect_worker(&mut self, wake: Arc<Wake>) {
        self.wake = Some(wake);
    }

    /// Calls `hook` as each request runs, with the request's kind.
    #[cfg(test)]
    pub(crate) fn set_run_hook(&mut self, hook: RunHook) {
        self.run_hook = Some(hook);
    }

    /// Builds a reset device over `file`, an open read-write disk.
    fn from_file(file: File) -> std::io::Result<Self> {
        let capacity_sectors = backing_len(&file)? / SECTOR;
        // The inode identifies the backing store across the two processes that
        // care about it, without agreeing on a path: hvi may have been given a
        // relative one, and the reader is given its own.
        let disk_id = file.metadata().map(|m| m.ino()).unwrap_or(0);
        Ok(VirtioBlk {
            file: Arc::new(file),
            lock: None,
            capacity_sectors,
            status: 0,
            dev_feat_sel: 0,
            queue: Queue::default(),
            interrupt_status: 0,
            irq: Irq::default(),
            events: Vec::new(),
            sink: None,
            disk_id,
            trace: std::env::var_os("HVI_BLK_TRACE").is_some(),
            generation: 0,
            dirty: Dirty::new(capacity_sectors * SECTOR),
            epoch: 0,
            pass_left: 0,
            owed_irq: false,
            wake: None,
            fenced: false,
            #[cfg(test)]
            run_hook: None,
        })
    }

    /// Feeds each request to `sink` as well as the ledger.
    pub fn set_io_sink(&mut self, sink: Arc<dyn IoSink>) {
        self.sink = Some(sink);
    }

    /// The interrupt line level: asserted while an unacknowledged used-buffer
    /// notification is pending.
    #[must_use]
    pub fn irq_level(&self) -> bool {
        self.interrupt_status != 0
    }

    /// Connects the device to the interrupt line it raises, and sets the line
    /// to the device's level.
    ///
    /// A device built at boot has nothing pending, so the line stays low. One
    /// restored from a checkpoint may hold a used-buffer interrupt the driver
    /// has not acknowledged, and a line left low over it is an interrupt the
    /// guest never takes: it waits for a completion it was already given.
    pub(crate) fn connect_irq(&mut self, line: Arc<dyn IrqLine>) {
        self.irq.connect(line);
        self.sync_irq();
    }

    /// Sets the interrupt line to the device's level, whatever it was last
    /// set to, after a restore loaded the interrupt controller. See
    /// `Irq::redrive`.
    // The x86-64 restore does not exist yet.
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    pub(crate) fn redrive_irq(&mut self) {
        self.irq.redrive(self.irq_level());
    }

    /// Returns the number of writes and flushes the guest has had served
    /// since it booted.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the size of the disk in bytes, as the guest was told it.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.capacity_sectors * SECTOR
    }

    /// Returns the blocks the guest wrote since it booted, over every
    /// restore of it.
    #[must_use]
    pub fn dirty_since_boot(&self) -> &DirtyBlocks {
        &self.dirty.since_boot
    }

    /// Returns the rounds read since the last round 0, in order.
    #[must_use]
    pub fn rounds(&self) -> &[DiskRound] {
        &self.dirty.rounds
    }

    /// Returns the number of the last round read and the blocks it
    /// returned.
    #[must_use]
    pub fn last_round(&self) -> Option<(u32, &DirtyBlocks)> {
        let round = self.dirty.rounds.last()?.round;
        Some((round, self.dirty.last.as_ref()?))
    }

    /// Reads the dirty blocks `since` asks for, and starts a round.
    ///
    /// [`DirtySince::Boot`] returns every block written since boot, clears
    /// the blocks written since the last read, and starts the rounds over
    /// at round 0. [`DirtySince::Round`] returns the blocks written since the
    /// last read and clears them: the next round. Either way a write the
    /// guest makes after this call is in the next round, since the guest
    /// writes under the same lock the caller holds.
    ///
    /// # Errors
    ///
    /// Errors when a round is asked for before round 0, or past the
    /// [`MAX_ROUNDS`]th after it.
    pub fn read_dirty(&mut self, since: DirtySince) -> std::io::Result<DirtyRead> {
        let (round, dirty) = match since {
            DirtySince::Boot => {
                self.dirty.rounds.clear();
                self.dirty.since_read.take();
                (0, self.dirty.since_boot.clone())
            }
            DirtySince::Round => {
                let Some(last) = self.dirty.rounds.last() else {
                    return Err(invalid(format_args!(
                        "no round 0 yet: read the blocks since boot first"
                    )));
                };
                if self.dirty.rounds.len() > MAX_ROUNDS {
                    return Err(invalid(format_args!(
                        "{MAX_ROUNDS} rounds were read after round 0: read the blocks since \
                         boot to start over"
                    )));
                }
                let round = last.round + 1;
                (round, self.dirty.since_read.take())
            }
        };
        let bitmap_sha256 = hex(&Sha256::digest(dirty.as_bytes()));
        self.dirty.rounds.push(DiskRound {
            round,
            generation: self.generation,
            blocks: dirty.count(),
            bitmap_sha256: Some(bitmap_sha256.clone()),
            sent_sha256: None,
        });
        self.dirty.last = Some(dirty.clone());
        Ok(DirtyRead {
            round,
            generation: self.generation,
            dirty,
            bitmap_sha256,
        })
    }

    /// Records that `disk-blocks` sent round `round` whole, with the stream
    /// digest `sent_sha256`, when it is still the last round read. Returns
    /// whether it was.
    pub fn record_sent(&mut self, round: u32, sent_sha256: String) -> bool {
        match self.dirty.rounds.last_mut() {
            Some(last) if last.round == round => {
                last.sent_sha256 = Some(sent_sha256);
                true
            }
            _ => false,
        }
    }

    /// Returns the length of block `block` of the disk: [`DIRTY_BLOCK_BYTES`],
    /// or less for the last block of a disk that is not a whole number of
    /// blocks. `None` for a block past the disk.
    #[must_use]
    pub fn block_len(&self, block: u64) -> Option<u64> {
        let size = self.size_bytes();
        let start = block.checked_mul(DIRTY_BLOCK_BYTES)?;
        (start < size).then(|| (size - start).min(DIRTY_BLOCK_BYTES))
    }

    /// Reads block `block` of the disk into `out`, which must be
    /// [`block_len`](Self::block_len) bytes long.
    ///
    /// # Errors
    ///
    /// Errors when the block is past the disk, `out` is not its length, or
    /// the read fails.
    pub fn read_block(&self, block: u64, out: &mut [u8]) -> std::io::Result<()> {
        let len = self.block_len(block).ok_or_else(|| {
            invalid(format_args!(
                "block {block} is past the {} blocks of the disk",
                self.dirty.since_boot.blocks()
            ))
        })?;
        if out.len() as u64 != len {
            return Err(invalid(format_args!(
                "block {block} is {len} bytes, not {}",
                out.len()
            )));
        }
        self.file.read_exact_at(out, block * DIRTY_BLOCK_BYTES)
    }

    /// Writes the disk's data to stable storage, as a guest flush does.
    ///
    /// A checkpoint calls it with the guest parked, so the image another host
    /// reads holds every write the guest was told had completed.
    ///
    /// # Errors
    ///
    /// Errors as `fdatasync` does.
    pub fn sync_data(&self) -> std::io::Result<()> {
        self.file.sync_data()
    }

    /// Returns the disk's open file, to sync without holding the device's
    /// lock.
    ///
    /// A live move syncs the disk right before it pauses the guest, while
    /// the guest still runs, so the sync in the pause has only the last
    /// writes left. Holding the lock for that first sync would stall the
    /// guest's disk for as long as it takes, which was seconds on a busy
    /// host. Cloning the `Arc` needs no system call, so a confined process
    /// may do it.
    #[must_use]
    pub fn data_file(&self) -> Arc<File> {
        Arc::clone(&self.file)
    }

    /// Returns what a checkpoint keeps of the device.
    #[must_use]
    pub fn state(&self) -> BlkState {
        BlkState {
            version: BLK_STATE_VERSION,
            common: VirtioCommonState {
                status: self.status,
                dev_feat_sel: self.dev_feat_sel,
                queue_sel: 0,
                interrupt_status: self.interrupt_status,
            },
            queue: self.queue.state(),
            capacity_sectors: self.capacity_sectors,
        }
    }

    /// Rebuilds the device a checkpoint describes over the disk at `path`,
    /// opened read-write as [`VirtioBlk::open`] opens it, and the restored
    /// guest RAM `mem`. Its generation goes on from `generation`, the one
    /// the checkpoint's `disk.json` records, and its blocks written since
    /// boot from `since_boot`, the ones `disk.json` records, so a later move
    /// still sends every block that differs from the image the guest booted
    /// from. Its rounds start over.
    ///
    /// The disk must be the size the guest was told. A guest's filesystem
    /// sized itself to that capacity at mount, so a smaller disk fails its
    /// reads past the end and a larger one is space it never uses; either
    /// means the image is not the one the checkpoint was taken over. The
    /// interrupt line is connected afterwards, as at boot, and connecting it
    /// asserts it when the state holds an unacknowledged interrupt.
    ///
    /// # Errors
    ///
    /// Errors when the disk cannot be opened, when its size is not
    /// `capacity_sectors`, when `since_boot` is the bitmap of a disk of
    /// another size, or when the state is of another version, has a queue
    /// the transport would not have accepted, or has registers this device
    /// never holds.
    pub fn restore(
        path: &str,
        mem: &GuestRam,
        state: &BlkState,
        generation: u64,
        since_boot: Option<DirtyBlocks>,
    ) -> std::io::Result<Self> {
        state.check(mem)?;
        let queue = Queue::from_state(mem, &state.queue)?;
        let mut dev = Self::open(path)?;
        if dev.capacity_sectors != state.capacity_sectors {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "virtio-blk: {path} holds {} sectors, the guest was given {}",
                    dev.capacity_sectors, state.capacity_sectors
                ),
            ));
        }
        dev.status = state.common.status;
        dev.dev_feat_sel = state.common.dev_feat_sel;
        dev.interrupt_status = state.common.interrupt_status;
        if let Some(since_boot) = since_boot {
            if since_boot.blocks() != dev.dirty.since_boot.blocks() {
                return Err(invalid(format_args!(
                    "virtio-blk: the dirty bitmap covers {} blocks, {path} has {}",
                    since_boot.blocks(),
                    dev.dirty.since_boot.blocks()
                )));
            }
            dev.dirty.since_boot = since_boot;
        }
        dev.queue = queue;
        dev.generation = generation;
        Ok(dev)
    }

    /// Sets the interrupt line to the device's level.
    fn sync_irq(&mut self) {
        self.irq.set(self.irq_level());
    }

    /// Drains the captured requests for the event ledger.
    pub fn take_events(&mut self) -> Vec<CapturedEvent> {
        std::mem::take(&mut self.events)
    }

    /// The device features this device offers, both words: what the machine
    /// profile records, since a restored driver has negotiated against them.
    pub const FEATURES: u64 = ((F_VERSION_1_HI as u64) << 32) | F_BLK_FLUSH_LO as u64;

    /// Services one MMIO access. Returns the read value (0 for writes). When
    /// the driver notifies the queue, the worker is woken to serve it.
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
                mmio::QUEUE_SEL => {} // only queue 0
                mmio::QUEUE_NOTIFY => {
                    if let Some(wake) = &self.wake {
                        wake.wake();
                    }
                }
                mmio::INTERRUPT_ACK => self.interrupt_status &= !v,
                mmio::STATUS if v == 0 => self.reset(),
                mmio::STATUS => self.status = v,
                mmio::QUEUE_NUM
                | mmio::QUEUE_READY
                | mmio::QUEUE_DESC_LOW
                | mmio::QUEUE_DESC_HIGH
                | mmio::QUEUE_DRIVER_LOW
                | mmio::QUEUE_DRIVER_HIGH
                | mmio::QUEUE_DEVICE_LOW
                | mmio::QUEUE_DEVICE_HIGH => self.program_queue(mem, offset, v),
                _ => {}
            }
            0
        } else {
            match offset {
                mmio::MAGIC => MAGIC_VALUE,
                mmio::VERSION => 2,
                mmio::DEVICE_ID => VIRTIO_BLK_ID,
                mmio::VENDOR_ID => VENDOR,
                // Low word: VIRTIO_BLK_F_FLUSH. High word: VIRTIO_F_VERSION_1.
                mmio::DEVICE_FEATURES if self.dev_feat_sel == 0 => u64::from(F_BLK_FLUSH_LO),
                mmio::DEVICE_FEATURES if self.dev_feat_sel == 1 => u64::from(F_VERSION_1_HI),
                mmio::QUEUE_NUM_MAX => u64::from(QUEUE_NUM_MAX),
                mmio::QUEUE_READY => u64::from(self.queue.is_ready()),
                mmio::INTERRUPT_STATUS => u64::from(self.interrupt_status),
                mmio::STATUS => u64::from(self.status),
                // Config space: capacity (in 512-byte sectors) at offset 0.
                // Return the 8-byte little-endian window starting at the field
                // so a sized (byte/half/word) read takes the right low bytes;
                // the caller masks to the access width.
                _ if offset >= mmio::CONFIG => {
                    let field = (offset - mmio::CONFIG) as usize;
                    let cap = self.capacity_sectors.to_le_bytes();
                    let mut w = [0u8; 8];
                    for (i, b) in w.iter_mut().enumerate() {
                        if let Some(&c) = cap.get(field + i) {
                            *b = c;
                        }
                    }
                    u64::from_le_bytes(w)
                }
                _ => 0,
            }
        }
    }

    /// Resets the device, as a write of 0 to STATUS requests.
    fn reset(&mut self) {
        self.queue.reset();
        self.interrupt_status = 0;
        self.status = 0;
        self.dev_feat_sel = 0;
        self.forget_taken();
    }

    /// Writes `v` to the queue register at `offset`.
    fn program_queue(&mut self, mem: &GuestRam, offset: u64, v: u32) {
        match offset {
            mmio::QUEUE_NUM => self.queue.set_num(v),
            mmio::QUEUE_READY => self.queue.set_ready(v, mem),
            mmio::QUEUE_DESC_LOW => self.queue.set_desc_lo(v),
            mmio::QUEUE_DESC_HIGH => self.queue.set_desc_hi(v),
            mmio::QUEUE_DRIVER_LOW => self.queue.set_avail_lo(v),
            mmio::QUEUE_DRIVER_HIGH => self.queue.set_avail_hi(v),
            mmio::QUEUE_DEVICE_LOW => self.queue.set_used_lo(v),
            mmio::QUEUE_DEVICE_HIGH => self.queue.set_used_hi(v),
            _ => return,
        }
        self.forget_taken();
    }

    /// Ends the current pass and keeps every request taken so far off the
    /// rings, which the driver is replacing.
    fn forget_taken(&mut self) {
        self.epoch += 1;
        self.pass_left = 0;
        self.owed_irq = false;
    }

    /// Serves every chain the driver has made available on queue 0, in
    /// order, on the test's thread, as the worker would.
    #[cfg(test)]
    pub(crate) fn serve_now(&mut self, mem: &GuestRam) {
        while let Some(request) = self.take_request(mem) {
            let done = request.run(mem);
            self.finish(mem, request, done);
        }
    }

    /// Takes the next chain the driver made available on queue 0, and
    /// returns the request it holds, or `None` when there is none.
    ///
    /// The chains are taken in passes, each of the chains pending when it
    /// starts, and the last request of a pass raises the interrupt once it
    /// is finished, as a notify that served them all at once would. The
    /// request then runs with no lock held ([`BlkRequest::run`]), and
    /// [`finish`](Self::finish) completes it.
    pub(crate) fn take_request(&mut self, mem: &GuestRam) -> Option<BlkRequest> {
        let head = self.next_head(mem).filter(|_| !self.fenced);
        if head.is_none() {
            self.pass_left = 0;
            if self.owed_irq {
                // A pass that ended early still tells the driver about the
                // chains it finished.
                self.owed_irq = false;
                self.interrupt_status |= 1;
                self.sync_irq();
            }
        }
        let head = head?;
        let op = self.parse_chain(mem, head);
        Some(BlkRequest {
            head,
            epoch: self.epoch,
            file: Arc::clone(&self.file),
            op,
            last_of_pass: self.pass_left == 0,
            #[cfg(test)]
            run_hook: self.run_hook.clone(),
        })
    }

    /// Consumes the next available chain of the current pass, starting a
    /// pass when none is under way, and returns its head.
    fn next_head(&mut self, mem: &GuestRam) -> Option<u16> {
        if !self.queue.is_ready() {
            return None;
        }
        if self.pass_left == 0 {
            self.pass_left = self.queue.pending(mem)?;
        }
        if self.pass_left == 0 {
            return None;
        }
        let last = self.queue.last_avail();
        let head = mem.read_u16(self.queue.avail_slot(last)?).ok()?;
        self.queue.set_last_avail(last.wrapping_add(1));
        self.pass_left -= 1;
        Some(head)
    }

    /// Walks the descriptor chain at `head` and returns the request it
    /// holds. The first readable segment is the 16-byte header (type, _,
    /// sector); the last writable segment is the status byte; the segments
    /// between carry data.
    fn parse_chain(&self, mem: &GuestRam, head: u16) -> Op {
        // Collect readable and writable segments.
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        let mut d = head;
        // A conforming chain visits each descriptor at most once, so the ring
        // size bounds it; a cycle just runs out of budget instead of spinning.
        for _ in 0..self.queue.size() {
            let Some(da) = self.queue.desc_addr(d) else {
                break;
            };
            let (Ok(addr), Ok(len), Ok(flags), Ok(next)) = (
                mem.read_u64(da),
                mem.read_u32(da + 8),
                mem.read_u16(da + 12),
                mem.read_u16(da + 14),
            ) else {
                break;
            };
            if flags & VIRTQ_DESC_F_WRITE != 0 {
                writable.push((addr, len));
            } else {
                readable.push((addr, len));
            }
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            d = next;
        }
        let (Some(&(haddr, _)), Some(&(status, _))) = (readable.first(), writable.last()) else {
            return Op::Malformed;
        };
        let header = mem
            .read_u32(haddr)
            .and_then(|typ| Ok((typ, mem.read_u64(haddr + 8)?)))
            .map_err(other);
        let (typ, sector) = match header {
            Ok(header) => header,
            Err(error) => return Op::Refused { status, error },
        };
        let op = match typ {
            VIRTIO_BLK_T_IN => {
                // One positioned read for every data segment, scattered into
                // guest memory: one syscall per request, not one per
                // descriptor.
                writable.pop();
                Rw::new(sector, writable, status).map(Op::Read)
            }
            VIRTIO_BLK_T_OUT => {
                // The data segments gathered into one buffer, then one
                // positioned write.
                readable.remove(0);
                Rw::new(sector, readable, status).map(Op::Write)
            }
            VIRTIO_BLK_T_FLUSH => Ok(Op::Flush { status }),
            // get-id / etc.: acknowledge without data.
            _ => Ok(Op::Other {
                typ,
                sector,
                status,
            }),
        };
        op.and_then(|op| {
            if let Op::Read(rw) | Op::Write(rw) = &op {
                self.byte_range(rw.sector, rw.len as u64)?;
            }
            Ok(op)
        })
        .unwrap_or_else(|error| Op::Refused { status, error })
    }

    /// Completes `request`, which `done` says how it ran: answers the driver
    /// in the request's status byte and buffers, returns the chain on the
    /// used ring and, for the last request of a pass, raises the interrupt.
    ///
    /// The blocks a write covers are marked here, after the write, whether
    /// or not it succeeded: a move that reads the blocks while the write is
    /// in flight then finds them again in its next round. A driver that
    /// reset the queue since the request was taken gets nothing back, since
    /// its ring is gone.
    pub(crate) fn finish(&mut self, mem: &GuestRam, request: BlkRequest, done: Done) {
        if let Op::Write(rw) = &request.op {
            self.dirty.mark(rw.base(), rw.len as u64);
        }
        if matches!(done, Done::Wrote(Ok(())) | Done::Flushed(Ok(()))) {
            self.generation += 1;
        }
        if request.epoch != self.epoch {
            return;
        }
        let used = self.answer(mem, request.op, done);
        self.queue.push_used(mem, request.head, used);
        if request.last_of_pass {
            self.owed_irq = false;
            // Used-buffer notification.
            self.interrupt_status |= 1;
            self.sync_irq();
        } else {
            self.owed_irq = true;
        }
    }

    /// Writes the outcome of `op` into its status byte and, for a read, its
    /// buffers, records the request, and returns the number of
    /// device-written bytes for the used ring.
    fn answer(&mut self, mem: &GuestRam, op: Op, done: Done) -> u32 {
        // The bytes the device wrote into the chain, and what the request
        // was: its type, its sector and the data bytes it moved.
        let (status, served) = match (op, done) {
            (Op::Malformed, _) => return 0,
            (Op::Refused { status, error }, _) => (status, Err(error)),
            (Op::Read(rw), Done::Read(read)) => (
                rw.status,
                read.and_then(|buf| rw.scatter(mem, &buf))
                    .map(|written| (written, (VIRTIO_BLK_T_IN, rw.sector, rw.len as u64))),
            ),
            (Op::Write(rw), Done::Wrote(wrote)) => (
                rw.status,
                wrote.map(|()| (0, (VIRTIO_BLK_T_OUT, rw.sector, rw.len as u64))),
            ),
            (Op::Flush { status }, Done::Flushed(flushed)) => {
                (status, flushed.map(|()| (0, (VIRTIO_BLK_T_FLUSH, 0, 0))))
            }
            (
                Op::Other {
                    typ,
                    sector,
                    status,
                },
                _,
            ) => (status, Ok((0, (typ, sector, 0)))),
            (op, _) => (op.status(), Err(other("the request ran as another type"))),
        };
        let served = served.and_then(|served| {
            mem.write_u8(status, VIRTIO_BLK_S_OK).map_err(other)?;
            Ok(served)
        });
        let (written, (typ, sector, data_bytes)) = match served {
            Ok(served) => served,
            Err(e) => {
                // Always report a failure. Leaving the status byte untouched
                // let the driver read back whatever it had put there, so a
                // rejected or failed request could look like a success with
                // stale data in the buffer.
                if self.trace {
                    stderr!("\r\n[virtio-blk] request failed: {e}\r\n");
                }
                let _ = mem.write_u8(status, VIRTIO_BLK_S_IOERR);
                return 1;
            }
        };

        // Boundary capture: the guest's disk I/O, observed at the device. The
        // structured event is always recorded; the console line is opt-in
        // (HVI_BLK_TRACE) because a synchronous stderr write per request would
        // dominate the cost under a high-IOPS workload.
        if self.trace {
            let kind = match typ {
                VIRTIO_BLK_T_IN => "read ",
                VIRTIO_BLK_T_OUT => "write",
                VIRTIO_BLK_T_FLUSH => "flush",
                _ => "other",
            };
            stderr!("\r\n[virtio-blk] {kind} sector={sector} bytes={data_bytes}\r\n");
        }
        // Flush requests carry no data range — don't log them as I/O events.
        if typ == VIRTIO_BLK_T_IN || typ == VIRTIO_BLK_T_OUT {
            let write = typ == VIRTIO_BLK_T_OUT;
            self.events.push(CapturedEvent::Block {
                lba: sector,
                len: data_bytes,
                write,
            });
            // Same observation, handed to whoever is watching. A sink that
            // cannot keep up accounts for that itself: a lost record must not
            // fail the guest's I/O.
            if let Some(sink) = self.sink.as_ref() {
                sink.block(sector, data_bytes, self.disk_id, write);
            }
        }
        written + 1
    }

    /// Byte offset of `sector`, once we know the whole `len`-byte access falls
    /// inside the capacity we advertised in config space.
    ///
    /// The guest picks `sector`, so this is what keeps a request inside the
    /// disk it was given: without it a write past the end simply extended the
    /// backing file, and the multiplication wrapped in release builds.
    fn byte_range(&self, sector: u64, len: u64) -> std::io::Result<u64> {
        let base = sector
            .checked_mul(SECTOR)
            .ok_or_else(|| other("sector offset overflows"))?;
        let end = base
            .checked_add(len)
            .ok_or_else(|| other("request length overflows"))?;
        if end > self.capacity_sectors * SECTOR {
            return Err(other(format!(
                "request at sector {sector} (+{len} bytes) is past the {} sector capacity",
                self.capacity_sectors
            )));
        }
        Ok(base)
    }

    /// Writes `buf` at byte `base` as a guest write would, for a test that
    /// has no queue to post one on.
    #[cfg(test)]
    pub(crate) fn write_for_test(&mut self, base: u64, buf: &[u8]) {
        self.byte_range(base / SECTOR, buf.len() as u64).unwrap();
        self.file.write_all_at(buf, base).unwrap();
        self.dirty.mark(base, buf.len() as u64);
        self.generation += 1;
    }
}

/// A request taken off the queue, which runs without the device's lock.
///
/// [`VirtioBlk::take_request`] parses the chain under the lock,
/// [`run`](Self::run) makes the disk call with no lock held, and
/// [`VirtioBlk::finish`] completes it under the lock again.
pub(crate) struct BlkRequest {
    /// The chain's head, which the used ring returns.
    head: u16,
    /// The device's queue epoch when the chain was taken.
    epoch: u64,
    /// The disk.
    file: Arc<File>,
    /// What the chain asks for.
    op: Op,
    /// Whether this is the last request of its pass.
    last_of_pass: bool,
    /// The device's test hook.
    #[cfg(test)]
    run_hook: Option<RunHook>,
}

/// What a chain asks the device for.
enum Op {
    /// A chain without a readable or a writable segment, returned with no
    /// status.
    Malformed,
    /// A request refused before it ran, answered with an I/O error.
    Refused {
        /// The guest address of the status byte.
        status: u64,
        /// Why it was refused.
        error: std::io::Error,
    },
    /// A read into the data segments.
    Read(Rw),
    /// A write of the data segments.
    Write(Rw),
    /// A cache flush.
    Flush {
        /// The guest address of the status byte.
        status: u64,
    },
    /// Another type, such as get-id, acknowledged without data.
    Other {
        /// The request type.
        typ: u32,
        /// The sector the header names.
        sector: u64,
        /// The guest address of the status byte.
        status: u64,
    },
}

impl Op {
    /// The guest address of the status byte, or 0 for a chain without one.
    fn status(&self) -> u64 {
        match self {
            Op::Malformed => 0,
            Op::Refused { status, .. } | Op::Flush { status } | Op::Other { status, .. } => *status,
            Op::Read(rw) | Op::Write(rw) => rw.status,
        }
    }
}

/// A read or a write: the sector, and the data segments in guest RAM.
struct Rw {
    /// The first sector.
    sector: u64,
    /// The data segments, as (guest address, length).
    segs: Vec<(u64, u32)>,
    /// The bytes the segments hold.
    len: usize,
    /// The guest address of the status byte.
    status: u64,
}

impl Rw {
    /// Returns the request for `segs` at `sector`.
    ///
    /// # Errors
    ///
    /// Errors when the segments add up to more than the host can address.
    fn new(sector: u64, segs: Vec<(u64, u32)>, status: u64) -> std::io::Result<Self> {
        let len = segs
            .iter()
            .try_fold(0usize, |sum, &(_, l)| sum.checked_add(l as usize))
            .ok_or_else(|| other("request length overflows"))?;
        Ok(Rw {
            sector,
            segs,
            len,
            status,
        })
    }

    /// The byte offset of the first sector, which `parse_chain` checked.
    fn base(&self) -> u64 {
        self.sector * SECTOR
    }

    /// Copies `buf`, read from the disk, into the data segments, and returns
    /// how many bytes it wrote.
    fn scatter(&self, mem: &GuestRam, buf: &[u8]) -> std::io::Result<u32> {
        let mut o = 0;
        let mut written = 0u32;
        for &(a, l) in &self.segs {
            mem.write(a, &buf[o..o + l as usize]).map_err(other)?;
            o += l as usize;
            written = written.wrapping_add(l);
        }
        Ok(written)
    }

    /// Returns the data segments' bytes, gathered from guest RAM.
    fn gather(&self, mem: &GuestRam) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.len];
        let mut o = 0;
        for &(a, l) in &self.segs {
            mem.read(a, &mut buf[o..o + l as usize]).map_err(other)?;
            o += l as usize;
        }
        Ok(buf)
    }
}

/// How a [`BlkRequest`] ran.
pub(crate) enum Done {
    /// A read, with the bytes it read.
    Read(std::io::Result<Vec<u8>>),
    /// A write.
    Wrote(std::io::Result<()>),
    /// A flush.
    Flushed(std::io::Result<()>),
    /// A request that makes no disk call.
    Nothing,
}

impl BlkRequest {
    /// Makes the disk call the request asks for, holding no lock: a
    /// positioned read, a positioned write of the data gathered from guest
    /// RAM, or `fdatasync` for a flush.
    pub(crate) fn run(&self, mem: &GuestRam) -> Done {
        #[cfg(test)]
        if let Some(hook) = &self.run_hook {
            hook(match self.op {
                Op::Read(_) => "read",
                Op::Write(_) => "write",
                Op::Flush { .. } => "flush",
                Op::Malformed | Op::Refused { .. } | Op::Other { .. } => "other",
            });
        }
        match &self.op {
            Op::Read(rw) => {
                let mut buf = vec![0u8; rw.len];
                Done::Read(self.file.read_exact_at(&mut buf, rw.base()).map(|()| buf))
            }
            Op::Write(rw) => Done::Wrote(
                rw.gather(mem)
                    .and_then(|buf| self.file.write_all_at(&buf, rw.base())),
            ),
            // Honour the guest's cache flush (durability for fsync).
            Op::Flush { .. } => Done::Flushed(self.file.sync_data()),
            Op::Malformed | Op::Refused { .. } | Op::Other { .. } => Done::Nothing,
        }
    }
}

/// Serves `dev`'s queue on the calling thread, the device's worker, until
/// the stop. `record` takes the requests the device captured, for the
/// ledger.
///
/// The worker parks on `wake`, which every notify sets, and serves what the
/// driver made available, in order, one request at a time: a flush is
/// served only after every write before it in the queue has completed. It
/// starts with a pass, since a restored guest may have chains pending that
/// its notify announced to the process it was captured from.
///
/// Each request is taken, run and finished inside one admission of the
/// pause gate (see [`PauseGate`]). The disk call runs with no device lock
/// held, so a vCPU still reads and acknowledges the interrupt while an
/// `fdatasync` waits on a busy disk. A pause closes the gate and waits for
/// the request in flight to finish, with the vCPUs still running, and then
/// finds none in flight: no chain is ever half-served in a checkpoint, and
/// the device state stays what it was when the vCPU served the queue. The
/// pause's `gate_ms` carries that wait, and its park no longer does.
///
/// A finished request marks guest RAM's dirty log for what it wrote there,
/// and the disk's dirty blocks for a write, before the chain is on the used
/// ring, so a move that sees the completion has the pages and blocks
/// marked.
///
/// [`PauseGate`]: crate::teardown::PauseGate
pub(crate) fn serve(
    dev: &std::sync::Mutex<VirtioBlk>,
    mem: &GuestRam,
    wake: &Wake,
    stop: &StopToken,
    mut record: impl FnMut(&[CapturedEvent]),
) {
    wake.wake();
    while wake.park() {
        loop {
            let _in = stop.enter();
            // The stop opens the gate for good, so a worker held at it walks
            // through. Once it sees the stop it serves nothing more, and a
            // fenced device has nothing to take whichever comes first.
            if wake.is_stopped() {
                return;
            }
            let Some(request) = lock_or_recover(dev).take_request(mem) else {
                break;
            };
            let done = request.run(mem);
            let events = {
                let mut dev = lock_or_recover(dev);
                dev.finish(mem, request, done);
                dev.take_events()
            };
            if !events.is_empty() {
                record(&events);
            }
        }
    }
}

fn other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod backing_len_tests {
    use super::backing_len;

    /// A plain disk image still sizes from the file length.
    #[test]
    fn a_regular_file_reports_its_length() {
        let path = std::env::temp_dir().join("hvi-backing-len-test.img");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("create temp image");
        file.set_len(4 << 20).expect("size temp image");
        assert_eq!(backing_len(&file).expect("len"), 4 << 20);
        let _ = std::fs::remove_file(&path);
    }

    /// The regression: a block special file has a file length of 0, so sizing a
    /// virtio-blk from `metadata().len()` gives the guest a 0-sector disk. This
    /// needs a real block device. CI creates a loop device and names it in
    /// `HVI_BLOCK_DEV`; when the variable is set the device must be usable,
    /// because a skip there would silently drop the coverage the CI step exists
    /// to provide. Without it the test scans for one, and reports rather than
    /// fails when none is openable.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_block_device_reports_the_device_size() {
        use std::os::unix::fs::FileTypeExt;

        let picked = match std::env::var("HVI_BLOCK_DEV") {
            Ok(dev) => {
                let file = std::fs::File::open(&dev)
                    .unwrap_or_else(|e| panic!("HVI_BLOCK_DEV={dev}: {e}"));
                Some((std::path::PathBuf::from(dev), file))
            }
            Err(_) => std::fs::read_dir("/sys/block")
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    let path = std::path::Path::new("/dev").join(e.file_name());
                    let file = std::fs::File::open(&path).ok()?;
                    let is_block = file.metadata().ok()?.file_type().is_block_device();
                    is_block.then_some((path, file))
                })
                .next(),
        };
        let Some((path, file)) = picked else {
            eprintln!("skipping: no openable block device (needs root on most hosts)");
            return;
        };

        let meta_len = file.metadata().expect("metadata").len();
        let got = backing_len(&file).expect("backing_len");
        assert_eq!(meta_len, 0, "{path:?} unexpectedly has a file length");
        assert!(got > 0, "{path:?} sized as {got} bytes");
        assert_eq!(
            got % super::SECTOR,
            0,
            "{path:?} size is not sector-aligned"
        );
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;

    const BASE: u64 = 0x4000_0000;

    /// Programs a queue the way the Linux virtio-mmio driver does: size, then
    /// the three ring addresses, then READY last.
    fn program_queue(
        blk: &mut VirtioBlk,
        mem: &GuestRam,
        num: u32,
        desc: u64,
        avail: u64,
        used: u64,
    ) {
        blk.mmio(mem, mmio::QUEUE_NUM, true, u64::from(num));
        blk.mmio(mem, mmio::QUEUE_DESC_LOW, true, desc & 0xffff_ffff);
        blk.mmio(mem, mmio::QUEUE_DESC_HIGH, true, desc >> 32);
        blk.mmio(mem, mmio::QUEUE_DRIVER_LOW, true, avail & 0xffff_ffff);
        blk.mmio(mem, mmio::QUEUE_DRIVER_HIGH, true, avail >> 32);
        blk.mmio(mem, mmio::QUEUE_DEVICE_LOW, true, used & 0xffff_ffff);
        blk.mmio(mem, mmio::QUEUE_DEVICE_HIGH, true, used >> 32);
        blk.mmio(mem, mmio::QUEUE_READY, true, 1);
    }

    fn dev() -> VirtioBlk {
        VirtioBlk::open("/dev/null").unwrap()
    }

    /// Regression for the guest-triggerable panic: `0x10000` is non-zero as a
    /// `u32` and zero as a `u16`, so the old code divided by zero on notify.
    #[test]
    fn queue_num_65536_is_rejected_instead_of_panicking() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x4000)]);
        let mut blk = dev();
        program_queue(&mut blk, &mem, 0x10000, BASE, BASE + 0x1000, BASE + 0x2000);
        mem.write_u16(BASE + 0x1000 + 2, 1).unwrap(); // avail.idx = 1

        assert_eq!(blk.mmio(&mem, mmio::QUEUE_READY, false, 0), 0, "not ready");
        blk.mmio(&mem, mmio::QUEUE_NOTIFY, true, 0); // must not panic
        blk.serve_now(&mem);
        assert_eq!(blk.queue.size(), 0, "the size was refused");
    }

    /// The rings must fit in guest RAM before we will service the queue, so a
    /// driver cannot point them at unbacked addresses.
    #[test]
    fn queue_rejects_rings_outside_guest_ram() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x4000)]);
        let mut blk = dev();

        // desc table for 256 entries is 4 KiB, so this one runs off the end.
        program_queue(
            &mut blk,
            &mem,
            256,
            BASE + 0x3800,
            BASE + 0x1000,
            BASE + 0x2000,
        );
        assert_eq!(blk.mmio(&mem, mmio::QUEUE_READY, false, 0), 0);

        // Below the RAM base is refused too.
        program_queue(
            &mut blk,
            &mem,
            256,
            BASE - 0x1000,
            BASE + 0x1000,
            BASE + 0x2000,
        );
        assert_eq!(blk.mmio(&mem, mmio::QUEUE_READY, false, 0), 0);

        // The same size, in bounds, is accepted.
        program_queue(&mut blk, &mem, 256, BASE, BASE + 0x1000, BASE + 0x2000);
        assert_eq!(blk.mmio(&mem, mmio::QUEUE_READY, false, 0), 1);
    }

    /// A driver that has validated its rings must not be able to move them and
    /// keep the queue live. Every setter that feeds `rings_fit` drops `ready`,
    /// so the bounds are re-checked before the device services anything; this
    /// pins that, because otherwise a guest could pass the check on one set of
    /// addresses and then be serviced on another.
    #[test]
    fn re_programming_a_ready_queue_clears_ready() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x4000)]);

        // Each value is deliberately a legal one, and for QUEUE_NUM a
        // non-zero one: `is_ready` is false whenever the size is zero, so
        // writing 0 there would pass this test without `ready` ever being
        // cleared. What has to drop the queue is the write itself.
        for (r, v) in [
            (mmio::QUEUE_NUM, 128),
            (mmio::QUEUE_DESC_LOW, 0),
            (mmio::QUEUE_DESC_HIGH, 0),
            (mmio::QUEUE_DRIVER_LOW, 0),
            (mmio::QUEUE_DRIVER_HIGH, 0),
            (mmio::QUEUE_DEVICE_LOW, 0),
            (mmio::QUEUE_DEVICE_HIGH, 0),
        ] {
            let mut blk = dev();
            program_queue(&mut blk, &mem, 256, BASE, BASE + 0x1000, BASE + 0x2000);
            assert_eq!(blk.mmio(&mem, mmio::QUEUE_READY, false, 0), 1);

            blk.mmio(&mem, r, true, v);
            assert_eq!(
                blk.mmio(&mem, mmio::QUEUE_READY, false, 0),
                0,
                "writing {r:#05x} left the queue ready"
            );
        }
    }

    /// A chain that points back at itself must run out of budget rather than
    /// spin. The only bound on the walk is the ring size, so the shape to
    /// test is a cycle of *writable* descriptors: nothing accumulates, so
    /// no other limit can end it.
    #[test]
    fn a_descriptor_cycle_runs_out_of_budget() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x4000)]);
        let mut blk = dev();
        program_queue(&mut blk, &mem, 4, BASE, BASE + 0x1000, BASE + 0x2000);

        // desc[0] -> desc[0]: a one-hop cycle, writable and F_NEXT set.
        mem.write_u64(BASE, BASE + 0x3000).unwrap();
        mem.write_u32(BASE + 8, 16).unwrap();
        mem.write_u16(BASE + 12, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT)
            .unwrap();
        mem.write_u16(BASE + 14, 0).unwrap();

        // Terminating at all is the property. Nothing readable came out of the
        // walk, so there is no request to serve either.
        assert!(matches!(blk.parse_chain(&mem, 0), Op::Malformed));
    }

    /// A `next` that leaves the ring ends the walk, rather than reading a
    /// descriptor the driver never programmed.
    ///
    /// The descriptor one past the ring is deliberately a valid, writable one
    /// here. Without the bound the walk would find it, `writable` would be
    /// non-empty and the request would be serviced -- so this fails loudly
    /// rather than passing on an empty walk.
    #[test]
    fn a_next_index_outside_the_ring_ends_the_walk() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x4000)]);
        let mut blk = dev();
        program_queue(&mut blk, &mem, 4, BASE, BASE + 0x1000, BASE + 0x2000);

        // desc[0]: readable, chaining to index 4 -- one past a 4-entry ring.
        mem.write_u64(BASE, BASE + 0x3000).unwrap();
        mem.write_u32(BASE + 8, 16).unwrap();
        mem.write_u16(BASE + 12, VIRTQ_DESC_F_NEXT).unwrap();
        mem.write_u16(BASE + 14, 4).unwrap();

        // "desc[4]": in guest RAM, outside the ring, and writable, so it is
        // exactly what an unbounded walk would pick up.
        mem.write_u64(BASE + 64, BASE + 0x3100).unwrap();
        mem.write_u32(BASE + 72, 16).unwrap();
        mem.write_u16(BASE + 76, VIRTQ_DESC_F_WRITE).unwrap();
        mem.write_u16(BASE + 78, 0).unwrap();

        assert!(
            matches!(blk.parse_chain(&mem, 0), Op::Malformed),
            "the walk stopped at the ring"
        );
        assert!(
            matches!(blk.parse_chain(&mem, 4), Op::Malformed),
            "an out-of-ring head as well"
        );
        assert!(matches!(blk.parse_chain(&mem, u16::MAX), Op::Malformed));
    }

    /// The happy path still works: a conforming driver's read request is
    /// serviced, the data lands in guest RAM and the status byte is written.
    #[test]
    fn conforming_queue_still_services_a_request() {
        let path = std::env::temp_dir().join(format!("hvi-q-{}.img", std::process::id()));
        let mut disk = vec![0u8; 1024];
        disk[..5].copy_from_slice(b"HELLO");
        std::fs::write(&path, &disk).unwrap();
        let mut blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();

        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let (desc, avail, used) = (BASE, BASE + 0x2000, BASE + 0x3000);
        let buffers = BASE + 0x4000;
        publish_read(&mem, desc, avail, buffers);
        let data = buffers + 0x100;

        program_queue(&mut blk, &mem, 8, desc, avail, used);
        assert_eq!(blk.mmio(&mem, mmio::QUEUE_READY, false, 0), 1, "ready");
        blk.mmio(&mem, mmio::QUEUE_NOTIFY, true, 0);
        blk.serve_now(&mem);
        let _ = std::fs::remove_file(&path);

        let mut got = [0u8; 5];
        mem.read(data, &mut got).unwrap();
        assert_eq!(&got, b"HELLO", "the sector reached guest memory");
        assert_eq!(mem.read_u16(used + 2).unwrap(), 1, "used.idx advanced");
        assert!(blk.irq_level(), "used-buffer interrupt asserted");
    }

    /// Publishes one read of sector 0 on `avail`, as the next entry of an
    /// 8-entry ring at `desc`.
    ///
    /// The request header is at `buffers`, the data at `buffers + 0x100` and
    /// the status byte at `buffers + 0x400`, poisoned to `0xff` so an untouched
    /// byte is visible.
    fn publish_read(mem: &GuestRam, desc: u64, avail: u64, buffers: u64) {
        let (hdr, data, status) = (buffers, buffers + 0x100, buffers + 0x400);
        mem.write_u32(hdr, VIRTIO_BLK_T_IN).unwrap();
        mem.write_u64(hdr + 8, 0).unwrap();
        mem.write_u8(status, 0xff).unwrap();
        let write_descriptor = |i: u64, addr: u64, len: u32, flags: u16, next: u16| {
            mem.write_u64(desc + i * 16, addr).unwrap();
            mem.write_u32(desc + i * 16 + 8, len).unwrap();
            mem.write_u16(desc + i * 16 + 12, flags).unwrap();
            mem.write_u16(desc + i * 16 + 14, next).unwrap();
        };
        write_descriptor(0, hdr, 16, VIRTQ_DESC_F_NEXT, 1);
        write_descriptor(1, data, 512, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
        write_descriptor(2, status, 1, VIRTQ_DESC_F_WRITE, 0);
        let avail_idx = mem.read_u16(avail + 2).unwrap();
        mem.write_u16(avail + 4 + u64::from(avail_idx % 8) * 2, 0)
            .unwrap();
        mem.write_u16(avail + 2, avail_idx.wrapping_add(1)).unwrap();
    }

    // The re-programmed queue sits at fresh ring pages with `avail.idx` back
    // at 0.
    #[test]
    fn status_reset_lets_the_re_programmed_queue_service_a_request() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = dev();

        program_queue(&mut blk, &mem, 8, BASE, BASE + 0x1000, BASE + 0x2000);
        publish_read(&mem, BASE, BASE + 0x1000, BASE + 0x6000);
        blk.mmio(&mem, mmio::QUEUE_NOTIFY, true, 0);
        blk.serve_now(&mem);
        assert_eq!(
            mem.read_u16(BASE + 0x2000 + 2).unwrap(),
            1,
            "used.idx before the reset"
        );

        blk.mmio(&mem, mmio::STATUS, true, 0);
        program_queue(
            &mut blk,
            &mem,
            8,
            BASE + 0x3000,
            BASE + 0x4000,
            BASE + 0x5000,
        );
        publish_read(&mem, BASE + 0x3000, BASE + 0x4000, BASE + 0x7000);
        blk.mmio(&mem, mmio::QUEUE_NOTIFY, true, 0);
        blk.serve_now(&mem);
        assert_eq!(
            mem.read_u16(BASE + 0x5000 + 2).unwrap(),
            1,
            "the request published after the reset was serviced"
        );
        // `dev()` backs the disk with `/dev/null`, so the read fails with
        // IOERR. A written status byte shows the chain was walked.
        assert_eq!(
            mem.read_u16(BASE + 0x7000 + 0x400).unwrap() as u8,
            VIRTIO_BLK_S_IOERR
        );
    }

    // Linux `vm_setup_vq` refuses a queue whose QUEUE_READY reads non-zero, so
    // a stale bit fails the probe that follows a reset.
    #[test]
    fn status_reset_clears_queue_ready() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = dev();
        program_queue(&mut blk, &mem, 8, BASE, BASE + 0x1000, BASE + 0x2000);
        assert_eq!(blk.mmio(&mem, mmio::QUEUE_READY, false, 0), 1);

        blk.mmio(&mem, mmio::STATUS, true, 0);
        assert_eq!(blk.mmio(&mem, mmio::QUEUE_READY, false, 0), 0);
        assert_eq!(blk.mmio(&mem, mmio::STATUS, false, 0), 0);
    }

    #[test]
    fn status_reset_selects_the_first_feature_page() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = dev();
        blk.mmio(&mem, mmio::DEVICE_FEATURES_SEL, true, 1);
        assert_eq!(
            blk.mmio(&mem, mmio::DEVICE_FEATURES, false, 0),
            u64::from(F_VERSION_1_HI)
        );

        blk.mmio(&mem, mmio::STATUS, true, 0);
        assert_eq!(
            blk.mmio(&mem, mmio::DEVICE_FEATURES, false, 0),
            u64::from(F_BLK_FLUSH_LO)
        );
    }

    #[test]
    fn features_are_the_two_pages_the_window_offers() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = dev();
        let mut page = |sel| {
            blk.mmio(&mem, mmio::DEVICE_FEATURES_SEL, true, sel);
            blk.mmio(&mem, mmio::DEVICE_FEATURES, false, 0)
        };
        assert_eq!((page(1) << 32) | page(0), VirtioBlk::FEATURES);
    }

    #[test]
    fn status_reset_clears_the_pending_interrupt() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = dev();
        program_queue(&mut blk, &mem, 8, BASE, BASE + 0x1000, BASE + 0x2000);
        publish_read(&mem, BASE, BASE + 0x1000, BASE + 0x6000);
        blk.mmio(&mem, mmio::QUEUE_NOTIFY, true, 0);
        blk.serve_now(&mem);
        assert!(blk.irq_level());

        blk.mmio(&mem, mmio::STATUS, true, 0);
        assert!(!blk.irq_level());
        assert_eq!(blk.mmio(&mem, mmio::INTERRUPT_STATUS, false, 0), 0);
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    const BASE: u64 = 0x4000_0000;

    struct Rig {
        path: std::path::PathBuf,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// A 1-sector disk and a queue programmed the way Linux does it.
    fn rig(tag: &str) -> (Rig, VirtioBlk) {
        let path = std::env::temp_dir().join(format!("hvi-cap-{tag}-{}.img", std::process::id()));
        std::fs::write(&path, [0xabu8; 512]).unwrap();
        let blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();
        (Rig { path }, blk)
    }

    /// Submits one request and returns the status byte the device wrote.
    fn submit(blk: &mut VirtioBlk, mem: &GuestRam, typ: u32, sector: u64, len: u32) -> u8 {
        let (desc, avail, used) = (BASE, BASE + 0x2000, BASE + 0x3000);
        let (hdr, data, status) = (BASE + 0x4000, BASE + 0x5000, BASE + 0x6000);
        mem.write_u32(hdr, typ).unwrap();
        mem.write_u64(hdr + 8, sector).unwrap();
        // poison, so "untouched" is visible
        mem.write_u8(status, 0xff).unwrap();

        let write_flag = if typ == VIRTIO_BLK_T_IN {
            VIRTQ_DESC_F_WRITE
        } else {
            0
        };
        let d = |i: u64, addr: u64, len: u32, flags: u16, next: u16| {
            mem.write_u64(desc + i * 16, addr).unwrap();
            mem.write_u32(desc + i * 16 + 8, len).unwrap();
            mem.write_u16(desc + i * 16 + 12, flags).unwrap();
            mem.write_u16(desc + i * 16 + 14, next).unwrap();
        };
        d(0, hdr, 16, VIRTQ_DESC_F_NEXT, 1);
        d(1, data, len, VIRTQ_DESC_F_NEXT | write_flag, 2);
        d(2, status, 1, VIRTQ_DESC_F_WRITE, 0);

        let idx = mem.read_u16(avail + 2).unwrap();
        mem.write_u16(avail + 4 + u64::from(idx % 256) * 2, 0)
            .unwrap();
        mem.write_u16(avail + 2, idx.wrapping_add(1)).unwrap();

        blk.mmio(mem, mmio::QUEUE_NUM, true, 256);
        blk.mmio(mem, mmio::QUEUE_DESC_LOW, true, desc & 0xffff_ffff);
        blk.mmio(mem, mmio::QUEUE_DESC_HIGH, true, desc >> 32);
        blk.mmio(mem, mmio::QUEUE_DRIVER_LOW, true, avail & 0xffff_ffff);
        blk.mmio(mem, mmio::QUEUE_DRIVER_HIGH, true, avail >> 32);
        blk.mmio(mem, mmio::QUEUE_DEVICE_LOW, true, used & 0xffff_ffff);
        blk.mmio(mem, mmio::QUEUE_DEVICE_HIGH, true, used >> 32);
        blk.mmio(mem, mmio::QUEUE_READY, true, 1);
        blk.mmio(mem, mmio::QUEUE_NOTIFY, true, 0);
        blk.serve_now(mem);
        mem.read_u16(status).unwrap() as u8
    }

    /// Regression for the guest writing outside the disk it was advertised.
    #[test]
    fn write_past_the_advertised_capacity_is_refused() {
        let (r, mut blk) = rig("out");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        assert_eq!(blk.capacity_sectors, 1);

        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, 131_072, 16);
        assert_eq!(
            st, VIRTIO_BLK_S_IOERR,
            "the guest is told the request failed"
        );
        assert_eq!(
            std::fs::metadata(&r.path).unwrap().len(),
            512,
            "the backing file was not extended"
        );
    }

    #[test]
    fn read_past_the_advertised_capacity_is_refused() {
        let (_r, mut blk) = rig("in");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_IN, 9_999, 512);
        assert_eq!(st, VIRTIO_BLK_S_IOERR);
    }

    /// A sector that would wrap the byte offset is refused rather than aliased
    /// back into the file (release builds used to wrap silently).
    #[test]
    fn sector_offset_overflow_is_refused() {
        let (r, mut blk) = rig("ovf");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, u64::MAX / 256, 16);
        assert_eq!(st, VIRTIO_BLK_S_IOERR);
        assert_eq!(std::fs::metadata(&r.path).unwrap().len(), 512);
    }

    // A checkpoint compares the counter across captures to tell whether the
    // disk changed, so a read or a refused write must not move it.
    #[test]
    fn writes_and_flushes_advance_the_generation() {
        let (_r, mut blk) = rig("gen");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        assert_eq!(blk.generation(), 0);
        assert_eq!(blk.size_bytes(), 512);
        assert_eq!(
            submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, 0, 16),
            VIRTIO_BLK_S_OK
        );
        assert_eq!(
            submit(&mut blk, &mem, VIRTIO_BLK_T_IN, 0, 16),
            VIRTIO_BLK_S_OK
        );
        assert_eq!(blk.generation(), 1);
        assert_eq!(
            submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, 131_072, 16),
            VIRTIO_BLK_S_IOERR
        );
        assert_eq!(blk.generation(), 1);
        assert_eq!(
            submit(&mut blk, &mem, VIRTIO_BLK_T_FLUSH, 0, 16),
            VIRTIO_BLK_S_OK
        );
        assert_eq!(blk.generation(), 2);
        blk.sync_data().unwrap();
    }

    /// The last sector inside the capacity still works, so the bound is not
    /// off by one.
    #[test]
    fn a_request_inside_the_capacity_still_succeeds() {
        let (_r, mut blk) = rig("ok");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_IN, 0, 512);
        assert_eq!(st, VIRTIO_BLK_S_OK, "sector 0 of a 1-sector disk is valid");
        let mut got = [0u8; 4];
        mem.read(BASE + 0x5000, &mut got).unwrap();
        assert_eq!(&got, &[0xab; 4], "the sector reached guest memory");
    }

    /// The bound is on the bytes actually transferred, so it is exact at the
    /// end of the disk in both directions.
    #[test]
    fn byte_range_bounds_are_exact() {
        let (_r, blk) = rig("rng");
        // 1 sector = 512 bytes of capacity.
        assert_eq!(blk.byte_range(0, 512).unwrap(), 0, "the whole disk is fine");
        assert!(blk.byte_range(0, 513).is_err(), "one byte past is not");
        assert!(blk.byte_range(1, 1).is_err(), "nor is one byte at sector 1");
        // A zero-length request touches nothing, so the end offset is allowed;
        // this matches Firecracker's `sector + num_sectors > capacity` check.
        assert_eq!(blk.byte_range(1, 0).unwrap(), 512);
        assert!(blk.byte_range(u64::MAX, 1).is_err(), "overflow is refused");
        assert!(blk.byte_range(u64::MAX / 256, 16).is_err());
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;
    use crate::devices::irq::test_line::LevelLine;

    const BASE: u64 = 0x4000_0000;
    const DESC: u64 = BASE;
    const AVAIL: u64 = BASE + 0x1000;
    const USED: u64 = BASE + 0x2000;

    /// A disk image of `sectors` sectors, removed on drop.
    struct Disk {
        path: std::path::PathBuf,
    }

    impl Disk {
        fn new(tag: &str, sectors: usize) -> Disk {
            let path = std::env::temp_dir()
                .join(format!("hvi-blk-state-{tag}-{}.img", std::process::id()));
            std::fs::write(&path, vec![0x5au8; sectors * 512]).unwrap();
            Disk { path }
        }

        fn path(&self) -> &str {
            self.path.to_str().unwrap()
        }
    }

    impl Drop for Disk {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Programs the queue as a driver does and has it serve one read of
    /// sector 0, so the state holds a consumed chain and a pending interrupt.
    fn served_one_read(blk: &mut VirtioBlk, mem: &GuestRam) {
        blk.mmio(mem, mmio::STATUS, true, 0xf);
        blk.mmio(mem, mmio::DEVICE_FEATURES_SEL, true, 1);
        blk.mmio(mem, mmio::QUEUE_NUM, true, 8);
        blk.mmio(mem, mmio::QUEUE_DESC_LOW, true, DESC);
        blk.mmio(mem, mmio::QUEUE_DRIVER_LOW, true, AVAIL);
        blk.mmio(mem, mmio::QUEUE_DEVICE_LOW, true, USED);
        blk.mmio(mem, mmio::QUEUE_READY, true, 1);
        post_read(mem, 0);
        blk.mmio(mem, mmio::QUEUE_NOTIFY, true, 0);
        blk.serve_now(mem);
    }

    /// Posts a read of sector 0 as avail entry `idx`, on descriptors 0-2.
    fn post_read(mem: &GuestRam, idx: u16) {
        let (hdr, data, status) = (BASE + 0x4000, BASE + 0x5000, BASE + 0x6000);
        mem.write_u32(hdr, VIRTIO_BLK_T_IN).unwrap();
        mem.write_u64(hdr + 8, 0).unwrap();
        mem.write_u8(status, 0xff).unwrap();
        let d = |i: u64, addr: u64, len: u32, flags: u16| {
            mem.write_u64(DESC + i * 16, addr).unwrap();
            mem.write_u32(DESC + i * 16 + 8, len).unwrap();
            mem.write_u16(DESC + i * 16 + 12, flags).unwrap();
            mem.write_u16(DESC + i * 16 + 14, (i + 1) as u16).unwrap();
        };
        d(0, hdr, 16, VIRTQ_DESC_F_NEXT);
        d(1, data, 512, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
        d(2, status, 1, VIRTQ_DESC_F_WRITE);
        mem.write_u16(AVAIL + 4 + u64::from(idx % 8) * 2, 0)
            .unwrap();
        mem.write_u16(AVAIL + 2, idx.wrapping_add(1)).unwrap();
    }

    #[test]
    fn state_round_trips_through_json_and_a_restored_device() {
        let disk = Disk::new("rt", 2);
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = VirtioBlk::open(disk.path()).unwrap();
        served_one_read(&mut blk, &mem);
        let state = blk.state();
        assert_eq!(state.common.interrupt_status, 1);
        assert_eq!(state.queue.last_avail, 1);
        assert_eq!(state.capacity_sectors, 2);

        let json = serde_json::to_vec(&state).unwrap();
        let back: BlkState = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, state);
        // As a fenced source does, so the restore can take the disk.
        assert!(blk.release_lock());
        let mut restored = VirtioBlk::restore(disk.path(), &mem, &back, 1046, None).unwrap();
        assert_eq!(restored.state(), state);

        // The restored device carries on where the first left off: the next
        // chain is the one after the consumed one, and its read succeeds.
        restored.mmio(&mem, mmio::INTERRUPT_ACK, true, 1);
        post_read(&mem, 1);
        restored.mmio(&mem, mmio::QUEUE_NOTIFY, true, 0);
        restored.serve_now(&mem);
        assert_eq!(mem.read_u16(USED + 2).unwrap(), 2, "two chains used");
        assert_eq!(mem.read_u16(BASE + 0x6000).unwrap() as u8, VIRTIO_BLK_S_OK);
        assert_eq!(restored.state().queue.last_avail, 2);

        // Its generation goes on from the checkpoint's: a read leaves it,
        // and a flush moves it on by one.
        assert_eq!(restored.generation(), 1046);
        post_read(&mem, 2);
        mem.write_u32(BASE + 0x4000, VIRTIO_BLK_T_FLUSH).unwrap();
        restored.mmio(&mem, mmio::QUEUE_NOTIFY, true, 0);
        restored.serve_now(&mem);
        assert_eq!(mem.read_u16(USED + 2).unwrap(), 3, "three chains used");
        assert_eq!(restored.generation(), 1047);
    }

    /// A restored device with an interrupt the driver had not acknowledged
    /// asserts its line once the line is connected, and one with nothing
    /// pending leaves the line alone.
    #[test]
    fn connecting_a_restored_device_drives_its_line_from_the_interrupt_status() {
        let disk = Disk::new("irq", 2);
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = VirtioBlk::open(disk.path()).unwrap();
        served_one_read(&mut blk, &mem);
        let pending = blk.state();
        drop(blk);

        let mut restored = VirtioBlk::restore(disk.path(), &mem, &pending, 0, None).unwrap();
        let line = Arc::new(LevelLine::default());
        restored.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
        assert!(line.is_high(), "the pending interrupt is asserted");
        assert_eq!(line.raises(), 1);

        let quiet = BlkState {
            common: VirtioCommonState {
                interrupt_status: 0,
                ..pending.common.clone()
            },
            ..pending
        };
        drop(restored);
        let mut restored = VirtioBlk::restore(disk.path(), &mem, &quiet, 0, None).unwrap();
        let line = Arc::new(LevelLine::default());
        restored.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
        assert_eq!(line.sets(), 0, "a line with nothing pending is not set");
    }

    /// Two guests writing one image corrupt it, so a disk one device has
    /// open is refused to a second until the first releases its lock or
    /// goes, and a device that is not a disk is not locked at all.
    #[test]
    fn a_disk_is_the_disk_of_one_device_at_a_time() {
        let disk = Disk::new("lock", 2);
        let mut first = VirtioBlk::open(disk.path()).unwrap();
        let err = VirtioBlk::open(disk.path())
            .err()
            .expect("a second device opened a locked disk");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        assert!(
            err.to_string().contains("is locked by another process"),
            "{err}"
        );
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let err = VirtioBlk::restore(disk.path(), &mem, &first.state(), 0, None)
            .err()
            .expect("a restore opened a locked disk");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);

        assert!(first.release_lock());
        assert!(!first.release_lock(), "the lock was released twice");
        let second = VirtioBlk::open(disk.path()).unwrap();
        assert!(VirtioBlk::open(disk.path()).is_err());
        drop(second);
        let _third = VirtioBlk::open(disk.path()).unwrap();

        let _a = VirtioBlk::open("/dev/null").unwrap();
        let _b = VirtioBlk::open("/dev/null").unwrap();
    }

    #[test]
    fn a_disk_of_another_size_is_refused() {
        let disk = Disk::new("cap", 2);
        let other = Disk::new("cap-other", 3);
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = VirtioBlk::open(disk.path()).unwrap();
        served_one_read(&mut blk, &mem);
        let err = VirtioBlk::restore(other.path(), &mem, &blk.state(), 0, None)
            .err()
            .expect("a 3-sector disk is not the 2-sector one the guest has");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("holds 3 sectors"), "{err}");
    }

    #[test]
    fn a_queue_outside_the_restored_ram_is_refused() {
        let disk = Disk::new("ram", 2);
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = VirtioBlk::open(disk.path()).unwrap();
        served_one_read(&mut blk, &mem);
        let smaller = GuestRam::from_ranges(&[(BASE, 0x2000)]);
        let err = VirtioBlk::restore(disk.path(), &smaller, &blk.state(), 0, None).err();
        assert_eq!(err.map(|e| e.kind()), Some(std::io::ErrorKind::InvalidData));
    }

    #[test]
    fn state_this_device_never_holds_is_refused() {
        let disk = Disk::new("bad", 2);
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let good = VirtioBlk::open(disk.path()).unwrap().state();
        let bad = [
            BlkState {
                version: 2,
                ..good.clone()
            },
            BlkState {
                common: VirtioCommonState {
                    queue_sel: 1,
                    ..good.common.clone()
                },
                ..good.clone()
            },
            BlkState {
                common: VirtioCommonState {
                    interrupt_status: 2,
                    ..good.common.clone()
                },
                ..good.clone()
            },
        ];
        for state in bad {
            let err = VirtioBlk::restore(disk.path(), &mem, &state, 0, None).err();
            assert_eq!(
                err.map(|e| e.kind()),
                Some(std::io::ErrorKind::InvalidData),
                "{state:?}"
            );
        }
    }
}

#[cfg(test)]
mod dirty_tests {
    use super::*;

    const BASE: u64 = 0x4000_0000;
    /// Three whole blocks and one sector: the last block is short.
    const SIZE: u64 = 3 * DIRTY_BLOCK_BYTES + 512;
    /// virtio-blk `VIRTIO_BLK_T_DISCARD`, which the device does not offer.
    const T_DISCARD: u32 = 11;

    /// A disk of [`SIZE`] bytes, each byte its offset's low byte, removed on
    /// drop.
    struct Disk(std::path::PathBuf);

    impl Disk {
        fn new(tag: &str) -> Disk {
            let path = std::env::temp_dir()
                .join(format!("hvi-blk-dirty-{tag}-{}.img", std::process::id()));
            let bytes: Vec<u8> = (0..SIZE).map(|i| i as u8).collect();
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

    /// Submits one request of `typ` at `sector` with 16 bytes of 0xee and
    /// returns the status byte.
    fn submit(blk: &mut VirtioBlk, mem: &GuestRam, typ: u32, sector: u64) -> u8 {
        let (desc, avail, used) = (BASE, BASE + 0x2000, BASE + 0x3000);
        let (hdr, data, status) = (BASE + 0x4000, BASE + 0x5000, BASE + 0x6000);
        mem.write_u32(hdr, typ).unwrap();
        mem.write_u64(hdr + 8, sector).unwrap();
        mem.write(data, &[0xee; 16]).unwrap();
        mem.write_u8(status, 0xff).unwrap();
        let data_flag = if typ == VIRTIO_BLK_T_IN {
            VIRTQ_DESC_F_WRITE
        } else {
            0
        };
        for (i, (addr, len, flags)) in [
            (hdr, 16, VIRTQ_DESC_F_NEXT),
            (data, 16, VIRTQ_DESC_F_NEXT | data_flag),
            (status, 1, VIRTQ_DESC_F_WRITE),
        ]
        .into_iter()
        .enumerate()
        {
            let d = desc + i as u64 * 16;
            mem.write_u64(d, addr).unwrap();
            mem.write_u32(d + 8, len).unwrap();
            mem.write_u16(d + 12, flags).unwrap();
            mem.write_u16(d + 14, i as u16 + 1).unwrap();
        }
        let idx = mem.read_u16(avail + 2).unwrap();
        mem.write_u16(avail + 4 + u64::from(idx % 8) * 2, 0)
            .unwrap();
        mem.write_u16(avail + 2, idx.wrapping_add(1)).unwrap();
        if !blk.queue.is_ready() {
            blk.mmio(mem, mmio::QUEUE_NUM, true, 8);
            blk.mmio(mem, mmio::QUEUE_DESC_LOW, true, desc);
            blk.mmio(mem, mmio::QUEUE_DRIVER_LOW, true, avail);
            blk.mmio(mem, mmio::QUEUE_DEVICE_LOW, true, used);
            blk.mmio(mem, mmio::QUEUE_READY, true, 1);
        }
        blk.mmio(mem, mmio::QUEUE_NOTIFY, true, 0);
        blk.serve_now(mem);
        mem.read_u16(status).unwrap() as u8
    }

    fn set(dirty: &DirtyBlocks) -> Vec<u64> {
        dirty.iter().collect()
    }

    /// The first sector of block `block`.
    fn sector(block: u64) -> u64 {
        block * DIRTY_BLOCK_BYTES / SECTOR
    }

    // Bit i is bit i % 8 of byte i / 8, as in ram.map: hull decodes both
    // with one function.
    #[test]
    fn the_bitmap_marks_every_block_a_range_touches_in_ram_map_order() {
        let mut d = DirtyBlocks::for_size(20 * DIRTY_BLOCK_BYTES - 1);
        assert_eq!(d.blocks(), 20);
        assert_eq!(d.as_bytes().len(), 3);
        d.mark(9 * DIRTY_BLOCK_BYTES, 1);
        assert_eq!(d.as_bytes(), &[0, 0b10, 0]);
        d.mark(DIRTY_BLOCK_BYTES - 1, 2);
        assert_eq!(set(&d), [0, 1, 9]);
        d.mark(5 * DIRTY_BLOCK_BYTES, 0);
        assert_eq!(d.count(), 3);
        // A range that runs past the disk marks up to its last block, and
        // one that starts past it marks nothing.
        d.mark(19 * DIRTY_BLOCK_BYTES, 4 * DIRTY_BLOCK_BYTES);
        d.mark(40 * DIRTY_BLOCK_BYTES, 1);
        d.mark(u64::MAX - 1, 10);
        assert_eq!(set(&d), [0, 1, 9, 19]);
        assert!(d.is_set(19) && !d.is_set(20) && !d.is_set(u64::MAX));
    }

    #[test]
    fn a_bitmap_of_another_disk_is_refused() {
        let ok = DirtyBlocks::from_bytes(vec![0b1000_0001, 0b0000_0100], 11 * DIRTY_BLOCK_BYTES)
            .unwrap();
        assert_eq!(set(&ok), [0, 7, 10]);
        let short = DirtyBlocks::from_bytes(vec![0], 11 * DIRTY_BLOCK_BYTES).unwrap_err();
        assert!(short.to_string().contains("is 1 bytes"), "{short}");
        let past =
            DirtyBlocks::from_bytes(vec![0, 0b0000_1000], 11 * DIRTY_BLOCK_BYTES).unwrap_err();
        assert!(past.to_string().contains("past the 11 blocks"), "{past}");
        assert!(DirtyBlocks::from_bytes(Vec::new(), 0).is_ok());
    }

    // Only a write changes the disk. A read, a flush, a refused write and a
    // discard the device never offered leave both bitmaps alone; the flush
    // still moves the generation.
    #[test]
    fn writes_mark_the_bitmaps_and_nothing_else_does() {
        let disk = Disk::new("marks");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = VirtioBlk::open(disk.path()).unwrap();
        assert_eq!(blk.dirty_since_boot().blocks(), 4);

        assert_eq!(submit(&mut blk, &mem, VIRTIO_BLK_T_IN, sector(1)), 0);
        assert_eq!(submit(&mut blk, &mem, VIRTIO_BLK_T_FLUSH, 0), 0);
        assert_eq!(blk.generation(), 1);
        assert_eq!(blk.dirty_since_boot().count(), 0);
        assert_eq!(
            submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, SIZE / SECTOR),
            VIRTIO_BLK_S_IOERR
        );
        let before = std::fs::read(disk.path()).unwrap();
        assert_eq!(submit(&mut blk, &mem, T_DISCARD, sector(2)), 0);
        assert_eq!(std::fs::read(disk.path()).unwrap(), before);
        assert_eq!(blk.dirty_since_boot().count(), 0);

        // The last sector of block 0 and the short last block.
        assert_eq!(submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, sector(1) - 1), 0);
        assert_eq!(submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, sector(3)), 0);
        assert_eq!(set(blk.dirty_since_boot()), [0, 3]);
        assert_eq!(blk.generation(), 3);

        // A reset, as a guest reboot makes, keeps the disk and the bitmaps.
        blk.mmio(&mem, mmio::STATUS, true, 0);
        assert_eq!(set(blk.dirty_since_boot()), [0, 3]);
        assert_eq!(
            set(&blk.read_dirty(DirtySince::Boot).unwrap().dirty),
            [0, 3]
        );
    }

    // Round 0 is every block since boot; each later round is what was
    // written since the read before, which the read clears.
    #[test]
    fn each_round_holds_the_writes_since_the_read_before() {
        let disk = Disk::new("rounds");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = VirtioBlk::open(disk.path()).unwrap();
        let err = blk.read_dirty(DirtySince::Round).unwrap_err();
        assert!(err.to_string().contains("no round 0"), "{err}");
        assert!(blk.rounds().is_empty());

        submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, sector(2));
        let r0 = blk.read_dirty(DirtySince::Boot).unwrap();
        assert_eq!((r0.round, r0.generation, set(&r0.dirty)), (0, 1, vec![2]));

        submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, sector(1));
        submit(&mut blk, &mem, VIRTIO_BLK_T_FLUSH, 0);
        let r1 = blk.read_dirty(DirtySince::Round).unwrap();
        assert_eq!((r1.round, r1.generation, set(&r1.dirty)), (1, 3, vec![1]));
        assert_eq!(
            blk.last_round().map(|(n, d)| (n, set(d))),
            Some((1, vec![1]))
        );

        let r2 = blk.read_dirty(DirtySince::Round).unwrap();
        assert_eq!((r2.round, r2.dirty.count()), (2, 0));
        assert_eq!(set(blk.dirty_since_boot()), [1, 2]);
        let listed: Vec<(u32, u64, u64)> = blk
            .rounds()
            .iter()
            .map(|r| (r.round, r.generation, r.blocks))
            .collect();
        assert_eq!(listed, [(0, 1, 1), (1, 3, 1), (2, 3, 0)]);
        // Each round records its bitmap's digest, and is sent once a
        // disk-blocks of it says so, only while it is the last round.
        for (listed, read) in blk.rounds().iter().zip([&r0, &r1, &r2]) {
            let want = hex(&Sha256::digest(read.dirty.as_bytes()));
            assert_eq!(read.bitmap_sha256, want);
            assert_eq!(listed.bitmap_sha256.as_ref(), Some(&want));
            assert_eq!(listed.sent_sha256, None);
        }
        assert!(!blk.record_sent(1, "11".repeat(32)));
        assert!(blk.record_sent(2, "22".repeat(32)));
        assert_eq!(blk.rounds()[2].sent_sha256, Some("22".repeat(32)));
        assert_eq!(blk.rounds()[1].sent_sha256, None);

        // Reading since boot again starts the rounds over, and clears the
        // writes since the last read: round 0 already holds them.
        submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, 0);
        let again = blk.read_dirty(DirtySince::Boot).unwrap();
        assert_eq!((again.round, set(&again.dirty)), (0, vec![0, 1, 2]));
        assert_eq!(blk.rounds().len(), 1);
        assert_eq!(blk.read_dirty(DirtySince::Round).unwrap().dirty.count(), 0);
    }

    #[test]
    fn blocks_read_back_as_the_disk_holds_them_and_the_last_is_short() {
        let disk = Disk::new("read");
        let blk = VirtioBlk::open(disk.path()).unwrap();
        let image = std::fs::read(disk.path()).unwrap();
        assert_eq!(blk.block_len(0), Some(DIRTY_BLOCK_BYTES));
        assert_eq!(blk.block_len(3), Some(512));
        assert_eq!(blk.block_len(4), None);
        assert_eq!(blk.block_len(u64::MAX), None);
        let mut out = vec![0u8; 512];
        blk.read_block(3, &mut out).unwrap();
        assert_eq!(out, image[3 * DIRTY_BLOCK_BYTES as usize..]);
        let mut out = vec![0u8; DIRTY_BLOCK_BYTES as usize];
        blk.read_block(1, &mut out).unwrap();
        assert_eq!(
            out,
            image[DIRTY_BLOCK_BYTES as usize..2 * DIRTY_BLOCK_BYTES as usize]
        );
        let past = blk.read_block(4, &mut out).unwrap_err();
        assert!(past.to_string().contains("past the 4 blocks"), "{past}");
        assert!(
            blk.read_block(3, &mut out).is_err(),
            "a buffer of another length"
        );
    }

    // A restored device goes on from the blocks the source wrote since boot,
    // so the next move still sends every block that differs from the image
    // the guest booted from.
    #[test]
    fn a_restore_carries_the_blocks_written_since_boot() {
        let disk = Disk::new("seed");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let mut blk = VirtioBlk::open(disk.path()).unwrap();
        submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, sector(1));
        blk.read_dirty(DirtySince::Boot).unwrap();
        let (state, since_boot) = (blk.state(), blk.dirty_since_boot().clone());
        assert!(blk.release_lock());
        drop(blk);

        let mut restored =
            VirtioBlk::restore(disk.path(), &mem, &state, 1, Some(since_boot)).unwrap();
        assert!(restored.rounds().is_empty());
        submit(&mut restored, &mem, VIRTIO_BLK_T_OUT, sector(3));
        assert_eq!(set(restored.dirty_since_boot()), [1, 3]);
        let r0 = restored.read_dirty(DirtySince::Boot).unwrap();
        assert_eq!((r0.generation, set(&r0.dirty)), (2, vec![1, 3]));
        assert!(restored.release_lock());
        drop(restored);

        let other = DirtyBlocks::for_size(SIZE + DIRTY_BLOCK_BYTES);
        let err = VirtioBlk::restore(disk.path(), &mem, &state, 1, Some(other))
            .err()
            .unwrap();
        assert!(err.to_string().contains("covers 5 blocks"), "{err}");
    }

    // A mover that keeps reading rounds cannot grow the list without
    // bound: past the cap it starts over at round 0.
    #[test]
    fn rounds_stop_at_the_cap_until_round_0_is_read_again() {
        let disk = Disk::new("cap");
        let mut blk = VirtioBlk::open(disk.path()).unwrap();
        blk.read_dirty(DirtySince::Boot).unwrap();
        for want in 1..=MAX_ROUNDS as u32 {
            assert_eq!(blk.read_dirty(DirtySince::Round).unwrap().round, want);
        }
        let err = blk.read_dirty(DirtySince::Round).unwrap_err();
        assert!(err.to_string().contains("start over"), "{err}");
        assert_eq!(blk.rounds().len(), MAX_ROUNDS + 1);
        assert_eq!(blk.read_dirty(DirtySince::Boot).unwrap().round, 0);
        assert_eq!(blk.read_dirty(DirtySince::Round).unwrap().round, 1);
    }

    // A disk with a base must be one whose bitmap a checkpoint can hold.
    #[test]
    fn a_disk_over_4_tib_takes_no_base() {
        let path = std::env::temp_dir().join(format!("hvi-blk-4tib-{}.img", std::process::id()));
        let path = path.to_str().unwrap().to_string();
        let sized = |len: u64| {
            let f = std::fs::File::create(&path).unwrap();
            f.set_len(len).unwrap();
        };
        sized(MAX_BITMAP_DISK_BYTES);
        let blk = VirtioBlk::open_with_base(&path, true, None).unwrap();
        assert_eq!(blk.dirty_since_boot().blocks(), 1 << 26);
        drop(blk);
        sized(MAX_BITMAP_DISK_BYTES + DIRTY_BLOCK_BYTES);
        let err = VirtioBlk::open_with_base(&path, true, None).err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("at most 4 TiB"), "{err}");
        assert!(VirtioBlk::open_with_base(&path, false, None).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    // A launcher that wrote files into its copy of the base before the boot
    // names the blocks it changed, and round 0 holds them with the guest's
    // own writes; a bitmap of another disk's size is refused.
    #[test]
    fn the_blocks_written_before_the_boot_start_round_0() {
        let path = std::env::temp_dir().join(format!("hvi-blk-written-{}.img", std::process::id()));
        let path = path.to_str().unwrap().to_string();
        std::fs::write(&path, vec![0u8; (20 * DIRTY_BLOCK_BYTES + 512) as usize]).unwrap();
        let mut written = DirtyBlocks::for_size(20 * DIRTY_BLOCK_BYTES + 512);
        written.mark(3 * DIRTY_BLOCK_BYTES, 1);
        written.mark(20 * DIRTY_BLOCK_BYTES, 1);
        let mut blk = VirtioBlk::open_with_base(&path, true, Some(written.as_bytes())).unwrap();
        blk.write_for_test(7 * DIRTY_BLOCK_BYTES, &[1; 16]);
        let round0 = blk.read_dirty(DirtySince::Boot).unwrap();
        assert_eq!(round0.dirty.iter().collect::<Vec<_>>(), [3, 7, 20]);
        drop(blk);
        for bad in [vec![0u8; 2], vec![0u8; 4], vec![0, 0, 0x40]] {
            let err = VirtioBlk::open_with_base(&path, true, Some(&bad))
                .err()
                .unwrap();
            assert!(err.to_string().contains("--disk-written"), "{err}");
        }
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod worker_tests {
    use super::*;
    use crate::devices::irq::test_line::LevelLine;
    use crate::teardown::{join_by, StopSource};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    const BASE: u64 = 0x4000_0000;
    const DESC: u64 = BASE;
    const AVAIL: u64 = BASE + 0x1000;
    const USED: u64 = BASE + 0x2000;
    /// The ring size the rig programs.
    const RING: u16 = 16;
    /// The disk: 64 sectors, each byte 0x5a.
    const DISK_BYTES: usize = 64 * 512;
    /// How long a test waits for the worker before it fails.
    const PATIENCE: Duration = Duration::from_secs(5);

    /// A disk removed on drop.
    struct Disk(std::path::PathBuf);

    impl Drop for Disk {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// A device over a disk with its queue programmed, and its worker once
    /// [`start`](Rig::start)ed.
    struct Rig {
        disk: Disk,
        mem: Arc<GuestRam>,
        dev: Arc<Mutex<VirtioBlk>>,
        line: Arc<LevelLine>,
        source: StopSource,
        wake: Arc<Wake>,
        worker: Option<JoinHandle<()>>,
    }

    fn rig(tag: &str) -> Rig {
        let path =
            std::env::temp_dir().join(format!("hvi-blk-worker-{tag}-{}.img", std::process::id()));
        std::fs::write(&path, vec![0x5a; DISK_BYTES]).unwrap();
        let disk = Disk(path);
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x10_0000)]));
        let mut blk = VirtioBlk::open(disk.0.to_str().unwrap()).unwrap();
        for (reg, v) in [
            (mmio::QUEUE_NUM, u64::from(RING)),
            (mmio::QUEUE_DESC_LOW, DESC),
            (mmio::QUEUE_DRIVER_LOW, AVAIL),
            (mmio::QUEUE_DEVICE_LOW, USED),
            (mmio::QUEUE_READY, 1),
        ] {
            blk.mmio(&mem, reg, true, v);
        }
        let line = Arc::new(LevelLine::default());
        blk.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
        Rig {
            disk,
            mem,
            dev: Arc::new(Mutex::new(blk)),
            line,
            source: StopSource::new().unwrap(),
            wake: Arc::new(Wake::new()),
            worker: None,
        }
    }

    impl Rig {
        /// Starts the worker, as `IoThreads::start` does.
        fn start(&mut self) {
            lock_or_recover(&self.dev).connect_worker(Arc::clone(&self.wake));
            let (dev, mem, wake, stop) = (
                Arc::clone(&self.dev),
                Arc::clone(&self.mem),
                Arc::clone(&self.wake),
                self.source.token(),
            );
            self.worker = Some(std::thread::spawn(move || {
                serve(&dev, &mem, &wake, &stop, |_| {});
            }));
        }

        /// Posts request `slot` of type `typ` at `sector`: a header, one
        /// sector of data filled with `fill` (none for a flush) and a status
        /// byte poisoned to 0xff. Returns the chain's head.
        fn post(&self, slot: u16, typ: u32, sector: u64, fill: u8) -> u16 {
            let mem = &self.mem;
            let room = BASE + 0x1_0000 + u64::from(slot) * 0x1000;
            let (hdr, data, status) = (room, room + 0x200, room + 0x800);
            mem.write_u32(hdr, typ).unwrap();
            mem.write_u64(hdr + 8, sector).unwrap();
            mem.write(data, &[fill; 512]).unwrap();
            mem.write_u8(status, 0xff).unwrap();
            let head = slot * 3;
            let data_flag = if typ == VIRTIO_BLK_T_IN {
                VIRTQ_DESC_F_WRITE
            } else {
                0
            };
            let mut chain = vec![(hdr, 16, VIRTQ_DESC_F_NEXT)];
            if typ != VIRTIO_BLK_T_FLUSH {
                chain.push((data, 512, VIRTQ_DESC_F_NEXT | data_flag));
            }
            chain.push((status, 1, VIRTQ_DESC_F_WRITE));
            for (i, &(addr, len, flags)) in chain.iter().enumerate() {
                let d = DESC + u64::from(head + i as u16) * 16;
                mem.write_u64(d, addr).unwrap();
                mem.write_u32(d + 8, len).unwrap();
                mem.write_u16(d + 12, flags).unwrap();
                mem.write_u16(d + 14, head + i as u16 + 1).unwrap();
            }
            let idx = mem.read_u16(AVAIL + 2).unwrap();
            mem.write_u16(AVAIL + 4 + u64::from(idx % RING) * 2, head)
                .unwrap();
            mem.write_u16(AVAIL + 2, idx.wrapping_add(1)).unwrap();
            head
        }

        /// The status byte of request `slot`.
        fn status(&self, slot: u16) -> u8 {
            let room = BASE + 0x1_0000 + u64::from(slot) * 0x1000;
            self.mem.read_u16(room + 0x800).unwrap() as u8
        }

        /// The data of request `slot`.
        fn data(&self, slot: u16) -> Vec<u8> {
            let room = BASE + 0x1_0000 + u64::from(slot) * 0x1000;
            let mut buf = vec![0; 512];
            self.mem.read(room + 0x200, &mut buf).unwrap();
            buf
        }

        /// Writes QUEUE_NOTIFY, as the guest's driver does.
        fn notify(&self) {
            lock_or_recover(&self.dev).mmio(&self.mem, mmio::QUEUE_NOTIFY, true, 0);
        }

        fn used_idx(&self) -> u16 {
            self.mem.read_u16(USED + 2).unwrap()
        }

        /// The heads on the used ring, in the order they were returned.
        fn used_heads(&self) -> Vec<u16> {
            (0..self.used_idx())
                .map(|i| {
                    self.mem
                        .read_u32(USED + 4 + u64::from(i % RING) * 8)
                        .unwrap() as u16
                })
                .collect()
        }

        /// Waits until `n` chains are on the used ring.
        fn wait_used(&self, n: u16) {
            let deadline = Instant::now() + PATIENCE;
            while self.used_idx() < n {
                assert!(
                    Instant::now() < deadline,
                    "{} of {n} chains returned",
                    self.used_idx()
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        /// The disk's bytes in `sector`.
        fn sector(&self, sector: u64) -> Vec<u8> {
            let bytes = std::fs::read(&self.disk.0).unwrap();
            bytes[sector as usize * 512..][..512].to_vec()
        }

        /// Stops the worker as `IoThreads::stop` does, and checks it ended.
        fn stop(mut self) {
            self.source.request_stop();
            self.wake.stop();
            let worker = self.worker.take().expect("started");
            join_by("virtio-blk worker", worker, Instant::now() + PATIENCE).unwrap();
        }
    }

    /// A hook that holds a request of `kind` in its run until released.
    #[derive(Clone, Default)]
    struct Hold {
        entered: Arc<AtomicBool>,
        released: Arc<AtomicBool>,
    }

    impl Hold {
        fn hook(&self, kind: &'static str) -> RunHook {
            let hold = self.clone();
            Arc::new(move |k| {
                if k != kind {
                    return;
                }
                hold.entered.store(true, Ordering::SeqCst);
                while !hold.released.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        }

        fn wait_entered(&self) {
            let deadline = Instant::now() + PATIENCE;
            while !self.entered.load(Ordering::SeqCst) {
                assert!(Instant::now() < deadline, "the request never ran");
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_notify_only_wakes_the_worker_which_serves_the_chain() {
        let mut rig = rig("notify");
        let ran_on = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&ran_on);
        lock_or_recover(&rig.dev).set_run_hook(Arc::new(move |_| {
            *lock_or_recover(&seen) = Some(std::thread::current().id());
        }));
        rig.start();
        rig.post(0, VIRTIO_BLK_T_IN, 3, 0);
        rig.notify();
        rig.wait_used(1);
        assert_eq!(rig.status(0), VIRTIO_BLK_S_OK);
        assert_eq!(rig.data(0), vec![0x5a; 512], "the read landed");
        assert!(rig.line.is_high(), "the worker raised the line");
        let ran_on = lock_or_recover(&ran_on).expect("the request ran");
        assert_ne!(
            ran_on,
            std::thread::current().id(),
            "not on the notifying thread"
        );
        rig.stop();
    }

    /// The gate: a pause waits for the request in flight, with the device's
    /// lock free meanwhile, and then finds no chain taken but not returned.
    /// A chain the guest posts while paused waits for the resume.
    #[test]
    fn a_pause_waits_for_the_request_in_flight_and_then_finds_none() {
        let mut rig = rig("gate");
        let hold = Hold::default();
        lock_or_recover(&rig.dev).set_run_hook(hold.hook("write"));
        rig.start();
        rig.post(0, VIRTIO_BLK_T_OUT, 2, 0xc3);
        rig.notify();
        hold.wait_entered();

        let gate = Arc::clone(rig.source.gate());
        let pause = std::thread::spawn(move || gate.pause(PATIENCE));
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !pause.is_finished(),
            "the pause waits for the write in flight"
        );
        // A vCPU reads the interrupt status while the disk call runs: the
        // device's lock is not held across it.
        let started = Instant::now();
        let _ = lock_or_recover(&rig.dev).mmio(&rig.mem, mmio::INTERRUPT_STATUS, false, 0);
        assert!(started.elapsed() < Duration::from_millis(50));

        hold.release();
        assert_eq!(pause.join().unwrap(), Ok(()));
        assert_eq!(rig.used_idx(), 1, "the write was returned before the pause");
        let state = lock_or_recover(&rig.dev).state();
        assert_eq!(state.queue.last_avail, rig.used_idx(), "nothing in flight");
        assert_eq!(rig.sector(2), vec![0xc3; 512]);

        rig.post(1, VIRTIO_BLK_T_IN, 2, 0);
        rig.notify();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(rig.used_idx(), 1, "nothing is served while paused");
        rig.source.gate().unpause();
        rig.wait_used(2);
        assert_eq!(rig.data(1), vec![0xc3; 512]);
        rig.stop();
    }

    /// A flush completes only after every write before it in the queue.
    #[test]
    fn a_flush_completes_after_every_write_before_it() {
        let mut rig = rig("order");
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&log);
        lock_or_recover(&rig.dev).set_run_hook(Arc::new(move |kind| {
            lock_or_recover(&seen).push(kind);
        }));
        rig.start();
        let heads = [
            rig.post(0, VIRTIO_BLK_T_OUT, 0, 1),
            rig.post(1, VIRTIO_BLK_T_OUT, 1, 2),
            rig.post(2, VIRTIO_BLK_T_FLUSH, 0, 0),
            rig.post(3, VIRTIO_BLK_T_OUT, 2, 3),
        ];
        rig.notify();
        rig.wait_used(4);
        assert_eq!(rig.used_heads(), heads, "returned in the order posted");
        assert_eq!(*lock_or_recover(&log), ["write", "write", "flush", "write"]);
        assert!((0..4).all(|slot| rig.status(slot) == VIRTIO_BLK_S_OK));
        rig.stop();
    }

    #[test]
    fn the_stop_ends_a_parked_worker() {
        let mut rig = rig("parked");
        rig.start();
        rig.stop();
    }

    /// A fenced source's worker held at the closed gate serves nothing when
    /// the gate opens, as the stop opens it: the disk is the restore's by
    /// then. The stop then ends it.
    #[test]
    fn a_fenced_device_serves_nothing_once_its_gate_opens() {
        let mut rig = rig("fenced");
        rig.start();
        rig.source.gate().pause(PATIENCE).unwrap();
        rig.post(0, VIRTIO_BLK_T_OUT, 4, 0x77);
        rig.notify();
        std::thread::sleep(Duration::from_millis(50));
        lock_or_recover(&rig.dev).release_lock();
        rig.source.gate().unpause();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(rig.used_idx(), 0, "nothing returned");
        assert_eq!(rig.sector(4), vec![0x5a; 512], "nothing written");
        rig.stop();
    }

    /// A restored guest may have chains pending whose notify went to the
    /// process it was captured from: the worker serves them with no notify.
    #[test]
    fn chains_pending_at_the_start_are_served_without_a_notify() {
        let mut rig = rig("pending");
        rig.post(0, VIRTIO_BLK_T_IN, 0, 0);
        rig.start();
        rig.wait_used(1);
        assert_eq!(rig.data(0), vec![0x5a; 512]);
        rig.stop();
    }

    /// A move's round read while a write is in flight does not take the
    /// write's block, and the next round does: marked before the write, the
    /// block would go with the round read before the write landed, and no
    /// later round would send what it wrote.
    #[test]
    fn a_round_read_while_a_write_runs_leaves_its_block_to_the_next() {
        let mut rig = rig("round");
        let hold = Hold::default();
        {
            let mut dev = lock_or_recover(&rig.dev);
            dev.set_run_hook(hold.hook("write"));
            dev.read_dirty(DirtySince::Boot).unwrap();
        }
        rig.start();
        rig.post(0, VIRTIO_BLK_T_OUT, 1, 0x99);
        rig.notify();
        hold.wait_entered();
        let during = lock_or_recover(&rig.dev)
            .read_dirty(DirtySince::Round)
            .unwrap();
        assert_eq!(during.dirty.count(), 0, "the write has not landed yet");
        hold.release();
        rig.wait_used(1);
        let after = lock_or_recover(&rig.dev)
            .read_dirty(DirtySince::Round)
            .unwrap();
        assert_eq!(after.dirty.iter().collect::<Vec<_>>(), [0]);
        rig.stop();
    }
}

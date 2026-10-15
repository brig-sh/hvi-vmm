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
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::checkpoint::bundle::hex;
use crate::config;
use crate::memory::GuestRam;
use crate::LOG_PREFIX;

use crate::devices::irq::{Irq, IrqLine};
use crate::devices::state::{check_version, invalid};
use crate::devices::virtio::{
    mmio, Queue, QueueState, VirtioCommonState, QUEUE_NUM_MAX, VIRTQ_DESC_F_NEXT,
    VIRTQ_DESC_F_WRITE,
};
use crate::events::CapturedEvent;
use crate::plugin::IoSink;
use crate::sync::lock_or_recover;

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
/// `VIRTIO_BLK_F_RO` (low word): the disk is read-only, and Linux marks the
/// guest's block device read-only to match.
const F_BLK_RO_LO: u32 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_RO;

/// virtio-blk request types.
const VIRTIO_BLK_T_IN: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_IN; // read disk -> guest
const VIRTIO_BLK_T_OUT: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_OUT; // guest -> write disk
const VIRTIO_BLK_T_FLUSH: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_FLUSH; // flush the cache
const VIRTIO_BLK_T_GET_ID: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_GET_ID; // read the serial

/// Length of the serial `GET_ID` returns, zero-padded.
pub const SERIAL_LEN: usize = virtio_bindings::virtio_blk::VIRTIO_BLK_ID_BYTES as usize;

/// virtio-blk status byte.
const VIRTIO_BLK_S_OK: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_OK as u8;
const VIRTIO_BLK_S_IOERR: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_IOERR as u8;
/// The device does not implement this request type (virtio 1.2, 5.2.6).
/// Answering `S_OK` instead tells the driver a request it depends on, such as a
/// discard, did its work when it did nothing at all.
const VIRTIO_BLK_S_UNSUPP: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_UNSUPP as u8;

const SECTOR: u64 = 512;

/// The [`BlkState`] format this build writes and reads. Version 2 added the
/// disk's serial and its read-only flag.
pub const BLK_STATE_VERSION: u32 = 2;

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
/// reopens it. Nothing is in flight either, since a notify serves every chain
/// before the MMIO exit returns. The ledger staging, the plugin feed, the
/// inode and the trace switch belong to the host the device runs on.
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
    /// The serial the disk answers `GET_ID` with, which the guest reads from
    /// `/sys/block/vdX/serial`. The restored disk answers with it too.
    pub serial: String,
    /// Whether the guest was told the disk is read-only. A checkpoint is only
    /// ever taken of a writable disk, so it is `false` in every bundle.
    pub read_only: bool,
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
    /// The backing file is open read-only, and every write is refused.
    read_only: bool,
    /// What `GET_ID` returns, zero-padded.
    serial: [u8; SERIAL_LEN],
    /// The serial as given, for the ledger.
    serial_text: Arc<str>,
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
}

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

/// Takes the lock on `file` that its mode needs, without waiting.
///
/// # Errors
///
/// Errors with `WouldBlock` when a lock this one excludes is held, and with
/// what the filesystem answered otherwise, as on NFS without a lock service.
fn lock(file: &File, read_only: bool) -> std::io::Result<()> {
    let taken = if read_only {
        file.try_lock_shared()
    } else {
        file.try_lock()
    };
    match taken {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            if read_only {
                "the image is open for writing elsewhere"
            } else {
                "the image is open elsewhere"
            },
        )),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

/// How often, and how long apart, a lock on a block device is retried.
///
/// systemd-udevd holds a shared lock on a whole-disk device while it handles an
/// event for it, as after `losetup`, so a first attempt can land in that
/// window.
const BLOCK_DEVICE_LOCK_TRIES: u32 = 20;
const BLOCK_DEVICE_LOCK_PAUSE: Duration = Duration::from_millis(50);

/// Takes [`lock`] on `file`, retried for a second when it is a block device.
///
/// # Errors
///
/// Errors as [`lock`] does, once the tries are spent.
fn lock_retrying(file: &File, read_only: bool, block_device: bool) -> std::io::Result<()> {
    let mut tries = if block_device {
        BLOCK_DEVICE_LOCK_TRIES
    } else {
        1
    };
    loop {
        tries -= 1;
        match lock(file, read_only) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && tries > 0 => {
                std::thread::sleep(BLOCK_DEVICE_LOCK_PAUSE);
            }
            taken => break taken,
        }
    }
}

/// A writable disk's exclusive lock, held on an open of the image of its own
/// rather than on the device's file.
///
/// The lock is [`lock`]'s, as [`VirtioBlk::open_as`] takes it for a writable
/// disk. Holding it apart lets a fenced source release it while the device
/// keeps the image open (see [`VirtioBlk::release_lock`]): closing that open
/// releases it, which needs no system call the sandbox would have to allow
/// after confinement.
#[derive(Debug)]
pub(crate) struct DiskLock {
    /// The open that holds the lock; closing it releases the lock.
    _file: File,
}

impl DiskLock {
    /// Takes a writer's lock on the image at `path`, retried as
    /// [`lock_retrying`] does when it is a block device.
    ///
    /// # Errors
    ///
    /// Errors when the path cannot be opened again, and as [`lock`] does.
    pub(crate) fn take(path: &str, block_device: bool) -> std::io::Result<Self> {
        let file = File::open(path)?;
        lock_retrying(&file, false, block_device)?;
        Ok(DiskLock { _file: file })
    }
}

/// Returns the id `IoSink::block` reports for the backing store `meta`
/// describes, which a reader derives from its own path to the same store.
///
/// For a block device it is the device number, `st_rdev`, so every node for
/// one device gives one id. For a regular file it is `st_dev` rotated left by
/// 32 bits, xor `st_ino`, so two images on different filesystems with one
/// inode number differ.
#[must_use]
pub fn disk_id(meta: &std::fs::Metadata) -> u64 {
    store_id(
        meta.file_type().is_block_device(),
        meta.dev(),
        meta.ino(),
        meta.rdev(),
    )
}

/// Returns [`disk_id`] for a node `ino` on filesystem `dev`, which is the
/// device number `rdev` when `block_device` is set.
fn store_id(block_device: bool, dev: u64, ino: u64, rdev: u64) -> u64 {
    if block_device {
        rdev
    } else {
        dev.rotate_left(32) ^ ino
    }
}

impl VirtioBlk {
    /// Opens `path` read-write as the backing disk, with an empty serial.
    ///
    /// # Errors
    ///
    /// Errors if the file cannot be opened or its length read.
    #[cfg(test)]
    pub(crate) fn open(path: &str) -> std::io::Result<Self> {
        Self::open_as(path, false, "")
    }

    /// Opens `path` as the backing disk, read-only when `read_only` is set, and
    /// answers `GET_ID` with `serial`.
    ///
    /// A read-only disk is opened `O_RDONLY`, so an image the VMM cannot write
    /// still attaches, and the guest is told it is read-only.
    ///
    /// The file is locked for as long as it is open, shared for a read-only
    /// disk and exclusive for a writable one, so two hvi processes never write
    /// one image at once and no hvi writes an image another one reads. One
    /// read-only image can back any number of guests. A writable disk's lock
    /// is held on an open of its own, so a fenced source can release it and
    /// keep the disk (see [`release_lock`](Self::release_lock)). A writable
    /// block device is opened `O_EXCL` on Linux as well, which claims the
    /// device itself and so holds against another device node for it and
    /// against a mount. A read-only open claims nothing, so a reader through
    /// another node is not held against a writer.
    ///
    /// # Errors
    ///
    /// Errors if `serial` is longer than [`SERIAL_LEN`] bytes, the file cannot
    /// be opened or its length read, or a lock on it that this one excludes is
    /// held.
    pub fn open_as(path: &str, read_only: bool, serial: &str) -> std::io::Result<Self> {
        if serial.len() > SERIAL_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("virtio-blk serial {serial:?} is longer than {SERIAL_LEN} bytes"),
            ));
        }
        let mut id = [0u8; SERIAL_LEN];
        id[..serial.len()].copy_from_slice(serial.as_bytes());
        let block_device = std::fs::metadata(path)?.file_type().is_block_device();
        let mut options = OpenOptions::new();
        options.read(true).write(!read_only);
        #[cfg(target_os = "linux")]
        if block_device && !read_only {
            options.custom_flags(libc::O_EXCL);
        }
        let file = options.open(path).map_err(|e| {
            // O_EXCL is what fails with EBUSY, so the message says what it
            // means rather than what errno it was.
            if block_device && e.raw_os_error() == Some(libc::EBUSY) {
                std::io::Error::new(
                    e.kind(),
                    "the device is claimed elsewhere: open for writing, or mounted",
                )
            } else {
                e
            }
        })?;
        let lock = if read_only {
            lock_retrying(&file, true, block_device)?;
            None
        } else {
            Some(DiskLock::take(path, block_device)?)
        };
        let capacity_sectors = backing_len(&file)? / SECTOR;
        // The backing store is identified across the two processes that care
        // about it without agreeing on a path: hvi may have been given a
        // relative one, and the reader is given its own.
        let disk_id = disk_id(&file.metadata()?);
        Ok(VirtioBlk {
            file: Arc::new(file),
            lock,
            capacity_sectors,
            status: 0,
            dev_feat_sel: 0,
            queue: Queue::default(),
            interrupt_status: 0,
            irq: Irq::default(),
            events: Vec::new(),
            sink: None,
            disk_id,
            read_only,
            serial: id,
            serial_text: Arc::from(serial),
            trace: std::env::var_os("HVI_BLK_TRACE").is_some(),
            generation: 0,
            dirty: Dirty::new(capacity_sectors * SECTOR),
        })
    }

    /// Opens `path` as [`open`](Self::open) does, and gives it the base of
    /// [`take_base`](Self::take_base).
    ///
    /// # Errors
    ///
    /// Errors as [`open`](Self::open) and [`take_base`](Self::take_base) do.
    #[cfg(test)]
    pub(crate) fn open_with_base(
        path: &str,
        has_base: bool,
        written: Option<&[u8]>,
    ) -> std::io::Result<Self> {
        let mut dev = Self::open(path)?;
        dev.take_base(path, has_base, written)?;
        Ok(dev)
    }

    /// Takes what a boot was told of the disk at `path`, this device's: that
    /// it was given the digest of the disk's base image when `has_base`, and,
    /// with `written`, the bitmap of the blocks where the disk already differs
    /// from that base, which start the blocks written since boot.
    ///
    /// # Errors
    ///
    /// Errors when `has_base` and the disk is larger than
    /// [`MAX_BITMAP_DISK_BYTES`]: a checkpoint could not record the blocks it
    /// wrote since boot, which a move by its blocks needs. Errors too when
    /// `written` is not the bitmap of this disk.
    pub fn take_base(
        &mut self,
        path: &str,
        has_base: bool,
        written: Option<&[u8]>,
    ) -> std::io::Result<()> {
        if has_base && self.size_bytes() > MAX_BITMAP_DISK_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "--disk-base-sha256: {path} is {} bytes, and a move by its blocks takes a \
                     disk of at most 4 TiB",
                    self.size_bytes()
                ),
            ));
        }
        if let Some(bits) = written {
            self.dirty.since_boot = DirtyBlocks::from_bytes(bits.to_vec(), self.size_bytes())
                .map_err(|e| {
                    std::io::Error::new(e.kind(), format!("--disk-written for {path}: {e}"))
                })?;
        }
        Ok(())
    }

    /// Releases the disk's lock, so another hvi may open the disk while
    /// this one still has it open. Returns whether there was a lock, which
    /// only a writable disk holds.
    ///
    /// A source fenced after a checkpoint calls it: its guest never runs
    /// again, so it never writes the disk again, and the restore that takes
    /// the guest over may start before the source is stopped. A writable
    /// block device stays claimed by its `O_EXCL` open until the source
    /// stops, so a restore on the same host waits for that.
    pub fn release_lock(&mut self) -> bool {
        self.lock.take().is_some()
    }

    /// Returns whether the disk is read-only.
    #[cfg(test)]
    pub(crate) fn read_only(&self) -> bool {
        self.read_only
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
            serial: self.serial_text.to_string(),
            read_only: self.read_only,
        }
    }

    /// Rebuilds the device a checkpoint describes over the disk at `path`,
    /// opened as [`VirtioBlk::open_as`] opens it with the state's mode and
    /// serial, and the restored guest RAM `mem`. Its generation goes on from
    /// `generation`, the one the checkpoint's `disk.json` records, and its
    /// blocks written since boot from `since_boot`, the ones `disk.json`
    /// records, so a later move still sends every block that differs from the
    /// image the guest booted from. Its rounds start over.
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
        let mut dev = Self::open_as(path, state.read_only, &state.serial)?;
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
    /// the driver notifies a queue, the virtqueue is processed inline.
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
                mmio::QUEUE_NUM => self.queue.set_num(v),
                mmio::QUEUE_READY => self.queue.set_ready(v, mem),
                mmio::QUEUE_NOTIFY => self.process_queue(mem),
                mmio::INTERRUPT_ACK => self.interrupt_status &= !v,
                mmio::STATUS if v == 0 => self.reset(),
                mmio::STATUS => self.status = v,
                mmio::QUEUE_DESC_LOW => self.queue.set_desc_lo(v),
                mmio::QUEUE_DESC_HIGH => self.queue.set_desc_hi(v),
                mmio::QUEUE_DRIVER_LOW => self.queue.set_avail_lo(v),
                mmio::QUEUE_DRIVER_HIGH => self.queue.set_avail_hi(v),
                mmio::QUEUE_DEVICE_LOW => self.queue.set_used_lo(v),
                mmio::QUEUE_DEVICE_HIGH => self.queue.set_used_hi(v),
                _ => {}
            }
            0
        } else {
            match offset {
                mmio::MAGIC => MAGIC_VALUE,
                mmio::VERSION => 2,
                mmio::DEVICE_ID => VIRTIO_BLK_ID,
                mmio::VENDOR_ID => VENDOR,
                // Low word: VIRTIO_BLK_F_FLUSH, and VIRTIO_BLK_F_RO on a
                // read-only disk. High word: VIRTIO_F_VERSION_1.
                mmio::DEVICE_FEATURES if self.dev_feat_sel == 0 => u64::from(self.features_lo()),
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

    /// Returns the low 32 feature bits the device offers.
    fn features_lo(&self) -> u32 {
        if self.read_only {
            F_BLK_FLUSH_LO | F_BLK_RO_LO
        } else {
            F_BLK_FLUSH_LO
        }
    }

    /// Resets the device, as a write of 0 to STATUS requests.
    fn reset(&mut self) {
        self.queue.reset();
        self.interrupt_status = 0;
        self.status = 0;
        self.dev_feat_sel = 0;
    }

    /// Processes every buffer the driver has made available on queue 0.
    fn process_queue(&mut self, mem: &GuestRam) {
        if !self.queue.is_ready() {
            return;
        }
        let Some(pending) = self.queue.pending(mem) else {
            return;
        };
        let mut last = self.queue.last_avail();
        let mut serviced = false;
        for _ in 0..pending {
            let Some(slot) = self.queue.avail_slot(last) else {
                break;
            };
            let Ok(head) = mem.read_u16(slot) else {
                break;
            };
            let used_len = self.handle_chain(mem, head);
            self.queue.push_used(mem, head, used_len);
            last = last.wrapping_add(1);
            serviced = true;
        }
        self.queue.set_last_avail(last);
        if serviced {
            // Used-buffer notification.
            self.interrupt_status |= 1;
        }
    }

    /// Walks the descriptor chain at `head`, runs the block request, and
    /// returns the number of device-written bytes for the used ring.
    fn handle_chain(&mut self, mem: &GuestRam, head: u16) -> u32 {
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
        if readable.is_empty() || writable.is_empty() {
            return 0;
        }
        let (saddr, _) = *writable.last().unwrap();
        match self.handle_request(mem, &readable, &writable) {
            Ok(written) => written,
            Err(e) => {
                // Always report a failure. Leaving the status byte untouched
                // let the driver read back whatever it had put there, so a
                // rejected or failed request could look like a success with
                // stale data in the buffer.
                if self.trace {
                    stderr!("\r\n[virtio-blk] request failed: {e}\r\n");
                }
                let _ = mem.write_u8(saddr, VIRTIO_BLK_S_IOERR);
                1
            }
        }
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

    /// Writes `buf` at byte `base` of the disk, as a guest write does, once
    /// [`byte_range`](Self::byte_range) has checked the range.
    ///
    /// The blocks are marked before the write, so a write that fails part
    /// way is still in the next round: the blocks may hold some of it.
    fn write_at(&mut self, base: u64, buf: &[u8]) -> std::io::Result<()> {
        self.dirty.mark(base, buf.len() as u64);
        self.file.write_all_at(buf, base)?;
        self.generation += 1;
        Ok(())
    }

    /// Writes `buf` at byte `base` as a guest write would, for a test that
    /// has no queue to post one on.
    #[cfg(test)]
    pub(crate) fn write_for_test(&mut self, base: u64, buf: &[u8]) {
        self.byte_range(base / SECTOR, buf.len() as u64).unwrap();
        self.write_at(base, buf).unwrap();
    }

    /// Runs a single virtio-blk request. The first readable segment is the
    /// 16-byte header (type, _, sector); the last writable segment is the
    /// status byte; the segments between carry data.
    fn handle_request(
        &mut self,
        mem: &GuestRam,
        readable: &[(u64, u32)],
        writable: &[(u64, u32)],
    ) -> std::io::Result<u32> {
        let (haddr, _) = readable[0];
        let typ = mem.read_u32(haddr).map_err(other)?;
        let sector = mem.read_u64(haddr + 8).map_err(other)?;
        // Device-written bytes (for the used ring) vs data bytes transferred
        // (the boundary metric — the actual I/O volume).
        let mut device_written = 0u32;
        let mut data_bytes = 0u64;

        let status = match typ {
            VIRTIO_BLK_T_IN => {
                // Coalesce the data segments into one positioned read, then
                // scatter into guest memory: one syscall per request, not one
                // per descriptor.
                let segs = &writable[..writable.len() - 1];
                let total: usize = segs.iter().map(|&(_, l)| l as usize).sum();
                let base = self.byte_range(sector, total as u64)?;
                let mut buf = vec![0u8; total];
                self.file.read_exact_at(&mut buf, base).map_err(other)?;
                device_written += scatter(mem, segs, &buf)?;
                data_bytes = total as u64;
                VIRTIO_BLK_S_OK
            }
            // The guest was offered VIRTIO_BLK_F_RO. A write that arrives
            // anyway fails.
            VIRTIO_BLK_T_OUT if self.read_only => VIRTIO_BLK_S_IOERR,
            // Nothing was written, so there is nothing to make durable.
            VIRTIO_BLK_T_FLUSH if self.read_only => VIRTIO_BLK_S_OK,
            VIRTIO_BLK_T_OUT => {
                // Gather the data segments into one buffer, then one positioned
                // write.
                let segs = &readable[1..];
                let total: usize = segs.iter().map(|&(_, l)| l as usize).sum();
                let base = self.byte_range(sector, total as u64)?;
                let mut buf = vec![0u8; total];
                let mut o = 0;
                for &(a, l) in segs {
                    mem.read(a, &mut buf[o..o + l as usize]).map_err(other)?;
                    o += l as usize;
                }
                self.write_at(base, &buf).map_err(other)?;
                data_bytes = total as u64;
                VIRTIO_BLK_S_OK
            }
            VIRTIO_BLK_T_FLUSH => {
                // Honour the guest's cache flush (durability for fsync).
                self.file.sync_data().map_err(other)?;
                self.generation += 1;
                VIRTIO_BLK_S_OK
            }
            VIRTIO_BLK_T_GET_ID => {
                // The serial goes into the data segments, up to their length.
                // Linux offers exactly SERIAL_LEN bytes.
                device_written += scatter(mem, &writable[..writable.len() - 1], &self.serial)?;
                VIRTIO_BLK_S_OK
            }
            // Every request type this device does not implement, discard and
            // write-zeroes among them. None of them were negotiated, but a
            // driver that sends one anyway must learn that nothing happened.
            _ => VIRTIO_BLK_S_UNSUPP,
        };

        let (saddr, _) = *writable.last().unwrap();
        mem.write_u8(saddr, status).map_err(other)?;
        device_written += 1;

        // Boundary capture: the guest's disk I/O, observed at the device. The
        // structured event is always recorded; the console line is opt-in
        // (HVI_BLK_TRACE) because a synchronous stderr write per request would
        // dominate the cost under a high-IOPS workload.
        if self.trace {
            let kind = match typ {
                VIRTIO_BLK_T_IN => "read ",
                VIRTIO_BLK_T_OUT => "write",
                VIRTIO_BLK_T_FLUSH => "flush",
                VIRTIO_BLK_T_GET_ID => "getid",
                _ => "other",
            };
            stderr!(
                "\r\n[virtio-blk] {kind} sector={sector} bytes={data_bytes} status={status}\r\n"
            );
        }
        // Only a read or write that went through is I/O on the disk. A flush
        // carries no data range, and a refused write moved nothing.
        if status == VIRTIO_BLK_S_OK && (typ == VIRTIO_BLK_T_IN || typ == VIRTIO_BLK_T_OUT) {
            let write = typ == VIRTIO_BLK_T_OUT;
            self.events.push(CapturedEvent::Block {
                disk: Arc::clone(&self.serial_text),
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
        Ok(device_written)
    }
}

/// Opens every disk in `disks` in order, each with the [`serial_at`] its
/// position, and logs each one.
///
/// [`serial_at`]: config::DiskConfig::serial_at
///
/// # Errors
///
/// Errors when [`config::check_disks`] refuses the list, when one image backs
/// two disks of which one is writable, or when a disk does not open. The
/// message names the disk and its path.
pub fn open_disks(disks: &[config::DiskConfig]) -> Result<Vec<Arc<Mutex<VirtioBlk>>>, String> {
    config::check_disks(disks)?;
    let mut opened: Vec<(Arc<Mutex<VirtioBlk>>, u64)> = Vec::new();
    for (index, disk) in disks.iter().enumerate() {
        let serial = disk.serial_at(index);
        let fail =
            |e: &dyn std::fmt::Display| format!("virtio-blk disk {index} ({}): {e}", disk.path);
        // The lock would refuse this too, with a message about another process.
        // Here the other holder is known, so the message names it.
        let id = std::fs::metadata(&disk.path)
            .map(|meta| disk_id(&meta))
            .map_err(|e| fail(&e))?;
        if let Some(earlier) = opened.iter().position(|(_, other)| *other == id) {
            let earlier_writes = !disks[earlier].read_only;
            if earlier_writes || !disk.read_only {
                return Err(fail(&format!(
                    "the same image is disk {earlier}, {}",
                    if earlier_writes {
                        "which this guest writes"
                    } else {
                        "and only one of the two may be writable"
                    }
                )));
            }
        }
        let blk = VirtioBlk::open_as(&disk.path, disk.read_only, &serial).map_err(|e| fail(&e))?;
        let mode = if disk.read_only { "ro" } else { "rw" };
        eprintln!(
            "{LOG_PREFIX} virtio-blk[{index}]: {} ({mode}, serial {serial})",
            disk.path
        );
        opened.push((Arc::new(Mutex::new(blk)), id));
    }
    Ok(opened.into_iter().map(|(blk, _)| blk).collect())
}

/// Opens the disks of a boot as [`open_disks`] does, and gives disk 0 the base
/// the boot named, as [`VirtioBlk::take_base`] takes it: `has_base` when it was
/// given `--disk-base-sha256`, and `written` from `--disk-written`.
///
/// `BootConfig::validate` refuses a base without exactly one writable disk, so
/// disk 0 is the guest's only disk whenever there is a base.
///
/// # Errors
///
/// Errors as [`open_disks`] and [`VirtioBlk::take_base`] do.
pub fn open_boot_disks(
    disks: &[config::DiskConfig],
    has_base: bool,
    written: Option<&[u8]>,
) -> Result<Vec<Arc<Mutex<VirtioBlk>>>, String> {
    let opened = open_disks(disks)?;
    if let (Some(dev), Some(disk)) = (opened.first(), disks.first()) {
        lock_or_recover(dev)
            .take_base(&disk.path, has_base, written)
            .map_err(|e| format!("virtio-blk disk 0 ({}): {e}", disk.path))?;
    }
    Ok(opened)
}

/// Writes `src` across the guest segments `segs`, each up to its length, and
/// returns how many bytes were written.
///
/// A source shorter than the segments fills them in order and leaves the rest,
/// which is what `GET_ID` does with a serial shorter than the buffer.
fn scatter(mem: &GuestRam, segs: &[(u64, u32)], mut src: &[u8]) -> std::io::Result<u32> {
    let mut written = 0u32;
    for &(addr, len) in segs {
        let n = (len as usize).min(src.len());
        mem.write(addr, &src[..n]).map_err(other)?;
        src = &src[n..];
        written += n as u32;
    }
    Ok(written)
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

    /// A device over an empty image, so every sector is past the capacity.
    ///
    /// Each call gets a file of its own, since a writable disk locks its image
    /// and the tests run in parallel. The file is unlinked at once; the open
    /// descriptor keeps it.
    fn dev() -> VirtioBlk {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("hvi-dev-{}-{n}.img", std::process::id()));
        std::fs::write(&path, []).unwrap();
        let blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).unwrap();
        blk
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
        assert_eq!(blk.handle_chain(&mem, 0), 0);
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

        assert_eq!(blk.handle_chain(&mem, 0), 0, "the walk stopped at the ring");
        assert_eq!(blk.handle_chain(&mem, 4), 0, "an out-of-ring head as well");
        assert_eq!(blk.handle_chain(&mem, u16::MAX), 0);
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

    // A reader in a container reaches the device through its own node: the
    // node differs in filesystem and inode, the device number is the same.
    #[test]
    fn two_nodes_for_one_block_device_give_one_disk_id() {
        let host = store_id(true, 6, 1200, 0x0800);
        let container = store_id(true, 0x2f, 4, 0x0800);
        assert_eq!(host, container);
        assert_ne!(
            host,
            store_id(true, 6, 1201, 0x0810),
            "another device differs"
        );
    }

    #[test]
    fn disk_id_of_an_image_follows_its_inode() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let a = dir.join(format!("hvi-id-a-{pid}.img"));
        let b = dir.join(format!("hvi-id-b-{pid}.img"));
        let c = dir.join(format!("hvi-id-c-{pid}.img"));
        for p in [&a, &b, &c] {
            let _ = std::fs::remove_file(p);
        }
        std::fs::write(&a, []).unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        std::fs::write(&c, []).unwrap();
        let id = |p: &std::path::Path| disk_id(&std::fs::metadata(p).unwrap());

        assert_eq!(id(&a), id(&b), "two paths to one image give one id");
        assert_ne!(id(&a), id(&c), "another image differs");
        assert_ne!(
            store_id(false, 1, 7, 0),
            store_id(false, 2, 7, 0),
            "one inode number on two filesystems differs"
        );
        for p in [&a, &b, &c] {
            std::fs::remove_file(p).unwrap();
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

        let write_flag = if typ == VIRTIO_BLK_T_IN || typ == VIRTIO_BLK_T_GET_ID {
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

    /// A request type the device does not implement is answered `S_UNSUPP`, not
    /// `S_OK`: a driver told its discard succeeded would trust a range that
    /// still holds the old data.
    #[test]
    fn unknown_request_type_is_unsupported() {
        let (r, mut blk) = rig("unsupp");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let discard = virtio_bindings::virtio_blk::VIRTIO_BLK_T_DISCARD;
        let write_zeroes = virtio_bindings::virtio_blk::VIRTIO_BLK_T_WRITE_ZEROES;
        for typ in [discard, write_zeroes, 0xdead_beef] {
            let st = submit(&mut blk, &mem, typ, 0, 16);
            // The wire value from the spec, not the constant the device uses.
            assert_eq!(st, 2, "type {typ:#x} is VIRTIO_BLK_S_UNSUPP");
            // Only the status byte was written: used.len of the newest entry.
            let used = BASE + 0x3000;
            let slot = u64::from(mem.read_u16(used + 2).unwrap().wrapping_sub(1) % 256);
            assert_eq!(mem.read_u32(used + 4 + slot * 8 + 4).unwrap(), 1);
        }
        assert_eq!(
            std::fs::read(&r.path).unwrap(),
            [0xabu8; 512],
            "nothing reached the disk"
        );
        assert!(blk.take_events().is_empty(), "and no I/O was recorded");
    }

    /// A 1-sector read-only disk on a `0444` image, opened with `serial`.
    fn ro_rig(tag: &str, serial: &str) -> (Rig, VirtioBlk) {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("hvi-ro-{tag}-{}.img", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, [0xabu8; 512]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let blk = VirtioBlk::open_as(path.to_str().unwrap(), true, serial).unwrap();
        (Rig { path }, blk)
    }

    // The ro lower image of an overlay root is 0444 in the store; opening it
    // for writing failed the boot.
    #[test]
    fn read_only_disk_opens_an_image_nobody_may_write() {
        let (r, blk) = ro_rig("open", "disk0");
        assert!(blk.read_only());
        // The rig's handle holds the shared lock, which would refuse a writer
        // on its own; the mode is what this test is about.
        drop(blk);
        // Root writes a 0444 file anyway, so the refusal is only checked for
        // everyone else.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            match VirtioBlk::open_as(r.path.to_str().unwrap(), false, "disk0") {
                Ok(_) => panic!("a writable open of a 0444 image succeeded"),
                Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}"),
            }
        }
    }

    #[test]
    fn read_only_disk_advertises_f_ro() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let (_r, mut ro) = ro_rig("feat", "");
        // The spec's bit numbers, not the constants the device uses:
        // VIRTIO_BLK_F_FLUSH is bit 9, VIRTIO_BLK_F_RO bit 5.
        let features = ro.mmio(&mem, mmio::DEVICE_FEATURES, false, 0) as u32;
        assert_eq!(features, (1 << 9) | (1 << 5));

        let (_w, mut rw) = rig("feat");
        let features = rw.mmio(&mem, mmio::DEVICE_FEATURES, false, 0) as u32;
        assert_eq!(features, 1 << 9, "a writable disk is not ro");
    }

    #[test]
    fn write_to_a_read_only_disk_is_refused() {
        let (r, mut blk) = ro_rig("out", "");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        mem.write(BASE + 0x5000, &[0x11; 512]).unwrap();
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, 0, 512);
        assert_eq!(st, VIRTIO_BLK_S_IOERR);
        assert_eq!(std::fs::read(&r.path).unwrap(), [0xabu8; 512]);
        assert!(blk.take_events().is_empty(), "a refused write is not I/O");

        // Reads still work.
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_IN, 0, 512);
        assert_eq!(st, VIRTIO_BLK_S_OK);
        let mut got = [0u8; 4];
        mem.read(BASE + 0x5000, &mut got).unwrap();
        assert_eq!(got, [0xab; 4]);
    }

    // `submit` chains a data segment, and Linux never sends one with a flush.
    // Either way nothing was written, so the flush succeeds.
    #[test]
    fn flush_on_a_read_only_disk_succeeds() {
        let (_r, mut blk) = ro_rig("flush", "");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_FLUSH, 0, 16);
        assert_eq!(st, VIRTIO_BLK_S_OK);
    }

    // Two guests writing one image corrupt it, and a guest writing an image
    // another reads changes what the reader sees. A read-only image is shared,
    // as hull shares one lower image across sandboxes.
    #[test]
    fn open_disks_lock_the_image_by_mode() {
        use std::os::unix::fs::PermissionsExt;
        let refused = |path: &str, read_only: bool| match VirtioBlk::open_as(path, read_only, "") {
            Ok(_) => panic!("{path} opened while locked"),
            Err(err) => {
                assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock, "{err}");
                err.to_string()
            }
        };
        let (r, _ro) = ro_rig("lock", "");
        let path = r.path.to_str().unwrap();
        VirtioBlk::open_as(path, true, "").expect("a second reader");
        // Root may write a 0444 file, so the writer's refusal has to come from
        // the lock, which is what this checks on every uid.
        std::fs::set_permissions(&r.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(refused(path, false).contains("open"));

        let (w, writer) = rig("lock");
        let path = w.path.to_str().unwrap();
        refused(path, false);
        assert!(refused(path, true).contains("for writing"));
        drop(writer);
        VirtioBlk::open_as(path, true, "").expect("the lock went with the writer");
    }

    // One image may back two read-only disks of a guest. With a writer among
    // them the message names the other disk, where the lock alone would say
    // "elsewhere".
    #[test]
    fn open_disks_names_the_other_disk_on_one_image() {
        use std::os::unix::fs::PermissionsExt;
        let (r, blk) = ro_rig("twice", "");
        drop(blk);
        // The writer below has to get as far as the duplicate check.
        std::fs::set_permissions(&r.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = r.path.to_str().unwrap();
        let ro = |serial: &str| config::DiskConfig {
            path: path.to_string(),
            read_only: true,
            serial: Some(serial.to_string()),
        };
        assert_eq!(open_disks(&[ro("a"), ro("b")]).unwrap().len(), 2);
        let refused = |disks: &[config::DiskConfig]| match open_disks(disks) {
            Ok(_) => panic!("one image opened twice with a writer"),
            Err(err) => err,
        };
        let err = refused(&[ro("a"), config::DiskConfig::rw(path)]);
        assert!(err.contains("disk 1") && err.contains("is disk 0"), "{err}");
        let err = refused(&[config::DiskConfig::rw(path), ro("b")]);
        assert!(err.contains("which this guest writes"), "{err}");
    }

    #[test]
    fn get_id_returns_the_zero_padded_serial() {
        let (_r, mut blk) = ro_rig("id", "disk1");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        mem.write(BASE + 0x5000, &[0xff; 32]).unwrap();
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_GET_ID, 0, SERIAL_LEN as u32);
        assert_eq!(st, VIRTIO_BLK_S_OK);
        let mut got = [0u8; 32];
        mem.read(BASE + 0x5000, &mut got).unwrap();
        let mut want = [0u8; SERIAL_LEN];
        want[..5].copy_from_slice(b"disk1");
        assert_eq!(&got[..SERIAL_LEN], &want);
        assert_eq!(&got[SERIAL_LEN..], &[0xff; 12], "nothing past the buffer");
        assert_eq!(
            mem.read_u32(BASE + 0x3000 + 8).unwrap(),
            SERIAL_LEN as u32 + 1,
            "the used length counts the serial and the status byte"
        );
    }

    #[test]
    fn get_id_stops_at_a_short_buffer() {
        let (r, _) = rig("idshort");
        let mut blk = VirtioBlk::open_as(r.path.to_str().unwrap(), false, "disk3").unwrap();
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        mem.write(BASE + 0x5000, &[0xff; 8]).unwrap();
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_GET_ID, 0, 3);
        assert_eq!(st, VIRTIO_BLK_S_OK);
        let mut got = [0u8; 4];
        mem.read(BASE + 0x5000, &mut got).unwrap();
        assert_eq!(&got, b"dis\xff");
    }

    // The guest finds its disks by serial, so position N in the disk list has
    // to answer GET_ID with disk<N> and keep its own access mode.
    #[test]
    fn open_disks_gives_each_position_its_serial_and_mode() {
        let (a, _) = ro_rig("argv-a", "");
        let (b, _) = rig("argv-b");
        let disks = open_disks(&[
            config::DiskConfig::ro(a.path.to_str().unwrap()),
            config::DiskConfig::rw(b.path.to_str().unwrap()),
        ])
        .unwrap();
        assert_eq!(disks.len(), 2);
        for (index, (dev, read_only)) in disks.iter().zip([true, false]).enumerate() {
            let mut blk = dev.lock().unwrap();
            assert_eq!(blk.read_only(), read_only, "disk {index}");
            let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
            let st = submit(&mut blk, &mem, VIRTIO_BLK_T_GET_ID, 0, 20);
            assert_eq!(st, 0, "disk {index} answered GET_ID");
            let mut got = [0u8; 20];
            mem.read(BASE + 0x5000, &mut got).unwrap();
            let mut want = [0u8; 20];
            want[..5].copy_from_slice(format!("disk{index}").as_bytes());
            assert_eq!(got, want, "disk {index}");
        }
    }

    #[test]
    fn serial_longer_than_the_id_field_is_refused() {
        let (r, blk) = rig("idlong");
        // The rig's own handle holds the image's lock.
        drop(blk);
        let long = "x".repeat(SERIAL_LEN + 1);
        assert!(VirtioBlk::open_as(r.path.to_str().unwrap(), false, &long).is_err());
        let exact = "x".repeat(SERIAL_LEN);
        VirtioBlk::open_as(r.path.to_str().unwrap(), false, &exact).expect("20 bytes fit");
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
        assert_eq!(mem.read_u16(USED + 2).unwrap(), 2, "two chains used");
        assert_eq!(mem.read_u16(BASE + 0x6000).unwrap() as u8, VIRTIO_BLK_S_OK);
        assert_eq!(restored.state().queue.last_avail, 2);

        // Its generation goes on from the checkpoint's: a read leaves it,
        // and a flush moves it on by one.
        assert_eq!(restored.generation(), 1046);
        post_read(&mem, 2);
        mem.write_u32(BASE + 0x4000, VIRTIO_BLK_T_FLUSH).unwrap();
        restored.mmio(&mem, mmio::QUEUE_NOTIFY, true, 0);
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
    /// goes. The lock is the one `open_as` takes; what the release adds is
    /// that a fenced device lets it go and keeps the disk open.
    #[test]
    fn a_disk_is_the_disk_of_one_device_at_a_time() {
        let disk = Disk::new("lock", 2);
        let mut first = VirtioBlk::open(disk.path()).unwrap();
        let err = VirtioBlk::open(disk.path())
            .err()
            .expect("a second device opened a locked disk");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        assert!(
            err.to_string().contains("the image is open elsewhere"),
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
                version: BLK_STATE_VERSION + 1,
                ..good.clone()
            },
            // The format before the serial and the read-only flag.
            BlkState {
                version: 1,
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

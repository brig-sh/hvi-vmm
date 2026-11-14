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

//! The virtio-blk device behind the transport, and the image it opens.

use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(target_os = "linux")]
use vmm_sys_util::eventfd::EventFd;

use super::worker::{Shared, DEFAULT_POLL_MAX};
use crate::config;
use crate::devices::virtio::mmio::Interrupt;
use crate::devices::virtio::{self, read_config_bytes, Queue, QUEUE_MAX_SIZE};
use crate::memory::GuestRam;
use crate::plugin::IoSink;
use crate::LOG_PREFIX;

/// The `VIRTIO_BLK_F_FLUSH` feature bit, which lets the guest issue explicit
/// cache-flush requests.
///
/// With it, an `fsync` in the guest reaches stable storage on the host.
const F_FLUSH: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_FLUSH;
/// The `VIRTIO_BLK_F_RO` feature bit, which tells the guest the disk is
/// read-only.
///
/// Linux marks the guest's block device read-only to match.
const F_RO: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_RO;

/// Length of the serial `GET_ID` returns, zero-padded.
pub const SERIAL_LEN: usize = virtio_bindings::virtio_blk::VIRTIO_BLK_ID_BYTES as usize;

pub(super) const SECTOR: u64 = 512;

/// A virtio-blk device behind a virtio-mmio transport.
///
/// It holds what the registers read, and the state it shares with its worker,
/// which `take_worker` returns.
pub struct VirtioBlk {
    /// The backing file, until the worker takes it.
    pub(super) file: Option<File>,
    /// The disk's size in 512-byte sectors.
    pub(super) capacity_sectors: u64,
    /// Whether the backing file is open read-only and every write is refused.
    pub(super) read_only: bool,
    /// What `GET_ID` returns, zero-padded.
    pub(super) serial: [u8; SERIAL_LEN],
    /// The serial as given, for the ledger.
    pub(super) serial_text: Arc<str>,
    /// Stable id for this backing file, so a reader can tell two disks apart.
    pub(super) disk_id: u64,
    /// The state the device shares with its worker.
    pub(super) shared: Arc<Shared>,
    /// The longest the worker polls an empty ring before it sleeps.
    pub(super) poll_max: Duration,
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

    /// Opens `path` as the backing disk, read-only when `read_only` is set, for
    /// a device that answers `GET_ID` with `serial`.
    ///
    /// A read-only disk is opened `O_RDONLY`, so an image the VMM cannot write
    /// still attaches, and the guest is told it is read-only.
    ///
    /// The file is locked for as long as it is open, shared for a read-only
    /// disk and exclusive for a writable one, so two hvi processes never write
    /// one image at once and no hvi writes an image another one reads. One
    /// read-only image can back any number of guests. A writable block device
    /// is opened `O_EXCL` on Linux as well, which claims the device itself and
    /// so holds against another device node for it and against a mount. A
    /// read-only open claims nothing, so a reader through another node is not
    /// held against a writer.
    ///
    /// # Errors
    ///
    /// Errors if `serial` is longer than [`SERIAL_LEN`] bytes, the file cannot
    /// be opened or its length read, a lock on it that this one excludes is
    /// held, or the worker's wake cannot be made.
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
        let mut tries = if block_device {
            BLOCK_DEVICE_LOCK_TRIES
        } else {
            1
        };
        loop {
            tries -= 1;
            match lock(&file, read_only) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && tries > 0 => {
                    std::thread::sleep(BLOCK_DEVICE_LOCK_PAUSE);
                }
                taken => break taken?,
            }
        }
        let capacity_sectors = backing_len(&file)? / SECTOR;
        // The backing store is identified across the two processes that care
        // about it without agreeing on a path: hvi may have been given a
        // relative one, and the reader is given its own.
        let disk_id = disk_id(&file.metadata()?);
        Ok(VirtioBlk {
            file: Some(file),
            capacity_sectors,
            read_only,
            serial: id,
            serial_text: Arc::from(serial),
            disk_id,
            shared: Arc::new(Shared::new()?),
            poll_max: DEFAULT_POLL_MAX,
        })
    }

    /// Returns whether the disk is read-only.
    #[cfg(test)]
    pub(crate) fn read_only(&self) -> bool {
        self.read_only
    }

    /// Sets the longest the disk's worker polls an empty ring before it sleeps,
    /// in place of [`DEFAULT_POLL_MAX`].
    ///
    /// Zero means the worker never polls. It takes effect for a worker taken
    /// after the call.
    pub fn set_poll_max(&mut self, longest: Duration) {
        self.poll_max = longest;
    }

    /// Feeds each request to `sink` as well as the ledger.
    pub fn set_io_sink(&self, sink: Arc<dyn IoSink>) {
        self.shared.lock().sink.set(sink);
    }
}

impl virtio::Device for VirtioBlk {
    fn device_type(&self) -> u32 {
        virtio_bindings::virtio_ids::VIRTIO_ID_BLOCK
    }

    fn features(&self) -> u64 {
        if self.read_only {
            F_FLUSH | F_RO
        } else {
            F_FLUSH
        }
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &[QUEUE_MAX_SIZE]
    }

    // The configuration space starts with the capacity, in 512-byte sectors.
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        read_config_bytes(&self.capacity_sectors.to_le_bytes(), offset, data);
    }

    fn activate(
        &mut self,
        _ram: &GuestRam,
        _driver_features: u64,
        queues: Vec<Option<Queue>>,
        interrupt: Arc<Interrupt>,
    ) -> std::io::Result<()> {
        let queue = <[Option<Queue>; 1]>::try_from(queues)
            .ok()
            .and_then(|[queue]| queue);
        self.shared.activate(queue, interrupt);
        Ok(())
    }

    fn notify(&mut self, _ram: &GuestRam, _queue: u16) {
        self.shared.wake.signal();
    }

    #[cfg(target_os = "linux")]
    fn notify_fds(&self) -> &[EventFd] {
        std::slice::from_ref(self.shared.wake.eventfd())
    }

    // The reset waits for a request in flight, as `Shared::reset` describes.
    // The transport holds its state lock until it returns, so a later
    // activation cannot hand the worker a new queue while an old request is
    // still in flight.
    fn reset(&mut self) {
        self.shared.reset();
    }

    // The worker serves the queue from its own wake and from its poll, which
    // the transport's refusal of a notification does not reach.
    fn driver_failed(&mut self) {
        self.shared.reset();
    }
}

/// Returns the size in bytes of whatever is behind `file`.
///
/// `metadata().len()` is the *file* size, which is 0 for a block special file.
/// A disk image sizes correctly from it, but a block device sized from it would
/// advertise a zero-sector virtio-blk. The guest would then register `/dev/vda`
/// normally and fail every read, and the console would say "unable to read
/// superblock" rather than anything about a missing disk.
///
/// Container runtimes pass such a device. urunc passes the devmapper snapshot
/// of the container's rootfs (`/dev/mapper/...`), not a file. The size of a
/// block device therefore comes from the kernel.
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

/// Returns the id `IoSink::on_block` reports for the backing store `meta`
/// describes, which a reader derives from its own path to the same store.
///
/// For a block device it is the device number, `st_rdev`, so every node for one
/// device gives one id. For a regular file it is `st_dev` rotated left by 32
/// bits, xor `st_ino`, so two images on different filesystems with one inode
/// number differ.
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
pub(super) fn store_id(block_device: bool, dev: u64, ino: u64, rdev: u64) -> u64 {
    if block_device {
        rdev
    } else {
        dev.rotate_left(32) ^ ino
    }
}

/// Opens every disk in `disks` in order, each with the [`serial_at`] its
/// position.
///
/// It logs each disk it opens.
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
        let mut blk =
            VirtioBlk::open_as(&disk.path, disk.read_only, &serial).map_err(|e| fail(&e))?;
        blk.set_poll_max(disk.poll_max.unwrap_or(DEFAULT_POLL_MAX));
        let mode = if disk.read_only { "ro" } else { "rw" };
        eprintln!(
            "{LOG_PREFIX} virtio-blk[{index}]: {} ({mode}, serial {serial})",
            disk.path
        );
        opened.push((Arc::new(Mutex::new(blk)), id));
    }
    Ok(opened.into_iter().map(|(blk, _)| blk).collect())
}

#[cfg(test)]
mod backing_len_tests {
    use super::backing_len;

    #[test]
    fn regular_file_reports_its_length() {
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

    // A block special file has a file length of 0, so sizing a virtio-blk from
    // `metadata().len()` would give the guest a 0-sector disk. This test needs
    // a real block device. When `HVI_BLOCK_DEV` names one, the device must be
    // usable, since a skip would drop the coverage the variable asks for.
    // Without it the test scans for one, and reports rather than fails when
    // none is openable.
    #[cfg(target_os = "linux")]
    #[test]
    fn block_device_reports_the_device_size() {
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

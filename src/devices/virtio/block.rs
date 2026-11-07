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
//! The device has one queue, served on the vCPU that notifies it.
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

use crate::config;
use crate::memory::GuestRam;
use crate::LOG_PREFIX;

use crate::devices::virtio::mmio::Interrupt;
use crate::devices::virtio::{
    self, read_config_bytes, DeviceState, Queue, SinkSlot, QUEUE_MAX_SIZE, VIRTQ_DESC_F_NEXT,
    VIRTQ_DESC_F_WRITE,
};
use crate::events::CapturedEvent;
use crate::plugin::IoSink;

/// `VIRTIO_BLK_F_FLUSH`: the guest may issue explicit cache-flush requests.
///
/// With it, an `fsync` in the guest reaches stable storage on the host.
const F_FLUSH: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_FLUSH;
/// `VIRTIO_BLK_F_RO`: the disk is read-only, and Linux marks the guest's block
/// device read-only to match.
const F_RO: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_RO;

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

/// A virtio-blk device behind a virtio-mmio transport.
pub struct VirtioBlk {
    /// The backing file.
    file: File,
    /// The disk's size in 512-byte sectors.
    capacity_sectors: u64,
    /// The request queue.
    queue: Queue,
    /// The activation state, with the interrupt once active.
    state: DeviceState,
    /// Captured requests, drained by the hypervisor backend into the event
    /// ledger.
    events: Vec<CapturedEvent>,
    /// Live feed of each request to a plugin, when one asked for it. The
    /// same requests the ledger records, handed over as they happen rather
    /// than drained after the fact.
    sink: SinkSlot,
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

/// Returns the id `IoSink::on_block` reports for the backing store `meta`
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
    /// read-only image can back any number of guests. A writable block device
    /// is opened `O_EXCL` on Linux as well, which claims the device itself and
    /// so holds against another device node for it and against a mount. A
    /// read-only open claims nothing, so a reader through another node is not
    /// held against a writer.
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
            file,
            capacity_sectors,
            queue: Queue::new(QUEUE_MAX_SIZE),
            state: DeviceState::Inactive,
            events: Vec::new(),
            sink: SinkSlot::default(),
            disk_id,
            read_only,
            serial: id,
            serial_text: Arc::from(serial),
            trace: std::env::var_os("HVI_BLK_TRACE").is_some(),
        })
    }

    /// Returns whether the disk is read-only.
    #[cfg(test)]
    pub(crate) fn read_only(&self) -> bool {
        self.read_only
    }

    /// Feeds each request to `sink` as well as the ledger.
    pub fn set_io_sink(&mut self, sink: Arc<dyn IoSink>) {
        self.sink.set(sink);
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
            self.state.signal_used_buffer();
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
                self.file.write_all_at(&buf, base).map_err(other)?;
                data_bytes = total as u64;
                VIRTIO_BLK_S_OK
            }
            VIRTIO_BLK_T_FLUSH => {
                // Honour the guest's cache flush (durability for fsync).
                self.file.sync_data().map_err(other)?;
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
            self.sink
                .feed(|sink| sink.on_block(sector, data_bytes, self.disk_id, write));
        }
        Ok(device_written)
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
        queues: Vec<Queue>,
        interrupt: Arc<Interrupt>,
    ) -> std::io::Result<()> {
        if let Ok([queue]) = <[Queue; 1]>::try_from(queues) {
            self.queue = queue;
        }
        self.state = DeviceState::Active(interrupt);
        Ok(())
    }

    fn notify(&mut self, ram: &GuestRam, _queue: u16) {
        if self.state.is_active() {
            self.process_queue(ram);
        }
    }

    fn reset(&mut self) {
        self.queue = Queue::new(QUEUE_MAX_SIZE);
        self.state = DeviceState::Inactive;
    }

    fn take_events(&mut self) -> Vec<CapturedEvent> {
        std::mem::take(&mut self.events)
    }

    fn take_fed_sink(&mut self) -> Option<Arc<dyn IoSink>> {
        self.sink.take_fed()
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
    use crate::devices::virtio::mmio::testing::{self, Driver, Rings};
    use crate::devices::virtio::Device as _;

    const BASE: u64 = 0x4000_0000;

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

    /// Returns a fresh device activated with a 4-entry queue at the start of
    /// `mem`.
    fn activated(mem: &GuestRam) -> VirtioBlk {
        let mut blk = dev();
        let rings = Rings {
            size: 4,
            desc_table: BASE,
            avail_ring: BASE + 0x1000,
            used_ring: BASE + 0x2000,
        };
        let queue = testing::ready_queue(QUEUE_MAX_SIZE, rings, mem);
        let (interrupt, _) = testing::enabled_interrupt();
        blk.activate(mem, 0, vec![queue], interrupt).unwrap();
        blk
    }

    #[test]
    fn common_registers_follow_virtio_1_2() {
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x4000)]));
        let rings = Rings {
            size: 8,
            desc_table: BASE,
            avail_ring: BASE + 0x1000,
            used_ring: BASE + 0x2000,
        };
        testing::assert_common_registers(dev(), &mem, rings);
    }

    /// A chain that points back at itself must run out of budget rather than
    /// spin. The only bound on the walk is the ring size, so the shape to
    /// test is a cycle of *writable* descriptors: nothing accumulates, so
    /// no other limit can end it.
    #[test]
    fn a_descriptor_cycle_runs_out_of_budget() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x4000)]);
        let mut blk = activated(&mem);

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
        let mut blk = activated(&mem);

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
        let blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();

        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x8000)]));
        let (desc, avail, used) = (BASE, BASE + 0x2000, BASE + 0x3000);
        let buffers = BASE + 0x4000;
        let driver = Driver::new(blk, &mem);
        driver.start(&[Rings {
            size: 8,
            desc_table: desc,
            avail_ring: avail,
            used_ring: used,
        }]);
        publish_read(&mem, desc, avail, buffers);
        driver.notify(0);
        let _ = std::fs::remove_file(&path);

        let mut got = [0u8; 5];
        mem.read(buffers + 0x100, &mut got).unwrap();
        assert_eq!(&got, b"HELLO", "the sector reached guest memory");
        assert_eq!(mem.read_u16(used + 2).unwrap(), 1, "used.idx advanced");
        assert!(driver.line.is_high(), "used-buffer interrupt asserted");
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
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x8000)]));
        let driver = Driver::new(dev(), &mem);

        driver.start(&[Rings {
            size: 8,
            desc_table: BASE,
            avail_ring: BASE + 0x1000,
            used_ring: BASE + 0x2000,
        }]);
        publish_read(&mem, BASE, BASE + 0x1000, BASE + 0x6000);
        driver.notify(0);
        assert_eq!(
            mem.read_u16(BASE + 0x2000 + 2).unwrap(),
            1,
            "used.idx before the reset"
        );

        driver.reset();
        driver.start(&[Rings {
            size: 8,
            desc_table: BASE + 0x3000,
            avail_ring: BASE + 0x4000,
            used_ring: BASE + 0x5000,
        }]);
        publish_read(&mem, BASE + 0x3000, BASE + 0x4000, BASE + 0x7000);
        driver.notify(0);
        assert_eq!(
            mem.read_u16(BASE + 0x5000 + 2).unwrap(),
            1,
            "the request published after the reset was serviced"
        );
        // `dev()` backs the disk with an empty image, so the read fails with
        // IOERR. A written status byte shows the chain was walked.
        assert_eq!(
            mem.read_u16(BASE + 0x7000 + 0x400).unwrap() as u8,
            VIRTIO_BLK_S_IOERR
        );
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use crate::devices::virtio::mmio::testing::{self, Rings};
    use crate::devices::virtio::Device as _;

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

    /// Returns a writable 1-sector disk over an image of `0xab` bytes, and the
    /// guard that removes the image.
    fn rig(tag: &str) -> (Rig, VirtioBlk) {
        let path = std::env::temp_dir().join(format!("hvi-cap-{tag}-{}.img", std::process::id()));
        std::fs::write(&path, [0xabu8; 512]).unwrap();
        let blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();
        (Rig { path }, blk)
    }

    /// Submits one request and returns the status byte the device wrote.
    ///
    /// The first request activates the device with a 256-entry queue, and each
    /// request takes the next entry of the avail ring.
    fn submit(blk: &mut VirtioBlk, mem: &GuestRam, typ: u32, sector: u64, len: u32) -> u8 {
        let (desc, avail, used) = (BASE, BASE + 0x2000, BASE + 0x3000);
        if !blk.state.is_active() {
            let rings = Rings {
                size: 256,
                desc_table: desc,
                avail_ring: avail,
                used_ring: used,
            };
            let queue = testing::ready_queue(QUEUE_MAX_SIZE, rings, mem);
            let (interrupt, _) = testing::enabled_interrupt();
            blk.activate(mem, 0, vec![queue], interrupt).unwrap();
        }
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

        blk.notify(mem, 0);
        mem.read_u16(status).unwrap() as u8
    }

    /// A sink that counts the requests it is fed.
    #[derive(Default)]
    struct CountingSink(std::sync::atomic::AtomicUsize);

    impl IoSink for CountingSink {
        fn on_block(&self, _sector: u64, _length: u64, _disk_id: u64, _write: bool) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn on_net(&self, _frame: &[u8], _egress: bool) {}
    }

    #[test]
    fn request_that_reaches_the_disk_feeds_its_sink_once() {
        let (_r, mut blk) = rig("fed");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let sink = Arc::new(CountingSink::default());
        blk.set_io_sink(Arc::clone(&sink) as Arc<dyn IoSink>);
        assert_eq!(
            submit(&mut blk, &mem, VIRTIO_BLK_T_IN, 0, 512),
            VIRTIO_BLK_S_OK
        );
        assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        let fed = blk.take_fed_sink().expect("the request fed the sink");
        assert!(std::ptr::addr_eq(Arc::as_ptr(&fed), Arc::as_ptr(&sink)));
        assert!(blk.take_fed_sink().is_none(), "the sink is taken once");
    }

    #[test]
    fn refused_request_feeds_no_sink() {
        let (_r, mut blk) = rig("unfed");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let sink = Arc::new(CountingSink::default());
        blk.set_io_sink(Arc::clone(&sink) as Arc<dyn IoSink>);
        let status = submit(&mut blk, &mem, VIRTIO_BLK_T_IN, 9_999, 512);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(blk.take_fed_sink().is_none());
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
        let (_r, ro) = ro_rig("feat", "");
        // The spec's bit numbers, not the constants the device uses:
        // VIRTIO_BLK_F_FLUSH is bit 9, VIRTIO_BLK_F_RO bit 5.
        assert_eq!(ro.features(), (1 << 9) | (1 << 5));

        let (_w, rw) = rig("feat");
        assert_eq!(rw.features(), 1 << 9, "a writable disk is not ro");
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

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
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this
// VMM's own.
#![allow(clippy::disallowed_methods)]

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use crate::memory::GuestRam;

use crate::devices::irq::{Irq, IrqLine};
use crate::devices::virtio::{mmio, Queue, QUEUE_NUM_MAX, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::events::CapturedEvent;
use crate::plugin::IoSink;

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
/// Answering `S_OK` instead tells the driver a request it depends on, such as
/// a discard, did its work when it did nothing at all.
const VIRTIO_BLK_S_UNSUPP: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_UNSUPP as u8;

const SECTOR: u64 = 512;

/// A virtio-blk device behind a virtio-mmio transport.
pub struct VirtioBlk {
    file: File,
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

impl VirtioBlk {
    /// Opens `path` read-write as the backing disk, with an empty serial.
    ///
    /// # Errors
    ///
    /// Errors if the file cannot be opened or its length read.
    pub fn open(path: &str) -> std::io::Result<Self> {
        Self::open_as(path, false, "")
    }

    /// Opens `path` as the backing disk, read-only when `read_only` is set,
    /// and answers `GET_ID` with `serial`.
    ///
    /// A read-only disk is opened `O_RDONLY`, so an image the VMM cannot write
    /// still attaches, and the guest is told it is read-only.
    ///
    /// # Errors
    ///
    /// Errors if `serial` is longer than [`SERIAL_LEN`] bytes, or the file
    /// cannot be opened or its length read.
    pub fn open_as(path: &str, read_only: bool, serial: &str) -> std::io::Result<Self> {
        if serial.len() > SERIAL_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("virtio-blk serial {serial:?} is longer than {SERIAL_LEN} bytes"),
            ));
        }
        let mut id = [0u8; SERIAL_LEN];
        id[..serial.len()].copy_from_slice(serial.as_bytes());
        let file = OpenOptions::new().read(true).write(!read_only).open(path)?;
        let capacity_sectors = backing_len(&file)? / SECTOR;
        // The inode identifies the backing store across the two processes that
        // care about it, without agreeing on a path: hvi may have been given a
        // relative one, and the reader is given its own.
        let disk_id = file.metadata().map(|m| m.ino()).unwrap_or(0);
        Ok(VirtioBlk {
            file,
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
            trace: std::env::var_os("HVI_BLK_TRACE").is_some(),
        })
    }

    /// Returns whether the disk is read-only.
    #[must_use]
    pub fn read_only(&self) -> bool {
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

    /// Connects the device to the interrupt line it raises.
    pub(crate) fn connect_irq(&mut self, line: Arc<dyn IrqLine>) {
        self.irq.connect(line);
    }

    /// Sets the interrupt line to the device's level.
    fn sync_irq(&mut self) {
        self.irq.set(self.irq_level());
    }

    /// Drains the captured requests for the event ledger.
    pub fn take_events(&mut self) -> Vec<CapturedEvent> {
        std::mem::take(&mut self.events)
    }

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
                    eprint!("\r\n[virtio-blk] request failed: {e}\r\n");
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
                let mut o = 0;
                for &(a, l) in segs {
                    mem.write(a, &buf[o..o + l as usize]).map_err(other)?;
                    o += l as usize;
                    device_written += l;
                }
                data_bytes = total as u64;
                VIRTIO_BLK_S_OK
            }
            // The guest was offered VIRTIO_BLK_F_RO. A write that arrives
            // anyway fails, and so does a flush carrying data.
            VIRTIO_BLK_T_OUT if self.read_only => VIRTIO_BLK_S_IOERR,
            VIRTIO_BLK_T_FLUSH if self.read_only && (readable.len() > 1 || writable.len() > 1) => {
                VIRTIO_BLK_S_IOERR
            }
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
                let mut src = &self.serial[..];
                for &(a, l) in &writable[..writable.len() - 1] {
                    let n = (l as usize).min(src.len());
                    mem.write(a, &src[..n]).map_err(other)?;
                    src = &src[n..];
                    device_written += n as u32;
                }
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
            eprint!(
                "\r\n[virtio-blk] {kind} sector={sector} bytes={data_bytes} status={status}\r\n"
            );
        }
        // Only a read or write that went through is I/O on the disk. A flush
        // carries no data range, and a refused write moved nothing.
        if status == VIRTIO_BLK_S_OK && (typ == VIRTIO_BLK_T_IN || typ == VIRTIO_BLK_T_OUT) {
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
        Ok(device_written)
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

    /// A request type the device does not implement is answered `S_UNSUPP`,
    /// not `S_OK`: a driver told its discard succeeded would trust a range
    /// that still holds the old data.
    #[test]
    fn an_unknown_request_type_is_unsupported() {
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
    fn a_read_only_disk_opens_an_image_nobody_may_write() {
        let (r, blk) = ro_rig("open", "disk0");
        assert!(blk.read_only());
        let err = VirtioBlk::open_as(r.path.to_str().unwrap(), false, "disk0");
        // Root writes a 0444 file anyway, so the refusal is only checked for
        // everyone else.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            assert!(err.is_err(), "a writable open of a 0444 image fails");
        }
    }

    #[test]
    fn a_read_only_disk_advertises_f_ro() {
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
    fn a_write_to_a_read_only_disk_is_refused() {
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

    // `submit` always chains a data segment, so this flush carries data.
    #[test]
    fn a_flush_with_data_on_a_read_only_disk_is_refused() {
        let (_r, mut blk) = ro_rig("flush", "");
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_FLUSH, 0, 16);
        assert_eq!(st, VIRTIO_BLK_S_IOERR);
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

    #[test]
    fn a_serial_longer_than_the_id_field_is_refused() {
        let (r, _blk) = rig("idlong");
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

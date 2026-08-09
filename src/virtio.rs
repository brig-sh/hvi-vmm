//! A minimal virtio-mmio transport with a split virtqueue and a virtio-blk
//! device. Being the device is what lets the VMM record the guest's disk I/O
//! as it serves it.
//!
//! Because this VMM implements the device backend, every block request the
//! guest issues passes through our code by construction: servicing the
//! virtqueue and capturing the guest's disk I/O are the same act (see the
//! `[virtio-blk]` log lines). The virtqueue machinery here is device-agnostic
//! and will carry virtio-net (the network boundary) next.
//!
//! Modern virtio-mmio (version 2) is implemented — enough for the Linux
//! `virtio_mmio` + `virtio_blk` drivers to negotiate `VIRTIO_F_VERSION_1`,
//! set up one queue, and do reads/writes.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use crate::guestmem::GuestRam;

use crate::events::CapturedEvent;
use crate::plugin::IoSink;

/// virtio-mmio register offsets (subset we implement). Shared with virtio-net.
pub(crate) mod reg {
    pub const MAGIC: u64 = 0x000; // "virt"
    pub const VERSION: u64 = 0x004; // 2
    pub const DEVICE_ID: u64 = 0x008;
    pub const VENDOR_ID: u64 = 0x00c;
    pub const DEVICE_FEATURES: u64 = 0x010;
    pub const DEVICE_FEATURES_SEL: u64 = 0x014;
    pub const DRIVER_FEATURES: u64 = 0x020;
    pub const DRIVER_FEATURES_SEL: u64 = 0x024;
    pub const QUEUE_SEL: u64 = 0x030;
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    pub const QUEUE_NUM: u64 = 0x038;
    pub const QUEUE_READY: u64 = 0x044;
    pub const QUEUE_NOTIFY: u64 = 0x050;
    pub const INTERRUPT_STATUS: u64 = 0x060;
    pub const INTERRUPT_ACK: u64 = 0x064;
    pub const STATUS: u64 = 0x070;
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    pub const QUEUE_DESC_HIGH: u64 = 0x084;
    pub const QUEUE_DRIVER_LOW: u64 = 0x090; // avail ring
    pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
    pub const QUEUE_DEVICE_LOW: u64 = 0x0a0; // used ring
    pub const QUEUE_DEVICE_HIGH: u64 = 0x0a4;
    pub const CONFIG: u64 = 0x100;
}

const MAGIC_VALUE: u64 = 0x7472_6976; // "virt" little-endian
const VIRTIO_BLK_ID: u64 = 2;
const VENDOR: u64 = 0x4649_4f4e; // "NOIF"

/// `VIRTIO_F_VERSION_1` (feature bit 32) — required for a modern device.
const F_VERSION_1_HI: u32 = 1; // bit 0 of the high 32-bit word
/// `VIRTIO_BLK_F_FLUSH` (feature bit 9, low word): the guest may issue explicit
/// cache-flush requests. Advertising and honouring it gives correct durability
/// semantics for `fsync`/`end_fsync` workloads instead of the guest guessing.
const F_BLK_FLUSH_LO: u32 = 1 << 9;

/// Descriptor flags.
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// virtio-blk request types.
const VIRTIO_BLK_T_IN: u32 = 0; // read disk -> guest
const VIRTIO_BLK_T_OUT: u32 = 1; // guest -> write disk
const VIRTIO_BLK_T_FLUSH: u32 = 4; // flush the device cache

/// virtio-blk status byte.
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;

const SECTOR: u64 = 512;

/// Largest queue size we advertise in `QUEUE_NUM_MAX`, and so the largest a
/// driver may legally program.
pub(crate) const QUEUE_NUM_MAX: u32 = 256;

/// One virtqueue's driver-programmed state. Shared with virtio-net and
/// virtio-vsock.
///
/// Every field here is driver-controlled, so the fields are private and the
/// validation lives in the setters: this is the single place where a hostile
/// queue programming is rejected. In particular `num` is only ever stored if it
/// is a non-zero power of two no greater than [`QUEUE_NUM_MAX`], which is what
/// makes [`Queue::size`] a `u16` that can be used as a modulus. Storing the raw
/// `u32` and truncating at the point of use was a guest-triggerable panic
/// (`0x10000` is non-zero as a `u32` and zero as a `u16`).
#[derive(Default)]
pub(crate) struct Queue {
    num: u32,
    ready: bool,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
}

impl Queue {
    /// Records the driver's queue size, ignoring anything the spec does not
    /// allow. A rejected size leaves the queue unusable rather than trusted.
    pub(crate) fn set_num(&mut self, v: u32) {
        self.num = if v != 0 && v <= QUEUE_NUM_MAX && v.is_power_of_two() {
            v
        } else {
            0
        };
        self.ready = false; // resizing invalidates the ring bounds we checked
    }

    /// The validated ring size. Zero means the driver has not programmed a
    /// usable queue, and every caller must treat it as "do nothing".
    pub(crate) fn size(&self) -> u16 {
        self.num as u16 // <= QUEUE_NUM_MAX by construction in `set_num`
    }

    /// Marks the queue ready, but only once the size is valid and all three
    /// rings fit inside guest RAM at the addresses the driver gave us.
    pub(crate) fn set_ready(&mut self, v: u32, mem: &GuestRam) {
        self.ready = v & 1 == 1 && self.rings_fit(mem);
    }

    /// True once the driver has a usable, in-bounds queue.
    pub(crate) fn is_ready(&self) -> bool {
        self.ready && self.num != 0
    }

    /// Split-virtqueue ring extents: descriptor table `16*n`, avail ring
    /// `6+2*n`, used ring `6+8*n` (each includes the 2-byte event suffix).
    fn rings_fit(&self, mem: &GuestRam) -> bool {
        let n = u64::from(self.num);
        n != 0
            && mem.contains(self.desc, 16 * n)
            && mem.contains(self.avail, 6 + 2 * n)
            && mem.contains(self.used, 6 + 8 * n)
    }

    /// Address of descriptor `d`, or `None` if the driver referenced an index
    /// outside the ring it programmed.
    pub(crate) fn desc_addr(&self, d: u16) -> Option<u64> {
        (u32::from(d) < self.num).then(|| self.desc + u64::from(d) * 16)
    }

    /// Address of the avail ring's `idx`-th slot, wrapped into the ring.
    pub(crate) fn avail_slot(&self, idx: u16) -> Option<u64> {
        let n = self.size();
        (n != 0).then(|| self.avail + 4 + u64::from(idx % n) * 2)
    }

    /// How many buffers the driver has published since `last_avail`.
    ///
    /// `None` if `avail.idx` is unreadable, or if it claims more than a ring's
    /// worth -- which no conforming driver can do, and which would otherwise
    /// let a single notify drive up to 65535 descriptor-chain walks.
    pub(crate) fn pending(&self, mem: &GuestRam) -> Option<u16> {
        let idx = mem.read_u16(self.avail + 2).ok()?;
        let n = idx.wrapping_sub(self.last_avail);
        (n <= self.size()).then_some(n)
    }

    pub(crate) fn last_avail(&self) -> u16 {
        self.last_avail
    }
    pub(crate) fn set_last_avail(&mut self, v: u16) {
        self.last_avail = v;
    }

    pub(crate) fn set_desc_lo(&mut self, v: u32) {
        self.desc = set_lo(self.desc, v);
        self.ready = false;
    }
    pub(crate) fn set_desc_hi(&mut self, v: u32) {
        self.desc = set_hi(self.desc, v);
        self.ready = false;
    }
    pub(crate) fn set_avail_lo(&mut self, v: u32) {
        self.avail = set_lo(self.avail, v);
        self.ready = false;
    }
    pub(crate) fn set_avail_hi(&mut self, v: u32) {
        self.avail = set_hi(self.avail, v);
        self.ready = false;
    }
    pub(crate) fn set_used_lo(&mut self, v: u32) {
        self.used = set_lo(self.used, v);
        self.ready = false;
    }
    pub(crate) fn set_used_hi(&mut self, v: u32) {
        self.used = set_hi(self.used, v);
        self.ready = false;
    }

    /// Appends a completed buffer to the used ring and advances its index.
    pub(crate) fn push_used(&self, mem: &GuestRam, head: u16, len: u32) {
        let Some(n) = Some(self.size()).filter(|&n| n != 0) else {
            return;
        };
        let Ok(used_idx) = mem.read_u16(self.used + 2) else {
            return;
        };
        let entry = self.used + 4 + u64::from(used_idx % n) * 8;
        let _ = mem.write_u32(entry, u32::from(head));
        let _ = mem.write_u32(entry + 4, len);
        let _ = mem.write_u16(self.used + 2, used_idx.wrapping_add(1));
    }
}

/// A virtio-blk device behind a virtio-mmio transport.
pub struct VirtioBlk {
    file: File,
    capacity_sectors: u64,
    status: u32,
    dev_feat_sel: u32,
    queue: Queue,
    interrupt_status: u32,
    /// Captured requests, drained by the machine into the event ledger.
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
            // BLKGETSIZE64: _IOR(0x12, 114, size_t), the size in bytes.
            const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;
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
    /// Opens `path` read-write as the backing disk.
    ///
    /// # Errors
    ///
    /// Errors if the file cannot be opened or its length read.
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
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
            events: Vec::new(),
            sink: None,
            disk_id,
            trace: std::env::var_os("HVI_BLK_TRACE").is_some(),
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

    /// Drains the captured requests for the event ledger.
    pub fn take_events(&mut self) -> Vec<CapturedEvent> {
        std::mem::take(&mut self.events)
    }

    /// Services one MMIO access. Returns the read value (0 for writes). When
    /// the driver notifies a queue, the virtqueue is processed inline.
    pub fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        let v = value as u32;
        if is_write {
            match offset {
                reg::DEVICE_FEATURES_SEL => self.dev_feat_sel = v,
                reg::DRIVER_FEATURES_SEL | reg::DRIVER_FEATURES => {}
                reg::QUEUE_SEL => {} // only queue 0
                reg::QUEUE_NUM => self.queue.set_num(v),
                reg::QUEUE_READY => self.queue.set_ready(v, mem),
                reg::QUEUE_NOTIFY => self.process_queue(mem),
                reg::INTERRUPT_ACK => self.interrupt_status &= !v,
                reg::STATUS => self.status = v, // 0 = driver reset
                reg::QUEUE_DESC_LOW => self.queue.set_desc_lo(v),
                reg::QUEUE_DESC_HIGH => self.queue.set_desc_hi(v),
                reg::QUEUE_DRIVER_LOW => self.queue.set_avail_lo(v),
                reg::QUEUE_DRIVER_HIGH => self.queue.set_avail_hi(v),
                reg::QUEUE_DEVICE_LOW => self.queue.set_used_lo(v),
                reg::QUEUE_DEVICE_HIGH => self.queue.set_used_hi(v),
                _ => {}
            }
            0
        } else {
            match offset {
                reg::MAGIC => MAGIC_VALUE,
                reg::VERSION => 2,
                reg::DEVICE_ID => VIRTIO_BLK_ID,
                reg::VENDOR_ID => VENDOR,
                // Low word: VIRTIO_BLK_F_FLUSH. High word: VIRTIO_F_VERSION_1.
                reg::DEVICE_FEATURES if self.dev_feat_sel == 0 => u64::from(F_BLK_FLUSH_LO),
                reg::DEVICE_FEATURES if self.dev_feat_sel == 1 => u64::from(F_VERSION_1_HI),
                reg::QUEUE_NUM_MAX => u64::from(QUEUE_NUM_MAX),
                reg::QUEUE_READY => u64::from(self.queue.is_ready()),
                reg::INTERRUPT_STATUS => u64::from(self.interrupt_status),
                reg::STATUS => u64::from(self.status),
                // Config space: capacity (in 512-byte sectors) at offset 0.
                // Return the 8-byte little-endian window starting at the field
                // so a sized (byte/half/word) read takes the right low bytes;
                // the caller masks to the access width.
                _ if offset >= reg::CONFIG => {
                    let field = (offset - reg::CONFIG) as usize;
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

        match typ {
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
            }
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
            }
            VIRTIO_BLK_T_FLUSH => {
                // Honour the guest's cache flush (durability for fsync).
                self.file.sync_data().map_err(other)?;
            }
            _ => {} // get-id / etc.: acknowledge without data.
        }

        let (saddr, _) = *writable.last().unwrap();
        mem.write_u8(saddr, VIRTIO_BLK_S_OK).map_err(other)?;
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
                _ => "other",
            };
            eprint!("\r\n[virtio-blk] {kind} sector={sector} bytes={data_bytes}\r\n");
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
        Ok(device_written)
    }
}

fn set_lo(v: u64, lo: u32) -> u64 {
    (v & 0xffff_ffff_0000_0000) | u64::from(lo)
}
fn set_hi(v: u64, hi: u32) -> u64 {
    (v & 0x0000_0000_ffff_ffff) | (u64::from(hi) << 32)
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
    fn program(blk: &mut VirtioBlk, mem: &GuestRam, num: u32, desc: u64, avail: u64, used: u64) {
        blk.mmio(mem, reg::QUEUE_NUM, true, u64::from(num));
        blk.mmio(mem, reg::QUEUE_DESC_LOW, true, desc & 0xffff_ffff);
        blk.mmio(mem, reg::QUEUE_DESC_HIGH, true, desc >> 32);
        blk.mmio(mem, reg::QUEUE_DRIVER_LOW, true, avail & 0xffff_ffff);
        blk.mmio(mem, reg::QUEUE_DRIVER_HIGH, true, avail >> 32);
        blk.mmio(mem, reg::QUEUE_DEVICE_LOW, true, used & 0xffff_ffff);
        blk.mmio(mem, reg::QUEUE_DEVICE_HIGH, true, used >> 32);
        blk.mmio(mem, reg::QUEUE_READY, true, 1);
    }

    fn dev() -> VirtioBlk {
        VirtioBlk::open("/dev/null").unwrap()
    }

    /// Regression for the guest-triggerable panic: `0x10000` is non-zero as a
    /// `u32` and zero as a `u16`, so the old code divided by zero on notify.
    #[test]
    fn queue_num_65536_is_rejected_instead_of_panicking() {
        let mut backing = vec![0u8; 0x4000];
        let mem = GuestRam::new(backing.as_mut_ptr(), BASE, backing.len());
        let mut blk = dev();
        program(&mut blk, &mem, 0x10000, BASE, BASE + 0x1000, BASE + 0x2000);
        mem.write_u16(BASE + 0x1000 + 2, 1).unwrap(); // avail.idx = 1

        assert_eq!(blk.mmio(&mem, reg::QUEUE_READY, false, 0), 0, "not ready");
        blk.mmio(&mem, reg::QUEUE_NOTIFY, true, 0); // must not panic
        assert_eq!(blk.queue.size(), 0, "the size was refused");
    }

    #[test]
    fn queue_rejects_zero_non_power_of_two_and_over_max() {
        let mut backing = vec![0u8; 0x4000];
        let mem = GuestRam::new(backing.as_mut_ptr(), BASE, backing.len());
        for bad in [0, 3, 100, QUEUE_NUM_MAX + 1, 0x1_0000, u32::MAX] {
            let mut q = Queue::default();
            q.set_num(bad);
            assert_eq!(q.size(), 0, "{bad} should be refused");
            q.set_ready(1, &mem);
            assert!(!q.is_ready(), "{bad} must not become ready");
        }
        for good in [1, 2, 4, 128, QUEUE_NUM_MAX] {
            let mut q = Queue::default();
            q.set_num(good);
            assert_eq!(u32::from(q.size()), good, "{good} should be accepted");
        }
    }

    /// The rings must fit in guest RAM before we will service the queue, so a
    /// driver cannot point them at unbacked addresses.
    #[test]
    fn queue_rejects_rings_outside_guest_ram() {
        let mut backing = vec![0u8; 0x4000];
        let mem = GuestRam::new(backing.as_mut_ptr(), BASE, backing.len());
        let mut blk = dev();

        // desc table for 256 entries is 4 KiB, so this one runs off the end.
        program(
            &mut blk,
            &mem,
            256,
            BASE + 0x3800,
            BASE + 0x1000,
            BASE + 0x2000,
        );
        assert_eq!(blk.mmio(&mem, reg::QUEUE_READY, false, 0), 0);

        // Below the RAM base is refused too.
        program(
            &mut blk,
            &mem,
            256,
            BASE - 0x1000,
            BASE + 0x1000,
            BASE + 0x2000,
        );
        assert_eq!(blk.mmio(&mem, reg::QUEUE_READY, false, 0), 0);

        // The same size, in bounds, is accepted.
        program(&mut blk, &mem, 256, BASE, BASE + 0x1000, BASE + 0x2000);
        assert_eq!(blk.mmio(&mem, reg::QUEUE_READY, false, 0), 1);
    }

    #[test]
    fn descriptor_index_outside_the_ring_is_refused() {
        let mut q = Queue::default();
        q.set_num(8);
        q.set_desc_lo(0x1000);
        assert_eq!(q.desc_addr(0), Some(0x1000));
        assert_eq!(q.desc_addr(7), Some(0x1000 + 7 * 16));
        assert_eq!(q.desc_addr(8), None, "index == size is out of the ring");
        assert_eq!(q.desc_addr(u16::MAX), None);
    }

    /// `avail.idx` claiming more than a ring's worth is a bogus ring, not
    /// 65535 chain walks.
    #[test]
    fn avail_idx_beyond_the_ring_is_refused() {
        let mut backing = vec![0u8; 0x4000];
        let mem = GuestRam::new(backing.as_mut_ptr(), BASE, backing.len());
        let mut q = Queue::default();
        q.set_num(8);
        q.set_avail_lo((BASE + 0x1000) as u32);
        q.set_avail_hi(((BASE + 0x1000) >> 32) as u32);

        mem.write_u16(BASE + 0x1000 + 2, 8).unwrap();
        assert_eq!(q.pending(&mem), Some(8), "a full ring is fine");
        mem.write_u16(BASE + 0x1000 + 2, 9).unwrap();
        assert_eq!(q.pending(&mem), None, "one past the ring is refused");
        mem.write_u16(BASE + 0x1000 + 2, 0xffff).unwrap();
        assert_eq!(q.pending(&mem), None);
    }

    /// The happy path still works: a conforming driver's read request is
    /// serviced, the data lands in guest RAM and the status byte is written.
    #[test]
    fn a_conforming_queue_still_services_a_request() {
        let path = std::env::temp_dir().join(format!("hvi-q-{}.img", std::process::id()));
        let mut disk = vec![0u8; 1024];
        disk[..5].copy_from_slice(b"HELLO");
        std::fs::write(&path, &disk).unwrap();
        let mut blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();

        let mut backing = vec![0u8; 0x8000];
        let mem = GuestRam::new(backing.as_mut_ptr(), BASE, backing.len());
        let (desc, avail, used) = (BASE, BASE + 0x2000, BASE + 0x3000);
        let (hdr, data, status) = (BASE + 0x4000, BASE + 0x5000, BASE + 0x6000);

        mem.write_u32(hdr, VIRTIO_BLK_T_IN).unwrap();
        mem.write_u64(hdr + 8, 0).unwrap(); // sector 0
        let d = |i: u64, addr: u64, len: u32, flags: u16, next: u16| {
            mem.write_u64(desc + i * 16, addr).unwrap();
            mem.write_u32(desc + i * 16 + 8, len).unwrap();
            mem.write_u16(desc + i * 16 + 12, flags).unwrap();
            mem.write_u16(desc + i * 16 + 14, next).unwrap();
        };
        d(0, hdr, 16, VIRTQ_DESC_F_NEXT, 1);
        d(1, data, 512, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
        d(2, status, 1, VIRTQ_DESC_F_WRITE, 0);
        mem.write_u16(avail + 2, 1).unwrap(); // avail.idx
        mem.write_u16(avail + 4, 0).unwrap(); // avail.ring[0] = desc 0

        program(&mut blk, &mem, 256, desc, avail, used);
        assert_eq!(blk.mmio(&mem, reg::QUEUE_READY, false, 0), 1, "ready");
        blk.mmio(&mem, reg::QUEUE_NOTIFY, true, 0);
        let _ = std::fs::remove_file(&path);

        let mut got = [0u8; 5];
        mem.read(data, &mut got).unwrap();
        assert_eq!(&got, b"HELLO", "the sector reached guest memory");
        assert_eq!(mem.read_u16(used + 2).unwrap(), 1, "used.idx advanced");
        assert!(blk.irq_level(), "used-buffer interrupt asserted");
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    const BASE: u64 = 0x4000_0000;

    struct Rig {
        path: std::path::PathBuf,
        backing: Vec<u8>,
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
        (
            Rig {
                path,
                backing: vec![0u8; 0x8000],
            },
            blk,
        )
    }

    /// Submits one request and returns the status byte the device wrote.
    fn submit(blk: &mut VirtioBlk, mem: &GuestRam, typ: u32, sector: u64, len: u32) -> u8 {
        let (desc, avail, used) = (BASE, BASE + 0x2000, BASE + 0x3000);
        let (hdr, data, status) = (BASE + 0x4000, BASE + 0x5000, BASE + 0x6000);
        mem.write_u32(hdr, typ).unwrap();
        mem.write_u64(hdr + 8, sector).unwrap();
        mem.write_u8(status, 0xff).unwrap(); // poison, so "untouched" is visible

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

        blk.mmio(mem, reg::QUEUE_NUM, true, 256);
        blk.mmio(mem, reg::QUEUE_DESC_LOW, true, desc & 0xffff_ffff);
        blk.mmio(mem, reg::QUEUE_DESC_HIGH, true, desc >> 32);
        blk.mmio(mem, reg::QUEUE_DRIVER_LOW, true, avail & 0xffff_ffff);
        blk.mmio(mem, reg::QUEUE_DRIVER_HIGH, true, avail >> 32);
        blk.mmio(mem, reg::QUEUE_DEVICE_LOW, true, used & 0xffff_ffff);
        blk.mmio(mem, reg::QUEUE_DEVICE_HIGH, true, used >> 32);
        blk.mmio(mem, reg::QUEUE_READY, true, 1);
        blk.mmio(mem, reg::QUEUE_NOTIFY, true, 0);
        mem.read_u16(status).unwrap() as u8
    }

    /// Regression for the guest writing outside the disk it was advertised.
    #[test]
    fn write_past_the_advertised_capacity_is_refused() {
        let (mut r, mut blk) = rig("out");
        let mem = GuestRam::new(r.backing.as_mut_ptr(), BASE, r.backing.len());
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
        let (mut r, mut blk) = rig("in");
        let mem = GuestRam::new(r.backing.as_mut_ptr(), BASE, r.backing.len());
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_IN, 9_999, 512);
        assert_eq!(st, VIRTIO_BLK_S_IOERR);
    }

    /// A sector that would wrap the byte offset is refused rather than aliased
    /// back into the file (release builds used to wrap silently).
    #[test]
    fn sector_offset_overflow_is_refused() {
        let (mut r, mut blk) = rig("ovf");
        let mem = GuestRam::new(r.backing.as_mut_ptr(), BASE, r.backing.len());
        let st = submit(&mut blk, &mem, VIRTIO_BLK_T_OUT, u64::MAX / 256, 16);
        assert_eq!(st, VIRTIO_BLK_S_IOERR);
        assert_eq!(std::fs::metadata(&r.path).unwrap().len(), 512);
    }

    /// The last sector inside the capacity still works, so the bound is not
    /// off by one.
    #[test]
    fn a_request_inside_the_capacity_still_succeeds() {
        let (mut r, mut blk) = rig("ok");
        let mem = GuestRam::new(r.backing.as_mut_ptr(), BASE, r.backing.len());
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

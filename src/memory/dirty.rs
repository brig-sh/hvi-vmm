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

//! Which pages of guest RAM were written, and by whom.
//!
//! A live move copies guest RAM while the guest runs, then copies again the
//! pages written since. Two kinds of writer change guest RAM:
//!
//! - the guest's vCPUs, which the hypervisor sees: KVM keeps a dirty log per
//!   memory slot, and on HVF hvi write-protects RAM and records each fault.
//!   A backend reports them to the mover;
//! - hvi's own threads, which write through [`GuestRam`](super::GuestRam):
//!   the virtio devices fill guest buffers and publish used rings. The
//!   hypervisor never sees those writes, so `GuestRam` records each one in
//!   its [`DirtyLog`].
//!
//! Both are cut into periods by a reader that takes the set and clears it in
//! one step, and both report in [`DirtyPages`], one bit per 4 KiB page.
//!
//! A host write marks its pages after it has written them. A reader that
//! takes a mark reads the page after the take, so it sees the write; a mark
//! that lands after the take belongs to the next period, whose read comes
//! later still. The bytes a reader copies may therefore be newer than its
//! period, never older than the last mark it took.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::memory::RamRegion;

/// The page size the logs count in: the arm64 and x86-64 base page, and the
/// page of a checkpoint's RAM image.
pub const DIRTY_PAGE: u64 = 4096;

/// One region's bitmap: its place in the guest and its words.
#[derive(Debug)]
struct LogRegion {
    /// Guest-physical address of page 0.
    gpa: u64,
    /// Length in bytes.
    size: u64,
    /// One bit per [`DIRTY_PAGE`], bit `i % 64` of word `i / 64`.
    words: Box<[AtomicU64]>,
}

/// The pages hvi's own threads wrote, one atomic bit per 4 KiB page of each
/// region of guest RAM.
///
/// It marks every write, whether or not a move is under way: a mark is one
/// atomic OR per 64 pages a write touches, and a reader that starts a move
/// clears it first.
#[derive(Debug)]
pub struct DirtyLog {
    /// The regions, in address order.
    regions: Vec<LogRegion>,
}

impl DirtyLog {
    /// Returns an empty log over `regions`.
    #[must_use]
    pub fn new(regions: &[RamRegion]) -> Self {
        let mut regions: Vec<LogRegion> = regions
            .iter()
            .map(|r| LogRegion {
                gpa: r.gpa,
                size: r.size,
                words: (0..pages_of(r.size).div_ceil(64))
                    .map(|_| AtomicU64::new(0))
                    .collect(),
            })
            .collect();
        regions.sort_by_key(|r| r.gpa);
        Self { regions }
    }

    /// Marks the pages `[gpa, gpa+len)` touches. A range outside guest RAM,
    /// which no accessor writes, marks nothing.
    ///
    /// The caller has written the bytes already: see the module
    /// documentation for why the mark comes second.
    pub fn mark(&self, gpa: u64, len: u64) {
        if len == 0 {
            return;
        }
        let Some(region) = self
            .regions
            .iter()
            .find(|r| gpa >= r.gpa && gpa - r.gpa < r.size)
        else {
            return;
        };
        let offset = gpa - region.gpa;
        let end = offset.saturating_add(len).min(region.size);
        let (first, last) = (offset / DIRTY_PAGE, (end - 1) / DIRTY_PAGE);
        let mut page = first;
        while page <= last {
            let word = (page / 64) as usize;
            let bit = page % 64;
            let upto = last.min(page - bit + 63);
            let n = upto - page + 1;
            let mask = if n == 64 {
                u64::MAX
            } else {
                ((1u64 << n) - 1) << bit
            };
            region.words[word].fetch_or(mask, Ordering::Release);
            page = upto + 1;
        }
    }

    /// Moves every mark into `into` and clears it, region by region.
    ///
    /// # Errors
    ///
    /// Errors when `into` is not of this log's regions.
    pub fn take_into(&self, into: &mut DirtyPages) -> io::Result<()> {
        into.check_same(self.regions.iter().map(|r| (r.gpa, r.size)))?;
        for (region, bits) in self.regions.iter().zip(&mut into.regions) {
            for (word, out) in region.words.iter().zip(bits.words.iter_mut()) {
                *out |= word.swap(0, Ordering::AcqRel);
            }
        }
        Ok(())
    }

    /// Clears every mark.
    pub fn clear(&self) {
        for region in &self.regions {
            for word in region.words.iter() {
                word.store(0, Ordering::Release);
            }
        }
    }
}

/// Returns the number of [`DIRTY_PAGE`]s in `size` bytes, a partial page
/// counting as one.
fn pages_of(size: u64) -> u64 {
    size.div_ceil(DIRTY_PAGE)
}

/// One region's pages in a [`DirtyPages`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct RegionBits {
    /// Guest-physical address of page 0.
    gpa: u64,
    /// Length in bytes.
    size: u64,
    /// One bit per page.
    words: Vec<u64>,
}

impl RegionBits {
    fn pages(&self) -> u64 {
        pages_of(self.size)
    }
}

/// A set of 4 KiB pages of guest RAM: one bitmap per region, in address
/// order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirtyPages {
    /// The regions, in address order.
    regions: Vec<RegionBits>,
}

impl DirtyPages {
    /// Returns the empty set over `regions`.
    #[must_use]
    pub fn new(regions: &[RamRegion]) -> Self {
        let mut regions: Vec<RegionBits> = regions
            .iter()
            .map(|r| RegionBits {
                gpa: r.gpa,
                size: r.size,
                words: vec![0; pages_of(r.size).div_ceil(64) as usize],
            })
            .collect();
        regions.sort_by_key(|r| r.gpa);
        Self { regions }
    }

    /// Returns the set of every page of `regions`.
    #[must_use]
    pub fn all(regions: &[RamRegion]) -> Self {
        let mut set = Self::new(regions);
        for index in 0..set.regions.len() {
            let pages = set.regions[index].pages();
            set.set_range(index, 0, pages);
        }
        set
    }

    /// Returns the number of regions.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Returns region `index`'s guest-physical address and page count.
    #[must_use]
    pub fn region(&self, index: usize) -> Option<(u64, u64)> {
        self.regions.get(index).map(|r| (r.gpa, r.pages()))
    }

    /// Refuses a set of other regions than `regions`.
    fn check_same(&self, regions: impl Iterator<Item = (u64, u64)>) -> io::Result<()> {
        let theirs: Vec<(u64, u64)> = regions.collect();
        let ours: Vec<(u64, u64)> = self.regions.iter().map(|r| (r.gpa, r.size)).collect();
        if theirs == ours {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("dirty pages over {ours:x?}, the log has {theirs:x?}"),
            ))
        }
    }

    /// Adds `count` pages of region `index` from page `first`. Pages past
    /// the region's end are left out.
    pub fn set_range(&mut self, index: usize, first: u64, count: u64) {
        let Some(region) = self.regions.get_mut(index) else {
            return;
        };
        let end = first.saturating_add(count).min(region.pages());
        for page in first..end {
            region.words[(page / 64) as usize] |= 1 << (page % 64);
        }
    }

    /// Adds the pages at `[gpa, gpa+len)`, as [`DirtyLog::mark`] would.
    pub fn set_gpa(&mut self, gpa: u64, len: u64) {
        if len == 0 {
            return;
        }
        if let Some(index) = self
            .regions
            .iter()
            .position(|r| gpa >= r.gpa && gpa - r.gpa < r.size)
        {
            let region = &self.regions[index];
            let offset = gpa - region.gpa;
            let end = offset.saturating_add(len).min(region.size);
            let first = offset / DIRTY_PAGE;
            self.set_range(index, first, (end - 1) / DIRTY_PAGE - first + 1);
        }
    }

    /// Returns whether page `page` of region `index` is in the set.
    #[must_use]
    pub fn contains(&self, index: usize, page: u64) -> bool {
        self.regions.get(index).is_some_and(|r| {
            page < r.pages() && r.words[(page / 64) as usize] & (1 << (page % 64)) != 0
        })
    }

    /// Adds region `index`'s pages from `bitmap`, a hypervisor's log with one
    /// bit per `granule` bytes (a multiple of [`DIRTY_PAGE`]): each set bit
    /// adds every page of its granule.
    ///
    /// # Errors
    ///
    /// Errors when the granule is not a multiple of the page or there is no
    /// region `index`.
    pub fn or_granules(&mut self, index: usize, bitmap: &[u64], granule: u64) -> io::Result<()> {
        if granule == 0 || granule % DIRTY_PAGE != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a {granule}-byte granule is not whole 4 KiB pages"),
            ));
        }
        if index >= self.regions.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("no RAM region {index}"),
            ));
        }
        let per = granule / DIRTY_PAGE;
        for (w, word) in bitmap.iter().enumerate() {
            let mut bits = *word;
            while bits != 0 {
                let bit = u64::from(bits.trailing_zeros());
                bits &= bits - 1;
                let g = w as u64 * 64 + bit;
                self.set_range(index, g * per, per);
            }
        }
        Ok(())
    }

    /// Adds every page of `other`.
    ///
    /// # Errors
    ///
    /// Errors when `other` is of other regions.
    pub fn union(&mut self, other: &DirtyPages) -> io::Result<()> {
        self.check_same(other.regions.iter().map(|r| (r.gpa, r.size)))?;
        for (mine, theirs) in self.regions.iter_mut().zip(&other.regions) {
            for (a, b) in mine.words.iter_mut().zip(&theirs.words) {
                *a |= *b;
            }
        }
        Ok(())
    }

    /// Empties the set.
    pub fn clear(&mut self) {
        for region in &mut self.regions {
            region.words.fill(0);
        }
    }

    /// Returns the number of pages in the set.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.regions
            .iter()
            .flat_map(|r| &r.words)
            .map(|w| u64::from(w.count_ones()))
            .sum()
    }

    /// Returns whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.iter().all(|r| r.words.iter().all(|w| *w == 0))
    }

    /// Returns the set as runs of consecutive pages, each at most `max`
    /// pages long and inside one region: `(region, first page, count)`, in
    /// address order.
    #[must_use]
    pub fn runs(&self, max: u64) -> Vec<(usize, u64, u64)> {
        let max = max.max(1);
        let mut out = Vec::new();
        for (index, region) in self.regions.iter().enumerate() {
            let mut start: Option<u64> = None;
            for page in 0..=region.pages() {
                let set = page < region.pages()
                    && region.words[(page / 64) as usize] & (1 << (page % 64)) != 0;
                match (set, start) {
                    (true, None) => start = Some(page),
                    (true, Some(s)) if page - s == max => {
                        out.push((index, s, max));
                        start = Some(page);
                    }
                    (false, Some(s)) => {
                        out.push((index, s, page - s));
                        start = None;
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x4000_0000;

    fn one(size: u64) -> Vec<RamRegion> {
        vec![RamRegion {
            gpa: BASE,
            size,
            file_offset: 0,
        }]
    }

    #[test]
    fn a_mark_covers_every_page_a_range_touches() {
        let regions = one(1 << 20);
        let log = DirtyLog::new(&regions);
        log.mark(BASE + 4095, 2); // pages 0 and 1
        log.mark(BASE + 64 * 4096 - 1, 4096 * 64 + 2); // pages 63..=128
        log.mark(BASE - 1, 1); // outside: nothing
        log.mark(BASE + (1 << 20), 1); // past the end: nothing
        let mut got = DirtyPages::new(&regions);
        log.take_into(&mut got).unwrap();
        let mut want = DirtyPages::new(&regions);
        want.set_range(0, 0, 2);
        want.set_range(0, 63, 66);
        assert_eq!(got, want);
        assert_eq!(got.count(), 68);
        // The take cleared it.
        let mut again = DirtyPages::new(&regions);
        log.take_into(&mut again).unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn a_mark_that_runs_off_the_region_stops_at_its_end() {
        let regions = one(8 * 4096);
        let log = DirtyLog::new(&regions);
        log.mark(BASE + 6 * 4096, u64::MAX);
        let mut got = DirtyPages::new(&regions);
        log.take_into(&mut got).unwrap();
        assert_eq!(got.runs(64), vec![(0, 6, 2)]);
    }

    #[test]
    fn runs_are_split_at_the_cap_and_at_gaps() {
        let regions = one(1 << 20);
        let mut set = DirtyPages::new(&regions);
        set.set_range(0, 10, 130);
        set.set_range(0, 200, 1);
        assert_eq!(
            set.runs(64),
            vec![(0, 10, 64), (0, 74, 64), (0, 138, 2), (0, 200, 1)]
        );
        assert_eq!(set.count(), 131);
    }

    #[test]
    fn a_granule_bit_adds_each_of_its_pages() {
        let regions = one(2 << 20);
        let mut set = DirtyPages::new(&regions);
        // 16 KiB granules: bit 0 and bit 65.
        set.or_granules(0, &[1, 2], 16 << 10).unwrap();
        assert_eq!(set.runs(64), vec![(0, 0, 4), (0, 260, 4)]);
        assert!(set.or_granules(0, &[1], 6 << 10).is_err());
        assert!(set.or_granules(1, &[1], 16 << 10).is_err());
    }

    #[test]
    fn sets_of_other_regions_do_not_mix() {
        let mut a = DirtyPages::new(&one(1 << 20));
        let b = DirtyPages::new(&one(2 << 20));
        assert!(a.union(&b).is_err());
        let log = DirtyLog::new(&one(2 << 20));
        assert!(log.take_into(&mut a).is_err());
    }

    #[test]
    fn two_regions_are_kept_apart() {
        let regions = vec![
            RamRegion {
                gpa: 0x1_0000_0000,
                size: 1 << 20,
                file_offset: 1 << 20,
            },
            RamRegion {
                gpa: 0,
                size: 1 << 20,
                file_offset: 0,
            },
        ];
        let log = DirtyLog::new(&regions);
        log.mark(0x1_0000_0000 + 4096, 1);
        log.mark(0, 1);
        let mut got = DirtyPages::new(&regions);
        log.take_into(&mut got).unwrap();
        assert_eq!(got.runs(64), vec![(0, 0, 1), (1, 1, 1)]);
        assert_eq!(got.region(1), Some((0x1_0000_0000, 256)));
    }
}

// Every path by which a device writes guest RAM marks the pages it wrote:
// a virtio-blk read's data and status bytes, a received frame, a vsock
// packet, and the used ring each completion publishes. They all write
// through `GuestRam`'s accessors, so these drive each device through its
// own interface and look at the log.
#[cfg(test)]
mod device_writes {
    use super::*;
    use crate::devices::virtio::block::VirtioBlk;
    use crate::devices::virtio::mmio;
    use crate::devices::virtio::net::VirtioNet;
    use crate::devices::virtio::vsock::VirtioVsock;
    use crate::memory::GuestRam;
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

    const VIRTQ_DESC_F_NEXT: u16 = VRING_DESC_F_NEXT as u16;
    const VIRTQ_DESC_F_WRITE: u16 = VRING_DESC_F_WRITE as u16;
    const BASE: u64 = 0x4000_0000;
    const DESC: u64 = BASE;
    const AVAIL: u64 = BASE + 0x1000;
    const USED: u64 = BASE + 0x2000;
    /// The page of the used ring.
    const USED_PAGE: u64 = 2;

    fn guest() -> GuestRam {
        GuestRam::from_ranges(&[(BASE, 0x10_0000)])
    }

    /// Returns the pages marked since the last call, and clears them.
    fn marked(ram: &GuestRam) -> Vec<u64> {
        let mut set = DirtyPages::new(&ram.regions());
        ram.dirty_log().take_into(&mut set).unwrap();
        let mut pages = Vec::new();
        for (_, first, count) in set.runs(64) {
            pages.extend(first..first + count);
        }
        pages
    }

    /// Writes descriptor `i` and makes `head` the next available entry.
    fn descriptor(ram: &GuestRam, i: u64, addr: u64, len: u32, flags: u16, next: u16) {
        ram.write_u64(DESC + i * 16, addr).unwrap();
        ram.write_u32(DESC + i * 16 + 8, len).unwrap();
        ram.write_u16(DESC + i * 16 + 12, flags).unwrap();
        ram.write_u16(DESC + i * 16 + 14, next).unwrap();
    }

    fn publish(ram: &GuestRam, head: u16) {
        let idx = ram.read_u16(AVAIL + 2).unwrap();
        ram.write_u16(AVAIL + 4 + u64::from(idx % 8) * 2, head)
            .unwrap();
        ram.write_u16(AVAIL + 2, idx.wrapping_add(1)).unwrap();
    }

    /// Programs queue `queue` of a device through `mmio` as an 8-entry ring
    /// at the fixed addresses.
    fn program(mut mmio_write: impl FnMut(u64, u64), queue: u64) {
        mmio_write(mmio::QUEUE_SEL, queue);
        mmio_write(mmio::QUEUE_NUM, 8);
        mmio_write(mmio::QUEUE_DESC_LOW, DESC & 0xffff_ffff);
        mmio_write(mmio::QUEUE_DESC_HIGH, DESC >> 32);
        mmio_write(mmio::QUEUE_DRIVER_LOW, AVAIL & 0xffff_ffff);
        mmio_write(mmio::QUEUE_DRIVER_HIGH, AVAIL >> 32);
        mmio_write(mmio::QUEUE_DEVICE_LOW, USED & 0xffff_ffff);
        mmio_write(mmio::QUEUE_DEVICE_HIGH, USED >> 32);
        mmio_write(mmio::QUEUE_READY, 1);
    }

    #[test]
    fn a_virtio_blk_read_marks_its_data_status_and_used_ring() {
        let path = std::env::temp_dir().join(format!("hvi-dirty-blk-{}.img", std::process::id()));
        #[allow(clippy::disallowed_methods)]
        std::fs::write(&path, vec![0x5a; 4096]).unwrap();
        let mut blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();
        #[allow(clippy::disallowed_methods)]
        let _ = std::fs::remove_file(&path);
        let ram = guest();
        let (hdr, data, status) = (BASE + 0x4000, BASE + 0x5000, BASE + 0x7000);
        ram.write_u32(hdr, virtio_bindings::virtio_blk::VIRTIO_BLK_T_IN)
            .unwrap();
        ram.write_u64(hdr + 8, 0).unwrap();
        descriptor(&ram, 0, hdr, 16, VIRTQ_DESC_F_NEXT, 1);
        descriptor(
            &ram,
            1,
            data,
            4096,
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            2,
        );
        descriptor(&ram, 2, status, 1, VIRTQ_DESC_F_WRITE, 0);
        publish(&ram, 0);
        program(
            |o, v| {
                blk.mmio(&ram, o, true, v);
            },
            0,
        );
        let _ = marked(&ram);
        blk.mmio(&ram, mmio::QUEUE_NOTIFY, true, 0);
        assert_eq!(
            ram.read_u64(data).unwrap(),
            0x5a5a_5a5a_5a5a_5a5a,
            "the read landed"
        );
        assert_eq!(marked(&ram), vec![USED_PAGE, 5, 7]);
    }

    #[test]
    fn a_received_frame_marks_its_buffer_and_used_ring() {
        let mut net = VirtioNet::new();
        let ram = guest();
        let buffer = BASE + 0x6000;
        descriptor(&ram, 0, buffer, 2048, VIRTQ_DESC_F_WRITE, 0);
        publish(&ram, 0);
        net.mmio(&ram, mmio::STATUS, true, 0xf);
        program(
            |o, v| {
                net.mmio(&ram, o, true, v);
            },
            0,
        );
        let _ = marked(&ram);
        net.deliver(&ram, &[0xab; 60]);
        assert_eq!(marked(&ram), vec![USED_PAGE, 6]);
    }

    #[test]
    fn a_vsock_packet_marks_its_buffer_and_used_ring() {
        let mut vsock = VirtioVsock::new();
        let ram = guest();
        let buffer = BASE + 0x9000;
        descriptor(&ram, 0, buffer, 4096, VIRTQ_DESC_F_WRITE, 0);
        publish(&ram, 0);
        program(
            |o, v| {
                vsock.mmio(&ram, o, true, v);
            },
            0,
        );
        let (host, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let port = vsock.add_conn(host).unwrap();
        let _ = marked(&ram);
        vsock.connect(&ram, port);
        assert_eq!(marked(&ram), vec![USED_PAGE, 9]);
    }
}

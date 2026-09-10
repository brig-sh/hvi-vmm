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

//! Guest physical RAM as a `vm-memory` region collection.
//!
//! [`GuestRam`](crate::guestmem::GuestRam) wraps a
//! [`GuestMemoryMmap`](vm_memory::GuestMemoryMmap) whose regions map the
//! shareable object a [`SharedRam`](crate::sharedmem::SharedRam) allocates, so
//! the VMM, its device models and an out-of-process plugin all see the same
//! pages. The rust-vmm crates take the collection as guest memory. The
//! accessors the devices and plugins use are methods on the wrapper; they find
//! the region through a table kept beside the collection, which is cheaper
//! than the collection's own lookup through its `Arc`-held regions. The table
//! is built from the collection once and never changes after.
//!
//! Access is through `&self`, so device backends and a plugin take a shared
//! `&GuestRam`. Reads and writes race the running guest; that is inherent in
//! observing a live VM. They stay in bounds, and a refused range is not
//! touched.
//!
//! Guest RAM is not always one span. The x86 backend splits it around the
//! sub-4 GiB MMIO hole, so it has two regions. An access never crosses from
//! one region into the next, and an address in the gap is a device, not RAM.

use std::io;
use std::sync::Arc;

use vm_memory::{
    Address, ByteValued, FileOffset, GuestAddress, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap, MemoryRegionAddress, MmapRegion, VolatileMemory, VolatileSlice,
};

use crate::sharedmem::SharedRam;

/// A guest-physical span of the VM's RAM and where it sits in the backing
/// object, so a process that maps the same object sees the same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemRegion {
    /// Guest-physical address this span starts at.
    pub gpa: u64,
    /// Length in bytes.
    pub size: u64,
    /// Offset of `gpa` within the shareable backing object.
    pub file_offset: u64,
}

impl MemRegion {
    /// Alignment of `gpa`, `size` and `file_offset`, 1 MiB.
    ///
    /// Every host page size divides it, so a region's mapping offset and its
    /// hypervisor slot are page-aligned on any host.
    pub const ALIGN: u64 = 1 << 20;
}

/// A region and its mapping in this process; the accessors resolve
/// addresses through it.
#[derive(Debug, Clone)]
struct MappedRegion {
    /// The guest-physical span and its file offset.
    region: MemRegion,
    /// The region's mapping, shared with the collection.
    mmap: Arc<GuestRegionMmap>,
}

/// Guest physical RAM, one or more regions mapped from a shareable object.
pub struct GuestRam {
    /// The collection the rust-vmm crates take.
    mem: GuestMemoryMmap,
    /// The regions of `mem` in address order, sharing its mappings.
    mapped: Vec<MappedRegion>,
}

impl GuestRam {
    /// Maps `regions` of `shared` into this process.
    ///
    /// Each region is its own `MAP_SHARED` mapping of the descriptor at its
    /// `file_offset`, so the guest-physical layout can have gaps while the
    /// backing object stays one contiguous file.
    ///
    /// # Errors
    ///
    /// Errors if a region is not [`MemRegion::ALIGN`]-aligned, does not fit
    /// the address space, or its mapping fails.
    pub fn new(shared: &SharedRam, regions: &[MemRegion]) -> io::Result<Self> {
        let mappings = regions
            .iter()
            .map(|region| {
                if [region.gpa, region.size, region.file_offset]
                    .iter()
                    .any(|v| v % MemRegion::ALIGN != 0)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "guest RAM region {:#x}+{:#x} at file offset {:#x} is not 1 MiB-aligned",
                            region.gpa, region.size, region.file_offset
                        ),
                    ));
                }
                let size = usize::try_from(region.size).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "guest RAM region too large")
                })?;
                let file = FileOffset::from_arc(Arc::clone(shared.file()), region.file_offset);
                let mapping = MmapRegion::from_file(file, size).map_err(io::Error::other)?;
                GuestRegionMmap::new(mapping, GuestAddress(region.gpa))
                    .map(Arc::new)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "guest RAM region wraps")
                    })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Self::from_arc_regions(mappings)
    }

    /// Builds guest RAM from anonymous mappings, one region per `(gpa, len)`,
    /// for unit tests that need guest memory without a shareable object.
    #[cfg(test)]
    pub(crate) fn from_ranges(regions: &[(u64, usize)]) -> Self {
        let mappings = regions
            .iter()
            .map(|&(gpa, len)| {
                let mapping = MmapRegion::new(len).expect("anonymous mapping");
                Arc::new(GuestRegionMmap::new(mapping, GuestAddress(gpa)).expect("region fits"))
            })
            .collect();
        Self::from_arc_regions(mappings).expect("anonymous guest RAM")
    }

    /// Builds the collection and the accessor table over one set of mapped
    /// regions.
    fn from_arc_regions(mappings: Vec<Arc<GuestRegionMmap>>) -> io::Result<Self> {
        let mem = GuestMemoryMmap::from_arc_regions(mappings.clone()).map_err(io::Error::other)?;
        let mut mapped: Vec<MappedRegion> = mappings
            .into_iter()
            .map(|mmap| MappedRegion {
                region: MemRegion {
                    gpa: mmap.start_addr().raw_value(),
                    size: mmap.len(),
                    file_offset: mmap.file_offset().map_or(0, FileOffset::start),
                },
                mmap,
            })
            .collect();
        mapped.sort_by_key(|mapping| mapping.region.gpa);
        Ok(GuestRam { mem, mapped })
    }

    /// Registers every region as a KVM memory slot of `vm`, numbered in
    /// address order.
    ///
    /// # Errors
    ///
    /// Errors if KVM refuses a slot.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub fn register_kvm_slots(&self, vm: &kvm_ioctls::VmFd) -> io::Result<()> {
        for (index, mapping) in self.mapped.iter().enumerate() {
            let slot = kvm_bindings::kvm_userspace_memory_region {
                slot: index as u32,
                flags: 0, // no dirty tracking
                guest_phys_addr: mapping.region.gpa,
                memory_size: mapping.region.size,
                userspace_addr: mapping.mmap.as_ptr() as u64,
            };
            // SAFETY: the mapping holds `memory_size` bytes and lives as long
            // as `self`, which outlives the VM.
            unsafe { vm.set_user_memory_region(slot) }.map_err(io::Error::from)?;
        }
        Ok(())
    }

    /// Returns the underlying region collection.
    #[must_use]
    pub fn memory(&self) -> &GuestMemoryMmap {
        &self.mem
    }

    /// Returns the regions as spans of the shareable backing object, in
    /// address order.
    #[must_use]
    pub fn regions(&self) -> Vec<MemRegion> {
        self.mapped.iter().map(|mapping| mapping.region).collect()
    }

    /// Scans all of guest RAM for `needle`, returning the guest-physical
    /// addresses of the matches (capped at 64).
    #[must_use]
    pub fn scan(&self, needle: &[u8]) -> Vec<u64> {
        let mut out = Vec::new();
        if needle.is_empty() {
            return out;
        }
        for mapping in &self.mapped {
            let len = usize::try_from(mapping.region.size).expect("a mapping fits in usize");
            // SAFETY: the mapping holds `len` valid bytes for as long as `self`
            // lives, and the slice is only read. The search needs a byte slice
            // over the whole region; `vm-memory` only hands out copies.
            let hay = unsafe { std::slice::from_raw_parts(mapping.mmap.as_ptr(), len) };
            let first = needle[0];
            let mut i = 0;
            while i + needle.len() <= len {
                if hay[i] == first && &hay[i..i + needle.len()] == needle {
                    out.push(mapping.region.gpa + i as u64);
                    if out.len() >= 64 {
                        return out;
                    }
                    i += needle.len();
                } else {
                    i += 1;
                }
            }
        }
        out
    }

    /// Returns whether `[gpa, gpa+len)` lies inside one region of guest RAM.
    ///
    /// An address in the hole between two regions is not RAM, and a range may
    /// not run from one region into the next.
    #[must_use]
    pub fn contains(&self, gpa: u64, len: u64) -> bool {
        usize::try_from(len).is_ok_and(|len| self.slice(gpa, len).is_ok())
    }

    /// Reads `buf.len()` bytes at guest-physical `gpa`.
    ///
    /// The range is resolved to one region before any byte is copied, so a
    /// range that fails leaves `buf` untouched.
    ///
    /// # Errors
    ///
    /// Errors if the range is outside guest RAM or runs from one region into
    /// the next.
    pub fn read(&self, gpa: u64, buf: &mut [u8]) -> io::Result<()> {
        self.slice(gpa, buf.len())?.copy_to(buf);
        Ok(())
    }

    /// Writes `data` at guest-physical `gpa`.
    ///
    /// The range is resolved to one region before any byte is copied, so a
    /// range that fails writes nothing.
    ///
    /// # Errors
    ///
    /// Errors if the range is outside guest RAM or runs from one region into
    /// the next.
    pub fn write(&self, gpa: u64, data: &[u8]) -> io::Result<()> {
        self.slice(gpa, data.len())?.copy_from(data);
        Ok(())
    }

    /// Returns the host address of `[gpa, gpa+len)` for zero-copy I/O such as
    /// an iovec.
    ///
    /// # Errors
    ///
    /// Errors if the range is outside guest RAM or runs from one region into
    /// the next.
    ///
    /// # Safety contract
    ///
    /// Returns a raw pointer rather than a slice. A `&[u8]` or `&mut [u8]`
    /// would claim exclusive or immutable access that does not hold: the
    /// guest writes these bytes while the syscall runs, and a chain may point
    /// two descriptors at one address, so an iovec array would hold
    /// overlapping borrows. The pointer keeps the bounds check without that
    /// claim.
    ///
    /// The caller must stay within `len` and expect the bytes to change under
    /// it, as with `read` and `write`.
    pub fn host_ptr(&self, gpa: u64, len: usize) -> io::Result<*mut u8> {
        Ok(self.slice(gpa, len)?.ptr_guard_mut().as_ptr())
    }

    /// Reads a little-endian `u16` at `gpa`.
    pub fn read_u16(&self, gpa: u64) -> io::Result<u16> {
        self.load::<u16>(gpa).map(u16::from_le)
    }
    /// Reads a little-endian `u32` at `gpa`.
    pub fn read_u32(&self, gpa: u64) -> io::Result<u32> {
        self.load::<u32>(gpa).map(u32::from_le)
    }
    /// Reads a little-endian `u64` at `gpa`.
    pub fn read_u64(&self, gpa: u64) -> io::Result<u64> {
        self.load::<u64>(gpa).map(u64::from_le)
    }
    /// Writes a byte at `gpa`.
    pub fn write_u8(&self, gpa: u64, v: u8) -> io::Result<()> {
        self.store(gpa, v)
    }
    /// Writes a little-endian `u16` at `gpa`.
    pub fn write_u16(&self, gpa: u64, v: u16) -> io::Result<()> {
        self.store(gpa, v.to_le())
    }
    /// Writes a little-endian `u32` at `gpa`.
    pub fn write_u32(&self, gpa: u64, v: u32) -> io::Result<()> {
        self.store(gpa, v.to_le())
    }
    /// Writes a little-endian `u64` at `gpa`.
    pub fn write_u64(&self, gpa: u64, v: u64) -> io::Result<()> {
        self.store(gpa, v.to_le())
    }

    /// Returns the bounds-checked slice for `[gpa, gpa+len)` when one region
    /// holds all of it.
    fn slice(&self, gpa: u64, len: usize) -> io::Result<VolatileSlice<'_, ()>> {
        let mapping = self
            .mapped
            .iter()
            .find_map(|mapping| {
                let offset = gpa.checked_sub(mapping.region.gpa)?;
                let end = offset.checked_add(len as u64)?;
                (end <= mapping.region.size).then_some((mapping, offset))
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "guest range outside guest RAM or across two regions",
                )
            })?;
        mapping
            .0
            .mmap
            .get_slice(MemoryRegionAddress(mapping.1), len)
            .map_err(out_of_ram)
    }

    /// Reads one `T` at `gpa` as a single volatile load.
    fn load<T: ByteValued>(&self, gpa: u64) -> io::Result<T> {
        let slice = self.slice(gpa, size_of::<T>())?;
        Ok(slice.get_ref::<T>(0).map_err(out_of_ram)?.load())
    }

    /// Writes one `T` at `gpa` as a single volatile store.
    fn store<T: ByteValued>(&self, gpa: u64, v: T) -> io::Result<()> {
        let slice = self.slice(gpa, size_of::<T>())?;
        slice.get_ref::<T>(0).map_err(out_of_ram)?.store(v);
        Ok(())
    }
}

/// Converts a `vm-memory` bounds error into the `io::Error` every accessor
/// returns for a range the guest does not own.
fn out_of_ram<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, e)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALIGN: usize = MemRegion::ALIGN as usize;

    #[test]
    fn read_write_roundtrip_and_bounds() {
        let base = 0x4000_0000;
        let ram = GuestRam::from_ranges(&[(base, 0x1000)]);
        ram.write_u32(base + 0x10, 0xdead_beef).unwrap();
        assert_eq!(ram.read_u32(base + 0x10).unwrap(), 0xdead_beef);
        // Below the base and past the end both fail.
        assert!(ram.read_u32(base - 4).is_err());
        assert!(ram.read_u32(base + 0x0ffe).is_err());
    }

    // The length is guest-controlled too: a length that carries the range past
    // the end, or wraps a `u64`, must be refused.
    #[test]
    fn contains_bounds_the_length_as_well_as_the_address() {
        let base = 0x4000_0000u64;
        let len = 0x1000u64;
        let ram = GuestRam::from_ranges(&[(base, len as usize)]);

        assert!(ram.contains(base, len), "the whole mapping is in");
        assert!(ram.contains(base + len - 1, 1), "the last byte is in");
        assert!(ram.contains(base, 0), "an empty range at a valid address");

        assert!(!ram.contains(base, len + 1), "one byte past the end");
        assert!(!ram.contains(base + len - 1, 2), "straddling the end");
        assert!(!ram.contains(base - 1, 1), "below the base");
        assert!(!ram.contains(base + len, 1), "at the end");

        // The wrap edge. `base + u64::MAX` overflows, and `u64::MAX` also
        // exceeds a `usize` on a 32-bit host, so both arms have to refuse it.
        assert!(!ram.contains(base, u64::MAX));
        assert!(!ram.contains(u64::MAX, 1));
        assert!(!ram.contains(u64::MAX, u64::MAX));
    }

    #[test]
    fn scan_finds_guest_physical_addresses() {
        let base = 0x4000_0000;
        let ram = GuestRam::from_ranges(&[(base, 0x1000)]);
        ram.write(base + 0x100, b"needle-xy").unwrap();
        ram.write(base + 0x800, b"needle-xy").unwrap();
        let hits = ram.scan(b"needle-xy");
        assert_eq!(hits, vec![base + 0x100, base + 0x800]);
        assert!(ram.scan(b"not-present").is_empty());
    }

    #[test]
    fn host_ptr_in_bounds_addresses_the_mapping() {
        let base = 0x4000_0000;
        let ram = GuestRam::from_ranges(&[(base, 0x1000)]);
        let ptr = ram.host_ptr(base + 0x10, 4).unwrap();
        // SAFETY: `host_ptr` bounds-checked these four bytes.
        unsafe { std::ptr::copy_nonoverlapping(0xdead_beefu32.to_le_bytes().as_ptr(), ptr, 4) };
        let mut got = [0u8; 4];
        ram.read(base + 0x10, &mut got).unwrap();
        assert_eq!(u32::from_le_bytes(got), 0xdead_beef);
    }

    #[test]
    fn host_ptr_out_of_bounds_errors() {
        let base = 0x4000_0000;
        let ram = GuestRam::from_ranges(&[(base, 0x1000)]);
        assert!(ram.host_ptr(base - 4, 4).is_err());
        assert!(ram.host_ptr(base + 0x0ffe, 4).is_err());
    }

    // A region mapped at a file offset reads and writes the bytes at that
    // offset of the shared object, so a second process mapping the same
    // descriptor sees the same guest.
    #[test]
    fn mapped_regions_address_their_file_offsets() {
        const HIGH_BASE: u64 = 0x1_0000_0000;
        let shared = SharedRam::new(2 * ALIGN).expect("allocate");
        let regions = [
            MemRegion {
                gpa: 0,
                size: ALIGN as u64,
                file_offset: 0,
            },
            MemRegion {
                gpa: HIGH_BASE,
                size: ALIGN as u64,
                file_offset: ALIGN as u64,
            },
        ];
        let ram = GuestRam::new(&shared, &regions).expect("map");
        assert_eq!(ram.regions(), regions);
        ram.write(HIGH_BASE + 8, b"HIGH").expect("write high");
        ram.write(8, b"LOW!").expect("write low");

        // SAFETY: a second, read-only view of the whole object.
        let other = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                shared.len(),
                libc::PROT_READ,
                libc::MAP_SHARED,
                shared.fd(),
                0,
            )
        };
        assert_ne!(other, libc::MAP_FAILED);
        // SAFETY: both offsets are inside the `2 * ALIGN` mapping.
        let (low, high) = unsafe {
            let p = other.cast::<u8>();
            (
                std::slice::from_raw_parts(p.add(8), 4),
                std::slice::from_raw_parts(p.add(ALIGN + 8), 4),
            )
        };
        assert_eq!(low, b"LOW!");
        assert_eq!(high, b"HIGH", "the high region is not at its file offset");
        // SAFETY: unmapping the view we just made.
        unsafe { libc::munmap(other, shared.len()) };
    }

    // Every host page size divides 1 MiB, so a region that keeps the alignment
    // maps and registers on any host; one that does not is refused up front.
    #[test]
    fn misaligned_regions_are_refused() {
        let shared = SharedRam::new(2 * ALIGN).expect("allocate");
        let region = |gpa, size, file_offset| MemRegion {
            gpa,
            size,
            file_offset,
        };
        // `InvalidInput` is the alignment check's kind; a mapping failure the
        // host would report instead (`mmap` refusing the offset) is `Other`.
        for bad in [
            region(0, 0x1000, 0),
            region(0x1000, ALIGN as u64, 0),
            region(0, ALIGN as u64, 0x1000),
        ] {
            let err = GuestRam::new(&shared, &[bad])
                .err()
                .expect("misaligned region");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        }
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;

    const LOW: usize = 0x1000; // stand-in for the MMIO gap base
    const HIGH_BASE: u64 = 0x1_0000; // stand-in for 4 GiB
    const HIGH: usize = 0x1000;

    /// Builds two regions with a hole between them, the first byte of each
    /// marked so a mistranslation is visible rather than merely out of range.
    fn split() -> GuestRam {
        let ram = GuestRam::from_ranges(&[(0, LOW), (HIGH_BASE, HIGH)]);
        ram.write_u8(0, 0xa1).unwrap();
        ram.write_u8(HIGH_BASE, 0xb2).unwrap();
        ram
    }

    #[test]
    fn the_low_half_translates_identically() {
        let ram = split();
        let mut b = [0u8; 1];
        ram.read(0, &mut b).expect("low base");
        assert_eq!(b[0], 0xa1);
    }

    // A naive `gpa - ram_base` translation returns the wrong bytes here rather
    // than an error.
    #[test]
    fn the_high_half_translates_across_the_hole() {
        let ram = split();
        let mut b = [0u8; 1];
        ram.read(HIGH_BASE, &mut b).expect("high base");
        assert_eq!(b[0], 0xb2);
    }

    // Folding hole addresses into the high half is the bug that makes RAM
    // shadow the virtio registers.
    #[test]
    fn the_hole_itself_is_not_ram() {
        let ram = split();
        let mut b = [0u8; 1];
        for gpa in [LOW as u64, LOW as u64 + 1, HIGH_BASE - 1] {
            assert!(
                ram.read(gpa, &mut b).is_err(),
                "gpa {gpa:#x} should not be RAM"
            );
            assert!(!ram.contains(gpa, 1), "gpa {gpa:#x} should not be RAM");
        }
    }

    #[test]
    fn a_read_may_not_straddle_the_seam() {
        let ram = split();
        let mut buf = [0u8; 8];
        assert!(ram.read(LOW as u64 - 4, &mut buf).is_err());
        // But a read that ends exactly at the seam is fine.
        assert!(ram.read(LOW as u64 - 8, &mut buf).is_ok());
    }

    // The in-region prefix of a refused range must stay as it was.
    #[test]
    fn refused_write_touches_nothing() {
        let ram = split();
        ram.write(LOW as u64 - 4, &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
        assert!(ram.write(LOW as u64 - 4, &[0xee; 8]).is_err());
        let mut back = [0u8; 4];
        ram.read(LOW as u64 - 4, &mut back).unwrap();
        assert_eq!(
            back,
            [0x11, 0x22, 0x33, 0x44],
            "the in-region prefix was written"
        );
        let mut back = [0u8; 8];
        assert!(ram.read(LOW as u64 - 4, &mut back).is_err());
        assert_eq!(back, [0u8; 8], "a refused read fills nothing");
    }

    #[test]
    fn host_ptr_may_not_straddle_the_seam() {
        let ram = split();
        assert!(ram.host_ptr(LOW as u64 - 4, 8).is_err());
        assert!(ram.host_ptr(LOW as u64 - 8, 8).is_ok());
    }

    #[test]
    fn reads_past_the_end_of_the_high_half_fail() {
        let ram = split();
        let mut b = [0u8; 1];
        assert!(ram.read(HIGH_BASE + HIGH as u64, &mut b).is_err());
        assert!(ram.contains(HIGH_BASE + HIGH as u64 - 1, 1));
    }

    #[test]
    fn scan_reports_guest_addresses_on_both_sides() {
        let ram = GuestRam::from_ranges(&[(0, LOW), (HIGH_BASE, HIGH)]);
        ram.write(0x40, b"MARK").unwrap();
        ram.write(HIGH_BASE + 0x20, b"MARK").unwrap();
        assert_eq!(ram.scan(b"MARK"), vec![0x40, HIGH_BASE + 0x20]);
    }

    #[test]
    fn an_unsplit_guest_is_unaffected() {
        let ram = GuestRam::from_ranges(&[(0, 0x2000)]);
        ram.write_u8(0x1fff, 0xcc).unwrap();
        let mut b = [0u8; 1];
        ram.read(0x1fff, &mut b).expect("last byte");
        assert_eq!(b[0], 0xcc);
        assert!(ram.read(0x2000, &mut b).is_err());
    }
}

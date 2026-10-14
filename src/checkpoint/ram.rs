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

//! Guest RAM in a checkpoint: `ram.map` says which pages hold data, and
//! `ram.bin` holds those pages.
//!
//! Most of a guest's RAM is pages it never touched, and those read as zero on
//! both hosts, since a fresh RAM object is zero-filled. So the image stores
//! only the pages that are not all zero. `ram.map` is a 16-byte header, the
//! magic [`RAM_MAGIC`], a little-endian `u32` page size and a little-endian
//! `u32` region count, then one bitmap per region in address order. Bit `i` of
//! a region's bitmap is bit `i % 8` of its byte `i / 8`: 1 means page `i` is
//! the next page in `ram.bin`, 0 means it is all zero. `ram.bin` is the
//! present pages of every region, in order, with nothing between them.
//!
//! The reader refuses anything that does not match its regions exactly: a
//! bitmap of another length, a bit past the end of its region, a page count
//! that does not match the manifest, or a `ram.bin` that is short or long. A
//! half-loaded guest is never the outcome of a bad image.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use crate::memory::{GuestRam, GuestRamView};

/// The page size the image is cut into, the arm64 and x86-64 base page.
pub const PAGE_SIZE: u64 = 4096;

/// The first eight bytes of `ram.map`.
pub const RAM_MAGIC: &[u8; 8] = b"HVIRAM01";

/// The length of the `ram.map` header.
pub const HEADER_LEN: usize = 16;

/// The most regions an image may have. x86-64 guests have two, either side of
/// the MMIO hole, and arm64 guests one.
pub const MAX_REGIONS: usize = 8;

/// How much RAM one read copies out of the guest while writing the image.
const CHUNK: usize = 64 * PAGE_SIZE as usize;

/// One region of a RAM image, as the manifest records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegionImage {
    /// The guest-physical address the region starts at.
    pub gpa: u64,
    /// The region's length in bytes, a multiple of [`PAGE_SIZE`].
    pub size: u64,
    /// The pages of the region `ram.bin` holds.
    pub present_pages: u64,
}

impl RegionImage {
    /// Returns the number of pages in the region.
    #[must_use]
    pub fn pages(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Returns the length of the region's bitmap in `ram.map`.
    #[must_use]
    pub fn bitmap_len(&self) -> usize {
        // A region is at most a 64 GiB component's worth of pages, so the
        // bitmap fits in memory on any host this runs on.
        self.pages().div_ceil(8) as usize
    }
}

/// What [`write_ram`] wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RamImage {
    /// The regions, in address order.
    pub regions: Vec<RegionImage>,
    /// The whole of `ram.map`.
    pub map: Vec<u8>,
}

impl RamImage {
    /// Returns the number of bytes `ram.bin` holds.
    #[must_use]
    pub fn present_bytes(&self) -> u64 {
        self.regions
            .iter()
            .map(|r| r.present_pages * PAGE_SIZE)
            .sum()
    }

    /// Returns the size of guest RAM.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.regions.iter().map(|r| r.size).sum()
    }
}

/// Returns an error naming `component`.
fn bad(component: &str, what: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{component}: {what}"))
}

/// Writes every page of `ram` that is not all zero to `bin`, region by
/// region, and returns the map of which pages it wrote.
///
/// A page is tested a word at a time. `stopping` is asked between reads, so a
/// stop during a capture of a large guest is not held up by it. The caller
/// keeps the guest still while this runs: the vCPUs parked and no host thread
/// inside the pause gate.
///
/// # Errors
///
/// Errors when a region is not a whole number of pages, there are more than
/// [`MAX_REGIONS`], `stopping` returns true, or `bin` fails.
pub fn write_ram(
    ram: &GuestRamView,
    bin: &mut dyn Write,
    stopping: &dyn Fn() -> bool,
) -> io::Result<RamImage> {
    let regions = ram.regions();
    if regions.len() > MAX_REGIONS {
        return Err(bad(
            "ram.map",
            format!("{} RAM regions, at most {MAX_REGIONS}", regions.len()),
        ));
    }
    let mut map = header(regions.len());
    let mut images = Vec::with_capacity(regions.len());
    let mut buf = vec![0u8; CHUNK];
    for region in &regions {
        if region.size % PAGE_SIZE != 0 {
            return Err(bad(
                "ram.map",
                format!("region at {:#x} is not a whole number of pages", region.gpa),
            ));
        }
        let mut image = RegionImage {
            gpa: region.gpa,
            size: region.size,
            present_pages: 0,
        };
        let mut bitmap = vec![0u8; image.bitmap_len()];
        let mut offset = 0u64;
        while offset < region.size {
            if stopping() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "the run is stopping",
                ));
            }
            let len = (region.size - offset).min(CHUNK as u64) as usize;
            let chunk = &mut buf[..len];
            ram.read(region.gpa + offset, chunk)?;
            for (index, page) in chunk.chunks_exact(PAGE_SIZE as usize).enumerate() {
                if is_zero(page) {
                    continue;
                }
                let page_no = offset / PAGE_SIZE + index as u64;
                bitmap[(page_no / 8) as usize] |= 1 << (page_no % 8);
                image.present_pages += 1;
                bin.write_all(page)?;
            }
            offset += len as u64;
        }
        map.extend_from_slice(&bitmap);
        images.push(image);
    }
    bin.flush()?;
    Ok(RamImage {
        regions: images,
        map,
    })
}

/// Returns whether every 8-byte word of `page` is zero.
fn is_zero(page: &[u8]) -> bool {
    page.chunks_exact(8).all(|word| {
        u64::from_ne_bytes([
            word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
        ]) == 0
    })
}

/// Returns the `ram.map` header for `regions` regions.
fn header(regions: usize) -> Vec<u8> {
    let mut map = Vec::with_capacity(HEADER_LEN);
    map.extend_from_slice(RAM_MAGIC);
    map.extend_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
    map.extend_from_slice(&(regions as u32).to_le_bytes());
    map
}

/// Checks `map` against `regions`, the manifest's account of it, and returns
/// each region's bitmap.
///
/// # Errors
///
/// Errors, naming `ram.map`, when the header is wrong, the map is not exactly
/// the header and one bitmap per region, a region is not a whole number of
/// pages, a bit is set past the end of its region, or a region's set bits do
/// not number its `present_pages`.
pub fn check_map<'a>(map: &'a [u8], regions: &[RegionImage]) -> io::Result<Vec<&'a [u8]>> {
    if regions.len() > MAX_REGIONS {
        return Err(bad(
            "ram.map",
            format!("{} regions, at most {MAX_REGIONS}", regions.len()),
        ));
    }
    if map.len() < HEADER_LEN || &map[..8] != RAM_MAGIC {
        return Err(bad("ram.map", "no HVIRAM01 header"));
    }
    let page_size = u32::from_le_bytes([map[8], map[9], map[10], map[11]]);
    if u64::from(page_size) != PAGE_SIZE {
        return Err(bad(
            "ram.map",
            format!("page size {page_size}, this build reads {PAGE_SIZE}"),
        ));
    }
    let count = u32::from_le_bytes([map[12], map[13], map[14], map[15]]);
    if count as usize != regions.len() {
        return Err(bad(
            "ram.map",
            format!("{count} regions, the manifest has {}", regions.len()),
        ));
    }
    let mut rest = &map[HEADER_LEN..];
    let mut bitmaps = Vec::with_capacity(regions.len());
    for region in regions {
        if region.size == 0 || region.size % PAGE_SIZE != 0 {
            return Err(bad(
                "ram.map",
                format!("region at {:#x} is not a whole number of pages", region.gpa),
            ));
        }
        let len = region.bitmap_len();
        if rest.len() < len {
            return Err(bad(
                "ram.map",
                format!("the bitmap of the region at {:#x} is short", region.gpa),
            ));
        }
        let (bitmap, tail) = rest.split_at(len);
        rest = tail;
        let pages = region.pages();
        let spare = (len as u64 * 8 - pages) as u32;
        if spare > 0 && bitmap[len - 1] >> (8 - spare) != 0 {
            return Err(bad(
                "ram.map",
                format!(
                    "a bit is set past the end of the region at {:#x}",
                    region.gpa
                ),
            ));
        }
        let set: u64 = bitmap.iter().map(|b| u64::from(b.count_ones())).sum();
        if set != region.present_pages {
            return Err(bad(
                "ram.map",
                format!(
                    "the region at {:#x} marks {set} pages present, the manifest says {}",
                    region.gpa, region.present_pages
                ),
            ));
        }
        bitmaps.push(bitmap);
    }
    if !rest.is_empty() {
        return Err(bad(
            "ram.map",
            format!("{} bytes after the last bitmap", rest.len()),
        ));
    }
    Ok(bitmaps)
}

/// Copies the present pages of an image into `ram`, which must have exactly
/// the image's regions and be zero, as a fresh RAM object is.
///
/// Pages the map marks absent are not written. The map is checked whole
/// before the first page is copied, and `bin` must end exactly after the last
/// present page.
///
/// # Errors
///
/// Errors when `ram`'s regions are not the image's, the map fails
/// [`check_map`], or `bin` is short, long or fails, naming the component.
pub fn load_ram(
    map: &[u8],
    regions: &[RegionImage],
    bin: &mut dyn Read,
    ram: &GuestRam,
) -> io::Result<()> {
    let bitmaps = check_map(map, regions)?;
    let have = ram.regions();
    let same = have.len() == regions.len()
        && have
            .iter()
            .zip(regions)
            .all(|(h, r)| h.gpa == r.gpa && h.size == r.size);
    if !same {
        return Err(bad(
            "ram.map",
            "the image's regions are not those of the guest RAM it is loaded into",
        ));
    }
    let mut page = vec![0u8; PAGE_SIZE as usize];
    for (region, bitmap) in regions.iter().zip(bitmaps) {
        for page_no in 0..region.pages() {
            if bitmap[(page_no / 8) as usize] & (1 << (page_no % 8)) == 0 {
                continue;
            }
            bin.read_exact(&mut page).map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    bad("ram.bin", "ends before the last present page")
                } else {
                    e
                }
            })?;
            ram.write(region.gpa + page_no * PAGE_SIZE, &page)?;
        }
    }
    let mut extra = [0u8; 1];
    loop {
        match bin.read(&mut extra) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(bad("ram.bin", "has bytes after the last present page")),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: usize = 1 << 20;

    /// A two-region guest with data in a few pages of each, and one page
    /// whose only non-zero byte is its last, which a test of the first word
    /// alone would miss.
    fn sparse() -> GuestRam {
        let ram = GuestRam::from_ranges(&[(0x4000_0000, MIB), (0x1_0000_0000, 2 * MIB)]);
        ram.write(0x4000_0000, b"first page").unwrap();
        ram.write(0x4000_0000 + 5 * PAGE_SIZE + 4095, &[0xff])
            .unwrap();
        ram.write(0x1_0000_0000 + 511 * PAGE_SIZE, b"last page of the region")
            .unwrap();
        ram
    }

    fn never() -> bool {
        false
    }

    fn image(ram: &GuestRam) -> (RamImage, Vec<u8>) {
        let mut bin = Vec::new();
        let image = write_ram(ram, &mut bin, &never).unwrap();
        (image, bin)
    }

    #[test]
    fn only_pages_with_data_are_written() {
        let (image, bin) = image(&sparse());
        assert_eq!(
            image.regions,
            [
                RegionImage {
                    gpa: 0x4000_0000,
                    size: MIB as u64,
                    present_pages: 2
                },
                RegionImage {
                    gpa: 0x1_0000_0000,
                    size: 2 * MIB as u64,
                    present_pages: 1
                },
            ]
        );
        assert_eq!(bin.len() as u64, 3 * PAGE_SIZE);
        assert_eq!(image.present_bytes(), 3 * PAGE_SIZE);
        assert_eq!(image.total_bytes(), 3 * MIB as u64);
        assert_eq!(&image.map[..8], RAM_MAGIC);
        assert_eq!(image.map.len(), HEADER_LEN + 32 + 64);
        // Page 0 and page 5 of the first region, page 511 of the second.
        assert_eq!(image.map[HEADER_LEN], 0b0010_0001);
        assert_eq!(image.map[HEADER_LEN + 32 + 63], 0b1000_0000);
        assert_eq!(&bin[..10], b"first page");
    }

    #[test]
    fn an_image_loads_back_into_fresh_ram() {
        let source = sparse();
        let (image, bin) = image(&source);
        let fresh = GuestRam::from_ranges(&[(0x4000_0000, MIB), (0x1_0000_0000, 2 * MIB)]);
        load_ram(&image.map, &image.regions, &mut bin.as_slice(), &fresh).unwrap();
        for region in source.regions() {
            let (mut a, mut b) = (
                vec![0u8; region.size as usize],
                vec![1u8; region.size as usize],
            );
            source.read(region.gpa, &mut a).unwrap();
            fresh.read(region.gpa, &mut b).unwrap();
            assert!(a == b, "region at {:#x} differs", region.gpa);
        }
    }

    #[test]
    fn a_stop_ends_the_write() {
        let mut bin = Vec::new();
        let err = write_ram(&sparse(), &mut bin, &|| true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }

    fn refusal(map: &[u8], regions: &[RegionImage], bin: &[u8]) -> String {
        let fresh = GuestRam::from_ranges(&[(0x4000_0000, MIB), (0x1_0000_0000, 2 * MIB)]);
        let err = load_ram(map, regions, &mut &bin[..], &fresh).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        err.to_string()
    }

    #[test]
    fn a_bitmap_of_another_length_is_refused() {
        let (image, bin) = image(&sparse());
        let mut short = image.map.clone();
        short.pop();
        assert!(refusal(&short, &image.regions, &bin).starts_with("ram.map: the bitmap"));
        let mut long = image.map.clone();
        long.push(0);
        assert!(refusal(&long, &image.regions, &bin).contains("after the last bitmap"));
    }

    // Three pages leave five spare bits in the bitmap's one byte, and a set
    // one there names a page the region does not have.
    #[test]
    fn a_bit_past_the_region_is_refused() {
        let regions = [RegionImage {
            gpa: 0,
            size: 3 * PAGE_SIZE,
            present_pages: 1,
        }];
        let mut map = header(1);
        map.push(0b0000_1000);
        let err = check_map(&map, &regions).unwrap_err();
        assert!(err.to_string().contains("past the end"), "{err}");
        map[HEADER_LEN] = 0b0000_0100;
        assert_eq!(check_map(&map, &regions).unwrap().len(), 1);
    }

    #[test]
    fn a_count_that_disagrees_with_the_manifest_is_refused() {
        let (image, bin) = image(&sparse());
        let mut regions = image.regions.clone();
        regions[1].present_pages = 2;
        assert!(refusal(&image.map, &regions, &bin).contains("the manifest says 2"));
        let mut regions = image.regions.clone();
        regions.pop();
        assert!(refusal(&image.map, &regions, &bin).contains("2 regions, the manifest has 1"));
    }

    #[test]
    fn a_bad_header_is_refused() {
        let (image, bin) = image(&sparse());
        let mut map = image.map.clone();
        map[0] = b'X';
        assert!(refusal(&map, &image.regions, &bin).contains("no HVIRAM01 header"));
        let mut map = image.map.clone();
        map[9] = 0x20;
        assert!(refusal(&map, &image.regions, &bin).contains("page size"));
        assert!(refusal(&image.map[..4], &image.regions, &bin).contains("header"));
    }

    #[test]
    fn a_truncated_or_padded_bin_is_refused() {
        let (image, bin) = image(&sparse());
        assert_eq!(
            refusal(&image.map, &image.regions, &bin[..bin.len() - 1]),
            "ram.bin: ends before the last present page"
        );
        let mut long = bin.clone();
        long.push(0);
        assert_eq!(
            refusal(&image.map, &image.regions, &long),
            "ram.bin: has bytes after the last present page"
        );
    }

    #[test]
    fn ram_of_other_regions_is_refused() {
        let (image, bin) = image(&sparse());
        let other = GuestRam::from_ranges(&[(0x4000_0000, 3 * MIB)]);
        let err = load_ram(&image.map, &image.regions, &mut bin.as_slice(), &other).unwrap_err();
        assert!(
            err.to_string().contains("not those of the guest RAM"),
            "{err}"
        );
    }
}

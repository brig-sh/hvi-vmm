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

//! arm64 Linux `Image` header parsing.
//!
//! The arm64 boot protocol (Documentation/arm64/booting.rst) puts a 64-byte
//! header at the front of the flat `Image`. The loader only needs three fields
//! from it — where to place the image (`text_offset`), how much room it needs
//! (`image_size`), and the magic to sanity-check the file — so we parse those
//! directly rather than pull `linux-loader` (which would drag a second,
//! version-pinned `vm-memory` in; `applevisor` owns guest RAM here anyway).
//!
//! Header layout (all little-endian):
//! ```text
//!   0x00 u32 code0            0x20 u64 res2 (0)
//!   0x04 u32 code1            0x28 u64 res3 (0)
//!   0x08 u64 text_offset      0x30 u64 res4 (0)
//!   0x10 u64 image_size       0x38 u32 magic = 0x644d5241 "ARM\x64"
//!   0x18 u64 flags            0x3c u32 res5 (PE header offset)
//! ```

/// arm64 `Image` magic, "ARM\x64" read as a little-endian `u32`.
const ARM64_MAGIC: u32 = 0x644d_5241;

/// The header length; a valid `Image` is at least this long.
const HEADER_LEN: usize = 64;

/// The fields the loader needs from an arm64 `Image` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64Image {
    /// Load offset from the 2 MiB-aligned base of usable RAM.
    pub text_offset: u64,
    /// Effective image size (header + text + bss); the kernel may write up to
    /// here at runtime, so the loader reserves it. Zero on very old kernels,
    /// which the loader treats as "unknown" and falls back to the file length.
    pub image_size: u64,
}

impl Arm64Image {
    /// Parses the header at the front of `image`.
    ///
    /// # Errors
    ///
    /// Errors if the slice is too short or the magic does not match (i.e. it is
    /// not a flat arm64 `Image` — e.g. a gzip-compressed `Image.gz`, which the
    /// caller must decompress first).
    pub fn parse(image: &[u8]) -> Result<Arm64Image, String> {
        if image.len() < HEADER_LEN {
            return Err(format!(
                "image too short: {} bytes, need at least {HEADER_LEN}",
                image.len()
            ));
        }
        let magic = u32::from_le_bytes(image[0x38..0x3c].try_into().unwrap());
        if magic != ARM64_MAGIC {
            return Err(format!(
                "not an arm64 Image: magic {magic:#010x} != {ARM64_MAGIC:#010x} \
                 (a compressed Image.gz must be decompressed first)"
            ));
        }
        let text_offset = u64::from_le_bytes(image[0x08..0x10].try_into().unwrap());
        let image_size = u64::from_le_bytes(image[0x10..0x18].try_into().unwrap());
        Ok(Arm64Image {
            text_offset,
            image_size,
        })
    }

    /// The RAM the kernel needs reserved: `image_size` when the header carries
    /// one, otherwise the on-disk length as a floor.
    #[must_use]
    pub fn reserved_size(&self, file_len: u64) -> u64 {
        if self.image_size == 0 {
            file_len
        } else {
            self.image_size
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_header(text_offset: u64, image_size: u64, magic: u32) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_LEN];
        h[0x08..0x10].copy_from_slice(&text_offset.to_le_bytes());
        h[0x10..0x18].copy_from_slice(&image_size.to_le_bytes());
        h[0x38..0x3c].copy_from_slice(&magic.to_le_bytes());
        h
    }

    #[test]
    fn parses_valid_header() {
        let h = synth_header(0, 0x0142_0000, ARM64_MAGIC);
        let img = Arm64Image::parse(&h).unwrap();
        assert_eq!(img.text_offset, 0);
        assert_eq!(img.image_size, 0x0142_0000);
        assert_eq!(img.reserved_size(0x1000), 0x0142_0000);
    }

    #[test]
    fn rejects_bad_magic() {
        let h = synth_header(0, 0x1000, 0xdead_beef);
        assert!(Arm64Image::parse(&h).is_err());
    }

    #[test]
    fn rejects_short_image() {
        assert!(Arm64Image::parse(&[0u8; 8]).is_err());
    }

    #[test]
    fn zero_image_size_falls_back_to_file_len() {
        let h = synth_header(0x8_0000, 0, ARM64_MAGIC);
        let img = Arm64Image::parse(&h).unwrap();
        assert_eq!(img.reserved_size(0x0080_0000), 0x0080_0000);
    }
}

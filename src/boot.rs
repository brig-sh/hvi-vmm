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

//! arm64 Linux `Image`, devicetree and initramfs placement in guest RAM.
//!
//! `linux-loader` reads the 64-byte `Image` header
//! (Documentation/arm64/booting.rst), checks the magic, copies the file to
//! `RAM_BASE + text_offset`, and writes the devicetree under the boot
//! protocol's size cap. The header's `image_size` is the RAM the kernel needs
//! at runtime, header through BSS, more than the file holds;
//! [`LoadedKernel`](crate::boot::LoadedKernel) carries it so the layout keeps
//! the devicetree and initramfs clear of it.
//! [`Payload::load`](crate::boot::Payload::load) places all three images;
//! [`LoadedKernel::plan`](crate::boot::LoadedKernel::plan) computes the
//! placement without writing.

use std::io::Cursor;

use linux_loader::loader::pe::{arm64_image_header, load_dtb, PE};
use linux_loader::loader::KernelLoader;
use vm_memory::{Address, ByteValued, GuestAddress, GuestMemoryBackend};

use crate::fdt::{self, VirtioDevices};
use crate::layout::{GicLayout, GuestLayout, RAM_BASE};

/// arm64 `Image` magic, "ARM\x64" read as a little-endian `u32`.
const IMAGE_MAGIC: u32 = 0x644d_5241;

/// The `text_offset` a header that predates `image_size` implies, per
/// booting.rst; `linux-loader` applies the same rule.
const LEGACY_TEXT_OFFSET: u64 = 0x8_0000;

/// The provisional devicetree slot the first layout pass reserves before the
/// blob's real length is known.
const PROVISIONAL_DTB_SIZE: u64 = 0x4000;

/// Where the kernel lands and how much RAM it claims from there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedKernel {
    /// Guest-physical address of the first byte of the image.
    pub addr: u64,
    /// RAM the kernel needs from `addr`, the header's `image_size` or the file
    /// length on a header that leaves it zero.
    pub size: u64,
}

impl LoadedKernel {
    /// Reads the placement from the `Image` header alone, without copying the
    /// image anywhere.
    ///
    /// # Errors
    ///
    /// Errors when `kernel` is too short for a header or is not a flat arm64
    /// `Image` (a gzip-compressed `Image.gz` must be decompressed first).
    pub fn from_header(kernel: &[u8]) -> Result<Self, String> {
        let Some(bytes) = kernel.get(..size_of::<arm64_image_header>()) else {
            return Err(format!(
                "image too short for an arm64 Image header: {} bytes",
                kernel.len()
            ));
        };
        let mut header = arm64_image_header::default();
        header.as_mut_slice().copy_from_slice(bytes);
        if u32::from_le(header.magic) != IMAGE_MAGIC {
            return Err(
                "not an arm64 Image (a compressed Image.gz must be decompressed first)".into(),
            );
        }
        let image_size = u64::from_le(header.image_size);
        let text_offset = if image_size == 0 {
            LEGACY_TEXT_OFFSET
        } else {
            u64::from_le(header.text_offset)
        };
        Ok(Self {
            addr: RAM_BASE + text_offset,
            size: image_size.max(kernel.len() as u64),
        })
    }

    /// Copies the flat `Image` in `kernel` to `RAM_BASE + text_offset`.
    ///
    /// # Errors
    ///
    /// Errors when `kernel` is not a flat arm64 `Image` or does not fit in
    /// RAM.
    pub fn load<M: GuestMemoryBackend>(mem: &M, kernel: &[u8]) -> Result<Self, String> {
        let loaded = PE::load(
            mem,
            Some(GuestAddress(RAM_BASE)),
            &mut Cursor::new(kernel),
            None,
        )
        .map_err(|e| format!("loading the arm64 Image: {e}"))?;
        let placed = Self::from_header(kernel)?;
        if placed.addr != loaded.kernel_load.raw_value() {
            return Err(format!(
                "kernel placement disagrees with the loader: {:#x} vs {:#x}",
                placed.addr,
                loaded.kernel_load.raw_value()
            ));
        }
        Ok(placed)
    }

    /// Computes the layout for this kernel and builds the devicetree that
    /// describes it.
    ///
    /// The devicetree's own length feeds the initramfs placement it records,
    /// so the blob is built twice, once with a provisional slot and again at
    /// the settled layout.
    ///
    /// # Errors
    ///
    /// Errors when the images do not fit in RAM or the devicetree cannot be
    /// built.
    pub fn plan(
        self,
        ram_size: u64,
        initrd_size: u64,
        gic: &GicLayout,
        num_cpus: u32,
        cmdline: &str,
        devices: VirtioDevices,
    ) -> Result<Plan, String> {
        let provisional = GuestLayout::new(
            ram_size,
            self.addr,
            self.size,
            PROVISIONAL_DTB_SIZE,
            initrd_size,
        );
        let dtb = fdt::build(&provisional, gic, num_cpus, cmdline, devices)
            .map_err(|e| format!("building the devicetree: {e}"))?;
        let layout = GuestLayout::new(
            ram_size,
            self.addr,
            self.size,
            dtb.len() as u64,
            initrd_size,
        );
        let dtb = fdt::build(&layout, gic, num_cpus, cmdline, devices)
            .map_err(|e| format!("building the devicetree: {e}"))?;
        layout.validate()?;
        Ok(Plan { layout, dtb })
    }
}

/// The settled layout and the devicetree that describes it.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Where the kernel, devicetree and initramfs go.
    pub layout: GuestLayout,
    /// The devicetree blob for `layout`.
    pub dtb: Vec<u8>,
}

/// The files and command line a guest boots with.
#[derive(Debug, Clone, Copy)]
pub struct Payload<'a> {
    /// The flat arm64 `Image`.
    pub kernel: &'a [u8],
    /// The initramfs cpio, if any.
    pub initramfs: Option<&'a [u8]>,
    /// The kernel command line for `/chosen`.
    pub cmdline: &'a str,
}

impl Payload<'_> {
    /// Places the kernel, devicetree and initramfs in `ram_size` bytes of
    /// guest RAM at `RAM_BASE`, returning where each went.
    ///
    /// # Errors
    ///
    /// Errors when the kernel is not a flat arm64 `Image`, the images do not
    /// fit in RAM, or the devicetree cannot be built or written.
    pub fn load<M: GuestMemoryBackend>(
        self,
        mem: &M,
        ram_size: u64,
        gic: &GicLayout,
        num_cpus: u32,
        devices: VirtioDevices,
    ) -> Result<GuestLayout, String> {
        let kernel = LoadedKernel::load(mem, self.kernel)?;
        let initrd_size = self.initramfs.map_or(0, |v| v.len() as u64);
        let plan = kernel.plan(ram_size, initrd_size, gic, num_cpus, self.cmdline, devices)?;
        write_dtb(mem, plan.layout.dtb_addr, &plan.dtb)?;
        if let Some(initramfs) = self.initramfs {
            mem.get_slice(GuestAddress(plan.layout.initrd_addr), initramfs.len())
                .map_err(|e| format!("placing the initramfs: {e}"))?
                .copy_from(initramfs);
        }
        Ok(plan.layout)
    }
}

/// Writes the finished devicetree blob at `addr`.
///
/// # Errors
///
/// Errors when the blob exceeds the boot protocol's 2 MiB devicetree limit or
/// does not fit in RAM at `addr`.
fn write_dtb<M: GuestMemoryBackend>(mem: &M, addr: u64, dtb: &[u8]) -> Result<(), String> {
    load_dtb(mem, GuestAddress(addr), &mut Cursor::new(dtb))
        .map_err(|e| format!("writing the devicetree: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guestmem::GuestRam;

    const RAM_LEN: usize = 8 << 20;

    /// Builds an `Image` with the header fields the loader reads and a body of
    /// `body_len` bytes with a recognisable pattern.
    fn synthetic_image(text_offset: u64, image_size: u64, body_len: usize) -> Vec<u8> {
        let header = arm64_image_header {
            text_offset: text_offset.to_le(),
            image_size: image_size.to_le(),
            magic: IMAGE_MAGIC.to_le(),
            ..Default::default()
        };
        let mut image = header.as_slice().to_vec();
        image.extend((0..body_len).map(|i| (i % 251) as u8));
        image
    }

    #[test]
    fn loads_the_image_at_ram_base_plus_text_offset() {
        let mem = GuestRam::from_ranges(&[(RAM_BASE, RAM_LEN)]);
        let image = synthetic_image(0x8_0000, 0x40_0000, 0x3000);
        let kernel = LoadedKernel::load(mem.memory(), &image).expect("a flat Image loads");
        assert_eq!(kernel.addr, RAM_BASE + 0x8_0000);
        assert_eq!(
            kernel.size, 0x40_0000,
            "the header's image_size is reserved"
        );
        let mut back = vec![0u8; image.len()];
        mem.read(kernel.addr, &mut back).unwrap();
        assert_eq!(
            back, image,
            "the whole file, header included, lands at addr"
        );
    }

    // `dump-fdt` prints the header-only placement, so it must agree with the
    // loader, legacy rule included.
    #[test]
    fn header_placement_matches_the_loader() {
        let mem = GuestRam::from_ranges(&[(RAM_BASE, RAM_LEN)]);
        for image in [
            synthetic_image(0x8_0000, 0x40_0000, 0x3000),
            synthetic_image(0x20_0000, 0x30_0000, 0x1000),
            synthetic_image(0, 0, 0x3000),
        ] {
            let placed = LoadedKernel::from_header(&image).expect("header");
            let loaded = LoadedKernel::load(mem.memory(), &image).expect("load");
            assert_eq!(placed, loaded);
        }
    }

    #[test]
    fn header_without_image_size_reserves_the_file_at_the_legacy_offset() {
        let image = synthetic_image(0, 0, 0x3000);
        let kernel = LoadedKernel::from_header(&image).expect("an old header still places");
        assert_eq!(kernel.addr, RAM_BASE + LEGACY_TEXT_OFFSET);
        assert_eq!(kernel.size, image.len() as u64);
    }

    #[test]
    fn rejects_a_compressed_or_truncated_image() {
        let mut gz = vec![0x1f, 0x8b, 0x08, 0x00];
        gz.resize(0x1000, 0);
        let err = LoadedKernel::from_header(&gz).expect_err("gzip is not a flat Image");
        assert!(err.contains("arm64 Image"), "{err}");
        let err = LoadedKernel::from_header(&gz[..16]).expect_err("shorter than a header");
        assert!(err.contains("too short"), "{err}");

        let mem = GuestRam::from_ranges(&[(RAM_BASE, RAM_LEN)]);
        let err = LoadedKernel::load(mem.memory(), &gz).expect_err("the loader refuses it too");
        assert!(err.contains("arm64 Image"), "{err}");
    }

    #[test]
    fn rejects_an_image_larger_than_ram() {
        let mem = GuestRam::from_ranges(&[(RAM_BASE, RAM_LEN)]);
        let image = synthetic_image(0, 0, RAM_LEN);
        assert!(LoadedKernel::load(mem.memory(), &image).is_err());
    }

    #[test]
    fn writes_the_dtb_at_its_slot_within_the_protocol_cap() {
        let mem = GuestRam::from_ranges(&[(RAM_BASE, RAM_LEN)]);
        let dtb: Vec<u8> = (0..0x800u32).map(|i| (i % 253) as u8).collect();
        let addr = RAM_BASE + 0x20_0000;
        write_dtb(mem.memory(), addr, &dtb).expect("the blob fits");
        let mut back = vec![0u8; dtb.len()];
        mem.read(addr, &mut back).unwrap();
        assert_eq!(back, dtb);
        assert!(
            write_dtb(mem.memory(), RAM_BASE + RAM_LEN as u64 - 0x10, &dtb).is_err(),
            "a blob past the end of RAM is refused"
        );
        let oversized = vec![0u8; 0x20_0001];
        let err = write_dtb(mem.memory(), addr, &oversized).expect_err("over 2 MiB");
        assert!(err.contains("devicetree"), "{err}");
    }

    #[test]
    fn plan_settles_the_initramfs_after_the_real_devicetree() {
        let kernel = LoadedKernel {
            addr: RAM_BASE,
            size: 0x40_0000,
        };
        let Plan { layout, dtb } = kernel
            .plan(
                512 << 20,
                0x1000,
                &GicLayout::QEMU_VIRT,
                2,
                "console=ttyAMA0",
                VirtioDevices::default(),
            )
            .expect("plan");
        assert_eq!(layout.dtb_addr, RAM_BASE + 0x40_0000);
        assert_eq!(layout.dtb_size, dtb.len() as u64);
        assert!(layout.initrd_addr >= layout.dtb_addr + dtb.len() as u64);
        assert_eq!(layout.initrd_addr % 0x1000, 0);
        assert!(
            kernel
                .plan(
                    4 << 20,
                    0,
                    &GicLayout::QEMU_VIRT,
                    1,
                    "",
                    VirtioDevices::default()
                )
                .is_err(),
            "a kernel larger than RAM does not fit"
        );
    }

    #[test]
    fn load_places_every_image_where_the_layout_says() {
        let mem = GuestRam::from_ranges(&[(RAM_BASE, RAM_LEN)]);
        let image = synthetic_image(0, 0x40_0000, 0x2000);
        let initramfs: Vec<u8> = (0..0x1800u32).map(|i| (i % 241) as u8).collect();
        let layout = Payload {
            kernel: &image,
            initramfs: Some(&initramfs),
            cmdline: "console=ttyAMA0",
        }
        .load(
            mem.memory(),
            RAM_LEN as u64,
            &GicLayout::QEMU_VIRT,
            1,
            VirtioDevices::default(),
        )
        .expect("load");
        assert_eq!(layout.kernel_addr, RAM_BASE);
        let mut back = vec![0u8; image.len()];
        mem.read(layout.kernel_addr, &mut back).unwrap();
        assert_eq!(back, image);
        let mut back = vec![0u8; initramfs.len()];
        mem.read(layout.initrd_addr, &mut back).unwrap();
        assert_eq!(back, initramfs);
        assert_eq!(
            mem.read_u32(layout.dtb_addr).unwrap(),
            0xd00d_feed_u32.swap_bytes(),
            "the devicetree header magic sits at dtb_addr"
        );
    }
}

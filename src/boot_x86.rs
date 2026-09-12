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

//! x86-64 Linux boot preparation, from a `bzImage` or an uncompressed
//! `vmlinux` to a written `boot_params` zero page, command line and entry
//! point.
//!
//! `linux-loader` handles both formats. For a `bzImage` it reads the setup
//! header, checks the boot protocol version and copies the protected-mode
//! kernel to its `code32_start`; the entry is `code32_start + 0x200`. For a
//! `vmlinux` it copies each `PT_LOAD` segment to its physical address; the
//! entry is `e_entry` and the file carries no setup header, so hvi supplies the
//! fields the 64-bit entry reads. Either way hvi fills in the header fields a
//! boot loader owns, the e820 map from the RAM regions, and the command line.
//! The vCPU then enters in long mode at the kernel entry with `RSI` pointing
//! at the zero page: the Linux 64-bit boot protocol.
//!
//! This module mirrors Firecracker's `arch::x86_64` loader.

use std::fmt;
use std::io::Cursor;

use linux_loader::configurator::linux::LinuxBootConfigurator;
use linux_loader::configurator::{BootConfigurator, BootParams};
use linux_loader::elf::ELFMAG;
use linux_loader::loader::bootparam::{boot_e820_entry, boot_params, setup_header};
use linux_loader::loader::bzimage::BzImage;
use linux_loader::loader::elf::Elf;
use linux_loader::loader::{load_cmdline, Cmdline, KernelLoader, KernelLoaderResult};
use vm_memory::{Address, GuestAddress, GuestMemoryBackend, GuestMemoryRegion};

use crate::layout_x86::{
    CMDLINE_ADDR, CMDLINE_MAX, EBDA_START, HIGH_MEM_START, KERNEL_ENTRY_OFF, RAM_BASE, ZERO_PAGE,
};

/// The e820 type of usable RAM (`E820_TYPE_RAM`); the bindings carry the table
/// but not the type constants.
const E820_RAM: u32 = 1;

/// The setup header magic, "HdrS" read as a little-endian `u32`.
const HEADER_MAGIC: u32 = 0x5372_6448;

/// The boot sector signature every bzImage ends its first sector with.
const BOOT_FLAG: u16 = 0xaa55;

/// The boot protocol version the synthesized `vmlinux` header claims, the one
/// the kernel's own direct-entry path (`arch/x86/platform/pvh`) writes.
const SYNTHESIZED_PROTOCOL: u16 = 0x020c;

/// The x86 kernel image formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFormat {
    /// A `bzImage` with its real-mode setup header.
    BzImage,
    /// An uncompressed `vmlinux` ELF.
    Vmlinux,
}

impl KernelFormat {
    /// Returns the format `kernel` is in, a `vmlinux` when it starts with the
    /// ELF magic and a `bzImage` otherwise.
    #[must_use]
    pub fn detect(kernel: &[u8]) -> Self {
        if kernel.starts_with(ELFMAG) {
            KernelFormat::Vmlinux
        } else {
            KernelFormat::BzImage
        }
    }
}

impl fmt::Display for KernelFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KernelFormat::BzImage => "bzImage",
            KernelFormat::Vmlinux => "vmlinux",
        })
    }
}

/// The loaded kernel and how to enter it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedKernel {
    /// The format the kernel file turned out to be.
    pub format: KernelFormat,
    /// Where the `boot_params` zero page was written.
    pub zero_page_addr: u64,
    /// Guest-physical address to place the initramfs, if any.
    pub initrd_addr: Option<u64>,
    /// 64-bit entry point (RIP).
    pub entry: u64,
}

impl LoadedKernel {
    /// Loads `kernel` into `mem` along with its zero page and command line,
    /// and reserves a slot for the initramfs.
    ///
    /// The e820 map is the region list of `mem`: the region at address 0 is low
    /// RAM, split around the EBDA, and every further region is one entry.
    ///
    /// # Errors
    ///
    /// Errors when `kernel` is neither a `vmlinux` ELF nor a `bzImage` with
    /// boot protocol 2.00 or later, when `mem` has no region at address 0,
    /// when the kernel or the command line does not fit, when the
    /// initramfs would overlap the kernel in low RAM or does not fit its
    /// 32-bit header fields, or when the e820 table is full.
    pub fn load<M: GuestMemoryBackend>(
        mem: &M,
        kernel: &[u8],
        cmdline: &str,
        initrd_len: u64,
    ) -> Result<Self, String> {
        // The zero page, the boot structures and the kernel all live in the
        // region at address 0; without it nothing below can be written.
        let low_end = mem
            .find_region(GuestAddress(RAM_BASE))
            .ok_or("guest RAM has no region at address 0")?
            .len();
        let (loaded, format) = load_kernel(mem, kernel)?;
        let kernel_load = loaded.kernel_load.raw_value();
        let mut params = boot_params {
            hdr: match loaded.setup_header {
                // The image's own header, `code32_start` updated by the loader.
                Some(hdr) => hdr,
                // A `vmlinux` has none. The 64-bit entry copies `boot_params`
                // again when `version` is zero, so the version is set; the rest
                // is filled in below.
                None => setup_header {
                    boot_flag: BOOT_FLAG,
                    header: HEADER_MAGIC,
                    version: SYNTHESIZED_PROTOCOL,
                    ..Default::default()
                },
            },
            ..Default::default()
        };
        params.hdr.type_of_loader = 0xff; // undefined boot loader

        let cmdline = Cmdline::try_from(cmdline, CMDLINE_MAX)
            .map_err(|e| format!("kernel command line: {e}"))?;
        load_cmdline(mem, GuestAddress(CMDLINE_ADDR), &cmdline)
            .map_err(|e| format!("writing the kernel command line: {e}"))?;
        params.hdr.cmd_line_ptr = CMDLINE_ADDR as u32;

        // e820: RAM below the EBDA, then from 1 MiB to the end of the low
        // region, then every further region as it is. The guest treats
        // anything omitted as not memory, so the hole is left out: described
        // as RAM, it would be allocated over the devices.
        for region in mem.iter() {
            let start = region.start_addr().raw_value();
            if start == RAM_BASE {
                add_e820(&mut params, RAM_BASE, EBDA_START.min(low_end))?;
                if low_end > HIGH_MEM_START {
                    add_e820(&mut params, HIGH_MEM_START, low_end - HIGH_MEM_START)?;
                }
            } else {
                add_e820(&mut params, start, region.len())?;
            }
        }

        // initrd placement: 2 MiB-aligned near the top of *low* RAM, above the
        // room the kernel needs: its segments through BSS for a vmlinux, and
        // the space a bzImage decompresses into (`init_size`). It has
        // to be low RAM regardless of guest size, because the header
        // field that points at it is 32 bits wide.
        let initrd_addr = if initrd_len > 0 {
            let kernel_room = loaded
                .kernel_end
                .max(kernel_load + u64::from(params.hdr.init_size));
            let addr = low_end.saturating_sub(initrd_len) & !0x1f_ffff;
            if addr < kernel_room {
                return Err(format!(
                    "initramfs ({initrd_len:#x} bytes) does not fit above the kernel \
                 (needs RAM through {kernel_room:#x}) in low RAM ({low_end:#x})"
                ));
            }
            params.hdr.ramdisk_image = u32::try_from(addr).map_err(|_| {
                format!("initramfs address {addr:#x} exceeds the 32-bit ramdisk_image field")
            })?;
            params.hdr.ramdisk_size = u32::try_from(initrd_len).map_err(|_| {
                format!("initramfs ({initrd_len:#x} bytes) exceeds the 32-bit ramdisk_size field")
            })?;
            Some(addr)
        } else {
            None
        };

        LinuxBootConfigurator::write_bootparams(
            &BootParams::new(&params, GuestAddress(ZERO_PAGE)),
            mem,
        )
        .map_err(|e| format!("writing boot_params: {e}"))?;

        Ok(LoadedKernel {
            format,
            zero_page_addr: ZERO_PAGE,
            initrd_addr,
            entry: match format {
                KernelFormat::BzImage => kernel_load + KERNEL_ENTRY_OFF,
                KernelFormat::Vmlinux => kernel_load,
            },
        })
    }
}

/// Loads `kernel` as the format `detect` reports; either lands at the
/// address the image names.
fn load_kernel<M: GuestMemoryBackend>(
    mem: &M,
    kernel: &[u8],
) -> Result<(KernelLoaderResult, KernelFormat), String> {
    let mut image = Cursor::new(kernel);
    let highmem = Some(GuestAddress(HIGH_MEM_START));
    let format = KernelFormat::detect(kernel);
    if format == KernelFormat::Vmlinux {
        let loaded = Elf::load(mem, None, &mut image, highmem)
            .map_err(|e| format!("loading the vmlinux: {e}"))?;
        return Ok((loaded, format));
    }
    let loaded = BzImage::load(mem, None, &mut image, highmem)
        .map_err(|e| format!("loading the bzImage: {e}"))?;
    // The loader checks the magic and the protocol version but not the boot
    // sector signature; a file that fails it is not a bzImage.
    if loaded
        .setup_header
        .is_some_and(|hdr| hdr.boot_flag != BOOT_FLAG)
    {
        return Err("loading the bzImage: the boot sector signature is not 0xAA55".into());
    }
    Ok((loaded, format))
}

/// Appends a usable-RAM e820 entry of `size` bytes at `addr`.
///
/// # Errors
///
/// Errors when the table's 128 entries are used.
fn add_e820(params: &mut boot_params, addr: u64, size: u64) -> Result<(), String> {
    let i = params.e820_entries as usize;
    if i == params.e820_table.len() {
        return Err("the e820 table is full".into());
    }
    params.e820_table[i] = boot_e820_entry {
        addr,
        size,
        r#type: E820_RAM,
    };
    params.e820_entries += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guestmem::GuestRam;
    use crate::layout_x86::{HIGH_RAM_BASE, MMIO_GAP_START};
    use linux_loader::elf::{
        Elf64_Ehdr, Elf64_Phdr, EI_CLASS, EI_DATA, EI_NIDENT, EI_VERSION, ELFCLASS64, ELFDATA2LSB,
        EM_X86_64, ET_EXEC, EV_CURRENT, PT_LOAD,
    };
    use vm_memory::{ByteValued, Bytes};

    /// The setup header sits at this offset of the image and of the zero page.
    const SETUP_HEADER_OFFSET: usize = 0x1f1;

    /// Where a stock kernel links its physical start (`CONFIG_PHYSICAL_START`).
    const VMLINUX_LOAD: u64 = 0x100_0000;
    /// The synthetic vmlinux's segment: this much file, this much memory (BSS
    /// after the file bytes).
    const VMLINUX_FILESZ: u64 = 0x800;
    const VMLINUX_MEMSZ: u64 = 0x3000;

    /// Builds a minimal bzImage, one setup sector carrying the fields the
    /// loader checks (boot flag, `HdrS`, protocol 2.15, `LOADED_HIGH`, the
    /// 1 MiB `code32_start`) and a protected-mode body with a recognisable
    /// pattern.
    fn synthetic_bzimage() -> Vec<u8> {
        let hdr = setup_header {
            setup_sects: 1, // setup area = (1 + 1) * 512 bytes
            boot_flag: BOOT_FLAG,
            header: HEADER_MAGIC,
            version: 0x020f,
            loadflags: 1, // LOADED_HIGH
            code32_start: HIGH_MEM_START as u32,
            ..Default::default()
        };
        let mut k = vec![0u8; 0x1000];
        k[SETUP_HEADER_OFFSET..SETUP_HEADER_OFFSET + size_of::<setup_header>()]
            .copy_from_slice(hdr.as_slice());
        for (i, b) in k[0x400..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        k
    }

    /// Builds a minimal vmlinux, an ELF64 executable with one `PT_LOAD` at the
    /// stock physical start whose memory size exceeds its file size, and an
    /// entry inside it.
    fn synthetic_vmlinux() -> Vec<u8> {
        let mut e_ident = [0u8; EI_NIDENT];
        e_ident[..4].copy_from_slice(ELFMAG);
        e_ident[EI_CLASS] = ELFCLASS64;
        e_ident[EI_DATA] = ELFDATA2LSB;
        e_ident[EI_VERSION] = EV_CURRENT;
        let ehdr = Elf64_Ehdr {
            e_ident,
            e_type: ET_EXEC,
            e_machine: EM_X86_64,
            e_version: 1,
            e_entry: VMLINUX_LOAD + 0x40,
            e_phoff: size_of::<Elf64_Ehdr>() as u64,
            e_ehsize: size_of::<Elf64_Ehdr>() as u16,
            e_phentsize: size_of::<Elf64_Phdr>() as u16,
            e_phnum: 1,
            ..Default::default()
        };
        let phdr = Elf64_Phdr {
            p_type: PT_LOAD,
            p_flags: 5, // R + X
            p_offset: 0x1000,
            p_vaddr: 0xffff_ffff_8100_0000,
            p_paddr: VMLINUX_LOAD,
            p_filesz: VMLINUX_FILESZ,
            p_memsz: VMLINUX_MEMSZ,
            p_align: 0x20_0000,
        };
        let mut f = vec![0u8; 0x1000];
        f[..size_of::<Elf64_Ehdr>()].copy_from_slice(ehdr.as_slice());
        f[size_of::<Elf64_Ehdr>()..size_of::<Elf64_Ehdr>() + size_of::<Elf64_Phdr>()]
            .copy_from_slice(phdr.as_slice());
        f.extend((0..VMLINUX_FILESZ).map(|i| (i % 251) as u8));
        f
    }

    /// Builds guest RAM of `mem_bytes` split around the MMIO hole as the x86
    /// machine splits it.
    ///
    /// The mappings are anonymous and lazily backed, so a 4 GiB guest costs
    /// address space, not memory.
    fn guest_ram(mem_bytes: u64) -> GuestRam {
        let low = mem_bytes.min(MMIO_GAP_START);
        let mut regions = vec![(RAM_BASE, low as usize)];
        if mem_bytes > low {
            regions.push((HIGH_RAM_BASE, (mem_bytes - low) as usize));
        }
        GuestRam::from_ranges(&regions)
    }

    /// Reads the written `boot_params` back from the zero page.
    fn zero_page(ram: &GuestRam) -> boot_params {
        ram.memory().read_obj(GuestAddress(ZERO_PAGE)).unwrap()
    }

    /// Returns the e820 table from the written zero page as (addr, size,
    /// type) rows.
    fn e820(ram: &GuestRam) -> Vec<(u64, u64, u32)> {
        let params = zero_page(ram);
        params.e820_table[..params.e820_entries as usize]
            .iter()
            .map(|e| (e.addr, e.size, e.r#type))
            .collect()
    }

    #[test]
    fn bzimage_lands_at_code32_start_with_its_header_in_the_zero_page() {
        let ram = guest_ram(1024 << 20);
        let image = synthetic_bzimage();
        let kernel = LoadedKernel::load(ram.memory(), &image, "console=ttyS0", 0).expect("load");
        assert_eq!(kernel.format, KernelFormat::BzImage);
        assert_eq!(kernel.entry, HIGH_MEM_START + KERNEL_ENTRY_OFF);
        assert_eq!(kernel.initrd_addr, None);

        let mut body = vec![0u8; image.len() - 0x400];
        ram.read(HIGH_MEM_START, &mut body).unwrap();
        assert_eq!(body, image[0x400..], "the setup sectors are stripped");

        // Copies, since `boot_params` is packed.
        let hdr = zero_page(&ram).hdr;
        let (header, version, type_of_loader, cmd_line_ptr, ramdisk_image) = (
            hdr.header,
            hdr.version,
            hdr.type_of_loader,
            hdr.cmd_line_ptr,
            hdr.ramdisk_image,
        );
        assert_eq!(header, HEADER_MAGIC, "the image's header is carried over");
        assert_eq!(version, 0x020f);
        assert_eq!(type_of_loader, 0xff);
        assert_eq!(u64::from(cmd_line_ptr), CMDLINE_ADDR);
        assert_eq!(ramdisk_image, 0);
    }

    #[test]
    fn vmlinux_is_entered_at_e_entry_with_a_synthesized_header() {
        let ram = guest_ram(1024 << 20);
        let image = synthetic_vmlinux();
        let kernel = LoadedKernel::load(ram.memory(), &image, "console=ttyS0", 0).expect("load");
        assert_eq!(kernel.format, KernelFormat::Vmlinux);
        assert_eq!(
            kernel.entry,
            VMLINUX_LOAD + 0x40,
            "e_entry, no 0x200 offset"
        );

        let mut seg = vec![0u8; VMLINUX_FILESZ as usize];
        ram.read(VMLINUX_LOAD, &mut seg).unwrap();
        assert_eq!(seg, image[0x1000..], "the PT_LOAD lands at p_paddr");

        let hdr = zero_page(&ram).hdr;
        let (boot_flag, header, version, type_of_loader, cmd_line_ptr) = (
            hdr.boot_flag,
            hdr.header,
            hdr.version,
            hdr.type_of_loader,
            hdr.cmd_line_ptr,
        );
        assert_eq!(boot_flag, BOOT_FLAG);
        assert_eq!(header, HEADER_MAGIC);
        assert_eq!(
            version, SYNTHESIZED_PROTOCOL,
            "zero would make the kernel copy boot_params a second time"
        );
        assert_eq!(
            type_of_loader, 0xff,
            "the kernel skips the initrd without it"
        );
        assert_eq!(u64::from(cmd_line_ptr), CMDLINE_ADDR);
    }

    // Both a header-sized and a shorter file are refused.
    #[test]
    fn rejects_an_image_of_neither_format() {
        let ram = guest_ram(1024 << 20);
        let err = LoadedKernel::load(ram.memory(), &[0u8; 0x1000], "console=ttyS0", 0)
            .expect_err("no HdrS");
        assert!(err.contains("bzImage"), "{err}");
        let err = LoadedKernel::load(ram.memory(), &[0u8; 16], "console=ttyS0", 0)
            .expect_err("too short");
        assert!(err.contains("bzImage"), "{err}");
    }

    // The loader's own checks pass; the signature check is hvi's.
    #[test]
    fn rejects_a_bzimage_without_the_boot_sector_signature() {
        let ram = guest_ram(1024 << 20);
        let mut image = synthetic_bzimage();
        image[0x1fe] = 0;
        image[0x1ff] = 0;
        let err =
            LoadedKernel::load(ram.memory(), &image, "console=ttyS0", 0).expect_err("no 0xAA55");
        assert!(err.contains("boot sector"), "{err}");
    }

    #[test]
    fn rejects_a_broken_elf_without_falling_back() {
        let ram = guest_ram(1024 << 20);
        let mut image = synthetic_vmlinux();
        image[EI_DATA] = 2; // big-endian
        let err =
            LoadedKernel::load(ram.memory(), &image, "console=ttyS0", 0).expect_err("not for us");
        assert!(err.contains("vmlinux"), "{err}");
    }

    // `Cmdline` parses `--` into init arguments; the guest must still see the
    // spliced line unchanged.
    #[test]
    fn cmdline_with_init_args_is_written_verbatim() {
        let ram = guest_ram(1024 << 20);
        let line = "console=ttyS0 rdinit=/init -- --flag value";
        LoadedKernel::load(ram.memory(), &synthetic_bzimage(), line, 0).expect("load");
        let mut back = vec![0u8; line.len() + 1];
        ram.read(CMDLINE_ADDR, &mut back).unwrap();
        assert_eq!(&back[..line.len()], line.as_bytes());
        assert_eq!(back[line.len()], 0, "NUL-terminated");
    }

    // Omitting the high entry loses the memory silently; describing the hole
    // as RAM puts allocations over the devices.
    #[test]
    fn large_guest_gets_a_high_e820_entry() {
        let ram = guest_ram(4096 << 20);
        let regions = ram.regions();
        assert_eq!(regions.len(), 2, "a 4 GiB guest must split");
        LoadedKernel::load(ram.memory(), &synthetic_bzimage(), "console=ttyS0", 0).expect("load");

        let map = e820(&ram);
        assert_eq!(map.len(), 3, "e820: {map:x?}");
        assert_eq!(
            map[2],
            (HIGH_RAM_BASE, regions[1].size, E820_RAM),
            "the displaced remainder must resume at the high base"
        );
        // The low entry must stop at the hole, not run through it.
        assert_eq!(
            map[1],
            (HIGH_MEM_START, regions[0].size - HIGH_MEM_START, E820_RAM)
        );
    }

    // The header's initrd pointer is 32 bits wide.
    #[test]
    fn initrd_stays_below_4gib() {
        let ram = guest_ram(4096 << 20);
        let low = ram.regions()[0].size;
        let initrd_len = 8 << 20;
        let kernel = LoadedKernel::load(
            ram.memory(),
            &synthetic_bzimage(),
            "console=ttyS0",
            initrd_len,
        )
        .expect("load");

        let addr = kernel.initrd_addr.expect("an initrd must get an address");
        let params = zero_page(&ram);
        assert_eq!(
            u64::from(params.hdr.ramdisk_image),
            addr,
            "header must point at the placement"
        );
        assert_eq!(u64::from(params.hdr.ramdisk_size), initrd_len);
        assert!(
            addr + initrd_len <= low,
            "initrd @ {addr:#x}+{initrd_len:#x} spills past low RAM ({low:#x})"
        );
        assert!(addr < HIGH_RAM_BASE);
    }

    #[test]
    fn initrd_that_would_overlap_the_kernel_is_refused() {
        let ram = guest_ram(3 << 20);
        let err = LoadedKernel::load(ram.memory(), &synthetic_bzimage(), "console=ttyS0", 2 << 20)
            .expect_err("2 MiB initrd in 3 MiB of low RAM lands on the kernel");
        assert!(err.contains("initramfs"), "{err}");
    }

    // The room a vmlinux needs ends at `p_memsz`, past the bytes the file
    // holds.
    #[test]
    fn initrd_clears_the_vmlinux_bss() {
        // The only 2 MiB-aligned slot below this much low RAM is the kernel's
        // own load address.
        let low = VMLINUX_LOAD + VMLINUX_MEMSZ + 0x1000;
        let ram = guest_ram(low);
        let err = LoadedKernel::load(ram.memory(), &synthetic_vmlinux(), "console=ttyS0", 0x1000)
            .expect_err("the slot is inside the kernel");
        assert!(err.contains("initramfs"), "{err}");

        let ram = guest_ram(low + (2 << 20));
        let kernel =
            LoadedKernel::load(ram.memory(), &synthetic_vmlinux(), "console=ttyS0", 0x1000)
                .expect("the next slot is clear of the kernel");
        assert!(kernel.initrd_addr.unwrap() >= VMLINUX_LOAD + VMLINUX_MEMSZ);
    }

    #[test]
    fn small_guest_is_unsplit() {
        let ram = guest_ram(1024 << 20);
        assert_eq!(ram.regions().len(), 1);
        LoadedKernel::load(ram.memory(), &synthetic_bzimage(), "console=ttyS0", 0).expect("load");

        assert_eq!(
            e820(&ram),
            vec![
                (RAM_BASE, EBDA_START, E820_RAM),
                (HIGH_MEM_START, (1024 << 20) - HIGH_MEM_START, E820_RAM),
            ]
        );
    }

    // The zero page and the real-mode structures live in the region at
    // address 0.
    // The header's size field is 32 bits wide; a larger initramfs is refused
    // rather than written with a truncated size.
    #[test]
    fn initramfs_beyond_the_ramdisk_size_field_is_refused() {
        // Low RAM of 5 GiB is not a layout the machine builds; it is the one
        // shape in which a 4 GiB initramfs passes the placement check.
        let ram = GuestRam::from_ranges(&[(0, 5 << 30)]);
        let err = LoadedKernel::load(ram.memory(), &synthetic_bzimage(), "console=ttyS0", 1 << 32)
            .expect_err("4 GiB initramfs");
        assert!(err.contains("ramdisk_size"), "{err}");
    }

    #[test]
    fn ram_without_a_low_region_is_refused() {
        let ram = GuestRam::from_ranges(&[(HIGH_RAM_BASE, 32 << 20)]);
        let err = LoadedKernel::load(ram.memory(), &synthetic_bzimage(), "console=ttyS0", 0)
            .expect_err("nothing at address 0");
        assert!(err.contains("address 0"), "{err}");
    }
}

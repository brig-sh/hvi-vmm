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

//! x86-64 Linux boot preparation: parse a `bzImage`, build the `boot_params`
//! "zero page" (setup header + e820 + cmdline/initrd pointers), and say where
//! the 64-bit kernel and its entry go. The machine writes the bytes into guest
//! RAM and enters the vCPU in long mode at
//! [`BootPlan::entry`](crate::boot_x86::BootPlan::entry) with `RSI` pointing at
//! the zero page — the Linux 64-bit boot protocol.
//!
//! Mirrors Firecracker's `arch::x86_64` loader at the level we need.

use crate::layout_x86::{CMDLINE_ADDR, HIGH_MEM_START, HIGH_RAM_BASE, KERNEL_ENTRY_OFF, ZERO_PAGE};

// setup_header field offsets within the boot image / boot_params.
const HDR_SETUP_SECTS: usize = 0x1f1;
const HDR_BOOT_FLAG: usize = 0x1fe; // 0xAA55
const HDR_MAGIC: usize = 0x202; // "HdrS"
const HDR_TYPE_OF_LOADER: usize = 0x210;
const HDR_RAMDISK_IMAGE: usize = 0x218;
const HDR_RAMDISK_SIZE: usize = 0x21c;
const HDR_CMD_LINE_PTR: usize = 0x228;
const HDR_END: usize = 0x268; // copy the setup header through here
                              // boot_params e820.
const BP_E820_ENTRIES: usize = 0x1e8; // u8 count
const BP_E820_TABLE: usize = 0x2d0; // array of 20-byte entries
const E820_RAM: u32 = 1;

/// What to place in guest RAM and how to enter the vCPU.
pub struct BootPlan {
    /// Guest-physical load address of the 64-bit kernel.
    pub kernel_load: u64,
    /// The 64-bit protected-mode kernel (bzImage minus the real-mode setup).
    pub kernel_image: Vec<u8>,
    /// The 4 KiB `boot_params` zero page and where it goes.
    pub zero_page: Vec<u8>,
    pub zero_page_addr: u64,
    /// NUL-terminated kernel command line and where it goes.
    pub cmdline: Vec<u8>,
    pub cmdline_addr: u64,
    /// Guest-physical address to place the initramfs, if any.
    pub initrd_addr: Option<u64>,
    /// 64-bit entry point (RIP).
    pub entry: u64,
}

/// Parses `kernel` (a bzImage) and builds the boot plan.
///
/// RAM is described in two pieces because a guest larger than the MMIO hole
/// cannot be contiguous in guest-physical space: `low_bytes` sits at 0 and
/// `high_bytes` (often zero) resumes at [`HIGH_RAM_BASE`]. See
/// [`MMIO_GAP_START`](crate::layout_x86::MMIO_GAP_START) for why the hole has
/// to be there.
pub fn prepare(
    kernel: &[u8],
    cmdline: &str,
    initrd_len: u64,
    low_bytes: u64,
    high_bytes: u64,
) -> Result<BootPlan, String> {
    if kernel.len() < HDR_END {
        return Err("kernel too small for a bzImage setup header".into());
    }
    if kernel[HDR_BOOT_FLAG] != 0x55 || kernel[HDR_BOOT_FLAG + 1] != 0xaa {
        return Err("bad bzImage boot flag (0xAA55)".into());
    }
    if &kernel[HDR_MAGIC..HDR_MAGIC + 4] != b"HdrS" {
        return Err("bad bzImage magic (HdrS)".into());
    }

    let setup_sects = if kernel[HDR_SETUP_SECTS] == 0 {
        4
    } else {
        kernel[HDR_SETUP_SECTS] as usize
    };
    let setup_size = (setup_sects + 1) * 512;
    if kernel.len() < setup_size {
        return Err("bzImage shorter than its setup area".into());
    }
    let kernel_image = kernel[setup_size..].to_vec();

    // Zero page: copy the setup header from the image, then override the loader
    // fields we own.
    let mut zp = vec![0u8; 4096];
    zp[HDR_SETUP_SECTS..HDR_END].copy_from_slice(&kernel[HDR_SETUP_SECTS..HDR_END]);
    zp[HDR_TYPE_OF_LOADER] = 0xff; // undefined bootloader
    put_u32(&mut zp, HDR_CMD_LINE_PTR, CMDLINE_ADDR as u32);

    // initrd placement: 2 MiB-aligned near the top of *low* RAM, above the
    // kernel. It has to be low RAM regardless of guest size, because the header
    // field that points at it is 32 bits wide.
    let initrd_addr = if initrd_len > 0 {
        let addr = (low_bytes - initrd_len) & !0x1f_ffff;
        put_u32(&mut zp, HDR_RAMDISK_IMAGE, addr as u32);
        put_u32(&mut zp, HDR_RAMDISK_SIZE, initrd_len as u32);
        Some(addr)
    } else {
        None
    };

    // e820: RAM below the EBDA, then from 1 MiB to the MMIO hole, then whatever
    // was displaced by the hole, above 4 GiB. Anything omitted here the guest
    // will not touch as memory, which is the point: the hole must not be
    // described as RAM or the guest will allocate over the devices.
    let mut count = 0u8;
    add_e820(&mut zp, &mut count, 0, 0x9_fc00, E820_RAM);
    if low_bytes > HIGH_MEM_START {
        add_e820(
            &mut zp,
            &mut count,
            HIGH_MEM_START,
            low_bytes - HIGH_MEM_START,
            E820_RAM,
        );
    }
    if high_bytes > 0 {
        add_e820(&mut zp, &mut count, HIGH_RAM_BASE, high_bytes, E820_RAM);
    }
    zp[BP_E820_ENTRIES] = count;

    let mut cmd = cmdline.as_bytes().to_vec();
    cmd.push(0);

    Ok(BootPlan {
        kernel_load: HIGH_MEM_START,
        kernel_image,
        zero_page: zp,
        zero_page_addr: ZERO_PAGE,
        cmdline: cmd,
        cmdline_addr: CMDLINE_ADDR,
        initrd_addr,
        entry: HIGH_MEM_START + KERNEL_ENTRY_OFF,
    })
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn add_e820(zp: &mut [u8], count: &mut u8, addr: u64, size: u64, typ: u32) {
    let base = BP_E820_TABLE + (*count as usize) * 20;
    zp[base..base + 8].copy_from_slice(&addr.to_le_bytes());
    zp[base + 8..base + 16].copy_from_slice(&size.to_le_bytes());
    zp[base + 16..base + 20].copy_from_slice(&typ.to_le_bytes());
    *count += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout_x86::MMIO_GAP_START;

    /// A minimal bzImage: the boot flag, the `HdrS` magic and one setup
    /// sector, which is all `prepare` reads (the same trick as the arm64
    /// `boot` tests' synthetic Image header).
    fn synth_bzimage() -> Vec<u8> {
        let mut k = vec![0u8; 0x1000];
        k[HDR_SETUP_SECTS] = 1; // setup area = (1 + 1) * 512 bytes
        k[HDR_BOOT_FLAG] = 0x55;
        k[HDR_BOOT_FLAG + 1] = 0xaa;
        k[HDR_MAGIC..HDR_MAGIC + 4].copy_from_slice(b"HdrS");
        k
    }

    /// The RAM split exactly as `machine_x86::boot` derives it from the
    /// requested guest size, so the tests feed `prepare` realistic inputs.
    fn ram_split(mem_bytes: u64) -> (u64, u64) {
        let low = mem_bytes.min(MMIO_GAP_START);
        (low, mem_bytes - low)
    }

    /// The e820 table from a built zero page, as (addr, size, type) rows.
    fn e820(zp: &[u8]) -> Vec<(u64, u64, u32)> {
        let u64_at = |o: usize| u64::from_le_bytes(zp[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(zp[o..o + 4].try_into().unwrap());
        (0..zp[BP_E820_ENTRIES] as usize)
            .map(|i| {
                let o = BP_E820_TABLE + i * 20;
                (u64_at(o), u64_at(o + 8), u32_at(o + 16))
            })
            .collect()
    }

    /// A guest bigger than the low-RAM cap must get its remainder described
    /// above 4 GiB. Omitting the entry loses the memory silently; describing
    /// the hole as RAM makes the guest allocate over the devices.
    #[test]
    fn a_large_guest_gets_a_high_e820_entry() {
        let (low, high) = ram_split(4096 << 20);
        assert!(high > 0, "a 4 GiB guest must split");
        let plan = prepare(&synth_bzimage(), "console=ttyS0", 0, low, high).expect("prepare");

        let map = e820(&plan.zero_page);
        assert_eq!(map.len(), 3, "e820: {map:x?}");
        assert_eq!(
            map[2],
            (HIGH_RAM_BASE, high, E820_RAM),
            "the displaced remainder must resume at the high base"
        );
        // The low entry must stop at the hole, not run through it.
        assert_eq!(map[1], (HIGH_MEM_START, low - HIGH_MEM_START, E820_RAM));
    }

    /// The header field pointing at the initrd is 32 bits wide, so no matter
    /// how big the guest is the initrd must be placed in low RAM.
    #[test]
    fn the_initrd_stays_below_4gib() {
        let (low, high) = ram_split(4096 << 20);
        let initrd_len = 8 << 20;
        let plan =
            prepare(&synth_bzimage(), "console=ttyS0", initrd_len, low, high).expect("prepare");

        let addr = plan.initrd_addr.expect("an initrd must get an address");
        let field = u32::from_le_bytes(
            plan.zero_page[HDR_RAMDISK_IMAGE..HDR_RAMDISK_IMAGE + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(u64::from(field), addr, "header must point at the placement");
        assert!(
            addr + initrd_len <= low,
            "initrd @ {addr:#x}+{initrd_len:#x} spills past low RAM ({low:#x})"
        );
        assert!(u64::from(field) < HIGH_RAM_BASE);
    }

    /// A guest that fits under the hole keeps the pre-split layout: two RAM
    /// entries and nothing above 4 GiB.
    #[test]
    fn a_small_guest_is_unsplit() {
        let (low, high) = ram_split(1024 << 20);
        assert_eq!(high, 0);
        let plan = prepare(&synth_bzimage(), "console=ttyS0", 0, low, high).expect("prepare");

        let map = e820(&plan.zero_page);
        assert_eq!(
            map,
            vec![
                (0, 0x9_fc00, E820_RAM),
                (HIGH_MEM_START, low - HIGH_MEM_START, E820_RAM),
            ]
        );
    }
}

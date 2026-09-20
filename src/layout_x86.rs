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

//! Guest physical-address-space layout for the x86-64 KVM machine.
//!
//! Unlike arm64 (RAM at 1 GiB, devices below), x86 guest RAM starts at 0 and
//! the low megabyte holds the legacy BIOS/real-mode area. We follow the usual
//! Firecracker/CH placement: the 64-bit kernel at 1 MiB, the `boot_params`
//! "zero page" and cmdline in low RAM, a minimal MP table in the EBDA, and the
//! virtio-mmio window up in the sub-4 GiB MMIO hole.

/// Guest RAM base (x86 RAM starts at physical 0).
pub const RAM_BASE: u64 = 0x0;

/// `boot_params` (the "zero page") — 4 KiB.
pub const ZERO_PAGE: u64 = 0x7000;
/// Kernel command line.
pub const CMDLINE_ADDR: u64 = 0x2_0000;
pub const CMDLINE_MAX: usize = 0x1_0000;
/// Start of the EBDA, where usable low RAM ends.
pub const EBDA_START: u64 = 0x9_fc00;
/// Minimal MP floating pointer + config table, in the EBDA.
pub const MPTABLE_ADDR: u64 = EBDA_START;
/// Boot page tables (PML4/PDPT/PD) for the initial long-mode identity map.
pub const PML4_ADDR: u64 = 0x9000;
pub const PDPT_ADDR: u64 = 0xa000;
pub const PD_ADDR: u64 = 0xb000;
/// A small boot GDT.
pub const GDT_ADDR: u64 = 0xc000;
/// The 64-bit protected-mode kernel loads at 1 MiB.
pub const HIGH_MEM_START: u64 = 0x10_0000;
/// The 64-bit entry sits 0x200 past the load address (compressed kernel).
pub const KERNEL_ENTRY_OFF: u64 = 0x200;
/// Initial stack pointer for the BSP (top of low RAM below the zero page).
pub const BOOT_STACK: u64 = 0x6ff0;

/// COM1 16550 UART, I/O port + IOAPIC GSI.
pub const COM1_PORT: u16 = 0x3f8;
pub const COM1_GSI: u32 = 4;

/// virtio-mmio window in the sub-4 GiB MMIO hole: one 0x200 page per device
/// (blk, net, vsock), with IOAPIC GSIs 5/6/7. The guest is told about these via
/// `virtio_mmio.device=` on the kernel command line (see `boot_x86`).
pub const VIRTIO_MMIO_BASE: u64 = 0xd000_0000;
pub const VIRTIO_SIZE: u64 = 0x200;
pub const VIRTIO_BLK_BASE: u64 = VIRTIO_MMIO_BASE;
pub const VIRTIO_NET_BASE: u64 = VIRTIO_MMIO_BASE + 0x200;
pub const VIRTIO_VSOCK_BASE: u64 = VIRTIO_MMIO_BASE + 0x400;
pub const VIRTIO_BLK_GSI: u32 = 5;
pub const VIRTIO_NET_GSI: u32 = 6;
pub const VIRTIO_VSOCK_GSI: u32 = 7;

/// First virtio-fs window, one 0x200 page per export, and the first GSI they
/// take.
///
/// The MP table describes ISA IRQs 0..15 and nothing above them, so an export
/// has to take one of those lines. 9 to 12 are the ones no device in this
/// machine claims: 8 is the RTC, 13 the FPU, and 14 and 15 the IDE pair that
/// a guest kernel probes whether or not we have a disk. That bounds the x86
/// machine at [`MAX_FS_DEVICES`] exports, where arm64 has a full SPI range to
/// hand out.
pub const VIRTIO_FS_BASE: u64 = VIRTIO_MMIO_BASE + 0x600;
pub const VIRTIO_FS_GSI: u32 = 9;

/// How many virtio-fs exports this machine has interrupt lines for.
pub const MAX_FS_DEVICES: usize = 4;

/// Returns the window base of the `index`th virtio-fs export, or `None` when
/// the machine has no line left for it.
#[must_use]
pub fn virtio_fs_base(index: usize) -> Option<u64> {
    if index >= MAX_FS_DEVICES {
        return None;
    }
    VIRTIO_FS_BASE.checked_add((index as u64).checked_mul(VIRTIO_SIZE)?)
}

/// Returns the GSI of the `index`th virtio-fs export, or `None` when the
/// machine has no line left for it.
#[must_use]
pub fn virtio_fs_gsi(index: usize) -> Option<u32> {
    if index >= MAX_FS_DEVICES {
        return None;
    }
    VIRTIO_FS_GSI.checked_add(u32::try_from(index).ok()?)
}

/// Base of the sub-4 GiB MMIO hole: guest RAM stops here and the remainder,
/// if any, resumes at [`HIGH_RAM_BASE`].
///
/// A guest cannot simply be one contiguous span from 0. Two fixed things live
/// under 4 GiB and RAM laid over either one breaks, in different ways:
///
/// - the virtio-mmio window at [`VIRTIO_MMIO_BASE`] (3.25 GiB). RAM over it
///   shadows the device registers, so KVM services the access from memory and
///   never exits to us. The guest registers the device and then finds no virtio
///   magic, so `virtio_blk` never probes -- a *silent* loss of the disk, which
///   is the dangerous half of this.
/// - the in-kernel LAPIC page at 0xfee00000 (4078 MiB). KVM keeps that as an
///   internal memory slot, so a userspace slot overlapping it is refused with
///   `EEXIST` and the VM does not start at all.
///
/// The hole starts at the device window, which is the lower of the two, so one
/// hole covers both.
pub const MMIO_GAP_START: u64 = VIRTIO_MMIO_BASE;

/// Where guest RAM resumes above the MMIO hole.
pub const HIGH_RAM_BASE: u64 = 0x1_0000_0000; // 4 GiB

#[cfg(test)]
mod tests {
    use super::{
        virtio_fs_base, virtio_fs_gsi, COM1_GSI, MAX_FS_DEVICES, MMIO_GAP_START, VIRTIO_BLK_GSI,
        VIRTIO_NET_GSI, VIRTIO_SIZE, VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_GSI,
    };

    // The fs windows sit after the three fixed devices and inside the MMIO
    // hole. RAM laid over either end is the failure this guards: the guest
    // then finds no virtio magic and never probes the device.
    #[test]
    fn every_fs_window_is_inside_the_device_hole() {
        for index in 0..MAX_FS_DEVICES {
            let base = virtio_fs_base(index).expect("a placement");
            assert!(
                base >= VIRTIO_VSOCK_BASE + VIRTIO_SIZE,
                "fs {index} overlaps vsock"
            );
            assert!(
                base + VIRTIO_SIZE <= MMIO_GAP_START + 0x1000,
                "fs {index} escapes the hole"
            );
        }
        assert_eq!(virtio_fs_base(MAX_FS_DEVICES), None);
    }

    // An interrupt shared with another device delivers one guest's completion
    // to the other's handler.
    #[test]
    fn no_fs_interrupt_is_claimed_by_another_device() {
        let taken = [COM1_GSI, VIRTIO_BLK_GSI, VIRTIO_NET_GSI, VIRTIO_VSOCK_GSI];
        let mut seen = Vec::new();
        for index in 0..MAX_FS_DEVICES {
            let gsi = virtio_fs_gsi(index).expect("an interrupt");
            assert!(!taken.contains(&gsi), "fs {index} takes GSI {gsi}");
            assert!(!seen.contains(&gsi), "GSI {gsi} handed out twice");
            // The MP table writes ISA entries for IRQs 0..15 only.
            assert!(gsi < 16, "GSI {gsi} has no MP table entry");
            seen.push(gsi);
        }
        assert_eq!(virtio_fs_gsi(MAX_FS_DEVICES), None);
    }
}

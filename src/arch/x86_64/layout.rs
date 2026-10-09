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
//! x86 guest RAM starts at 0, unlike arm64's (RAM at 1 GiB, devices below), and
//! the low megabyte holds the legacy BIOS and real-mode area. The 64-bit kernel
//! loads at 1 MiB. The `boot_params` zero page and the command line sit in low
//! RAM, the MP table in the EBDA and the ACPI tables in the BIOS area. The
//! virtio-mmio window is in the sub-4 GiB MMIO hole.

use crate::config::MAX_DISKS;

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
/// The ACPI tables, RSDP first, at the start of the BIOS area where the guest
/// scans for the RSDP.
///
/// The e820 map leaves the area out, so the guest never takes it for RAM.
pub const ACPI_ADDR: u64 = 0xe_0000;
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

/// The i8042 command and status port.
pub const I8042_COMMAND_PORT: u16 = 0x64;
/// The base port of the ACPI PM1 event block, the PM1 control block and the
/// reset register.
pub const ACPI_PM_PORT: u16 = 0x600;
/// The GSI of the ACPI system control interrupt.
///
/// hvi never raises it, but the guest's ACPI driver needs a line for its
/// handler. It is the IOAPIC's last line, away from the ISA lines the devices
/// take.
pub const SCI_GSI: u32 = 23;

/// The local APIC's base address, where a PC has it.
pub const LAPIC_ADDR: u32 = 0xfee0_0000;
/// The IOAPIC's base address, where a PC has it.
pub const IOAPIC_ADDR: u32 = 0xfec0_0000;

/// How many input lines the IOAPIC has, which is the GSI bound for every
/// device.
pub const IOAPIC_INPUTS: u8 = 24;

/// virtio-mmio window in the sub-4 GiB MMIO hole: one 0x200 page per device,
/// each on its own IOAPIC GSI. The guest learns them from the ACPI DSDT (see
/// `acpi.rs`), so none of these is a contract.
///
/// | window from `VIRTIO_MMIO_BASE` | GSI      | device                   |
/// |--------------------------------|----------|--------------------------|
/// | `+0x000`                       | 5        | virtio-blk, disk 0       |
/// | `+0x200`                       | 6        | virtio-net               |
/// | `+0x400`                       | 7        | virtio-vsock             |
/// | `+0x600` .. `+0xa00`           | 9 .. 11  | virtio-blk, disks 1 .. 3 |
/// | `+0xc00 + i * 0x200`           | `12 + i` | virtio-fs export `i`     |
///
/// COM1 holds GSI 4 and the guest's rtc-cmos driver claims 8, so the disks
/// after the first start at 9. The exports run up to the ACPI SCI on the
/// IOAPIC's last line, [`SCI_GSI`], which bounds them at [`MAX_FS_DEVICES`].
/// Lines 16 to 22 have no ISA IRQ, so a guest reaches a device on one only
/// through the DSDT.
pub const VIRTIO_MMIO_BASE: u64 = 0xd000_0000;
pub const VIRTIO_SIZE: u64 = 0x200;
pub const VIRTIO_BLK_BASE: u64 = VIRTIO_MMIO_BASE;
pub const VIRTIO_NET_BASE: u64 = VIRTIO_MMIO_BASE + 0x200;
pub const VIRTIO_VSOCK_BASE: u64 = VIRTIO_MMIO_BASE + 0x400;
pub const VIRTIO_BLK_GSI: u32 = 5;
pub const VIRTIO_NET_GSI: u32 = 6;
pub const VIRTIO_VSOCK_GSI: u32 = 7;
/// Window and GSI of disk 1. Disks 2 and 3 follow, one slot each.
pub const VIRTIO_BLK_EXTRA_BASE: u64 = VIRTIO_MMIO_BASE + 0x600;
pub const VIRTIO_BLK_EXTRA_GSI: u32 = 9;
/// Window and GSI of export 0. The others follow, one slot each.
pub const VIRTIO_FS_BASE: u64 = VIRTIO_BLK_EXTRA_BASE + (MAX_DISKS as u64 - 1) * VIRTIO_SIZE;
pub const VIRTIO_FS_GSI: u32 = VIRTIO_BLK_EXTRA_GSI + MAX_DISKS as u32 - 1;
/// How many virtio-fs exports this machine has interrupt lines for: the lines
/// from [`VIRTIO_FS_GSI`] up to the SCI.
pub const MAX_FS_DEVICES: usize = (SCI_GSI - VIRTIO_FS_GSI) as usize;

/// Placement of the virtio-blk device for disk `index`, or `None` past
/// [`MAX_DISKS`].
#[must_use]
pub fn virtio_blk_base(index: usize) -> Option<u64> {
    match index {
        0 => Some(VIRTIO_BLK_BASE),
        i if i < MAX_DISKS => Some(VIRTIO_BLK_EXTRA_BASE + (i as u64 - 1) * VIRTIO_SIZE),
        _ => None,
    }
}

/// The GSI of the virtio-blk device for disk `index`, or `None` past
/// [`MAX_DISKS`].
#[must_use]
pub fn virtio_blk_gsi(index: usize) -> Option<u32> {
    match index {
        0 => Some(VIRTIO_BLK_GSI),
        i if i < MAX_DISKS => Some(VIRTIO_BLK_EXTRA_GSI + i as u32 - 1),
        _ => None,
    }
}

/// Returns the window base of the `index`th virtio-fs export, or `None` when
/// the machine has no line left for it.
#[must_use]
pub fn virtio_fs_base(index: usize) -> Option<u64> {
    if index >= MAX_FS_DEVICES {
        return None;
    }
    Some(VIRTIO_FS_BASE + index as u64 * VIRTIO_SIZE)
}

/// Returns the GSI of the `index`th virtio-fs export, or `None` when the
/// machine has no line left for it.
#[must_use]
pub fn virtio_fs_gsi(index: usize) -> Option<u32> {
    if index >= MAX_FS_DEVICES {
        return None;
    }
    Some(VIRTIO_FS_GSI + index as u32)
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
    use super::*;

    // Every device adds a window and a GSI. Neither may land on another device,
    // every window has to sit in the MMIO hole, and every GSI has to be an
    // IOAPIC input no legacy device claims.
    #[test]
    fn no_device_shares_a_window_or_a_gsi_with_another() {
        let rtc_gsi = 8;
        let mut devices = vec![
            ("net".to_string(), VIRTIO_NET_BASE, VIRTIO_NET_GSI),
            ("vsock".to_string(), VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_GSI),
        ];
        for i in 0..MAX_DISKS {
            devices.push((
                format!("disk {i}"),
                virtio_blk_base(i).expect("a disk slot"),
                virtio_blk_gsi(i).expect("a disk GSI"),
            ));
        }
        for i in 0..MAX_FS_DEVICES {
            devices.push((
                format!("export {i}"),
                virtio_fs_base(i).expect("an export slot"),
                virtio_fs_gsi(i).expect("an export GSI"),
            ));
        }
        for (a, (na, base_a, gsi_a)) in devices.iter().enumerate() {
            assert!(
                *gsi_a < u32::from(IOAPIC_INPUTS),
                "{na} GSI {gsi_a} is not an IOAPIC input"
            );
            assert!(
                ![COM1_GSI, rtc_gsi, SCI_GSI].contains(gsi_a),
                "{na} takes another device's GSI {gsi_a}"
            );
            assert!(*base_a >= MMIO_GAP_START, "{na} is in RAM");
            assert!(
                base_a + VIRTIO_SIZE <= MMIO_GAP_START + 0x4000,
                "{na} escapes the hole"
            );
            for (nb, base_b, gsi_b) in devices.iter().skip(a + 1) {
                let overlap = base_a < &(base_b + VIRTIO_SIZE) && base_b < &(base_a + VIRTIO_SIZE);
                assert!(!overlap, "{na} at {base_a:#x} overlaps {nb} at {base_b:#x}");
                assert_ne!(gsi_a, gsi_b, "{na} and {nb} share GSI {gsi_a}");
            }
        }
    }

    // Disk 0 keeps the window and the GSI it had when it was the only disk, the
    // others follow vsock, and the exports follow the disks up to the IOAPIC's
    // last line.
    #[test]
    fn disks_and_exports_take_fixed_slots_in_order() {
        assert_eq!(
            virtio_blk_base(0),
            Some(VIRTIO_BLK_BASE),
            "disk 0 stays put"
        );
        assert_eq!(virtio_blk_gsi(0), Some(VIRTIO_BLK_GSI));
        assert_eq!(virtio_blk_base(1), Some(0xd000_0600));
        assert_eq!(virtio_blk_gsi(1), Some(9));
        assert_eq!(virtio_blk_base(3), Some(0xd000_0a00));
        assert_eq!(virtio_blk_gsi(3), Some(11));
        assert_eq!(virtio_blk_base(MAX_DISKS), None);
        assert_eq!(virtio_blk_gsi(MAX_DISKS), None);
        assert_eq!(virtio_fs_base(0), Some(0xd000_0c00));
        assert_eq!(virtio_fs_gsi(0), Some(12));
        assert_eq!(MAX_FS_DEVICES, 11);
        assert_eq!(
            virtio_fs_gsi(MAX_FS_DEVICES - 1),
            Some(22),
            "the SCI holds 23"
        );
        assert_eq!(virtio_fs_base(MAX_FS_DEVICES), None);
        assert_eq!(virtio_fs_gsi(MAX_FS_DEVICES), None);
    }
}

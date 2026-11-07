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

use crate::devices::manager::SlotAllocator;

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
/// The base port of the MC146818 CMOS RTC.
pub const RTC_PORT: u16 = 0x70;
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

/// The GSI of the CMOS RTC, ISA IRQ 8, which the guest's rtc-cmos driver
/// claims.
pub const RTC_GSI: u32 = 8;

/// The base of the virtio-mmio window in the sub-4 GiB MMIO hole.
///
/// `virtio_slots` hands out one range per device from here. The guest learns
/// them from the ACPI DSDT (see `acpi.rs`), so none of them is a contract.
pub const VIRTIO_MMIO_BASE: u64 = 0xd000_0000;
/// The GSI of the first virtio device. COM1 holds GSI 4.
pub const VIRTIO_GSI: u32 = 5;

/// Returns the slots of the virtio devices, with ranges from
/// [`VIRTIO_MMIO_BASE`] up to the IOAPIC and GSIs from [`VIRTIO_GSI`] up to the
/// ACPI SCI on the IOAPIC's last line, [`SCI_GSI`].
///
/// The GSIs skip [`RTC_GSI`], which leaves 17 for the virtio devices of all
/// kinds. Lines 16 to 22 have no ISA IRQ, so a guest reaches a device on one
/// only through the DSDT.
pub(crate) fn virtio_slots() -> SlotAllocator {
    SlotAllocator::new(
        VIRTIO_MMIO_BASE..u64::from(IOAPIC_ADDR),
        (VIRTIO_GSI..SCI_GSI).filter(|&gsi| gsi != RTC_GSI),
    )
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
    use crate::devices::virtio::mmio::RANGE_SIZE;

    // Every device adds a range and a GSI. The ranges follow one another in the
    // MMIO hole, below the IOAPIC, and every GSI is an IOAPIC input no legacy
    // device claims.
    #[test]
    fn virtio_slots_take_every_free_gsi_in_order() {
        let mut slots = virtio_slots();
        let taken: Vec<_> = std::iter::from_fn(|| slots.allocate().ok()).collect();
        let gsis: Vec<u32> = taken.iter().map(|slot| slot.irq).collect();
        assert_eq!(
            gsis,
            [5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]
        );
        for (index, slot) in taken.iter().enumerate() {
            assert_eq!(slot.base, VIRTIO_MMIO_BASE + index as u64 * RANGE_SIZE);
            assert!(slot.irq < u32::from(IOAPIC_INPUTS));
            assert!(![COM1_GSI, RTC_GSI, SCI_GSI].contains(&slot.irq));
            assert!(slot.base >= MMIO_GAP_START, "slot {index} is in RAM");
        }
        assert!(slots
            .allocate()
            .unwrap_err()
            .contains("after 17 virtio devices"));
    }
}

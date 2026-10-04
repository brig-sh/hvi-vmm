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

/// virtio-mmio window in the sub-4 GiB MMIO hole: one 0x200 page per device
/// (blk, net, vsock), with IOAPIC GSIs 5/6/7. The guest is told about these via
/// `virtio_mmio.device=` on the kernel command line (see `kvm::boot`).
pub const VIRTIO_MMIO_BASE: u64 = 0xd000_0000;
pub const VIRTIO_SIZE: u64 = 0x200;
pub const VIRTIO_BLK_BASE: u64 = VIRTIO_MMIO_BASE;
pub const VIRTIO_NET_BASE: u64 = VIRTIO_MMIO_BASE + 0x200;
pub const VIRTIO_VSOCK_BASE: u64 = VIRTIO_MMIO_BASE + 0x400;
pub const VIRTIO_BLK_GSI: u32 = 5;
pub const VIRTIO_NET_GSI: u32 = 6;
pub const VIRTIO_VSOCK_GSI: u32 = 7;

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

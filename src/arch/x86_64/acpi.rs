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

//! The ACPI tables an x86-64 guest powers off and resets through.
//!
//! These tables give the guest a power-off. Without them, Linux turns
//! `poweroff` into a halt, which KVM's in-kernel irqchip handles with no exit
//! to the VMM.
//!
//! The FADT describes a PC's fixed hardware: the [`PmRegisters`] at
//! [`ACPI_PM_PORT`], and a system control interrupt hvi never raises. The DSDT
//! holds only `\_S5`, the sleep type the guest writes to power off. The MADT
//! lists the CPUs and the IOAPIC as the MP table does, since a guest that finds
//! ACPI tables without a MADT discards the MP table.
//!
//! The FADT is not hardware-reduced. A hardware-reduced guest drops the legacy
//! PIC and numbers its interrupts dynamically, so the ISA lines the console and
//! the `virtio_mmio.device=` devices use would no longer reach their drivers.
//!
//! [`PmRegisters`]: crate::devices::legacy::acpi_pm::PmRegisters

use acpi_tables::aml::{Name, Package};
use acpi_tables::facs::FACS;
use acpi_tables::fadt::{FADTBuilder, Flags, FADT};
use acpi_tables::gas::{AccessSize, AddressSpace, GAS};
use acpi_tables::madt::{
    EnabledStatus, IoApic, LocalInterruptController, ProcessorLocalApic, MADT,
};
use acpi_tables::rsdp::Rsdp;
use acpi_tables::sdt::Sdt;
use acpi_tables::xsdt::XSDT;
use acpi_tables::Aml;

use crate::arch::x86_64::layout::{ACPI_ADDR, ACPI_PM_PORT, IOAPIC_ADDR, LAPIC_ADDR, SCI_GSI};
use crate::devices::legacy::acpi_pm::{
    PM1_CONTROL, PM1_CONTROL_LEN, PM1_EVENT_LEN, PM1_STATUS, RESET_REGISTER, RESET_VALUE,
    SLP_TYP_S5,
};

/// The OEM id every table carries.
const OEM_ID: [u8; 6] = *b"HVI   ";
/// The OEM table id every table carries.
const OEM_TABLE_ID: [u8; 8] = *b"HVI x86 ";
/// The OEM revision every table carries.
const OEM_REVISION: u32 = 1;

/// The alignment of the FACS, 64 bytes.
const FACS_ALIGN: usize = 64;

/// The IA-PC boot architecture flag that says the guest has no VGA.
const IAPC_VGA_NOT_PRESENT: u16 = 1 << 2;
/// The IA-PC boot architecture flag that says the guest must not enable MSI.
const IAPC_MSI_NOT_SUPPORTED: u16 = 1 << 3;

/// Builds the tables for `num_cpus` vCPUs, as the bytes to write at
/// [`ACPI_ADDR`].
#[must_use]
pub fn build(num_cpus: u32) -> Vec<u8> {
    let mut tables = Tables::new();
    let mut dsdt = Sdt::new(*b"DSDT", 36, 2, OEM_ID, OEM_TABLE_ID, OEM_REVISION);
    Name::new("_S5_".into(), &Package::new(vec![&SLP_TYP_S5])).to_aml_bytes(&mut dsdt);
    let dsdt = tables.place(&dsdt, 1);
    let facs = tables.place(&FACS::new(), FACS_ALIGN);
    let fadt = tables.place(&build_fadt(dsdt, facs), 1);
    let madt = tables.place(&build_madt(num_cpus), 1);
    let mut xsdt = XSDT::new(OEM_ID, OEM_TABLE_ID, OEM_REVISION);
    xsdt.add_entry(fadt);
    xsdt.add_entry(madt);
    let xsdt = tables.place(&xsdt, 1);
    tables.finish(xsdt)
}

/// Returns the FADT that points at the DSDT at `dsdt` and the FACS at `facs`.
fn build_fadt(dsdt: u64, facs: u64) -> FADT {
    // The buttons are flagged as ones the guest has no fixed hardware for.
    let mut fadt = FADTBuilder::new(OEM_ID, OEM_TABLE_ID, OEM_REVISION)
        .dsdt_64(dsdt)
        .firmware_ctrl_64(facs)
        .flag(Flags::Wbinvd)
        .flag(Flags::PwrButton)
        .flag(Flags::SlpButton)
        .flag(Flags::ResetRegSup);
    let pm = u32::from(ACPI_PM_PORT);
    fadt.sci_int = u16::try_from(SCI_GSI)
        .expect("the SCI is an IOAPIC line")
        .into();
    fadt.pm1a_evt_blk = (pm + u32::from(PM1_STATUS)).into();
    fadt.pm1a_cnt_blk = (pm + u32::from(PM1_CONTROL)).into();
    fadt.pm1_evt_len = PM1_EVENT_LEN;
    fadt.pm1_cnt_len = PM1_CONTROL_LEN;
    // The i8042 flag stays clear. hvi serves only the controller's reset
    // command, so the guest has no keyboard to probe for.
    fadt.iapc_boot_arch = (IAPC_VGA_NOT_PRESENT | IAPC_MSI_NOT_SUPPORTED).into();
    fadt.reset_reg = GAS::new(
        AddressSpace::SystemIo,
        8,
        0,
        AccessSize::ByteAccess,
        u64::from(ACPI_PM_PORT + RESET_REGISTER),
    );
    fadt.reset_value = RESET_VALUE;
    fadt.finalize()
}

/// Returns the MADT for `num_cpus` vCPUs.
///
/// The processor UID and the APIC id of each CPU are its vCPU index, and the
/// IOAPIC takes the id after the last CPU, as in the MP table. The table leaves
/// the PC-AT flag clear, so Linux probes for the 8259 by its ports and finds
/// KVM's.
fn build_madt(num_cpus: u32) -> MADT {
    let mut madt = MADT::new(
        OEM_ID,
        OEM_TABLE_ID,
        OEM_REVISION,
        LocalInterruptController::Address(LAPIC_ADDR),
    );
    for id in 0..num_cpus {
        let id = id as u8;
        madt.add_structure(ProcessorLocalApic::new(id, id, EnabledStatus::Enabled));
    }
    madt.add_structure(IoApic::new(num_cpus as u8, IOAPIC_ADDR, 0));
    madt
}

/// The tables as they are laid out from [`ACPI_ADDR`], with the RSDP first.
struct Tables {
    /// The bytes from [`ACPI_ADDR`] on, with the RSDP's place still zero.
    bytes: Vec<u8>,
}

impl Tables {
    /// Returns an empty layout that keeps the RSDP's place.
    fn new() -> Self {
        Self {
            bytes: vec![0; Rsdp::len()],
        }
    }

    /// Appends `table` at the next multiple of `align`.
    ///
    /// Returns the table's guest address.
    fn place(&mut self, table: &dyn Aml, align: usize) -> u64 {
        let at = self.bytes.len().next_multiple_of(align);
        self.bytes.resize(at, 0);
        table.to_aml_bytes(&mut self.bytes);
        ACPI_ADDR + at as u64
    }

    /// Returns the bytes, with the RSDP written to point at the XSDT at `xsdt`.
    fn finish(mut self, xsdt: u64) -> Vec<u8> {
        let mut rsdp = Vec::new();
        Rsdp::new(OEM_ID, xsdt).to_aml_bytes(&mut rsdp);
        self.bytes[..rsdp.len()].copy_from_slice(&rsdp);
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::layout::HIGH_MEM_START;
    use crate::config::Stop;
    use crate::devices::legacy::acpi_pm::{PmRegisters, SLP_EN, SLP_TYP_SHIFT};

    // Offsets and bits the ACPI specification gives the fields a guest reads
    // and writes.
    const RSDP_XSDT: usize = 24;
    const HEADER_LEN: usize = 36;
    const FADT_SCI_INT: usize = 46;
    const FADT_SMI_CMD: usize = 48;
    const FADT_PM1A_EVT_BLK: usize = 56;
    const FADT_PM1A_CNT_BLK: usize = 64;
    const FADT_PM1_EVT_LEN: usize = 88;
    const FADT_PM1_CNT_LEN: usize = 89;
    const FADT_FLAGS: usize = 112;
    const FADT_RESET_REG_ADDRESS: usize = 120;
    const FADT_RESET_VALUE: usize = 128;
    const FADT_X_FIRMWARE_CTRL: usize = 132;
    const FADT_X_DSDT: usize = 140;
    const FADT_HW_REDUCED_ACPI: u32 = 1 << 20;
    const FADT_RESET_REG_SUP: u32 = 1 << 10;
    const MADT_LOCAL_APIC: u8 = 0;
    const MADT_IO_APIC: u8 = 1;
    const AML_PACKAGE_OP: u8 = 0x12;
    const AML_BYTE_PREFIX: u8 = 0x0a;

    /// Returns the byte sum of `bytes`, which is zero over a table with a valid
    /// checksum.
    fn sum(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b))
    }

    /// Returns the little-endian `u16` at offset `at` of `bytes`.
    fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
    }

    /// Returns the little-endian `u32` at offset `at` of `bytes`.
    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    /// Returns the little-endian `u64` at offset `at` of `bytes`.
    fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    /// Returns the table at guest address `addr`, by the length in its header.
    fn table(blob: &[u8], addr: u64) -> &[u8] {
        let start = usize::try_from(addr - ACPI_ADDR).unwrap();
        let len = u32_at(blob, start + 4) as usize;
        &blob[start..start + len]
    }

    /// Returns the XSDT's entries, the FADT first.
    fn xsdt_entries(blob: &[u8]) -> Vec<u64> {
        let xsdt = table(blob, u64_at(blob, RSDP_XSDT));
        assert_eq!(&xsdt[0..4], b"XSDT");
        (HEADER_LEN..xsdt.len())
            .step_by(8)
            .map(|at| u64_at(xsdt, at))
            .collect()
    }

    /// Returns the FADT, the XSDT's first entry.
    fn fadt(blob: &[u8]) -> &[u8] {
        table(blob, xsdt_entries(blob)[0])
    }

    // The guest scans 0xe0000-0xfffff on 16-byte boundaries for the RSDP.
    #[test]
    fn rsdp_sits_where_the_guest_scans() {
        let blob = build(255);
        assert_eq!(&blob[0..8], b"RSD PTR ");
        assert!((0xe_0000..HIGH_MEM_START).contains(&ACPI_ADDR));
        assert_eq!(ACPI_ADDR % 16, 0);
        assert!(ACPI_ADDR + blob.len() as u64 <= HIGH_MEM_START);
    }

    #[test]
    fn every_checksum_sums_to_zero() {
        let blob = build(4);
        assert_eq!(sum(&blob[..20]), 0, "RSDP, ACPI 1.0 part");
        assert_eq!(sum(&blob[..Rsdp::len()]), 0, "RSDP, extended");
        let fadt = fadt(&blob);
        let dsdt = u64_at(fadt, FADT_X_DSDT);
        for addr in [u64_at(&blob, RSDP_XSDT), dsdt]
            .into_iter()
            .chain(xsdt_entries(&blob))
        {
            assert_eq!(sum(table(&blob, addr)), 0, "table at {addr:#x}");
        }
    }

    #[test]
    fn tables_chain_from_the_rsdp() {
        let blob = build(2);
        let entries = xsdt_entries(&blob);
        assert_eq!(entries.len(), 2, "the FADT and the MADT");
        let fadt = fadt(&blob);
        assert_eq!(&fadt[0..4], b"FACP");
        assert_eq!(&table(&blob, entries[1])[0..4], b"APIC");
        assert_eq!(&table(&blob, u64_at(fadt, FADT_X_DSDT))[0..4], b"DSDT");
        let facs = u64_at(fadt, FADT_X_FIRMWARE_CTRL);
        assert_eq!(facs % 64, 0, "the FACS is 64-byte aligned");
        assert_eq!(&table(&blob, facs)[0..4], b"FACS");
    }

    // A guest that finds ACPI tables reads its CPUs from the MADT alone.
    #[test]
    fn madt_lists_every_cpu_and_the_ioapic() {
        let blob = build(3);
        let madt = table(&blob, xsdt_entries(&blob)[1]);
        assert_eq!(u32_at(madt, HEADER_LEN), LAPIC_ADDR);
        let mut at = HEADER_LEN + 8;
        let mut apic_ids = Vec::new();
        let mut ioapic = None;
        while at < madt.len() {
            let (kind, len) = (madt[at], usize::from(madt[at + 1]));
            match kind {
                MADT_LOCAL_APIC => {
                    assert_eq!(u32_at(madt, at + 4), 1, "enabled");
                    apic_ids.push(madt[at + 3]);
                }
                MADT_IO_APIC => ioapic = Some((madt[at + 2], u32_at(madt, at + 4))),
                other => panic!("unexpected MADT entry {other}"),
            }
            at += len;
        }
        assert_eq!(at, madt.len());
        assert_eq!(apic_ids, [0, 1, 2]);
        assert_eq!(ioapic, Some((3, IOAPIC_ADDR)));
    }

    #[test]
    fn fadt_names_the_pm_registers() {
        let blob = build(1);
        let fadt = fadt(&blob);
        let flags = u32_at(fadt, FADT_FLAGS);
        assert_eq!(flags & FADT_HW_REDUCED_ACPI, 0, "not hardware-reduced");
        assert_ne!(flags & FADT_RESET_REG_SUP, 0);
        assert_eq!(u32::from(u16_at(fadt, FADT_SCI_INT)), SCI_GSI);
        assert_eq!(u32_at(fadt, FADT_SMI_CMD), 0, "always in ACPI mode");
        assert_eq!(
            u32_at(fadt, FADT_PM1A_EVT_BLK),
            u32::from(ACPI_PM_PORT + PM1_STATUS)
        );
        assert_eq!(
            u32_at(fadt, FADT_PM1A_CNT_BLK),
            u32::from(ACPI_PM_PORT + PM1_CONTROL)
        );
        assert_eq!(fadt[FADT_PM1_EVT_LEN], PM1_EVENT_LEN);
        assert_eq!(fadt[FADT_PM1_CNT_LEN], PM1_CONTROL_LEN);
        let reset = u16::try_from(u64_at(fadt, FADT_RESET_REG_ADDRESS)).unwrap();
        let mut pm = PmRegisters::default();
        assert!(matches!(
            pm.write(reset - ACPI_PM_PORT, &[fadt[FADT_RESET_VALUE]]),
            Some(Stop::SystemReset)
        ));
    }

    // The guest takes the sleep type from the DSDT's `\_S5` package, so the
    // test decodes it from there and writes it as ACPICA's legacy sleep does.
    #[test]
    fn s5_package_powers_off() {
        let blob = build(1);
        let dsdt = table(&blob, u64_at(fadt(&blob), FADT_X_DSDT));
        let name = dsdt.windows(4).position(|w| w == b"_S5_").unwrap();
        let package = &dsdt[name + 4..];
        assert_eq!(package[0], AML_PACKAGE_OP);
        assert_eq!(package[2], 1, "one element: SLP_TYPa, with SLP_TYPb zero");
        assert_eq!(package[3], AML_BYTE_PREFIX);
        let slp_typ = u16::from(package[4]);

        let mut pm = PmRegisters::default();
        let typ = slp_typ << SLP_TYP_SHIFT;
        assert!(pm.write(PM1_CONTROL, &typ.to_le_bytes()).is_none());
        let off = typ | SLP_EN;
        assert!(matches!(
            pm.write(PM1_CONTROL, &off.to_le_bytes()),
            Some(Stop::SystemOff)
        ));
    }
}

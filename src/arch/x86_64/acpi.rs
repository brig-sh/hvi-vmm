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

//! ACPI tables and power registers, so an x86 guest can power off.
//!
//! A guest with no ACPI registers no power-off handler and turns `poweroff`
//! into a halt. With the in-kernel irqchip, KVM handles that halt itself and
//! the VMM never sees it. These tables give the guest a power-off.
//!
//! The FADT describes a PC's fixed hardware: a PM1 event block, a PM1 control
//! block and a reset register at [`ACPI_PM_PORT`], which [`PmRegisters`]
//! serves, and a system control interrupt hvi never raises. The DSDT holds the
//! `\_S5` package, which says what the guest writes to PM1 control to power
//! off. The MADT lists the CPUs and the IOAPIC as the MP table does. A guest
//! that finds ACPI tables without a MADT discards the MP table.
//!
//! The FADT is not hardware-reduced. A hardware-reduced guest drops the legacy
//! PIC and numbers its interrupts dynamically, so the ISA lines the console and
//! the `virtio_mmio.device=` devices use would no longer reach their drivers.
//!
//! [`build`] returns the bytes to place at [`ACPI_ADDR`]: the RSDP first,
//! where the guest scans for it, then the other tables.

use crate::arch::x86_64::layout::{
    ACPI_ADDR, ACPI_PM_PORT, ACPI_PM_PORTS, IOAPIC_ADDR, LAPIC_ADDR, SCI_GSI,
};
use crate::config::Stop;

/// Where each table sits, as an offset from [`ACPI_ADDR`]. The FACS needs a
/// 64-byte boundary, and the MADT goes last because it grows with the CPUs.
const XSDT_OFFSET: u64 = 0x40;
const FADT_OFFSET: u64 = 0x80;
const DSDT_OFFSET: u64 = 0x200;
const FACS_OFFSET: u64 = 0x280;
const MADT_OFFSET: u64 = 0x300;

/// The system description table header every table but the RSDP and the FACS
/// starts with.
const HEADER_LEN: usize = 36;
/// The RSDP of ACPI 2.0 and later, which carries an XSDT address.
const RSDP_LEN: usize = 36;
/// The FADT of ACPI 6.x, up to and including the hypervisor vendor field.
const FADT_LEN: usize = 276;
const FACS_LEN: usize = 64;

const OEM_ID: &[u8; 6] = b"HVI   ";
const OEM_TABLE_ID: &[u8; 8] = b"HVI x86 ";
const CREATOR_ID: &[u8; 4] = b"HVI ";

/// FADT flags. The buttons are ones the guest has no fixed hardware for.
const FADT_WBINVD: u32 = 1 << 0;
const FADT_PWR_BUTTON: u32 = 1 << 4;
const FADT_SLP_BUTTON: u32 = 1 << 5;
const FADT_RESET_REG_SUP: u32 = 1 << 10;

/// IA-PC boot architecture flags. The i8042 bit stays clear: hvi serves the
/// controller's reset command and nothing else, so the guest has no keyboard
/// to probe for.
const IAPC_VGA_NOT_PRESENT: u16 = 1 << 2;
const IAPC_MSI_NOT_SUPPORTED: u16 = 1 << 3;

/// Register offsets from [`ACPI_PM_PORT`]. PM1 status and PM1 enable are the
/// two halves of the PM1 event block.
const PM1_STATUS: usize = 0;
const PM1_ENABLE: usize = 2;
const PM1_CONTROL: usize = 4;
const RESET_REGISTER: usize = 6;
const PM1_EVENT_LEN: u8 = 4;
const PM1_CONTROL_LEN: u8 = 2;

/// PM1 control bits. SCI_EN set means the machine is in ACPI mode.
const SCI_EN: u16 = 1 << 0;
const SLP_TYP_SHIFT: u16 = 10;
const SLP_TYP_MASK: u16 = 0x7;
const SLP_EN: u16 = 1 << 13;

/// The sleep type of S5, as the `\_S5` package gives it.
const SLP_TYP_S5: u8 = 5;
/// What the guest writes to the reset register.
const RESET_VALUE: u8 = 1;

/// The DSDT's only object, `Name (_S5, Package () { 5, 0, 0, 0 })`.
const S5_AML: [u8; 13] = [
    0x08, b'_', b'S', b'5', b'_', // NameOp "_S5_"
    0x12, 0x07, 0x04, // PackageOp, PkgLength 7, four elements
    0x0a, SLP_TYP_S5, // BytePrefix: SLP_TYPa
    0x00, 0x00, 0x00, // Zero: SLP_TYPb and two reserved
];

/// MADT entries and flags.
const MADT_PCAT_COMPAT: u32 = 1;
const MADT_LOCAL_APIC: u8 = 0;
const MADT_IO_APIC: u8 = 1;
const LOCAL_APIC_ENABLED: u32 = 1;

/// The PM1 event and control registers and the reset register, as the guest
/// reads and writes them at [`ACPI_PM_PORT`].
///
/// PM1 status reads zero, since hvi raises no ACPI event. PM1 enable keeps
/// what the guest writes, because the guest reads an enable bit back to check
/// it. PM1 control reads SCI_EN.
#[derive(Debug, Default)]
pub struct PmRegisters {
    /// What the guest last wrote to PM1 enable.
    enable: u16,
}

impl PmRegisters {
    /// Returns whether `port` is one of these registers.
    #[must_use]
    pub fn serves(port: u16) -> bool {
        (ACPI_PM_PORT..ACPI_PM_PORT + ACPI_PM_PORTS).contains(&port)
    }

    /// Fills `data` with what a read of `data.len()` bytes at `port` returns.
    pub fn read(&self, port: u16, data: &mut [u8]) {
        let image = self.image();
        let start = usize::from(port.wrapping_sub(ACPI_PM_PORT));
        for (i, b) in data.iter_mut().enumerate() {
            *b = image.get(start + i).copied().unwrap_or(0xff);
        }
    }

    /// Applies a write of `data` at `port`, and returns the stop it asks for.
    ///
    /// The sleep type and SLP_EN are both in the high byte of PM1 control. The
    /// guest writes the sleep type alone first, and that write returns `None`.
    pub fn write(&mut self, port: u16, data: &[u8]) -> Option<Stop> {
        let start = usize::from(port.wrapping_sub(ACPI_PM_PORT));
        let mut stop = None;
        for (i, &b) in data.iter().enumerate() {
            match start + i {
                PM1_ENABLE => self.enable = (self.enable & 0xff00) | u16::from(b),
                at if at == PM1_ENABLE + 1 => {
                    self.enable = (self.enable & 0x00ff) | (u16::from(b) << 8);
                }
                at if at == PM1_CONTROL + 1 => {
                    let control = u16::from(b) << 8;
                    let slp_typ = (control >> SLP_TYP_SHIFT) & SLP_TYP_MASK;
                    if control & SLP_EN != 0 && slp_typ == u16::from(SLP_TYP_S5) {
                        stop = Some(Stop::SystemOff);
                    }
                }
                RESET_REGISTER if b == RESET_VALUE => stop = Some(Stop::SystemReset),
                _ => {}
            }
        }
        stop
    }

    /// Returns the registers as the guest reads them, one byte per port.
    fn image(&self) -> [u8; ACPI_PM_PORTS as usize] {
        let mut image = [0u8; ACPI_PM_PORTS as usize];
        image[PM1_ENABLE..PM1_ENABLE + 2].copy_from_slice(&self.enable.to_le_bytes());
        image[PM1_CONTROL..PM1_CONTROL + 2].copy_from_slice(&SCI_EN.to_le_bytes());
        image
    }
}

/// Builds the tables for `num_cpus` vCPUs (bytes to write at [`ACPI_ADDR`]).
#[must_use]
pub fn build(num_cpus: u32) -> Vec<u8> {
    let mut dsdt = vec![0u8; HEADER_LEN];
    dsdt.extend_from_slice(&S5_AML);
    finish_table(b"DSDT", 2, &mut dsdt);

    let mut facs = [0u8; FACS_LEN];
    facs[0..4].copy_from_slice(b"FACS");
    facs[4..8].copy_from_slice(&(FACS_LEN as u32).to_le_bytes());
    facs[32] = 2; // version

    let mut madt = vec![0u8; HEADER_LEN + 8];
    madt[36..40].copy_from_slice(&LAPIC_ADDR.to_le_bytes());
    madt[40..44].copy_from_slice(&MADT_PCAT_COMPAT.to_le_bytes());
    for id in 0..num_cpus {
        // Processor UID and APIC id are both the vCPU index, as in the MP
        // table.
        madt.extend_from_slice(&[MADT_LOCAL_APIC, 8, id as u8, id as u8]);
        madt.extend_from_slice(&LOCAL_APIC_ENABLED.to_le_bytes());
    }
    // The IOAPIC takes the id after the last CPU, as in the MP table, and
    // its lines start at GSI 0.
    madt.extend_from_slice(&[MADT_IO_APIC, 12, num_cpus as u8, 0]);
    madt.extend_from_slice(&IOAPIC_ADDR.to_le_bytes());
    madt.extend_from_slice(&0u32.to_le_bytes());
    finish_table(b"APIC", 5, &mut madt);

    let pm = u32::from(ACPI_PM_PORT);
    let mut fadt = vec![0u8; FADT_LEN];
    fadt[46..48].copy_from_slice(&(SCI_GSI as u16).to_le_bytes());
    fadt[56..60].copy_from_slice(&(pm + PM1_STATUS as u32).to_le_bytes()); // PM1a_EVT_BLK
    fadt[64..68].copy_from_slice(&(pm + PM1_CONTROL as u32).to_le_bytes()); // PM1a_CNT_BLK
    fadt[88] = PM1_EVENT_LEN;
    fadt[89] = PM1_CONTROL_LEN;
    let iapc = IAPC_VGA_NOT_PRESENT | IAPC_MSI_NOT_SUPPORTED;
    fadt[109..111].copy_from_slice(&iapc.to_le_bytes());
    let flags = FADT_WBINVD | FADT_PWR_BUTTON | FADT_SLP_BUTTON | FADT_RESET_REG_SUP;
    fadt[112..116].copy_from_slice(&flags.to_le_bytes());
    fadt[116..128].copy_from_slice(&io_byte(ACPI_PM_PORT + RESET_REGISTER as u16)); // RESET_REG
    fadt[128] = RESET_VALUE;
    fadt[131] = 5; // minor version: ACPI 6.5
    fadt[132..140].copy_from_slice(&(ACPI_ADDR + FACS_OFFSET).to_le_bytes()); // X_FIRMWARE_CTRL
    fadt[140..148].copy_from_slice(&(ACPI_ADDR + DSDT_OFFSET).to_le_bytes()); // X_DSDT
    finish_table(b"FACP", 6, &mut fadt);

    let mut xsdt = vec![0u8; HEADER_LEN];
    xsdt.extend_from_slice(&(ACPI_ADDR + FADT_OFFSET).to_le_bytes());
    xsdt.extend_from_slice(&(ACPI_ADDR + MADT_OFFSET).to_le_bytes());
    finish_table(b"XSDT", 1, &mut xsdt);

    let mut rsdp = [0u8; RSDP_LEN];
    rsdp[0..8].copy_from_slice(b"RSD PTR ");
    rsdp[9..15].copy_from_slice(OEM_ID);
    rsdp[15] = 2; // revision: ACPI 2.0 or later
    rsdp[20..24].copy_from_slice(&(RSDP_LEN as u32).to_le_bytes());
    rsdp[24..32].copy_from_slice(&(ACPI_ADDR + XSDT_OFFSET).to_le_bytes());
    // The first checksum covers the ACPI 1.0 part, the second the whole.
    rsdp[8] = checksum(&rsdp[..20]);
    rsdp[32] = checksum(&rsdp);

    let mut out = vec![0u8; MADT_OFFSET as usize + madt.len()];
    for (offset, table) in [
        (0, &rsdp[..]),
        (XSDT_OFFSET, &xsdt[..]),
        (FADT_OFFSET, &fadt[..]),
        (DSDT_OFFSET, &dsdt[..]),
        (FACS_OFFSET, &facs[..]),
        (MADT_OFFSET, &madt[..]),
    ] {
        let start = offset as usize;
        out[start..start + table.len()].copy_from_slice(table);
    }
    out
}

/// Fills in the header of `table`, whose length is its final one, and sets the
/// checksum last.
fn finish_table(signature: &[u8; 4], revision: u8, table: &mut [u8]) {
    let len = u32::try_from(table.len()).expect("an ACPI table fits in 4 GiB");
    table[0..4].copy_from_slice(signature);
    table[4..8].copy_from_slice(&len.to_le_bytes());
    table[8] = revision;
    table[10..16].copy_from_slice(OEM_ID);
    table[16..24].copy_from_slice(OEM_TABLE_ID);
    table[24..28].copy_from_slice(&1u32.to_le_bytes()); // OEM revision
    table[28..32].copy_from_slice(CREATOR_ID);
    table[32..36].copy_from_slice(&1u32.to_le_bytes()); // creator revision
    table[9] = checksum(table);
}

/// Returns a Generic Address Structure for one byte at I/O port `port`.
fn io_byte(port: u16) -> [u8; 12] {
    let mut gas = [0u8; 12];
    gas[0] = 1; // address space: system I/O
    gas[1] = 8; // register width in bits
    gas[3] = 1; // access size: byte
    gas[4..12].copy_from_slice(&u64::from(port).to_le_bytes());
    gas
}

/// Returns the byte that makes the sum of `bytes` zero, with the checksum
/// field still zero among them.
fn checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    sum.wrapping_neg()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::layout::HIGH_MEM_START;

    fn sum(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b))
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    /// Returns the table at guest address `addr`, by the length in its header.
    fn table(blob: &[u8], addr: u64) -> &[u8] {
        let start = (addr - ACPI_ADDR) as usize;
        let len = u32_at(blob, start + 4) as usize;
        &blob[start..start + len]
    }

    /// Returns what PM1 control reads as one 16-bit access.
    fn control(pm: &PmRegisters) -> u16 {
        let mut word = [0u8; 2];
        pm.read(ACPI_PM_PORT + PM1_CONTROL as u16, &mut word);
        u16::from_le_bytes(word)
    }

    // The guest scans 0xe0000-0xfffff on 16-byte boundaries for the RSDP.
    #[test]
    fn the_rsdp_is_where_the_guest_scans() {
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
        assert_eq!(sum(&blob[..RSDP_LEN]), 0, "RSDP, extended");
        for offset in [XSDT_OFFSET, FADT_OFFSET, DSDT_OFFSET, MADT_OFFSET] {
            assert_eq!(sum(table(&blob, ACPI_ADDR + offset)), 0, "{offset:#x}");
        }
    }

    #[test]
    fn the_tables_chain_from_the_rsdp() {
        let blob = build(2);
        let xsdt = table(&blob, u64_at(&blob, 24));
        assert_eq!(&xsdt[0..4], b"XSDT");
        assert_eq!(xsdt.len(), HEADER_LEN + 16, "the FADT and the MADT");
        let fadt = table(&blob, u64_at(xsdt, HEADER_LEN));
        assert_eq!(&fadt[0..4], b"FACP");
        assert_eq!(fadt.len(), FADT_LEN);
        assert_eq!(fadt[8], 6, "revision");
        assert_eq!(&table(&blob, u64_at(xsdt, HEADER_LEN + 8))[0..4], b"APIC");
        let dsdt = table(&blob, u64_at(fadt, 140));
        assert_eq!(&dsdt[0..4], b"DSDT");
        assert_eq!(&dsdt[HEADER_LEN..], &S5_AML);
        let facs = u64_at(fadt, 132);
        assert_eq!(facs % 64, 0, "the FACS is 64-byte aligned");
        assert_eq!(&table(&blob, facs)[0..4], b"FACS");
    }

    // A guest that finds ACPI tables reads its CPUs from the MADT alone.
    #[test]
    fn the_madt_lists_every_cpu_and_the_ioapic() {
        let blob = build(3);
        let madt = table(&blob, ACPI_ADDR + MADT_OFFSET);
        assert_eq!(u32_at(madt, 36), LAPIC_ADDR);
        let mut at = HEADER_LEN + 8;
        let mut apic_ids = Vec::new();
        let mut ioapic = None;
        while at < madt.len() {
            let (kind, len) = (madt[at], usize::from(madt[at + 1]));
            match kind {
                MADT_LOCAL_APIC => {
                    assert_eq!(u32_at(madt, at + 4), LOCAL_APIC_ENABLED);
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
    fn the_fadt_names_the_pm_registers() {
        let blob = build(1);
        let fadt = table(&blob, ACPI_ADDR + FADT_OFFSET);
        let flags = u32_at(fadt, 112);
        assert_eq!(flags & (1 << 20), 0, "not hardware-reduced");
        assert_ne!(flags & FADT_RESET_REG_SUP, 0);
        assert_eq!(u32::from(u16::from_le_bytes([fadt[46], fadt[47]])), SCI_GSI);
        assert_eq!(u32_at(fadt, 56), u32::from(ACPI_PM_PORT));
        assert_eq!(u32_at(fadt, 64), u32::from(ACPI_PM_PORT) + 4);
        assert_eq!((fadt[88], fadt[89]), (4, 2));
        assert_eq!(u32_at(fadt, 48), 0, "no SMI command: always in ACPI mode");
        let reset = u64_at(fadt, 120);
        assert!(PmRegisters::serves(reset as u16));
        let mut pm = PmRegisters::default();
        assert!(matches!(
            pm.write(reset as u16, &[fadt[128]]),
            Some(Stop::SystemReset)
        ));
    }

    // What the guest writes is computed from the `\_S5` package, the way
    // ACPICA's legacy sleep does it, so the package and the decode cannot
    // drift apart.
    #[test]
    fn the_s5_package_powers_off() {
        let mut pm = PmRegisters::default();
        let port = ACPI_PM_PORT + PM1_CONTROL as u16;
        let typ = (u16::from(S5_AML[9]) << SLP_TYP_SHIFT) | control(&pm);
        assert!(
            pm.write(port, &typ.to_le_bytes()).is_none(),
            "SLP_TYP alone"
        );
        let off = typ | SLP_EN;
        assert!(matches!(
            pm.write(port, &off.to_le_bytes()),
            Some(Stop::SystemOff)
        ));
        // The same write as two byte accesses.
        assert!(pm.write(port, &off.to_le_bytes()[..1]).is_none());
        assert!(matches!(
            pm.write(port + 1, &off.to_le_bytes()[1..]),
            Some(Stop::SystemOff)
        ));
    }

    #[test]
    fn pm1_control_reads_acpi_mode() {
        assert_eq!(control(&PmRegisters::default()) & SCI_EN, SCI_EN);
    }

    // The guest reads an enable bit back after it sets it, and reports the
    // event as missing hardware when the bit reads clear.
    #[test]
    fn pm1_enable_reads_back() {
        let mut pm = PmRegisters::default();
        let port = ACPI_PM_PORT + PM1_ENABLE as u16;
        assert!(pm.write(port, &0x0520u16.to_le_bytes()).is_none());
        let mut word = [0u8; 2];
        pm.read(port, &mut word);
        assert_eq!(u16::from_le_bytes(word), 0x0520);
        let mut status = [0xffu8; 2];
        pm.read(ACPI_PM_PORT, &mut status);
        assert_eq!(status, [0, 0]);
    }

    #[test]
    fn writes_outside_the_power_bits_ask_for_nothing() {
        let mut pm = PmRegisters::default();
        assert!(pm.write(ACPI_PM_PORT, &[0xff, 0xff]).is_none(), "status");
        assert!(
            pm.write(ACPI_PM_PORT + 6, &[0]).is_none(),
            "reset, wrong value"
        );
        assert!(!PmRegisters::serves(ACPI_PM_PORT + ACPI_PM_PORTS));
        assert!(!PmRegisters::serves(ACPI_PM_PORT - 1));
    }
}

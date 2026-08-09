//! A minimal Intel MultiProcessor (MP) table, so a guest booted without ACPI
//! discovers its CPUs and the IOAPIC (Linux `CONFIG_X86_MPPARSE` fallback).
//!
//! Layout follows the MP spec 1.4 and mirrors Firecracker's small table: an MP
//! floating pointer, a config header, then one processor entry per vCPU, a bus
//! entry, an IOAPIC entry, and ISA interrupt entries for the 16 legacy lines.
//! All checksums are one's-of-sum-is-zero over the relevant bytes. Returns the
//! bytes to place at [`crate::layout_x86::MPTABLE_ADDR`]; the floating pointer
//! sits first and points at the config table right after it.

use crate::layout_x86::MPTABLE_ADDR;

const APIC_LAPIC_BASE: u32 = 0xfee0_0000;
const IOAPIC_BASE: u32 = 0xfec0_0000;
const APIC_VERSION: u8 = 0x14;
const CPU_ENABLED: u8 = 1;
const CPU_BSP: u8 = 2;
const CPU_STEPPING: u32 = 0x600; // a plausible family/model/stepping
const CPU_FEATURE_FPU_APIC: u32 = 0x0201;

const ENTRY_PROCESSOR: u8 = 0;
const ENTRY_BUS: u8 = 1;
const ENTRY_IOAPIC: u8 = 2;
const ENTRY_IOINT: u8 = 3;

fn checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    (!sum).wrapping_add(1) // value that makes the total sum zero
}

/// Builds the MP table for `num_cpus` (bytes to write at `MPTABLE_ADDR`).
#[must_use]
pub fn build(num_cpus: u32) -> Vec<u8> {
    let config_phys = (MPTABLE_ADDR as u32) + 16; // config table follows the FP

    // --- config table entries ---
    let mut entries: Vec<u8> = Vec::new();

    // Processor entries (20 bytes each).
    for id in 0..num_cpus {
        let mut e = vec![0u8; 20];
        e[0] = ENTRY_PROCESSOR;
        e[1] = id as u8; // local APIC id
        e[2] = APIC_VERSION;
        e[3] = CPU_ENABLED | if id == 0 { CPU_BSP } else { 0 };
        e[4..8].copy_from_slice(&CPU_STEPPING.to_le_bytes());
        e[8..12].copy_from_slice(&CPU_FEATURE_FPU_APIC.to_le_bytes());
        entries.extend_from_slice(&e);
    }

    // Bus entry (8 bytes): ISA bus 0.
    let mut bus = vec![0u8; 8];
    bus[0] = ENTRY_BUS;
    bus[1] = 0; // bus id
    bus[2..8].copy_from_slice(b"ISA   ");
    entries.extend_from_slice(&bus);

    // IOAPIC entry (8 bytes).
    let ioapic_id = num_cpus as u8; // one past the last CPU apic id
    let mut io = vec![0u8; 8];
    io[0] = ENTRY_IOAPIC;
    io[1] = ioapic_id;
    io[2] = APIC_VERSION;
    io[3] = 1; // enabled
    io[4..8].copy_from_slice(&IOAPIC_BASE.to_le_bytes());
    entries.extend_from_slice(&io);

    // I/O interrupt entries (8 bytes each): ISA IRQ n -> IOAPIC input n.
    for irq in 0u8..16 {
        let mut it = vec![0u8; 8];
        it[0] = ENTRY_IOINT;
        it[1] = 0; // INT
        it[2..4].copy_from_slice(&0u16.to_le_bytes()); // flags: conforming
        it[4] = 0; // source bus id (ISA)
        it[5] = irq; // source bus irq
        it[6] = ioapic_id; // dest IOAPIC id
        it[7] = irq; // dest IOAPIC intin
        entries.extend_from_slice(&it);
    }
    let entry_count = num_cpus as u16 + 1 /*bus*/ + 1 /*ioapic*/ + 16 /*ioint*/;

    // --- config header (44 bytes) ---
    let mut hdr = vec![0u8; 44];
    hdr[0..4].copy_from_slice(b"PCMP");
    let base_len = (44 + entries.len()) as u16;
    hdr[4..6].copy_from_slice(&base_len.to_le_bytes());
    hdr[6] = 4; // spec rev 1.4
                // hdr[7] = checksum, filled below
    hdr[8..16].copy_from_slice(b"HVI     ");
    hdr[16..28].copy_from_slice(b"HVI x86 vm  ");
    hdr[34..36].copy_from_slice(&entry_count.to_le_bytes());
    hdr[36..40].copy_from_slice(&APIC_LAPIC_BASE.to_le_bytes());

    // Header checksum is over the header + all entries (the base table).
    let mut base = hdr.clone();
    base.extend_from_slice(&entries);
    let cksum = checksum(&base);
    // Rebuild with the checksum in place.
    let mut out_config = hdr;
    out_config[7] = cksum;
    out_config.extend_from_slice(&entries);

    // --- MP floating pointer (16 bytes) ---
    let mut fp = vec![0u8; 16];
    fp[0..4].copy_from_slice(b"_MP_");
    fp[4..8].copy_from_slice(&config_phys.to_le_bytes()); // -> config table
    fp[8] = 1; // length in 16-byte units
    fp[9] = 4; // spec rev 1.4
               // fp[10] = checksum, filled below
               // fp[11] = feature1 = 0 (config table present)
    fp[10] = checksum(&fp);

    let mut out = fp;
    out.extend_from_slice(&out_config);
    out
}

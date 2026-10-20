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

//! The guest-visible contract of the `portable-arm64-v1` machine profile
//! that does not depend on the hypervisor: the CPU baseline, the kernel
//! arguments, the devicetree's inputs, the firmware's answers and what a
//! KVM host must offer to present them.
//!
//! The values come from measurements on a Raspberry Pi 5 (KVM, Linux
//! 6.12.25) and an Apple M5 Pro (Hypervisor.framework, macOS 26.7). See
//! `docs/portable-profile.md` for the contract and where each number comes
//! from.

use crate::arch::aarch64::fdt::{ArchTimer, VirtioDevices};
use crate::arch::aarch64::layout::{GicLayout, GicVersion};
use crate::config::BootConfig;

/// The ID registers a portable guest reads, by name, in the order a backend
/// writes them. Every field is at most what both hosts have, except where the
/// Pi fixes a value above the Mac's (MMFR1 VMIDBits and VH), which the Mac
/// then raises to match. `MPIDR_EL1` is not here: it stays
/// `0x8000_0000 | cpu`.
pub const BASELINE: [(&str, u64); 12] = [
    // Cortex-A76 r4p1, as on the Pi.
    ("MIDR_EL1", 0x414f_d0b1),
    // EL0/EL1 AArch64 only, FP, AdvSIMD, RAS, CSV2, CSV3; GIC system
    // registers off.
    ("ID_AA64PFR0_EL1", 0x1100_0000_1011_0011),
    ("ID_AA64PFR1_EL1", 0),
    ("ID_AA64ZFR0_EL1", 0),
    ("ID_AA64SMFR0_EL1", 0),
    // AES+PMULL, SHA1, SHA256, CRC32, LSE, RDM, DotProd.
    ("ID_AA64ISAR0_EL1", 0x0000_1000_1021_1120),
    // DPB, LRCPC.
    ("ID_AA64ISAR1_EL1", 0x0000_0000_0010_0001),
    // 40-bit PA, 16-bit ASID, 4K and 16K granules, no 64K.
    ("ID_AA64MMFR0_EL1", 0x0000_0000_0f10_0022),
    ("ID_AA64MMFR1_EL1", 0x0000_0000_1021_2120),
    // CnP, UAO, IESB.
    ("ID_AA64MMFR2_EL1", 0x0000_0000_0000_1011),
    // DebugVer 8.0, 6 breakpoints, 4 watchpoints, 2 context comparators, no
    // PMU.
    ("ID_AA64DFR0_EL1", 0x0000_0000_1030_5006),
    ("ID_AA64DFR1_EL1", 0),
];

/// The 4-bit ID register fields that are signed: 0xf means the feature is
/// absent, 0 present, 1 present with more. Linux declares exactly these
/// with `S_ARM64_FTR_BITS` in `arch/arm64/kernel/cpufeature.c` (6.12) for
/// the registers of [`BASELINE`]. Every other field is unsigned. Each entry
/// is a register and the field's low bit.
const SIGNED_FIELDS: [(&str, u32); 5] = [
    ("ID_AA64PFR0_EL1", 16),  // FP
    ("ID_AA64PFR0_EL1", 20),  // AdvSIMD
    ("ID_AA64MMFR0_EL1", 24), // TGran64
    ("ID_AA64MMFR0_EL1", 28), // TGran4
    ("ID_AA64DFR0_EL1", 36),  // DoubleLock
];

/// The fields [`BASELINE`] may hold above what a host has, and why that
/// is safe. The Pi fixes them above the Mac's 0, and KVM refuses to lower
/// them, so the Mac raises them.
const ALLOWED_RAISES: [(&str, u32, &str); 2] = [
    (
        "ID_AA64MMFR1_EL1",
        4,
        "VMIDBits describes stage-2 translation, which needs EL2",
    ),
    (
        "ID_AA64MMFR1_EL1",
        8,
        "VH describes EL2, which the baseline hides",
    ),
];

/// Returns the fields of baseline register `name` that claim more than the
/// host's `host` value of it, one description each, allowing the raises a
/// backend can make (`ALLOWED_RAISES`).
///
/// A host must back every field: Hypervisor.framework accepts a raised
/// field and the guest then reads it, so a guest told of a feature its
/// host lacks would fault on the first instruction that uses it. An
/// unsigned field claims more when it is larger, a signed field (see
/// `SIGNED_FIELDS`) when it is larger as a signed number, so 0xf, absent,
/// never claims more. `ALLOWED_RAISES` are let through.
#[must_use]
pub fn excess_fields(name: &str, baseline: u64, host: u64) -> Vec<String> {
    excess(name, baseline, host, &ALLOWED_RAISES)
}

/// [`excess_fields`] with the raises in `allowed` let through.
fn excess(name: &str, baseline: u64, host: u64, allowed: &[(&str, u32, &str)]) -> Vec<String> {
    let mut out = Vec::new();
    for shift in (0..64).step_by(4) {
        let b = (baseline >> shift) & 0xf;
        let h = (host >> shift) & 0xf;
        let raised = if SIGNED_FIELDS.contains(&(name, shift)) {
            // Sign-extend the nibble.
            ((b as i8) << 4 >> 4) > ((h as i8) << 4 >> 4)
        } else {
            b > h
        };
        if raised && !allowed.iter().any(|(n, s, _)| *n == name && *s == shift) {
            out.push(format!(
                "{name}[{}:{shift}] is {b:#x} in the baseline but {h:#x} on this host",
                shift + 3
            ));
        }
    }
    out
}

/// `DCZID_EL0`, which no backend can set. Both hosts report 64-byte
/// `DC ZVA` blocks.
pub const DCZID_EL0: u64 = 0x4;

/// Kernel arguments a portable boot adds, so the guest stays off the
/// features the baseline already hides even if a register slipped through.
pub const KERNEL_ARGS: &str = "arm64.nopauth arm64.nobti arm64.nosve arm64.nosme arm64.nomte";

/// Returns `cmdline` with [`KERNEL_ARGS`] in front.
///
/// In front, because Linux hands everything after a standalone `--` to
/// init, and its early `arm64.*` parser stops there too
/// (`arch/arm64/kernel/pi/idreg-override.c`, 6.12). Appended, the arguments
/// would be lost on a command line that has one.
#[must_use]
pub fn cmdline(cmdline: &str) -> String {
    if cmdline.is_empty() {
        KERNEL_ARGS.to_string()
    } else {
        format!("{KERNEL_ARGS} {cmdline}")
    }
}

/// What the devicetree of a portable guest is built from.
///
/// Both backends take it from [`devicetree`], so a guest given the same
/// configuration on a Mac and on a Pi gets the same tree, byte for byte,
/// and the same `dtb_sha256` in its profile.
#[derive(Debug, Clone)]
pub(crate) struct Devicetree {
    /// The GICv2, at QEMU virt's v2 addresses.
    pub(crate) gic: GicLayout,
    /// The kernel command line, [`KERNEL_ARGS`] first.
    pub(crate) cmdline: String,
    /// The device nodes: the virtio devices the backend backs, `/timer`
    /// without interrupts unless the configuration asks for them, and
    /// `hvi-time`.
    pub(crate) devices: VirtioDevices,
}

/// Returns the devicetree inputs of a portable guest of `cfg` with `vcpus`
/// vCPUs and the virtio devices the backend backs.
///
/// # Errors
///
/// Errors when `vcpus` is more than a GICv2 reaches.
pub(crate) fn devicetree(
    cfg: &BootConfig,
    vcpus: u32,
    blk_count: usize,
    net: bool,
    vsock: bool,
) -> Result<Devicetree, String> {
    Ok(Devicetree {
        gic: GicLayout::for_vcpus(GicVersion::V2, vcpus)?,
        cmdline: cmdline(&cfg.cmdline),
        devices: VirtioDevices {
            // `BootConfig::validate` refuses a second disk under this
            // profile, but the tree carries every disk it is given, as the
            // native one does.
            blk_count,
            net,
            vsock,
            // `BootConfig::validate` refuses shares under this profile.
            fs_count: 0,
            timer: if cfg.arch_timer_irq() {
                ArchTimer::Interrupts
            } else {
                ArchTimer::NoInterrupts {
                    clock_frequency: ArchTimer::PORTABLE_HZ,
                }
            },
            hvi_time: true,
        },
    })
}

/// What a KVM host offers a portable guest, as the backend reads it before
/// the guest's first instruction.
#[derive(Debug, Clone)]
pub struct KvmHost {
    /// Whether KVM creates a vGICv2 here.
    pub vgic_v2: bool,
    /// The host page size, in bytes.
    pub page_size: u64,
    /// The largest guest physical address size KVM offers, in bits.
    pub ipa_bits: u32,
    /// The value KVM gives a new guest of each [`BASELINE`] register, by
    /// name. A register it does not report is missing.
    pub id_regs: Vec<(&'static str, u64)>,
    /// The writable mask of each [`BASELINE`] register, by name, when KVM
    /// reports them (`KVM_ARM_GET_REG_WRITABLE_MASKS`). A field whose mask
    /// is 0xf can be lowered.
    pub writable: Option<Vec<(&'static str, u64)>>,
}

/// Returns why a KVM host cannot present the portable machine, one reason
/// each, or nothing when it can.
///
/// KVM lowers an ID register field only, never raises it, and not every
/// field can be written: `MIDR_EL1` cannot be changed at all, so the host
/// must be a Cortex-A76 r4p1. The rest of the machine needs a vGICv2, the
/// guest's 40-bit physical address space and 4 KiB or 16 KiB host pages
/// (the baseline offers the guest no 64 KiB granule).
#[must_use]
pub fn kvm_host_problems(host: &KvmHost) -> Vec<String> {
    let mut why = Vec::new();
    if !host.vgic_v2 {
        why.push(
            "KVM offers no vGICv2 here (a GICv3-only host); the portable profile's interrupt \
             controller is a GICv2"
                .to_string(),
        );
    }
    if host.page_size != 0x1000 && host.page_size != 0x4000 {
        why.push(format!(
            "the host page size is {} bytes; the portable profile needs 4 KiB or 16 KiB",
            host.page_size
        ));
    }
    if host.ipa_bits < 40 {
        why.push(format!(
            "KVM offers a {}-bit guest physical address space; the baseline has 40 bits",
            host.ipa_bits
        ));
    }
    let find = |list: &[(&'static str, u64)], name: &str| {
        list.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    };
    for (name, value) in BASELINE {
        let Some(have) = find(&host.id_regs, name) else {
            why.push(format!("{name} cannot be read on this host"));
            continue;
        };
        if name == "MIDR_EL1" {
            if have != value {
                why.push(format!(
                    "MIDR_EL1 is {have:#x} here and KVM cannot change it; the baseline is \
                     {value:#x} (Cortex-A76 r4p1)"
                ));
            }
            continue;
        }
        // KVM takes no raise at all.
        why.extend(excess(name, value, have, &[]));
        let Some(mask) = host.writable.as_deref().and_then(|m| find(m, name)) else {
            continue;
        };
        for shift in (0..64).step_by(4) {
            let (b, h) = ((value >> shift) & 0xf, (have >> shift) & 0xf);
            if b != h && (mask >> shift) & 0xf != 0xf {
                why.push(format!(
                    "{name}[{}:{shift}] is {h:#x} here and must read {b:#x}, but KVM does not \
                     let that field be written",
                    shift + 3
                ));
            }
        }
    }
    why
}

/// SMCCC and PSCI function IDs and return values the portable firmware
/// answers.
pub mod fw {
    pub const SMCCC_VERSION: u32 = 0x8000_0000;
    pub const SMCCC_ARCH_FEATURES: u32 = 0x8000_0001;
    pub const SMCCC_ARCH_WORKAROUND_1: u32 = 0x8000_8000;
    pub const SMCCC_ARCH_WORKAROUND_2: u32 = 0x8000_7fff;
    pub const SMCCC_ARCH_WORKAROUND_3: u32 = 0x8000_3fff;

    pub const PSCI_VERSION: u32 = 0x8400_0000;
    pub const CPU_SUSPEND_32: u32 = 0x8400_0001;
    pub const CPU_SUSPEND_64: u32 = 0xc400_0001;
    pub const CPU_OFF: u32 = 0x8400_0002;
    pub const CPU_ON_32: u32 = 0x8400_0003;
    pub const CPU_ON_64: u32 = 0xc400_0003;
    pub const AFFINITY_INFO_32: u32 = 0x8400_0004;
    pub const AFFINITY_INFO_64: u32 = 0xc400_0004;
    pub const MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
    pub const SYSTEM_OFF: u32 = 0x8400_0008;
    pub const SYSTEM_RESET: u32 = 0x8400_0009;
    pub const PSCI_FEATURES: u32 = 0x8400_000a;
    pub const SYSTEM_RESET2_32: u32 = 0x8400_0012;
    pub const SYSTEM_RESET2_64: u32 = 0xc400_0012;

    /// PSCI 1.1, and SMCCC 1.1.
    pub const VERSION_1_1: u64 = 0x0001_0001;
    pub const SUCCESS: u64 = 0;
    pub const NOT_SUPPORTED: u64 = (-1i64) as u64;
    pub const INVALID_PARAMETERS: u64 = (-2i64) as u64;
    pub const ALREADY_ON: u64 = (-4i64) as u64;
    /// `MIGRATE_INFO_TYPE`: no Trusted OS that needs migrating.
    pub const MIGRATE_NOT_REQUIRED: u64 = 2;
    /// `AFFINITY_INFO` states.
    pub const AFFINITY_ON: u64 = 0;
    pub const AFFINITY_OFF: u64 = 1;
    /// `SMCCC_ARCH_FEATURES` for a workaround the CPU does not need.
    pub const WORKAROUND_NOT_REQUIRED: u64 = 1;
    /// `SMCCC_RET_NOT_REQUIRED`: what KVM answers `SMCCC_ARCH_FEATURES`
    /// of workaround 2 with when the guest needs no firmware mitigation.
    pub const NOT_REQUIRED: u64 = (-2i64) as u64;
}

/// The functions `PSCI_FEATURES` reports as implemented.
///
/// Measured on rp2 (KVM, Linux 6.12.25, firmware bitmaps lowered to 0) with
/// `scratchpad/portable/p1/smccc_probe.c`: these answer 0 and every other
/// PSCI 0.2-1.1 function answers `NOT_SUPPORTED`, `SYSTEM_SUSPEND` included.
const PSCI_IMPLEMENTED: [u32; 15] = [
    fw::PSCI_VERSION,
    fw::CPU_SUSPEND_32,
    fw::CPU_SUSPEND_64,
    fw::CPU_OFF,
    fw::CPU_ON_32,
    fw::CPU_ON_64,
    fw::AFFINITY_INFO_32,
    fw::AFFINITY_INFO_64,
    fw::MIGRATE_INFO_TYPE,
    fw::SYSTEM_OFF,
    fw::SYSTEM_RESET,
    fw::PSCI_FEATURES,
    fw::SYSTEM_RESET2_32,
    fw::SYSTEM_RESET2_64,
    fw::SMCCC_VERSION,
];

/// Returns what `PSCI_FEATURES(function)` answers.
#[must_use]
pub fn psci_features(function: u32) -> u64 {
    if PSCI_IMPLEMENTED.contains(&function) {
        fw::SUCCESS
    } else {
        fw::NOT_SUPPORTED
    }
}

/// Returns what `SMCCC_ARCH_FEATURES(function)` answers.
///
/// On the Pi, KVM answers that the Cortex-A76 does not need workaround 1
/// (Spectre v2), that workaround 2 (SSB) is not required and that
/// workaround 3 (Spectre-BHB) is available. Every other function is not
/// supported, `SMCCC_ARCH_SOC_ID` included.
///
/// Workaround 2's answer depends on the guest's `ID_AA64PFR1_EL1`: KVM
/// answers `NOT_SUPPORTED` while SSBS is visible, and `NOT_REQUIRED` (-2)
/// once the baseline hides it, because it then keeps the guest mitigated
/// itself. A Linux guest reads `NOT_REQUIRED` as not affected by Spectre v4.
/// hvi gives that answer on the Mac too, so that a guest reads the same
/// mitigation state wherever it boots. On the Mac nothing backs the answer:
/// a guest there was unmitigated before, when it read `NOT_SUPPORTED` and
/// called itself vulnerable, and is now.
#[must_use]
pub fn smccc_arch_features(function: u32) -> u64 {
    match function {
        fw::SMCCC_ARCH_WORKAROUND_1 => fw::WORKAROUND_NOT_REQUIRED,
        fw::SMCCC_ARCH_WORKAROUND_2 => fw::NOT_REQUIRED,
        fw::SMCCC_ARCH_WORKAROUND_3 => fw::SUCCESS,
        _ => fw::NOT_SUPPORTED,
    }
}

/// Checks that the guest counter KVM reports (`KVM_REG_ARM_TIMER_CNT`),
/// `guest`, lies within hvi's reads before and after it, `[before, after]`,
/// widened by `slack` ticks on each side.
///
/// # Errors
///
/// Errors naming both values when it does not.
pub fn check_guest_counter(guest: u64, before: u64, after: u64, slack: u64) -> Result<(), String> {
    if (before.saturating_sub(slack)..=after.saturating_add(slack)).contains(&guest) {
        Ok(())
    } else {
        Err(format!(
            "KVM_REG_ARM_TIMER_CNT reads {guest}, and hvi's view of the guest counter \
             around that read is [{before}, {after}] (slack {slack} ticks)"
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// The answers a KVM guest on rp2 read, from `smccc_probe.out`: the
    /// "LOWERED" section, and for workaround 2 the section that also sets
    /// `ID_AA64PFR1_EL1` to the baseline's 0.
    #[test]
    fn firmware_answers_match_the_pi() {
        assert_eq!(smccc_arch_features(0x8000_8000), 1);
        assert_eq!(smccc_arch_features(0x8000_7fff), 0xffff_ffff_ffff_fffe);
        assert_eq!(smccc_arch_features(0x8000_3fff), 0);
        for f in [0x8000_0000, 0x8000_0001, 0x8000_0002] {
            assert_eq!(smccc_arch_features(f), u64::MAX, "{f:#x}");
        }
        for f in [
            0x8400_0000,
            0xc400_0001,
            0x8400_0001,
            0x8400_0002,
            0xc400_0003,
            0x8400_0003,
            0xc400_0004,
            0x8400_0004,
            0x8400_0006,
            0x8400_0008,
            0x8400_0009,
            0x8400_000a,
            0xc400_0012,
            0x8400_0012,
            0x8000_0000,
        ] {
            assert_eq!(psci_features(f), 0, "{f:#x}");
        }
        for f in [
            0xc400_000e,
            0x8400_000e,
            0xc400_0005,
            0xc400_0007,
            0x8400_000b,
            0xc400_000c,
            0xc400_000d,
            0x8400_000f,
            0xc400_0010,
            0xc400_0011,
            0x8400_0013,
            0x8000_0001,
            0x8000_8000,
            0x8400_1234,
        ] {
            assert_eq!(psci_features(f), u64::MAX, "{f:#x}");
        }
    }

    #[test]
    fn kernel_arguments_come_before_the_command_line() {
        assert_eq!(cmdline(""), KERNEL_ARGS);
        assert_eq!(
            cmdline("console=ttyAMA0"),
            format!("{KERNEL_ARGS} console=ttyAMA0")
        );
        // Everything after `--` is init's, so the arguments must precede it.
        for line in ["console=ttyAMA0 -- foo", "console=ttyAMA0 --", "-- foo"] {
            let full = cmdline(line);
            let dashes = full.split_whitespace().position(|t| t == "--").unwrap();
            let nomte = full
                .split_whitespace()
                .position(|t| t == "arm64.nomte")
                .unwrap();
            assert!(nomte < dashes, "{full}");
            assert!(full.ends_with(line), "{full}");
        }
    }

    /// The default guest ID registers of an Apple M5 Pro under
    /// Hypervisor.framework without hv_gic (P0 report hvf.md, section 2).
    const M5_PRO: [(&str, u64); 11] = [
        ("ID_AA64PFR0_EL1", 0x1101_0000_1011_0011),
        ("ID_AA64PFR1_EL1", 0x0000_0002_0200_0001),
        ("ID_AA64ZFR0_EL1", 0x0000_1000_0120_0002),
        ("ID_AA64SMFR0_EL1", 0x02f1_5cff_0000_0000),
        ("ID_AA64ISAR0_EL1", 0x0221_1001_1021_2120),
        ("ID_AA64ISAR1_EL1", 0x0000_2211_1021_1502),
        ("ID_AA64MMFR0_EL1", 0x0000_1000_0f10_0022),
        ("ID_AA64MMFR1_EL1", 0x0000_1000_1131_2000),
        ("ID_AA64MMFR2_EL1", 0x1001_0011_0200_1011),
        ("ID_AA64DFR0_EL1", 0x1030_5006),
        ("ID_AA64DFR1_EL1", 0),
    ];

    fn baseline(name: &str) -> u64 {
        BASELINE.iter().find(|(n, _)| *n == name).unwrap().1
    }

    #[test]
    fn an_m5_pro_backs_the_baseline() {
        for (name, host) in M5_PRO {
            assert_eq!(
                excess_fields(name, baseline(name), host),
                Vec::<String>::new(),
                "{name}"
            );
        }
        // VMIDBits and VH are the raises let through.
        assert_eq!(baseline("ID_AA64MMFR1_EL1") & 0xff0, 0x120);
    }

    #[test]
    fn a_host_without_a_baseline_feature_is_refused() {
        // No RAS (PFR0[31:28]).
        let pfr0 = 0x1101_0000_0011_0011;
        assert_eq!(
            excess_fields("ID_AA64PFR0_EL1", baseline("ID_AA64PFR0_EL1"), pfr0),
            vec!["ID_AA64PFR0_EL1[31:28] is 0x1 in the baseline but 0x0 on this host"]
        );
        // No floating point: FP is signed, 0xf is absent.
        let pfr0 = 0x1101_0000_101f_0011;
        assert_eq!(
            excess_fields("ID_AA64PFR0_EL1", baseline("ID_AA64PFR0_EL1"), pfr0).len(),
            1
        );
        // No DotProd or RDM.
        let isar0 = 0x0221_0001_0021_2120;
        assert_eq!(
            excess_fields("ID_AA64ISAR0_EL1", baseline("ID_AA64ISAR0_EL1"), isar0).len(),
            2
        );
    }

    #[test]
    fn signed_fields_compare_as_signed() {
        // TGran64 absent (0xf) in the baseline is never more than a host
        // with 64K pages (0).
        let mmfr0 = 0x0000_0000_0010_0022;
        assert!(excess_fields("ID_AA64MMFR0_EL1", baseline("ID_AA64MMFR0_EL1"), mmfr0).is_empty());
        // TGran4 present (0) is more than a host without 4K pages (0xf).
        let mmfr0 = 0x0000_0000_ff10_0022;
        assert_eq!(
            excess_fields("ID_AA64MMFR0_EL1", baseline("ID_AA64MMFR0_EL1"), mmfr0),
            vec!["ID_AA64MMFR0_EL1[31:28] is 0x0 in the baseline but 0xf on this host"]
        );
    }

    #[test]
    fn a_raise_outside_the_allowed_ones_is_refused() {
        // A baseline that claimed SVE (PFR0[35:32]) on an M5 Pro.
        let raised = baseline("ID_AA64PFR0_EL1") | (1 << 32);
        assert_eq!(
            excess_fields("ID_AA64PFR0_EL1", raised, M5_PRO[0].1),
            vec!["ID_AA64PFR0_EL1[35:32] is 0x1 in the baseline but 0x0 on this host"]
        );
        // VMIDBits is let through only in MMFR1.
        assert_eq!(excess_fields("ID_AA64MMFR2_EL1", 0x20, 0).len(), 1);
    }

    /// What KVM on rp2 (Raspberry Pi 5, Linux 6.12.25) gives a new guest and
    /// lets userspace write, from the P0 probe (`probe.out`).
    fn pi5() -> KvmHost {
        KvmHost {
            vgic_v2: true,
            page_size: 0x4000,
            ipa_bits: 40,
            id_regs: vec![
                ("MIDR_EL1", 0x414f_d0b1),
                ("ID_AA64PFR0_EL1", 0x1100_0000_1011_1112),
                ("ID_AA64PFR1_EL1", 0x10),
                ("ID_AA64ZFR0_EL1", 0),
                ("ID_AA64SMFR0_EL1", 0),
                ("ID_AA64ISAR0_EL1", 0x0000_1000_1021_1120),
                ("ID_AA64ISAR1_EL1", 0x0010_0001),
                ("ID_AA64MMFR0_EL1", 0x0010_1122),
                ("ID_AA64MMFR1_EL1", 0x1021_2122),
                ("ID_AA64MMFR2_EL1", 0x1011),
                ("ID_AA64DFR0_EL1", 0x1030_5008),
                ("ID_AA64DFR1_EL1", 0),
            ],
            writable: Some(vec![
                ("MIDR_EL1", 0),
                ("ID_AA64PFR0_EL1", 0xffff_00f0_0f00_ffff),
                ("ID_AA64PFR1_EL1", 0x0000_000f_0000_00ff),
                ("ID_AA64ZFR0_EL1", 0x0ff0_ff0f_0fff_00ff),
                ("ID_AA64SMFR0_EL1", 0),
                ("ID_AA64ISAR0_EL1", 0xffff_ffff_ffff_fff0),
                ("ID_AA64ISAR1_EL1", 0xffff_ffff_00ff_f00f),
                ("ID_AA64MMFR0_EL1", 0xff00_f000_ffff_ff0f),
                ("ID_AA64MMFR1_EL1", 0xffff_f0f0_0fff_f00f),
                ("ID_AA64MMFR2_EL1", 0xf0ff_000f_f00f_ffff),
                ("ID_AA64DFR0_EL1", 0x0000_00f0_00f0_0f0f),
                ("ID_AA64DFR1_EL1", 0),
            ]),
        }
    }

    #[test]
    fn a_pi5_presents_the_portable_machine() {
        assert_eq!(kvm_host_problems(&pi5()), Vec::<String>::new());
        // Without the masks, the comparison alone decides.
        let mut no_masks = pi5();
        no_masks.writable = None;
        assert_eq!(kvm_host_problems(&no_masks), Vec::<String>::new());
    }

    #[test]
    fn a_kvm_host_that_cannot_present_it_is_named() {
        let mut host = pi5();
        host.vgic_v2 = false;
        host.page_size = 0x1_0000;
        host.ipa_bits = 36;
        let why = kvm_host_problems(&host);
        assert_eq!(why.len(), 3, "{why:?}");
        assert!(why[0].contains("vGICv2"));
        assert!(why[1].contains("65536"));
        assert!(why[2].contains("36-bit"));
        // A 4 KiB host is fine.
        host = pi5();
        host.page_size = 0x1000;
        assert!(kvm_host_problems(&host).is_empty());

        // Another CPU: MIDR cannot be changed.
        let mut a72 = pi5();
        a72.id_regs[0].1 = 0x410f_d083;
        assert!(kvm_host_problems(&a72)[0].starts_with("MIDR_EL1 is 0x410fd083"));

        // A host without DotProd cannot be raised to it.
        let mut no_dp = pi5();
        no_dp.id_regs[5].1 = 0x0000_0000_1021_1120;
        assert_eq!(
            kvm_host_problems(&no_dp),
            vec!["ID_AA64ISAR0_EL1[47:44] is 0x1 in the baseline but 0x0 on this host"]
        );

        // KVM takes no raise, not even the two hvf makes: a host with
        // VMIDBits 0 is refused.
        let mut low_vmid = pi5();
        low_vmid.id_regs[8].1 = 0x1021_2102;
        let why = kvm_host_problems(&low_vmid);
        assert_eq!(
            why[0],
            "ID_AA64MMFR1_EL1[7:4] is 0x2 in the baseline but 0x0 on this host"
        );

        // A field that must be lowered but is fixed: RAS 2 on a host whose
        // mask keeps RAS read-only.
        let mut ras2 = pi5();
        ras2.id_regs[1].1 = 0x1100_0000_2011_1112;
        assert_eq!(
            kvm_host_problems(&ras2),
            vec![
                "ID_AA64PFR0_EL1[31:28] is 0x2 here and must read 0x1, but KVM does not let \
                 that field be written"
            ]
        );
    }

    /// The baseline keeps the GIC system-register interface off, which is
    /// what makes the guest use the memory-mapped GICv2.
    #[test]
    fn the_baseline_hides_the_gic_system_registers() {
        let pfr0 = BASELINE
            .iter()
            .find(|(name, _)| *name == "ID_AA64PFR0_EL1")
            .map(|(_, v)| *v)
            .unwrap();
        assert_eq!((pfr0 >> 24) & 0xf, 0);
    }

    #[test]
    fn a_guest_counter_outside_hvis_view_is_refused() {
        assert!(check_guest_counter(92, 52, 99, 54).is_ok());
        // The slack covers an ioctl's worth of skew either side.
        assert!(check_guest_counter(0, 52, 99, 54).is_ok());
        assert!(check_guest_counter(153, 52, 99, 54).is_ok());
        let e = check_guest_counter(154, 52, 99, 54).unwrap_err();
        assert!(e.contains("154") && e.contains("[52, 99]"), "{e}");
        // A counter in another domain, as on a host where the offset did
        // not take.
        let e = check_guest_counter(3_000_000_000, 52, 99, 54).unwrap_err();
        assert!(e.contains("3000000000"), "{e}");
        assert!(check_guest_counter(5, 100, 200, 54).is_err());
    }
}

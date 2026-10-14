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
//! arguments and the firmware's answers.
//!
//! The values come from measurements on a Raspberry Pi 5 (KVM, Linux
//! 6.12.25) and an Apple M5 Pro (Hypervisor.framework, macOS 26.7). See
//! `docs/portable-profile.md` for the contract and where each number comes
//! from.

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

/// `DCZID_EL0`, which no backend can set. Both hosts report 64-byte
/// `DC ZVA` blocks.
pub const DCZID_EL0: u64 = 0x4;

/// Kernel arguments a portable boot appends, so the guest stays off the
/// features the baseline already hides even if a register slipped through.
pub const KERNEL_ARGS: &str = "arm64.nopauth arm64.nobti arm64.nosve arm64.nosme arm64.nomte";

/// Returns `cmdline` with [`KERNEL_ARGS`] appended.
#[must_use]
pub fn cmdline(cmdline: &str) -> String {
    if cmdline.is_empty() {
        KERNEL_ARGS.to_string()
    } else {
        format!("{cmdline} {KERNEL_ARGS}")
    }
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
/// (Spectre v2), that workaround 2 (SSB) is not available and that
/// workaround 3 (Spectre-BHB) is. Every other function is not supported,
/// `SMCCC_ARCH_SOC_ID` included.
#[must_use]
pub fn smccc_arch_features(function: u32) -> u64 {
    match function {
        fw::SMCCC_ARCH_WORKAROUND_1 => fw::WORKAROUND_NOT_REQUIRED,
        fw::SMCCC_ARCH_WORKAROUND_3 => fw::SUCCESS,
        _ => fw::NOT_SUPPORTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The answers a KVM guest on rp2 read, from `smccc_probe.out`
    /// ("LOWERED" section).
    #[test]
    fn firmware_answers_match_the_pi() {
        assert_eq!(smccc_arch_features(0x8000_8000), 1);
        assert_eq!(smccc_arch_features(0x8000_7fff), u64::MAX);
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
    fn kernel_arguments_are_appended() {
        assert_eq!(cmdline(""), KERNEL_ARGS);
        assert_eq!(
            cmdline("console=ttyAMA0"),
            format!("console=ttyAMA0 {KERNEL_ARGS}")
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
}

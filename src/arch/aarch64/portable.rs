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
//! that does not depend on the hypervisor: the CPU baseline and the kernel
//! arguments.
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

#[cfg(test)]
mod tests {
    use super::*;

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

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

//! What each arm64 KVM register id is to a checkpoint.
//!
//! `KVM_GET_REG_LIST` names every register of a KVM vCPU by a 64-bit id.
//! [`classify`] puts each id in one of four classes, and the KVM export and
//! import do with it what its class says:
//!
//! - **shared**: the register has a canonical name in `cpu.json` (a general or
//!   SIMD register, or a system register of
//!   [`AARCH64_SYSREGS`](crate::checkpoint::cpu::AARCH64_SYSREGS)). The export
//!   reads it under that name and the import writes it from that name,
//!   whichever backend wrote the state. `MPIDR_EL1` is compared, not written,
//!   as on HVF.
//! - **set-by-baseline**: the machine, not the vCPU state, gives the value: an
//!   ID register the profile's baseline sets or the profile compares, the
//!   counter the restore's counter offset sets, or a register of a feature the
//!   baseline hides from the guest (AArch32, `FEAT_TCR2`, `FEAT_S1PIE`).
//!   Neither side carries it.
//! - **checked-equal-on-import**: a register only KVM has whose value a guest
//!   keeps fixed, and the firmware registers. The export records it (`fixed`
//!   and `firmware` in `cpu.json`) and the import compares the destination's
//!   value with the recorded one, or with the value a guest on HVF sees when
//!   the state came from HVF, and refuses a difference.
//! - **refused**: an id hvi has no rule for. A vCPU that lists one cannot be
//!   checkpointed, and a host whose vCPUs list one cannot restore.
//!
//! The rules were measured on rp2 (Raspberry Pi 5, Linux 6.12.25); the
//! test fixture `testdata/kvm-reg-list-rp2.txt` holds that list, and a test
//! checks that no id of it is refused. Ids are built and decoded here, as
//! the kernel's `ARM64_SYS_REG` and `KVM_REG_ARM_CORE_REG` build them, so
//! this compiles and is tested on every host.

use crate::checkpoint::cpu::{sysreg_encoding, sysreg_named, AARCH64_SIMD_REGS};

/// `KVM_REG_ARM64`.
const ARM64: u64 = 0x6000_0000_0000_0000;
/// `KVM_REG_SIZE_U32`.
const SIZE_U32: u64 = 0x0020_0000_0000_0000;
/// `KVM_REG_SIZE_U64`.
const SIZE_U64: u64 = 0x0030_0000_0000_0000;
/// `KVM_REG_SIZE_U128`.
const SIZE_U128: u64 = 0x0040_0000_0000_0000;
/// The coprocessor field of an id, `KVM_REG_ARM_COPROC_MASK`.
const COPROC_MASK: u64 = 0x0000_0000_0fff_0000;
/// `KVM_REG_ARM_CORE`.
const CORE: u64 = 0x0010 << 16;
/// `KVM_REG_ARM_DEMUX`, `CCSIDR_EL1` by cache level.
const DEMUX: u64 = 0x0011 << 16;
/// `KVM_REG_ARM64_SYSREG`.
const SYSREG: u64 = 0x0013 << 16;
/// `KVM_REG_ARM_FW`.
const FW: u64 = 0x0014 << 16;
/// `KVM_REG_ARM_FW_FEAT_BMAP`.
const FW_FEAT_BMAP: u64 = 0x0016 << 16;

/// Returns the `KVM_GET_ONE_REG` id of the 64-bit system register with
/// encoding `[op0, op1, CRn, CRm, op2]`.
#[must_use]
pub const fn sysreg_id(enc: [u8; 5]) -> u64 {
    ARM64
        | SIZE_U64
        | SYSREG
        | ((enc[0] as u64) << 14)
        | ((enc[1] as u64) << 11)
        | ((enc[2] as u64) << 7)
        | ((enc[3] as u64) << 3)
        | (enc[4] as u64)
}

/// Returns the encoding of a system register id.
#[must_use]
pub const fn sysreg_enc(id: u64) -> [u8; 5] {
    [
        ((id >> 14) & 3) as u8,
        ((id >> 11) & 7) as u8,
        ((id >> 7) & 0xf) as u8,
        ((id >> 3) & 0xf) as u8,
        (id & 7) as u8,
    ]
}

/// Returns the id of the core register at 32-bit word `word` of
/// `struct kvm_regs`, of `size`.
const fn core_id(size: u64, word: u64) -> u64 {
    ARM64 | size | CORE | word
}

/// `KVM_REG_ARM_TIMER_CTL`, the virtual timer's `CNTV_CTL_EL0`.
pub const TIMER_CTL: u64 = sysreg_id([3, 3, 14, 3, 1]);
/// `KVM_REG_ARM_TIMER_CVAL`: `CNTV_CVAL_EL0`, under the encoding of
/// `CNTVCT_EL0`, which the UAPI swapped by mistake and has kept.
pub const TIMER_CVAL: u64 = sysreg_id([3, 3, 14, 0, 2]);
/// `KVM_REG_ARM_TIMER_CNT`: the guest's virtual counter, under the encoding
/// of `CNTV_CVAL_EL0`.
pub const TIMER_CNT: u64 = sysreg_id([3, 3, 14, 3, 2]);
/// `KVM_REG_ARM_PTIMER_CNT`, the guest's physical counter.
pub const PTIMER_CNT: u64 = sysreg_id([3, 3, 14, 0, 1]);

/// The general register `x0`..`x30` of index `n`.
#[must_use]
pub const fn x_id(n: u8) -> u64 {
    core_id(SIZE_U64, 2 * n as u64)
}

/// The SIMD register `q0`..`q31` of index `n`.
#[must_use]
pub const fn q_id(n: u8) -> u64 {
    core_id(SIZE_U128, 0x54 + 4 * n as u64)
}

/// The core registers with a name of their own, by id: the ones `regs`
/// holds, and `ELR_EL1` and `SPSR_EL1`, which `sysregs` holds.
const NAMED_CORE: [(u64, Slot); 8] = [
    (core_id(SIZE_U64, 0x3e), Slot::Reg("sp_el0")),
    (core_id(SIZE_U64, 0x40), Slot::Reg("pc")),
    (core_id(SIZE_U64, 0x42), Slot::Reg("pstate")),
    (core_id(SIZE_U64, 0x44), Slot::Reg("sp_el1")),
    (core_id(SIZE_U64, 0x46), Slot::Sys("ELR_EL1")),
    (core_id(SIZE_U64, 0x48), Slot::Sys("SPSR_EL1")),
    (core_id(SIZE_U32, 0xd4), Slot::Reg("fpsr")),
    (core_id(SIZE_U32, 0xd5), Slot::Reg("fpcr")),
];

/// Where a shared register lives in `cpu.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// `regs`, `x0`..`x30` by index.
    X(u8),
    /// `regs`, by name.
    Reg(&'static str),
    /// `simd`, `q0`..`q31` by index.
    Q(u8),
    /// `sysregs`, by name.
    Sys(&'static str),
}

/// How a checked register's value is compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// A firmware register, under `firmware` by name, compared by what the
    /// guest sees of it (see [`firmware_view`]).
    Firmware(&'static str),
    /// A register only KVM has, under `fixed` by name: the bits of `mask`
    /// must be equal, and a state from HVF, which cannot carry the
    /// register, must hold `hvf` in them, the value a guest on HVF sees.
    Fixed {
        /// The name, the architectural one where there is one.
        name: &'static str,
        /// The bits that count.
        mask: u64,
        /// The value a guest on HVF sees.
        hvf: u64,
    },
}

impl Check {
    /// Returns the name the register has in `cpu.json`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Firmware(name) | Self::Fixed { name, .. } => name,
        }
    }
}

/// What a KVM register id is to a checkpoint. See the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Carried by its canonical name.
    Shared(Slot),
    /// Given by the machine, with why.
    SetByBaseline(&'static str),
    /// Recorded, and compared on import.
    CheckedEqual(Check),
    /// No rule: refused, with why.
    Refused(&'static str),
}

impl Class {
    /// Returns the class's name as the documentation's table gives it.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Shared(_) => "shared",
            Self::SetByBaseline(_) => "set-by-baseline",
            Self::CheckedEqual(_) => "checked-equal-on-import",
            Self::Refused(_) => "refused",
        }
    }
}

/// Why an AArch32 register is not carried.
const AARCH32: &str = "AArch32 state: the baseline offers AArch64 at EL0 and EL1 only";
/// Why an ID register is not carried.
const ID: &str = "an ID register: the baseline sets it, or the profile compares it";
/// Why a counter is not carried.
const COUNTER: &str = "the counter: the restore's counter offset sets it";

/// The firmware registers, by id, `KVM_REG_ARM_FW_REG(n)` and
/// `KVM_REG_ARM_FW_FEAT_BMAP_REG(n)`.
pub const FIRMWARE: [(u64, &str); 7] = [
    (ARM64 | SIZE_U64 | FW, "PSCI_VERSION"),
    (ARM64 | SIZE_U64 | FW | 1, "SMCCC_ARCH_WORKAROUND_1"),
    (ARM64 | SIZE_U64 | FW | 2, "SMCCC_ARCH_WORKAROUND_2"),
    (ARM64 | SIZE_U64 | FW | 3, "SMCCC_ARCH_WORKAROUND_3"),
    (ARM64 | SIZE_U64 | FW_FEAT_BMAP, "STD_BMAP"),
    (ARM64 | SIZE_U64 | FW_FEAT_BMAP | 1, "STD_HYP_BMAP"),
    (ARM64 | SIZE_U64 | FW_FEAT_BMAP | 2, "VENDOR_HYP_BMAP"),
];

/// The firmware registers' values for a portable guest on HVF, whose PSCI
/// and SMCCC answers mirror KVM's on the Pi (`portable::smccc_arch_features`):
/// PSCI 1.1, workaround 1 not required (2), workaround 2 not supported (0),
/// workaround 3 available (1), and no firmware services.
pub const PORTABLE_HVF_FIRMWARE: [(&str, u64); 7] = [
    ("PSCI_VERSION", 0x1_0001),
    ("SMCCC_ARCH_WORKAROUND_1", 2),
    ("SMCCC_ARCH_WORKAROUND_2", 0),
    ("SMCCC_ARCH_WORKAROUND_3", 1),
    ("STD_BMAP", 0),
    ("STD_HYP_BMAP", 0),
    ("VENDOR_HYP_BMAP", 0),
];

/// Returns a firmware register's value as the guest sees it, so that two
/// that look the same to a guest compare equal.
///
/// Workaround 2's register reads 0 (not available) on a native vCPU on the
/// Pi and 3 (not required) once the portable baseline is written (measured
/// on rp2); either way a guest never calls the workaround, so both read as
/// "not called" here.
#[must_use]
pub fn firmware_view(name: &str, value: u64) -> u64 {
    match (name, value) {
        ("SMCCC_ARCH_WORKAROUND_2", 0 | 3) => 0,
        _ => value,
    }
}

/// The registers only KVM lists that a guest cannot change, or keeps at one
/// value, by encoding. Measured on rp2; see the module documentation.
const KVM_ONLY: [([u8; 5], Class); 15] = [
    (
        [2, 0, 1, 1, 4],
        Class::CheckedEqual(Check::Fixed {
            name: "OSLSR_EL1",
            mask: u64::MAX,
            // The OS lock is implemented and clear: Linux clears it at boot,
            // and KVM resets it so.
            hvf: 0x8,
        }),
    ),
    (
        [3, 0, 12, 1, 1],
        Class::CheckedEqual(Check::Fixed {
            name: "DISR_EL1",
            mask: u64::MAX,
            // Linux clears it when it enables RAS.
            hvf: 0,
        }),
    ),
    (
        [3, 3, 14, 2, 1],
        Class::CheckedEqual(Check::Fixed {
            name: "CNTP_CTL_EL0",
            // ENABLE and IMASK; ISTATUS follows the counter. hvi's HVF guest
            // reads the physical timer as zero.
            mask: 0b11,
            hvf: 0,
        }),
    ),
    (
        [3, 3, 14, 2, 2],
        Class::CheckedEqual(Check::Fixed {
            name: "CNTP_CVAL_EL0",
            mask: u64::MAX,
            hvf: 0,
        }),
    ),
    ([3, 3, 14, 3, 2], Class::SetByBaseline(COUNTER)),
    ([3, 3, 14, 0, 1], Class::SetByBaseline(COUNTER)),
    (
        [3, 0, 2, 0, 3],
        Class::SetByBaseline("TCR2_EL1: FEAT_TCR2, which ID_AA64MMFR3_EL1 hides"),
    ),
    (
        [3, 0, 10, 2, 2],
        Class::SetByBaseline("PIRE0_EL1: FEAT_S1PIE, which ID_AA64MMFR3_EL1 hides"),
    ),
    (
        [3, 0, 10, 2, 3],
        Class::SetByBaseline("PIR_EL1: FEAT_S1PIE, which ID_AA64MMFR3_EL1 hides"),
    ),
    ([3, 4, 3, 0, 0], Class::SetByBaseline(AARCH32)),
    ([3, 4, 5, 0, 1], Class::SetByBaseline(AARCH32)),
    ([3, 4, 5, 3, 0], Class::SetByBaseline(AARCH32)),
    ([2, 4, 0, 7, 0], Class::SetByBaseline(AARCH32)),
    (
        [3, 1, 0, 0, 1],
        Class::SetByBaseline("CLIDR_EL1: the host's caches, which the profile compares"),
    ),
    (
        [3, 1, 0, 0, 7],
        Class::SetByBaseline("AIDR_EL1: the host's identification"),
    ),
];

/// Returns the class of the KVM register `id`.
#[must_use]
pub fn classify(id: u64) -> Class {
    if id & ARM64 != ARM64 {
        return Class::Refused("not an arm64 register");
    }
    match id & COPROC_MASK {
        CORE => classify_core(id),
        DEMUX => Class::SetByBaseline("CCSIDR_EL1: the host's cache geometry"),
        FW | FW_FEAT_BMAP => FIRMWARE.iter().find(|(known, _)| *known == id).map_or(
            Class::Refused("a firmware register hvi has no rule for"),
            |(_, name)| Class::CheckedEqual(Check::Firmware(name)),
        ),
        SYSREG if id & !(COPROC_MASK | 0xffff) == ARM64 | SIZE_U64 => classify_sysreg(id),
        _ => Class::Refused("a register class hvi has no rule for"),
    }
}

/// See [`classify`]; `id` is a core register.
fn classify_core(id: u64) -> Class {
    let word = id & 0xffff;
    let size = id & !(COPROC_MASK | 0xffff);
    if size == ARM64 | SIZE_U64 && word < 0x3e && word % 2 == 0 {
        return Class::Shared(Slot::X((word / 2) as u8));
    }
    if size == ARM64 | SIZE_U128 && (0x54..0x54 + 4 * AARCH64_SIMD_REGS as u64).contains(&word) {
        return if (word - 0x54) % 4 == 0 {
            Class::Shared(Slot::Q(((word - 0x54) / 4) as u8))
        } else {
            Class::Refused("not the start of a SIMD register")
        };
    }
    if let Some((_, slot)) = NAMED_CORE.iter().find(|(known, _)| *known == id) {
        return Class::Shared(*slot);
    }
    // spsr[1..5]: the AArch32 abort, undefined, IRQ and FIQ modes.
    if size == ARM64 | SIZE_U64 && matches!(word, 0x4a | 0x4c | 0x4e | 0x50) {
        return Class::SetByBaseline(AARCH32);
    }
    Class::Refused("a core register hvi has no rule for")
}

/// See [`classify`]; `id` is a 64-bit system register.
fn classify_sysreg(id: u64) -> Class {
    match id {
        TIMER_CVAL => return Class::Shared(Slot::Sys("CNTV_CVAL_EL0")),
        TIMER_CNT | PTIMER_CNT => return Class::SetByBaseline(COUNTER),
        _ => {}
    }
    let enc = sysreg_enc(id);
    if let Some(name) = sysreg_named(enc) {
        return Class::Shared(Slot::Sys(name));
    }
    if let Some((_, class)) = KVM_ONLY.iter().find(|(known, _)| *known == enc) {
        return *class;
    }
    match enc {
        // Op0 3, op1 0, CRn 0: MIDR, REVIDR and the feature ID registers.
        [3, 0, 0, _, _] => Class::SetByBaseline(ID),
        // CTR_EL0 and DCZID_EL0.
        [3, 3, 0, 0, 1 | 7] => Class::SetByBaseline(ID),
        _ => Class::Refused("a system register hvi has no rule for"),
    }
}

/// Returns the KVM id of the register `slot` names: a shared register's id
/// on KVM, or `None` for a system register of the canonical table that KVM
/// has no id for in this form.
#[must_use]
pub fn id_of(slot: Slot) -> Option<u64> {
    match slot {
        Slot::X(n) if n < 31 => Some(x_id(n)),
        Slot::Q(n) if (n as usize) < AARCH64_SIMD_REGS => Some(q_id(n)),
        Slot::X(_) | Slot::Q(_) => None,
        Slot::Reg(_) | Slot::Sys("ELR_EL1" | "SPSR_EL1") => NAMED_CORE
            .iter()
            .find(|(_, known)| *known == slot)
            .map(|(id, _)| *id),
        Slot::Sys("CNTV_CVAL_EL0") => Some(TIMER_CVAL),
        Slot::Sys(name) => sysreg_encoding(name).map(sysreg_id),
    }
}

/// Returns the width in bytes of register `id`'s value.
#[must_use]
pub fn size_of(id: u64) -> usize {
    1 << ((id >> 52) & 0xf)
}

/// The system registers of the canonical table a portable guest's KVM vCPU
/// does not have, because the baseline hides their feature: a state from
/// HVF may hold them, and a KVM restore drops them.
///
/// The pointer-authentication keys (`ID_AA64ISAR1_EL1` hides PAuth, and the
/// guest runs with `arm64.nopauth`), `SCXTNUM_EL0/1` (`ID_AA64PFR0_EL1.CSV2`
/// is 1) and SME's (`ID_AA64PFR1_EL1.SME` is 0, and `arm64.nosme`).
pub const HIDDEN_BY_PORTABLE: [&str; 15] = [
    "APIAKEYLO_EL1",
    "APIAKEYHI_EL1",
    "APIBKEYLO_EL1",
    "APIBKEYHI_EL1",
    "APDAKEYLO_EL1",
    "APDAKEYHI_EL1",
    "APDBKEYLO_EL1",
    "APDBKEYHI_EL1",
    "APGAKEYLO_EL1",
    "APGAKEYHI_EL1",
    "SCXTNUM_EL0",
    "SCXTNUM_EL1",
    "TPIDR2_EL0",
    "SMCR_EL1",
    "SMPRI_EL1",
];

/// Returns the checked register named `name`, as `fixed` names it.
#[must_use]
pub fn fixed_named(name: &str) -> Option<Check> {
    KVM_ONLY.iter().find_map(|(_, class)| match class {
        Class::CheckedEqual(check @ Check::Fixed { name: known, .. }) if *known == name => {
            Some(*check)
        }
        _ => None,
    })
}

/// Returns whether `name` is a firmware register of [`FIRMWARE`].
#[must_use]
pub fn is_firmware(name: &str) -> bool {
    FIRMWARE.iter().any(|(_, known)| *known == name)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::checkpoint::cpu::{aarch64_reg_names, AARCH64_SYSREGS, AARCH64_SYSREG_ENCODINGS};

    /// The fixture: every id rp2's KVM lists, with its value, for the
    /// native and the portable vCPU.
    pub(crate) fn fixture() -> Vec<(&'static str, u64, &'static str)> {
        include_str!("testdata/kvm-reg-list-rp2.txt")
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| {
                let mut f = l.split_whitespace();
                let profile = f.next().unwrap();
                let id = f.next().unwrap();
                let value = f.next().unwrap();
                (
                    profile,
                    u64::from_str_radix(id.trim_start_matches("0x"), 16).unwrap(),
                    value,
                )
            })
            .collect()
    }

    // The classification is complete for what the Pi lists: nothing of
    // either list is refused, and both lists are the same.
    #[test]
    fn every_id_rp2_lists_has_a_class() {
        let ids = fixture();
        let native: Vec<u64> = ids
            .iter()
            .filter(|r| r.0 == "native")
            .map(|r| r.1)
            .collect();
        let portable: Vec<u64> = ids
            .iter()
            .filter(|r| r.0 == "portable")
            .map(|r| r.1)
            .collect();
        assert_eq!(native.len(), 259);
        assert_eq!(native, portable);
        for id in &native {
            let class = classify(*id);
            assert!(
                !matches!(class, Class::Refused(_)),
                "{id:#018x} is {class:?}"
            );
        }
        let count = |label: &str| {
            native
                .iter()
                .filter(|id| classify(**id).label() == label)
                .count()
        };
        assert_eq!(
            (
                count("shared"),
                count("set-by-baseline"),
                count("checked-equal-on-import")
            ),
            (160, 88, 11)
        );
    }

    // Every general, SIMD and system register a KVM vCPU of the Pi has goes
    // to exactly the canonical name, and that name back to the id.
    #[test]
    fn shared_ids_and_names_round_trip() {
        let mut seen = std::collections::BTreeSet::new();
        for (_, id, _) in fixture().into_iter().filter(|r| r.0 == "native") {
            if let Class::Shared(slot) = classify(id) {
                assert_eq!(id_of(slot), Some(id), "{slot:?}");
                assert!(seen.insert(format!("{slot:?}")), "{slot:?} twice");
            }
        }
        // Every general register, every SIMD register, and every system
        // register but the ones the baseline hides on KVM.
        assert_eq!(
            seen.len(),
            aarch64_reg_names().len() + AARCH64_SIMD_REGS + 106 - 15
        );
        for (name, _) in AARCH64_SYSREGS {
            let slot = Slot::Sys(name);
            let listed = seen.contains(&format!("{slot:?}"));
            assert_eq!(listed, !HIDDEN_BY_PORTABLE.contains(&name), "{name}");
        }
    }

    #[test]
    fn the_encodings_are_the_canonical_names_in_order() {
        for ((name, _), (enc_name, enc)) in AARCH64_SYSREGS.iter().zip(AARCH64_SYSREG_ENCODINGS) {
            assert_eq!(name, &enc_name);
            assert_eq!(sysreg_named(enc), Some(*name));
            assert_eq!(sysreg_enc(sysreg_id(enc)), enc);
        }
    }

    // The ids hvi already spelled out by hand are the ones built here.
    #[test]
    fn known_ids_are_built_as_the_kernel_builds_them() {
        assert_eq!(id_of(Slot::Reg("pc")), Some(0x6030_0000_0010_0040));
        assert_eq!(id_of(Slot::Reg("sp_el0")), Some(0x6030_0000_0010_003e));
        assert_eq!(id_of(Slot::Reg("fpcr")), Some(0x6020_0000_0010_00d5));
        assert_eq!(id_of(Slot::Q(31)), Some(0x6040_0000_0010_00d0));
        assert_eq!(id_of(Slot::Sys("SCTLR_EL1")), Some(0x6030_0000_0013_c080));
        assert_eq!(TIMER_CTL, 0x6030_0000_0013_df19);
        assert_eq!(TIMER_CVAL, 0x6030_0000_0013_df02);
        assert_eq!(TIMER_CNT, 0x6030_0000_0013_df1a);
        assert_eq!(classify(TIMER_CNT), Class::SetByBaseline(COUNTER));
        assert_eq!(
            classify(TIMER_CVAL),
            Class::Shared(Slot::Sys("CNTV_CVAL_EL0"))
        );
        assert_eq!(
            classify(TIMER_CTL),
            Class::Shared(Slot::Sys("CNTV_CTL_EL0"))
        );
    }

    #[test]
    fn what_hvi_has_no_rule_for_is_refused() {
        // An SVE Z register, a PMU register, a size the class does not
        // have, and a firmware register past the known ones.
        for id in [
            0x6080_0000_0015_0000u64,
            sysreg_id([3, 3, 9, 12, 0]),
            0x6020_0000_0013_c080,
            ARM64 | SIZE_U64 | FW | 9,
            0x6030_0000_0010_0052,
        ] {
            assert!(matches!(classify(id), Class::Refused(_)), "{id:#x}");
        }
    }

    #[test]
    fn firmware_compares_by_what_the_guest_sees() {
        assert_eq!(
            firmware_view("SMCCC_ARCH_WORKAROUND_2", 0),
            firmware_view("SMCCC_ARCH_WORKAROUND_2", 3)
        );
        assert_ne!(
            firmware_view("SMCCC_ARCH_WORKAROUND_2", 0),
            firmware_view("SMCCC_ARCH_WORKAROUND_2", 1)
        );
        // The portable vCPU's measured values are the ones HVF mirrors.
        for (_, id, value) in fixture().into_iter().filter(|r| r.0 == "portable") {
            if let Class::CheckedEqual(Check::Firmware(name)) = classify(id) {
                let value = u64::from_str_radix(value, 16).unwrap();
                let hvf = PORTABLE_HVF_FIRMWARE
                    .iter()
                    .find(|(n, _)| *n == name)
                    .unwrap()
                    .1;
                assert_eq!(
                    firmware_view(name, value),
                    firmware_view(name, hvf),
                    "{name}"
                );
            }
        }
    }
}

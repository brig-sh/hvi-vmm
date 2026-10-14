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

//! `cpu.json`: the state of every vCPU, by register name.
//!
//! Each architecture has one canonical form, whichever backend wrote it, so a
//! reader never needs a hypervisor's own register numbering. Values are hex
//! strings by register name, as `"0x..."`. The arm64 form is
//! [`Aarch64Vcpu`], the x86-64 one [`X86Vcpu`].
//!
//! A vCPU writes its own state, on its own thread, at the point in its run
//! loop where it parks, since only that thread may read its registers on
//! either hypervisor. The control thread asks for it with a `Work` request
//! (see `Vcpus::request_export`).
//!
//! Both arm64 backends write the whole state: the general, SIMD and
//! floating-point registers, every system register of [`AARCH64_SYSREGS`]
//! the vCPU has, and the virtual timer's mask. KVM names its registers by
//! id, which `checkpoint::kvm_regs` maps to these names, and records beside
//! them its firmware registers, the few registers only it has, and any
//! pending SError. The x86-64 backend still writes only the register view
//! the plugin interface has, RIP and CR3. Such a state says
//! `"partial": true`, and a restore refuses it.

use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::checkpoint::platform::{IrqCpuState, PlatformState};
use crate::hypervisor::guest::SafepointVcpu;
use crate::plugin::{GuestArch, RegsView};

/// The [`CpuState`] format this build writes and reads.
pub const CPU_STATE_VERSION: u32 = 1;

/// The most vCPUs a `cpu.json` may describe.
pub const MAX_VCPUS: usize = 64;

/// A 64-bit register value, written as a `"0x..."` hex string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hex64(pub u64);

impl Serialize for Hex64 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:#x}", self.0))
    }
}

impl<'de> Deserialize<'de> for Hex64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let digits = text
            .strip_prefix("0x")
            .ok_or_else(|| serde::de::Error::custom(format!("{text:?} is not 0x-prefixed hex")))?;
        u64::from_str_radix(digits, 16)
            .map(Hex64)
            .map_err(|e| serde::de::Error::custom(format!("{text:?}: {e}")))
    }
}

/// Whether a vCPU runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Power {
    /// The vCPU has run and runs on after a restore.
    On,
    /// The guest has not brought the vCPU up.
    Off,
    /// The guest asked for the vCPU with PSCI `CPU_ON`, and its thread had not
    /// taken the request yet.
    PendingOn {
        /// The entry point the guest gave.
        entry: Hex64,
        /// The context argument the guest gave, for `x0`.
        ctx: Hex64,
    },
}

/// A vCPU's own part of the virtual timer, beside `CNTV_CTL_EL0` and
/// `CNTV_CVAL_EL0` in the system registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VcpuTimer {
    /// Whether the hypervisor holds the virtual timer's interrupt masked.
    pub vtimer_masked: bool,
}

/// Whether a restore needs a system register of [`AARCH64_SYSREGS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// A failed read fails the export, and a state without it is refused.
    Required,
    /// A register not every vCPU has: SME's and macOS 15.2's, which only
    /// some Macs have, and the pointer-authentication keys, which a KVM
    /// vCPU has only with PAuth, which hvi does not give it. A failed read
    /// lists it under `unavailable`, and a state may lack it.
    Optional,
}

/// Every arm64 system register `sysregs` may hold, by architectural name.
///
/// This is the EL1 and EL0 state a running Linux guest keeps in system
/// registers, apart from the ID registers, which the machine profile
/// compares instead, and the counter, which `platform.json` carries.
pub const AARCH64_SYSREGS: [(&str, Need); 106] = [
    ("SCTLR_EL1", Need::Required),
    ("ACTLR_EL1", Need::Required),
    ("CPACR_EL1", Need::Required),
    ("TTBR0_EL1", Need::Required),
    ("TTBR1_EL1", Need::Required),
    ("TCR_EL1", Need::Required),
    ("MAIR_EL1", Need::Required),
    ("AMAIR_EL1", Need::Required),
    ("VBAR_EL1", Need::Required),
    ("ELR_EL1", Need::Required),
    ("SPSR_EL1", Need::Required),
    ("ESR_EL1", Need::Required),
    ("FAR_EL1", Need::Required),
    ("PAR_EL1", Need::Required),
    ("AFSR0_EL1", Need::Required),
    ("AFSR1_EL1", Need::Required),
    ("CONTEXTIDR_EL1", Need::Required),
    ("TPIDR_EL0", Need::Required),
    ("TPIDRRO_EL0", Need::Required),
    ("TPIDR_EL1", Need::Required),
    ("CNTKCTL_EL1", Need::Required),
    ("CSSELR_EL1", Need::Required),
    ("CNTV_CTL_EL0", Need::Required),
    ("CNTV_CVAL_EL0", Need::Required),
    ("MDSCR_EL1", Need::Required),
    ("MDCCINT_EL1", Need::Required),
    ("APIAKEYLO_EL1", Need::Optional),
    ("APIAKEYHI_EL1", Need::Optional),
    ("APIBKEYLO_EL1", Need::Optional),
    ("APIBKEYHI_EL1", Need::Optional),
    ("APDAKEYLO_EL1", Need::Optional),
    ("APDAKEYHI_EL1", Need::Optional),
    ("APDBKEYLO_EL1", Need::Optional),
    ("APDBKEYHI_EL1", Need::Optional),
    ("APGAKEYLO_EL1", Need::Optional),
    ("APGAKEYHI_EL1", Need::Optional),
    ("MPIDR_EL1", Need::Required),
    ("SCXTNUM_EL0", Need::Optional),
    ("SCXTNUM_EL1", Need::Optional),
    ("TPIDR2_EL0", Need::Optional),
    ("SMCR_EL1", Need::Optional),
    ("SMPRI_EL1", Need::Optional),
    ("DBGBVR0_EL1", Need::Required),
    ("DBGBCR0_EL1", Need::Required),
    ("DBGWVR0_EL1", Need::Required),
    ("DBGWCR0_EL1", Need::Required),
    ("DBGBVR1_EL1", Need::Required),
    ("DBGBCR1_EL1", Need::Required),
    ("DBGWVR1_EL1", Need::Required),
    ("DBGWCR1_EL1", Need::Required),
    ("DBGBVR2_EL1", Need::Required),
    ("DBGBCR2_EL1", Need::Required),
    ("DBGWVR2_EL1", Need::Required),
    ("DBGWCR2_EL1", Need::Required),
    ("DBGBVR3_EL1", Need::Required),
    ("DBGBCR3_EL1", Need::Required),
    ("DBGWVR3_EL1", Need::Required),
    ("DBGWCR3_EL1", Need::Required),
    ("DBGBVR4_EL1", Need::Required),
    ("DBGBCR4_EL1", Need::Required),
    ("DBGWVR4_EL1", Need::Required),
    ("DBGWCR4_EL1", Need::Required),
    ("DBGBVR5_EL1", Need::Required),
    ("DBGBCR5_EL1", Need::Required),
    ("DBGWVR5_EL1", Need::Required),
    ("DBGWCR5_EL1", Need::Required),
    ("DBGBVR6_EL1", Need::Required),
    ("DBGBCR6_EL1", Need::Required),
    ("DBGWVR6_EL1", Need::Required),
    ("DBGWCR6_EL1", Need::Required),
    ("DBGBVR7_EL1", Need::Required),
    ("DBGBCR7_EL1", Need::Required),
    ("DBGWVR7_EL1", Need::Required),
    ("DBGWCR7_EL1", Need::Required),
    ("DBGBVR8_EL1", Need::Required),
    ("DBGBCR8_EL1", Need::Required),
    ("DBGWVR8_EL1", Need::Required),
    ("DBGWCR8_EL1", Need::Required),
    ("DBGBVR9_EL1", Need::Required),
    ("DBGBCR9_EL1", Need::Required),
    ("DBGWVR9_EL1", Need::Required),
    ("DBGWCR9_EL1", Need::Required),
    ("DBGBVR10_EL1", Need::Required),
    ("DBGBCR10_EL1", Need::Required),
    ("DBGWVR10_EL1", Need::Required),
    ("DBGWCR10_EL1", Need::Required),
    ("DBGBVR11_EL1", Need::Required),
    ("DBGBCR11_EL1", Need::Required),
    ("DBGWVR11_EL1", Need::Required),
    ("DBGWCR11_EL1", Need::Required),
    ("DBGBVR12_EL1", Need::Required),
    ("DBGBCR12_EL1", Need::Required),
    ("DBGWVR12_EL1", Need::Required),
    ("DBGWCR12_EL1", Need::Required),
    ("DBGBVR13_EL1", Need::Required),
    ("DBGBCR13_EL1", Need::Required),
    ("DBGWVR13_EL1", Need::Required),
    ("DBGWCR13_EL1", Need::Required),
    ("DBGBVR14_EL1", Need::Required),
    ("DBGBCR14_EL1", Need::Required),
    ("DBGWVR14_EL1", Need::Required),
    ("DBGWCR14_EL1", Need::Required),
    ("DBGBVR15_EL1", Need::Required),
    ("DBGBCR15_EL1", Need::Required),
    ("DBGWVR15_EL1", Need::Required),
    ("DBGWCR15_EL1", Need::Required),
];

/// The architectural encoding, `[op0, op1, CRn, CRm, op2]`, of every
/// system register of [`AARCH64_SYSREGS`], in its order.
///
/// This is where a canonical name meets a hypervisor's number on KVM, whose
/// `KVM_GET_ONE_REG` id of a system register is its encoding (see
/// `checkpoint::kvm_regs`). The one exception is KVM's virtual timer:
/// `KVM_REG_ARM_TIMER_CVAL` and `KVM_REG_ARM_TIMER_CNT` swap the encodings of
/// `CNTV_CVAL_EL0` and `CNTVCT_EL0`, which `kvm_regs` undoes.
pub const AARCH64_SYSREG_ENCODINGS: [(&str, [u8; 5]); 106] = [
    ("SCTLR_EL1", [3, 0, 1, 0, 0]),
    ("ACTLR_EL1", [3, 0, 1, 0, 1]),
    ("CPACR_EL1", [3, 0, 1, 0, 2]),
    ("TTBR0_EL1", [3, 0, 2, 0, 0]),
    ("TTBR1_EL1", [3, 0, 2, 0, 1]),
    ("TCR_EL1", [3, 0, 2, 0, 2]),
    ("MAIR_EL1", [3, 0, 10, 2, 0]),
    ("AMAIR_EL1", [3, 0, 10, 3, 0]),
    ("VBAR_EL1", [3, 0, 12, 0, 0]),
    ("ELR_EL1", [3, 0, 4, 0, 1]),
    ("SPSR_EL1", [3, 0, 4, 0, 0]),
    ("ESR_EL1", [3, 0, 5, 2, 0]),
    ("FAR_EL1", [3, 0, 6, 0, 0]),
    ("PAR_EL1", [3, 0, 7, 4, 0]),
    ("AFSR0_EL1", [3, 0, 5, 1, 0]),
    ("AFSR1_EL1", [3, 0, 5, 1, 1]),
    ("CONTEXTIDR_EL1", [3, 0, 13, 0, 1]),
    ("TPIDR_EL0", [3, 3, 13, 0, 2]),
    ("TPIDRRO_EL0", [3, 3, 13, 0, 3]),
    ("TPIDR_EL1", [3, 0, 13, 0, 4]),
    ("CNTKCTL_EL1", [3, 0, 14, 1, 0]),
    ("CSSELR_EL1", [3, 2, 0, 0, 0]),
    ("CNTV_CTL_EL0", [3, 3, 14, 3, 1]),
    ("CNTV_CVAL_EL0", [3, 3, 14, 3, 2]),
    ("MDSCR_EL1", [2, 0, 0, 2, 2]),
    ("MDCCINT_EL1", [2, 0, 0, 2, 0]),
    ("APIAKEYLO_EL1", [3, 0, 2, 1, 0]),
    ("APIAKEYHI_EL1", [3, 0, 2, 1, 1]),
    ("APIBKEYLO_EL1", [3, 0, 2, 1, 2]),
    ("APIBKEYHI_EL1", [3, 0, 2, 1, 3]),
    ("APDAKEYLO_EL1", [3, 0, 2, 2, 0]),
    ("APDAKEYHI_EL1", [3, 0, 2, 2, 1]),
    ("APDBKEYLO_EL1", [3, 0, 2, 2, 2]),
    ("APDBKEYHI_EL1", [3, 0, 2, 2, 3]),
    ("APGAKEYLO_EL1", [3, 0, 2, 3, 0]),
    ("APGAKEYHI_EL1", [3, 0, 2, 3, 1]),
    ("MPIDR_EL1", [3, 0, 0, 0, 5]),
    ("SCXTNUM_EL0", [3, 3, 13, 0, 7]),
    ("SCXTNUM_EL1", [3, 0, 13, 0, 7]),
    ("TPIDR2_EL0", [3, 3, 13, 0, 5]),
    ("SMCR_EL1", [3, 0, 1, 2, 6]),
    ("SMPRI_EL1", [3, 0, 1, 2, 4]),
    ("DBGBVR0_EL1", [2, 0, 0, 0, 4]),
    ("DBGBCR0_EL1", [2, 0, 0, 0, 5]),
    ("DBGWVR0_EL1", [2, 0, 0, 0, 6]),
    ("DBGWCR0_EL1", [2, 0, 0, 0, 7]),
    ("DBGBVR1_EL1", [2, 0, 0, 1, 4]),
    ("DBGBCR1_EL1", [2, 0, 0, 1, 5]),
    ("DBGWVR1_EL1", [2, 0, 0, 1, 6]),
    ("DBGWCR1_EL1", [2, 0, 0, 1, 7]),
    ("DBGBVR2_EL1", [2, 0, 0, 2, 4]),
    ("DBGBCR2_EL1", [2, 0, 0, 2, 5]),
    ("DBGWVR2_EL1", [2, 0, 0, 2, 6]),
    ("DBGWCR2_EL1", [2, 0, 0, 2, 7]),
    ("DBGBVR3_EL1", [2, 0, 0, 3, 4]),
    ("DBGBCR3_EL1", [2, 0, 0, 3, 5]),
    ("DBGWVR3_EL1", [2, 0, 0, 3, 6]),
    ("DBGWCR3_EL1", [2, 0, 0, 3, 7]),
    ("DBGBVR4_EL1", [2, 0, 0, 4, 4]),
    ("DBGBCR4_EL1", [2, 0, 0, 4, 5]),
    ("DBGWVR4_EL1", [2, 0, 0, 4, 6]),
    ("DBGWCR4_EL1", [2, 0, 0, 4, 7]),
    ("DBGBVR5_EL1", [2, 0, 0, 5, 4]),
    ("DBGBCR5_EL1", [2, 0, 0, 5, 5]),
    ("DBGWVR5_EL1", [2, 0, 0, 5, 6]),
    ("DBGWCR5_EL1", [2, 0, 0, 5, 7]),
    ("DBGBVR6_EL1", [2, 0, 0, 6, 4]),
    ("DBGBCR6_EL1", [2, 0, 0, 6, 5]),
    ("DBGWVR6_EL1", [2, 0, 0, 6, 6]),
    ("DBGWCR6_EL1", [2, 0, 0, 6, 7]),
    ("DBGBVR7_EL1", [2, 0, 0, 7, 4]),
    ("DBGBCR7_EL1", [2, 0, 0, 7, 5]),
    ("DBGWVR7_EL1", [2, 0, 0, 7, 6]),
    ("DBGWCR7_EL1", [2, 0, 0, 7, 7]),
    ("DBGBVR8_EL1", [2, 0, 0, 8, 4]),
    ("DBGBCR8_EL1", [2, 0, 0, 8, 5]),
    ("DBGWVR8_EL1", [2, 0, 0, 8, 6]),
    ("DBGWCR8_EL1", [2, 0, 0, 8, 7]),
    ("DBGBVR9_EL1", [2, 0, 0, 9, 4]),
    ("DBGBCR9_EL1", [2, 0, 0, 9, 5]),
    ("DBGWVR9_EL1", [2, 0, 0, 9, 6]),
    ("DBGWCR9_EL1", [2, 0, 0, 9, 7]),
    ("DBGBVR10_EL1", [2, 0, 0, 10, 4]),
    ("DBGBCR10_EL1", [2, 0, 0, 10, 5]),
    ("DBGWVR10_EL1", [2, 0, 0, 10, 6]),
    ("DBGWCR10_EL1", [2, 0, 0, 10, 7]),
    ("DBGBVR11_EL1", [2, 0, 0, 11, 4]),
    ("DBGBCR11_EL1", [2, 0, 0, 11, 5]),
    ("DBGWVR11_EL1", [2, 0, 0, 11, 6]),
    ("DBGWCR11_EL1", [2, 0, 0, 11, 7]),
    ("DBGBVR12_EL1", [2, 0, 0, 12, 4]),
    ("DBGBCR12_EL1", [2, 0, 0, 12, 5]),
    ("DBGWVR12_EL1", [2, 0, 0, 12, 6]),
    ("DBGWCR12_EL1", [2, 0, 0, 12, 7]),
    ("DBGBVR13_EL1", [2, 0, 0, 13, 4]),
    ("DBGBCR13_EL1", [2, 0, 0, 13, 5]),
    ("DBGWVR13_EL1", [2, 0, 0, 13, 6]),
    ("DBGWCR13_EL1", [2, 0, 0, 13, 7]),
    ("DBGBVR14_EL1", [2, 0, 0, 14, 4]),
    ("DBGBCR14_EL1", [2, 0, 0, 14, 5]),
    ("DBGWVR14_EL1", [2, 0, 0, 14, 6]),
    ("DBGWCR14_EL1", [2, 0, 0, 14, 7]),
    ("DBGBVR15_EL1", [2, 0, 0, 15, 4]),
    ("DBGBCR15_EL1", [2, 0, 0, 15, 5]),
    ("DBGWVR15_EL1", [2, 0, 0, 15, 6]),
    ("DBGWCR15_EL1", [2, 0, 0, 15, 7]),
];

/// Returns the encoding of the system register `name` of
/// [`AARCH64_SYSREGS`].
#[must_use]
pub fn sysreg_encoding(name: &str) -> Option<[u8; 5]> {
    AARCH64_SYSREG_ENCODINGS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, enc)| *enc)
}

/// Returns the name in [`AARCH64_SYSREGS`] of the system register with
/// encoding `enc`.
#[must_use]
pub fn sysreg_named(enc: [u8; 5]) -> Option<&'static str> {
    AARCH64_SYSREG_ENCODINGS
        .iter()
        .find(|(_, known)| *known == enc)
        .map(|(name, _)| *name)
}

/// The general registers `regs` holds for a vCPU that runs, in the order a
/// backend writes them: `x0`..`x30`, then the stack pointers, `pc`, `pstate`
/// and the floating-point control and status.
#[must_use]
pub fn aarch64_reg_names() -> Vec<String> {
    (0..31)
        .map(|n| format!("x{n}"))
        .chain(
            ["sp_el0", "sp_el1", "pc", "pstate", "fpcr", "fpsr"]
                .iter()
                .map(|name| (*name).to_string()),
        )
        .collect()
}

/// The number of SIMD and floating-point registers, `q0`..`q31`.
pub const AARCH64_SIMD_REGS: usize = 32;

/// Returns a 128-bit SIMD register as `simd` holds it: 32 lowercase hex
/// digits, no prefix.
#[must_use]
pub fn simd_hex(value: u128) -> String {
    format!("{value:032x}")
}

/// Parses a SIMD register as [`simd_hex`] writes it, and nothing else.
#[must_use]
pub fn parse_simd(text: &str) -> Option<u128> {
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(text, 16).ok()
}

/// One arm64 vCPU.
///
/// `regs` holds `x0`..`x30`, `sp_el0`, `sp_el1`, `pc`, `pstate`, `fpcr` and
/// `fpsr`; `simd` holds `q0`..`q31` as 32 hex digits each; `sysregs` holds the
/// EL1 and EL0 system registers by their architectural names (`SCTLR_EL1`,
/// `TTBR0_EL1`, `CNTV_CVAL_EL0`, the pointer-authentication keys, the debug
/// registers, `MPIDR_EL1` and so on). A KVM register this build has no name
/// for goes into `kvm_extra` by its id, so nothing read is lost, and a
/// register a backend could not read is listed in `unavailable`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aarch64Vcpu {
    /// The vCPU's index, which is also its MPIDR affinity 0.
    pub id: u32,
    /// Whether it runs.
    pub power: Power,
    /// `runnable` or `stopped`, as KVM reports it; absent on HVF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mp_state: Option<String>,
    /// The general registers, by name.
    pub regs: BTreeMap<String, Hex64>,
    /// The SIMD and floating-point registers, `q0` first.
    #[serde(default)]
    pub simd: Vec<String>,
    /// The system registers, by name.
    pub sysregs: BTreeMap<String, Hex64>,
    /// The vCPU's view of the virtual timer, on HVF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timer: Option<VcpuTimer>,
    /// `hvf` or `kvm`.
    pub backend: String,
    /// KVM registers this build has no name for, by id, both as hex.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub kvm_extra: BTreeMap<String, String>,
    /// KVM's firmware registers by name (`PSCI_VERSION`, the SMCCC
    /// workarounds, the feature bitmaps): what the guest's firmware
    /// answers. A restore compares them with the destination's; see
    /// `checkpoint::kvm_regs`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub firmware: BTreeMap<String, Hex64>,
    /// Registers only KVM has whose value a guest keeps fixed, by name. A
    /// restore compares them rather than loads them; see
    /// `checkpoint::kvm_regs`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fixed: BTreeMap<String, Hex64>,
    /// An SError or external abort KVM holds pending for the vCPU, from
    /// `KVM_GET_VCPU_EVENTS`; absent when nothing is pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Arm64Events>,
    /// Registers the backend could not read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<String>,
    /// Whether this is less than a restore needs.
    pub partial: bool,
}

impl Aarch64Vcpu {
    /// Checks that the state is whole, so a restore can load it as it is.
    ///
    /// A vCPU that runs needs every general register of
    /// [`aarch64_reg_names`], all [`AARCH64_SIMD_REGS`] SIMD registers in the
    /// [`simd_hex`] form, every required system register of
    /// [`AARCH64_SYSREGS`] and its timer. An optional register may be absent
    /// only when `unavailable` names it. No name outside those lists is
    /// accepted, since a restore would have nowhere to put it. A vCPU that
    /// is off, or waits for its `CPU_ON`, holds no register at all.
    ///
    /// # Errors
    ///
    /// Errors with the first thing that does not hold, naming the vCPU.
    pub fn check_restorable(&self) -> Result<(), String> {
        let id = self.id;
        let refuse = |why: String| Err(format!("vCPU {id}: {why}"));
        if self.partial {
            return refuse("the state is partial".to_string());
        }
        if !self.kvm_extra.is_empty() {
            return refuse(format!(
                "{} KVM register(s) this build has no name for",
                self.kvm_extra.len()
            ));
        }
        if let Some(name) = self
            .firmware
            .keys()
            .find(|n| !crate::checkpoint::kvm_regs::is_firmware(n))
        {
            return refuse(format!("unknown firmware register {name:?}"));
        }
        if let Some(name) = self
            .fixed
            .keys()
            .find(|n| crate::checkpoint::kvm_regs::fixed_named(n).is_none())
        {
            return refuse(format!("unknown fixed register {name:?}"));
        }
        if self.power != Power::On {
            if !self.regs.is_empty() || !self.simd.is_empty() || !self.sysregs.is_empty() {
                return refuse("a vCPU that is not on holds registers".to_string());
            }
            return Ok(());
        }
        let names = aarch64_reg_names();
        if let Some(name) = names.iter().find(|n| !self.regs.contains_key(*n)) {
            return refuse(format!("register {name} is missing"));
        }
        if let Some(name) = self.regs.keys().find(|n| !names.contains(n)) {
            return refuse(format!("unknown register {name:?}"));
        }
        if self.simd.len() != AARCH64_SIMD_REGS {
            return refuse(format!(
                "{} SIMD registers, not {AARCH64_SIMD_REGS}",
                self.simd.len()
            ));
        }
        if let Some((n, _)) = self
            .simd
            .iter()
            .enumerate()
            .find(|(_, q)| parse_simd(q).is_none())
        {
            return refuse(format!("q{n} is not 32 hex digits"));
        }
        let need = |name: &str| {
            AARCH64_SYSREGS
                .iter()
                .find(|(known, _)| *known == name)
                .map(|(_, need)| *need)
        };
        if let Some(name) = self.sysregs.keys().find(|n| need(n).is_none()) {
            return refuse(format!("unknown system register {name:?}"));
        }
        if let Some(name) = self
            .unavailable
            .iter()
            .find(|n| need(n) != Some(Need::Optional))
        {
            return refuse(format!(
                "{name} is listed as unavailable, and a restore needs it"
            ));
        }
        for (name, need) in AARCH64_SYSREGS {
            let unread = self.unavailable.iter().any(|n| n == name);
            match (self.sysregs.contains_key(name), unread) {
                (true, true) => return refuse(format!("{name} is both read and unavailable")),
                (false, false) => {
                    return refuse(format!(
                        "system register {name} is missing{}",
                        if need == Need::Optional {
                            " and not listed as unavailable"
                        } else {
                            ""
                        }
                    ))
                }
                _ => {}
            }
        }
        if self.timer.is_none() {
            return refuse("the virtual timer is missing".to_string());
        }
        Ok(())
    }
}

/// The exceptions KVM holds pending for an arm64 vCPU, `struct
/// kvm_vcpu_events`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arm64Events {
    /// An SError is pending.
    pub serror_pending: bool,
    /// The pending SError has the syndrome `serror_esr`.
    pub serror_has_esr: bool,
    /// An external data abort is pending.
    pub ext_dabt_pending: bool,
    /// The pending SError's syndrome.
    pub serror_esr: Hex64,
}

impl Arm64Events {
    /// Returns whether anything is pending.
    #[must_use]
    pub fn any(&self) -> bool {
        self.serror_pending || self.ext_dabt_pending
    }
}

/// One x86-64 vCPU, as KVM holds it.
///
/// `regs` holds the general registers, `rip` and `rflags`; `sregs` the
/// control registers, `efer` and `apic_base`; `msrs` every MSR by its hex
/// index. The blobs KVM defines by size (XSAVE, the local APIC page) are
/// base64. Segment and descriptor-table registers are not in the schema yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X86Vcpu {
    /// The vCPU's index, which is also its APIC ID.
    pub id: u32,
    /// KVM's multiprocessing state, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mp_state: Option<String>,
    /// The general registers, by name.
    pub regs: BTreeMap<String, Hex64>,
    /// The control registers, by name.
    pub sregs: BTreeMap<String, Hex64>,
    /// The MSRs, by index.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub msrs: BTreeMap<String, Hex64>,
    /// The extended control registers, by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub xcrs: BTreeMap<String, Hex64>,
    /// The XSAVE area, base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xsave_b64: Option<String>,
    /// The local APIC register page, base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lapic_b64: Option<String>,
    /// The guest TSC rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsc_khz: Option<u32>,
    /// `kvm`.
    pub backend: String,
    /// Registers the backend could not read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<String>,
    /// Whether this is less than a restore needs.
    pub partial: bool,
}

/// One vCPU of either architecture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum VcpuState {
    /// An arm64 vCPU.
    Aarch64(Aarch64Vcpu),
    /// An x86-64 vCPU.
    X86_64(X86Vcpu),
}

impl VcpuState {
    /// Returns the vCPU's index.
    #[must_use]
    pub fn id(&self) -> u32 {
        match self {
            Self::Aarch64(v) => v.id,
            Self::X86_64(v) => v.id,
        }
    }

    /// Returns whether a restore would need more than this.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        match self {
            Self::Aarch64(v) => v.partial,
            Self::X86_64(v) => v.partial,
        }
    }

    /// Returns the part of a vCPU's state the plugin register view gives.
    ///
    /// A register the backend could not read is 0 in the view, so it is 0
    /// here too, and the state says it is partial.
    #[must_use]
    pub fn from_regs_view(arch: GuestArch, backend: &str, id: u32, view: &RegsView) -> Self {
        let named = |pairs: &[(&str, u64)]| {
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_string(), Hex64(*value)))
                .collect::<BTreeMap<_, _>>()
        };
        match arch {
            GuestArch::Aarch64 => Self::Aarch64(Aarch64Vcpu {
                id,
                power: Power::On,
                mp_state: None,
                regs: named(&[
                    ("pc", view.pc),
                    ("pstate", view.cpsr),
                    ("sp_el0", view.current_task),
                    ("sp_el1", view.sp_el1),
                ]),
                simd: Vec::new(),
                sysregs: named(&[
                    ("SCTLR_EL1", view.sctlr),
                    ("TCR_EL1", view.tcr),
                    ("TTBR0_EL1", view.ttbr0),
                    ("TTBR1_EL1", view.ttbr1),
                ]),
                timer: None,
                backend: backend.to_string(),
                kvm_extra: BTreeMap::new(),
                firmware: BTreeMap::new(),
                fixed: BTreeMap::new(),
                events: None,
                unavailable: Vec::new(),
                partial: true,
            }),
            GuestArch::X86_64 => Self::X86_64(X86Vcpu {
                id,
                mp_state: None,
                regs: named(&[("rip", view.pc)]),
                sregs: named(&[("cr3", view.root)]),
                msrs: BTreeMap::new(),
                xcrs: BTreeMap::new(),
                xsave_b64: None,
                lapic_b64: None,
                tsc_khz: None,
                backend: backend.to_string(),
                unavailable: Vec::new(),
                partial: true,
            }),
        }
    }

    /// Returns the state of an arm64 vCPU the guest asked to start with PSCI
    /// `CPU_ON` at `entry`, with `ctx` for `x0`, whose thread had not taken
    /// the request.
    ///
    /// It holds no register, as one that is off holds none: a restore
    /// starts it as the request would have. An x86-64 vCPU never waits so,
    /// and is written as off.
    #[must_use]
    pub fn pending_on(arch: GuestArch, backend: &str, id: u32, entry: u64, ctx: u64) -> Self {
        match Self::powered_off(arch, backend, id) {
            Self::Aarch64(mut vcpu) => {
                vcpu.power = Power::PendingOn {
                    entry: Hex64(entry),
                    ctx: Hex64(ctx),
                };
                Self::Aarch64(vcpu)
            }
            other => other,
        }
    }

    /// Returns the state of a vCPU the guest never brought up.
    ///
    /// Only an arm64 vCPU can be in this state: every x86-64 vCPU enters KVM
    /// at once and waits there for its INIT and SIPI. An arm64 vCPU that is
    /// off has no register worth keeping, since `CPU_ON` sets the ones it
    /// starts from, so the state is whole.
    #[must_use]
    pub fn powered_off(arch: GuestArch, backend: &str, id: u32) -> Self {
        match arch {
            GuestArch::Aarch64 => Self::Aarch64(Aarch64Vcpu {
                id,
                power: Power::Off,
                mp_state: None,
                regs: BTreeMap::new(),
                simd: Vec::new(),
                sysregs: BTreeMap::new(),
                timer: None,
                backend: backend.to_string(),
                kvm_extra: BTreeMap::new(),
                firmware: BTreeMap::new(),
                fixed: BTreeMap::new(),
                events: None,
                unavailable: Vec::new(),
                partial: false,
            }),
            GuestArch::X86_64 => Self::X86_64(X86Vcpu {
                id,
                mp_state: Some("uninitialized".to_string()),
                regs: BTreeMap::new(),
                sregs: BTreeMap::new(),
                msrs: BTreeMap::new(),
                xcrs: BTreeMap::new(),
                xsave_b64: None,
                lapic_b64: None,
                tsc_khz: None,
                backend: backend.to_string(),
                unavailable: Vec::new(),
                partial: true,
            }),
        }
    }
}

/// The whole of `cpu.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CpuState {
    /// [`CPU_STATE_VERSION`] when written by this build.
    pub version: u32,
    /// `aarch64` or `x86_64`.
    pub arch: String,
    /// Every vCPU, in index order.
    pub vcpus: Vec<VcpuState>,
}

impl CpuState {
    /// Returns the document for `vcpus`, which must be in index order.
    #[must_use]
    pub fn new(arch: GuestArch, vcpus: Vec<VcpuState>) -> Self {
        Self {
            version: CPU_STATE_VERSION,
            arch: arch_name(arch).to_string(),
            vcpus,
        }
    }

    /// Returns whether any vCPU state is less than a restore needs.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.vcpus.iter().any(VcpuState::is_partial)
    }

    /// Parses `cpu.json`, refusing another version, an unknown architecture,
    /// a state of the other architecture, more than [`MAX_VCPUS`] vCPUs, and
    /// vCPUs out of index order.
    ///
    /// # Errors
    ///
    /// Errors, as `InvalidData`, on any of those or on JSON that is not this
    /// document.
    pub fn from_json(json: &[u8]) -> io::Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            version: u32,
            arch: String,
            vcpus: Vec<serde_json::Value>,
        }
        let invalid = |what: String| io::Error::new(io::ErrorKind::InvalidData, what);
        let wire: Wire = serde_json::from_slice(json).map_err(|e| invalid(e.to_string()))?;
        if wire.version != CPU_STATE_VERSION {
            return Err(invalid(format!(
                "version {}, this build reads {CPU_STATE_VERSION}",
                wire.version
            )));
        }
        if wire.vcpus.len() > MAX_VCPUS {
            return Err(invalid(format!(
                "{} vCPUs, at most {MAX_VCPUS}",
                wire.vcpus.len()
            )));
        }
        let vcpus = wire
            .vcpus
            .into_iter()
            .map(|v| match wire.arch.as_str() {
                "aarch64" => serde_json::from_value(v).map(VcpuState::Aarch64),
                "x86_64" => serde_json::from_value(v).map(VcpuState::X86_64),
                _ => Err(serde::de::Error::custom("unknown arch")),
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| invalid(format!("{} vCPU: {e}", wire.arch)))?;
        for (index, vcpu) in vcpus.iter().enumerate() {
            if vcpu.id() as usize != index {
                return Err(invalid(format!(
                    "vCPU {index} has id {}; the list must be in index order",
                    vcpu.id()
                )));
            }
        }
        Ok(Self {
            version: wire.version,
            arch: wire.arch,
            vcpus,
        })
    }
}

/// Returns the name `cpu.json` and the profile give `arch`.
#[must_use]
pub fn arch_name(arch: GuestArch) -> &'static str {
    match arch {
        GuestArch::Aarch64 => "aarch64",
        GuestArch::X86_64 => "x86_64",
    }
}

/// A request a vCPU carries out on its own thread, outside the guest.
// Only HVF hands back a platform or loads a state so far.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub(crate) enum Work<'a> {
    /// Write this vCPU's state, and its own part of the interrupt
    /// controller.
    Export,
    /// Once every vCPU has exported: vCPU 0 reads the interrupt controller,
    /// the counter and the backend's blob, and the others do nothing.
    ExportPlatform,
    /// One step of a restore, for this vCPU, from `plan`.
    Import(ImportStep, &'a ImportPlan),
}

/// The steps of a restore, in order. The control thread waits for every
/// vCPU to finish one before it posts the next, so each is a barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// See `Work`.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub(crate) enum ImportStep {
    /// Each vCPU loads its registers and its timer.
    Vcpu,
    /// vCPU 0 loads the interrupt controller, once every vCPU exists and
    /// none has run. The others do nothing.
    Platform,
    /// Each vCPU loads its own part of the interrupt controller, which the
    /// step before reset.
    IrqCpu,
}

/// What a restore loads into the vCPUs and the interrupt controller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ImportPlan {
    /// Every vCPU's state, by index.
    pub(crate) vcpus: Vec<VcpuState>,
    /// The interrupt controller and the counter.
    pub(crate) platform: PlatformState,
}

/// What a vCPU hands back from its work.
#[derive(Clone, Debug, PartialEq, Eq)]
// See `Work`.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub(crate) enum Output {
    /// From [`Work::Export`]: its state, and its part of the interrupt
    /// controller when the backend reads one.
    Vcpu {
        /// The vCPU's state.
        state: VcpuState,
        /// Its redistributor and CPU interface.
        irq: Option<IrqCpuState>,
    },
    /// From [`Work::ExportPlatform`] on vCPU 0.
    Platform {
        /// The platform, without the vCPUs' parts of the interrupt
        /// controller, which the control thread adds.
        platform: PlatformState,
        /// What a restore must be able to load, for the manifest.
        capabilities: Vec<String>,
    },
}

/// Carries out `work` with what the plugin register view reads: an export
/// gives a partial state, the platform is not read, and an import is
/// refused.
///
/// This is the work the x86-64 backend does until its own export and
/// import exist.
///
/// # Errors
///
/// Errors on an import.
// The arm64 backends have their own, so only the x86-64 build calls it.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) fn serve_from_regs_view<V: SafepointVcpu>(
    arch: GuestArch,
    backend: &str,
    id: u32,
    vcpu: &V,
    work: Work<'_>,
) -> io::Result<Option<Output>> {
    match work {
        Work::Export => Ok(Some(Output::Vcpu {
            state: VcpuState::from_regs_view(arch, backend, id, &vcpu.regs()),
            irq: None,
        })),
        Work::ExportPlatform => Ok(None),
        Work::Import(..) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("the {backend} backend cannot load a vCPU state yet (vCPU {id})"),
        )),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn view() -> RegsView {
        RegsView {
            root: 0x4100_0000,
            pc: 0xffff_8000_0801_0000,
            cpsr: 0x3c5,
            ttbr0: 0x4200_0000,
            ttbr1: 0x4100_0000,
            sctlr: 0x30d0_5199,
            sp_el1: 0xffff_8000_0a00_0000,
            tcr: 0x32_b551_9510,
            current_task: 0xffff_0000_c000_0000,
        }
    }

    // The names are the contract with the exports that complete them, so the
    // document is pinned.
    #[test]
    fn a_partial_arm64_state_is_pinned() {
        let doc = CpuState::new(
            GuestArch::Aarch64,
            vec![
                VcpuState::from_regs_view(GuestArch::Aarch64, "hvf", 0, &view()),
                VcpuState::powered_off(GuestArch::Aarch64, "hvf", 1),
            ],
        );
        assert!(doc.is_partial());
        assert_eq!(
            serde_json::to_string(&doc).unwrap(),
            concat!(
                r#"{"version":1,"arch":"aarch64","vcpus":["#,
                r#"{"id":0,"power":"on","regs":{"pc":"0xffff800008010000","#,
                r#""pstate":"0x3c5","sp_el0":"0xffff0000c0000000","sp_el1":"0xffff80000a000000"},"#,
                r#""simd":[],"sysregs":{"SCTLR_EL1":"0x30d05199","TCR_EL1":"0x32b5519510","#,
                r#""TTBR0_EL1":"0x42000000","TTBR1_EL1":"0x41000000"},"backend":"hvf","partial":true},"#,
                r#"{"id":1,"power":"off","regs":{},"simd":[],"sysregs":{},"backend":"hvf","partial":false}"#,
                r#"]}"#
            )
        );
    }

    /// A whole state, every register set to a value of its own.
    pub(crate) fn whole(id: u32) -> Aarch64Vcpu {
        Aarch64Vcpu {
            id,
            power: Power::On,
            mp_state: None,
            regs: aarch64_reg_names()
                .into_iter()
                .zip(1u64..)
                .map(|(name, v)| (name, Hex64(v)))
                .collect(),
            simd: (0..AARCH64_SIMD_REGS as u128)
                .map(|q| simd_hex(q << 64 | q))
                .collect(),
            sysregs: AARCH64_SYSREGS
                .iter()
                .zip(0x100u64..)
                .map(|((name, _), v)| ((*name).to_string(), Hex64(v)))
                .collect(),
            timer: Some(VcpuTimer {
                vtimer_masked: false,
            }),
            backend: "hvf".to_string(),
            kvm_extra: BTreeMap::new(),
            firmware: BTreeMap::new(),
            fixed: BTreeMap::new(),
            events: None,
            unavailable: Vec::new(),
            partial: false,
        }
    }

    // The shape of a whole state, pinned on a small one: the schema is the
    // contract with the KVM export, which writes the same document.
    #[test]
    fn a_whole_arm64_state_is_pinned() {
        let state = VcpuState::Aarch64(Aarch64Vcpu {
            id: 0,
            power: Power::On,
            mp_state: None,
            regs: [("pc", 0xffff_8000_0801_0000u64), ("x0", 7)]
                .into_iter()
                .map(|(n, v)| (n.to_string(), Hex64(v)))
                .collect(),
            simd: vec![simd_hex(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10)],
            sysregs: [("CNTV_CTL_EL0".to_string(), Hex64(5))].into(),
            timer: Some(VcpuTimer {
                vtimer_masked: true,
            }),
            backend: "hvf".to_string(),
            kvm_extra: BTreeMap::new(),
            firmware: BTreeMap::new(),
            fixed: BTreeMap::new(),
            events: None,
            unavailable: vec!["TPIDR2_EL0".to_string()],
            partial: false,
        });
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            json,
            concat!(
                r#"{"id":0,"power":"on","regs":{"pc":"0xffff800008010000","x0":"0x7"},"#,
                r#""simd":["0102030405060708090a0b0c0d0e0f10"],"#,
                r#""sysregs":{"CNTV_CTL_EL0":"0x5"},"timer":{"vtimer_masked":true},"#,
                r#""backend":"hvf","unavailable":["TPIDR2_EL0"],"partial":false}"#
            )
        );
        let doc = CpuState::new(GuestArch::Aarch64, vec![state]);
        let json = serde_json::to_vec(&doc).unwrap();
        assert_eq!(CpuState::from_json(&json).unwrap(), doc);
    }

    #[test]
    fn a_whole_state_is_restorable_and_reads_back() {
        let state = whole(0);
        state.check_restorable().unwrap();
        let doc = CpuState::new(GuestArch::Aarch64, vec![VcpuState::Aarch64(state)]);
        assert!(!doc.is_partial());
        let json = serde_json::to_vec(&doc).unwrap();
        assert_eq!(CpuState::from_json(&json).unwrap(), doc);
        // A vCPU that never started is whole as it is.
        let VcpuState::Aarch64(off) = VcpuState::powered_off(GuestArch::Aarch64, "hvf", 1) else {
            unreachable!()
        };
        off.check_restorable().unwrap();
    }

    #[test]
    fn a_state_a_restore_cannot_load_is_refused() {
        let refused = |edit: &dyn Fn(&mut Aarch64Vcpu), want: &str| {
            let mut state = whole(3);
            edit(&mut state);
            let err = state.check_restorable().unwrap_err();
            assert!(err.starts_with("vCPU 3: "), "{err}");
            assert!(err.contains(want), "{err} lacks {want:?}");
        };
        refused(&|s| s.partial = true, "partial");
        refused(
            &|s| {
                s.regs.remove("x17");
            },
            "register x17 is missing",
        );
        refused(
            &|s| {
                s.regs.insert("x31".into(), Hex64(0));
            },
            "unknown register \"x31\"",
        );
        refused(
            &|s| {
                s.simd.pop();
            },
            "31 SIMD registers",
        );
        refused(&|s| s.simd[4] = "0x12".into(), "q4 is not 32 hex digits");
        refused(&|s| s.simd[5] = "g".repeat(32), "q5 is not 32 hex digits");
        refused(
            &|s| {
                s.sysregs.remove("TTBR1_EL1");
            },
            "system register TTBR1_EL1 is missing",
        );
        refused(
            &|s| {
                s.sysregs.remove("TPIDR2_EL0");
            },
            "TPIDR2_EL0 is missing and not listed as unavailable",
        );
        refused(
            &|s| s.unavailable.push("SCTLR_EL1".into()),
            "SCTLR_EL1 is listed as unavailable",
        );
        refused(
            &|s| s.unavailable.push("SMCR_EL1".into()),
            "SMCR_EL1 is both read and unavailable",
        );
        refused(
            &|s| {
                s.sysregs.insert("HCR_EL2".into(), Hex64(0));
            },
            "unknown system register \"HCR_EL2\"",
        );
        refused(&|s| s.timer = None, "virtual timer is missing");
        refused(
            &|s| {
                s.kvm_extra.insert("0x1".into(), "0x2".into());
            },
            "KVM register",
        );
        refused(&|s| s.power = Power::Off, "not on holds registers");
        refused(
            &|s| {
                s.firmware.insert("PSCI_VERSIONS".into(), Hex64(0));
            },
            "unknown firmware register \"PSCI_VERSIONS\"",
        );
        refused(
            &|s| {
                s.fixed.insert("OSLAR_EL1".into(), Hex64(0));
            },
            "unknown fixed register \"OSLAR_EL1\"",
        );
        // What KVM records beside the registers reads back and is whole.
        let mut state = whole(0);
        state
            .firmware
            .insert("PSCI_VERSION".into(), Hex64(0x1_0001));
        state.fixed.insert("OSLSR_EL1".into(), Hex64(8));
        state.events = Some(Arm64Events {
            serror_pending: true,
            serror_has_esr: true,
            ext_dabt_pending: false,
            serror_esr: Hex64(0x96),
        });
        state.check_restorable().unwrap();
        let doc = CpuState::new(GuestArch::Aarch64, vec![VcpuState::Aarch64(state)]);
        let json = serde_json::to_vec(&doc).unwrap();
        assert_eq!(CpuState::from_json(&json).unwrap(), doc);
        // An optional register the host did not have is fine when listed.
        let mut state = whole(0);
        state.sysregs.remove("SCXTNUM_EL1");
        state.unavailable.push("SCXTNUM_EL1".into());
        state.check_restorable().unwrap();
    }

    #[test]
    fn simd_registers_parse_only_as_written() {
        for v in [0u128, 1, u128::MAX, 0xdead_beef << 64] {
            assert_eq!(parse_simd(&simd_hex(v)), Some(v));
        }
        for bad in [
            "",
            "0x0",
            "+0000000000000000000000000000000",
            &"0".repeat(33),
        ] {
            assert_eq!(parse_simd(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_system_register_list_has_no_duplicates() {
        let mut names: Vec<&str> = AARCH64_SYSREGS.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), AARCH64_SYSREGS.len());
        assert_eq!(aarch64_reg_names().len(), 37);
    }

    #[test]
    fn a_document_reads_back() {
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            let doc = CpuState::new(
                arch,
                vec![
                    VcpuState::from_regs_view(arch, "kvm", 0, &view()),
                    VcpuState::from_regs_view(arch, "kvm", 1, &view()),
                ],
            );
            let json = serde_json::to_vec(&doc).unwrap();
            assert_eq!(CpuState::from_json(&json).unwrap(), doc);
        }
    }

    #[test]
    fn a_pending_cpu_on_is_named() {
        let power = Power::PendingOn {
            entry: Hex64(0x4008_0000),
            ctx: Hex64(0),
        };
        let json = serde_json::to_string(&power).unwrap();
        assert_eq!(json, r#"{"pending_on":{"entry":"0x40080000","ctx":"0x0"}}"#);
        assert_eq!(serde_json::from_str::<Power>(&json).unwrap(), power);
    }

    #[test]
    fn bad_documents_are_refused() {
        let refused = |json: &str| {
            let err = CpuState::from_json(json.as_bytes()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{json}: {err}");
            err.to_string()
        };
        let arm = r#"{"id":0,"power":"on","regs":{},"sysregs":{},"backend":"hvf","partial":true}"#;
        let x86 = r#"{"id":0,"regs":{},"sregs":{},"backend":"kvm","partial":true}"#;
        refused(&format!(
            r#"{{"version":2,"arch":"aarch64","vcpus":[{arm}]}}"#
        ));
        refused(&format!(
            r#"{{"version":1,"arch":"riscv64","vcpus":[{arm}]}}"#
        ));
        refused(&format!(
            r#"{{"version":1,"arch":"aarch64","vcpus":[{x86}]}}"#
        ));
        refused(&format!(
            r#"{{"version":1,"arch":"x86_64","vcpus":[{arm}]}}"#
        ));
        refused(
            r#"{"version":1,"arch":"aarch64","vcpus":[{"id":0,"power":"on","regs":{"pc":"12"},"sysregs":{},"backend":"hvf","partial":true}]}"#,
        );
        refused(&format!(
            r#"{{"version":1,"arch":"aarch64","vcpus":[{arm}],"extra":1}}"#
        ));
        let many = vec![arm; MAX_VCPUS + 1].join(",");
        assert!(refused(&format!(
            r#"{{"version":1,"arch":"aarch64","vcpus":[{many}]}}"#
        ))
        .contains("at most 64"));
        let two = format!(r#"{{"version":1,"arch":"aarch64","vcpus":[{arm},{arm}]}}"#);
        assert!(refused(&two).contains("index order"));
        // Both well-formed: they read.
        CpuState::from_json(
            format!(r#"{{"version":1,"arch":"aarch64","vcpus":[{arm}]}}"#).as_bytes(),
        )
        .unwrap();
        CpuState::from_json(
            format!(r#"{{"version":1,"arch":"x86_64","vcpus":[{x86}]}}"#).as_bytes(),
        )
        .unwrap();
    }
}

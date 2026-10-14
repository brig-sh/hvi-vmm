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
//! What the backends read today is the register view the plugin interface
//! has: on arm64 PC, PSTATE, SP_EL0, SP_EL1 and four translation registers; on
//! x86-64 RIP and CR3. That is far short of a vCPU a restore could resume, so
//! such a state says `"partial": true`, and a restore must refuse it. The HVF
//! and KVM exports that fill the rest come next and write the same names.

use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
    /// Whether the virtual timer's interrupt is masked, on HVF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vtimer_masked: Option<bool>,
    /// `hvf` or `kvm`.
    pub backend: String,
    /// KVM registers this build has no name for, by id, both as hex.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub kvm_extra: BTreeMap<String, String>,
    /// Registers the backend could not read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<String>,
    /// Whether this is less than a restore needs.
    pub partial: bool,
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
                vtimer_masked: None,
                backend: backend.to_string(),
                kvm_extra: BTreeMap::new(),
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
                vtimer_masked: None,
                backend: backend.to_string(),
                kvm_extra: BTreeMap::new(),
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
pub(crate) enum Work<'a> {
    /// Write this vCPU's state.
    Export,
    /// Load this state into this vCPU.
    Import(&'a VcpuState),
}

/// Carries out `work` with what the plugin register view reads: an export
/// gives a partial state and an import is refused.
///
/// This is the work every backend does until its own export and import
/// exist.
///
/// # Errors
///
/// Errors on an import.
pub(crate) fn serve_from_regs_view<V: SafepointVcpu>(
    arch: GuestArch,
    backend: &str,
    id: u32,
    vcpu: &V,
    work: Work<'_>,
) -> io::Result<Option<VcpuState>> {
    match work {
        Work::Export => Ok(Some(VcpuState::from_regs_view(
            arch,
            backend,
            id,
            &vcpu.regs(),
        ))),
        Work::Import(state) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "the {backend} backend cannot load a vCPU state yet (vCPU {})",
                state.id()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
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

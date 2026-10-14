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

//! `platform.json`: the interrupt controller and the guest counter.
//!
//! Each section is tagged with its `kind`, so a restore picks the import
//! that matches and refuses a kind it has none for:
//!
//! | section | kind | written by |
//! |---|---|---|
//! | `irq` | `hv-gic-v3` | HVF's in-kernel GICv3 (`hv_gic`): [`GicV3State`] |
//! | `timer` | `arch-timer` | the architected counter: [`ArchTimerState`] |
//! | either | `not-captured` | a backend that does not read it yet (KVM) |
//!
//! The portable profile adds `gicv2` and `hvi-time` beside them. A
//! `not-captured` section is a marker with the reason, so a bundle says what
//! it lacks instead of holding a default a restore could mistake for the
//! real thing, and a restore refuses it.
//!
//! The canonical GICv3 registers are what a later import on another backend
//! would consume. HVF restores its own GIC from the opaque `hv_gic_state`
//! blob instead, which `backend_adjunct` carries as base64 with its SHA-256,
//! and which only the same macOS build can load.

use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Serialize};

use crate::checkpoint::cpu::arch_name;
use crate::checkpoint::profile::sha256_hex;
use crate::plugin::GuestArch;

/// The [`PlatformState`] format this build writes and reads.
pub const PLATFORM_STATE_VERSION: u32 = 1;

/// The adjunct kind of HVF's `hv_gic_state` blob.
pub const HVF_GIC_STATE: &str = "hvf_gic_state";

/// The manifest capability a bundle with an `hv_gic_state` blob requires.
pub const HVF_GIC_STATE_CAPABILITY: &str = "hvf-gic-state-v1";

/// The most interrupt IDs a GICv3 distributor has: SGIs, PPIs and SPIs up to
/// 1019.
pub const GICV3_MAX_INTIDS: u32 = 1020;

/// The largest adjunct blob, decoded. `hv_gic_state` is a few KiB.
pub const MAX_ADJUNCT_BYTES: usize = 4 << 20;

/// The interrupt controller's state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum IrqState {
    /// This build does not read the controller.
    #[serde(rename = "not-captured")]
    NotCaptured {
        /// Why, for a person.
        reason: String,
    },
    /// HVF's in-kernel GICv3.
    #[serde(rename = "hv-gic-v3")]
    HvGicV3(Box<GicV3State>),
}

impl IrqState {
    /// Returns the kind, as `platform.json` names it.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotCaptured { .. } => "not-captured",
            Self::HvGicV3(_) => "hv-gic-v3",
        }
    }
}

/// A GICv3 in canonical form: the distributor, and each vCPU's
/// redistributor and CPU interface.
///
/// The per-interrupt arrays hold one register each, by register number,
/// from register 0, which affinity routing leaves to the redistributors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GicV3State {
    /// 3.
    pub version: u32,
    /// The distributor.
    pub dist: GicV3Dist,
    /// The redistributor of each vCPU that has run, by vCPU.
    pub redist: Vec<GicV3Redist>,
    /// The CPU interface of each vCPU that has run, by vCPU.
    pub icc: Vec<GicV3Icc>,
    /// The number of SPIs the distributor implements.
    pub spi_count: u32,
}

/// The GICv3 distributor registers, `GICD_*`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GicV3Dist {
    /// `GICD_CTLR`.
    pub ctlr: u32,
    /// `GICD_IGROUPR<n>`.
    pub igroupr: Vec<u32>,
    /// `GICD_ISENABLER<n>`.
    pub isenabler: Vec<u32>,
    /// `GICD_ISPENDR<n>`.
    pub ispendr: Vec<u32>,
    /// `GICD_ISACTIVER<n>`.
    pub isactiver: Vec<u32>,
    /// `GICD_IPRIORITYR<n>`, four interrupts each.
    pub ipriorityr: Vec<u32>,
    /// `GICD_ICFGR<n>`, sixteen interrupts each.
    pub icfgr: Vec<u32>,
    /// `GICD_IROUTER<n>` of every SPI, by interrupt ID.
    pub irouter: BTreeMap<String, u64>,
}

/// One vCPU's GICv3 redistributor, its SGI and PPI registers `GICR_*`.
///
/// `GICR_CTLR` is not here: Hypervisor.framework has no call that reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GicV3Redist {
    /// The vCPU.
    pub vcpu: u32,
    /// `GICR_IGROUPR0`.
    pub igroupr0: u32,
    /// `GICR_ISENABLER0`.
    pub isenabler0: u32,
    /// `GICR_ISPENDR0`.
    pub ispendr0: u32,
    /// `GICR_ISACTIVER0`.
    pub isactiver0: u32,
    /// `GICR_IPRIORITYR0`..`7`.
    pub ipriorityr: Vec<u32>,
    /// `GICR_ICFGR0`.
    pub icfgr0: u32,
    /// `GICR_ICFGR1`.
    pub icfgr1: u32,
}

/// One vCPU's GICv3 CPU interface, its `ICC_*_EL1` registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GicV3Icc {
    /// The vCPU.
    pub vcpu: u32,
    /// `ICC_PMR_EL1`.
    pub pmr: u64,
    /// `ICC_BPR0_EL1`.
    pub bpr0: u64,
    /// `ICC_BPR1_EL1`.
    pub bpr1: u64,
    /// `ICC_AP0R0_EL1`.
    pub ap0r0: u64,
    /// `ICC_AP1R0_EL1`.
    pub ap1r0: u64,
    /// `ICC_CTLR_EL1`.
    pub ctlr: u64,
    /// `ICC_SRE_EL1`.
    pub sre_el1: u64,
    /// `ICC_IGRPEN0_EL1`.
    pub igrpen0: u64,
    /// `ICC_IGRPEN1_EL1`.
    pub igrpen1: u64,
}

/// What one vCPU reads of its own part of the interrupt controller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IrqCpuState {
    /// A GICv3 redistributor and CPU interface.
    GicV3(GicV3Redist, GicV3Icc),
}

/// The guest counter's state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum TimerState {
    /// This build does not read the counter.
    #[serde(rename = "not-captured")]
    NotCaptured {
        /// Why, for a person.
        reason: String,
    },
    /// The architected generic timer, `CNTVCT_EL0`.
    #[serde(rename = "arch-timer")]
    ArchTimer(ArchTimerState),
}

impl TimerState {
    /// Returns the kind, as `platform.json` names it.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotCaptured { .. } => "not-captured",
            Self::ArchTimer(_) => "arch-timer",
        }
    }
}

/// The architected counter at the capture.
///
/// A restore makes the guest's `CNTVCT_EL0` go on from `counter_at_capture`,
/// so the time the guest was away is not seen on its counter. Each vCPU's
/// `CNTV_CTL_EL0` and `CNTV_CVAL_EL0` are in its system registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchTimerState {
    /// The counter's frequency, `CNTFRQ_EL0`.
    pub counter_freq_hz: u64,
    /// The guest's `CNTVCT_EL0` as vCPU 0 saw it at the capture.
    pub counter_at_capture: u64,
    /// The host's monotonic clock at the same moment, in nanoseconds.
    pub host_monotonic_at_capture_ns: u64,
}

/// An opaque blob a backend keeps beside the canonical state, such as HVF's
/// `hv_gic_state`, which only the same macOS build can load.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adjunct {
    /// What the blob is, such as `hvf_gic_state`.
    pub kind: String,
    /// The blob, base64.
    pub data_b64: String,
    /// The SHA-256 of the blob's bytes, hex.
    pub sha256: String,
}

impl Adjunct {
    /// Returns the adjunct of `kind` that carries `data`.
    #[must_use]
    pub fn new(kind: &str, data: &[u8]) -> Self {
        Self {
            kind: kind.to_string(),
            data_b64: base64_encode(data),
            sha256: sha256_hex(data),
        }
    }

    /// Returns the blob's bytes, once they decode and match their SHA-256.
    ///
    /// # Errors
    ///
    /// Errors, as `InvalidData`, on a blob over [`MAX_ADJUNCT_BYTES`], base64
    /// that is not in its canonical form, or bytes whose SHA-256 differs.
    pub fn data(&self) -> io::Result<Vec<u8>> {
        let invalid = |why: String| io::Error::new(io::ErrorKind::InvalidData, why);
        if self.data_b64.len() / 4 * 3 > MAX_ADJUNCT_BYTES {
            return Err(invalid(format!(
                "the {} blob is over {MAX_ADJUNCT_BYTES} bytes",
                self.kind
            )));
        }
        let data = base64_decode(&self.data_b64)
            .ok_or_else(|| invalid(format!("the {} blob is not canonical base64", self.kind)))?;
        if sha256_hex(&data) != self.sha256 {
            return Err(invalid(format!(
                "the {} blob does not match its SHA-256",
                self.kind
            )));
        }
        Ok(data)
    }
}

/// The whole of `platform.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformState {
    /// [`PLATFORM_STATE_VERSION`] when written by this build.
    pub version: u32,
    /// `aarch64` or `x86_64`.
    pub arch: String,
    /// `hvf` or `kvm`.
    pub backend: String,
    /// The interrupt controller.
    pub irq: IrqState,
    /// The guest counter.
    pub timer: TimerState,
    /// The backend's own blob, when it has one.
    pub backend_adjunct: Option<Adjunct>,
}

impl PlatformState {
    /// Returns the document of a backend that reads neither section: both
    /// marked as not captured.
    #[must_use]
    pub fn not_captured(arch: GuestArch, backend: &str) -> Self {
        Self {
            version: PLATFORM_STATE_VERSION,
            arch: arch_name(arch).to_string(),
            backend: backend.to_string(),
            irq: IrqState::NotCaptured {
                reason: format!("this hvi does not read the {backend} interrupt controller yet"),
            },
            timer: TimerState::NotCaptured {
                reason: format!("this hvi does not read the {backend} guest counter yet"),
            },
            backend_adjunct: None,
        }
    }

    /// Returns whether a restore would need more than this.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        matches!(self.irq, IrqState::NotCaptured { .. })
            || matches!(self.timer, TimerState::NotCaptured { .. })
    }

    /// Parses `platform.json`, refusing another version.
    ///
    /// # Errors
    ///
    /// Errors, as `InvalidData`, when the JSON is not this document or is of
    /// another version.
    pub fn from_json(json: &[u8]) -> io::Result<Self> {
        let state: Self = serde_json::from_slice(json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if state.version != PLATFORM_STATE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "version {}, this build reads {PLATFORM_STATE_VERSION}",
                    state.version
                ),
            ));
        }
        Ok(state)
    }

    /// Adds each vCPU's part of the interrupt controller, which each read on
    /// its own thread, to the controller vCPU 0 read.
    ///
    /// # Errors
    ///
    /// Errors when a part is of another kind than the controller.
    pub fn add_cpus(&mut self, cpus: Vec<IrqCpuState>) -> Result<(), String> {
        for cpu in cpus {
            match (&mut self.irq, cpu) {
                (IrqState::HvGicV3(gic), IrqCpuState::GicV3(redist, icc)) => {
                    gic.redist.push(redist);
                    gic.icc.push(icc);
                }
                (other, IrqCpuState::GicV3(redist, _)) => {
                    return Err(format!(
                        "vCPU {} read a GICv3 interface, and the controller is {}",
                        redist.vcpu,
                        other.kind()
                    ))
                }
            }
        }
        Ok(())
    }

    /// Checks the canonical state against a machine of `vcpus` vCPUs and
    /// `spi_count` SPIs, before a restore allocates or loads anything by it.
    ///
    /// The register lists must be as long as the distributor's interrupt
    /// count makes them, each vCPU may appear once and must exist, and a
    /// blob must decode within its limit and match its hash.
    ///
    /// # Errors
    ///
    /// Errors with the first thing that does not hold.
    pub fn check(&self, vcpus: u32) -> Result<(), String> {
        if let IrqState::HvGicV3(gic) = &self.irq {
            gic.check(vcpus)?;
        }
        if let TimerState::ArchTimer(timer) = &self.timer {
            if timer.counter_freq_hz == 0 {
                return Err("timer: counter_freq_hz is 0".to_string());
            }
        }
        if let Some(adjunct) = &self.backend_adjunct {
            adjunct
                .data()
                .map_err(|e| format!("backend_adjunct: {e}"))?;
        }
        Ok(())
    }
}

impl GicV3State {
    /// See [`PlatformState::check`].
    fn check(&self, vcpus: u32) -> Result<(), String> {
        if self.version != 3 {
            return Err(format!("irq: GIC version {}, not 3", self.version));
        }
        if self.spi_count > GICV3_MAX_INTIDS - 32 || self.spi_count % 32 != 0 {
            return Err(format!(
                "irq: {} SPIs, not a multiple of 32 up to {}",
                self.spi_count,
                GICV3_MAX_INTIDS - 32
            ));
        }
        let intids = (self.spi_count + 32) as usize;
        let lengths = [
            ("igroupr", self.dist.igroupr.len(), intids.div_ceil(32)),
            ("isenabler", self.dist.isenabler.len(), intids.div_ceil(32)),
            ("ispendr", self.dist.ispendr.len(), intids.div_ceil(32)),
            ("isactiver", self.dist.isactiver.len(), intids.div_ceil(32)),
            ("ipriorityr", self.dist.ipriorityr.len(), intids.div_ceil(4)),
            ("icfgr", self.dist.icfgr.len(), intids.div_ceil(16)),
            ("irouter", self.dist.irouter.len(), intids - 32),
        ];
        for (name, got, want) in lengths {
            if got != want {
                return Err(format!(
                    "irq: dist.{name} has {got} registers, {want} for {} SPIs",
                    self.spi_count
                ));
            }
        }
        for intid in self.dist.irouter.keys() {
            let ok = intid
                .parse::<u32>()
                .is_ok_and(|n| (32..intids as u32).contains(&n) && n.to_string() == *intid);
            if !ok {
                return Err(format!("irq: dist.irouter has interrupt {intid:?}"));
            }
        }
        let mut seen = vec![false; vcpus as usize];
        for redist in &self.redist {
            if redist.ipriorityr.len() != 8 {
                return Err(format!(
                    "irq: redist of vCPU {} has {} priority registers, not 8",
                    redist.vcpu,
                    redist.ipriorityr.len()
                ));
            }
            once(&mut seen, redist.vcpu, "redist")?;
        }
        let mut seen = vec![false; vcpus as usize];
        for icc in &self.icc {
            once(&mut seen, icc.vcpu, "icc")?;
        }
        Ok(())
    }
}

/// Marks `vcpu` in `seen`, refusing one past the end or seen before.
fn once(seen: &mut [bool], vcpu: u32, what: &str) -> Result<(), String> {
    match seen.get_mut(vcpu as usize) {
        Some(slot) if !*slot => {
            *slot = true;
            Ok(())
        }
        Some(_) => Err(format!("irq: {what} lists vCPU {vcpu} twice")),
        None => Err(format!(
            "irq: {what} lists vCPU {vcpu}, and the machine has {}",
            seen.len()
        )),
    }
}

/// The standard base64 alphabet.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `data` as standard base64 with padding.
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(B64[(n >> shift & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard base64 as [`base64_encode`] writes it, and nothing
/// else: no whitespace, padding only at the end and to a whole group, and
/// no bits set past the last byte.
#[must_use]
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let value = |c: u8| B64.iter().position(|&b| b == c).map(|v| v as u32);
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let groups = bytes.len() / 4;
    for (index, group) in bytes.chunks(4).enumerate() {
        let pad = group.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && index + 1 != groups) {
            return None;
        }
        let mut n = 0u32;
        for &c in &group[..4 - pad] {
            n = n << 6 | value(c)?;
        }
        n <<= 6 * pad as u32;
        let decoded = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // The bits a padded group drops must be zero, or two texts would
        // decode to the same bytes.
        if decoded[3 - pad..].iter().any(|&b| b != 0) {
            return None;
        }
        out.extend_from_slice(&decoded[..3 - pad]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_markers_are_pinned_and_read_back() {
        let state = PlatformState::not_captured(GuestArch::Aarch64, "hvf");
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            json,
            concat!(
                r#"{"version":1,"arch":"aarch64","backend":"hvf","#,
                r#""irq":{"kind":"not-captured","reason":"this hvi does not read the hvf interrupt controller yet"},"#,
                r#""timer":{"kind":"not-captured","reason":"this hvi does not read the hvf guest counter yet"},"#,
                r#""backend_adjunct":null}"#
            )
        );
        assert!(state.is_partial());
        assert_eq!(PlatformState::from_json(json.as_bytes()).unwrap(), state);
        let other = json.replace(r#""version":1"#, r#""version":2"#);
        assert!(PlatformState::from_json(other.as_bytes()).is_err());
        let unknown = json.replace("not-captured", "gic-v9");
        assert!(PlatformState::from_json(unknown.as_bytes()).is_err());
    }

    /// A GICv3 of 32 SPIs and two vCPUs, every register a value of its own.
    pub(crate) fn gic(vcpus: u32) -> GicV3State {
        let words = |n: usize, base: u32| (0..n as u32).map(|i| base + i).collect::<Vec<_>>();
        GicV3State {
            version: 3,
            dist: GicV3Dist {
                ctlr: 0x12,
                igroupr: words(2, 0x10),
                isenabler: words(2, 0x20),
                ispendr: words(2, 0x30),
                isactiver: words(2, 0x40),
                ipriorityr: words(16, 0x50),
                icfgr: words(4, 0x60),
                irouter: (32u32..64)
                    .map(|i| (i.to_string(), u64::from(i % 2)))
                    .collect(),
            },
            redist: (0..vcpus)
                .map(|vcpu| GicV3Redist {
                    vcpu,
                    igroupr0: 1,
                    isenabler0: 2,
                    ispendr0: 3,
                    isactiver0: 4,
                    ipriorityr: words(8, 0x70),
                    icfgr0: 5,
                    icfgr1: 6,
                })
                .collect(),
            icc: (0..vcpus)
                .map(|vcpu| GicV3Icc {
                    vcpu,
                    pmr: 0xf0,
                    bpr0: 1,
                    bpr1: 2,
                    ap0r0: 0,
                    ap1r0: 0,
                    ctlr: 0x400,
                    sre_el1: 7,
                    igrpen0: 0,
                    igrpen1: 1,
                })
                .collect(),
            spi_count: 32,
        }
    }

    #[test]
    fn a_captured_platform_is_pinned_and_reads_back() {
        let mut gic = gic(1);
        gic.dist.irouter = [("32".to_string(), 0)].into();
        gic.dist.igroupr.truncate(1);
        let state = PlatformState {
            version: 1,
            arch: "aarch64".into(),
            backend: "hvf".into(),
            irq: IrqState::HvGicV3(Box::new(gic)),
            timer: TimerState::ArchTimer(ArchTimerState {
                counter_freq_hz: 24_000_000,
                counter_at_capture: 123,
                host_monotonic_at_capture_ns: 456,
            }),
            backend_adjunct: Some(Adjunct::new(HVF_GIC_STATE, b"gic")),
        };
        let json = serde_json::to_string(&state).unwrap();
        let want = format!(
            concat!(
                r#"{{"version":1,"arch":"aarch64","backend":"hvf","#,
                r#""irq":{{"kind":"hv-gic-v3","version":3,"#,
                r#""dist":{{"ctlr":18,"igroupr":[16],"isenabler":[32,33],"ispendr":[48,49],"#,
                r#""isactiver":[64,65],"ipriorityr":[{prio}],"icfgr":[96,97,98,99],"#,
                r#""irouter":{{"32":0}}}},"#,
                r#""redist":[{{"vcpu":0,"igroupr0":1,"isenabler0":2,"ispendr0":3,"#,
                r#""isactiver0":4,"ipriorityr":[112,113,114,115,116,117,118,119],"#,
                r#""icfgr0":5,"icfgr1":6}}],"#,
                r#""icc":[{{"vcpu":0,"pmr":240,"bpr0":1,"bpr1":2,"ap0r0":0,"ap1r0":0,"#,
                r#""ctlr":1024,"sre_el1":7,"igrpen0":0,"igrpen1":1}}],"spi_count":32}},"#,
                r#""timer":{{"kind":"arch-timer","counter_freq_hz":24000000,"#,
                r#""counter_at_capture":123,"host_monotonic_at_capture_ns":456}},"#,
                r#""backend_adjunct":{{"kind":"hvf_gic_state","data_b64":"Z2lj","#,
                r#""sha256":"{sha}"}}}}"#
            ),
            prio = (0x50..0x60)
                .map(|v: u32| v.to_string())
                .collect::<Vec<_>>()
                .join(","),
            sha = sha256_hex(b"gic"),
        );
        assert_eq!(json, want);
        assert!(!state.is_partial());
        assert_eq!(PlatformState::from_json(json.as_bytes()).unwrap(), state);
        assert_eq!(
            state.backend_adjunct.as_ref().unwrap().data().unwrap(),
            b"gic"
        );
    }

    #[test]
    fn canonical_gic_state_is_checked_against_the_machine() {
        let platform = |gic: GicV3State| PlatformState {
            irq: IrqState::HvGicV3(Box::new(gic)),
            ..PlatformState::not_captured(GuestArch::Aarch64, "hvf")
        };
        platform(gic(2)).check(2).unwrap();
        let refused_on = |edit: &dyn Fn(&mut GicV3State), vcpus: u32, want: &str| {
            let mut g = gic(2);
            edit(&mut g);
            let err = platform(g).check(vcpus).unwrap_err();
            assert!(err.contains(want), "{err} lacks {want:?}");
        };
        let refused = |edit: &dyn Fn(&mut GicV3State), want: &str| refused_on(edit, 2, want);
        refused(&|g| g.version = 2, "GIC version 2");
        refused(&|g| g.spi_count = 33, "33 SPIs");
        refused(&|g| g.spi_count = 1024, "1024 SPIs");
        refused(&|g| g.spi_count = 64, "dist.igroupr has 2 registers, 3");
        refused(&|g| g.dist.ipriorityr.push(0), "dist.ipriorityr has 17");
        refused(
            &|g| {
                g.dist.irouter.remove("40");
                g.dist.irouter.insert("64".into(), 0);
            },
            "irouter has interrupt \"64\"",
        );
        refused(
            &|g| {
                g.dist.irouter.remove("40");
                g.dist.irouter.insert("033".into(), 0);
            },
            "irouter has interrupt \"033\"",
        );
        refused(&|g| g.redist[1].vcpu = 0, "redist lists vCPU 0 twice");
        refused_on(&|_| {}, 1, "redist lists vCPU 1, and the machine has 1");
        refused(&|g| g.icc[0].vcpu = 9, "icc lists vCPU 9");
        refused(
            &|g| {
                g.redist[0].ipriorityr.pop();
            },
            "7 priority registers",
        );
        let mut bad = platform(gic(1));
        bad.backend_adjunct = Some(Adjunct {
            kind: HVF_GIC_STATE.into(),
            data_b64: "Z2lj".into(),
            sha256: "00".repeat(32),
        });
        assert!(bad
            .check(1)
            .unwrap_err()
            .contains("does not match its SHA-256"));
        let mut freq = platform(gic(1));
        freq.timer = TimerState::ArchTimer(ArchTimerState {
            counter_freq_hz: 0,
            counter_at_capture: 0,
            host_monotonic_at_capture_ns: 0,
        });
        assert!(freq.check(1).unwrap_err().contains("counter_freq_hz is 0"));
    }

    #[test]
    fn base64_round_trips_and_refuses_what_it_would_not_write() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let text = base64_encode(data);
            assert_eq!(base64_decode(&text).as_deref(), Some(data), "{text}");
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(base64_decode(&base64_encode(&all)).unwrap(), all);
        for bad in [
            "Zm8", "Zm9=", "Zg==Zg==", "Z===", "Zm 9v", "Zm9v\n", "Zh==", "Zm9-",
        ] {
            assert_eq!(base64_decode(bad), None, "{bad:?}");
        }
    }
}

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

//! The machine profile: what a guest was built against, as canonical JSON.
//!
//! A checkpoint holds guest state that only makes sense on a machine the guest
//! cannot tell from the one it booted on. The guest kernel read the CPU's ID
//! registers, the counter frequency and the interrupt controller once, at boot,
//! and never reads them again; RAM and the device windows sit at addresses the
//! devicetree or the boot parameters fixed. [`MachineProfile`] records all of
//! that, and [`MachineProfile::compatible_with`] says whether two machines are
//! the same in every way a restored guest would notice, with one reason per
//! difference. Version 1 is strict: every recorded value must be equal, and a
//! value that could not be read never matches.
//!
//! The JSON is canonical: fields in declaration order, maps sorted by key,
//! register values as `0x`-prefixed lowercase hex strings, no whitespace. Two
//! equal profiles serialize to the same bytes.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::sync::lock_or_recover;

/// The version of the profile format this hvi writes and reads.
pub const PROFILE_VERSION: u32 = 1;

/// The version of the checkpoint bundle format this hvi writes and reads.
pub const CHECKPOINT_FORMAT: u32 = 1;

/// The largest profile [`MachineProfile::from_json`] parses. A real one is a
/// few KiB; the bound keeps a hostile file from costing more than that.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;

/// The value of a build or host identifier that could not be read.
pub const UNKNOWN: &str = "unknown";

/// What a guest was built against. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineProfile {
    /// [`PROFILE_VERSION`] when this hvi wrote it.
    pub profile_version: u32,
    /// The guest architecture, `aarch64` or `x86_64`.
    pub arch: String,
    /// The hypervisor, `hvf` or `kvm`.
    pub backend: String,
    /// The hvi that built the guest.
    pub hvi_build: HviBuild,
    /// [`CHECKPOINT_FORMAT`] when this hvi wrote it.
    pub checkpoint_format: u32,
    /// The host the guest runs on.
    pub host: Host,
    /// The CPU the guest sees.
    pub cpu: Cpu,
    /// The frequency of the counter the guest reads: `CNTFRQ_EL0` on arm64,
    /// the TSC on x86-64. Zero when it could not be read.
    pub counter_freq_hz: u64,
    /// The arm64 interrupt controller, `None` on x86-64.
    pub gic: Option<Gic>,
    /// The x86-64 platform devices, `None` on arm64.
    pub x86: Option<X86Platform>,
    /// The host page size the guest RAM is mapped with.
    pub page_size: u64,
    /// Guest RAM, region by region, as the backing object is laid out.
    pub ram_regions: Vec<RamRegion>,
    /// The number of vCPUs.
    pub vcpus: u32,
    /// The devices the guest was given, in a fixed order per backend.
    pub devices: Vec<Device>,
    /// What the firmware handed the guest kernel.
    pub firmware: Firmware,
    /// Whether the agent vsock bridge is on.
    pub agent_sock: bool,
    /// The number of virtio-fs shares. A share's state is host file handles,
    /// which do not move, so a profile with any is never compatible.
    pub fs_shares: u32,
}

/// The hvi a profile was written by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HviBuild {
    /// The crate version.
    pub version: String,
    /// The commit, with `-dirty` for a tree with uncommitted changes, or
    /// [`UNKNOWN`].
    pub git_sha: String,
}

/// The host a profile was written on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    /// `macos` or `linux`.
    pub os: String,
    /// The macOS build (`kern.osversion`) or the Linux kernel release
    /// (`uname -r`), or [`UNKNOWN`].
    pub kernel_or_macos_build: String,
}

/// The CPU as the guest sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cpu {
    /// The CPU's identity: `MIDR_EL1` as hex on arm64, the vendor, family,
    /// model and stepping on x86-64. `None` until it has been read.
    pub ident: Option<String>,
    /// Feature registers by name, each as hex. On x86-64 the names are CPUID
    /// leaves and the values their four registers.
    pub id_regs: BTreeMap<String, String>,
}

/// The arm64 interrupt controller's version and placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gic {
    /// 2 or 3.
    pub version: u32,
    /// The distributor's base address.
    pub gicd_base: u64,
    /// The distributor's size.
    pub gicd_size: u64,
    /// The redistributor region (v3) or CPU interface (v2) base address.
    pub gicr_base: u64,
    /// The redistributor region (v3) or CPU interface (v2) size.
    pub gicr_size: u64,
}

/// The x86-64 platform devices KVM provides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X86Platform {
    /// Who runs the interrupt controllers; `kvm` for the in-kernel ones.
    pub irqchip: String,
    /// Whether the in-kernel PIT is on.
    pub pit: bool,
}

/// One region of guest RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RamRegion {
    /// The guest physical address of the region.
    pub gpa: u64,
    /// The region's length in bytes.
    pub size: u64,
    /// Where the region starts in the backing object.
    pub file_offset: u64,
}

impl From<crate::memory::RamRegion> for RamRegion {
    fn from(region: crate::memory::RamRegion) -> Self {
        Self {
            gpa: region.gpa,
            size: region.size,
            file_offset: region.file_offset,
        }
    }
}

/// One device the guest was given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// The device model, such as `virtio-blk` or `pl011`.
    pub kind: String,
    /// The MMIO base address, or the I/O port on x86-64.
    pub base: u64,
    /// The GIC INTID on arm64, the GSI on x86-64, `None` for a device with
    /// no interrupt line.
    pub irq: Option<u32>,
    /// The virtio device features as hex, `None` for a device that is not
    /// virtio.
    pub features_hex: Option<String>,
    /// How the device reaches the host, where it has a choice, such as `stub`,
    /// `gateway` or `tap` for the network.
    pub mode: Option<String>,
}

/// What the firmware handed the guest kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Firmware {
    /// The PSCI version the guest is served, as `major.minor`, on arm64.
    pub psci_version: Option<String>,
    /// SHA-256 of the devicetree on arm64, built with its two seeds zeroed:
    /// the seeds are fresh each boot, and the rest of the tree is the layout a
    /// restored guest still holds.
    pub dtb_sha256: Option<String>,
    /// SHA-256 of the boot parameters page on x86-64.
    pub boot_params_sha256: Option<String>,
}

impl MachineProfile {
    /// Returns a profile of this hvi on this host for a guest of `arch` on
    /// `backend`, with every guest-specific field still empty for the backend
    /// to fill.
    #[must_use]
    pub fn for_this_host(arch: &str, backend: &str) -> Self {
        Self {
            profile_version: PROFILE_VERSION,
            arch: arch.to_string(),
            backend: backend.to_string(),
            hvi_build: this_build(),
            checkpoint_format: CHECKPOINT_FORMAT,
            host: this_host(),
            cpu: Cpu {
                ident: None,
                id_regs: BTreeMap::new(),
            },
            counter_freq_hz: 0,
            gic: None,
            x86: None,
            page_size: host_page_size(),
            ram_regions: Vec::new(),
            vcpus: 0,
            devices: Vec::new(),
            firmware: Firmware {
                psci_version: None,
                dtb_sha256: None,
                boot_params_sha256: None,
            },
            agent_sock: false,
            fs_shares: 0,
        }
    }

    /// Returns the canonical JSON of the profile, on one line.
    #[must_use]
    pub fn to_json(&self) -> String {
        // Serializing plain structs, strings, integers and a BTreeMap cannot
        // fail.
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parses a profile from `json`, refusing one above [`MAX_PROFILE_BYTES`].
    ///
    /// # Errors
    ///
    /// Errors when the text is too long or is not a profile.
    pub fn from_json(json: &str) -> Result<Self, String> {
        if json.len() > MAX_PROFILE_BYTES {
            return Err(format!(
                "profile is {} bytes, above the {MAX_PROFILE_BYTES}-byte limit",
                json.len()
            ));
        }
        serde_json::from_str(json).map_err(|e| format!("not a machine profile: {e}"))
    }

    /// Returns whether a guest built against `self` can run on `other`
    /// without noticing the move.
    ///
    /// `self` is the source, whose guest was captured, and `other` the
    /// destination. The rules are version 1's: every recorded value must be
    /// equal, a value either side could not read never matches, and neither
    /// side may have virtio-fs shares.
    ///
    /// # Errors
    ///
    /// Errors with one reason per difference, each naming the field and both
    /// values.
    pub fn compatible_with(&self, other: &Self) -> Result<(), Vec<String>> {
        let mut why = Vec::new();
        for (side, p) in [("source", self), ("destination", other)] {
            if p.profile_version != PROFILE_VERSION {
                why.push(format!(
                    "profile_version: the {side} is version {}, this hvi reads {PROFILE_VERSION}",
                    p.profile_version
                ));
            }
            if p.checkpoint_format != CHECKPOINT_FORMAT {
                why.push(format!(
                    "checkpoint_format: the {side} writes format {}, this hvi reads \
                     {CHECKPOINT_FORMAT}",
                    p.checkpoint_format
                ));
            }
            if p.hvi_build.git_sha == UNKNOWN {
                why.push(format!(
                    "hvi_build.git_sha: the {side}'s hvi does not know its commit"
                ));
            }
            if p.cpu.ident.is_none() {
                why.push(format!("cpu.ident: the {side}'s CPU identity was not read"));
            }
            if p.counter_freq_hz == 0 {
                why.push(format!(
                    "counter_freq_hz: the {side}'s counter frequency was not read"
                ));
            }
            if p.fs_shares != 0 {
                why.push(format!(
                    "fs_shares: the {side} has {} virtio-fs share(s), whose host file \
                     handles cannot move",
                    p.fs_shares
                ));
            }
        }
        let mut differ = |field: &str, a: String, b: String| {
            if a != b {
                why.push(format!(
                    "{field}: {a} on the source, {b} on the destination"
                ));
            }
        };
        differ("arch", self.arch.clone(), other.arch.clone());
        differ("backend", self.backend.clone(), other.backend.clone());
        differ(
            "hvi_build.git_sha",
            self.hvi_build.git_sha.clone(),
            other.hvi_build.git_sha.clone(),
        );
        differ("host.os", self.host.os.clone(), other.host.os.clone());
        // Hypervisor.framework's GIC state blob is versioned by the OS and may
        // be refused by any other build, so an hvf guest moves only between
        // hosts on the same macOS build. KVM's GIC state is architectural.
        if self.backend == "hvf" {
            differ(
                "host.kernel_or_macos_build",
                self.host.kernel_or_macos_build.clone(),
                other.host.kernel_or_macos_build.clone(),
            );
        }
        differ(
            "counter_freq_hz",
            self.counter_freq_hz.to_string(),
            other.counter_freq_hz.to_string(),
        );
        if let (Some(a), Some(b)) = (&self.cpu.ident, &other.cpu.ident) {
            differ("cpu.ident", a.clone(), b.clone());
        }
        let names: std::collections::BTreeSet<&String> = self
            .cpu
            .id_regs
            .keys()
            .chain(other.cpu.id_regs.keys())
            .collect();
        for name in names {
            let read = |p: &Self| {
                p.cpu
                    .id_regs
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| "absent".to_string())
            };
            differ(&format!("cpu.id_regs.{name}"), read(self), read(other));
        }
        differ("gic", json(&self.gic), json(&other.gic));
        differ("x86", json(&self.x86), json(&other.x86));
        differ(
            "page_size",
            self.page_size.to_string(),
            other.page_size.to_string(),
        );
        differ(
            "ram_regions",
            json(&self.ram_regions),
            json(&other.ram_regions),
        );
        differ("vcpus", self.vcpus.to_string(), other.vcpus.to_string());
        if self.devices.len() != other.devices.len() {
            differ(
                "devices",
                format!("{} devices", self.devices.len()),
                format!("{} devices", other.devices.len()),
            );
        }
        for (index, (a, b)) in self.devices.iter().zip(&other.devices).enumerate() {
            differ(&format!("devices[{index}]"), json(a), json(b));
        }
        differ(
            "firmware.psci_version",
            json(&self.firmware.psci_version),
            json(&other.firmware.psci_version),
        );
        differ(
            "firmware.dtb_sha256",
            json(&self.firmware.dtb_sha256),
            json(&other.firmware.dtb_sha256),
        );
        differ(
            "firmware.boot_params_sha256",
            json(&self.firmware.boot_params_sha256),
            json(&other.firmware.boot_params_sha256),
        );
        differ(
            "agent_sock",
            self.agent_sock.to_string(),
            other.agent_sock.to_string(),
        );
        if why.is_empty() {
            Ok(())
        } else {
            Err(why)
        }
    }
}

/// The profile of the running guest, shared by the thread that boots it, the
/// boot vCPU and the control socket, with the file it is written to.
///
/// A backend creates it before confinement, since the profile file cannot be
/// created after. The profile is complete once [`complete`](Self::complete)
/// has run, which writes the file. On KVM that happens before the guest
/// starts. Hypervisor.framework shows `MIDR_EL1` only to a vCPU's own thread,
/// so on hvf the boot vCPU completes the profile before the guest's first
/// instruction, and the file is written then, through the descriptor opened
/// before confinement.
pub(crate) struct ProfileCell {
    /// The profile, whether it is complete, and the file still to write.
    state: Mutex<CellState>,
    /// Signals that the profile is complete.
    ready: Condvar,
}

/// The state behind [`ProfileCell`].
struct CellState {
    /// The profile, complete or not.
    profile: MachineProfile,
    /// Whether [`ProfileCell::complete`] has run.
    complete: bool,
    /// The file the complete profile goes to, with its path for a report,
    /// until it has been written.
    out: Option<(String, std::fs::File)>,
}

impl ProfileCell {
    /// Returns a cell holding `profile`, not yet complete, and creates the
    /// file at `out`, empty, when there is one.
    ///
    /// # Errors
    ///
    /// Errors when the file cannot be created.
    // The host-path ban in clippy.toml is aimed at the virtio-fs device. This
    // path is the operator's.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn new(profile: MachineProfile, out: Option<&str>) -> std::io::Result<Self> {
        let out = match out {
            Some(path) => {
                let file = std::fs::File::create(path).map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!("cannot create the profile file {path}: {e}"),
                    )
                })?;
                Some((path.to_string(), file))
            }
            None => None,
        };
        Ok(Self {
            state: Mutex::new(CellState {
                profile,
                complete: false,
                out,
            }),
            ready: Condvar::new(),
        })
    }

    /// Applies `finish` to the profile, marks it complete and writes the file.
    ///
    /// Only the first call does anything; a later one returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// Errors when the file cannot be written. The profile is complete
    /// anyway, so the control socket still reports it.
    pub(crate) fn complete(&self, finish: impl FnOnce(&mut MachineProfile)) -> std::io::Result<()> {
        let mut state = lock_or_recover(&self.state);
        if state.complete {
            return Ok(());
        }
        finish(&mut state.profile);
        state.complete = true;
        self.ready.notify_all();
        let Some((path, mut file)) = state.out.take() else {
            return Ok(());
        };
        let line = state.profile.to_json() + "\n";
        file.write_all(line.as_bytes()).map_err(|e| {
            std::io::Error::new(e.kind(), format!("writing the profile file {path}: {e}"))
        })
    }

    /// Returns the profile once it is complete, waiting for at most
    /// `timeout`, or `None` when it is not complete by then.
    pub(crate) fn get(&self, timeout: Duration) -> Option<MachineProfile> {
        let state = lock_or_recover(&self.state);
        let (state, _) = self
            .ready
            .wait_timeout_while(state, timeout, |state| !state.complete)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.complete.then(|| state.profile.clone())
    }
}

/// Returns a device entry for the profile.
#[must_use]
pub fn device(kind: &str, base: u64, irq: Option<u32>, features: Option<u64>) -> Device {
    Device {
        kind: kind.to_string(),
        base,
        irq,
        features_hex: features.map(hex),
        mode: None,
    }
}

/// Returns `value` as compact JSON, for a reason that quotes it.
fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Returns `value` as the profile writes a register: `0x`, lowercase hex.
#[must_use]
pub fn hex(value: u64) -> String {
    format!("{value:#x}")
}

/// Returns the SHA-256 of `bytes` as lowercase hex.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Returns the build of the running hvi.
#[must_use]
pub fn this_build() -> HviBuild {
    HviBuild {
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_sha: env!("HVI_GIT_SHA").to_string(),
    }
}

/// Returns the host's page size.
#[must_use]
pub fn host_page_size() -> u64 {
    // SAFETY: sysconf takes no pointer and only reads.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(size).unwrap_or(0)
}

/// Returns the host the calling process runs on.
#[must_use]
pub fn this_host() -> Host {
    #[cfg(target_os = "macos")]
    let (os, build) = ("macos", macos_build());
    #[cfg(target_os = "linux")]
    let (os, build) = ("linux", linux_release());
    Host {
        os: os.to_string(),
        kernel_or_macos_build: build.unwrap_or_else(|| UNKNOWN.to_string()),
    }
}

/// Returns the macOS build, such as `25G62`, from `kern.osversion`.
#[cfg(target_os = "macos")]
fn macos_build() -> Option<String> {
    let mut buf = [0u8; 64];
    let mut len = buf.len();
    // SAFETY: the name is NUL-terminated, `buf` holds `len` bytes, and no
    // new value is passed.
    let ret = unsafe {
        libc::sysctlbyname(
            c"kern.osversion".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return None;
    }
    let text = buf.get(..len)?.split(|b| *b == 0).next()?;
    String::from_utf8(text.to_vec())
        .ok()
        .filter(|s| !s.is_empty())
}

/// Returns the Linux kernel release, as `uname -r` prints it.
#[cfg(target_os = "linux")]
fn linux_release() -> Option<String> {
    // SAFETY: `utsname` is plain bytes, so zeroed is a valid value.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `uts` is a live, writable utsname.
    if unsafe { libc::uname(&mut uts) } != 0 {
        return None;
    }
    // SAFETY: uname NUL-terminates the field, which lives as long as `uts`.
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
    release
        .to_str()
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Returns `CNTFRQ_EL0`, the frequency of the counter an arm64 guest reads.
///
/// The register is readable at EL0 on macOS and on Linux, and no hypervisor
/// here lets the guest see another value, so the host's is the guest's.
#[cfg(target_arch = "aarch64")]
#[must_use]
pub fn counter_freq_hz() -> u64 {
    let freq: u64;
    // SAFETY: reads a system register EL0 may read; no memory is touched.
    unsafe {
        std::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack, preserves_flags));
    }
    freq
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete arm64 profile, as an hvf boot with a disk and the agent
    /// socket writes it.
    fn sample() -> MachineProfile {
        MachineProfile {
            profile_version: PROFILE_VERSION,
            arch: "aarch64".into(),
            backend: "hvf".into(),
            hvi_build: HviBuild {
                version: "0.1.0".into(),
                git_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            },
            checkpoint_format: CHECKPOINT_FORMAT,
            host: Host {
                os: "macos".into(),
                kernel_or_macos_build: "25G62".into(),
            },
            cpu: Cpu {
                ident: Some("0x611f0490".into()),
                id_regs: [
                    ("ID_AA64ISAR0_EL1", "0x221100110212120"),
                    ("ID_AA64PFR0_EL1", "0x1100000011111112"),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            },
            counter_freq_hz: 24_000_000,
            gic: Some(Gic {
                version: 3,
                gicd_base: 0x0800_0000,
                gicd_size: 0x1_0000,
                gicr_base: 0x080a_0000,
                gicr_size: 0x2_0000,
            }),
            x86: None,
            page_size: 16384,
            ram_regions: vec![RamRegion {
                gpa: 0x4000_0000,
                size: 512 << 20,
                file_offset: 0,
            }],
            vcpus: 2,
            devices: vec![
                Device {
                    kind: "pl011".into(),
                    base: 0x0900_0000,
                    irq: Some(33),
                    features_hex: None,
                    mode: None,
                },
                Device {
                    kind: "virtio-blk".into(),
                    base: 0x0a00_0000,
                    irq: Some(48),
                    features_hex: Some("0x100000200".into()),
                    mode: None,
                },
            ],
            firmware: Firmware {
                psci_version: Some("1.0".into()),
                dtb_sha256: Some("ab".repeat(32)),
                boot_params_sha256: None,
            },
            agent_sock: true,
            fs_shares: 0,
        }
    }

    /// Returns the reasons `a` is refused for `b`, or none.
    fn reasons(a: &MachineProfile, b: &MachineProfile) -> Vec<String> {
        a.compatible_with(b).err().unwrap_or_default()
    }

    /// Asserts that changing the destination with `change` is refused with
    /// exactly one reason, which names `field`.
    fn refused_for(field: &str, change: impl FnOnce(&mut MachineProfile)) {
        let mut other = sample();
        change(&mut other);
        let why = reasons(&sample(), &other);
        assert_eq!(why.len(), 1, "{field}: {why:?}");
        assert!(
            why[0].starts_with(&format!("{field}: ")),
            "{field}: {why:?}"
        );
    }

    #[test]
    fn identical_profiles_are_compatible() {
        assert_eq!(sample().compatible_with(&sample()), Ok(()));
    }

    // The bytes are the format: hull stores them and compares them, and a
    // second reader in another language parses them. Pinned in full so a
    // reordered field or a changed spelling is a deliberate change.
    #[test]
    fn canonical_json_is_pinned() {
        let mut p = sample();
        p.devices.truncate(1);
        p.cpu.id_regs.retain(|k, _| k == "ID_AA64PFR0_EL1");
        assert_eq!(
            p.to_json(),
            concat!(
                r#"{"profile_version":1,"arch":"aarch64","backend":"hvf","#,
                r#""hvi_build":{"version":"0.1.0","git_sha":"0123456789abcdef0123456789abcdef01234567"},"#,
                r#""checkpoint_format":1,"host":{"os":"macos","kernel_or_macos_build":"25G62"},"#,
                r#""cpu":{"ident":"0x611f0490","id_regs":{"ID_AA64PFR0_EL1":"0x1100000011111112"}},"#,
                r#""counter_freq_hz":24000000,"#,
                r#""gic":{"version":3,"gicd_base":134217728,"gicd_size":65536,"gicr_base":134873088,"gicr_size":131072},"#,
                r#""x86":null,"page_size":16384,"#,
                r#""ram_regions":[{"gpa":1073741824,"size":536870912,"file_offset":0}],"vcpus":2,"#,
                r#""devices":[{"kind":"pl011","base":150994944,"irq":33,"features_hex":null,"mode":null}],"#,
                r#""firmware":{"psci_version":"1.0","dtb_sha256":"abababababababababababababababababababababababababababababababab","boot_params_sha256":null},"#,
                r#""agent_sock":true,"fs_shares":0}"#,
            )
        );
    }

    #[test]
    fn json_round_trips_and_sorts_registers() {
        let p = sample();
        let text = p.to_json();
        assert!(text.find("ID_AA64ISAR0_EL1") < text.find("ID_AA64PFR0_EL1"));
        assert_eq!(MachineProfile::from_json(&text), Ok(p));
    }

    #[test]
    fn oversized_or_malformed_json_is_refused() {
        let long = " ".repeat(MAX_PROFILE_BYTES + 1);
        assert!(MachineProfile::from_json(&long)
            .unwrap_err()
            .contains("limit"));
        assert!(MachineProfile::from_json(r#"{"profile_version":1}"#)
            .unwrap_err()
            .starts_with("not a machine profile"));
    }

    #[test]
    fn each_field_that_differs_is_named() {
        refused_for("arch", |p| p.arch = "x86_64".into());
        refused_for("backend", |p| p.backend = "kvm".into());
        refused_for("hvi_build.git_sha", |p| {
            p.hvi_build.git_sha = "fedcba9876543210fedcba9876543210fedcba98".into();
        });
        refused_for("host.os", |p| p.host.os = "linux".into());
        refused_for("host.kernel_or_macos_build", |p| {
            p.host.kernel_or_macos_build = "25H1".into();
        });
        refused_for("counter_freq_hz", |p| p.counter_freq_hz = 54_000_000);
        refused_for("cpu.ident", |p| p.cpu.ident = Some("0x414fd0b1".into()));
        refused_for("cpu.id_regs.ID_AA64PFR0_EL1", |p| {
            p.cpu
                .id_regs
                .insert("ID_AA64PFR0_EL1".into(), "0x1100000011111111".into());
        });
        refused_for("gic", |p| p.gic.as_mut().unwrap().version = 2);
        refused_for("gic", |p| p.gic.as_mut().unwrap().gicr_size = 0x4_0000);
        refused_for("x86", |p| {
            p.x86 = Some(X86Platform {
                irqchip: "kvm".into(),
                pit: true,
            });
        });
        refused_for("page_size", |p| p.page_size = 4096);
        refused_for("ram_regions", |p| p.ram_regions[0].size = 256 << 20);
        refused_for("vcpus", |p| p.vcpus = 4);
        refused_for("devices[1]", |p| {
            p.devices[1].features_hex = Some("0x100000000".into());
        });
        refused_for("devices[0]", |p| p.devices[0].irq = Some(34));
        refused_for("devices[0]", |p| p.devices[0].mode = Some("stub".into()));
        refused_for("devices", |p| {
            p.devices.pop();
        });
        refused_for("firmware.psci_version", |p| {
            p.firmware.psci_version = Some("1.1".into());
        });
        refused_for("firmware.dtb_sha256", |p| {
            p.firmware.dtb_sha256 = Some("cd".repeat(32));
        });
        refused_for("firmware.boot_params_sha256", |p| {
            p.firmware.boot_params_sha256 = Some("ef".repeat(32));
        });
        refused_for("agent_sock", |p| p.agent_sock = false);
    }

    // A register one host reports and the other does not is a difference: the
    // guest may have read it.
    #[test]
    fn a_register_only_one_side_has_is_named() {
        refused_for("cpu.id_regs.CTR_EL0", |p| {
            p.cpu.id_regs.insert("CTR_EL0".into(), "0x80038003".into());
        });
        let mut fewer = sample();
        fewer.cpu.id_regs.remove("ID_AA64ISAR0_EL1");
        let why = reasons(&sample(), &fewer);
        assert_eq!(
            why,
            [
                "cpu.id_regs.ID_AA64ISAR0_EL1: 0x221100110212120 on the source, absent on the \
              destination"
            ]
        );
    }

    // KVM's GIC state is architectural, so two KVM hosts on different kernels
    // can still match.
    #[test]
    fn kvm_hosts_may_run_different_kernels() {
        let mut a = sample();
        a.backend = "kvm".into();
        a.host.os = "linux".into();
        a.host.kernel_or_macos_build = "6.12.25".into();
        let mut b = a.clone();
        b.host.kernel_or_macos_build = "6.12.47".into();
        assert_eq!(a.compatible_with(&b), Ok(()));
    }

    // A value nobody could read must never compare equal to another value
    // nobody could read, or two unknowns would pass the check.
    #[test]
    fn unknown_values_never_match() {
        let mut a = sample();
        a.hvi_build.git_sha = UNKNOWN.into();
        a.cpu.ident = None;
        a.counter_freq_hz = 0;
        let why = reasons(&a, &a);
        assert!(why
            .iter()
            .any(|w| w.starts_with("hvi_build.git_sha: the source")));
        assert!(why
            .iter()
            .any(|w| w.starts_with("cpu.ident: the destination")));
        assert!(why
            .iter()
            .any(|w| w.starts_with("counter_freq_hz: the source")));
        assert_eq!(why.len(), 6, "{why:?}");
    }

    #[test]
    fn shares_are_refused_on_either_side() {
        let mut shared = sample();
        shared.fs_shares = 1;
        assert!(reasons(&shared, &shared)
            .iter()
            .any(|w| w.starts_with("fs_shares: the source has 1")));
        let why = reasons(&sample(), &shared);
        assert!(why
            .iter()
            .any(|w| w.starts_with("fs_shares: the destination")));
    }

    #[test]
    fn other_versions_are_refused() {
        let mut v2 = sample();
        v2.profile_version = 2;
        v2.checkpoint_format = 2;
        let why = reasons(&sample(), &v2);
        assert_eq!(
            why,
            [
                "profile_version: the destination is version 2, this hvi reads 1",
                "checkpoint_format: the destination writes format 2, this hvi reads 1",
            ]
        );
    }

    #[test]
    fn every_reason_is_reported_at_once() {
        let mut other = sample();
        other.vcpus = 1;
        other.page_size = 4096;
        other.counter_freq_hz = 54_000_000;
        assert_eq!(reasons(&sample(), &other).len(), 3);
    }

    #[test]
    fn sha256_matches_the_standard_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn this_build_records_a_commit() {
        let build = this_build();
        assert_eq!(build.version, env!("CARGO_PKG_VERSION"));
        assert!(!build.git_sha.is_empty());
    }

    #[test]
    fn a_profile_for_this_host_is_filled_where_the_host_decides() {
        let p = MachineProfile::for_this_host("aarch64", "hvf");
        assert_eq!(p.profile_version, PROFILE_VERSION);
        assert_eq!(p.hvi_build, this_build());
        assert_eq!(p.page_size, host_page_size());
        assert_eq!(p.cpu.ident, None);
    }

    /// Returns a path for a profile file of this test process.
    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hvi-profile-{}-{name}.json", std::process::id()))
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn the_file_is_created_at_once_and_written_when_complete() {
        let path = temp_path("write");
        let cell = ProfileCell::new(sample(), path.to_str()).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        cell.complete(|p| p.vcpus = 3).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut want = sample();
        want.vcpus = 3;
        assert_eq!(text, want.to_json() + "\n");
        // A second completion changes nothing, on disk or in the cell.
        cell.complete(|p| p.vcpus = 9).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        assert_eq!(cell.get(Duration::ZERO), Some(want));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_incomplete_profile_is_not_reported() {
        let cell = std::sync::Arc::new(ProfileCell::new(sample(), None).unwrap());
        assert_eq!(cell.get(Duration::from_millis(10)), None);
        let waiter = {
            let cell = std::sync::Arc::clone(&cell);
            std::thread::spawn(move || cell.get(Duration::from_secs(5)))
        };
        std::thread::sleep(Duration::from_millis(20));
        cell.complete(|p| p.cpu.ident = Some("0x1".into())).unwrap();
        let got = waiter
            .join()
            .unwrap()
            .expect("the waiter saw the completion");
        assert_eq!(got.cpu.ident.as_deref(), Some("0x1"));
    }

    #[test]
    fn a_profile_file_that_cannot_be_created_is_an_error() {
        let err = ProfileCell::new(sample(), Some("/nonexistent-dir/p.json"))
            .err()
            .expect("no such directory");
        assert!(err.to_string().contains("/nonexistent-dir/p.json"), "{err}");
    }

    #[test]
    fn host_facts_are_read() {
        assert!(host_page_size().is_power_of_two());
        assert_ne!(this_host().kernel_or_macos_build, UNKNOWN);
        #[cfg(target_arch = "aarch64")]
        assert_ne!(counter_freq_hz(), 0);
    }
}

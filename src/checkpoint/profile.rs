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

/// The version of the profile format this hvi writes and reads.
pub const PROFILE_VERSION: u32 = 1;

/// The newest checkpoint format this hvi writes and reads: 2, the streamed
/// bundle of a live move. A profile carries it, so a mover can tell an hvi
/// that streams from one that writes only the bundle directory, format 1,
/// which this hvi still writes for `checkpoint` and reads.
pub const CHECKPOINT_FORMAT: u32 = 2;

/// The largest profile [`MachineProfile::from_json`] parses. A real one is a
/// few KiB; the bound keeps a hostile file from costing more than that.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;

/// The value of a build or host identifier that could not be read.
pub const UNKNOWN: &str = "unknown";

/// The suffix of the commit of an hvi built from a tree with uncommitted
/// changes. No profile check accepts it.
pub const DIRTY: &str = "-dirty";

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
    /// The number of virtio-blk disks after the first. A checkpoint and a
    /// move carry one disk, so a profile with any is never compatible. Not
    /// written when 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub extra_disks: u32,
    /// Whether a disk of the guest is read-only. A checkpoint and a move
    /// carry a writable disk, so a profile with one is never compatible. Not
    /// written when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disk_read_only: bool,
    /// The machine profile the guest was given, as `--profile` names it.
    /// [`NATIVE`] is not written, so a native profile reads as it did before
    /// portable profiles existed.
    #[serde(default = "native", skip_serializing_if = "is_native")]
    pub profile: String,
    /// A portable profile's CPU baseline: the ID registers every host gives
    /// the guest, by name, as hex. Not written on the native profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BTreeMap<String, String>>,
    /// A portable profile's interrupt controller. Not written on the native
    /// profile, whose controller is `gic`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub irq: Option<Irq>,
    /// A portable profile's clock and timer device. Not written on the
    /// native profile, whose guest uses the architected timer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<Time>,
    /// The SHA-256 of the disk as the boot given `--disk-base-sha256`
    /// opened it, before that hvi wrote it, as lowercase hex. A restore
    /// carries it on. A mover that holds that image sends only the blocks
    /// the guest wrote, see `disk-dirty`. It describes the disk's history,
    /// not the machine, so no compatibility check reads it. Not written
    /// when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_base_sha256: Option<String>,
}

/// The name of the native machine profile.
pub const NATIVE: &str = "native";

fn native() -> String {
    NATIVE.to_string()
}

#[allow(clippy::ptr_arg)] // serde passes the field as it is declared
fn is_native(profile: &String) -> bool {
    profile == NATIVE
}

/// A portable profile's interrupt controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Irq {
    /// `gicv2`.
    pub kind: String,
    /// Where the guest finds it.
    pub layout: Gic,
}

/// A portable profile's clock and timer device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Time {
    /// `hvi-time`.
    pub kind: String,
    /// The rate of the counter under the device on this host. The guest
    /// reads time in nanoseconds, so two hosts may differ here.
    pub counter_freq_hz: u64,
    /// The guest physical address of the pvclock page.
    pub page_base: u64,
    /// The guest physical address of the timer blocks.
    pub timers_base: u64,
    /// The timers' GIC interrupt ID.
    pub intid: u32,
}

/// The hvi a profile was written by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HviBuild {
    /// The crate version.
    pub version: String,
    /// The commit, with [`DIRTY`] appended for a tree with uncommitted
    /// changes, or [`UNKNOWN`].
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
    /// leaves and the values their four registers. A register the backend
    /// asked for and could not read is recorded as [`UNKNOWN`] rather than
    /// left out, so that two hosts that both fail to read it do not match.
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

#[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
fn is_false(b: &bool) -> bool {
    !*b
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
            extra_disks: 0,
            disk_read_only: false,
            profile: native(),
            baseline: None,
            irq: None,
            time: None,
            disk_base_sha256: None,
        }
    }

    /// Records the disks a guest was given: how many there are after the
    /// first, and whether one is read-only.
    pub fn set_disks(&mut self, disks: &[crate::config::DiskConfig]) {
        self.extra_disks = u32::try_from(disks.len().saturating_sub(1)).unwrap_or(u32::MAX);
        self.disk_read_only = disks.iter().any(|disk| disk.read_only);
    }

    /// Refuses a guest whose disks a checkpoint or a move cannot carry: one
    /// with more than one disk, or whose disk is read-only. The bundle, the
    /// dirty bitmap and the disk rounds all name one writable disk.
    ///
    /// # Errors
    ///
    /// Errors with the reason, which the control socket sends as its refusal.
    pub fn one_writable_disk(&self) -> Result<(), String> {
        if self.extra_disks != 0 {
            return Err(format!(
                "the guest has {} virtio-blk disks, and a checkpoint or a move carries one",
                u64::from(self.extra_disks) + 1
            ));
        }
        if self.disk_read_only {
            return Err(
                "the guest's disk is read-only, and a checkpoint or a move carries a writable one"
                    .into(),
            );
        }
        Ok(())
    }

    /// Returns the reasons the disks of `self`, the `side` of a move, cannot
    /// move, as [`one_writable_disk`](Self::one_writable_disk) has them.
    fn disk_refusals(&self, side: &str) -> Vec<String> {
        let mut why = Vec::new();
        if self.extra_disks != 0 {
            why.push(format!(
                "extra_disks: the {side} has {} virtio-blk disks, and a checkpoint or a move \
                 carries one",
                u64::from(self.extra_disks) + 1
            ));
        }
        if self.disk_read_only {
            why.push(format!(
                "disk_read_only: the {side}'s disk is read-only, and a checkpoint or a move \
                 carries a writable one"
            ));
        }
        why
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
    /// A portable profile has rules of its own; see
    /// [`portable_compatible_with`](Self::portable_compatible_with).
    ///
    /// # Errors
    ///
    /// Errors with one reason per difference, each naming the field and both
    /// values.
    pub fn compatible_with(&self, other: &Self) -> Result<(), Vec<String>> {
        if self.profile != NATIVE || other.profile != NATIVE {
            return self.portable_compatible_with(other);
        }
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
            // Two different sets of uncommitted changes on one commit record
            // the same sha, and device state is only defined by the code that
            // wrote it.
            if p.hvi_build.git_sha.ends_with(DIRTY) {
                why.push(format!(
                    "hvi_build.git_sha: the {side}'s hvi was built with uncommitted changes"
                ));
            }
            if p.cpu.ident.is_none() {
                why.push(format!("cpu.ident: the {side}'s CPU identity was not read"));
            }
            for (name, value) in &p.cpu.id_regs {
                if value == UNKNOWN {
                    why.push(format!("cpu.id_regs.{name}: the {side} could not read it"));
                }
            }
            // The macOS build is what keeps the hv_gic state blob readable,
            // below.
            if p.backend == "hvf" && p.host.kernel_or_macos_build == UNKNOWN {
                why.push(format!(
                    "host.kernel_or_macos_build: the {side}'s macOS build was not read"
                ));
            }
            // The firmware's handover is part of what the guest kernel holds,
            // so the digest its architecture has must be there.
            let firmware: &[(&str, &Option<String>)] = match p.arch.as_str() {
                "aarch64" => &[
                    ("firmware.psci_version", &p.firmware.psci_version),
                    ("firmware.dtb_sha256", &p.firmware.dtb_sha256),
                ],
                "x86_64" => &[(
                    "firmware.boot_params_sha256",
                    &p.firmware.boot_params_sha256,
                )],
                _ => &[],
            };
            for (field, value) in firmware {
                if value.is_none() {
                    why.push(format!("{field}: the {side}'s was not read"));
                }
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
            why.extend(p.disk_refusals(side));
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
            let (a, b) = (read(self), read(other));
            // An unread register is already a reason, above.
            if a != UNKNOWN && b != UNKNOWN {
                differ(&format!("cpu.id_regs.{name}"), a, b);
            }
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

impl MachineProfile {
    /// Returns whether a guest built against the portable profile `self`
    /// can run on `other`, which may be another host and another hypervisor.
    ///
    /// The guest of a portable profile sees the profile's machine, not the
    /// host's, so the rules compare what the profile fixes and leave out
    /// what it hides:
    ///
    /// - Compared: the profile's name, the profile and checkpoint formats, the
    ///   hvi commit, the architecture, the CPU baseline, the interrupt
    ///   controller, the clock device but for its counter rate, RAM, the vCPUs,
    ///   the devices but for how each reaches the host, the PSCI version, the
    ///   devicetree digest and the agent socket.
    /// - Not compared: the hypervisor, the host, the counter rate (the guest
    ///   reads nanoseconds), the CPU's identity and ID registers as read (the
    ///   baseline is what the guest sees; `CTR_EL0` and `CLIDR_EL1` differ
    ///   between a Mac and a Pi and neither can be set), and the host page
    ///   size, which need only be 4 KiB or 16 KiB on the destination.
    ///
    /// Whether the destination host can present the baseline at all is
    /// its backend's check, at its boot: Hypervisor.framework compares the
    /// baseline with the host's registers, KVM also needs a vGICv2, a 40-bit
    /// guest address space and writable fields (`portable::kvm_host_problems`).
    ///
    /// # Errors
    ///
    /// Errors with one reason per difference.
    pub fn portable_compatible_with(&self, other: &Self) -> Result<(), Vec<String>> {
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
            // As for the native machine: device state is only defined by
            // the code that wrote it.
            if p.hvi_build.git_sha.ends_with(DIRTY) {
                why.push(format!(
                    "hvi_build.git_sha: the {side}'s hvi was built with uncommitted changes"
                ));
            }
            if p.fs_shares != 0 {
                why.push(format!(
                    "fs_shares: the {side} has {} virtio-fs share(s), whose host file \
                     handles cannot move",
                    p.fs_shares
                ));
            }
            why.extend(p.disk_refusals(side));
            if p.profile != NATIVE && (p.baseline.is_none() || p.irq.is_none() || p.time.is_none())
            {
                why.push(format!(
                    "profile: the {side}'s {} profile lacks its baseline, irq or time",
                    p.profile
                ));
            }
        }
        if !matches!(other.page_size, 0x1000 | 0x4000) {
            why.push(format!(
                "page_size: the destination maps guest RAM with {}-byte pages; a portable \
                 guest needs 4 KiB or 16 KiB",
                other.page_size
            ));
        }
        let mut differ = |field: &str, a: String, b: String| {
            if a != b {
                why.push(format!(
                    "{field}: {a} on the source, {b} on the destination"
                ));
            }
        };
        differ("profile", self.profile.clone(), other.profile.clone());
        differ("arch", self.arch.clone(), other.arch.clone());
        differ(
            "hvi_build.git_sha",
            self.hvi_build.git_sha.clone(),
            other.hvi_build.git_sha.clone(),
        );
        differ("baseline", json(&self.baseline), json(&other.baseline));
        differ("irq", json(&self.irq), json(&other.irq));
        // The counter rate is the host's; the guest reads nanoseconds.
        let device = |p: &Self| {
            json(&p.time.as_ref().map(|t| Time {
                counter_freq_hz: 0,
                ..t.clone()
            }))
        };
        differ("time", device(self), device(other));
        differ("gic", json(&self.gic), json(&other.gic));
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
        // How a device reaches the host (the network's stub, gateway or
        // tap) is the host's business; the guest sees the same device.
        for (index, (a, b)) in self.devices.iter().zip(&other.devices).enumerate() {
            let seen = |d: &Device| {
                json(&Device {
                    mode: None,
                    ..d.clone()
                })
            };
            differ(&format!("devices[{index}]"), seen(a), seen(b));
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
        let mut state = self.state.lock().unwrap();
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
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .ready
            .wait_timeout_while(state, timeout, |state| !state.complete)
            .unwrap();
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
            extra_disks: 0,
            disk_read_only: false,
            profile: native(),
            baseline: None,
            irq: None,
            time: None,
            disk_base_sha256: None,
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
                r#""checkpoint_format":2,"host":{"os":"macos","kernel_or_macos_build":"25G62"},"#,
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

    // The disk's base digest is history, not machine: two profiles that
    // differ only in it are compatible, and it is written only when known.
    #[test]
    fn the_disk_base_is_recorded_and_never_compared() {
        let (a, mut b) = (sample(), sample());
        b.disk_base_sha256 = Some("ab".repeat(32));
        assert_eq!(a.compatible_with(&b), Ok(()));
        assert_eq!(b.compatible_with(&a), Ok(()));
        assert!(!a.to_json().contains("disk_base_sha256"));
        let json = b.to_json();
        assert!(
            json.ends_with(&format!(r#","disk_base_sha256":"{}"}}"#, "ab".repeat(32))),
            "{json}"
        );
        assert_eq!(MachineProfile::from_json(&json).unwrap(), b);
    }

    /// The profile a portable guest writes on a Mac: `sample` with the
    /// portable fields.
    fn portable_mac() -> MachineProfile {
        let v2 = Gic {
            version: 2,
            gicd_base: 0x0800_0000,
            gicd_size: 0x1_0000,
            gicr_base: 0x0801_0000,
            gicr_size: 0x1_0000,
        };
        let mut p = sample();
        p.profile = "portable-arm64-v1".into();
        p.cpu.ident = Some("0x414fd0b1".into());
        p.cpu.id_regs.insert("CTR_EL0".into(), "0x99444c004".into());
        p.gic = Some(v2.clone());
        p.firmware.psci_version = Some("1.1".into());
        p.baseline = Some(
            [
                ("MIDR_EL1", "0x414fd0b1"),
                ("ID_AA64PFR0_EL1", "0x1100000010110011"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        );
        p.irq = Some(Irq {
            kind: "gicv2".into(),
            layout: v2,
        });
        p.time = Some(Time {
            kind: "hvi-time".into(),
            counter_freq_hz: 24_000_000,
            page_base: 0x0d10_0000,
            timers_base: 0x0d11_0000,
            intid: 20,
        });
        p.devices[1].mode = Some("stub".into());
        p
    }

    /// The same guest's profile on a Pi: another hypervisor, host, counter
    /// rate, register reads and network mode.
    fn portable_pi() -> MachineProfile {
        let mut p = portable_mac();
        p.backend = "kvm".into();
        p.host = Host {
            os: "linux".into(),
            kernel_or_macos_build: "6.12.25+rpt-rpi-2712".into(),
        };
        p.counter_freq_hz = 54_000_000;
        if let Some(t) = p.time.as_mut() {
            t.counter_freq_hz = 54_000_000;
        }
        p.cpu.id_regs.insert("CTR_EL0".into(), "0x9444c004".into());
        p.cpu
            .id_regs
            .insert("ID_AA64PFR0_EL1".into(), "0x1100000010110011".into());
        p.devices[1].mode = Some("tap".into());
        p
    }

    #[test]
    fn a_portable_guest_moves_between_a_mac_and_a_pi() {
        assert_eq!(portable_mac().compatible_with(&portable_pi()), Ok(()));
        assert_eq!(portable_pi().compatible_with(&portable_mac()), Ok(()));
        // The native rules would have refused it on six counts.
        let mut as_native = (portable_mac(), portable_pi());
        as_native.0.profile = NATIVE.into();
        as_native.1.profile = NATIVE.into();
        assert!(reasons(&as_native.0, &as_native.1).len() >= 5);
    }

    #[test]
    fn a_portable_profile_compares_what_the_guest_sees() {
        let refused = |field: &str, change: &dyn Fn(&mut MachineProfile)| {
            let mut other = portable_pi();
            change(&mut other);
            let why = reasons(&portable_mac(), &other);
            assert_eq!(why.len(), 1, "{field}: {why:?}");
            assert!(why[0].starts_with(&format!("{field}: ")), "{why:?}");
        };
        refused("baseline", &|p| {
            p.baseline
                .as_mut()
                .unwrap()
                .insert("ID_AA64ISAR0_EL1".into(), "0x1".into());
        });
        refused("irq", &|p| p.irq.as_mut().unwrap().layout.gicd_base = 0);
        refused("time", &|p| {
            p.time.as_mut().unwrap().kind = "kvm-clock".into()
        });
        refused("time", &|p| p.time.as_mut().unwrap().intid = 27);
        refused("firmware.dtb_sha256", &|p| {
            p.firmware.dtb_sha256 = Some("cd".repeat(32));
        });
        refused("vcpus", &|p| p.vcpus = 1);
        refused("ram_regions", &|p| p.ram_regions[0].size = 256 << 20);
        refused("devices[1]", &|p| p.devices[1].irq = Some(49));
        refused("firmware.psci_version", &|p| {
            p.firmware.psci_version = Some("1.0".into());
        });
        refused("hvi_build.git_sha", &|p| {
            p.hvi_build.git_sha = "f".repeat(40)
        });
        refused("page_size", &|p| p.page_size = 0x1_0000);
        refused("fs_shares", &|p| p.fs_shares = 1);
        refused("agent_sock", &|p| p.agent_sock = false);
        // A 4 KiB destination is fine.
        let mut four_k = portable_pi();
        four_k.page_size = 0x1000;
        assert_eq!(portable_mac().compatible_with(&four_k), Ok(()));
    }

    #[test]
    fn a_portable_build_with_uncommitted_changes_never_matches() {
        let (mac, pi) = (portable_mac(), portable_pi());
        for (dirty_mac, dirty_pi) in [(true, false), (false, true)] {
            let (mut a, mut b) = (mac.clone(), pi.clone());
            if dirty_mac {
                a.hvi_build.git_sha += DIRTY;
            }
            if dirty_pi {
                b.hvi_build.git_sha += DIRTY;
            }
            let why = a.portable_compatible_with(&b).unwrap_err();
            let side = if dirty_mac { "source" } else { "destination" };
            assert!(
                why.contains(&format!(
                    "hvi_build.git_sha: the {side}'s hvi was built with uncommitted changes"
                )),
                "{why:?}"
            );
        }
    }

    #[test]
    fn a_portable_guest_never_lands_on_a_native_one() {
        let mut native_pi = portable_pi();
        native_pi.profile = NATIVE.into();
        native_pi.baseline = None;
        native_pi.irq = None;
        native_pi.time = None;
        let why = reasons(&portable_mac(), &native_pi);
        assert!(
            why.iter()
                .any(|w| w == "profile: portable-arm64-v1 on the source, native on the destination"),
            "{why:?}"
        );
        assert!(why.iter().any(|w| w.starts_with("baseline: ")), "{why:?}");
        assert!(!reasons(&native_pi, &portable_mac()).is_empty());
        // A portable profile missing its contract is refused outright.
        let mut bare = portable_mac();
        bare.time = None;
        assert!(reasons(&bare, &bare)
            .iter()
            .any(|w| w.contains("lacks its baseline, irq or time")));
    }

    /// The portable fields are written after the native ones, and a native
    /// profile writes none of them, so its bytes are as they were.
    #[test]
    fn portable_fields_are_written_only_for_a_portable_profile() {
        let native_json = sample().to_json();
        for key in ["\"profile\":", "\"baseline\":", "\"irq\":{", "\"time\":"] {
            assert!(!native_json.contains(key), "{key} in {native_json}");
        }
        let p = portable_mac();
        let text = p.to_json();
        assert!(text.ends_with(concat!(
            r#""fs_shares":0,"profile":"portable-arm64-v1","#,
            r#""baseline":{"ID_AA64PFR0_EL1":"0x1100000010110011","MIDR_EL1":"0x414fd0b1"},"#,
            r#""irq":{"kind":"gicv2","layout":{"version":2,"gicd_base":134217728,"gicd_size":65536,"gicr_base":134283264,"gicr_size":65536}},"#,
            r#""time":{"kind":"hvi-time","counter_freq_hz":24000000,"page_base":219152384,"timers_base":219217920,"intid":20}}"#,
        )), "{text}");
        assert_eq!(MachineProfile::from_json(&text), Ok(p));
        // A profile written before the fields existed reads as native.
        assert_eq!(
            MachineProfile::from_json(&native_json).unwrap().profile,
            NATIVE
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
        // Not x86_64, whose profile would also lack its boot page digest.
        refused_for("arch", |p| p.arch = "riscv64".into());
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
        a.cpu
            .id_regs
            .insert("DCZID_EL0".into(), UNKNOWN.to_string());
        a.host.kernel_or_macos_build = UNKNOWN.into();
        a.firmware.psci_version = None;
        a.firmware.dtb_sha256 = None;
        let why = reasons(&a, &a);
        for field in [
            "hvi_build.git_sha",
            "cpu.ident",
            "counter_freq_hz",
            "cpu.id_regs.DCZID_EL0",
            "host.kernel_or_macos_build",
            "firmware.psci_version",
            "firmware.dtb_sha256",
        ] {
            for side in ["source", "destination"] {
                assert!(
                    why.iter()
                        .any(|w| w.starts_with(&format!("{field}: the {side}"))),
                    "{field} on the {side}: {why:?}"
                );
            }
        }
        assert_eq!(why.len(), 14, "{why:?}");
    }

    // A register read on one side and not on the other is named once, as
    // unread, not again as a difference.
    #[test]
    fn a_register_one_side_could_not_read_is_named_once() {
        refused_for("cpu.id_regs.ID_AA64PFR0_EL1", |p| {
            p.cpu
                .id_regs
                .insert("ID_AA64PFR0_EL1".into(), UNKNOWN.to_string());
        });
    }

    // KVM's GIC state does not depend on the kernel, so an unread kernel
    // release is no reason to refuse; an x86 guest needs its boot page digest
    // and has no devicetree.
    #[test]
    fn unread_values_are_refused_only_where_they_count() {
        let mut a = sample();
        a.backend = "kvm".into();
        a.host.kernel_or_macos_build = UNKNOWN.into();
        assert_eq!(a.compatible_with(&a), Ok(()));
        a.arch = "x86_64".into();
        a.firmware = Firmware {
            psci_version: None,
            dtb_sha256: None,
            boot_params_sha256: Some("ef".repeat(32)),
        };
        assert_eq!(a.compatible_with(&a), Ok(()));
        a.firmware.boot_params_sha256 = None;
        assert!(reasons(&a, &a)
            .iter()
            .any(|w| w.starts_with("firmware.boot_params_sha256: the source")));
    }

    // The suffix says only that the tree had changes, not which, so two
    // builds that both carry it are not known to be the same code.
    #[test]
    fn a_build_with_uncommitted_changes_never_matches() {
        let mut dirty = sample();
        dirty.hvi_build.git_sha += DIRTY;
        let why = reasons(&dirty, &dirty);
        assert_eq!(
            why,
            [
                "hvi_build.git_sha: the source's hvi was built with uncommitted changes",
                "hvi_build.git_sha: the destination's hvi was built with uncommitted changes",
            ]
        );
    }

    // A checkpoint and a move carry one writable disk: the bundle, the dirty
    // bitmap and the disk rounds name it. A second disk, or a read-only one,
    // is refused on either side, on the native profile and the portable one.
    #[test]
    fn a_second_disk_or_a_read_only_one_is_refused_on_either_side() {
        for base in [sample(), portable_mac()] {
            let mut two = base.clone();
            two.extra_disks = 1;
            let mut ro = base.clone();
            ro.disk_read_only = true;
            assert!(reasons(&two, &base).iter().any(|w| w
                == "extra_disks: the source has 2 virtio-blk disks, and a checkpoint or a move \
                    carries one"));
            assert!(reasons(&base, &two)
                .iter()
                .any(|w| w.starts_with("extra_disks: the destination has 2")));
            assert!(reasons(&ro, &base)
                .iter()
                .any(|w| w.starts_with("disk_read_only: the source's disk is read-only")));
            assert!(reasons(&base, &ro)
                .iter()
                .any(|w| w.starts_with("disk_read_only: the destination's disk")));
            assert_eq!(base.one_writable_disk(), Ok(()));
            assert!(two
                .one_writable_disk()
                .unwrap_err()
                .contains("2 virtio-blk disks"));
            assert!(ro.one_writable_disk().unwrap_err().contains("read-only"));
        }
        // A guest of one writable disk writes neither field, so its profile
        // reads as it did before they existed.
        let mut one = sample();
        one.set_disks(&[crate::config::DiskConfig::rw("/a.img")]);
        let json = one.to_json();
        assert!(
            !json.contains("extra_disks") && !json.contains("disk_read_only"),
            "{json}"
        );
        one.set_disks(&[
            crate::config::DiskConfig::rw("/a.img"),
            crate::config::DiskConfig::ro("/b.img"),
        ]);
        assert!(one
            .to_json()
            .ends_with(r#","extra_disks":1,"disk_read_only":true}"#));
        assert_eq!(MachineProfile::from_json(&one.to_json()), Ok(one));
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
        v2.checkpoint_format = 3;
        let why = reasons(&sample(), &v2);
        assert_eq!(
            why,
            [
                "profile_version: the destination is version 2, this hvi reads 1",
                "checkpoint_format: the destination writes format 3, this hvi reads 2",
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

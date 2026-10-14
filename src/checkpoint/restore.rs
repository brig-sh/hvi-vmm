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

//! `hvi restore`: the parts every backend's restore shares.
//!
//! [`import`] loads a bundle's vCPUs and interrupt controller into vCPUs
//! that a backend has created and parked, in three steps, each one posted to
//! every vCPU and waited for before the next:
//!
//! 1. each vCPU loads its registers and its timer;
//! 2. vCPU 0 loads the interrupt controller, once every vCPU exists and none
//!    has run, as `hv_gic_set_state` requires: the import waits for the backend
//!    to have created every vCPU, the ones that were off as well, before it
//!    posts the first step;
//! 3. each vCPU loads its own part of the interrupt controller, its CPU
//!    interface, which step 2 reset.
//!
//! The waits between the steps are the barriers. The guest runs only once a
//! client sends `resume`.
//!
//! Before any of that, [`open`] reads the bundle and parses every document,
//! and [`refusals`] lists every reason this host cannot resume it: a part a
//! restore cannot load, a kind of interrupt controller or counter this
//! backend has no import for, and a disk, network or agent socket that does
//! not match what the guest had. The backend adds the differences between the
//! bundle's machine profile and its own, and refuses with all of them before
//! it creates anything.

// The x86-64 backend cannot restore yet.
#![cfg_attr(target_arch = "x86_64", allow(dead_code))]

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::checkpoint::bundle::{Bundle, Component, DevicesDoc, DiskState, Session};
use crate::checkpoint::cpu::{arch_name, ImportPlan, ImportStep, Power, VcpuState, MAX_VCPUS};
use crate::checkpoint::profile::{host_page_size, MachineProfile};
use crate::checkpoint::ram;
use crate::config::{DiskConfig, RestoreConfig};
use crate::devices::virtio::block::BlkState;
use crate::devices::virtio::net::NetMode;
use crate::hypervisor::vcpus::{Kick, Vcpus, WorkResult};
use crate::plugin::GuestArch;

/// The import steps, in the order [`import`] posts them.
// Only HVF loads the vCPUs on their own threads; KVM loads them before
// they run.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub(crate) const IMPORT_STEPS: [ImportStep; 3] =
    [ImportStep::Vcpu, ImportStep::Platform, ImportStep::IrqCpu];

/// Returns whether `state` is of a vCPU that starts on its own at a restore,
/// and so takes part in the import: one that ran, or one whose `CPU_ON` the
/// guest had sent. One that is off waits for the guest, as at boot.
// Only HVF loads the vCPUs on their own threads; KVM loads them before
// they run.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
fn starts(state: &VcpuState) -> bool {
    match state {
        VcpuState::Aarch64(v) => v.power != Power::Off,
        VcpuState::X86_64(_) => true,
    }
}

/// Loads `plan` into the vCPUs, in the three steps of [`IMPORT_STEPS`].
///
/// The caller holds the vCPUs paused from the control socket, so each one
/// parks at its first checkpoint, before it enters the guest. `created`
/// returns how many vCPUs the backend has created. Every vCPU must have been
/// created, and every one that [`starts`] must have started, within
/// `timeout`, before the first step is posted: a vCPU that was off takes no
/// part in the import, but the interrupt controller of the second step holds
/// its state too, and the hypervisor loads it only once every vCPU exists.
/// Each step must then finish within `timeout` of its post.
///
/// # Errors
///
/// Errors, naming the vCPU and the step, when a vCPU was not created or did
/// not start, did not finish a step in time, or could not load its part; or
/// when the VM stopped.
// Only HVF loads the vCPUs on their own threads; KVM loads them before
// they run.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub(crate) fn import<K: Kick>(
    vcpus: &Vcpus<K>,
    plan: &Arc<ImportPlan>,
    timeout: Duration,
    created: impl Fn() -> u32,
) -> Result<(), String> {
    let total = u32::try_from(plan.vcpus.len()).unwrap_or(u32::MAX);
    let expected = plan.vcpus.iter().filter(|v| starts(v)).count() as u32;
    let deadline = Instant::now() + timeout;
    while vcpus.started() < expected || created() < total {
        if !vcpus.is_running() {
            return Err("the run ended before the vCPUs started".to_string());
        }
        if Instant::now() >= deadline {
            return Err(if created() < total {
                format!("{} of {total} vCPUs were created in time", created())
            } else {
                format!("{} of {expected} vCPUs started in time", vcpus.started())
            });
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    for step in IMPORT_STEPS {
        vcpus.request_import(step, Arc::clone(plan));
        let waited = vcpus.wait_work(timeout);
        let results = vcpus.end_work();
        waited.map_err(|e| format!("{step:?} step: {e}"))?;
        for (cpu, (result, state)) in results.iter().zip(&plan.vcpus).enumerate() {
            match result {
                WorkResult::Done(_) => {}
                WorkResult::Failed(why) => {
                    return Err(format!("vCPU {cpu}, {step:?} step: {why}"));
                }
                WorkResult::NotStarted if starts(state) => {
                    return Err(format!("vCPU {cpu}, {step:?} step: it did not take part"));
                }
                WorkResult::NotStarted => {}
            }
        }
    }
    Ok(())
}

/// What a backend's restore can load.
pub(crate) struct Restorer {
    /// The guest architecture.
    pub(crate) arch: GuestArch,
    /// `hvf` or `kvm`: this host's backend.
    pub(crate) backend: &'static str,
    /// The backends whose bundles it takes: its own, and for the portable
    /// profile, whose machine is the same on both, the other one too.
    pub(crate) sources: &'static [&'static str],
    /// The machine profiles, by name, whose guests it rebuilds.
    pub(crate) profiles: &'static [&'static str],
    /// The `irq` kinds of `platform.json` it has an import for.
    pub(crate) irq_kinds: &'static [&'static str],
    /// The `timer` kinds it has an import for.
    pub(crate) timer_kinds: &'static [&'static str],
    /// The adjunct kind it loads its interrupt controller from, if any.
    pub(crate) adjunct: Option<&'static str>,
    /// The manifest capabilities it provides.
    pub(crate) capabilities: &'static [&'static str],
}

/// Returns the restore of the portable profile on `backend`: the GICv2 in
/// its canonical form and `hvi-time`, from a bundle of either backend.
pub(crate) const fn portable(backend: &'static str) -> Restorer {
    Restorer {
        arch: GuestArch::Aarch64,
        backend,
        sources: &["hvf", "kvm"],
        profiles: &["portable-arm64-v1"],
        irq_kinds: &["gicv2"],
        timer_kinds: &["hvi-time"],
        adjunct: None,
        capabilities: &[],
    }
}

/// A bundle opened for a restore, with every document read and parsed.
pub(crate) struct Opened {
    /// The bundle, every component's size and hash checked.
    pub(crate) bundle: Bundle,
    /// The vCPUs and the platform to import.
    pub(crate) plan: Arc<ImportPlan>,
    /// The devices and their line levels.
    pub(crate) devices: DevicesDoc,
    /// The disk the guest had, when it had one.
    pub(crate) disk: Option<DiskState>,
    /// Who captured it.
    pub(crate) session: Session,
}

impl Opened {
    /// Returns the source's machine profile.
    pub(crate) fn profile(&self) -> &MachineProfile {
        self.bundle.profile()
    }
}

/// Opens the bundle at `dir` and reads every document in it.
///
/// [`Bundle::open_for_restore`] checks the manifest against its limits and
/// every component's size and hash, but for the hash of `ram.bin`:
/// [`Bundle::load_ram`] checks that as it copies the image into the new
/// guest's RAM, before any device, disk or socket exists. This then checks
/// `ram.map` against the manifest and parses `cpu.json`, `platform.json`,
/// `devices.json`, `disk.json` and `session.json`. Nothing is allocated by a
/// count the manifest or a document gives before that count is checked.
///
/// # Errors
///
/// Errors, naming the file, on the first thing that does not hold.
pub(crate) fn open(dir: &Path) -> std::io::Result<Opened> {
    let bundle = Bundle::open_for_restore(dir)?;
    ram::check_map(
        &bundle.read(Component::RamMap)?,
        &bundle.manifest().ram.regions,
    )?;
    let cpu = bundle.cpu()?;
    let platform = bundle.platform()?;
    let devices = bundle.devices()?;
    let disk = bundle.disk()?;
    let session = bundle.session()?;
    Ok(Opened {
        bundle,
        plan: Arc::new(ImportPlan {
            vcpus: cpu.vcpus,
            platform,
        }),
        devices,
        disk,
        session,
    })
}

/// Returns every reason `can` cannot resume `opened` with the host
/// resources `cfg` names. An empty list means it can, as far as the bundle
/// and the flags show; the backend adds what only its own machine profile
/// shows.
#[must_use]
pub(crate) fn refusals(opened: &Opened, cfg: &RestoreConfig, can: &Restorer) -> Vec<String> {
    let mut why = Vec::new();
    let profile = opened.profile();
    let plan = &opened.plan;
    let arch = arch_name(can.arch);
    if profile.arch != arch || !can.sources.contains(&profile.backend.as_str()) {
        why.push(format!(
            "profile.json: an {} guest on {}, and this hvi restores {arch} guests from {} \
             on {}{}",
            profile.arch,
            profile.backend,
            can.sources.join(" or "),
            can.backend,
            if can.sources.len() == 1 {
                " (only the portable profile moves between backends)"
            } else {
                ""
            }
        ));
    }
    if !can.profiles.contains(&profile.profile.as_str()) {
        why.push(format!(
            "profile.json: a {} guest, which this hvi does not restore on {}",
            profile.profile, can.backend
        ));
    }
    let vcpus_ok = profile.vcpus != 0 && profile.vcpus as usize <= MAX_VCPUS;
    if !vcpus_ok {
        why.push(format!(
            "profile.json: {} vCPUs, a restore takes 1 to {MAX_VCPUS}",
            profile.vcpus
        ));
    }
    if plan.vcpus.len() != profile.vcpus as usize {
        why.push(format!(
            "cpu.json: {} vCPUs, the profile has {}",
            plan.vcpus.len(),
            profile.vcpus
        ));
    }
    let page = host_page_size();
    for region in &profile.ram_regions {
        if region.size == 0 || region.size % page != 0 || region.gpa % page != 0 {
            why.push(format!(
                "profile.json: RAM region {:#x}+{:#x} is not whole {page}-byte host pages",
                region.gpa, region.size
            ));
        }
    }
    for vcpu in &plan.vcpus {
        match vcpu {
            VcpuState::Aarch64(v) if can.arch == GuestArch::Aarch64 => {
                if let Err(e) = v.check_restorable() {
                    why.push(format!("cpu.json: {e}"));
                }
            }
            other => why.push(format!(
                "cpu.json: vCPU {} is not a state this hvi loads",
                other.id()
            )),
        }
    }
    let platform = &plan.platform;
    if platform.arch != profile.arch || platform.backend != profile.backend {
        why.push("platform.json: not of the profile's arch and backend".to_string());
    }
    if !can.irq_kinds.contains(&platform.irq.kind()) {
        why.push(format!(
            "platform.json: the interrupt controller is {}, which this hvi cannot \
             restore on {}",
            platform.irq.kind(),
            can.backend,
        ));
    }
    if !can.timer_kinds.contains(&platform.timer.kind()) {
        why.push(format!(
            "platform.json: the counter is {}, which this hvi cannot restore on {}",
            platform.timer.kind(),
            can.backend,
        ));
    }
    let adjunct = platform.backend_adjunct.as_ref().map(|a| a.kind.as_str());
    if can.adjunct.is_some() && adjunct != can.adjunct {
        why.push(format!(
            "platform.json: the {} blob is missing",
            can.adjunct.unwrap_or_default()
        ));
    }
    // The check allocates by the count, so it runs only on one that is
    // within bounds; the reason for one that is not is given above.
    if vcpus_ok {
        if let Err(e) = platform.check(profile.vcpus) {
            why.push(format!("platform.json: {e}"));
        }
    }
    for capability in &opened.bundle.manifest().capabilities {
        if !can.capabilities.contains(&capability.as_str()) {
            why.push(format!(
                "manifest.json: the bundle needs {capability}, which this hvi does not have"
            ));
        }
    }
    why.extend(device_refusals(opened, cfg, can));
    why
}

/// Returns why `given`, the restore's `--disk`, asks for another serial or
/// mode than `blk`, the bundle's disk, has. The restored disk answers `GET_ID`
/// with the bundle's serial, which the guest reads from
/// `/sys/block/vdX/serial`, and a checkpoint is only taken of a writable disk.
fn disk_mode_refusals(blk: &BlkState, given: &DiskConfig) -> Vec<String> {
    let bundle = format!(
        "the bundle's disk has serial={} and readonly={}",
        blk.serial,
        if blk.read_only { "on" } else { "off" }
    );
    let mut why = Vec::new();
    if given.read_only {
        why.push(format!(
            "--disk {}: readonly=on, and {bundle}: a restored guest writes its disk",
            given.path
        ));
    }
    if let Some(serial) = given.serial.as_ref().filter(|s| **s != blk.serial) {
        why.push(format!(
            "--disk {}: serial={serial}, and {bundle}: the guest finds its disk by its serial",
            given.path
        ));
    }
    why
}

/// Returns every reason the host resources `cfg` names do not match the
/// devices the guest had.
fn device_refusals(opened: &Opened, cfg: &RestoreConfig, can: &Restorer) -> Vec<String> {
    let mut why = Vec::new();
    let states = &opened.devices.states;
    if let (Some(blk), Some(given)) = (&states.blk, &cfg.disk) {
        why.extend(disk_mode_refusals(blk, given));
    }
    match (&states.blk, &cfg.disk, &opened.disk) {
        (Some(blk), Some(given), Some(disk)) => {
            let path = &given.path;
            let want = blk.capacity_sectors.saturating_mul(512);
            // The device checks the size again when it opens the disk; this
            // is so a wrong disk is refused with the other reasons, before
            // anything is created.
            #[allow(clippy::disallowed_methods)]
            match std::fs::metadata(path) {
                Ok(meta) if meta.is_file() && meta.len() != want => why.push(format!(
                    "--disk {path}: {} bytes, the guest was given {want}",
                    meta.len()
                )),
                Ok(_) => {}
                Err(e) => why.push(format!("--disk {path}: {e}")),
            }
            if disk.size_bytes != want {
                why.push(format!(
                    "disk.json: {} bytes, and devices.json gives the guest {want}",
                    disk.size_bytes
                ));
            }
        }
        (Some(_), None, _) => {
            why.push("the guest had a disk; give it with --disk".to_string());
        }
        (None, Some(given), _) => {
            why.push(format!("--disk {}: the guest had no disk", given.path));
        }
        (Some(_), Some(_), None) => why.push("disk.json is missing".to_string()),
        (None, None, _) => {}
    }
    let given = match (cfg.net, &cfg.net_gateway) {
        (true, Some(_)) => {
            why.push("--net-stub and --net-gateway are each a network; give one".to_string());
            None
        }
        (true, None) => Some(NetMode::Stub),
        (false, Some(_)) => Some(NetMode::Gateway),
        (false, None) => None,
    };
    match (&states.net, given) {
        (Some(net), Some(mode)) if net.mode != mode => why.push(format!(
            "the guest ran on a {} network, and this restore gives it a {} one",
            net_mode(net.mode),
            net_mode(mode)
        )),
        (Some(net), None) => why.push(format!(
            "the guest had a {} network; give it with {}",
            net_mode(net.mode),
            match net.mode {
                NetMode::Stub => "--net-stub",
                NetMode::Gateway => "--net-gateway",
                NetMode::Tap => "--net-tap, which a restore does not take",
            }
        )),
        (None, Some(mode)) => why.push(format!(
            "the guest had no network, and this restore gives it a {} one",
            net_mode(mode)
        )),
        _ => {}
    }
    if let (Some(net), Some(mac)) = (&states.net, cfg.net_mac) {
        if net.mac != mac {
            why.push(format!(
                "--net-mac {}: the guest answers to {}",
                mac_text(mac),
                mac_text(net.mac)
            ));
        }
    }
    match (&states.vsock, &cfg.agent_sock) {
        (Some(_), None) => {
            why.push("the guest had an agent socket; give it with --agent-sock".to_string());
        }
        (None, Some(path)) => why.push(format!("--agent-sock {path}: the guest had none")),
        _ => {}
    }
    if can.arch == GuestArch::Aarch64 && states.pl011.is_none() {
        why.push("devices.json: the guest has no PL011".to_string());
    }
    if opened.profile().fs_shares != 0 {
        why.push(format!(
            "profile.json: {} virtio-fs share(s), which a checkpoint never moves",
            opened.profile().fs_shares
        ));
    }
    why
}

/// Returns a network mode's name, as the flags call it.
fn net_mode(mode: NetMode) -> &'static str {
    match mode {
        NetMode::Stub => "stub",
        NetMode::Gateway => "gateway",
        NetMode::Tap => "tap",
    }
}

/// Returns a MAC address as `--net-mac` takes it.
fn mac_text(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Returns every difference between the source's machine profile and this
/// host's, `local`, each prefixed with `profile`.
#[must_use]
pub(crate) fn profile_refusals(source: &MachineProfile, local: &MachineProfile) -> Vec<String> {
    source
        .compatible_with(local)
        .err()
        .unwrap_or_default()
        .into_iter()
        .map(|why| format!("profile: {why}"))
        .collect()
}

/// The refusal of a restore, with every reason.
#[derive(Debug)]
pub(crate) struct Refused(pub(crate) Vec<String>);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "this host cannot resume the bundle:")?;
        for why in &self.0 {
            write!(f, "\n  - {why}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Refused {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::checkpoint::cpu::{Output, Work};
    use crate::checkpoint::platform::PlatformState;
    use crate::plugin::GuestArch;
    use std::sync::Mutex;
    use std::thread::JoinHandle;

    /// A kicker that reaches no thread; the fake vCPUs poll.
    #[derive(Default)]
    pub(crate) struct NoKick;

    impl Kick for NoKick {
        fn kick(&self, _cpu: u32) {}
        fn kick_all(&self) {}
        fn try_kick_all(&self) -> bool {
            true
        }
    }

    /// What each fake vCPU did, in the order they did it.
    pub(crate) type Log = Arc<Mutex<Vec<(u32, ImportStep)>>>;

    /// Spawns fake vCPU `cpu`, which starts, parks at every checkpoint and
    /// logs each import step it carries out on its own state. vCPU 0 alone
    /// logs the platform step, as only it loads the controller. It exports
    /// the plugin register view, so a capture of it works.
    pub(crate) fn importing_vcpu<K: Kick + 'static>(
        vcpus: &Arc<Vcpus<K>>,
        cpu: u32,
        log: &Log,
        fail: Option<ImportStep>,
    ) -> JoinHandle<()> {
        let (vcpus, log) = (Arc::clone(vcpus), Arc::clone(log));
        std::thread::spawn(move || {
            vcpus.mark_started(vcpus.started());
            while vcpus.is_running() {
                let _ = vcpus.checkpoint_with(cpu, |work| match work {
                    Work::Import(step, _) if Some(step) == fail => {
                        Err(std::io::Error::other("the hypervisor refused it"))
                    }
                    Work::Import(ImportStep::Platform, _) if cpu != 0 => Ok(None),
                    Work::Import(step, plan) => {
                        assert_eq!(plan.vcpus[cpu as usize].id(), cpu);
                        log.lock().unwrap().push((cpu, step));
                        Ok(None)
                    }
                    Work::Export => Ok(Some(Output::Vcpu {
                        state: VcpuState::from_regs_view(
                            GuestArch::Aarch64,
                            "hvf",
                            cpu,
                            &crate::plugin::RegsView::default(),
                        ),
                        irq: None,
                    })),
                    Work::ExportPlatform => Ok(None),
                });
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    }

    /// A plan of `on` vCPUs that ran and `off` ones that never did.
    pub(crate) fn plan(on: u32, off: u32) -> Arc<ImportPlan> {
        let arch = GuestArch::Aarch64;
        Arc::new(ImportPlan {
            vcpus: (0..on + off)
                .map(|cpu| {
                    let state = VcpuState::powered_off(arch, "hvf", cpu);
                    match state {
                        VcpuState::Aarch64(mut v) if cpu < on => {
                            v.power = Power::On;
                            VcpuState::Aarch64(v)
                        }
                        other => other,
                    }
                })
                .collect(),
            platform: PlatformState::not_captured(arch, "hvf"),
        })
    }

    /// Checks that every vCPU finished each step before any began the next.
    pub(crate) fn assert_barriers(log: &[(u32, ImportStep)], vcpus: u32) {
        let n = vcpus as usize;
        assert_eq!(log.len(), 2 * n + 1, "{log:?}");
        let sorted = |part: &[(u32, ImportStep)]| {
            let mut part = part.to_vec();
            part.sort_unstable_by_key(|(cpu, _)| *cpu);
            part
        };
        let every = |step| (0..vcpus).map(|cpu| (cpu, step)).collect::<Vec<_>>();
        assert_eq!(sorted(&log[..n]), every(ImportStep::Vcpu), "{log:?}");
        assert_eq!(log[n], (0, ImportStep::Platform), "{log:?}");
        assert_eq!(sorted(&log[n + 1..]), every(ImportStep::IrqCpu), "{log:?}");
    }

    use crate::checkpoint::bundle::{
        unix_ms, BundleWriter, Component, DevicesDoc, DiskState, IrqLevels, Session, DOC_VERSION,
    };
    use crate::checkpoint::cpu::CpuState;
    use crate::checkpoint::platform::{
        Adjunct, ArchTimerState, IrqState, TimerState, HVF_GIC_STATE, HVF_GIC_STATE_CAPABILITY,
    };
    use crate::checkpoint::profile::RamRegion;
    use crate::devices::legacy::pl011::Pl011;
    use crate::devices::state::DeviceStates;
    use crate::devices::virtio::block::VirtioBlk;
    use crate::devices::virtio::net::VirtioNet;
    use crate::devices::virtio::vsock::VirtioVsock;
    use crate::memory::GuestRam;
    use std::path::PathBuf;

    /// What the HVF restore loads.
    const HVF: Restorer = Restorer {
        arch: GuestArch::Aarch64,
        backend: "hvf",
        sources: &["hvf"],
        profiles: &["native"],
        irq_kinds: &["hv-gic-v3"],
        timer_kinds: &["arch-timer"],
        adjunct: Some(HVF_GIC_STATE),
        capabilities: &[HVF_GIC_STATE_CAPABILITY],
    };

    /// Where the test guests' RAM starts.
    const GPA: u64 = 0x4000_0000;

    /// The bundle a test writes, which it may change before the write.
    struct Parts {
        profile: MachineProfile,
        vcpus: Vec<VcpuState>,
        platform: PlatformState,
        states: DeviceStates,
        disk: Option<DiskState>,
        capabilities: Vec<String>,
    }

    /// A scratch directory with a disk image, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        #[allow(clippy::disallowed_methods)]
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("hvi-restore-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("disk.img"), vec![0u8; 1 << 20]).unwrap();
            Self(dir)
        }

        fn disk(&self) -> String {
            self.0.join("disk.img").display().to_string()
        }

        fn bundle(&self) -> PathBuf {
            self.0.join("ck")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            #[allow(clippy::disallowed_methods)]
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The parts of a whole two-vCPU HVF bundle over `scratch`'s disk, with a
    /// stub network, an agent socket and the console.
    fn parts(scratch: &Scratch) -> Parts {
        let size = 2u64 << 20;
        let mut profile = MachineProfile::for_this_host("aarch64", "hvf");
        profile.ram_regions = vec![RamRegion {
            gpa: GPA,
            size,
            file_offset: 0,
        }];
        profile.vcpus = 2;
        let mem = GuestRam::from_ranges(&[(GPA, size as usize)]);
        let blk = VirtioBlk::open_as(&scratch.disk(), false, "disk0")
            .unwrap()
            .state();
        Parts {
            profile,
            vcpus: (0..2)
                .map(|cpu| VcpuState::Aarch64(crate::checkpoint::cpu::tests::whole(cpu)))
                .collect(),
            platform: PlatformState {
                irq: IrqState::HvGicV3(Box::new(crate::checkpoint::platform::tests::gic(2))),
                timer: TimerState::ArchTimer(ArchTimerState {
                    counter_freq_hz: 24_000_000,
                    counter_at_capture: 1,
                    host_monotonic_at_capture_ns: 2,
                }),
                backend_adjunct: Some(Adjunct::new(HVF_GIC_STATE, b"blob")),
                ..PlatformState::not_captured(GuestArch::Aarch64, "hvf")
            },
            disk: Some(DiskState {
                version: DOC_VERSION,
                path_hint: scratch.disk(),
                size_bytes: blk.capacity_sectors * 512,
                sha256_sparse: None,
                generation: 0,
                synced: true,
            }),
            states: DeviceStates {
                blk: Some(blk),
                net: Some(VirtioNet::new().state()),
                vsock: Some(VirtioVsock::new().state()),
                pl011: Some(Pl011::new().state()),
                ..DeviceStates::default()
            },
            capabilities: vec![HVF_GIC_STATE_CAPABILITY.to_string()],
        }
        .checked(&mem)
    }

    impl Parts {
        /// Checks the device states as a capture would.
        fn checked(self, mem: &GuestRam) -> Self {
            self.states.check(mem).unwrap();
            self
        }

        /// Writes and seals the bundle at `dir`.
        fn write(self, dir: &Path) {
            let ram = GuestRam::from_ranges(&[(GPA, self.profile.ram_regions[0].size as usize)]);
            ram.write(GPA + 0x2000, b"guest").unwrap();
            let mut w = BundleWriter::create(dir).unwrap();
            w.write_bytes(Component::Profile, self.profile.to_json().as_bytes())
                .unwrap();
            w.write_ram(&ram, &|| false).unwrap();
            w.write_json(
                Component::Cpu,
                &CpuState::new(GuestArch::Aarch64, self.vcpus),
            )
            .unwrap();
            w.write_json(Component::Platform, &self.platform).unwrap();
            let devices = DevicesDoc {
                states: self.states,
                irq_levels: IrqLevels::default(),
            };
            w.write_bytes(Component::Devices, &devices.to_json().unwrap())
                .unwrap();
            if let Some(disk) = &self.disk {
                w.write_json(Component::Disk, disk).unwrap();
            }
            w.write_json(
                Component::Session,
                &Session {
                    version: DOC_VERSION,
                    sandbox_id: "sb".into(),
                    epoch: 4,
                    txid: None,
                    captured_at_unix_ms: unix_ms(),
                    then: "fence".into(),
                },
            )
            .unwrap();
            w.seal(self.capabilities).unwrap();
        }
    }

    /// The flags that match [`parts`].
    fn config(scratch: &Scratch) -> RestoreConfig {
        RestoreConfig {
            from: scratch.bundle().display().to_string(),
            control_sock: "/unused".into(),
            checkpoint_root: None,
            disk: Some(DiskConfig::rw(scratch.disk())),
            net: true,
            net_gateway: None,
            net_mac: None,
            agent_sock: Some("/unused-agent".into()),
            sandbox_id: None,
            events: None,
            profile_out: None,
            sandbox: true,
        }
    }

    /// Writes [`parts`] changed by `edit`, and returns the refusals of a
    /// restore with [`config`] changed by `flags`.
    fn refused(
        name: &str,
        edit: impl FnOnce(&mut Parts),
        flags: impl FnOnce(&mut RestoreConfig),
    ) -> Vec<String> {
        let scratch = Scratch::new(name);
        let mut parts = parts(&scratch);
        edit(&mut parts);
        parts.write(&scratch.bundle());
        let mut cfg = config(&scratch);
        flags(&mut cfg);
        refusals(&open(&scratch.bundle()).unwrap(), &cfg, &HVF)
    }

    /// Asserts that `reasons` has one that contains each of `want`.
    fn has(reasons: &[String], want: &[&str]) {
        for w in want {
            assert!(
                reasons.iter().any(|r| r.contains(w)),
                "no reason with {w:?} in {reasons:#?}"
            );
        }
    }

    #[test]
    fn a_whole_bundle_with_matching_flags_is_restorable() {
        let scratch = Scratch::new("whole");
        parts(&scratch).write(&scratch.bundle());
        let opened = open(&scratch.bundle()).unwrap();
        assert_eq!(
            refusals(&opened, &config(&scratch), &HVF),
            Vec::<String>::new()
        );
        assert_eq!(opened.plan.vcpus.len(), 2);
        assert_eq!(opened.session.epoch, 4);
    }

    #[test]
    fn flags_that_do_not_match_the_devices_are_refused_with_every_reason() {
        let reasons = refused(
            "flags",
            |_| {},
            |cfg| {
                cfg.disk = None;
                cfg.net = false;
                cfg.net_gateway = Some("/gw.sock".into());
                cfg.agent_sock = None;
                cfg.net_mac = Some([2, 0, 0, 0, 0, 9]);
            },
        );
        has(
            &reasons,
            &[
                "the guest had a disk; give it with --disk",
                "the guest ran on a stub network, and this restore gives it a gateway one",
                "--net-mac 02:00:00:00:00:09: the guest answers to",
                "the guest had an agent socket; give it with --agent-sock",
            ],
        );
        assert_eq!(reasons.len(), 4, "{reasons:#?}");
        let reasons = refused(
            "flags-extra",
            |p| {
                p.states.net = None;
                p.states.vsock = None;
            },
            |cfg| cfg.net_gateway = Some("/gw.sock".into()),
        );
        has(
            &reasons,
            &[
                "--net-stub and --net-gateway are each a network",
                "--agent-sock /unused-agent: the guest had none",
            ],
        );
        let reasons = refused("no-net", |_| {}, |cfg| cfg.net = false);
        has(
            &reasons,
            &["the guest had a stub network; give it with --net-stub"],
        );
    }

    // The restored disk answers GET_ID with the bundle's serial, which the
    // guest finds its disk by, and the guest goes on writing it. A --disk that
    // asks for another serial, or for a read-only disk, is refused with the
    // bundle's values; the bundle's own serial is accepted.
    #[test]
    fn a_disk_of_another_serial_or_a_read_only_one_is_refused() {
        let bundle = "the bundle's disk has serial=disk0 and readonly=off";
        let reasons = refused(
            "disk-serial",
            |_| {},
            |cfg| cfg.disk.as_mut().unwrap().serial = Some("data".into()),
        );
        has(&reasons, &[&format!("serial=data, and {bundle}")]);
        let reasons = refused(
            "disk-ro",
            |_| {},
            |cfg| cfg.disk.as_mut().unwrap().read_only = true,
        );
        has(&reasons, &[&format!("readonly=on, and {bundle}")]);
        let reasons = refused(
            "disk-same-serial",
            |_| {},
            |cfg| cfg.disk.as_mut().unwrap().serial = Some("disk0".into()),
        );
        assert!(reasons.is_empty(), "{reasons:#?}");
    }

    #[test]
    fn a_disk_of_another_size_is_refused() {
        let reasons = refused(
            "disk-size",
            |_| {},
            |cfg| {
                #[allow(clippy::disallowed_methods)]
                std::fs::write(&cfg.disk.as_ref().unwrap().path, vec![0u8; 1 << 19]).unwrap();
            },
        );
        has(&reasons, &["524288 bytes, the guest was given 1048576"]);
        let reasons = refused(
            "disk-json",
            |p| p.disk.as_mut().unwrap().size_bytes = 7,
            |_| {},
        );
        has(&reasons, &["disk.json: 7 bytes"]);
        let reasons = refused(
            "disk-none",
            |p| {
                p.states.blk = None;
                p.disk = None;
            },
            |_| {},
        );
        has(&reasons, &["the guest had no disk"]);
    }

    // A bundle of H3's partial export, or of a backend that does not read
    // its platform, is refused for every part it lacks.
    #[test]
    fn a_partial_bundle_is_refused_for_what_it_lacks() {
        let reasons = refused(
            "partial",
            |p| {
                p.vcpus = (0..2)
                    .map(|cpu| {
                        VcpuState::from_regs_view(
                            GuestArch::Aarch64,
                            "hvf",
                            cpu,
                            &crate::plugin::RegsView::default(),
                        )
                    })
                    .collect();
                p.platform = PlatformState::not_captured(GuestArch::Aarch64, "hvf");
                p.capabilities = vec!["kvm-vgic-v3".into()];
            },
            |_| {},
        );
        has(
            &reasons,
            &[
                "cpu.json: vCPU 0: the state is partial",
                "cpu.json: vCPU 1: the state is partial",
                "the interrupt controller is not-captured, which this hvi cannot restore on hvf",
                "the counter is not-captured",
                "the hvf_gic_state blob is missing",
                "the bundle needs kvm-vgic-v3",
            ],
        );
    }

    /// The parts of a portable bundle of `backend`: the GICv2 and
    /// `hvi-time` for its platform, and no blob.
    fn portable_parts(p: &mut Parts, backend: &str) {
        p.profile.profile = "portable-arm64-v1".into();
        p.profile.backend = backend.into();
        p.platform.backend = backend.into();
        for v in &mut p.vcpus {
            if let VcpuState::Aarch64(v) = v {
                v.backend = backend.into();
            }
        }
        p.platform.irq = IrqState::Gicv2(Box::new(crate::devices::gicv2::Gicv2::new(2).state()));
        p.platform.timer =
            TimerState::HviTime(Box::new(crate::checkpoint::platform::tests::hvi_time(2)));
        p.platform.backend_adjunct = None;
        p.capabilities = Vec::new();
    }

    /// Returns the refusals of `can` for a bundle `edit` makes.
    fn refused_by(name: &str, edit: impl FnOnce(&mut Parts), can: &Restorer) -> Vec<String> {
        let scratch = Scratch::new(name);
        let mut parts = parts(&scratch);
        edit(&mut parts);
        parts.write(&scratch.bundle());
        refusals(&open(&scratch.bundle()).unwrap(), &config(&scratch), can)
    }

    // A portable bundle of either backend is restorable on either, and the
    // native restore refuses it for its profile and its kinds.
    #[test]
    fn a_portable_bundle_moves_between_backends_and_a_native_one_does_not() {
        for from in ["hvf", "kvm"] {
            for on in ["hvf", "kvm"] {
                let reasons = refused_by(
                    &format!("portable-{from}-{on}"),
                    |p| portable_parts(p, from),
                    &portable(on),
                );
                assert_eq!(reasons, Vec::<String>::new(), "{from} -> {on}");
            }
        }
        let reasons = refused_by("portable-native", |p| portable_parts(p, "hvf"), &HVF);
        has(
            &reasons,
            &[
                "profile.json: a portable-arm64-v1 guest, which this hvi does not restore on hvf",
                "the interrupt controller is gicv2, which this hvi cannot restore on hvf",
                "the counter is hvi-time, which this hvi cannot restore on hvf",
                "the hvf_gic_state blob is missing",
            ],
        );
        // A native bundle of the other backend is refused for it.
        let reasons = refused_by(
            "native-kvm",
            |p| {
                p.profile.backend = "kvm".into();
            },
            &HVF,
        );
        has(
            &reasons,
            &[
                "an aarch64 guest on kvm, and this hvi restores aarch64 guests from hvf on hvf \
               (only the portable profile moves between backends)",
            ],
        );
        // The portable restore refuses a native bundle.
        let reasons = refused_by("native-portable", |_| {}, &portable("kvm"));
        has(
            &reasons,
            &[
                "a native guest, which this hvi does not restore on kvm",
                "the interrupt controller is hv-gic-v3",
                "the bundle needs hvf-gic-state-v1",
            ],
        );
    }

    #[test]
    fn counts_past_the_machine_are_refused() {
        let reasons = refused(
            "counts",
            |p| {
                let IrqState::HvGicV3(gic) = &mut p.platform.irq else {
                    unreachable!()
                };
                gic.icc[1].vcpu = 7;
                p.vcpus.truncate(1);
            },
            |_| {},
        );
        has(
            &reasons,
            &[
                "cpu.json: 1 vCPUs, the profile has 2",
                "icc lists vCPU 7, and the machine has 2",
            ],
        );
        let reasons = refused(
            "too-many",
            |p| {
                p.profile.vcpus = 65;
            },
            |_| {},
        );
        has(&reasons, &["65 vCPUs, a restore takes 1 to 64"]);
        let reasons = refused(
            "huge",
            |p| {
                p.profile.vcpus = u32::MAX;
            },
            |_| {},
        );
        has(&reasons, &["4294967295 vCPUs, a restore takes 1 to 64"]);
        assert!(
            !reasons.iter().any(|r| r.starts_with("platform.json: irq")),
            "the platform was checked against the count: {reasons:?}"
        );
        let reasons = refused(
            "odd-region",
            |p| {
                p.profile.ram_regions[0].size += 4096;
            },
            |_| {},
        );
        // A 4 KiB-page bundle on a 16 KiB-page host cannot be mapped.
        if host_page_size() > 4096 {
            has(&reasons, &["is not whole"]);
        }
    }

    #[test]
    fn a_bundle_missing_a_component_does_not_open() {
        let scratch = Scratch::new("missing");
        parts(&scratch).write(&scratch.bundle());
        #[allow(clippy::disallowed_methods)]
        std::fs::remove_file(scratch.bundle().join("platform.json")).unwrap();
        let err = open(&scratch.bundle())
            .err()
            .expect("it opened")
            .to_string();
        assert!(err.contains("platform.json"), "{err}");
    }

    #[test]
    fn profile_differences_are_named() {
        let source = MachineProfile::for_this_host("aarch64", "hvf");
        let mut local = source.clone();
        local.counter_freq_hz = source.counter_freq_hz + 1;
        local.vcpus = 3;
        let reasons = profile_refusals(&source, &local);
        has(
            &reasons,
            &["profile: counter_freq_hz: ", "profile: vcpus: "],
        );
        assert!(reasons.iter().all(|r| r.starts_with("profile: ")));
        let refused = Refused(reasons).to_string();
        assert!(refused.starts_with("this host cannot resume the bundle:\n  - profile: "));
    }

    #[test]
    fn the_steps_run_in_order_with_a_barrier_between_each() {
        let vcpus = Arc::new(Vcpus::new(
            3,
            NoKick,
            crate::run::StopHandle::new_pair().unwrap().0,
        ));
        vcpus.pause_from_control(Duration::ZERO).unwrap();
        let log = Log::default();
        let threads: Vec<_> = (0..2)
            .map(|cpu| importing_vcpu(&vcpus, cpu, &log, None))
            .collect();
        // vCPU 2 was off, and its thread waits for the guest, as at boot.
        import(&vcpus, &plan(2, 1), Duration::from_secs(5), || 3).unwrap();
        assert_barriers(&log.lock().unwrap(), 2);
        assert_eq!(vcpus.parked(), 2, "a vCPU left its park during the import");
        vcpus.stop();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn the_controller_waits_for_every_vcpu_to_exist() {
        // vCPUs 2 and 3 were off. Their threads create them in turn after
        // vCPU 1's, and nothing else orders them before the import.
        let vcpus = Arc::new(Vcpus::new(
            4,
            NoKick,
            crate::run::StopHandle::new_pair().unwrap().0,
        ));
        vcpus.pause_from_control(Duration::ZERO).unwrap();
        let log = Log::default();
        let threads: Vec<_> = (0..2)
            .map(|cpu| importing_vcpu(&vcpus, cpu, &log, None))
            .collect();
        let created = Arc::new(std::sync::atomic::AtomicU32::new(2));
        let late = {
            let (created, log) = (Arc::clone(&created), Arc::clone(&log));
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                let early = log.lock().unwrap().clone();
                created.store(4, std::sync::atomic::Ordering::SeqCst);
                early
            })
        };
        import(&vcpus, &plan(2, 2), Duration::from_secs(5), || {
            created.load(std::sync::atomic::Ordering::SeqCst)
        })
        .unwrap();
        let early = late.join().unwrap();
        assert!(
            early.is_empty(),
            "a step ran before every vCPU existed: {early:?}"
        );
        assert_barriers(&log.lock().unwrap(), 2);

        // One that is never created times the import out, and no step runs.
        let log_len = log.lock().unwrap().len();
        let err = import(&vcpus, &plan(2, 2), Duration::from_millis(100), || 3).unwrap_err();
        assert_eq!(err, "3 of 4 vCPUs were created in time");
        assert_eq!(
            log.lock().unwrap().len(),
            log_len,
            "a step ran without vCPU 3"
        );
        vcpus.stop();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn a_step_that_fails_ends_the_import_naming_the_vcpu() {
        let vcpus = Arc::new(Vcpus::new(
            2,
            NoKick,
            crate::run::StopHandle::new_pair().unwrap().0,
        ));
        vcpus.pause_from_control(Duration::ZERO).unwrap();
        let log = Log::default();
        let threads = [
            importing_vcpu(&vcpus, 0, &log, None),
            importing_vcpu(&vcpus, 1, &log, Some(ImportStep::IrqCpu)),
        ];
        let err = import(&vcpus, &plan(2, 0), Duration::from_secs(5), || 2).unwrap_err();
        assert_eq!(err, "vCPU 1, IrqCpu step: the hypervisor refused it");
        vcpus.stop();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn a_vcpu_that_never_starts_times_the_import_out() {
        let vcpus = Arc::new(Vcpus::new(
            2,
            NoKick,
            crate::run::StopHandle::new_pair().unwrap().0,
        ));
        vcpus.pause_from_control(Duration::ZERO).unwrap();
        let log = Log::default();
        let thread = importing_vcpu(&vcpus, 0, &log, None);
        // The fake marks itself started on its own thread, which a loaded
        // host may not have run yet when the import starts its short wait.
        while vcpus.started() < 1 {
            std::thread::sleep(Duration::from_millis(1));
        }
        let started = Instant::now();
        let err = import(&vcpus, &plan(2, 0), Duration::from_millis(100), || 2).unwrap_err();
        assert_eq!(err, "1 of 2 vCPUs started in time");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(log.lock().unwrap().is_empty(), "a step ran without vCPU 1");
        vcpus.stop();
        thread.join().unwrap();
        // The stop ends a wait for a vCPU that never comes.
        let stopped = Vcpus::new(1, NoKick, crate::run::StopHandle::new_pair().unwrap().0);
        stopped.stop();
        assert_eq!(
            import(&stopped, &plan(1, 0), Duration::from_secs(5), || 1).unwrap_err(),
            "the run ended before the vCPUs started"
        );
    }
}

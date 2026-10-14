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

//! A Hypervisor.framework vCPU and its GIC, read into the canonical
//! checkpoint state.
//!
//! [`serve`] is the work a vCPU thread does at its park point for the
//! control socket. [`Work::Export`] reads the vCPU's general, SIMD and system
//! registers by the names of `cpu.json`, its virtual timer mask, and its
//! GICv3 redistributor and CPU interface, which only its own thread may read.
//! [`Work::ExportPlatform`], on vCPU 0 once every vCPU has exported, reads the
//! distributor, the `hv_gic_state` blob and the guest counter.
//!
//! A restore loads them back in the steps of `checkpoint::restore`: each
//! vCPU's registers and timer mask, then the blob through `hv_gic_set_state`
//! on vCPU 0, then each vCPU's CPU interface. The counter goes on from the
//! captured value through [`RestoreClock`].
//!
//! Every register is named here by its `applevisor` variant, never by the
//! framework's number, so the tables below are the only place the two
//! meet. The tests check each name against the variant's own.

use std::io;

use applevisor::prelude::{
    GicDistributorReg, GicEnabled, GicIccReg, GicRedistributorReg, Reg, SimdFpReg, SysReg, Vcpu,
    VirtualMachineInstance,
};

use crate::checkpoint::cpu::{
    aarch64_reg_names, parse_simd, simd_hex, Aarch64Vcpu, Hex64, ImportStep, Need, Output, Power,
    VcpuState, VcpuTimer, Work, AARCH64_SYSREGS,
};
use crate::checkpoint::kvm_regs::{firmware_view, fixed_named, Check, PORTABLE_HVF_FIRMWARE};
use crate::checkpoint::platform::{
    Adjunct, ArchTimerState, GicV3Dist, GicV3Icc, GicV3Redist, GicV3State, IrqCpuState, IrqState,
    PlatformState, TimerState, GICV3_MAX_INTIDS, HVF_GIC_STATE, HVF_GIC_STATE_CAPABILITY,
    PLATFORM_STATE_VERSION,
};
use crate::checkpoint::profile::counter_freq_hz;
use crate::devices::gicv2::Gicv2;
use crate::devices::hvitime::HviTime;

/// The VM handle once the GICv3 is configured.
type VmGic = VirtualMachineInstance<GicEnabled>;

extern "C" {
    /// The host counter the guest's `CNTVCT_EL0` is an offset from: on Apple
    /// silicon it ticks at the 24 MHz of `CNTFRQ_EL0`. In libSystem, which
    /// every process links; the `libc` crate's binding is deprecated.
    fn mach_absolute_time() -> u64;
}

/// Returns the host counter, `mach_absolute_time()`.
pub(crate) fn host_counter() -> u64 {
    // SAFETY: it takes nothing and reads the clock.
    unsafe { mach_absolute_time() }
}

/// The guest counter of a restored VM, which goes on from the value the
/// capture left it at.
///
/// The counter stands still from the restore until the guest resumes: the
/// vtimer offset every vCPU runs with is fixed when the first vCPU is about
/// to enter the guest, so the guest's `CNTVCT_EL0` resumes at
/// `counter_at_capture` however long the restore and the wait for `resume`
/// took.
pub(crate) struct RestoreClock {
    /// The guest counter at the capture.
    counter_at_capture: u64,
    /// The vtimer offset, once a vCPU has asked for it.
    offset: std::sync::OnceLock<u64>,
}

impl RestoreClock {
    /// Returns the clock of a guest captured at `counter_at_capture`.
    pub(crate) fn new(counter_at_capture: u64) -> Self {
        Self {
            counter_at_capture,
            offset: std::sync::OnceLock::new(),
        }
    }

    /// Returns the vtimer offset each vCPU sets before it first enters the
    /// guest, fixed by the first to ask.
    pub(crate) fn offset(&self) -> u64 {
        *self
            .offset
            .get_or_init(|| host_counter().wrapping_sub(self.counter_at_capture))
    }

    /// Returns the guest counter now: `counter_at_capture` until the guest
    /// has resumed.
    fn counter(&self) -> u64 {
        self.offset.get().map_or(self.counter_at_capture, |offset| {
            host_counter().wrapping_sub(*offset)
        })
    }
}

/// Carries out `work` for vCPU `cpu`, whose thread this is, on `vm`.
///
/// `clock` is the counter of a restored VM, which a capture reads in place
/// of the vtimer offset until the guest has resumed.
///
/// # Errors
///
/// Errors when a register a restore needs cannot be read or written, when
/// the guest has SME state this build does not capture, or when a state to
/// load is not this vCPU's or is not whole.
pub(crate) fn serve(
    cpu: u32,
    vcpu: &Vcpu,
    vm: &VmGic,
    clock: Option<&RestoreClock>,
    work: Work<'_>,
) -> io::Result<Option<Output>> {
    // Only vCPU 0 reads and loads the platform; the others have nothing to
    // add to those steps.
    match work {
        Work::Export => export_vcpu(cpu, vcpu).map(Some),
        Work::ExportPlatform if cpu == 0 => export_platform(vcpu, vm, clock).map(Some),
        Work::Import(ImportStep::Platform, plan) if cpu == 0 => import_gic(&plan.platform),
        Work::ExportPlatform | Work::Import(ImportStep::Platform, _) => Ok(None),
        Work::Import(ImportStep::Vcpu, plan) => import_vcpu(cpu, vcpu, &plan.vcpus[cpu as usize]),
        Work::Import(ImportStep::IrqCpu, plan) => import_icc(cpu, vcpu, &plan.platform),
    }
}

/// Loads vCPU `cpu`'s registers and its timer mask from `state`.
///
/// A vCPU that was off, or waited for its `CPU_ON`, holds no register: the
/// first starts as at boot, and the second from the mailbox the restore
/// filled, so there is nothing to load. `MPIDR_EL1` is set when the vCPU is
/// created and must be the one the state has.
fn import_vcpu(cpu: u32, vcpu: &Vcpu, state: &VcpuState) -> io::Result<Option<Output>> {
    let VcpuState::Aarch64(state) = state else {
        return Err(io::Error::other(format!("vCPU {cpu}: not an arm64 state")));
    };
    if state.id != cpu {
        return Err(io::Error::other(format!(
            "vCPU {cpu} was handed the state of vCPU {}",
            state.id
        )));
    }
    state.check_restorable().map_err(io::Error::other)?;
    if state.power != Power::On {
        return Ok(None);
    }
    check_kvm_parts(state)?;
    let get = |name: &str| {
        state
            .regs
            .get(name)
            .map(|v| v.0)
            .ok_or_else(|| io::Error::other(format!("{name} is missing")))
    };
    for (name, reg) in aarch64_reg_names().iter().zip(REGS) {
        let value = get(name)?;
        match reg {
            Gpr::Reg(reg) => vcpu.set_reg(reg, value),
            Gpr::Sys(reg) => vcpu.set_sys_reg(reg, value),
        }
        .map_err(|e| failed(name, e))?;
    }
    for (n, (q, text)) in SIMD_REGS.iter().zip(&state.simd).enumerate() {
        let value = parse_simd(text)
            .ok_or_else(|| io::Error::other(format!("q{n} is not 32 hex digits")))?;
        vcpu.set_simd_fp_reg(*q, value)
            .map_err(|e| failed(&format!("q{n}"), e))?;
    }
    for (name, value) in &state.sysregs {
        let reg =
            sys_reg(name).ok_or_else(|| io::Error::other(format!("{name}: no hvf register")))?;
        if name == "MPIDR_EL1" {
            let have = vcpu.get_sys_reg(reg).map_err(|e| failed(name, e))?;
            if have != value.0 {
                return Err(io::Error::other(format!(
                    "MPIDR_EL1 is {have:#x} here and {:#x} in the state",
                    value.0
                )));
            }
            continue;
        }
        vcpu.set_sys_reg(reg, value.0)
            .map_err(|e| failed(name, e))?;
    }
    if let Some(timer) = state.timer {
        vcpu.set_vtimer_mask(timer.vtimer_masked)
            .map_err(|e| failed("the vtimer mask", e))?;
    }
    Ok(None)
}

/// Checks what a KVM vCPU recorded beside its registers against what a
/// portable guest on HVF sees, since HVF has no such registers to load: its
/// firmware answers, the registers only KVM has, and a pending SError or
/// abort, which HVF cannot make pending. A state HVF wrote has none of
/// them.
fn check_kvm_parts(state: &Aarch64Vcpu) -> io::Result<()> {
    let cpu = state.id;
    for (name, value) in &state.firmware {
        let here = PORTABLE_HVF_FIRMWARE
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, v)| *v);
        if here.map(|v| firmware_view(name, v)) != Some(firmware_view(name, value.0)) {
            return Err(io::Error::other(format!(
                "vCPU {cpu}: firmware register {name} was {:#x} at the capture, and hvi's \
                 firmware here answers as {}",
                value.0,
                here.map_or_else(|| "nothing".to_string(), |v| format!("{v:#x}"))
            )));
        }
    }
    for (name, value) in &state.fixed {
        let Some(Check::Fixed { mask, hvf, .. }) = fixed_named(name) else {
            return Err(io::Error::other(format!(
                "vCPU {cpu}: unknown fixed register {name}"
            )));
        };
        if value.0 & mask != hvf & mask {
            return Err(io::Error::other(format!(
                "vCPU {cpu}: {name} was {:#x} at the capture, and a guest here sees {hvf:#x}",
                value.0
            )));
        }
    }
    if state.events.is_some_and(|e| e.any()) {
        return Err(io::Error::other(format!(
            "vCPU {cpu}: an SError or external abort is pending, which HVF cannot make \
             pending"
        )));
    }
    Ok(())
}

/// Carries out `work` for portable vCPU `cpu`, whose thread this is: the
/// vCPU's registers as on the native machine, and on vCPU 0 the software
/// GICv2 `gic` and the `hvi-time` device, which hvi holds itself.
///
/// The platform is read with the device frozen, so no timer fires between
/// its state and the GIC's; the caller thaws it if the guest goes on. A
/// restore loads the GIC in the platform step and leaves `hvi-time` to the
/// guest's resume, when its page is published.
///
/// # Errors
///
/// As [`serve`].
pub(crate) fn serve_portable(
    cpu: u32,
    vcpu: &Vcpu,
    gic: &std::sync::Mutex<Gicv2>,
    hvitime: &HviTime,
    work: Work<'_>,
) -> io::Result<Option<Output>> {
    match work {
        Work::Export => Ok(Some(Output::Vcpu {
            state: export_vcpu_state(cpu, vcpu)?,
            irq: None,
        })),
        Work::ExportPlatform if cpu == 0 => {
            hvitime.freeze();
            let timer = hvitime.state();
            let irq = gic.lock().unwrap().state();
            Ok(Some(Output::Platform {
                platform: PlatformState {
                    version: PLATFORM_STATE_VERSION,
                    arch: "aarch64".to_string(),
                    backend: "hvf".to_string(),
                    irq: IrqState::Gicv2(Box::new(irq)),
                    timer: TimerState::HviTime(Box::new(timer)),
                    backend_adjunct: None,
                },
                capabilities: Vec::new(),
            }))
        }
        Work::Import(ImportStep::Platform, plan) if cpu == 0 => {
            let IrqState::Gicv2(state) = &plan.platform.irq else {
                return Err(io::Error::other(format!(
                    "the interrupt controller is {}, not gicv2",
                    plan.platform.irq.kind()
                )));
            };
            gic.lock()
                .unwrap()
                .restore(state)
                .map_err(io::Error::other)?;
            Ok(None)
        }
        Work::ExportPlatform | Work::Import(ImportStep::Platform | ImportStep::IrqCpu, _) => {
            Ok(None)
        }
        Work::Import(ImportStep::Vcpu, plan) => import_vcpu(cpu, vcpu, &plan.vcpus[cpu as usize]),
    }
}

/// Loads the GIC from the `hv_gic_state` blob, on vCPU 0's thread, once
/// every vCPU exists and none has run.
fn import_gic(platform: &PlatformState) -> io::Result<Option<Output>> {
    let adjunct = platform
        .backend_adjunct
        .as_ref()
        .filter(|a| a.kind == HVF_GIC_STATE)
        .ok_or_else(|| io::Error::other("the bundle has no hv_gic_state blob"))?;
    let blob = adjunct.data()?;
    // SAFETY: `blob` is a live buffer of `blob.len()` bytes for the call,
    // which only reads it.
    let ret = unsafe {
        applevisor_sys::hv_gic_set_state(blob.as_ptr().cast::<std::ffi::c_void>(), blob.len())
    };
    if ret != 0 {
        return Err(io::Error::other(format!(
            "hv_gic_set_state refused the {}-byte blob: {ret:#x} (a blob from another macOS \
             build may not load)",
            blob.len()
        )));
    }
    Ok(None)
}

/// Loads vCPU `cpu`'s GIC CPU interface, which the blob does not hold, in an
/// order that enables the system register interface first and the groups
/// last.
fn import_icc(cpu: u32, vcpu: &Vcpu, platform: &PlatformState) -> io::Result<Option<Output>> {
    let IrqState::HvGicV3(gic) = &platform.irq else {
        return Err(io::Error::other(format!(
            "the interrupt controller is {}, not hv-gic-v3",
            platform.irq.kind()
        )));
    };
    // A vCPU that never ran at the capture has no saved interface; it comes
    // up as the guest brings it up.
    let Some(icc) = gic.icc.iter().find(|icc| icc.vcpu == cpu) else {
        return Ok(None);
    };
    for (reg, value) in [
        (GicIccReg::SRE_EL1, icc.sre_el1),
        (GicIccReg::CTLR_EL1, icc.ctlr),
        (GicIccReg::PMR_EL1, icc.pmr),
        (GicIccReg::BPR0_EL1, icc.bpr0),
        (GicIccReg::BPR1_EL1, icc.bpr1),
        (GicIccReg::AP0R0_EL1, icc.ap0r0),
        (GicIccReg::AP1R0_EL1, icc.ap1r0),
        (GicIccReg::IGRPEN0_EL1, icc.igrpen0),
        (GicIccReg::IGRPEN1_EL1, icc.igrpen1),
    ] {
        vcpu.set_icc_reg(reg, value)
            .map_err(|e| failed(&format!("ICC {reg:?}"), e))?;
    }
    Ok(None)
}

/// Returns an error naming `what` for a failed Hypervisor.framework call.
fn failed(what: &str, e: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{what}: {e:?}"))
}

/// Reads vCPU `cpu`'s whole state and its part of the GIC.
fn export_vcpu(cpu: u32, vcpu: &Vcpu) -> io::Result<Output> {
    Ok(Output::Vcpu {
        state: export_vcpu_state(cpu, vcpu)?,
        irq: Some(export_gic_cpu(cpu, vcpu)?),
    })
}

/// Reads vCPU `cpu`'s whole state.
fn export_vcpu_state(cpu: u32, vcpu: &Vcpu) -> io::Result<VcpuState> {
    // The GIC blob may hold each vCPU's state by the framework's number, and
    // a restore creates vCPU n as number n. See `hvf::CreateOrder`.
    if vcpu.id() != u64::from(cpu) {
        return Err(io::Error::other(format!(
            "vCPU {cpu} is the framework's vCPU {}; a restore would give its GIC \
             state to another",
            vcpu.id()
        )));
    }
    // Streaming mode and ZA live in the Z, P and ZA registers, which the
    // schema has no place for. A host without SME refuses the call, and then
    // there is nothing to lose.
    if let Ok(sme) = vcpu.get_sme_state() {
        if sme.streaming_sve_mode_enabled || sme.za_storage_enabled {
            return Err(io::Error::other(format!(
                "vCPU {cpu} is in SME streaming mode or has ZA storage on, whose Z, P and \
                 ZA registers a checkpoint does not capture"
            )));
        }
    }
    let mut regs = std::collections::BTreeMap::new();
    for (name, reg) in aarch64_reg_names().into_iter().zip(REGS) {
        let value = match reg {
            Gpr::Reg(reg) => vcpu.get_reg(reg),
            Gpr::Sys(reg) => vcpu.get_sys_reg(reg),
        }
        .map_err(|e| failed(&name, e))?;
        regs.insert(name, Hex64(value));
    }
    let simd = SIMD_REGS
        .iter()
        .enumerate()
        .map(|(n, q)| {
            vcpu.get_simd_fp_reg(*q)
                .map(simd_hex)
                .map_err(|e| failed(&format!("q{n}"), e))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut sysregs = std::collections::BTreeMap::new();
    let mut unavailable = Vec::new();
    for (name, need) in AARCH64_SYSREGS {
        let read = sys_reg(name)
            .ok_or_else(|| io::Error::other(format!("{name}: no hvf register")))
            .and_then(|reg| vcpu.get_sys_reg(reg).map_err(|e| failed(name, e)));
        match (read, need) {
            (Ok(value), _) => {
                sysregs.insert(name.to_string(), Hex64(value));
            }
            (Err(_), Need::Optional) => unavailable.push(name.to_string()),
            (Err(e), Need::Required) => return Err(e),
        }
    }
    let vtimer_masked = vcpu
        .get_vtimer_mask()
        .map_err(|e| failed("the vtimer mask", e))?;
    let state = VcpuState::Aarch64(Aarch64Vcpu {
        id: cpu,
        power: Power::On,
        mp_state: None,
        regs,
        simd,
        sysregs,
        timer: Some(VcpuTimer { vtimer_masked }),
        backend: "hvf".to_string(),
        kvm_extra: std::collections::BTreeMap::new(),
        firmware: std::collections::BTreeMap::new(),
        fixed: std::collections::BTreeMap::new(),
        events: None,
        unavailable,
        partial: false,
    });
    Ok(state)
}

/// Reads vCPU `cpu`'s GICv3 redistributor and CPU interface.
fn export_gic_cpu(cpu: u32, vcpu: &Vcpu) -> io::Result<IrqCpuState> {
    let redist = |reg: GicRedistributorReg| {
        vcpu.get_redistributor_reg(reg)
            .map_err(|e| failed(&format!("GICR {reg:?}"), e))
            .and_then(|v| word(&format!("GICR {reg:?}"), v))
    };
    let icc = |reg: GicIccReg| {
        vcpu.get_icc_reg(reg)
            .map_err(|e| failed(&format!("ICC {reg:?}"), e))
    };
    let redist = GicV3Redist {
        vcpu: cpu,
        igroupr0: redist(GicRedistributorReg::IGROUPR0)?,
        isenabler0: redist(GicRedistributorReg::ISENABLER0)?,
        ispendr0: redist(GicRedistributorReg::ISPENDR0)?,
        isactiver0: redist(GicRedistributorReg::ISACTIVER0)?,
        ipriorityr: REDIST_PRIORITY
            .iter()
            .map(|reg| redist(*reg))
            .collect::<io::Result<Vec<_>>>()?,
        icfgr0: redist(GicRedistributorReg::ICFGR0)?,
        icfgr1: redist(GicRedistributorReg::ICFGR1)?,
    };
    let icc = GicV3Icc {
        vcpu: cpu,
        pmr: icc(GicIccReg::PMR_EL1)?,
        bpr0: icc(GicIccReg::BPR0_EL1)?,
        bpr1: icc(GicIccReg::BPR1_EL1)?,
        ap0r0: icc(GicIccReg::AP0R0_EL1)?,
        ap1r0: icc(GicIccReg::AP1R0_EL1)?,
        ctlr: icc(GicIccReg::CTLR_EL1)?,
        sre_el1: icc(GicIccReg::SRE_EL1)?,
        igrpen0: icc(GicIccReg::IGRPEN0_EL1)?,
        igrpen1: icc(GicIccReg::IGRPEN1_EL1)?,
    };
    Ok(IrqCpuState::GicV3(redist, icc))
}

/// Reads the distributor, the `hv_gic_state` blob and the guest counter, on
/// vCPU 0's thread, `vcpu`, once every vCPU has exported and none runs.
fn export_platform(vcpu: &Vcpu, vm: &VmGic, clock: Option<&RestoreClock>) -> io::Result<Output> {
    // The counter first, so it is as close as it can be to the moment the
    // guest stopped seeing it move.
    let counter_at_capture = match clock {
        Some(clock) => clock.counter(),
        None => {
            let offset = vcpu
                .get_vtimer_offset()
                .map_err(|e| failed("the vtimer offset", e))?;
            host_counter().wrapping_sub(offset)
        }
    };
    let host_monotonic_at_capture_ns = monotonic_ns();
    let read_dist = |offset: u32| {
        let reg = dist_reg(offset).ok_or_else(|| {
            io::Error::other(format!("GICD offset {offset:#x} is not a register"))
        })?;
        vm.gic_get_distributor_reg(reg)
            .map_err(|e| failed(&format!("GICD {reg:?}"), e))
            .and_then(|v| word(&format!("GICD {reg:?}"), v))
    };
    let typer = read_dist(GICD_TYPER)?;
    let intids = (32 * ((typer & 0x1f) + 1)).min(GICV3_MAX_INTIDS);
    let words = |base: u32, per_reg: u32| {
        (0..intids.div_ceil(per_reg))
            .map(|n| read_dist(base + 4 * n))
            .collect::<io::Result<Vec<u32>>>()
    };
    let dist = GicV3Dist {
        ctlr: read_dist(GICD_CTLR)?,
        igroupr: words(GICD_IGROUPR, 32)?,
        isenabler: words(GICD_ISENABLER, 32)?,
        ispendr: words(GICD_ISPENDR, 32)?,
        isactiver: words(GICD_ISACTIVER, 32)?,
        ipriorityr: words(GICD_IPRIORITYR, 4)?,
        icfgr: words(GICD_ICFGR, 16)?,
        irouter: (32..intids)
            .map(|intid| {
                let reg = dist_reg(GICD_IROUTER + 8 * intid).ok_or_else(|| {
                    io::Error::other(format!("GICD_IROUTER{intid} is not a register"))
                })?;
                vm.gic_get_distributor_reg(reg)
                    .map(|v| (intid.to_string(), v))
                    .map_err(|e| failed(&format!("GICD {reg:?}"), e))
            })
            .collect::<io::Result<_>>()?,
    };
    let mut state = vm
        .gic_state_create()
        .map_err(|e| failed("hv_gic_state_create", e))?;
    let size = state
        .size()
        .map_err(|e| failed("hv_gic_state_get_size", e))?;
    let mut blob = vec![0u8; size];
    state
        .get(&mut blob)
        .map_err(|e| failed("hv_gic_state_get_data", e))?;
    let platform = PlatformState {
        version: PLATFORM_STATE_VERSION,
        arch: "aarch64".to_string(),
        backend: "hvf".to_string(),
        irq: IrqState::HvGicV3(Box::new(GicV3State {
            version: 3,
            dist,
            redist: Vec::new(),
            icc: Vec::new(),
            spi_count: intids - 32,
        })),
        timer: TimerState::ArchTimer(ArchTimerState {
            counter_freq_hz: counter_freq_hz(),
            counter_at_capture,
            host_monotonic_at_capture_ns,
        }),
        backend_adjunct: Some(Adjunct::new(HVF_GIC_STATE, &blob)),
    };
    Ok(Output::Platform {
        platform,
        capabilities: vec![HVF_GIC_STATE_CAPABILITY.to_string()],
    })
}

/// Returns the host's `CLOCK_MONOTONIC`, in nanoseconds.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec for the call to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    u64::try_from(ts.tv_sec).unwrap_or(0) * 1_000_000_000 + u64::try_from(ts.tv_nsec).unwrap_or(0)
}

/// Returns a 32-bit GIC register's value, refusing one with high bits set.
fn word(what: &str, value: u64) -> io::Result<u32> {
    u32::try_from(value)
        .map_err(|_| io::Error::other(format!("{what} read {value:#x}, wider than 32 bits")))
}

/// A register of `regs`: a general register, or a stack pointer, which the
/// framework reaches as a system register.
#[derive(Clone, Copy)]
enum Gpr {
    Reg(Reg),
    Sys(SysReg),
}

/// The registers of [`aarch64_reg_names`], in its order.
const REGS: [Gpr; 37] = [
    Gpr::Reg(Reg::X0),
    Gpr::Reg(Reg::X1),
    Gpr::Reg(Reg::X2),
    Gpr::Reg(Reg::X3),
    Gpr::Reg(Reg::X4),
    Gpr::Reg(Reg::X5),
    Gpr::Reg(Reg::X6),
    Gpr::Reg(Reg::X7),
    Gpr::Reg(Reg::X8),
    Gpr::Reg(Reg::X9),
    Gpr::Reg(Reg::X10),
    Gpr::Reg(Reg::X11),
    Gpr::Reg(Reg::X12),
    Gpr::Reg(Reg::X13),
    Gpr::Reg(Reg::X14),
    Gpr::Reg(Reg::X15),
    Gpr::Reg(Reg::X16),
    Gpr::Reg(Reg::X17),
    Gpr::Reg(Reg::X18),
    Gpr::Reg(Reg::X19),
    Gpr::Reg(Reg::X20),
    Gpr::Reg(Reg::X21),
    Gpr::Reg(Reg::X22),
    Gpr::Reg(Reg::X23),
    Gpr::Reg(Reg::X24),
    Gpr::Reg(Reg::X25),
    Gpr::Reg(Reg::X26),
    Gpr::Reg(Reg::X27),
    Gpr::Reg(Reg::X28),
    Gpr::Reg(Reg::X29),
    Gpr::Reg(Reg::X30),
    Gpr::Sys(SysReg::SP_EL0),
    Gpr::Sys(SysReg::SP_EL1),
    Gpr::Reg(Reg::PC),
    Gpr::Reg(Reg::CPSR),
    Gpr::Reg(Reg::FPCR),
    Gpr::Reg(Reg::FPSR),
];

/// `q0`..`q31`.
const SIMD_REGS: [SimdFpReg; 32] = [
    SimdFpReg::Q0,
    SimdFpReg::Q1,
    SimdFpReg::Q2,
    SimdFpReg::Q3,
    SimdFpReg::Q4,
    SimdFpReg::Q5,
    SimdFpReg::Q6,
    SimdFpReg::Q7,
    SimdFpReg::Q8,
    SimdFpReg::Q9,
    SimdFpReg::Q10,
    SimdFpReg::Q11,
    SimdFpReg::Q12,
    SimdFpReg::Q13,
    SimdFpReg::Q14,
    SimdFpReg::Q15,
    SimdFpReg::Q16,
    SimdFpReg::Q17,
    SimdFpReg::Q18,
    SimdFpReg::Q19,
    SimdFpReg::Q20,
    SimdFpReg::Q21,
    SimdFpReg::Q22,
    SimdFpReg::Q23,
    SimdFpReg::Q24,
    SimdFpReg::Q25,
    SimdFpReg::Q26,
    SimdFpReg::Q27,
    SimdFpReg::Q28,
    SimdFpReg::Q29,
    SimdFpReg::Q30,
    SimdFpReg::Q31,
];

/// `GICR_IPRIORITYR0`..`7`.
const REDIST_PRIORITY: [GicRedistributorReg; 8] = [
    GicRedistributorReg::IPRIORITYR0,
    GicRedistributorReg::IPRIORITYR1,
    GicRedistributorReg::IPRIORITYR2,
    GicRedistributorReg::IPRIORITYR3,
    GicRedistributorReg::IPRIORITYR4,
    GicRedistributorReg::IPRIORITYR5,
    GicRedistributorReg::IPRIORITYR6,
    GicRedistributorReg::IPRIORITYR7,
];

/// Returns the framework's register for a system register of
/// [`AARCH64_SYSREGS`], by its name there.
#[allow(clippy::too_many_lines)]
pub(crate) fn sys_reg(name: &str) -> Option<SysReg> {
    Some(match name {
        "SCTLR_EL1" => SysReg::SCTLR_EL1,
        "ACTLR_EL1" => SysReg::ACTLR_EL1,
        "CPACR_EL1" => SysReg::CPACR_EL1,
        "TTBR0_EL1" => SysReg::TTBR0_EL1,
        "TTBR1_EL1" => SysReg::TTBR1_EL1,
        "TCR_EL1" => SysReg::TCR_EL1,
        "MAIR_EL1" => SysReg::MAIR_EL1,
        "AMAIR_EL1" => SysReg::AMAIR_EL1,
        "VBAR_EL1" => SysReg::VBAR_EL1,
        "ELR_EL1" => SysReg::ELR_EL1,
        "SPSR_EL1" => SysReg::SPSR_EL1,
        "ESR_EL1" => SysReg::ESR_EL1,
        "FAR_EL1" => SysReg::FAR_EL1,
        "PAR_EL1" => SysReg::PAR_EL1,
        "AFSR0_EL1" => SysReg::AFSR0_EL1,
        "AFSR1_EL1" => SysReg::AFSR1_EL1,
        "CONTEXTIDR_EL1" => SysReg::CONTEXTIDR_EL1,
        "TPIDR_EL0" => SysReg::TPIDR_EL0,
        "TPIDRRO_EL0" => SysReg::TPIDRRO_EL0,
        "TPIDR_EL1" => SysReg::TPIDR_EL1,
        "CNTKCTL_EL1" => SysReg::CNTKCTL_EL1,
        "CSSELR_EL1" => SysReg::CSSELR_EL1,
        "CNTV_CTL_EL0" => SysReg::CNTV_CTL_EL0,
        "CNTV_CVAL_EL0" => SysReg::CNTV_CVAL_EL0,
        "MDSCR_EL1" => SysReg::MDSCR_EL1,
        "MDCCINT_EL1" => SysReg::MDCCINT_EL1,
        "APIAKEYLO_EL1" => SysReg::APIAKEYLO_EL1,
        "APIAKEYHI_EL1" => SysReg::APIAKEYHI_EL1,
        "APIBKEYLO_EL1" => SysReg::APIBKEYLO_EL1,
        "APIBKEYHI_EL1" => SysReg::APIBKEYHI_EL1,
        "APDAKEYLO_EL1" => SysReg::APDAKEYLO_EL1,
        "APDAKEYHI_EL1" => SysReg::APDAKEYHI_EL1,
        "APDBKEYLO_EL1" => SysReg::APDBKEYLO_EL1,
        "APDBKEYHI_EL1" => SysReg::APDBKEYHI_EL1,
        "APGAKEYLO_EL1" => SysReg::APGAKEYLO_EL1,
        "APGAKEYHI_EL1" => SysReg::APGAKEYHI_EL1,
        "MPIDR_EL1" => SysReg::MPIDR_EL1,
        "SCXTNUM_EL0" => SysReg::SCXTNUM_EL0,
        "SCXTNUM_EL1" => SysReg::SCXTNUM_EL1,
        "TPIDR2_EL0" => SysReg::TPIDR2_EL0,
        "SMCR_EL1" => SysReg::SMCR_EL1,
        "SMPRI_EL1" => SysReg::SMPRI_EL1,
        "DBGBVR0_EL1" => SysReg::DBGBVR0_EL1,
        "DBGBCR0_EL1" => SysReg::DBGBCR0_EL1,
        "DBGWVR0_EL1" => SysReg::DBGWVR0_EL1,
        "DBGWCR0_EL1" => SysReg::DBGWCR0_EL1,
        "DBGBVR1_EL1" => SysReg::DBGBVR1_EL1,
        "DBGBCR1_EL1" => SysReg::DBGBCR1_EL1,
        "DBGWVR1_EL1" => SysReg::DBGWVR1_EL1,
        "DBGWCR1_EL1" => SysReg::DBGWCR1_EL1,
        "DBGBVR2_EL1" => SysReg::DBGBVR2_EL1,
        "DBGBCR2_EL1" => SysReg::DBGBCR2_EL1,
        "DBGWVR2_EL1" => SysReg::DBGWVR2_EL1,
        "DBGWCR2_EL1" => SysReg::DBGWCR2_EL1,
        "DBGBVR3_EL1" => SysReg::DBGBVR3_EL1,
        "DBGBCR3_EL1" => SysReg::DBGBCR3_EL1,
        "DBGWVR3_EL1" => SysReg::DBGWVR3_EL1,
        "DBGWCR3_EL1" => SysReg::DBGWCR3_EL1,
        "DBGBVR4_EL1" => SysReg::DBGBVR4_EL1,
        "DBGBCR4_EL1" => SysReg::DBGBCR4_EL1,
        "DBGWVR4_EL1" => SysReg::DBGWVR4_EL1,
        "DBGWCR4_EL1" => SysReg::DBGWCR4_EL1,
        "DBGBVR5_EL1" => SysReg::DBGBVR5_EL1,
        "DBGBCR5_EL1" => SysReg::DBGBCR5_EL1,
        "DBGWVR5_EL1" => SysReg::DBGWVR5_EL1,
        "DBGWCR5_EL1" => SysReg::DBGWCR5_EL1,
        "DBGBVR6_EL1" => SysReg::DBGBVR6_EL1,
        "DBGBCR6_EL1" => SysReg::DBGBCR6_EL1,
        "DBGWVR6_EL1" => SysReg::DBGWVR6_EL1,
        "DBGWCR6_EL1" => SysReg::DBGWCR6_EL1,
        "DBGBVR7_EL1" => SysReg::DBGBVR7_EL1,
        "DBGBCR7_EL1" => SysReg::DBGBCR7_EL1,
        "DBGWVR7_EL1" => SysReg::DBGWVR7_EL1,
        "DBGWCR7_EL1" => SysReg::DBGWCR7_EL1,
        "DBGBVR8_EL1" => SysReg::DBGBVR8_EL1,
        "DBGBCR8_EL1" => SysReg::DBGBCR8_EL1,
        "DBGWVR8_EL1" => SysReg::DBGWVR8_EL1,
        "DBGWCR8_EL1" => SysReg::DBGWCR8_EL1,
        "DBGBVR9_EL1" => SysReg::DBGBVR9_EL1,
        "DBGBCR9_EL1" => SysReg::DBGBCR9_EL1,
        "DBGWVR9_EL1" => SysReg::DBGWVR9_EL1,
        "DBGWCR9_EL1" => SysReg::DBGWCR9_EL1,
        "DBGBVR10_EL1" => SysReg::DBGBVR10_EL1,
        "DBGBCR10_EL1" => SysReg::DBGBCR10_EL1,
        "DBGWVR10_EL1" => SysReg::DBGWVR10_EL1,
        "DBGWCR10_EL1" => SysReg::DBGWCR10_EL1,
        "DBGBVR11_EL1" => SysReg::DBGBVR11_EL1,
        "DBGBCR11_EL1" => SysReg::DBGBCR11_EL1,
        "DBGWVR11_EL1" => SysReg::DBGWVR11_EL1,
        "DBGWCR11_EL1" => SysReg::DBGWCR11_EL1,
        "DBGBVR12_EL1" => SysReg::DBGBVR12_EL1,
        "DBGBCR12_EL1" => SysReg::DBGBCR12_EL1,
        "DBGWVR12_EL1" => SysReg::DBGWVR12_EL1,
        "DBGWCR12_EL1" => SysReg::DBGWCR12_EL1,
        "DBGBVR13_EL1" => SysReg::DBGBVR13_EL1,
        "DBGBCR13_EL1" => SysReg::DBGBCR13_EL1,
        "DBGWVR13_EL1" => SysReg::DBGWVR13_EL1,
        "DBGWCR13_EL1" => SysReg::DBGWCR13_EL1,
        "DBGBVR14_EL1" => SysReg::DBGBVR14_EL1,
        "DBGBCR14_EL1" => SysReg::DBGBCR14_EL1,
        "DBGWVR14_EL1" => SysReg::DBGWVR14_EL1,
        "DBGWCR14_EL1" => SysReg::DBGWCR14_EL1,
        "DBGBVR15_EL1" => SysReg::DBGBVR15_EL1,
        "DBGBCR15_EL1" => SysReg::DBGBCR15_EL1,
        "DBGWVR15_EL1" => SysReg::DBGWVR15_EL1,
        "DBGWCR15_EL1" => SysReg::DBGWCR15_EL1,
        _ => return None,
    })
}

/// `GICD_CTLR`.
const GICD_CTLR: u32 = 0x0000;
/// `GICD_TYPER`.
const GICD_TYPER: u32 = 0x0004;
/// `GICD_IGROUPR0`.
const GICD_IGROUPR: u32 = 0x0080;
/// `GICD_ISENABLER0`.
const GICD_ISENABLER: u32 = 0x0100;
/// `GICD_ISPENDR0`.
const GICD_ISPENDR: u32 = 0x0200;
/// `GICD_ISACTIVER0`.
const GICD_ISACTIVER: u32 = 0x0300;
/// `GICD_IPRIORITYR0`.
const GICD_IPRIORITYR: u32 = 0x0400;
/// `GICD_ICFGR0`.
const GICD_ICFGR: u32 = 0x0c00;
/// `GICD_IROUTER0`, the base the interrupt ID indexes; the first that
/// exists is `GICD_IROUTER32`.
const GICD_IROUTER: u32 = 0x6000;

/// Returns the distributor register at `offset`, when the framework names
/// one there.
///
/// The framework's enum is the register's offset, as its documentation says,
/// and lists over 1500 of them, which loops over the per-interrupt arrays
/// reach by offset as C callers do. Only an offset the enum declares may
/// become one, so each array's bounds are checked first: those are the ranges
/// of the declared variants, and the tests compare every one with its name.
fn dist_reg(offset: u32) -> Option<GicDistributorReg> {
    let in_array = |base: u32, stride: u32, first: u32, count: u32| {
        offset >= base + stride * first
            && offset < base + stride * (first + count)
            && (offset - base) % stride == 0
    };
    let declared = offset == GICD_CTLR
        || offset == GICD_TYPER
        || offset == 0xffe8
        || in_array(GICD_IGROUPR, 4, 0, 32)
        || in_array(GICD_ISENABLER, 4, 0, 32)
        || in_array(0x0180, 4, 0, 32)
        || in_array(GICD_ISPENDR, 4, 0, 32)
        || in_array(0x0280, 4, 0, 32)
        || in_array(GICD_ISACTIVER, 4, 0, 32)
        || in_array(0x0380, 4, 0, 32)
        || in_array(GICD_IPRIORITYR, 4, 0, 255)
        || in_array(GICD_ICFGR, 4, 0, 64)
        || in_array(GICD_IROUTER, 8, 32, GICV3_MAX_INTIDS - 32);
    // SAFETY: `GicDistributorReg` is a `repr(C)` enum, the size of a `u32`,
    // whose discriminants are the register offsets, and `offset` is one of
    // them: the ranges above are the declared variants, which the tests
    // check name by name.
    declared.then(|| unsafe { std::mem::transmute::<u32, GicDistributorReg>(offset) })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The table is the one place a canonical name meets the framework's
    // register, and the variant's own name is the check.
    #[test]
    fn every_system_register_name_is_its_framework_register() {
        let mut seen = Vec::new();
        for (name, _) in AARCH64_SYSREGS {
            let reg = sys_reg(name).unwrap_or_else(|| panic!("{name} has no register"));
            assert_eq!(format!("{reg:?}"), name);
            assert!(!seen.contains(&reg), "{name} is listed twice");
            seen.push(reg);
        }
        assert_eq!(sys_reg("CNTVCT_EL0"), None);
    }

    #[test]
    fn the_general_and_simd_registers_are_in_name_order() {
        for (name, reg) in aarch64_reg_names().iter().zip(REGS) {
            let framework = match reg {
                Gpr::Reg(reg) => format!("{reg:?}"),
                Gpr::Sys(reg) => format!("{reg:?}"),
            };
            let want = match name.as_str() {
                "pstate" => "CPSR".to_string(),
                other => other.to_uppercase(),
            };
            assert_eq!(framework, want);
        }
        for (n, q) in SIMD_REGS.iter().enumerate() {
            assert_eq!(format!("{q:?}"), format!("Q{n}"));
        }
        for (n, reg) in REDIST_PRIORITY.iter().enumerate() {
            assert_eq!(format!("{reg:?}"), format!("IPRIORITYR{n}"));
        }
    }

    #[test]
    fn every_distributor_offset_is_the_register_of_that_name() {
        let named = |offset: u32| dist_reg(offset).map(|reg| format!("{reg:?}"));
        assert_eq!(named(GICD_CTLR).as_deref(), Some("CTLR"));
        assert_eq!(named(GICD_TYPER).as_deref(), Some("TYPER"));
        assert_eq!(named(0xffe8).as_deref(), Some("PIDR2"));
        let arrays: [(&str, u32, u32, u32, u32); 10] = [
            ("IGROUPR", GICD_IGROUPR, 4, 0, 32),
            ("ISENABLER", GICD_ISENABLER, 4, 0, 32),
            ("ICENABLER", 0x0180, 4, 0, 32),
            ("ISPENDR", GICD_ISPENDR, 4, 0, 32),
            ("ICPENDR", 0x0280, 4, 0, 32),
            ("ISACTIVER", GICD_ISACTIVER, 4, 0, 32),
            ("ICACTIVER", 0x0380, 4, 0, 32),
            ("IPRIORITYR", GICD_IPRIORITYR, 4, 0, 255),
            ("ICFGR", GICD_ICFGR, 4, 0, 64),
            ("IROUTER", GICD_IROUTER, 8, 32, 988),
        ];
        let mut declared = 3;
        for (name, base, stride, first, count) in arrays {
            for n in first..first + count {
                assert_eq!(named(base + stride * n), Some(format!("{name}{n}")));
                declared += 1;
            }
            // Between two registers is not one. Past an array's end is the
            // next array, or nothing, which the count below checks.
            if first > 0 {
                assert_eq!(named(base + stride * (first - 1)), None, "{name}");
            }
            assert_eq!(named(base + stride * first + 1), None, "{name}");
        }
        // Every offset in the distributor's 64 KiB: only those above are
        // registers.
        let all = (0..0x1_0000).filter(|o| dist_reg(*o).is_some()).count();
        assert_eq!(all, declared);
    }
}

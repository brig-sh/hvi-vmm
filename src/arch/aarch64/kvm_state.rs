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

//! A KVM arm64 vCPU, read into the canonical checkpoint state by name.
//!
//! [`export`] reads every register `KVM_GET_REG_LIST` names and puts each
//! where its class in `checkpoint::kvm_regs` says: a shared register under
//! its canonical name, a firmware or fixed register under `firmware` or
//! `fixed`, and nothing of what the machine sets. An id with no rule fails
//! the export. The vCPU's `KVM_GET_MP_STATE` and `KVM_GET_VCPU_EVENTS`
//! complete it. A vCPU that is stopped (powered off, or never started) is
//! written as off, with no register: PSCI `CPU_ON` sets the ones it starts
//! from.
//!
//! The registers are reached through [`OneReg`], so the conversion is tested
//! without KVM.

use std::collections::BTreeMap;
use std::io;

use crate::checkpoint::cpu::{
    aarch64_reg_names, simd_hex, Aarch64Vcpu, Arm64Events, Hex64, Need, Power, VcpuTimer,
    AARCH64_SIMD_REGS, AARCH64_SYSREGS,
};
use crate::checkpoint::kvm_regs::{classify, size_of, Check, Class, Slot};

/// `KVM_MP_STATE_RUNNABLE`.
pub(crate) const MP_RUNNABLE: u32 = 0;
/// `KVM_MP_STATE_STOPPED`: powered off.
pub(crate) const MP_STOPPED: u32 = 5;
/// `KVM_MP_STATE_SUSPENDED`: in a PSCI `SYSTEM_SUSPEND`.
pub(crate) const MP_SUSPENDED: u32 = 9;

/// Returns `mp_state`'s name in `cpu.json`.
pub(crate) fn mp_state_name(mp_state: u32) -> Option<&'static str> {
    match mp_state {
        MP_RUNNABLE => Some("runnable"),
        MP_STOPPED => Some("stopped"),
        MP_SUSPENDED => Some("suspended"),
        _ => None,
    }
}

/// Returns the `mp_state` named `name` in `cpu.json`.
pub(crate) fn mp_state_of(name: &str) -> Option<u32> {
    [MP_RUNNABLE, MP_STOPPED, MP_SUSPENDED]
        .into_iter()
        .find(|s| mp_state_name(*s) == Some(name))
}

/// A vCPU's registers and state as KVM gives them.
pub(crate) trait OneReg {
    /// Returns every register id the vCPU has.
    ///
    /// # Errors
    ///
    /// Errors when KVM refuses the list.
    fn reg_list(&self) -> io::Result<Vec<u64>>;
    /// Reads register `id`, whose value is `buf.len()` bytes, little-endian.
    ///
    /// # Errors
    ///
    /// Errors when KVM refuses it.
    fn get(&self, id: u64, buf: &mut [u8]) -> io::Result<()>;
    /// Writes register `id`.
    ///
    /// # Errors
    ///
    /// Errors when KVM refuses it.
    fn set(&self, id: u64, buf: &[u8]) -> io::Result<()>;
    /// Returns `KVM_GET_MP_STATE`.
    ///
    /// # Errors
    ///
    /// Errors when KVM refuses it.
    fn mp_state(&self) -> io::Result<u32>;
    /// Returns what `KVM_GET_VCPU_EVENTS` holds pending.
    ///
    /// # Errors
    ///
    /// Errors when KVM refuses it.
    fn events(&self) -> io::Result<Arm64Events>;
    /// Sets `KVM_SET_MP_STATE`.
    ///
    /// # Errors
    ///
    /// Errors when KVM refuses it.
    fn set_mp_state(&self, mp_state: u32) -> io::Result<()>;
    /// Makes `events` pending, `KVM_SET_VCPU_EVENTS`.
    ///
    /// # Errors
    ///
    /// Errors when KVM refuses it.
    fn set_events(&self, events: &Arm64Events) -> io::Result<()>;
}

#[cfg(target_os = "linux")]
impl OneReg for kvm_ioctls::VcpuFd {
    fn reg_list(&self) -> io::Result<Vec<u64>> {
        // 500 is the most kvm-bindings' list holds; a Pi 5's vCPU has 259.
        let mut list = kvm_bindings::RegList::new(500)
            .map_err(|e| io::Error::other(format!("KVM_GET_REG_LIST: {e:?}")))?;
        self.get_reg_list(&mut list)
            .map_err(|e| io::Error::other(format!("KVM_GET_REG_LIST: {e}")))?;
        Ok(list.as_slice().to_vec())
    }

    fn get(&self, id: u64, buf: &mut [u8]) -> io::Result<()> {
        self.get_one_reg(id, buf)
            .map(|_| ())
            .map_err(io::Error::from)
    }

    fn set(&self, id: u64, buf: &[u8]) -> io::Result<()> {
        self.set_one_reg(id, buf)
            .map(|_| ())
            .map_err(io::Error::from)
    }

    fn mp_state(&self) -> io::Result<u32> {
        Ok(self.get_mp_state()?.mp_state)
    }

    fn events(&self) -> io::Result<Arm64Events> {
        let e = self.get_vcpu_events()?.exception;
        Ok(Arm64Events {
            serror_pending: e.serror_pending != 0,
            serror_has_esr: e.serror_has_esr != 0,
            ext_dabt_pending: e.ext_dabt_pending != 0,
            serror_esr: Hex64(e.serror_esr),
        })
    }

    fn set_mp_state(&self, mp_state: u32) -> io::Result<()> {
        Ok(kvm_ioctls::VcpuFd::set_mp_state(
            self,
            kvm_bindings::kvm_mp_state { mp_state },
        )?)
    }

    fn set_events(&self, events: &Arm64Events) -> io::Result<()> {
        let mut e = kvm_bindings::kvm_vcpu_events::default();
        e.exception.serror_pending = u8::from(events.serror_pending);
        e.exception.serror_has_esr = u8::from(events.serror_has_esr);
        e.exception.ext_dabt_pending = u8::from(events.ext_dabt_pending);
        e.exception.serror_esr = events.serror_esr.0;
        Ok(self.set_vcpu_events(&e)?)
    }
}

/// Reads register `id` as a number, of whatever width it has.
fn read(vcpu: &impl OneReg, id: u64) -> io::Result<u128> {
    let size = size_of(id);
    if size > 16 {
        return Err(io::Error::other(format!(
            "register {id:#x} is {size} bytes wide"
        )));
    }
    let mut buf = [0u8; 16];
    vcpu.get(id, &mut buf[..size])
        .map_err(|e| io::Error::other(format!("reading register {id:#x}: {e}")))?;
    Ok(u128::from_le_bytes(buf))
}

/// Reads vCPU `cpu`'s whole state by name.
///
/// # Errors
///
/// Errors when KVM refuses a read, when the vCPU has a register hvi has no
/// rule for, or when it lacks one a restore needs.
pub(crate) fn export(cpu: u32, vcpu: &impl OneReg) -> io::Result<Aarch64Vcpu> {
    let fail = |why: String| io::Error::other(format!("vCPU {cpu}: {why}"));
    let mp_state = vcpu
        .mp_state()
        .map_err(|e| fail(format!("KVM_GET_MP_STATE: {e}")))?;
    let mp_name =
        mp_state_name(mp_state).ok_or_else(|| fail(format!("unknown mp_state {mp_state}")))?;
    let mut state = Aarch64Vcpu {
        id: cpu,
        power: Power::Off,
        mp_state: Some(mp_name.to_string()),
        regs: BTreeMap::new(),
        simd: Vec::new(),
        sysregs: BTreeMap::new(),
        timer: None,
        backend: "kvm".to_string(),
        kvm_extra: BTreeMap::new(),
        firmware: BTreeMap::new(),
        fixed: BTreeMap::new(),
        events: None,
        unavailable: Vec::new(),
        partial: false,
    };
    // A stopped vCPU is off: `CPU_ON` resets every register it starts
    // from, so none is kept, as on HVF.
    if mp_state == MP_STOPPED {
        return Ok(state);
    }
    state.power = Power::On;
    let mut simd = vec![None; AARCH64_SIMD_REGS];
    for id in vcpu.reg_list().map_err(|e| fail(e.to_string()))? {
        match classify(id) {
            Class::SetByBaseline(_) => {}
            Class::Refused(why) => {
                return Err(fail(format!(
                    "KVM lists register {id:#018x}, which a checkpoint cannot carry: {why}"
                )))
            }
            Class::Shared(slot) => {
                let value = read(vcpu, id).map_err(|e| fail(e.to_string()))?;
                match slot {
                    Slot::X(n) => {
                        state.regs.insert(format!("x{n}"), Hex64(value as u64));
                    }
                    Slot::Reg(name) => {
                        state.regs.insert(name.to_string(), Hex64(value as u64));
                    }
                    Slot::Q(n) => simd[n as usize] = Some(simd_hex(value)),
                    Slot::Sys(name) => {
                        state.sysregs.insert(name.to_string(), Hex64(value as u64));
                    }
                }
            }
            Class::CheckedEqual(check) => {
                let value = Hex64(read(vcpu, id).map_err(|e| fail(e.to_string()))? as u64);
                match check {
                    Check::Firmware(name) => state.firmware.insert(name.to_string(), value),
                    Check::Fixed { name, .. } => state.fixed.insert(name.to_string(), value),
                };
            }
        }
    }
    state.simd = simd
        .into_iter()
        .enumerate()
        .map(|(n, q)| q.ok_or_else(|| fail(format!("KVM does not list q{n}"))))
        .collect::<io::Result<_>>()?;
    if let Some(name) = aarch64_reg_names()
        .into_iter()
        .find(|n| !state.regs.contains_key(n))
    {
        return Err(fail(format!("KVM does not list {name}")));
    }
    for (name, need) in AARCH64_SYSREGS {
        if !state.sysregs.contains_key(name) {
            match need {
                Need::Optional => state.unavailable.push(name.to_string()),
                Need::Required => return Err(fail(format!("KVM does not list {name}"))),
            }
        }
    }
    // KVM keeps no mask of its own over the virtual timer's interrupt.
    state.timer = Some(VcpuTimer {
        vtimer_masked: false,
    });
    let events = vcpu
        .events()
        .map_err(|e| fail(format!("KVM_GET_VCPU_EVENTS: {e}")))?;
    state.events = events.any().then_some(events);
    Ok(state)
}

/// Writes register `id`, `value` cut to its width.
fn write(vcpu: &impl OneReg, id: u64, value: u128) -> io::Result<()> {
    let size = size_of(id);
    vcpu.set(id, &value.to_le_bytes()[..size.min(16)])
        .map_err(|e| io::Error::other(format!("writing register {id:#x}: {e}")))
}

/// The PSTATE a vCPU starts in after PSCI `CPU_ON`: EL1h, DAIF masked.
const CPU_ON_PSTATE: u64 = 0x3c5;

/// Loads `state` into vCPU `cpu`, a KVM vCPU created and initialised as the
/// boot creates it, with the machine's baseline and counter already set,
/// and not run yet.
///
/// Every register the vCPU lists is handled by its class in
/// `checkpoint::kvm_regs`: a shared one is written from its canonical name,
/// `MPIDR_EL1` compared; a checked one compared with the value the state
/// recorded, or, for a state HVF wrote under `portable`, the value a guest
/// on HVF sees; one the machine sets is left alone. A system register the
/// state holds and this vCPU does not list is refused, but under `portable`
/// for one whose feature the baseline hides (`kvm_regs::HIDDEN_BY_PORTABLE`)
/// and which holds 0.
/// Then the `mp_state` and any pending SError or abort are set. A vCPU that
/// was off is left stopped, and one whose `CPU_ON` was pending starts where
/// the call would have started it.
///
/// # Errors
///
/// Errors naming the register, on a refusal, a difference or a write KVM
/// refuses.
pub(crate) fn import(
    cpu: u32,
    vcpu: &impl OneReg,
    state: &Aarch64Vcpu,
    portable: bool,
) -> io::Result<()> {
    let fail = |why: String| io::Error::other(format!("vCPU {cpu}: {why}"));
    if state.id != cpu {
        return Err(fail(format!("handed the state of vCPU {}", state.id)));
    }
    state.check_restorable().map_err(io::Error::other)?;
    match state.power {
        Power::Off => {
            return vcpu
                .set_mp_state(MP_STOPPED)
                .map_err(|e| fail(format!("KVM_SET_MP_STATE: {e}")))
        }
        Power::PendingOn { entry, ctx } => {
            for (id, value) in [
                (crate::checkpoint::kvm_regs::id_of(Slot::Reg("pc")), entry.0),
                (Some(crate::checkpoint::kvm_regs::x_id(0)), ctx.0),
                (
                    crate::checkpoint::kvm_regs::id_of(Slot::Reg("pstate")),
                    CPU_ON_PSTATE,
                ),
            ] {
                let id = id.ok_or_else(|| fail("no core register id".to_string()))?;
                write(vcpu, id, u128::from(value)).map_err(|e| fail(e.to_string()))?;
            }
            return vcpu
                .set_mp_state(MP_RUNNABLE)
                .map_err(|e| fail(format!("KVM_SET_MP_STATE: {e}")));
        }
        Power::On => {}
    }
    let from_hvf = state.backend == "hvf";
    let mut listed = std::collections::BTreeSet::new();
    for id in vcpu.reg_list().map_err(|e| fail(e.to_string()))? {
        match classify(id) {
            Class::SetByBaseline(_) => {}
            Class::Refused(why) => {
                return Err(fail(format!(
                    "this host's KVM lists register {id:#018x}, which a restore cannot \
                     load: {why}"
                )))
            }
            Class::Shared(slot) => {
                let value = match slot {
                    Slot::X(n) => state.regs.get(&format!("x{n}")).map(|v| u128::from(v.0)),
                    Slot::Reg(name) => state.regs.get(name).map(|v| u128::from(v.0)),
                    Slot::Q(n) => state
                        .simd
                        .get(n as usize)
                        .and_then(|q| crate::checkpoint::cpu::parse_simd(q)),
                    Slot::Sys(name) => {
                        listed.insert(name);
                        state.sysregs.get(name).map(|v| u128::from(v.0))
                    }
                };
                let Some(value) = value else {
                    match slot {
                        // A register the source had no way to read is left
                        // at its reset value; check_restorable allowed it.
                        Slot::Sys(name) if state.unavailable.iter().any(|n| n == name) => continue,
                        _ => return Err(fail(format!("the state has no {slot:?}"))),
                    }
                };
                if slot == Slot::Sys("MPIDR_EL1") {
                    let have = read(vcpu, id).map_err(|e| fail(e.to_string()))?;
                    if have != value {
                        return Err(fail(format!(
                            "MPIDR_EL1 is {have:#x} here and {value:#x} in the state"
                        )));
                    }
                    continue;
                }
                write(vcpu, id, value).map_err(|e| fail(format!("{slot:?}: {e}")))?;
            }
            Class::CheckedEqual(check) => {
                let have = read(vcpu, id).map_err(|e| fail(e.to_string()))? as u64;
                let name = check.name();
                match check {
                    Check::Firmware(_) => {
                        let want = state.firmware.get(name).map(|v| v.0).or_else(|| {
                            (from_hvf && portable).then(|| {
                                crate::checkpoint::kvm_regs::PORTABLE_HVF_FIRMWARE
                                    .iter()
                                    .find(|(n, _)| *n == name)
                                    .map_or(u64::MAX, |(_, v)| *v)
                            })
                        });
                        match want {
                            Some(want) if want == have => {}
                            Some(want) => {
                                return Err(fail(format!(
                                    "firmware register {name} is {have:#x} here and was \
                                     {want:#x} at the capture: the guest's firmware would \
                                     answer otherwise"
                                )))
                            }
                            None => {
                                return Err(fail(format!(
                                    "the state does not record firmware register {name}"
                                )))
                            }
                        }
                    }
                    Check::Fixed { mask, hvf, .. } => {
                        let want = match state.fixed.get(name) {
                            Some(v) => v.0,
                            None if from_hvf => hvf,
                            None => return Err(fail(format!("the state does not record {name}"))),
                        };
                        if want & mask != have & mask {
                            return Err(fail(format!(
                                "{name} is {have:#x} here and was {want:#x} at the capture, \
                                 and a restore cannot set it"
                            )));
                        }
                    }
                }
            }
        }
    }
    // A register of a feature the baseline hides is dropped only at 0, the
    // value it has on HVF for a portable guest (measured), which never
    // writes it.
    let dropped = |name: &str, value: u64| {
        portable && value == 0 && crate::checkpoint::kvm_regs::HIDDEN_BY_PORTABLE.contains(&name)
    };
    if let Some((name, value)) = state
        .sysregs
        .iter()
        .find(|(n, v)| !(listed.contains(n.as_str()) || dropped(n, v.0)))
    {
        return Err(fail(format!(
            "the state holds {name} = {:#x}, which this host's KVM vCPU does not have",
            value.0
        )));
    }
    let mp_state = match state.mp_state.as_deref() {
        None => MP_RUNNABLE,
        Some(name) => mp_state_of(name)
            .filter(|s| *s != MP_STOPPED)
            .ok_or_else(|| fail(format!("mp_state {name} for a vCPU that is on")))?,
    };
    vcpu.set_mp_state(mp_state)
        .map_err(|e| fail(format!("KVM_SET_MP_STATE: {e}")))?;
    if let Some(events) = state.events.filter(Arm64Events::any) {
        vcpu.set_events(&events)
            .map_err(|e| fail(format!("KVM_SET_VCPU_EVENTS: {e}")))?;
    }
    Ok(())
}

/// Loads a portable guest's state into a KVM VM before any of its vCPUs
/// has run: each vCPU's registers by name, in index order, then the vGIC
/// from the canonical state, which holds every vCPU's CPU interface, then
/// `redrive`, which connects the devices' lines and drives each to its
/// device's level, since loading the vGIC set every line behind the
/// devices' backs. Returns how many vGIC registers were read back.
///
/// The vCPUs must be created and initialised, the VM's baseline, firmware
/// registers and counter offset set, and the vGIC initialised.
///
/// # Errors
///
/// Errors, before `redrive`, when a state is not an arm64 one for its
/// vCPU, a vCPU refuses its state, or the vGIC refuses the canonical one.
pub(crate) fn load_portable(
    vcpus: &[impl OneReg],
    states: &[crate::checkpoint::cpu::VcpuState],
    vgic: &impl crate::arch::aarch64::vgicv2::VgicV2,
    gic: &crate::devices::gicv2::Gicv2State,
    redrive: impl FnOnce(),
) -> io::Result<usize> {
    if vcpus.len() != states.len() {
        return Err(io::Error::other(format!(
            "{} vCPUs for {} states",
            vcpus.len(),
            states.len()
        )));
    }
    for (id, (vcpu, state)) in (0u32..).zip(vcpus.iter().zip(states)) {
        let crate::checkpoint::cpu::VcpuState::Aarch64(state) = state else {
            return Err(io::Error::other(format!(
                "cpu.json: vCPU {id} is not an arm64 state"
            )));
        };
        import(id, vcpu, state, true)?;
    }
    let checked = crate::arch::aarch64::vgicv2::import(vgic, gic)
        .map_err(|e| io::Error::other(format!("the vGICv2: {e}")))?;
    redrive();
    Ok(checked)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::checkpoint::kvm_regs::tests::fixture;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// A vCPU that lists what rp2's lists and holds `value(id)` in each.
    pub(crate) struct FakeVcpu {
        pub(crate) ids: Vec<u64>,
        pub(crate) values: RefCell<HashMap<u64, u128>>,
        pub(crate) mp_state: u32,
        pub(crate) events: Arm64Events,
        /// Writes KVM refuses, by id.
        pub(crate) refuse: Vec<u64>,
        /// The `mp_state` and events last set.
        pub(crate) set_state: RefCell<(Option<u32>, Option<Arm64Events>)>,
    }

    impl FakeVcpu {
        /// The portable vCPU of the fixture, with its measured values.
        pub(crate) fn rp2() -> Self {
            let mut values = HashMap::new();
            let mut ids = Vec::new();
            for (_, id, value) in fixture().into_iter().filter(|r| r.0 == "portable") {
                ids.push(id);
                values.insert(id, u128::from_str_radix(value, 16).unwrap());
            }
            Self {
                ids,
                values: RefCell::new(values),
                mp_state: MP_RUNNABLE,
                events: Arm64Events {
                    serror_pending: false,
                    serror_has_esr: false,
                    ext_dabt_pending: false,
                    serror_esr: Hex64(0),
                },
                refuse: Vec::new(),
                set_state: RefCell::new((None, None)),
            }
        }
    }

    impl OneReg for FakeVcpu {
        fn reg_list(&self) -> io::Result<Vec<u64>> {
            Ok(self.ids.clone())
        }
        fn get(&self, id: u64, buf: &mut [u8]) -> io::Result<()> {
            let v = *self
                .values
                .borrow()
                .get(&id)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
            buf.copy_from_slice(&v.to_le_bytes()[..buf.len()]);
            Ok(())
        }
        fn set(&self, id: u64, buf: &[u8]) -> io::Result<()> {
            if self.refuse.contains(&id) || !self.ids.contains(&id) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            let mut b = [0u8; 16];
            b[..buf.len()].copy_from_slice(buf);
            self.values.borrow_mut().insert(id, u128::from_le_bytes(b));
            Ok(())
        }
        fn mp_state(&self) -> io::Result<u32> {
            Ok(self.mp_state)
        }
        fn events(&self) -> io::Result<Arm64Events> {
            Ok(self.events)
        }
        fn set_mp_state(&self, mp_state: u32) -> io::Result<()> {
            self.set_state.borrow_mut().0 = Some(mp_state);
            Ok(())
        }
        fn set_events(&self, events: &Arm64Events) -> io::Result<()> {
            self.set_state.borrow_mut().1 = Some(*events);
            Ok(())
        }
    }

    // The Pi's vCPU exports a whole state: every canonical register but the
    // ones the baseline hides, the firmware and fixed registers, nothing
    // else.
    #[test]
    fn a_kvm_vcpu_exports_a_whole_state() {
        let vcpu = FakeVcpu::rp2();
        vcpu.values
            .borrow_mut()
            .insert(crate::checkpoint::kvm_regs::q_id(3), 0x0102 << 64 | 0x0304);
        let state = export(0, &vcpu).unwrap();
        state.check_restorable().unwrap();
        assert_eq!(state.power, Power::On);
        assert_eq!(state.mp_state.as_deref(), Some("runnable"));
        assert_eq!(state.regs["pstate"], Hex64(0x3c5));
        assert_eq!(state.simd[3], simd_hex(0x0102 << 64 | 0x0304));
        assert_eq!(state.sysregs["MPIDR_EL1"], Hex64(0x8000_0000));
        assert_eq!(state.sysregs["CNTV_CTL_EL0"], Hex64(4));
        assert_eq!(state.firmware.len(), 7);
        assert_eq!(state.firmware["PSCI_VERSION"], Hex64(0x1_0001));
        assert_eq!(state.fixed["OSLSR_EL1"], Hex64(8));
        assert_eq!(state.unavailable.len(), 15);
        assert!(state.unavailable.contains(&"APIAKEYLO_EL1".to_string()));
        assert!(state.events.is_none());
        assert!(state.kvm_extra.is_empty());
    }

    #[test]
    fn a_stopped_vcpu_exports_as_off() {
        let mut vcpu = FakeVcpu::rp2();
        vcpu.mp_state = MP_STOPPED;
        let state = export(1, &vcpu).unwrap();
        assert_eq!(state.power, Power::Off);
        assert!(state.regs.is_empty() && state.sysregs.is_empty());
        state.check_restorable().unwrap();
    }

    #[test]
    fn a_register_without_a_rule_fails_the_export() {
        let mut vcpu = FakeVcpu::rp2();
        // An SVE register.
        vcpu.ids.push(0x6080_0000_0015_0000);
        let err = export(0, &vcpu).unwrap_err().to_string();
        assert!(err.contains("0x6080000000150000"), "{err}");
        // And a pending SError is kept.
        let mut vcpu = FakeVcpu::rp2();
        vcpu.events.serror_pending = true;
        assert!(export(0, &vcpu).unwrap().events.unwrap().serror_pending);
    }

    // A state exported from one Pi vCPU loads into another, and reads back
    // the same.
    #[test]
    fn a_kvm_state_round_trips_through_a_kvm_vcpu() {
        let source = FakeVcpu::rp2();
        source
            .values
            .borrow_mut()
            .insert(crate::checkpoint::kvm_regs::x_id(7), 0x77);
        let mut state = export(0, &source).unwrap();
        state.sysregs.insert("TPIDR_EL0".into(), Hex64(0xabc));
        state.events = Some(Arm64Events {
            serror_pending: true,
            serror_has_esr: false,
            ext_dabt_pending: false,
            serror_esr: Hex64(0),
        });
        let dest = FakeVcpu::rp2();
        import(0, &dest, &state, false).unwrap();
        assert_eq!(dest.set_state.borrow().0, Some(MP_RUNNABLE));
        assert!(dest.set_state.borrow().1.unwrap().serror_pending);
        let back = export(0, &dest).unwrap();
        assert_eq!(back.regs["x7"], Hex64(0x77));
        assert_eq!(back.sysregs["TPIDR_EL0"], Hex64(0xabc));
        assert_eq!(back.sysregs, state.sysregs);
        assert_eq!(back.simd, state.simd);
    }

    // An HVF state of a portable guest loads: the registers the baseline
    // hides on KVM are dropped, and the firmware and fixed registers are
    // compared with what a guest on HVF sees.
    #[test]
    fn a_portable_hvf_state_loads_into_a_kvm_vcpu() {
        let mut state = crate::checkpoint::cpu::tests::whole(0);
        state.sysregs.insert("MPIDR_EL1".into(), Hex64(0x8000_0000));
        // A portable guest on HVF holds 0 in what the baseline hides.
        for name in crate::checkpoint::kvm_regs::HIDDEN_BY_PORTABLE {
            state.sysregs.insert(name.into(), Hex64(0));
        }
        let dest = FakeVcpu::rp2();
        import(0, &dest, &state, true).unwrap();
        // One it set is not dropped.
        let mut keyed = state.clone();
        keyed.sysregs.insert("APIAKEYLO_EL1".into(), Hex64(7));
        let err = import(0, &FakeVcpu::rp2(), &keyed, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("APIAKEYLO_EL1 = 0x7"), "{err}");
        // The native machine has no such rules.
        let err = import(0, &FakeVcpu::rp2(), &state, false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not record firmware register PSCI_VERSION"),
            "{err}"
        );
        let mut recorded = state.clone();
        for (name, value) in crate::checkpoint::kvm_regs::PORTABLE_HVF_FIRMWARE {
            recorded.firmware.insert(name.to_string(), Hex64(value));
        }
        let err = import(0, &FakeVcpu::rp2(), &recorded, false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("which this host's KVM vCPU does not have"),
            "{err}"
        );
        // A fixed register KVM holds otherwise than HVF's guest saw.
        let dest = FakeVcpu::rp2();
        let oslsr = crate::checkpoint::kvm_regs::sysreg_id([2, 0, 1, 1, 4]);
        dest.values.borrow_mut().insert(oslsr, 0xa);
        let err = import(0, &dest, &state, true).unwrap_err().to_string();
        assert!(err.contains("OSLSR_EL1 is 0xa here and was 0x8"), "{err}");
    }

    #[test]
    fn what_kvm_cannot_load_is_refused() {
        let source = FakeVcpu::rp2();
        let state = export(0, &source).unwrap();
        // Another MPIDR_EL1.
        let dest = FakeVcpu::rp2();
        let mut second = Aarch64Vcpu {
            id: 1,
            ..state.clone()
        };
        second
            .sysregs
            .insert("MPIDR_EL1".into(), Hex64(0x8000_0001));
        let err = import(1, &dest, &second, false).unwrap_err().to_string();
        assert!(
            err.contains("MPIDR_EL1 is 0x80000000 here and 0x80000001"),
            "{err}"
        );
        // Firmware that answers otherwise.
        let mut other = state.clone();
        other
            .firmware
            .insert("SMCCC_ARCH_WORKAROUND_3".into(), Hex64(0));
        let err = import(0, &FakeVcpu::rp2(), &other, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("SMCCC_ARCH_WORKAROUND_3"), "{err}");
        // A write KVM refuses.
        let mut dest = FakeVcpu::rp2();
        let sctlr = crate::checkpoint::kvm_regs::sysreg_id([3, 0, 1, 0, 0]);
        dest.refuse.push(sctlr);
        assert!(import(0, &dest, &state, false)
            .unwrap_err()
            .to_string()
            .contains("SCTLR_EL1"));
        // A register this host lists that no rule covers.
        let mut dest = FakeVcpu::rp2();
        dest.ids.push(0x6080_0000_0015_0000);
        assert!(import(0, &dest, &state, false)
            .unwrap_err()
            .to_string()
            .contains("a restore cannot load"));
    }

    #[test]
    fn off_and_pending_vcpus_start_as_psci_would_start_them() {
        let dest = FakeVcpu::rp2();
        let off = crate::checkpoint::cpu::VcpuState::powered_off(
            crate::plugin::GuestArch::Aarch64,
            "kvm",
            1,
        );
        let crate::checkpoint::cpu::VcpuState::Aarch64(off) = off else {
            unreachable!()
        };
        import(1, &dest, &off, true).unwrap();
        assert_eq!(dest.set_state.borrow().0, Some(MP_STOPPED));
        let pending = Aarch64Vcpu {
            power: Power::PendingOn {
                entry: Hex64(0x4008_0000),
                ctx: Hex64(5),
            },
            ..off
        };
        let dest = FakeVcpu::rp2();
        import(1, &dest, &pending, true).unwrap();
        assert_eq!(dest.set_state.borrow().0, Some(MP_RUNNABLE));
        let pc = crate::checkpoint::kvm_regs::id_of(Slot::Reg("pc")).unwrap();
        assert_eq!(dest.values.borrow()[&pc], 0x4008_0000);
    }

    /// The order of what a restore did, by kind.
    type Order = RefCell<Vec<&'static str>>;

    /// A vCPU that logs each write.
    struct LoggedVcpu<'a>(FakeVcpu, &'a Order);

    impl OneReg for LoggedVcpu<'_> {
        fn reg_list(&self) -> io::Result<Vec<u64>> {
            self.0.reg_list()
        }
        fn get(&self, id: u64, buf: &mut [u8]) -> io::Result<()> {
            self.0.get(id, buf)
        }
        fn set(&self, id: u64, buf: &[u8]) -> io::Result<()> {
            self.1.borrow_mut().push("vcpu");
            self.0.set(id, buf)
        }
        fn mp_state(&self) -> io::Result<u32> {
            self.0.mp_state()
        }
        fn events(&self) -> io::Result<Arm64Events> {
            self.0.events()
        }
        fn set_mp_state(&self, mp_state: u32) -> io::Result<()> {
            self.1.borrow_mut().push("vcpu");
            self.0.set_mp_state(mp_state)
        }
        fn set_events(&self, events: &Arm64Events) -> io::Result<()> {
            self.0.set_events(events)
        }
    }

    /// A vGIC that logs each write.
    struct LoggedVgic<'a>(crate::arch::aarch64::vgicv2::tests::Fake, &'a Order);

    impl crate::arch::aarch64::vgicv2::VgicV2 for LoggedVgic<'_> {
        fn ncpu(&self) -> usize {
            self.0.ncpu()
        }
        fn read(
            &self,
            bank: crate::arch::aarch64::vgicv2::Bank,
            cpu: usize,
            offset: u64,
        ) -> Result<u32, String> {
            self.0.read(bank, cpu, offset)
        }
        fn write(
            &self,
            bank: crate::arch::aarch64::vgicv2::Bank,
            cpu: usize,
            offset: u64,
            value: u32,
        ) -> Result<(), String> {
            self.1.borrow_mut().push("vgic");
            self.0.write(bank, cpu, offset, value)
        }
        fn set_line(&self, cpu: usize, intid: u32, level: bool) -> Result<(), String> {
            self.1.borrow_mut().push("vgic");
            self.0.set_line(cpu, intid, level)
        }
    }

    // The restore's order before any vCPU runs: every vCPU's registers,
    // then the vGIC, then the lines, which the vGIC load set behind the
    // devices' backs. A vGIC that refuses the state stops it before the
    // lines.
    #[test]
    fn a_kvm_restore_loads_the_vcpus_then_the_vgic_then_the_lines() {
        use crate::arch::aarch64::vgicv2::tests::{busy_state, Fake};
        let source = FakeVcpu::rp2();
        let state = crate::checkpoint::cpu::VcpuState::Aarch64(export(0, &source).unwrap());
        let mut gic = busy_state();
        gic.cpus.truncate(1);
        // busy_state has two CPUs; keep cpu0's SGIs to itself.
        for s in &mut gic.cpus[0].sgi_sources {
            *s &= 1;
        }
        for t in &mut gic.dist.itargetsr {
            *t &= 1;
        }
        let order = Order::default();
        let vcpus = [LoggedVcpu(FakeVcpu::rp2(), &order)];
        let vgic = LoggedVgic(Fake::new(1), &order);
        let checked = load_portable(&vcpus, std::slice::from_ref(&state), &vgic, &gic, || {
            order.borrow_mut().push("redrive");
        })
        .unwrap();
        assert!(checked > 0);
        let mut runs: Vec<&str> = order.borrow().clone();
        runs.dedup();
        assert_eq!(runs, ["vcpu", "vgic", "redrive"]);

        let order = Order::default();
        let vcpus = [LoggedVcpu(FakeVcpu::rp2(), &order)];
        let vgic = LoggedVgic(Fake::new(1), &order);
        let mut refused = gic.clone();
        refused.cpus[0].apr[2] = 1;
        let err = load_portable(
            &vcpus,
            std::slice::from_ref(&state),
            &vgic,
            &refused,
            || {
                order.borrow_mut().push("redrive");
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("the vGICv2"), "{err}");
        assert!(!order.borrow().contains(&"redrive"));
        // A state for another number of vCPUs is refused before anything
        // is written.
        let order = Order::default();
        let vcpus = [LoggedVcpu(FakeVcpu::rp2(), &order)];
        assert!(load_portable(&vcpus, &[state.clone(), state], &vgic, &gic, || {}).is_err());
        assert!(order.borrow().is_empty());
    }
}

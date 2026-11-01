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

//! A vCPU thread of an arm64 guest on Hypervisor.framework, with the vCPU's
//! creation and start, its exit loop, and the MMIO, PSCI and system-register
//! exits it serves.

use std::ops::ControlFlow;
use std::sync::Arc;

use applevisor::prelude::{ExitReason, Reg, SysReg, Vcpu};

use super::gic::VmGic;
use super::kick::Kicker;
use crate::arch::aarch64::esr::{DataAbort, Ec};
use crate::arch::aarch64::layout::{mpidr_affinity, vcpu_index};
use crate::arch::aarch64::psci;
use crate::config::Stop;
use crate::devices::bus::UnclaimedError;
use crate::hypervisor::guest::{Guest, SafepointVcpu};
use crate::hypervisor::vcpus::{panic_detail, report_on_panic, Outcome};
use crate::plugin::{Plugin, RegsView};
use crate::LOG_PREFIX;

/// The state a vCPU thread needs beyond its own vCPU.
#[derive(Clone)]
pub(super) struct VcpuContext {
    /// The VM the vCPU is created in.
    pub(super) vm: VmGic,
    /// The guest's RAM, virtio devices and vCPUs.
    pub(super) guest: Arc<Guest<Kicker>>,
    /// The kernel entry the boot vCPU starts at.
    pub(super) kernel_addr: u64,
    /// The devicetree address the boot vCPU gets in `X0`.
    pub(super) dtb_addr: u64,
    /// The plugin, if the caller supplied one.
    pub(super) plugin: Option<Arc<dyn Plugin>>,
}

/// Creates vCPU `cpu_id`, starts it at the boot entry or at a `CPU_ON`, and
/// runs it until the VM stops.
pub(super) fn run_cpu(cpu_id: u32, context: VcpuContext) {
    // The vCPU is in an `Rc` so the panic report below can read it on this
    // thread.
    let vcpu = match context.vm.vcpu_create() {
        Ok(v) => std::rc::Rc::new(v),
        Err(e) => {
            context.guest.vcpus.report(Outcome::Failed(format!(
                "vcpu{cpu_id}: vcpu_create failed: {e:?}"
            )));
            return;
        }
    };
    let _ = vcpu.set_trap_debug_exceptions(false);
    let _ = vcpu.set_trap_debug_reg_accesses(false);
    // The affinity the devicetree names this vCPU by, with RES1 bit 31 set.
    let mpidr = 0x8000_0000 | u64::from(mpidr_affinity(cpu_id));
    let _ = vcpu.set_sys_reg(SysReg::MPIDR_EL1, mpidr);
    // Declared after the vCPU, so it drops first.
    let _registration = context.guest.vcpus.kicker().register(cpu_id, &vcpu);
    // A panic report names where the guest was and what it last did, so it is
    // usable without a debugger. The exit is left out until a run of the vCPU
    // has returned, since its exit information holds nothing before that.
    let ran = std::rc::Rc::new(std::cell::Cell::new(false));
    let _detail = report_on_panic({
        let vcpu = std::rc::Rc::clone(&vcpu);
        let ran = std::rc::Rc::clone(&ran);
        move || {
            let pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
            Some(if ran.get() {
                format!("last exit {:?}, pc {pc:#x}", vcpu.get_exit_info().reason)
            } else {
                format!("pc {pc:#x}")
            })
        }
    });

    if cpu_id == 0 {
        let _ = vcpu.set_reg(Reg::PC, context.kernel_addr);
        let _ = vcpu.set_reg(Reg::X0, context.dtb_addr);
        let _ = vcpu.set_reg(Reg::X1, 0);
        let _ = vcpu.set_reg(Reg::X2, 0);
        let _ = vcpu.set_reg(Reg::X3, 0);
        let _ = vcpu.set_reg(Reg::CPSR, 0x3c5); // EL1h, DAIF masked
    } else {
        // Park until the guest brings this cpu up via PSCI CPU_ON.
        let vcpus = &context.guest.vcpus;
        match vcpus
            .kicker()
            .wait_for_cpu_on(cpu_id, || vcpus.is_running())
        {
            Some((entry, ctx)) => {
                stderrln!("{LOG_PREFIX} vcpu{cpu_id}: PSCI CPU_ON -> {entry:#x}");
                let _ = vcpu.set_reg(Reg::PC, entry);
                let _ = vcpu.set_reg(Reg::X0, ctx);
                let _ = vcpu.set_reg(Reg::CPSR, 0x3c5);
            }
            None => return, // stopped while waiting
        }
    }
    context.guest.vcpus.mark_started(cpu_id);

    // The plugin runs on vcpu0, between guest entries, because only this thread
    // can read this vCPU's registers.
    let plugin = context.plugin.as_deref().filter(|_| cpu_id == 0);
    // The loop runs inside `catch_unwind` only for the panic report. The thread
    // then reports its exit like any other.
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        while context.guest.vcpus.is_running() {
            // Safe point for every vCPU: park here while vcpu0 lets a plugin
            // look at the guest.
            context.guest.pass_safepoint(&*vcpu, plugin);

            let flow = match vcpu.run() {
                Ok(()) => {
                    ran.set(true);
                    handle_exit(&vcpu, &context, cpu_id)
                }
                Err(e) => ControlFlow::Break(Outcome::Failed(format!(
                    "vcpu{cpu_id}: vcpu run failed: {e:?}"
                ))),
            };
            if let ControlFlow::Break(outcome) = flow {
                context.guest.vcpus.report(outcome);
                break;
            }
        }
    }));

    if let Err(payload) = unwound {
        let detail = panic_detail()
            .map(|detail| format!("; {detail}"))
            .unwrap_or_default();
        context.guest.vcpus.report(Outcome::Failed(format!(
            "vcpu{cpu_id}: panicked ({}){detail}",
            crate::panic_message(payload.as_ref()),
        )));
    }
}

/// Services one exit of vCPU `cpu_id`.
///
/// Returns `ControlFlow::Break` with the run's outcome when the exit ends the
/// run, and `ControlFlow::Continue` otherwise. The outcome is a guest-requested
/// stop or a failure.
fn handle_exit(vcpu: &Vcpu, context: &VcpuContext, cpu_id: u32) -> ControlFlow<Outcome> {
    let exit = vcpu.get_exit_info();
    match exit.reason {
        ExitReason::EXCEPTION => {
            let syn = exit.exception.syndrome;
            match Ec::from_syndrome(syn) {
                Ec::Hvc | Ec::Smc => {
                    service_psci(vcpu, context)?;
                    // Not restartable: the saved PC is already past HVC/SMC.
                }
                Ec::DataAbort => {
                    let da = DataAbort::from_syndrome(syn);
                    let ipa = exit.exception.physical_address;
                    // Guest RAM never traps, so this address has no cached data
                    // to act on, and the instruction has nothing to do. A table
                    // walk that took the abort has no result to give it, so it
                    // goes on to fail the run below.
                    if da.cm && !da.s1ptw {
                        advance_pc(vcpu);
                        return ControlFlow::Continue(());
                    }
                    // Without a syndrome the register and the width are
                    // unknown, so the access cannot be served.
                    if !da.isv {
                        return ControlFlow::Break(Outcome::Failed(format!(
                            "vcpu{cpu_id}: MMIO at {ipa:#x} without a syndrome (pc {:#x})",
                            vcpu.get_reg(Reg::PC).unwrap_or(0)
                        )));
                    }
                    service_mmio(vcpu, context, cpu_id, ipa, da)?;
                    advance_pc(vcpu);
                }
                Ec::SysReg => {
                    // RAZ/WI: unmodeled system register.
                    let iss = syn & 0x1ff_ffff;
                    if iss & 1 == 1 {
                        write_gpr(vcpu, ((iss >> 5) & 0x1f) as u8, 0);
                    }
                    advance_pc(vcpu);
                }
                Ec::Other(0x01) => {} // WFx: hvf handled the wait.
                other => {
                    return ControlFlow::Break(Outcome::Failed(format!(
                        "vcpu{cpu_id}: unhandled exception {other:?} (pc {:#x})",
                        vcpu.get_reg(Reg::PC).unwrap_or(0)
                    )));
                }
            }
        }
        ExitReason::VTIMER_ACTIVATED => {
            let _ = vcpu.set_vtimer_mask(true);
        }
        ExitReason::CANCELED => {} // kicked for a snapshot or a stop
        ExitReason::UNKNOWN => {
            // hvf could not say why it exited, so there is nothing to resume
            // into.
            return ControlFlow::Break(Outcome::Failed(format!(
                "vcpu{cpu_id}: unknown exit reason (pc {:#x})",
                vcpu.get_reg(Reg::PC).unwrap_or(0)
            )));
        }
    }
    ControlFlow::Continue(())
}

impl SafepointVcpu for Vcpu {
    fn regs(&self) -> RegsView {
        let ttbr1 = self.get_sys_reg(SysReg::TTBR1_EL1).unwrap_or(0);
        RegsView {
            // arm64's kernel-half page-table base is the walk root.
            root: ttbr1,
            pc: self.get_reg(Reg::PC).unwrap_or(0),
            cpsr: self.get_reg(Reg::CPSR).unwrap_or(0),
            ttbr0: self.get_sys_reg(SysReg::TTBR0_EL1).unwrap_or(0),
            ttbr1,
            sctlr: self.get_sys_reg(SysReg::SCTLR_EL1).unwrap_or(0),
            sp_el1: self.get_sys_reg(SysReg::SP_EL1).unwrap_or(0),
            tcr: self.get_sys_reg(SysReg::TCR_EL1).unwrap_or(0),
            current_task: self.get_sys_reg(SysReg::SP_EL0).unwrap_or(0),
        }
    }
}

/// Services a PSCI call.
///
/// Returns `ControlFlow::Break` with the stop for `SYSTEM_OFF` and
/// `SYSTEM_RESET`, and `ControlFlow::Continue` otherwise.
fn service_psci(vcpu: &Vcpu, context: &VcpuContext) -> ControlFlow<Outcome> {
    let fid = vcpu.get_reg(Reg::X0).unwrap_or(0);
    match fid {
        psci::VERSION => {
            let _ = vcpu.set_reg(Reg::X0, 0x0001_0000); // v1.0
            ControlFlow::Continue(())
        }
        psci::SYSTEM_OFF => ControlFlow::Break(Outcome::Stopped(Stop::SystemOff)),
        psci::SYSTEM_RESET => ControlFlow::Break(Outcome::Stopped(Stop::SystemReset)),
        psci::FEATURES => {
            let q = vcpu.get_reg(Reg::X1).unwrap_or(0);
            let known = matches!(
                q,
                psci::VERSION
                    | psci::SYSTEM_OFF
                    | psci::SYSTEM_RESET
                    | psci::FEATURES
                    | psci::CPU_ON_64
            );
            let _ = vcpu.set_reg(
                Reg::X0,
                if known {
                    psci::SUCCESS
                } else {
                    psci::NOT_SUPPORTED
                },
            );
            ControlFlow::Continue(())
        }
        psci::CPU_ON_64 => {
            let target = vcpu.get_reg(Reg::X1).unwrap_or(0);
            let entry = vcpu.get_reg(Reg::X2).unwrap_or(0);
            let ctx = vcpu.get_reg(Reg::X3).unwrap_or(0);
            let kicker = context.guest.vcpus.kicker();
            let ret = match vcpu_index(target) {
                Some(cpu) if kicker.cpu_on(cpu, entry, ctx) => psci::SUCCESS,
                _ => psci::NOT_SUPPORTED,
            };
            let _ = vcpu.set_reg(Reg::X0, ret);
            ControlFlow::Continue(())
        }
        psci::CPU_OFF => {
            let _ = vcpu.set_reg(Reg::X0, psci::SUCCESS);
            ControlFlow::Continue(())
        }
        _ => {
            let _ = vcpu.set_reg(Reg::X0, psci::NOT_SUPPORTED);
            ControlFlow::Continue(())
        }
    }
}

/// Serves the MMIO access `da` describes at `ipa`.
///
/// Returns `ControlFlow::Break` with the run's outcome when the access ends the
/// run, and `ControlFlow::Continue` otherwise.
fn service_mmio(
    vcpu: &Vcpu,
    context: &VcpuContext,
    cpu_id: u32,
    ipa: u64,
    da: DataAbort,
) -> ControlFlow<Outcome> {
    let width = usize::from(da.width);
    let served = if da.is_write {
        // The register can hold more than the access writes.
        let bytes = read_gpr(vcpu, da.reg).to_le_bytes();
        context.guest.mmio_bus.write(ipa, &bytes[..width])
    } else {
        let mut bytes = [0u8; 8];
        context
            .guest
            .mmio_bus
            .read(ipa, &mut bytes[..width])
            .map(|()| {
                write_gpr(vcpu, da.reg, u64::from_le_bytes(bytes));
                None
            })
    };
    match served {
        Ok(None) => ControlFlow::Continue(()),
        Ok(Some(stop)) => ControlFlow::Break(Outcome::Stopped(stop)),
        Err(UnclaimedError) => ControlFlow::Break(Outcome::Failed(format!(
            "vcpu{cpu_id}: unhandled MMIO at {ipa:#x} (pc {:#x})",
            vcpu.get_reg(Reg::PC).unwrap_or(0)
        ))),
    }
}

/// Reads general-purpose register `idx` (31 = XZR, reads as 0).
fn read_gpr(vcpu: &Vcpu, idx: u8) -> u64 {
    gpr(idx).map_or(0, |r| vcpu.get_reg(r).unwrap_or(0))
}

/// Writes `value` to general-purpose register `idx` (31 = XZR, discarded).
fn write_gpr(vcpu: &Vcpu, idx: u8, value: u64) {
    if let Some(r) = gpr(idx) {
        let _ = vcpu.set_reg(r, value);
    }
}

/// Advances PC past a 4-byte instruction (restartable exceptions only).
fn advance_pc(vcpu: &Vcpu) {
    let pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
    let _ = vcpu.set_reg(Reg::PC, pc + 4);
}

/// Maps a data-abort source-register index (`SRT`) to an `applevisor` register.
fn gpr(idx: u8) -> Option<Reg> {
    Some(match idx {
        0 => Reg::X0,
        1 => Reg::X1,
        2 => Reg::X2,
        3 => Reg::X3,
        4 => Reg::X4,
        5 => Reg::X5,
        6 => Reg::X6,
        7 => Reg::X7,
        8 => Reg::X8,
        9 => Reg::X9,
        10 => Reg::X10,
        11 => Reg::X11,
        12 => Reg::X12,
        13 => Reg::X13,
        14 => Reg::X14,
        15 => Reg::X15,
        16 => Reg::X16,
        17 => Reg::X17,
        18 => Reg::X18,
        19 => Reg::X19,
        20 => Reg::X20,
        21 => Reg::X21,
        22 => Reg::X22,
        23 => Reg::X23,
        24 => Reg::X24,
        25 => Reg::X25,
        26 => Reg::X26,
        27 => Reg::X27,
        28 => Reg::X28,
        29 => Reg::X29,
        30 => Reg::X30,
        _ => return None,
    })
}

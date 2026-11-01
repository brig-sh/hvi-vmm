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

//! A vCPU thread of an arm64 guest on KVM, with its exit loop.

use std::ops::ControlFlow;
use std::sync::Arc;

use kvm_ioctls::{VcpuExit, VcpuFd};

use super::regs::{
    get_u64, REG_PC, REG_PSTATE, REG_SCTLR_EL1, REG_SP_EL0, REG_SP_EL1, REG_TCR_EL1, REG_TTBR0_EL1,
    REG_TTBR1_EL1,
};
use crate::hypervisor::guest::{Guest, SafepointVcpu};
use crate::hypervisor::kvm::{run_vcpu, unhandled_exit, Kicker};
use crate::hypervisor::vcpus::Outcome;
use crate::plugin::{Plugin, RegsView};

/// The state a vCPU thread needs beyond its own vCPU.
#[derive(Clone)]
pub(super) struct VcpuContext {
    /// The guest's RAM, virtio devices and vCPUs.
    pub(super) guest: Arc<Guest<Kicker>>,
    /// The plugin, if the caller supplied one.
    pub(super) plugin: Option<Arc<dyn Plugin>>,
}

/// Runs one vCPU until the VM stops, servicing its MMIO exits.
pub(super) fn run_cpu(cpu_id: u32, vcpu: VcpuFd, kick_handle: VcpuFd, context: VcpuContext) {
    run_vcpu(
        cpu_id,
        vcpu,
        kick_handle,
        &context.guest,
        context.plugin.as_deref(),
        |exit| {
            match exit {
                VcpuExit::MmioRead(addr, data) => {
                    if context.guest.mmio_bus.read(addr, data).is_err() {
                        data.fill(0);
                    }
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if let Ok(Some(stop)) = context.guest.mmio_bus.write(addr, data) {
                        return ControlFlow::Break(Outcome::Stopped(stop));
                    }
                }
                // Kicked for a snapshot or a stop; the loop checks which.
                VcpuExit::Intr => {}
                other => return unhandled_exit(cpu_id, &other),
            }
            ControlFlow::Continue(())
        },
    );
}

impl SafepointVcpu for VcpuFd {
    fn regs(&self) -> RegsView {
        let ttbr1 = get_u64(self, REG_TTBR1_EL1);
        RegsView {
            // arm64's kernel-half page-table base is the walk root.
            root: ttbr1,
            pc: get_u64(self, REG_PC),
            cpsr: get_u64(self, REG_PSTATE),
            ttbr0: get_u64(self, REG_TTBR0_EL1),
            ttbr1,
            sctlr: get_u64(self, REG_SCTLR_EL1),
            sp_el1: get_u64(self, REG_SP_EL1),
            tcr: get_u64(self, REG_TCR_EL1),
            current_task: get_u64(self, REG_SP_EL0),
        }
    }
}

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

//! The arm64 vCPU registers the KVM backend reads and writes, by their
//! `KVM_GET_ONE_REG` id.

use kvm_ioctls::VcpuFd;

// Core regs: KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE |
// (byte_off/4).
const REG_X0: u64 = 0x6030_0000_0010_0000;
pub(super) const REG_PC: u64 = 0x6030_0000_0010_0040;
pub(super) const REG_PSTATE: u64 = 0x6030_0000_0010_0042;
pub(super) const REG_SP_EL1: u64 = 0x6030_0000_0010_0044;
// System regs: KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG | enc.
pub(super) const REG_MPIDR_EL1: u64 = 0x6030_0000_0013_c005;
pub(super) const REG_SCTLR_EL1: u64 = 0x6030_0000_0013_c080;
pub(super) const REG_TTBR0_EL1: u64 = 0x6030_0000_0013_c100;
pub(super) const REG_TTBR1_EL1: u64 = 0x6030_0000_0013_c101;
pub(super) const REG_TCR_EL1: u64 = 0x6030_0000_0013_c102;
// SP_EL0 is a core register (user_pt_regs.sp), not a sysreg: Linux keeps
// `current` there while running in the kernel.
pub(super) const REG_SP_EL0: u64 = 0x6030_0000_0010_003e;

/// The `PSTATE` of the arm64 Linux boot protocol, EL1h with DAIF masked.
const PSTATE_EL1H_DAIF: u64 = 0x3c5;

/// Writes `val` to register `id`, ignoring a refused write.
fn set_u64(vcpu: &VcpuFd, id: u64, val: u64) {
    let _ = vcpu.set_one_reg(id, &val.to_le_bytes());
}

/// Returns the value of register `id`.
pub(super) fn try_get_u64(vcpu: &VcpuFd, id: u64) -> Result<u64, kvm_ioctls::Error> {
    let mut b = [0u8; 8];
    vcpu.get_one_reg(id, &mut b).map(|_| u64::from_le_bytes(b))
}

/// Returns the value of register `id`, or 0 if KVM refuses the read.
pub(super) fn get_u64(vcpu: &VcpuFd, id: u64) -> u64 {
    try_get_u64(vcpu, id).unwrap_or(0)
}

/// Sets the boot vCPU to enter the kernel at `entry` with the devicetree at
/// `dtb` in `X0`.
pub(super) fn setup_boot_regs(vcpu: &VcpuFd, entry: u64, dtb: u64) {
    set_u64(vcpu, REG_PC, entry);
    set_u64(vcpu, REG_X0, dtb);
    set_u64(vcpu, REG_PSTATE, PSTATE_EL1H_DAIF);
}

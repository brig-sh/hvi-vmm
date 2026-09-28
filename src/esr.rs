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

//! AArch64 exception-syndrome (`ESR_EL2`) decoding for the VM-exit loop.
//!
//! Every guest exit that Apple's Hypervisor.framework reports as
//! `ExitReason::EXCEPTION` carries a syndrome whose top six bits (31:26) are
//! the exception class (EC). The whole VMM control flow keys off the EC: MMIO
//! (virtio) is a data abort, PSCI is an HVC/SMC, and sysreg accesses that trap
//! land here too. Keeping the decode in one place
//! means M1..M4 all share one classification.

/// Exception classes we act on. Values are the architectural EC encodings
/// (`ESR_ELx[31:26]`); anything else is surfaced as [`Ec::Other`] with the raw
/// EC so an unexpected exit is visible rather than silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ec {
    /// `SVC` from the guest (AArch64). Not normally taken to EL2.
    Svc,
    /// `HVC` from the guest — how PSCI (CPU_ON/OFF, SYSTEM_OFF) arrives.
    Hvc,
    /// `SMC` from the guest — the other PSCI conduit.
    Smc,
    /// Trapped `MSR`/`MRS`/system-instruction access.
    SysReg,
    /// Instruction abort from a lower EL (bad guest fetch).
    InstructionAbort,
    /// Data abort from a lower EL — the virtio-mmio doorbell path.
    DataAbort,
    /// `BRK` software breakpoint (used by the M0 smoke test).
    Brk,
    /// Anything else, carrying the raw EC for diagnosis.
    Other(u8),
}

impl Ec {
    /// Extracts the exception class from a raw `ESR_EL2` syndrome.
    #[must_use]
    pub fn from_syndrome(syndrome: u64) -> Self {
        let ec = ((syndrome >> 26) & 0x3f) as u8;
        match ec {
            0x15 => Ec::Svc,
            0x16 => Ec::Hvc,
            0x17 => Ec::Smc,
            0x18 => Ec::SysReg,
            0x20 | 0x21 => Ec::InstructionAbort,
            0x24 | 0x25 => Ec::DataAbort,
            0x3c => Ec::Brk,
            other => Ec::Other(other),
        }
    }
}

/// Decoded data-abort details needed to service a virtio-mmio access: the
/// faulting IPA offset, access width in bytes, whether it was a write, and the
/// source register index. Only valid when the syndrome is a data abort with a
/// valid instruction-syndrome (`ISV`) — the common case for aligned MMIO.
#[derive(Debug, Clone, Copy)]
pub struct DataAbort {
    /// Access size in bytes (1, 2, 4, or 8).
    pub width: u8,
    /// True if the guest was writing.
    pub is_write: bool,
    /// The `Xt` register index carrying (write) or receiving (read) the value.
    pub reg: u8,
    /// True if the instruction syndrome is valid (fields above are meaningful).
    pub isv: bool,
}

impl DataAbort {
    /// Decodes the data-abort-specific ISS fields from a data-abort syndrome.
    #[must_use]
    pub fn from_syndrome(syndrome: u64) -> Self {
        let iss = syndrome & 0x01ff_ffff;
        let isv = (iss >> 24) & 1 == 1;
        let sas = (iss >> 22) & 0x3; // access size: 0=B,1=H,2=W,3=D
        let width = 1u8 << sas;
        let is_write = (iss >> 6) & 1 == 1;
        let reg = ((iss >> 16) & 0x1f) as u8; // SRT
        DataAbort {
            width,
            is_write,
            reg,
            isv,
        }
    }
}

/// A system register's architectural encoding, `(op0, op1, CRn, CRm, op2)`,
/// as a trapped `MSR`/`MRS` reports it.
pub type SysRegEncoding = (u8, u8, u8, u8, u8);

/// `CNTHCTL_EL2`, the EL2 control of EL1's access to the physical timer and
/// counter.
pub const CNTHCTL_EL2: SysRegEncoding = (3, 4, 14, 1, 0);

/// Decoded fields of a trapped `MSR`/`MRS` (EC 0x18): which register, which
/// general-purpose register, and which way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysRegAccess {
    pub reg: SysRegEncoding,
    /// The `Xt` register index; 31 is XZR.
    pub rt: u8,
    /// True for `MRS` (the guest reads the register into `Xt`).
    pub is_read: bool,
}

impl SysRegAccess {
    /// Decodes the ISS of a sysreg-trap syndrome.
    #[must_use]
    pub fn from_syndrome(syndrome: u64) -> Self {
        let iss = syndrome & 0x01ff_ffff;
        let field = |shift: u32, mask: u64| ((iss >> shift) & mask) as u8;
        SysRegAccess {
            reg: (
                field(20, 0x3),
                field(14, 0x7),
                field(10, 0xf),
                field(1, 0xf),
                field(17, 0x7),
            ),
            rt: field(5, 0x1f),
            is_read: iss & 1 == 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two accesses a guest kernel at EL2 trapped with on hardware: its
    /// own `msr cnthctl_el2, x0` at boot, and KVM's `mrs x2, cnthctl_el2` on
    /// a world switch. Getting the field order wrong here would send the
    /// register to RAZ/WI, which hangs that guest before its first line of
    /// output.
    #[test]
    fn sysreg_access_decodes_cnthctl_el2() {
        let write = SysRegAccess::from_syndrome(0x6231_3802);
        assert_eq!(
            write,
            SysRegAccess {
                reg: CNTHCTL_EL2,
                rt: 0,
                is_read: false,
            }
        );
        let read = SysRegAccess::from_syndrome(0x6231_3843);
        assert_eq!(read.reg, CNTHCTL_EL2);
        assert_eq!(read.rt, 2);
        assert!(read.is_read);
    }

    /// `mrs x0, cntp_ctl_el0` from EL1, the access that trapped when
    /// `CNTHCTL_EL2` was lost. It must not be taken for `CNTHCTL_EL2`.
    #[test]
    fn sysreg_access_tells_cntp_ctl_from_cnthctl() {
        let access = SysRegAccess::from_syndrome(0x6232_f805);
        assert_eq!(Ec::from_syndrome(0x6232_f805), Ec::SysReg);
        assert_eq!(access.reg, (3, 3, 14, 2, 1));
        assert_ne!(access.reg, CNTHCTL_EL2);
        assert!(access.is_read);
    }

    #[test]
    fn hvc_class() {
        // EC=0x16 in bits 31:26.
        assert_eq!(Ec::from_syndrome(0x16 << 26), Ec::Hvc);
    }

    #[test]
    fn data_abort_write_word() {
        // EC=0x24, ISV=1, SAS=2 (word), WnR=1, SRT=3.
        let syn = (0x24u64 << 26) | (1 << 24) | (2 << 22) | (1 << 6) | (3 << 16);
        assert_eq!(Ec::from_syndrome(syn), Ec::DataAbort);
        let da = DataAbort::from_syndrome(syn);
        assert!(da.isv && da.is_write);
        assert_eq!(da.width, 4);
        assert_eq!(da.reg, 3);
    }
}

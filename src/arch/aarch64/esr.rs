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
//! land here too. Keeping the decode in one place means every exit handler
//! shares one classification.

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
    /// `BRK` software breakpoint (used by the smoke test).
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
    /// True if a cache maintenance or address translation instruction took the
    /// abort.
    pub cm: bool,
    /// True if the abort came from a stage-1 page table walk.
    pub s1ptw: bool,
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
        let cm = (iss >> 8) & 1 == 1;
        let s1ptw = (iss >> 7) & 1 == 1;
        DataAbort {
            width,
            is_write,
            reg,
            isv,
            cm,
            s1ptw,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_maintenance_abort_is_named_with_no_instruction_syndrome() {
        // `dc civac`: EC=0x24, CM and WnR set, ISV clear.
        let da = DataAbort::from_syndrome(0x24 << 26 | 1 << 8 | 1 << 6);
        assert!(da.cm);
        assert!(!da.isv);
        assert!(!da.s1ptw);
        assert!(!DataAbort::from_syndrome(0x24 << 26 | 1 << 24).cm);
    }

    // `dc civac` through a stage-1 table at an address outside guest RAM: the
    // walk took the abort, not the instruction's own access.
    #[test]
    fn table_walk_abort_is_named_apart_from_the_instruction() {
        let da = DataAbort::from_syndrome(0x24 << 26 | 1 << 8 | 1 << 7);
        assert!(da.cm);
        assert!(da.s1ptw);
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

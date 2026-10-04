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

//! The ACPI power-management registers of a PC, which an x86-64 guest writes to
//! power off or reset.
//!
//! The block holds the PM1 event registers (status, then enable), PM1 control
//! and the reset register, each at a fixed offset from the block's base port. A
//! guest powers off by writing a sleep type with `SLP_EN` to PM1 control, and
//! resets by writing [`RESET_VALUE`] to the reset register.
//!
//! hvi raises no ACPI event, so PM1 status reads zero. PM1 enable keeps what
//! the guest writes, because the guest reads an enable bit back to check that
//! the hardware has it. PM1 control reads `SCI_EN`, which tells the guest the
//! machine is in ACPI mode.

use crate::config::Stop;

/// The offset of PM1 status, the first half of the PM1 event block.
pub const PM1_STATUS: u16 = 0;
/// The offset of PM1 enable, the second half of the PM1 event block.
pub const PM1_ENABLE: u16 = 2;
/// The offset of PM1 control.
pub const PM1_CONTROL: u16 = 4;
/// The offset of the reset register.
pub const RESET_REGISTER: u16 = 6;
/// The length of the PM1 event block, status and enable together.
pub const PM1_EVENT_LEN: u8 = 4;
/// The length of the PM1 control block.
pub const PM1_CONTROL_LEN: u8 = 2;
/// The number of ports the registers take.
pub const PM_REGISTERS_LEN: u16 = RESET_REGISTER + 1;

/// The sleep type of S5, which the DSDT's `\_S5` object gives the guest.
pub const SLP_TYP_S5: u8 = 5;
/// The value a guest writes to the reset register.
pub const RESET_VALUE: u8 = 1;

// PM1 control bits.
const SCI_EN: u16 = 1 << 0;
pub(crate) const SLP_TYP_SHIFT: u16 = 10;
const SLP_TYP_MASK: u16 = 0x7;
pub(crate) const SLP_EN: u16 = 1 << 13;

/// The PM1 event and control registers and the reset register.
#[derive(Debug, Default)]
pub struct PmRegisters {
    /// What the guest last wrote to PM1 enable.
    enable: u16,
}

impl PmRegisters {
    /// Fills `data` with what a read of `data.len()` bytes at `offset` returns.
    pub fn read(&self, offset: u16, data: &mut [u8]) {
        let bytes = self.to_bytes();
        let start = usize::from(offset);
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = bytes.get(start + i).copied().unwrap_or(0xff);
        }
    }

    /// Applies a write of `data` at `offset`.
    ///
    /// Returns the stop the write asks for, or `None` when it asks for none.
    /// The sleep type and `SLP_EN` are both in the high byte of PM1 control.
    /// The guest writes the sleep type alone first, and that write returns
    /// `None`.
    pub fn write(&mut self, offset: u16, data: &[u8]) -> Option<Stop> {
        let mut stop = None;
        for (at, &byte) in (offset..).zip(data) {
            match at {
                PM1_ENABLE => self.enable = (self.enable & 0xff00) | u16::from(byte),
                at if at == PM1_ENABLE + 1 => {
                    self.enable = (self.enable & 0x00ff) | (u16::from(byte) << 8);
                }
                at if at == PM1_CONTROL + 1 => {
                    let control = u16::from(byte) << 8;
                    let slp_typ = (control >> SLP_TYP_SHIFT) & SLP_TYP_MASK;
                    if control & SLP_EN != 0 && slp_typ == u16::from(SLP_TYP_S5) {
                        stop = Some(Stop::SystemOff);
                    }
                }
                RESET_REGISTER if byte == RESET_VALUE => stop = Some(Stop::SystemReset),
                _ => {}
            }
        }
        stop
    }

    /// Returns the registers as the guest reads them, one byte per port.
    fn to_bytes(&self) -> [u8; PM_REGISTERS_LEN as usize] {
        let mut bytes = [0u8; PM_REGISTERS_LEN as usize];
        let enable = usize::from(PM1_ENABLE);
        bytes[enable..enable + 2].copy_from_slice(&self.enable.to_le_bytes());
        let control = usize::from(PM1_CONTROL);
        bytes[control..control + 2].copy_from_slice(&SCI_EN.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns what PM1 control reads as one 16-bit access.
    fn control(pm: &PmRegisters) -> u16 {
        let mut word = [0u8; 2];
        pm.read(PM1_CONTROL, &mut word);
        u16::from_le_bytes(word)
    }

    // ACPICA's legacy sleep reads PM1 control, writes the sleep type into it,
    // then writes it again with `SLP_EN`.
    #[test]
    fn s5_with_slp_en_powers_off() {
        let mut pm = PmRegisters::default();
        let typ = control(&pm) | (u16::from(SLP_TYP_S5) << SLP_TYP_SHIFT);
        assert!(pm.write(PM1_CONTROL, &typ.to_le_bytes()).is_none());
        let off = typ | SLP_EN;
        assert!(matches!(
            pm.write(PM1_CONTROL, &off.to_le_bytes()),
            Some(Stop::SystemOff)
        ));
        // The same write as two byte accesses.
        assert!(pm.write(PM1_CONTROL, &off.to_le_bytes()[..1]).is_none());
        assert!(matches!(
            pm.write(PM1_CONTROL + 1, &off.to_le_bytes()[1..]),
            Some(Stop::SystemOff)
        ));
    }

    // S1 is a sleep state hvi does not offer, so it does not end the run.
    #[test]
    fn other_sleep_type_does_not_stop() {
        let mut pm = PmRegisters::default();
        let s1 = SCI_EN | (1 << SLP_TYP_SHIFT) | SLP_EN;
        assert!(pm.write(PM1_CONTROL, &s1.to_le_bytes()).is_none());
    }

    #[test]
    fn reset_value_resets() {
        let mut pm = PmRegisters::default();
        assert!(pm.write(RESET_REGISTER, &[0]).is_none());
        assert!(matches!(
            pm.write(RESET_REGISTER, &[RESET_VALUE]),
            Some(Stop::SystemReset)
        ));
    }

    #[test]
    fn pm1_control_reads_acpi_mode() {
        assert_eq!(control(&PmRegisters::default()) & SCI_EN, SCI_EN);
    }

    // The guest reads an enable bit back after it sets it, and reports the
    // event as missing hardware when the bit reads clear.
    #[test]
    fn pm1_enable_reads_back() {
        let mut pm = PmRegisters::default();
        assert!(pm.write(PM1_ENABLE, &0x0520u16.to_le_bytes()).is_none());
        let mut word = [0u8; 2];
        pm.read(PM1_ENABLE, &mut word);
        assert_eq!(u16::from_le_bytes(word), 0x0520);
        let mut status = [0xffu8; 2];
        pm.read(PM1_STATUS, &mut status);
        assert_eq!(status, [0, 0]);
    }
}

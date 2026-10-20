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

//! The PL031 RTC for the arm64 backends, on the register file from
//! `vm-superio`.
//!
//! A Linux guest reads the data register at boot to set its system clock. The
//! register counts seconds since the epoch on the host's clock. The host's
//! clock is authoritative, as it is for the x86-64 CMOS RTC: a write to the
//! load or control register is ignored, so a guest's `hwclock -w` does not
//! move the RTC, and a driver rebind cannot reset it.
//!
//! The crate does not implement the match register, so the RTC has no alarm
//! and no interrupt. The registers are 32 bits wide, and Linux accesses them 4
//! bytes at a time. An access of any other width does not reach the crate.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use vm_superio::rtc_pl031::{NoEvents, RtcState};
use vm_superio::Rtc;

use crate::devices::state::{check_version, invalid};

/// Offset of the data register, which reads the current time in seconds.
const DR: u64 = 0x000;
/// Offset of the load register.
const LR: u64 = 0x008;
/// Offset of the control register.
const CR: u64 = 0x00c;

/// The [`Pl031State`] format this build writes and reads.
pub const PL031_STATE_VERSION: u32 = 1;

/// What a checkpoint keeps of the PL031: the registers a guest can set.
///
/// The clock is not kept. It reads the host's wall clock, and the load and
/// control registers that would move it ignore writes, so after a restore the
/// data register reads the restoring host's time, as the x86-64 CMOS RTC
/// does. The RTC raises no interrupt, so none is pending.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pl031State {
    /// [`PL031_STATE_VERSION`] when written by this build.
    pub version: u32,
    /// The match register (`RTCMR`), which the crate stores and never matches.
    pub mr: u32,
    /// The interrupt mask (`RTCIMSC`), one bit.
    pub imsc: u32,
    /// The raw interrupt status (`RTCRIS`), one bit.
    pub ris: u32,
}

impl Pl031State {
    /// Refuses a state this build could not restore.
    ///
    /// # Errors
    ///
    /// Errors when the state is of another version, or its interrupt mask or
    /// status has a bit other than bit 0, which the registers do not hold.
    pub fn check(&self) -> std::io::Result<()> {
        check_version("pl031", self.version, PL031_STATE_VERSION)?;
        if self.imsc > 1 || self.ris > 1 {
            return Err(invalid(format_args!(
                "pl031 interrupt mask {:#x} or status {:#x} holds more than bit 0",
                self.imsc, self.ris
            )));
        }
        Ok(())
    }
}

/// A PL031 RTC.
pub struct Pl031 {
    rtc: Rtc<NoEvents>,
}

impl Pl031 {
    /// Returns an RTC that reads the host's clock.
    #[must_use]
    pub fn new() -> Self {
        Pl031 { rtc: Rtc::new() }
    }

    /// Reads or writes the register at `offset` with an access of `width`
    /// bytes, and returns the value read, or 0 for a write.
    ///
    /// A write takes the low 32 bits of `value`. An access that is not 4 bytes
    /// wide, or an offset the crate does not serve, reads as 0, and a write
    /// there is ignored. A write to the load or control register is ignored
    /// too. The data register reads as 0 while the host's clock is before
    /// 1970, which the crate would otherwise panic on.
    pub fn mmio(&mut self, offset: u64, width: usize, is_write: bool, value: u64) -> u64 {
        let Ok(offset16) = u16::try_from(offset) else {
            return 0;
        };
        if width != 4 {
            return 0;
        }
        if is_write {
            if offset != LR && offset != CR {
                self.rtc.write(offset16, &(value as u32).to_le_bytes());
            }
            0
        } else {
            if offset == DR && SystemTime::now().duration_since(UNIX_EPOCH).is_err() {
                return 0;
            }
            let mut buf = [0u8; 4];
            self.rtc.read(offset16, &mut buf);
            u64::from(u32::from_le_bytes(buf))
        }
    }
}

impl Pl031 {
    /// Returns what a checkpoint keeps of the RTC.
    #[must_use]
    pub fn state(&self) -> Pl031State {
        let state = self.rtc.state();
        Pl031State {
            version: PL031_STATE_VERSION,
            mr: state.mr,
            imsc: state.imsc,
            ris: state.ris,
        }
    }

    /// Rebuilds the RTC a checkpoint describes, reading this host's clock.
    ///
    /// # Errors
    ///
    /// Errors when [`Pl031State::check`] refuses the state.
    pub fn restore(state: &Pl031State) -> std::io::Result<Self> {
        state.check()?;
        // No load and no offset, since a write never sets them: the data
        // register reads this host's clock.
        let registers = RtcState {
            lr: 0,
            offset: 0,
            mr: state.mr,
            imsc: state.imsc,
            ris: state.ris,
        };
        Ok(Pl031 {
            rtc: Rtc::from_state(&registers, NoEvents),
        })
    }
}

impl Default for Pl031 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the host's clock in seconds since the epoch.
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn data_register_reads_the_host_clock() {
        let mut rtc = Pl031::new();
        let host = now();
        let guest = rtc.mmio(DR, 4, false, 0);
        assert!(
            guest.abs_diff(host) <= 1,
            "guest {guest} is not within 1 s of host {host}"
        );
    }

    // Linux's rtc-pl031 sets the time through LR, and its probe writes CR
    // back with the enable bit, which the crate takes as a reset.
    #[test]
    fn load_and_control_register_writes_keep_the_host_clock() {
        let mut rtc = Pl031::new();
        assert_eq!(rtc.mmio(LR, 4, true, now() + 100), 0);
        assert_eq!(rtc.mmio(LR, 4, false, 0), 0, "LR took the write");
        rtc.mmio(CR, 4, true, 1);
        let host = now();
        let guest = rtc.mmio(DR, 4, false, 0);
        assert!(
            guest.abs_diff(host) <= 1,
            "guest {guest} is not within 1 s of host {host}"
        );
    }

    // The amba bus reads these IDs to bind the `rtc-pl031` driver.
    #[test]
    fn identifies_as_a_primecell_pl031() {
        let mut rtc = Pl031::new();
        let ids = [0x31, 0x10, 0x04, 0x00, 0x0d, 0xf0, 0x05, 0xb1];
        for (i, id) in ids.into_iter().enumerate() {
            let offset = 0xfe0 + 4 * i as u64;
            assert_eq!(rtc.mmio(offset, 4, false, 0), id, "offset {offset:#x}");
        }
    }

    #[test]
    fn reserved_offsets_read_zero_and_ignore_writes() {
        let mut rtc = Pl031::new();
        assert_eq!(rtc.mmio(0x020, 4, false, 0), 0);

        rtc.mmio(DR, 4, true, 1);
        let host = now();
        let guest = rtc.mmio(DR, 4, false, 0);
        assert!(
            guest.abs_diff(host) <= 1,
            "a write to DR moved the clock to {guest}"
        );
    }

    // A byte store to the interrupt mask would otherwise load the whole
    // register from the source register.
    #[test]
    fn only_word_accesses_reach_the_registers() {
        let mut rtc = Pl031::new();
        const IMSC: u64 = 0x010;
        for width in [1, 2, 8] {
            assert_eq!(rtc.mmio(0xfe0, width, false, 0), 0, "a {width}-byte read");
            rtc.mmio(IMSC, width, true, 1);
        }
        assert_eq!(
            rtc.mmio(IMSC, 4, false, 0),
            0,
            "a narrow or wide write reached IMSC"
        );
        rtc.mmio(IMSC, 4, true, 1);
        assert_eq!(rtc.mmio(IMSC, 4, false, 0), 1);
        assert_eq!(rtc.mmio(0xfe0, 4, false, 0), 0x31);
    }

    #[test]
    fn state_round_trips_through_json_and_a_restored_rtc() {
        const MR: u64 = 0x004;
        const IMSC: u64 = 0x010;
        let mut rtc = Pl031::new();
        rtc.mmio(MR, 4, true, 0x1234_5678);
        rtc.mmio(IMSC, 4, true, 1);
        let state = rtc.state();
        assert_eq!((state.mr, state.imsc, state.ris), (0x1234_5678, 1, 0));
        let json = serde_json::to_string(&state).unwrap();
        let back: Pl031State = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
        let mut restored = Pl031::restore(&back).unwrap();
        assert_eq!(restored.state(), state);
        assert_eq!(restored.mmio(MR, 4, false, 0), 0x1234_5678);
        assert_eq!(restored.mmio(IMSC, 4, false, 0), 1);
        let host = now();
        let guest = restored.mmio(DR, 4, false, 0);
        assert!(
            guest.abs_diff(host) <= 1,
            "the restored RTC reads {guest}, not the host's {host}"
        );
    }

    #[test]
    fn state_the_rtc_could_not_hold_is_refused() {
        let good = Pl031::new().state();
        for bad in [
            Pl031State {
                imsc: 2,
                ..good.clone()
            },
            Pl031State {
                ris: 0x8000_0000,
                ..good.clone()
            },
            Pl031State {
                version: 2,
                ..good.clone()
            },
        ] {
            let err = Pl031::restore(&bad).err();
            assert_eq!(
                err.map(|e| e.kind()),
                Some(std::io::ErrorKind::InvalidData),
                "{bad:?}"
            );
        }
    }
}

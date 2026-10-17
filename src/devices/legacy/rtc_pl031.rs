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
//! register counts seconds since the epoch on the host's clock, plus the offset
//! the guest last set through the load register.
//!
//! The crate does not implement the match register, so the RTC has no alarm
//! and no interrupt. The registers are 32 bits wide, and Linux accesses them 4
//! bytes at a time. An access of any other width does not reach the crate.

use vm_superio::rtc_pl031::NoEvents;
use vm_superio::Rtc;

/// Offset of the data register, which reads the current time in seconds.
pub const DR: u64 = 0x000;
/// Offset of the load register, which sets the time the data register counts
/// from.
pub const LR: u64 = 0x008;

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
    /// there is ignored.
    pub fn mmio(&mut self, offset: u64, width: usize, is_write: bool, value: u64) -> u64 {
        let Ok(offset) = u16::try_from(offset) else {
            return 0;
        };
        if width != 4 {
            return 0;
        }
        if is_write {
            self.rtc.write(offset, &(value as u32).to_le_bytes());
            0
        } else {
            let mut buf = [0u8; 4];
            self.rtc.read(offset, &mut buf);
            u64::from(u32::from_le_bytes(buf))
        }
    }
}

impl Default for Pl031 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn load_register_write_moves_the_clock() {
        let mut rtc = Pl031::new();
        let target = now() + 100;
        assert_eq!(rtc.mmio(LR, 4, true, target), 0);
        assert_eq!(rtc.mmio(LR, 4, false, 0), target);
        let guest = rtc.mmio(DR, 4, false, 0);
        assert!(
            guest.abs_diff(target) <= 1,
            "guest {guest} is not within 1 s of {target}"
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

        // An offset is narrowed to 16 bits, so a wide one must not wrap onto a
        // real register.
        let wide = u64::from(u16::MAX) + 1;
        assert_eq!(rtc.mmio(wide, 4, false, 0), 0);
        rtc.mmio(wide + LR, 4, true, 1);
        assert_eq!(rtc.mmio(LR, 4, false, 0), 0, "a wide write reached LR");
    }

    // A byte store to LR would otherwise load the whole register from the
    // source register.
    #[test]
    fn only_word_accesses_reach_the_registers() {
        let mut rtc = Pl031::new();
        for width in [1, 2, 8] {
            assert_eq!(rtc.mmio(0xfe0, width, false, 0), 0, "a {width}-byte read");
            rtc.mmio(LR, width, true, 1);
        }
        assert_eq!(
            rtc.mmio(LR, 4, false, 0),
            0,
            "a narrow or wide write reached LR"
        );
        assert_eq!(rtc.mmio(0xfe0, 4, false, 0), 0x31);
    }
}

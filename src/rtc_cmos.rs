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

//! The MC146818 CMOS RTC (ports `0x70`/`0x71`) -- the wall clock a PC-class
//! guest reads before it has any other time source.
//!
//! This is not an optional device. `timekeeping_init()` calls
//! `read_persistent_clock64()`, and on x86 with no paravirt clock advertised
//! that lands in `mach_get_cmos_time()`, which opens with
//!
//! ```text
//! spin_lock_irqsave(&rtc_lock, flags);
//! while ((CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP))
//!         cpu_relax();
//! ```
//!
//! an unbounded poll for update-in-progress to clear, with interrupts off. An
//! unimplemented port reads back `0xff`, so UIP (bit 7) is set on every pass
//! and the guest spins there forever: no console output, no forward progress,
//! one host core pegged. Linux 5.10 wedges exactly this way.
//!
//! We report the host wall clock and hold UIP clear. The time is latched, so a
//! guest reading seconds through year never sees a field tear across a second
//! boundary; the latch refreshes once it is older than `LATCH_MAX_AGE`.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Index register: selects the CMOS offset. Bit 7 is the NMI-disable line.
pub const RTC_INDEX_PORT: u16 = 0x70;
/// Data register: reads or writes the selected offset.
pub const RTC_DATA_PORT: u16 = 0x71;

// Register file offsets (MC146818).
const REG_SECONDS: u8 = 0x00;
const REG_MINUTES: u8 = 0x02;
const REG_HOURS: u8 = 0x04;
const REG_WEEKDAY: u8 = 0x06;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
const REG_A: u8 = 0x0a;
const REG_B: u8 = 0x0b;
const REG_C: u8 = 0x0c;
const REG_D: u8 = 0x0d;
/// Century, at the offset the ACPI FADT conventionally names.
const REG_CENTURY: u8 = 0x32;

/// Register A: 32.768 kHz base, 1024 Hz rate. UIP (0x80) stays clear.
const REG_A_VALUE: u8 = 0x26;
/// Register B: 24-hour mode, BCD (DM clear), no periodic interrupt.
const REG_B_VALUE: u8 = 0x02;
/// Register D: RAM and time valid.
const REG_D_VALUE: u8 = 0x80;

/// How stale the latched time may get before we re-read the host clock. Well
/// under a second, so the guest's wall clock is right, and far longer than the
/// microseconds a guest needs to read the register file.
const LATCH_MAX_AGE: Duration = Duration::from_millis(250);

/// Broken-down UTC, as the register file reports it.
#[derive(Clone, Copy)]
struct Wallclock {
    sec: u8,
    min: u8,
    hour: u8,
    weekday: u8,
    day: u8,
    month: u8,
    year: u8,
    century: u8,
}

/// An MC146818 RTC reporting the host wall clock.
pub struct RtcCmos {
    index: u8,
    /// CMOS RAM, for the offsets we do not synthesize.
    ram: [u8; 128],
    latched: Wallclock,
    latched_at: Instant,
}

impl RtcCmos {
    pub fn new() -> Self {
        Self {
            index: 0,
            ram: [0; 128],
            latched: now_utc(),
            latched_at: Instant::now(),
        }
    }

    /// Refreshes the latch if it has aged out. Called before serving any field
    /// of the clock, so one guest-side read of the file stays self-consistent.
    fn refresh(&mut self) {
        if self.latched_at.elapsed() >= LATCH_MAX_AGE {
            self.latched = now_utc();
            self.latched_at = Instant::now();
        }
    }

    /// Services an `in` from `port`.
    pub fn pio_read(&mut self, port: u16) -> u8 {
        if port == RTC_INDEX_PORT {
            // The index register is nominally write-only; real chips read back
            // the last index with the NMI bit masked.
            return self.index;
        }
        let idx = self.index;
        match idx {
            REG_A => REG_A_VALUE,
            REG_B => REG_B_VALUE,
            REG_C => 0, // no interrupt pending; a read clears the flags
            REG_D => REG_D_VALUE,
            REG_SECONDS | REG_MINUTES | REG_HOURS | REG_WEEKDAY | REG_DAY | REG_MONTH
            | REG_YEAR | REG_CENTURY => {
                self.refresh();
                let w = self.latched;
                let v = match idx {
                    REG_SECONDS => w.sec,
                    REG_MINUTES => w.min,
                    REG_HOURS => w.hour,
                    REG_WEEKDAY => return w.weekday, // 1-7, not BCD
                    REG_DAY => w.day,
                    REG_MONTH => w.month,
                    REG_YEAR => w.year,
                    _ => w.century,
                };
                to_bcd(v)
            }
            _ => self.ram[(idx & 0x7f) as usize],
        }
    }

    /// Services an `out` to `port`.
    pub fn pio_write(&mut self, port: u16, val: u8) {
        if port == RTC_INDEX_PORT {
            // Bit 7 gates NMI, which we do not deliver; the offset is bits 0-6.
            self.index = val & 0x7f;
            return;
        }
        match self.index {
            // The host clock is authoritative: accept a guest's attempt to set
            // the time and drop it, rather than letting the write land in RAM
            // and be read back as a stale reading.
            REG_SECONDS | REG_MINUTES | REG_HOURS | REG_WEEKDAY | REG_DAY | REG_MONTH
            | REG_YEAR | REG_CENTURY | REG_A | REG_B | REG_C | REG_D => {}
            idx => self.ram[(idx & 0x7f) as usize] = val,
        }
    }
}

impl Default for RtcCmos {
    fn default() -> Self {
        Self::new()
    }
}

fn to_bcd(v: u8) -> u8 {
    ((v / 10) << 4) | (v % 10)
}

/// Host wall clock, broken down as UTC.
fn now_utc() -> Wallclock {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    Wallclock {
        sec: (tod % 60) as u8,
        min: ((tod / 60) % 60) as u8,
        hour: (tod / 3600) as u8,
        // 1970-01-01 was a Thursday; the register counts 1 = Sunday.
        weekday: ((days + 4).rem_euclid(7) + 1) as u8,
        day: d as u8,
        month: m as u8,
        year: (y % 100) as u8,
        century: (y / 100) as u8,
    }
}

/// Days since the Unix epoch to a civil date (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uip_is_always_clear() {
        // The whole point: 5.10's mach_get_cmos_time() spins with interrupts
        // off until this bit reads back zero.
        let mut rtc = RtcCmos::new();
        rtc.pio_write(RTC_INDEX_PORT, REG_A);
        assert_eq!(rtc.pio_read(RTC_DATA_PORT) & 0x80, 0);
    }

    #[test]
    fn reports_bcd_24h() {
        let mut rtc = RtcCmos::new();
        rtc.pio_write(RTC_INDEX_PORT, REG_B);
        let b = rtc.pio_read(RTC_DATA_PORT);
        assert_eq!(b & 0x04, 0, "DM clear means BCD");
        assert_eq!(b & 0x02, 0x02, "24-hour mode");
    }

    #[test]
    fn fields_are_in_range() {
        let mut rtc = RtcCmos::new();
        for (idx, max) in [
            (REG_SECONDS, 59u8),
            (REG_MINUTES, 59),
            (REG_HOURS, 23),
            (REG_DAY, 31),
            (REG_MONTH, 12),
        ] {
            rtc.pio_write(RTC_INDEX_PORT, idx);
            let bcd = rtc.pio_read(RTC_DATA_PORT);
            let v = (bcd >> 4) * 10 + (bcd & 0x0f);
            assert!(v <= max, "reg {idx:#x} gave {v}, above {max}");
        }
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1)); // 2024-01-01
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn ram_holds_unsynthesized_offsets() {
        let mut rtc = RtcCmos::new();
        rtc.pio_write(RTC_INDEX_PORT, 0x0f); // shutdown status byte
        rtc.pio_write(RTC_DATA_PORT, 0x5a);
        rtc.pio_write(RTC_INDEX_PORT, 0x0f);
        assert_eq!(rtc.pio_read(RTC_DATA_PORT), 0x5a);
    }
}

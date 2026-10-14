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

//! Minimal PL011 UART with a receive path, enough for an interactive console.
//!
//! Each byte the guest writes to the data register goes to stdout through a
//! [`ConsoleFilter`]; the kernel driver polls the flag register, which always
//! reports the FIFO idle. Receive is interrupt-driven: a host thread pushes
//! keystrokes into the RX FIFO, which raises the UART's line; the guest reads
//! the data register on the resulting IRQ. Only the registers the Linux
//! `amba-pl011` driver touches for that flow are modeled: data, flags, and the
//! RX interrupt mask/status. The PrimeCell identification registers make the
//! driver bind (`ttyAMA0`); without them only `earlycon` runs.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::devices::irq::{Irq, IrqLine};
use crate::devices::state::{check_version, invalid};
use crate::terminal::ConsoleFilter;

/// Data register: reads pop the RX FIFO, writes are console bytes.
const DR: u64 = 0x000;
/// Flag register: TX/RX FIFO status.
const FR: u64 = 0x018;
/// Interrupt mask set/clear.
const IMSC: u64 = 0x038;
/// Raw interrupt status (before masking).
const RIS: u64 = 0x03c;
/// Masked interrupt status (`RIS & IMSC`).
const MIS: u64 = 0x040;
/// Interrupt clear (write-1-to-clear).
const ICR: u64 = 0x044;

/// FR: transmit FIFO empty (bit 7) — always set, we never buffer TX.
const FR_TXFE: u64 = 1 << 7;
/// FR: receive FIFO empty (bit 4).
const FR_RXFE: u64 = 1 << 4;

/// Receive interrupt bit, shared by IMSC/RIS/MIS (bit 4).
const INT_RX: u32 = 1 << 4;

/// Bound so a host that pastes a lot cannot grow the FIFO without limit.
const RX_CAP: usize = 4096;

/// The [`Pl011State`] format this build writes and reads.
pub const PL011_STATE_VERSION: u32 = 1;

/// What a checkpoint keeps of the PL011: the bytes the guest has not read and
/// the interrupt mask.
///
/// Transmit is synchronous, so no byte waits on the way out. The console
/// filter's place in an escape sequence the guest was writing is the host
/// terminal's, and a restore starts the filter afresh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pl011State {
    /// [`PL011_STATE_VERSION`] when written by this build.
    pub version: u32,
    /// Received bytes the guest has not read, oldest first.
    pub rx: Vec<u8>,
    /// The interrupt mask (`IMSC`).
    pub imsc: u32,
}

impl Pl011State {
    /// Refuses a state this build could not restore.
    ///
    /// # Errors
    ///
    /// Errors when the state is of another version or holds more bytes than
    /// the FIFO keeps.
    pub fn check(&self) -> std::io::Result<()> {
        check_version("pl011", self.version, PL011_STATE_VERSION)?;
        if self.rx.len() > RX_CAP {
            return Err(invalid(format_args!(
                "pl011 holds {} received bytes, the FIFO keeps {RX_CAP}",
                self.rx.len()
            )));
        }
        Ok(())
    }
}

/// A PL011 modelling console TX plus an interrupt-driven RX FIFO.
pub struct Pl011 {
    out: std::io::Stdout,
    /// The filter every transmitted byte passes through.
    filter: ConsoleFilter,
    /// What the filter passed of the last byte, reused across writes.
    passed: Vec<u8>,
    rx: VecDeque<u8>,
    /// Interrupt mask (`IMSC`); only the RX bit is acted on.
    imsc: u32,
    /// The interrupt line the UART drives.
    irq: Irq,
}

impl Pl011 {
    #[must_use]
    pub fn new() -> Self {
        Pl011 {
            out: std::io::stdout(),
            filter: ConsoleFilter::new(),
            passed: Vec::new(),
            rx: VecDeque::new(),
            imsc: 0,
            irq: Irq::default(),
        }
    }

    /// Connects the UART to the interrupt line it raises, and sets the line
    /// to the UART's level.
    ///
    /// A UART built at boot holds no byte, so the line stays low. A restored
    /// one may hold bytes the guest has not read with RX unmasked, and a line
    /// left low over them is input the guest never reads.
    // Only the arm64 backends attach a PL011.
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    pub(crate) fn connect_irq(&mut self, line: Arc<dyn IrqLine>) {
        self.irq.connect(line);
        self.irq.set(self.irq_level());
    }

    /// Sets the interrupt line to the device's level, whatever it was last
    /// set to, after a restore loaded the interrupt controller. See
    /// `Irq::redrive`.
    // Only the HVF restore calls it so far.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn redrive_irq(&mut self) {
        self.irq.redrive(self.irq_level());
    }

    /// Returns what a checkpoint keeps of the UART.
    #[must_use]
    pub fn state(&self) -> Pl011State {
        Pl011State {
            version: PL011_STATE_VERSION,
            rx: self.rx.iter().copied().collect(),
            imsc: self.imsc,
        }
    }

    /// Rebuilds the UART a checkpoint describes. The interrupt line is
    /// connected afterwards, as at boot, and connecting it asserts it when
    /// unread bytes wait with RX unmasked.
    ///
    /// # Errors
    ///
    /// Errors when the state is of another version or holds more bytes than
    /// the FIFO keeps.
    pub fn restore(state: &Pl011State) -> std::io::Result<Self> {
        state.check()?;
        Ok(Pl011 {
            rx: state.rx.iter().copied().collect(),
            imsc: state.imsc,
            ..Pl011::new()
        })
    }

    /// Queues a received byte (from the host). Drops it if the FIFO is full.
    pub fn push_rx(&mut self, byte: u8) {
        if self.rx.len() < RX_CAP {
            self.rx.push_back(byte);
        }
        self.irq.set(self.irq_level());
    }

    /// Returns whether the UART asserts its interrupt line: RX data is waiting
    /// and the RX interrupt is unmasked.
    ///
    /// The line is level-triggered, and the UART sets it to this level whenever
    /// an access or an RX push changes it.
    #[must_use]
    pub fn irq_level(&self) -> bool {
        !self.rx.is_empty() && (self.imsc & INT_RX != 0)
    }

    /// Services one MMIO access at register `offset`.
    pub fn mmio(&mut self, offset: u64, is_write: bool, value: u64) -> u64 {
        let read = self.serve_mmio(offset, is_write, value);
        self.irq.set(self.irq_level());
        read
    }

    /// Reads or writes register `offset`.
    fn serve_mmio(&mut self, offset: u64, is_write: bool, value: u64) -> u64 {
        if is_write {
            match offset {
                DR => {
                    self.passed.clear();
                    self.filter.filter(&[value as u8], &mut self.passed);
                    if !self.passed.is_empty() {
                        let mut lock = self.out.lock();
                        let _ = lock.write_all(&self.passed);
                        let _ = lock.flush();
                    }
                }
                IMSC => self.imsc = value as u32,
                // Level-based RX status clears when the FIFO drains, so the
                // write-1-to-clear register needs no state here.
                ICR => {}
                _ => {}
            }
            0
        } else {
            match offset {
                DR => u64::from(self.rx.pop_front().unwrap_or(0)),
                FR => FR_TXFE | if self.rx.is_empty() { FR_RXFE } else { 0 },
                IMSC => u64::from(self.imsc),
                RIS => u64::from(self.raw_int()),
                MIS => u64::from(self.raw_int() & self.imsc),
                _ => id_reg(offset).unwrap_or(0),
            }
        }
    }

    /// Raw interrupt status: RX bit set while the FIFO is non-empty.
    fn raw_int(&self) -> u32 {
        if self.rx.is_empty() {
            0
        } else {
            INT_RX
        }
    }
}

impl Default for Pl011 {
    fn default() -> Self {
        Self::new()
    }
}

/// PrimeCell/Periph identification registers, one byte per 4-byte slot at the
/// top of the page. The AMBA bus reads these to match a driver; without them
/// `amba_device_add` never binds `ttyAMA0`. PeriphID assembles to `0x00041011`
/// (the PL011 AMBA id) and CellID to the fixed `0xb105f00d`.
pub const ID_REGS: &[(u64, u8)] = &[
    (0xfe0, 0x11),
    (0xfe4, 0x10),
    (0xfe8, 0x04),
    (0xfec, 0x00),
    (0xff0, 0x0d),
    (0xff4, 0xf0),
    (0xff8, 0x05),
    (0xffc, 0xb1),
];

/// Returns the identification-register byte at `offset`, if any.
#[must_use]
pub fn id_reg(offset: u64) -> Option<u64> {
    ID_REGS
        .iter()
        .find(|&&(off, _)| off == offset)
        .map(|&(_, v)| u64::from(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::irq::test_line::LevelLine;

    #[test]
    fn state_round_trips_through_json_and_a_restored_uart() {
        let mut uart = Pl011::new();
        uart.mmio(IMSC, true, u64::from(INT_RX));
        for b in *b"hi" {
            uart.push_rx(b);
        }
        let state = uart.state();
        let json = serde_json::to_string(&state).unwrap();
        // The shape is the format other builds read, so it is pinned.
        assert_eq!(json, r#"{"version":1,"rx":[104,105],"imsc":16}"#);
        let back: Pl011State = serde_json::from_str(&json).unwrap();
        let mut restored = Pl011::restore(&back).unwrap();
        assert_eq!(restored.state(), state);
        assert_eq!(restored.mmio(DR, false, 0), u64::from(b'h'));
    }

    #[test]
    fn connecting_a_restored_uart_drives_its_line_from_its_fifo() {
        let pending = Pl011State {
            version: PL011_STATE_VERSION,
            rx: b"x".to_vec(),
            imsc: INT_RX,
        };
        let mut uart = Pl011::restore(&pending).unwrap();
        let line = Arc::new(LevelLine::default());
        uart.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
        assert!(line.is_high());
        assert_eq!(line.raises(), 1);

        // Bytes with RX masked, and an unmasked empty FIFO, both leave the
        // line low.
        for quiet in [
            Pl011State {
                imsc: 0,
                ..pending.clone()
            },
            Pl011State {
                rx: Vec::new(),
                ..pending.clone()
            },
        ] {
            let mut uart = Pl011::restore(&quiet).unwrap();
            let line = Arc::new(LevelLine::default());
            uart.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
            assert_eq!(line.sets(), 0);
        }
    }

    #[test]
    fn state_the_uart_could_not_hold_is_refused() {
        let full = Pl011State {
            version: PL011_STATE_VERSION,
            rx: vec![0; RX_CAP],
            imsc: 0,
        };
        assert!(Pl011::restore(&full).is_ok());
        for bad in [
            Pl011State {
                rx: vec![0; RX_CAP + 1],
                ..full.clone()
            },
            Pl011State {
                version: 2,
                ..full.clone()
            },
        ] {
            let err = Pl011::restore(&bad).err();
            assert_eq!(err.map(|e| e.kind()), Some(std::io::ErrorKind::InvalidData));
        }
    }
}

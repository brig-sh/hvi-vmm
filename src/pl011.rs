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
//! Transmit is trivial (writes to the data register stream to stdout; the
//! kernel driver polls the flag register, which always reports the FIFO idle).
//! Receive is interrupt-driven: a host thread pushes keystrokes into the RX
//! FIFO and raises the UART's GIC line; the guest reads the data register on
//! the resulting IRQ. Only the registers the Linux `amba-pl011` driver touches
//! for that flow are modelled — data, flags, and the RX interrupt
//! mask/status. The PrimeCell identification registers make the driver bind
//! (`ttyAMA0`); without them only `earlycon` runs.

use std::collections::VecDeque;
use std::io::Write;

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

/// A PL011 modelling console TX plus an interrupt-driven RX FIFO.
pub struct Pl011 {
    out: std::io::Stdout,
    rx: VecDeque<u8>,
    /// Interrupt mask (`IMSC`); only the RX bit is acted on.
    imsc: u32,
}

impl Pl011 {
    #[must_use]
    pub fn new() -> Self {
        Pl011 {
            out: std::io::stdout(),
            rx: VecDeque::new(),
            imsc: 0,
        }
    }

    /// Queues a received byte (from the host). Drops it if the FIFO is full.
    pub fn push_rx(&mut self, byte: u8) {
        if self.rx.len() < RX_CAP {
            self.rx.push_back(byte);
        }
    }

    /// Whether the UART is currently asserting its interrupt line: RX data is
    /// waiting and the RX interrupt is unmasked. Level-triggered — the caller
    /// drives the GIC SPI to this value after every access or RX push.
    #[must_use]
    pub fn irq_level(&self) -> bool {
        !self.rx.is_empty() && (self.imsc & INT_RX != 0)
    }

    /// Services one MMIO access at register `offset`.
    pub fn mmio(&mut self, offset: u64, is_write: bool, value: u64) -> u64 {
        if is_write {
            match offset {
                DR => {
                    let byte = [value as u8];
                    let mut lock = self.out.lock();
                    let _ = lock.write_all(&byte);
                    let _ = lock.flush();
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

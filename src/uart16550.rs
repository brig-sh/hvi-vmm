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

//! A minimal 16550 UART (COM1) behind x86 port I/O — the x86 analog of `pl011`.
//!
//! Enough of the 8250/16550 register file for the Linux `8250` driver on
//! `ttyS0`: TX drains straight to the host stdout, RX is fed from a queue (host
//! stdin), and the interrupt line follows THR-empty / data-ready per IER. The
//! machine services this on `KVM_EXIT_IO` for ports `0x3f8..0x3ff`.

use std::io::Write;

// Register offsets from the COM base (DLAB selects the divisor latch on 0/1).
const RBR_THR_DLL: u16 = 0; // RBR (read) / THR (write) / DLL (DLAB=1)
const IER_DLM: u16 = 1; // IER / DLM (DLAB=1)
const IIR_FCR: u16 = 2; // IIR (read) / FCR (write)
const LCR: u16 = 3;
const MCR: u16 = 4;
const LSR: u16 = 5;
const MSR: u16 = 6;
const SCR: u16 = 7;

// Line status bits.
const LSR_DR: u8 = 0x01; // data ready
const LSR_THRE: u8 = 0x20; // transmit holding register empty
const LSR_TEMT: u8 = 0x40; // transmitter empty

// Interrupt enable bits.
const IER_RDA: u8 = 0x01; // received-data-available
const IER_THRE: u8 = 0x02; // THR-empty

/// A 16550 UART with a host-stdout TX and a host-fed RX queue.
pub struct Uart16550 {
    ier: u8,
    lcr: u8,
    mcr: u8,
    scr: u8,
    dll: u8,
    dlm: u8,
    rx: std::collections::VecDeque<u8>,
    /// Pending interrupt (drives the machine's `set_irq_line`).
    irq: bool,
}

impl Uart16550 {
    #[must_use]
    pub fn new() -> Self {
        Uart16550 {
            ier: 0,
            lcr: 0,
            mcr: 0,
            scr: 0,
            dll: 0,
            dlm: 0,
            rx: std::collections::VecDeque::new(),
            irq: false,
        }
    }

    #[must_use]
    pub fn irq_level(&self) -> bool {
        self.irq
    }

    /// Queues a byte from the host (stdin) for the guest to read.
    pub fn push_rx(&mut self, b: u8) {
        self.rx.push_back(b);
        self.recompute_irq();
    }

    fn dlab(&self) -> bool {
        self.lcr & 0x80 != 0
    }

    /// THR is always empty (we drain synchronously); DR when the RX queue is
    /// non-empty. The line is asserted when an enabled source is active.
    fn recompute_irq(&mut self) {
        let rda = self.ier & IER_RDA != 0 && !self.rx.is_empty();
        let thre = self.ier & IER_THRE != 0; // THR is perpetually empty
        self.irq = rda || thre;
    }

    /// Services an `in` from `port` (COM base + offset), returning the byte.
    pub fn pio_read(&mut self, off: u16) -> u8 {
        let v = match off {
            RBR_THR_DLL if self.dlab() => self.dll,
            RBR_THR_DLL => self.rx.pop_front().unwrap_or(0),
            IER_DLM if self.dlab() => self.dlm,
            IER_DLM => self.ier,
            IIR_FCR => {
                // IIR: report the highest-priority pending interrupt, else
                // "none".
                if self.ier & IER_RDA != 0 && !self.rx.is_empty() {
                    0x04 // received data available
                } else if self.ier & IER_THRE != 0 {
                    0x02 // THR empty
                } else {
                    0x01 // no interrupt pending
                }
            }
            LCR => self.lcr,
            MCR => self.mcr,
            LSR => {
                let mut s = LSR_THRE | LSR_TEMT;
                if !self.rx.is_empty() {
                    s |= LSR_DR;
                }
                s
            }
            MSR => 0xb0, // DCD + DSR + CTS asserted
            SCR => self.scr,
            _ => 0,
        };
        self.recompute_irq();
        v
    }

    /// Services an `out` to `port` (COM base + offset).
    pub fn pio_write(&mut self, off: u16, val: u8) {
        match off {
            RBR_THR_DLL if self.dlab() => self.dll = val,
            RBR_THR_DLL => {
                // Transmit: straight to host stdout (raw; guest owns
                // formatting).
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(&[val]);
                let _ = out.flush();
            }
            IER_DLM if self.dlab() => self.dlm = val,
            IER_DLM => self.ier = val & 0x0f,
            IIR_FCR => {} // FIFO control: accept and ignore
            LCR => self.lcr = val,
            MCR => self.mcr = val,
            SCR => self.scr = val,
            _ => {}
        }
        self.recompute_irq();
    }
}

impl Default for Uart16550 {
    fn default() -> Self {
        Self::new()
    }
}

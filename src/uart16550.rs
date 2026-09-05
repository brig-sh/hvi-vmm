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

//! COM1 for the x86 backend: `vm-superio`'s 16550, wired to hvi's IRQ model.
//!
//! The register file is upstream's. What is ours is the wiring, and it needs
//! explaining, because the two sides model the interrupt differently.
//!
//! `vm-superio` is edge-triggered: it calls `Trigger::trigger` when an
//! interrupt becomes pending and never says when it goes away, which is what a
//! VMM wants when the line is an eventfd handed to `KVM_IRQFD`. hvi drives
//! COM1 as a **level** line instead -- `set_irq_line(COM1_GSI, level)` after
//! every access -- so it needs the assert *and* the deassert.
//!
//! So the trigger is a no-op and the level is read back from the interrupt
//! identification register, which is the register that answers exactly this
//! question. The one cost is that `state()` is the only accessor that reports
//! it without the reset-on-read side effect a guest would get, and `state()`
//! copies the receive buffer to do it. That is one small allocation per port
//! access, on a path that runs once per console byte; see the pull request for
//! the boot measurement that says it does not matter here.

use std::io::{self, Write};

use vm_superio::serial::NoEvents;
use vm_superio::{Serial, Trigger};

/// The two enable bits and the data-ready bit the level is computed from. The
/// crate keeps its register bits private, and these are the ones hvi needs to
/// answer "is a condition still true", which is a different question from the
/// IIR's "what should I service".
const IER_RECEIVED_DATA: u8 = 0x01;
const IER_THR_EMPTY: u8 = 0x02;
const LSR_DATA_READY: u8 = 0x01;

/// The edge callback hvi does not use. The line is level-driven and its state
/// is read from the IIR after each access, so there is nothing to do here.
struct NoTrigger;

impl Trigger for NoTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Guest transmit straight to the host's stdout, unbuffered.
///
/// Flushing per write is deliberate: the guest owns the formatting and the
/// console is what an operator watches a boot through, so a partial line has
/// to appear when the guest emits it rather than when a buffer happens to
/// fill.
struct ConsoleOut;

impl Write for ConsoleOut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut out = io::stdout().lock();
        out.write_all(buf)?;
        out.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

/// A 16550 UART with a host-stdout TX and a host-fed RX queue.
pub struct Uart16550 {
    inner: Serial<NoTrigger, NoEvents, ConsoleOut>,
}

impl Uart16550 {
    #[must_use]
    pub fn new() -> Self {
        Uart16550 {
            inner: Serial::new(NoTrigger, ConsoleOut),
        }
    }

    /// Whether COM1's interrupt line should be asserted right now.
    ///
    /// Computed from the conditions, not from the IIR. `vm-superio` clears the
    /// whole IIR when the guest reads it, which is right for a VMM whose line
    /// is an eventfd -- the next enqueue re-triggers the edge. hvi's line is a
    /// level, and a level has to stay asserted while the condition holds: a
    /// guest that reads IIR to find out why it was interrupted, and has not
    /// finished draining, must still see the line.
    ///
    /// So this asks the same two questions the hand-rolled device asked, in
    /// the same order: received-data if it is enabled and a byte is waiting,
    /// and THR-empty if it is enabled at all, because transmit drains
    /// synchronously and the holding register is therefore always empty.
    #[must_use]
    pub fn irq_level(&self) -> bool {
        let state = self.inner.state();
        let rda = state.interrupt_enable & IER_RECEIVED_DATA != 0
            && state.line_status & LSR_DATA_READY != 0;
        let thre = state.interrupt_enable & IER_THR_EMPTY != 0;
        rda || thre
    }

    /// Queues a byte from the host (stdin) for the guest to read.
    pub fn push_rx(&mut self, b: u8) {
        // Fails only when the receive buffer is full, which means the guest is
        // not draining the console. Dropping the byte is what a real UART does
        // with an overrun.
        let _ = self.inner.enqueue_raw_bytes(&[b]);
    }

    /// Services an `in` from `port` (COM base + offset), returning the byte.
    pub fn pio_read(&mut self, off: u16) -> u8 {
        self.inner.read(off as u8)
    }

    /// Services an `out` to `port` (COM base + offset).
    pub fn pio_write(&mut self, off: u16, val: u8) {
        // A write fails only if the console write failed; the guest has no way
        // to be told about a host stdout that has gone away, and it must not
        // stall waiting for one.
        let _ = self.inner.write(off as u8, val);
    }
}

impl Default for Uart16550 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // COM-base offsets, as the machine passes them in.
    const RBR_THR: u16 = 0;
    const IER: u16 = 1;
    const IIR: u16 = 2;
    const LSR: u16 = 5;

    const IER_RDA: u8 = 0x01;
    const LSR_DR: u8 = 0x01;

    /// The level derivation is ours, not the crate's, so it gets a test: a
    /// queued byte with receive interrupts enabled asserts COM1, and reading
    /// the byte back releases it.
    #[test]
    fn a_queued_byte_raises_the_line_and_reading_it_releases() {
        let mut u = Uart16550::new();
        assert!(!u.irq_level(), "idle line starts low");

        u.pio_write(IER, IER_RDA);
        assert!(!u.irq_level(), "enabling RDA alone does not assert it");

        u.push_rx(b'x');
        assert_eq!(u.pio_read(LSR) & LSR_DR, LSR_DR, "data-ready is set");
        assert!(u.irq_level(), "a queued byte asserts the line");

        assert_eq!(u.pio_read(RBR_THR), b'x', "the byte comes back");
        assert!(!u.irq_level(), "the line drops once the queue is drained");
    }

    /// The guest's real sequence: an interrupt fires, the guest reads IIR to
    /// find out why, then drains. The line must stay asserted while bytes
    /// remain, because hvi drives COM1 as a level.
    ///
    /// Regression test. Deriving the level from the IIR passed every other
    /// test here and failed this one: `vm-superio` clears the whole IIR on
    /// read, so the line dropped with two bytes still queued and a guest
    /// would have stopped being told about console input.
    #[test]
    fn the_level_survives_an_iir_read_while_bytes_remain() {
        let mut u = Uart16550::new();
        u.pio_write(IER, IER_RDA);
        u.push_rx(b'a');
        u.push_rx(b'b');
        assert!(u.irq_level(), "two bytes pending, line asserted");
        let _ = u.pio_read(IIR);
        assert!(u.irq_level(), "still two bytes pending after the IIR read");
        assert_eq!(u.pio_read(RBR_THR), b'a');
        assert!(u.irq_level(), "one byte still pending");
        assert_eq!(u.pio_read(RBR_THR), b'b');
        assert!(!u.irq_level(), "drained, line released");
    }

    /// Bytes come back in the order they were queued, and an empty queue does
    /// not report data ready.
    #[test]
    fn rx_is_a_queue_and_an_empty_one_is_quiet() {
        let mut u = Uart16550::new();
        u.pio_write(IER, IER_RDA);
        for b in b"hvi" {
            u.push_rx(*b);
        }
        let got: Vec<u8> = (0..3).map(|_| u.pio_read(RBR_THR)).collect();
        assert_eq!(&got, b"hvi");
        assert_eq!(u.pio_read(LSR) & LSR_DR, 0, "nothing left to read");
        assert!(!u.irq_level());
    }

    /// The FIFO bits in IIR are what the Linux 8250 driver's autoconfig uses
    /// to tell a 16550A from a 16450. The hand-rolled device this replaced
    /// never set them, so guests probed the port as a FIFO-less 16450.
    #[test]
    fn iir_advertises_the_fifo() {
        let mut u = Uart16550::new();
        assert_eq!(
            u.pio_read(IIR) & 0b1100_0000,
            0b1100_0000,
            "IIR must report FIFOs enabled"
        );
    }
}

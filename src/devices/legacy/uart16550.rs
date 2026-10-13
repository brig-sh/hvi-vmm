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

//! COM1 for the x86 backend, on the 16550 register file from `vm-superio`.
//!
//! The UART sets COM1's line whenever its level changes. The guest programs the
//! pin (ISA IRQ 4) as edge-triggered, so it sees an interrupt only when the
//! line rises. Its 8250 driver reads the interrupt identification register
//! (IIR) until IIR reports nothing pending. So the line is high exactly when an
//! IIR read would report an interrupt. A line left high after IIR reads empty
//! never rises again, and the guest then waits for a THR-empty interrupt that
//! does not come.
//!
//! The crate's own IIR does not keep that rule, so this module answers IIR
//! reads itself. The crate clears every pending bit on an IIR read, and raises
//! THR-empty only on a THR write. A 16550 also raises THR-empty when the guest
//! enables it while the holding register is empty. An IIR read clears
//! THR-empty only when that read reports it.

use std::io::{self, Write};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vm_superio::serial::NoEvents;
use vm_superio::{Serial, SerialState, Trigger};

use crate::devices::irq::{Irq, IrqLine};
use crate::devices::state::{check_version, invalid};
use crate::terminal::ConsoleFilter;

/// The register bits the interrupt state is computed from. The crate keeps its
/// own register bits private.
/// The received bytes the 16550's FIFO keeps.
///
/// This is vm-superio's `FIFO_SIZE`, which the crate does not export, and
/// `Serial::from_state` refuses a state holding more.
const RX_FIFO: usize = 64;
const IER_RECEIVED_DATA: u8 = 0x01;
const IER_THR_EMPTY: u8 = 0x02;
const LSR_DATA_READY: u8 = 0x01;
const LCR_DLAB: u8 = 0x80;

/// The COM-base offsets this module reads or intercepts. With DLAB set,
/// offsets 0 and 1 are the divisor latch instead.
const THR: u16 = 0;
const IER: u16 = 1;
const IIR: u16 = 2;
const LCR: u16 = 3;

/// The IIR interrupt IDs a read can report, by priority, and the bits that
/// advertise the FIFOs. The Linux 8250 driver reads the FIFO bits to tell a
/// 16550A from a 16450.
const IIR_RECEIVED_DATA: u8 = 0x04;
const IIR_THR_EMPTY: u8 = 0x02;
const IIR_NONE: u8 = 0x01;
const IIR_FIFO_ENABLED: u8 = 0xc0;

/// The edge callback hvi does not use. The UART sets its line to
/// [`Uart16550::irq_level`] whenever that changes.
struct NoTrigger;

impl Trigger for NoTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Guest transmit to the host's stdout through a [`ConsoleFilter`], unbuffered.
///
/// Flushing per write is deliberate: the guest owns the formatting and the
/// console is what an operator watches a boot through, so a partial line has
/// to appear when the guest emits it rather than when a buffer happens to
/// fill.
struct ConsoleOut {
    filter: ConsoleFilter,
    /// What the filter passed of the last write, reused across writes.
    passed: Vec<u8>,
}

impl ConsoleOut {
    fn new() -> Self {
        ConsoleOut {
            filter: ConsoleFilter::new(),
            passed: Vec::new(),
        }
    }
}

impl Write for ConsoleOut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.passed.clear();
        self.filter.filter(buf, &mut self.passed);
        if !self.passed.is_empty() {
            let mut out = io::stdout().lock();
            out.write_all(&self.passed)?;
            out.flush()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

/// The [`UartState`] format this build writes and reads.
pub const UART_STATE_VERSION: u32 = 1;

/// What a checkpoint keeps of the 16550: the register file the crate holds,
/// its receive buffer, and the THR-empty interrupt this module tracks.
///
/// The crate's `SerialState` has no serde, so this mirrors it field for
/// field. Transmit drains synchronously, so no byte waits on the way out. The
/// console filter's place in an escape sequence is the host terminal's, and a
/// restore starts it afresh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UartState {
    /// [`UART_STATE_VERSION`] when written by this build.
    pub version: u32,
    /// The divisor latch, low byte.
    pub baud_divisor_low: u8,
    /// The divisor latch, high byte.
    pub baud_divisor_high: u8,
    /// IER.
    pub interrupt_enable: u8,
    /// The crate's IIR, which reads do not answer from but keep in step.
    pub interrupt_identification: u8,
    /// LCR.
    pub line_control: u8,
    /// LSR.
    pub line_status: u8,
    /// MCR.
    pub modem_control: u8,
    /// MSR.
    pub modem_status: u8,
    /// The scratch register.
    pub scratch: u8,
    /// Received bytes the guest has not read, oldest first.
    pub rx: Vec<u8>,
    /// Whether a THR-empty interrupt is pending.
    pub thr_empty_pending: bool,
}

impl UartState {
    /// Refuses a state this build could not restore.
    ///
    /// # Errors
    ///
    /// Errors when the state is of another version or holds more received
    /// bytes than the crate's FIFO keeps.
    pub fn check(&self) -> io::Result<()> {
        check_version("16550", self.version, UART_STATE_VERSION)?;
        if self.rx.len() > RX_FIFO {
            return Err(invalid(format_args!(
                "16550 holds {} received bytes, the FIFO keeps {RX_FIFO}",
                self.rx.len()
            )));
        }
        Ok(())
    }
}

/// A 16550 UART with a host-stdout TX and a host-fed RX queue.
pub struct Uart16550 {
    inner: Serial<NoTrigger, NoEvents, ConsoleOut>,
    /// Whether a THR-empty interrupt is pending. IER can still mask it.
    thr_empty_pending: bool,
    /// The interrupt line the UART drives.
    irq: Irq,
}

impl Uart16550 {
    #[must_use]
    pub fn new() -> Self {
        Uart16550 {
            inner: Serial::new(NoTrigger, ConsoleOut::new()),
            thr_empty_pending: false,
            irq: Irq::default(),
        }
    }

    /// Connects the UART to the interrupt line it raises, and sets the line
    /// to the UART's level.
    ///
    /// A UART built at boot has nothing pending, so the line stays low. A
    /// restored one may have an interrupt pending that an IIR read would
    /// report. The guest programs the pin edge-triggered, so a line left low
    /// over it never rises, and the guest waits for an interrupt that does not
    /// come.
    // Only the x86-64 backend attaches a 16550.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub(crate) fn connect_irq(&mut self, line: Arc<dyn IrqLine>) {
        self.irq.connect(line);
        self.irq.set(self.irq_level());
    }

    /// Returns what a checkpoint keeps of the UART.
    #[must_use]
    pub fn state(&self) -> UartState {
        let s = self.inner.state();
        UartState {
            version: UART_STATE_VERSION,
            baud_divisor_low: s.baud_divisor_low,
            baud_divisor_high: s.baud_divisor_high,
            interrupt_enable: s.interrupt_enable,
            interrupt_identification: s.interrupt_identification,
            line_control: s.line_control,
            line_status: s.line_status,
            modem_control: s.modem_control,
            modem_status: s.modem_status,
            scratch: s.scratch,
            rx: s.in_buffer,
            thr_empty_pending: self.thr_empty_pending,
        }
    }

    /// Rebuilds the UART a checkpoint describes. The interrupt line is
    /// connected afterwards, as at boot, and connecting it asserts it when an
    /// IIR read would report an interrupt.
    ///
    /// # Errors
    ///
    /// Errors when the state is of another version or holds more received
    /// bytes than the crate's FIFO keeps.
    pub fn restore(state: &UartState) -> io::Result<Self> {
        state.check()?;
        let serial = SerialState {
            baud_divisor_low: state.baud_divisor_low,
            baud_divisor_high: state.baud_divisor_high,
            interrupt_enable: state.interrupt_enable,
            interrupt_identification: state.interrupt_identification,
            line_control: state.line_control,
            line_status: state.line_status,
            modem_control: state.modem_control,
            modem_status: state.modem_status,
            scratch: state.scratch,
            in_buffer: state.rx.clone(),
        };
        let inner = Serial::from_state(&serial, NoTrigger, NoEvents, ConsoleOut::new())
            .map_err(|e| invalid(format_args!("16550: {e}")))?;
        Ok(Uart16550 {
            inner,
            thr_empty_pending: state.thr_empty_pending,
            irq: Irq::default(),
        })
    }

    /// Returns the interrupt ID an IIR read would report now, without the FIFO
    /// bits.
    ///
    /// Received data comes first, while it is enabled and a byte is waiting.
    /// THR-empty comes next, while it is enabled and pending. Transmit drains
    /// synchronously, so the holding register is always empty.
    ///
    /// It reads the registers through `Serial::state`, which copies the
    /// receive buffer. That allocates only while received bytes are waiting.
    fn interrupt_id(&self) -> u8 {
        let state = self.inner.state();
        if state.interrupt_enable & IER_RECEIVED_DATA != 0
            && state.line_status & LSR_DATA_READY != 0
        {
            IIR_RECEIVED_DATA
        } else if state.interrupt_enable & IER_THR_EMPTY != 0 && self.thr_empty_pending {
            IIR_THR_EMPTY
        } else {
            IIR_NONE
        }
    }

    /// Returns whether COM1's interrupt line should be asserted right now.
    ///
    /// The line is high exactly when an IIR read would report an interrupt. The
    /// [module documentation](self) says why.
    #[must_use]
    pub fn irq_level(&self) -> bool {
        self.interrupt_id() != IIR_NONE
    }

    /// Queues a byte from the host (stdin) for the guest to read.
    pub fn push_rx(&mut self, b: u8) {
        // Fails only when the receive buffer is full, which means the guest is
        // not draining the console. Dropping the byte is what a real UART does
        // with an overrun.
        let _ = self.inner.enqueue_raw_bytes(&[b]);
        self.irq.set(self.irq_level());
    }

    /// Services an `in` from register `off`, an offset from the COM base.
    pub fn pio_read(&mut self, off: u16) -> u8 {
        let read = self.read_port(off);
        self.irq.set(self.irq_level());
        read
    }

    /// Services an `out` of `val` to register `off`, an offset from the COM
    /// base.
    pub fn pio_write(&mut self, off: u16, val: u8) {
        self.write_port(off, val);
        self.irq.set(self.irq_level());
    }

    /// Reads the register at offset `off`.
    fn read_port(&mut self, off: u16) -> u8 {
        if off != IIR {
            return self.inner.read(off as u8);
        }
        // The crate's IIR is not used, but the read keeps it in step.
        let _ = self.inner.read(off as u8);
        let id = self.interrupt_id();
        if id == IIR_THR_EMPTY {
            self.thr_empty_pending = false;
        }
        id | IIR_FIFO_ENABLED
    }

    /// Writes `val` to the register at offset `off`.
    fn write_port(&mut self, off: u16, val: u8) {
        // The crate's LCR and IER reads have no side effects. IER reads the
        // divisor latch while DLAB is set, but it is not used then.
        let dlab = self.inner.read(LCR as u8) & LCR_DLAB != 0;
        let ier = self.inner.read(IER as u8);
        // A write fails only if the console write failed; the guest has no way
        // to be told about a host stdout that has gone away, and it must not
        // stall waiting for one.
        let _ = self.inner.write(off as u8, val);
        if dlab {
            return;
        }
        match off {
            THR => self.thr_empty_pending = true,
            IER => {
                let enabled = val & IER_THR_EMPTY != 0;
                if enabled != (ier & IER_THR_EMPTY != 0) {
                    self.thr_empty_pending = enabled;
                }
            }
            _ => {}
        }
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
    use crate::devices::irq::test_line::LevelLine;

    // COM-base offsets, as the hypervisor backend passes them in.
    const RBR_THR: u16 = 0;
    const IER: u16 = 1;
    const IIR: u16 = 2;
    const LCR: u16 = 3;
    const LSR: u16 = 5;

    const IER_RDA: u8 = 0x01;
    const IER_THRI: u8 = 0x02;
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

    // The x86 console stall: the guest enabled THR-empty and another vCPU read
    // IIR as empty, but the line stayed high. The writes that followed raised
    // no edge, and the guest waited for an interrupt that never came.
    #[test]
    fn the_line_is_low_whenever_iir_reads_empty() {
        let mut u = Uart16550::new();
        u.pio_write(IER, IER_THRI);
        assert!(u.irq_level(), "enabling THR-empty asserts it");
        assert_eq!(u.pio_read(IIR), 0xc2, "IIR reports THR-empty");
        assert!(!u.irq_level(), "the read cleared it");
        assert_eq!(u.pio_read(IIR), 0xc1, "nothing else is pending");

        for b in b"0123456789abcdef" {
            u.pio_write(RBR_THR, *b);
        }
        assert!(u.irq_level(), "the writes raise the line again");
        assert_eq!(u.pio_read(IIR), 0xc2);
        assert!(!u.irq_level());
    }

    // The 8250 console write saves IER, clears it, writes, and restores it.
    #[test]
    fn disabling_thr_empty_drops_it_and_enabling_raises_it_again() {
        let mut u = Uart16550::new();
        u.pio_write(IER, IER_THRI);
        u.pio_write(IER, 0);
        assert!(!u.irq_level());
        assert_eq!(u.pio_read(IIR), 0xc1);
        u.pio_write(IER, IER_THRI);
        assert!(u.irq_level());
    }

    #[test]
    fn an_iir_read_that_reports_received_data_keeps_thr_empty_pending() {
        let mut u = Uart16550::new();
        u.pio_write(IER, IER_RDA | IER_THRI);
        u.push_rx(b'x');
        assert_eq!(u.pio_read(IIR), 0xc4, "received data comes first");
        assert_eq!(u.pio_read(RBR_THR), b'x');
        assert!(u.irq_level(), "THR-empty is still pending");
        assert_eq!(u.pio_read(IIR), 0xc2);
        assert!(!u.irq_level());
    }

    /// Writes the baud divisor `d` the way the 8250 driver's `set_termios`
    /// does: DLAB on, the low byte, the high byte, DLAB off.
    fn set_divisor(u: &mut Uart16550, d: u16) {
        u.pio_write(LCR, 0x83);
        u.pio_write(RBR_THR, d as u8);
        u.pio_write(IER, (d >> 8) as u8);
        u.pio_write(LCR, 0x03);
    }

    // With DLAB set, offsets 0 and 1 are the divisor latch. Their writes must
    // neither raise THR-empty nor clear it, or a baud change with a transmit
    // in flight would drop the line.
    #[test]
    fn the_divisor_latch_leaves_the_interrupts_alone() {
        let mut u = Uart16550::new();
        u.pio_write(IER, IER_THRI);
        assert_eq!(u.pio_read(IIR), 0xc2);
        set_divisor(&mut u, 0x0201);
        assert!(!u.irq_level(), "the divisor writes raise nothing");

        u.pio_write(RBR_THR, b'x');
        set_divisor(&mut u, 0x0001);
        assert!(u.thr_empty_pending, "nor do they clear THR-empty");
        assert!(u.irq_level());
        assert_eq!(u.pio_read(IER), IER_THRI, "IER kept its value");
        assert_eq!(u.pio_read(IIR), 0xc2);
    }

    /// A restored UART answers the guest as the one it was taken from: the
    /// line settings, the unread byte and the pending THR-empty interrupt all
    /// carry over, and the JSON is the same both ways.
    #[test]
    fn state_round_trips_through_json_and_a_restored_uart() {
        let mut u = Uart16550::new();
        u.pio_write(LCR, 0x80);
        u.pio_write(RBR_THR, 0x0c); // divisor low, 9600 baud
        u.pio_write(LCR, 0x03);
        u.pio_write(IER, IER_RDA | IER_THRI);
        u.pio_write(7, 0x5a); // scratch
        u.push_rx(b'k');
        let state = u.state();
        assert!(state.thr_empty_pending);
        assert_eq!(state.rx, b"k");
        assert_eq!(state.baud_divisor_low, 0x0c);

        let json = serde_json::to_string(&state).unwrap();
        let back: UartState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
        let mut restored = Uart16550::restore(&back).unwrap();
        assert_eq!(restored.state(), state);
        assert_eq!(restored.pio_read(LSR) & LSR_DR, LSR_DR);
        assert_eq!(restored.pio_read(RBR_THR), b'k');
        assert_eq!(restored.pio_read(IIR) & 0x0f, IIR_THR_EMPTY);
    }

    #[test]
    fn connecting_a_restored_uart_drives_its_line_from_its_registers() {
        let mut u = Uart16550::new();
        u.pio_write(IER, IER_RDA);
        u.push_rx(b'k');
        let pending = u.state();
        let mut restored = Uart16550::restore(&pending).unwrap();
        let line = Arc::new(LevelLine::default());
        restored.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
        assert!(
            line.is_high(),
            "the unread byte with RDA enabled raises COM1"
        );
        assert_eq!(line.raises(), 1);

        let mut restored = Uart16550::restore(&Uart16550::new().state()).unwrap();
        let line = Arc::new(LevelLine::default());
        restored.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
        assert_eq!(line.sets(), 0);
    }

    #[test]
    fn state_the_uart_could_not_hold_is_refused() {
        let good = Uart16550::new().state();
        for bad in [
            UartState {
                rx: vec![0; 65],
                ..good.clone()
            },
            UartState {
                version: 0,
                ..good.clone()
            },
        ] {
            let err = Uart16550::restore(&bad).err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
        }
        let full = UartState {
            rx: vec![0; 64],
            ..good
        };
        assert!(Uart16550::restore(&full).is_ok(), "a full FIFO is fine");
    }

    /// `RX_FIFO` copies a constant the crate keeps private, so the copy is
    /// held to what `Serial::from_state` accepts.
    #[test]
    fn the_fifo_check_matches_the_crate() {
        let serial = |len: usize| SerialState {
            in_buffer: vec![0; len],
            ..Serial::new(NoTrigger, ConsoleOut::new()).state()
        };
        let from_state =
            |len: usize| Serial::from_state(&serial(len), NoTrigger, NoEvents, ConsoleOut::new());
        assert!(from_state(RX_FIFO).is_ok());
        assert!(from_state(RX_FIFO + 1).is_err());
        let state = |len: usize| UartState {
            rx: vec![0; len],
            ..Uart16550::new().state()
        };
        assert!(state(RX_FIFO).check().is_ok());
        assert!(state(RX_FIFO + 1).check().is_err());
    }
}

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

//! A vCPU thread of an x86-64 guest on KVM, with its exit loop and the bus of
//! its port I/O.

use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kvm_ioctls::{VcpuExit, VcpuFd};

use crate::arch::x86_64::layout::{ACPI_PM_PORT, COM1_PORT, I8042_COMMAND_PORT, RTC_PORT};
use crate::config::Stop;
use crate::devices::bus::{self, Bus};
use crate::devices::legacy::acpi_pm::{PmRegisters, PM_REGISTERS_LEN};
use crate::devices::legacy::i8042::I8042;
use crate::devices::legacy::rtc_cmos::{RtcCmos, RTC_REGISTERS_LEN};
use crate::devices::legacy::uart16550::{Uart16550, UART_REGISTERS_LEN};
use crate::hypervisor::guest::{Guest, SafepointVcpu};
use crate::hypervisor::kvm::{run_vcpu, unhandled_exit, Kicker};
use crate::hypervisor::vcpus::Outcome;
use crate::memory::GuestRam;
use crate::plugin::{Plugin, RegsView};
use crate::LOG_PREFIX;

/// The shortest pause the guest is notified of.
///
/// It stays below the soft-lockup and RCU stall thresholds a Linux guest can be
/// set to, and above the pause an observation takes. Each notice resets the
/// soft-lockup check of its vCPU and the guest-wide RCU stall and hung-task
/// checks, so leaving out shorter pauses keeps those checks armed through
/// frequent observations.
const MIN_NOTIFIED_PAUSE: Duration = Duration::from_secs(1);

/// The state a vCPU thread needs beyond its own vCPU.
#[derive(Clone)]
pub(super) struct VcpuContext {
    /// The guest's RAM, virtio devices and vCPUs.
    pub(super) guest: Arc<Guest<Kicker>>,
    /// The devices the vCPU reaches through port I/O.
    pub(super) port_bus: Arc<Bus>,
    /// The plugin, if the caller supplied one.
    pub(super) plugin: Option<Arc<dyn Plugin>>,
}

/// Runs one vCPU until the VM stops, servicing its port I/O and MMIO exits.
pub(super) fn run_cpu(cpu_id: u32, vcpu: VcpuFd, kick_handle: VcpuFd, context: VcpuContext) {
    let dbg = std::env::var_os("HVI_X86_TRACE").is_some();
    let mut n_exit = 0u64;
    run_vcpu(
        cpu_id,
        vcpu,
        kick_handle,
        &context.guest,
        context.plugin.as_deref(),
        |exit| {
            // The trace reads registers through the vCPU's second handle, since
            // the exit borrows the one the run uses.
            let dump = |tag: &str| {
                let kicker = context.guest.vcpus.kicker();
                kicker.with_vcpu(cpu_id, |vcpu| {
                    dump_regs(vcpu, &context.guest.ram, cpu_id, tag)
                });
            };
            match exit {
                VcpuExit::IoIn(port, data) => {
                    if dbg && n_exit < 80 {
                        stderrln!("[trace] vcpu{cpu_id} IoIn {port:#x}");
                        n_exit += 1;
                    }
                    // A port no device claims reads all ones, as an absent port
                    // does on a PC.
                    if context.port_bus.read(u64::from(port), data).is_err() {
                        data.fill(0xff);
                    }
                }
                VcpuExit::IoOut(port, data) => {
                    let stop = context
                        .port_bus
                        .write(u64::from(port), data)
                        .unwrap_or(None);
                    // A write that ends the run is traced past the first exits
                    // too.
                    if dbg && (n_exit < 80 || stop.is_some()) {
                        stderrln!(
                            "[trace] vcpu{cpu_id} IoOut {port:#x} = {:02x?}",
                            &data[..data.len().min(4)]
                        );
                        n_exit += 1;
                    }
                    if let Some(stop) = stop {
                        return ControlFlow::Break(Outcome::Stopped(stop));
                    }
                }
                VcpuExit::MmioRead(addr, data) => {
                    if dbg && n_exit < 80 {
                        stderrln!("[trace] vcpu{cpu_id} MmioRead {addr:#x}");
                        n_exit += 1;
                    }
                    if context.guest.mmio_bus.read(addr, data).is_err() {
                        data.fill(0);
                    }
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if dbg && n_exit < 80 {
                        stderrln!("[trace] vcpu{cpu_id} MmioWrite {addr:#x}");
                        n_exit += 1;
                    }
                    if let Ok(Some(stop)) = context.guest.mmio_bus.write(addr, data) {
                        return ControlFlow::Break(Outcome::Stopped(stop));
                    }
                }
                VcpuExit::Shutdown => {
                    if dbg {
                        dump("SHUTDOWN");
                    }
                    return ControlFlow::Break(Outcome::Stopped(Stop::SystemReset));
                }
                VcpuExit::Intr => {
                    if dbg && cpu_id == 0 {
                        dump("kick");
                    }
                }
                other => return unhandled_exit(cpu_id, &other),
            }
            ControlFlow::Continue(())
        },
    );
}

impl SafepointVcpu for VcpuFd {
    fn regs(&self) -> RegsView {
        // CR3 is the walk root on x86-64; the arm64 registers stay zero.
        RegsView {
            root: self.get_sregs().map(|s| s.cr3).unwrap_or(0),
            pc: self.get_regs().map(|r| r.rip).unwrap_or(0),
            ..RegsView::default()
        }
    }

    fn notify_guest_paused(&self, paused_for: Duration) {
        if paused_for < MIN_NOTIFIED_PAUSE {
            return;
        }
        // The notice is the mark `KVM_KVMCLOCK_CTRL` leaves in the vCPU's
        // kvm-clock page. KVM refuses it with `EINVAL` while the guest has no
        // kvm-clock set up, such as early in boot, and then nothing in the
        // guest would read it.
        if let Err(e) = self.kvmclock_ctrl() {
            if e.errno() != libc::EINVAL {
                stderrln!("{LOG_PREFIX} could not notify the guest of the pause: {e}");
            }
        }
    }
}

/// Prints the vCPU's control and state registers and the instruction bytes at
/// RIP, for `HVI_X86_TRACE`.
///
/// It reads RIP as a guest-physical address, which holds while the early kernel
/// is identity-mapped.
fn dump_regs(vcpu: &VcpuFd, mem: &GuestRam, cpu_id: u32, tag: &str) {
    if let (Ok(r), Ok(s)) = (vcpu.get_regs(), vcpu.get_sregs()) {
        let mut code = [0u8; 16];
        let _ = mem.read(r.rip, &mut code);
        stderrln!(
            "[trace] vcpu{cpu_id} {tag}: rip={:#x} rsp={:#x} rflags={:#x} cs.sel={:#x} cs.l={} cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x} code@rip={:02x?}",
            r.rip, r.rsp, r.rflags, s.cs.selector, s.cs.l, s.cr0, s.cr3, s.cr4, s.efer, code
        );
    }
}

/// Returns the bus of an x86-64 guest's port I/O, with `uart` as COM1.
///
/// # Errors
///
/// Errors if two ranges overlap.
pub(super) fn port_bus(uart: &Arc<Mutex<Uart16550>>) -> Result<Bus, String> {
    let mut ports = Bus::new();
    ports.insert(
        u64::from(COM1_PORT),
        u64::from(UART_REGISTERS_LEN),
        Arc::clone(uart) as Arc<dyn bus::Device>,
    )?;
    ports.insert(
        u64::from(RTC_PORT),
        u64::from(RTC_REGISTERS_LEN),
        Arc::new(Mutex::new(RtcCmos::new())),
    )?;
    ports.insert(u64::from(I8042_COMMAND_PORT), 1, Arc::new(I8042))?;
    ports.insert(
        u64::from(ACPI_PM_PORT),
        u64::from(PM_REGISTERS_LEN),
        Arc::new(Mutex::new(PmRegisters::default())),
    )?;
    Ok(ports)
}

#[cfg(test)]
mod pio_tests {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use super::*;
    use crate::devices::bus::UnclaimedError;
    use crate::devices::irq::IrqLine;
    use crate::devices::legacy::acpi_pm::{PM1_CONTROL, SLP_EN, SLP_TYP_S5, SLP_TYP_SHIFT};

    /// Returns the byte a read of `port` gets.
    fn read_byte(ports: &Bus, port: u16) -> u8 {
        let mut data = [0];
        ports.read(u64::from(port), &mut data).unwrap();
        data[0]
    }

    /// Returns the bus with a COM1 of its own.
    fn ports() -> Bus {
        port_bus(&Arc::new(Mutex::new(Uart16550::new()))).unwrap()
    }

    // A routing mistake that leaves 0x70 or 0x71 to the 0xff of an unclaimed
    // port would hang the guest's boot while the device's own tests still pass.
    #[test]
    fn rtc_ports_reach_the_device() {
        let ports = ports();

        // out 0x70, 0x0b; in 0x71, for status register B.
        const REG_B: u8 = 0x0b;
        ports.write(u64::from(RTC_PORT), &[REG_B]).unwrap();
        let via_ports = read_byte(&ports, RTC_PORT + 1);

        // Status B reports BCD and 24-hour mode.
        assert_eq!(via_ports & 0x04, 0, "DM clear means BCD");
        assert_eq!(via_ports & 0x02, 0x02, "24-hour mode");
    }

    // The guest programs COM1's pin as edge-triggered. This is its transmit
    // start, split across two vCPUs: one enables THR-empty, the interrupted one
    // reads IIR, and the THR writes that follow must raise a new edge.
    #[test]
    fn com1_rises_again_for_the_writes_after_an_iir_read() {
        let line = Arc::new(EdgeCounter::default());
        let mut com1 = Uart16550::new();
        com1.connect_irq(Arc::clone(&line) as Arc<dyn IrqLine>);
        let ports = port_bus(&Arc::new(Mutex::new(com1))).unwrap();
        const IER: u16 = COM1_PORT + 1;
        const IIR: u16 = COM1_PORT + 2;

        ports.write(u64::from(IER), &[0x02]).unwrap();
        assert_eq!(line.edges.load(Ordering::SeqCst), 1);
        assert_eq!(read_byte(&ports, IIR), 0xc2);
        assert!(
            !line.high.load(Ordering::SeqCst),
            "the IIR read drops the line"
        );
        for b in b"0123456789abcdef" {
            ports.write(u64::from(COM1_PORT), &[*b]).unwrap();
        }
        assert_eq!(
            line.edges.load(Ordering::SeqCst),
            2,
            "the THR writes raise a second edge"
        );
    }

    // KVM hands over an `outw` as one slice of bytes for one port.
    #[test]
    fn com1_takes_several_bytes_as_writes_to_one_port() {
        let ports = ports();
        const IER: u16 = COM1_PORT + 1;
        ports.write(u64::from(IER), &[0x01, 0x02]).unwrap();
        assert_eq!(read_byte(&ports, IER), 0x02);
    }

    #[test]
    fn i8042_reset_command_ends_the_run() {
        let ports = ports();
        assert!(matches!(
            ports.write(u64::from(I8042_COMMAND_PORT), &[0xfe]),
            Ok(Some(Stop::SystemReset))
        ));
        assert!(matches!(ports.write(0x60, &[0xfe]), Err(UnclaimedError)));
    }

    #[test]
    fn acpi_power_off_ends_the_run() {
        let ports = ports();
        let pm1_control = u64::from(ACPI_PM_PORT + PM1_CONTROL);
        let off = (u16::from(SLP_TYP_S5) << SLP_TYP_SHIFT) | SLP_EN;
        assert!(matches!(
            ports.write(pm1_control, &off.to_le_bytes()),
            Ok(Some(Stop::SystemOff))
        ));
    }

    #[test]
    fn acpi_range_covers_its_registers_only() {
        let ports = ports();
        let mut data = [0];
        let first = u64::from(ACPI_PM_PORT);
        let end = first + u64::from(PM_REGISTERS_LEN);
        assert_eq!(ports.read(first - 1, &mut data), Err(UnclaimedError));
        ports.read(first, &mut data).unwrap();
        ports.read(end - 1, &mut data).unwrap();
        assert_eq!(ports.read(end, &mut data), Err(UnclaimedError));
    }

    /// A line that holds its level and counts the times it rose.
    #[derive(Default)]
    struct EdgeCounter {
        /// The level the line was last set to.
        high: AtomicBool,
        /// The number of times the line rose.
        edges: AtomicU32,
    }

    impl IrqLine for EdgeCounter {
        fn set_level(&self, level: bool) -> std::io::Result<()> {
            if level && !self.high.swap(level, Ordering::SeqCst) {
                self.edges.fetch_add(1, Ordering::SeqCst);
            }
            self.high.store(level, Ordering::SeqCst);
            Ok(())
        }
    }
}

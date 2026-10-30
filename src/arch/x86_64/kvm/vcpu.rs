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

//! A vCPU thread of an x86-64 guest on KVM, with its exit loop and the port I/O
//! and MMIO dispatch to the devices.

use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kvm_ioctls::{VcpuExit, VcpuFd};

use crate::arch::x86_64::layout::{
    ACPI_PM_PORT, COM1_PORT, I8042_COMMAND_PORT, VIRTIO_NET_BASE, VIRTIO_SIZE, VIRTIO_VSOCK_BASE,
};
use crate::config::Stop;
use crate::devices::legacy::acpi_pm::{PmRegisters, PM_REGISTERS_LEN};
use crate::devices::legacy::rtc_cmos::{RtcCmos, RTC_DATA_PORT, RTC_INDEX_PORT};
use crate::devices::legacy::uart16550::Uart16550;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::fs::vhost_user::{export_at, serve_mmio, Export};
use crate::hypervisor::guest::{Guest, SafepointVcpu};
use crate::hypervisor::kvm::{run_vcpu, unhandled_exit, Kicker};
use crate::hypervisor::vcpus::Outcome;
use crate::memory::GuestRam;
use crate::plugin::{Plugin, RegsView};
use crate::LOG_PREFIX;

/// The i8042's CPU-reset command, on [`I8042_COMMAND_PORT`].
const I8042_RESET_CPU: u8 = 0xfe;
/// The i8042 status the guest reads.
///
/// The input buffer reads empty, so the kernel's reset path sends its command
/// at once. The other bits read set, as on a port with nothing behind it, so a
/// guest that probes for the controller finds none at its first flush.
const I8042_STATUS: u8 = !0x02;

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
    /// The COM1 16550 UART.
    pub(super) uart: Arc<Mutex<Uart16550>>,
    /// The CMOS RTC, without which a guest hangs in
    /// `read_persistent_clock64()`.
    pub(super) rtc: Arc<Mutex<RtcCmos>>,
    /// The ACPI PM1 and reset registers, which the guest writes to power off or
    /// reset.
    pub(super) pm: Arc<Mutex<PmRegisters>>,
    /// One entry per virtio-fs export, in the order the exports were given.
    pub(super) fs: Arc<Vec<Export>>,
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
                    // The PM1 registers are 16 bits wide, so the ACPI block
                    // takes the whole access. Every other port is a byte port.
                    if let Some(offset) = pm_offset(port) {
                        context.pm.lock().unwrap().read(offset, data);
                    } else {
                        for b in data.iter_mut() {
                            *b = pio_read(&context, port);
                        }
                    }
                }
                VcpuExit::IoOut(port, data) => {
                    let stop = if let Some(offset) = pm_offset(port) {
                        context.pm.lock().unwrap().write(offset, data)
                    } else {
                        for &b in data.iter() {
                            pio_write(&context, port, b);
                        }
                        pio_stop(port, data)
                    };
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
                    let val = mmio_read(&context, addr);
                    let n = data.len().min(8);
                    data[..n].copy_from_slice(&val.to_le_bytes()[..n]);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if dbg && n_exit < 80 {
                        stderrln!("[trace] vcpu{cpu_id} MmioWrite {addr:#x}");
                        n_exit += 1;
                    }
                    let mut b = [0u8; 8];
                    let n = data.len().min(8);
                    b[..n].copy_from_slice(&data[..n]);
                    mmio_write(&context, addr, u64::from_le_bytes(b));
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

/// Returns what a port-I/O read of `port` gets from the device behind it.
///
/// It takes the devices rather than a [`VcpuContext`], so a test can call it
/// without a vCPU.
fn pio_dispatch_read(uart: &Mutex<Uart16550>, rtc: &Mutex<RtcCmos>, port: u16) -> u8 {
    if (COM1_PORT..COM1_PORT + 8).contains(&port) {
        uart.lock().unwrap().pio_read(port - COM1_PORT)
    } else if port == RTC_INDEX_PORT || port == RTC_DATA_PORT {
        rtc.lock().unwrap().pio_read(port)
    } else if port == I8042_COMMAND_PORT {
        I8042_STATUS
    } else {
        0xff
    }
}

/// Routes a port-I/O write of `val` to the device behind `port`.
fn pio_dispatch_write(uart: &Mutex<Uart16550>, rtc: &Mutex<RtcCmos>, port: u16, val: u8) {
    if (COM1_PORT..COM1_PORT + 8).contains(&port) {
        uart.lock().unwrap().pio_write(port - COM1_PORT, val);
    } else if port == RTC_INDEX_PORT || port == RTC_DATA_PORT {
        rtc.lock().unwrap().pio_write(port, val);
    }
}

/// Returns [`Stop::SystemReset`] for the i8042's CPU-reset command written as
/// one byte, or `None` for any other byte-port write.
fn pio_stop(port: u16, data: &[u8]) -> Option<Stop> {
    (port == I8042_COMMAND_PORT && *data == [I8042_RESET_CPU]).then_some(Stop::SystemReset)
}

/// Returns the offset of `port` in the ACPI registers, or `None` when the port
/// is not one of them.
fn pm_offset(port: u16) -> Option<u16> {
    port.checked_sub(ACPI_PM_PORT)
        .filter(|&offset| offset < PM_REGISTERS_LEN)
}

/// Services an `in` from `port`.
fn pio_read(context: &VcpuContext, port: u16) -> u8 {
    pio_dispatch_read(&context.uart, &context.rtc, port)
}

/// Services an `out` of `val` to `port`.
fn pio_write(context: &VcpuContext, port: u16, val: u8) {
    pio_dispatch_write(&context.uart, &context.rtc, port, val);
}

/// Services an MMIO read of the virtio register at `addr`.
fn mmio_read(context: &VcpuContext, addr: u64) -> u64 {
    if let Some((dev, off)) = context.guest.disk_at(addr, VIRTIO_SIZE) {
        blk_read(context, dev, off)
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        net_read(context, addr - VIRTIO_NET_BASE)
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        vsock_read(context, addr - VIRTIO_VSOCK_BASE)
    } else if let Some(export) = export_at(&context.fs, addr, VIRTIO_SIZE) {
        serve_mmio(
            &export.dev,
            &context.guest.ram,
            addr - export.base,
            false,
            0,
        )
    } else {
        0
    }
}

/// Services an MMIO write of `val` to the virtio register at `addr`.
fn mmio_write(context: &VcpuContext, addr: u64, val: u64) {
    if let Some((dev, off)) = context.guest.disk_at(addr, VIRTIO_SIZE) {
        blk_write(context, dev, off, val);
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        net_write(context, addr - VIRTIO_NET_BASE, val);
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        vsock_write(context, addr - VIRTIO_VSOCK_BASE, val);
    } else if let Some(export) = export_at(&context.fs, addr, VIRTIO_SIZE) {
        serve_mmio(
            &export.dev,
            &context.guest.ram,
            addr - export.base,
            true,
            val,
        );
    }
}

/// Services a read of register `off` of the virtio-blk device `dev`.
fn blk_read(context: &VcpuContext, dev: &Mutex<VirtioBlk>, off: u64) -> u64 {
    context.guest.read_device(dev, off)
}

/// Services a write of `val` to register `off` of the virtio-blk device `dev`.
fn blk_write(context: &VcpuContext, dev: &Mutex<VirtioBlk>, off: u64, val: u64) {
    context.guest.write_device(dev, off, val);
}

/// Services a read of virtio-net register `off`.
fn net_read(context: &VcpuContext, off: u64) -> u64 {
    let Some(dev) = context.guest.net.as_ref() else {
        return 0;
    };
    context.guest.read_device(dev, off)
}

/// Services a write of `val` to virtio-net register `off`.
fn net_write(context: &VcpuContext, off: u64, val: u64) {
    let Some(dev) = context.guest.net.as_ref() else {
        return;
    };
    context.guest.write_device(dev, off, val);
}

/// Services a read of virtio-vsock register `off`.
fn vsock_read(context: &VcpuContext, off: u64) -> u64 {
    let Some(dev) = context.guest.vsock.as_ref() else {
        return 0;
    };
    context.guest.read_device(dev, off)
}

/// Services a write of `val` to virtio-vsock register `off`.
fn vsock_write(context: &VcpuContext, off: u64, val: u64) {
    let Some(dev) = context.guest.vsock.as_ref() else {
        return;
    };
    context.guest.write_device(dev, off, val);
}

#[cfg(test)]
mod pio_tests {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use super::*;
    use crate::devices::irq::IrqLine;

    // A routing mistake that sends 0x70 or 0x71 to the 0xff default would hang
    // the guest's boot while the device's own tests still pass.
    #[test]
    fn rtc_ports_reach_the_device() {
        let uart = Mutex::new(Uart16550::new());
        let rtc = Mutex::new(RtcCmos::new());

        // out 0x70, 0x0b; in 0x71, for status register B.
        const REG_B: u8 = 0x0b;
        pio_dispatch_write(&uart, &rtc, RTC_INDEX_PORT, REG_B);
        let via_ports = pio_dispatch_read(&uart, &rtc, RTC_DATA_PORT);

        // The same register read straight from a device instance must match.
        let mut direct = RtcCmos::new();
        direct.pio_write(RTC_INDEX_PORT, REG_B);
        assert_eq!(via_ports, direct.pio_read(RTC_DATA_PORT));
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
        let uart = Mutex::new(com1);
        let rtc = Mutex::new(RtcCmos::new());
        const IER: u16 = COM1_PORT + 1;
        const IIR: u16 = COM1_PORT + 2;

        pio_dispatch_write(&uart, &rtc, IER, 0x02);
        assert_eq!(line.edges.load(Ordering::SeqCst), 1);
        assert_eq!(pio_dispatch_read(&uart, &rtc, IIR), 0xc2);
        assert!(
            !line.high.load(Ordering::SeqCst),
            "the IIR read drops the line"
        );
        for b in b"0123456789abcdef" {
            pio_dispatch_write(&uart, &rtc, COM1_PORT, *b);
        }
        assert_eq!(
            line.edges.load(Ordering::SeqCst),
            2,
            "the THR writes raise a second edge"
        );
    }

    // The kernel's i8042 reset waits for the input buffer to empty before each
    // command. A full one costs the whole poll before every try.
    #[test]
    fn i8042_takes_its_reset_command_at_once() {
        let uart = Mutex::new(Uart16550::new());
        let rtc = Mutex::new(RtcCmos::new());
        let status = pio_dispatch_read(&uart, &rtc, I8042_COMMAND_PORT);
        assert_eq!(status & 0x02, 0, "input buffer empty");
        assert_eq!(status & 0x01, 0x01, "a probe's first flush still fails");
        assert!(matches!(
            pio_stop(I8042_COMMAND_PORT, &[I8042_RESET_CPU]),
            Some(Stop::SystemReset)
        ));
        assert!(pio_stop(I8042_COMMAND_PORT, &[0xaa]).is_none());
        assert!(pio_stop(0x60, &[I8042_RESET_CPU]).is_none());
        // A wider access is not the command, whatever its bytes.
        assert!(pio_stop(I8042_COMMAND_PORT, &[0x00, I8042_RESET_CPU]).is_none());
    }

    #[test]
    fn pm_offset_covers_the_acpi_registers_only() {
        assert_eq!(pm_offset(ACPI_PM_PORT), Some(0));
        assert_eq!(
            pm_offset(ACPI_PM_PORT + PM_REGISTERS_LEN - 1),
            Some(PM_REGISTERS_LEN - 1)
        );
        assert_eq!(pm_offset(ACPI_PM_PORT - 1), None);
        assert_eq!(pm_offset(ACPI_PM_PORT + PM_REGISTERS_LEN), None);
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

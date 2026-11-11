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

//! The IOAPIC of an x86-64 guest on KVM, and the interrupt lines and triggers
//! on its inputs.
//!
//! [`KernelIoApic`] is KVM's in-kernel IOAPIC, which `KVM_CREATE_IRQCHIP`
//! creates with a PIC and a PIT beside it. [`IoApic`] is an IOAPIC that hvi
//! serves itself over KVM's split irqchip, in which KVM runs only the local
//! APICs. Each input of an [`IoApic`] is the KVM GSI of the same number, whose
//! route is the MSI the input's redirection entry describes, and an irqfd on
//! that GSI delivers the input's interrupt. KVM delivers an irqfd on an MSI
//! route in the thread that writes it.
//!
//! An [`IoApic`] serves edge-triggered inputs, which every hvi device on x86
//! drives. It holds an edge that arrives while the guest has the input masked
//! and sends it when the guest unmasks the input. A level-triggered entry gets
//! its route too, but the IOAPIC keeps no remote IRR. A split irqchip has no
//! PIC and no PIT. [`NoPic`] answers the 8259's ports.
//!
//! The registers follow the 82093AA's layout and answer as KVM's in-kernel
//! IOAPIC does, so a guest reads the same values in either mode.

// The boot path that builds an `IoApic` is not wired in yet.
#![cfg_attr(not(test), expect(dead_code))]

use std::io;
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    kvm_irq_routing_entry, kvm_irq_routing_msi, KvmIrqRouting, KVM_IRQ_ROUTING_MSI,
};
use kvm_ioctls::VmFd;
use vmm_sys_util::eventfd::EventFd;

use crate::arch::x86_64::layout::{IOAPIC_ADDR, IOAPIC_INPUTS, PIC_PORTS};
use crate::config::Stop;
use crate::devices::bus::{self, Bus};
use crate::devices::irq;
use crate::hypervisor::kvm;
use crate::LOG_PREFIX;

/// The in-kernel IOAPIC of an x86-64 guest on KVM, whose lines and triggers are
/// its pins.
pub(super) struct KernelIoApic {
    /// The VM whose IOAPIC has the lines.
    pub(super) vm: Arc<VmFd>,
}

impl irq::Chip for KernelIoApic {
    fn line(&self, gsi: u32) -> Arc<dyn irq::Line> {
        Arc::new(kvm::IrqLine::new(Arc::clone(&self.vm), gsi))
    }

    fn trigger(&self, gsi: u32) -> io::Result<Arc<dyn irq::Trigger>> {
        Ok(Arc::new(Pulsed::new(kvm::IrqLine::new(
            Arc::clone(&self.vm),
            gsi,
        ))))
    }
}

/// The trigger of an edge-triggered IOAPIC pin, which raises the pin's line and
/// lowers it again.
///
/// The IOAPIC takes an edge only on a 0 to 1 transition. The line is locked
/// across the raise and the lower, so two calls cannot both raise it before
/// either lowers it, which the IOAPIC would take as one edge. The lock covers
/// the pin because the pin has one trigger, as each virtio device has a pin of
/// its own.
struct Pulsed<L> {
    /// The pin's line.
    line: Mutex<L>,
}

impl<L> Pulsed<L> {
    /// Returns the trigger that pulses `line`.
    fn new(line: L) -> Self {
        Self {
            line: Mutex::new(line),
        }
    }
}

// `Pulsed` keeps the default `register_irqfd`, which answers `Unsupported`. KVM
// delivers an irqfd on a pin of the in-kernel IOAPIC from a kernel worker
// thread, which is slower than a pulse from the thread that reads the eventfd.
impl<L: irq::Line> irq::Trigger for Pulsed<L> {
    fn trigger(&self) -> io::Result<()> {
        let line = self.line.lock().unwrap();
        line.set_level(true)?;
        line.set_level(false)
    }
}

/// The number of inputs of an [`IoApic`].
const INPUTS: usize = IOAPIC_INPUTS as usize;

/// The offset of the register select register, IOREGSEL.
const SELECT: u64 = 0x00;
/// The offset of the register window, IOWIN.
const WINDOW: u64 = 0x10;
/// The length of an [`IoApic`]'s range, the one KVM's in-kernel IOAPIC claims.
const REGISTERS_LEN: u64 = 0x100;

/// The index of the IOAPIC id register.
const ID: u8 = 0x00;
/// The index of the version register.
const VERSION: u8 = 0x01;
/// The index of the arbitration register.
const ARBITRATION: u8 = 0x02;
/// The index of the first redirection table register, entry 0's low half.
const REDIRECTION_TABLE: u8 = 0x10;
/// The version the version register reports, an 82093AA's.
const VERSION_ID: u32 = 0x11;

/// A function that replaces a VM's GSI routes with MSI routes, each with its
/// GSI.
type RouteSetter = Box<dyn Fn(&[(u32, Msi)]) -> io::Result<()> + Send + Sync>;

/// The calls an [`IoApic`] makes on the GSI routing of its VM.
struct Routing {
    /// The function that registers an irqfd.
    register_irqfd: kvm::IrqfdRegistrar,
    /// The function that sets the routes.
    set_routes: RouteSetter,
}

impl From<Arc<VmFd>> for Routing {
    fn from(vm: Arc<VmFd>) -> Self {
        let registrar = Arc::clone(&vm);
        Self {
            register_irqfd: Box::new(move |fd, gsi| Ok(registrar.register_irqfd(fd, gsi)?)),
            set_routes: Box::new(move |routes| {
                let entries: Vec<kvm_irq_routing_entry> = routes
                    .iter()
                    .map(|&(gsi, msi)| {
                        let mut entry = kvm_irq_routing_entry {
                            gsi,
                            type_: KVM_IRQ_ROUTING_MSI,
                            ..Default::default()
                        };
                        entry.u.msi = kvm_irq_routing_msi {
                            address_lo: msi.address,
                            data: msi.data,
                            ..Default::default()
                        };
                        entry
                    })
                    .collect();
                let table = KvmIrqRouting::from_entries(&entries)
                    .expect("one route per IOAPIC input should fit the routing table");
                Ok(vm.set_gsi_routing(&table)?)
            }),
        }
    }
}

/// An MSI message, as a KVM MSI route carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Msi {
    /// The low 32 bits of the address.
    address: u32,
    /// The data.
    data: u32,
}

impl Msi {
    /// The fixed part of an MSI's address, `0xfee` in bits 31 to 20.
    const ADDRESS: u32 = 0xfee0_0000;
    /// The shift of the destination field in the address.
    const DESTINATION_SHIFT: u32 = 12;
    /// The redirection hint bit of the address.
    const REDIRECTION_HINT: u32 = 1 << 3;
    /// The destination mode bit of the address, set for logical.
    const LOGICAL: u32 = 1 << 2;
    /// The shift of the delivery mode field in the data.
    const DELIVERY_MODE_SHIFT: u32 = 8;
    /// The level bit of the data, set to assert a level-triggered interrupt.
    const ASSERT: u32 = 1 << 14;
    /// The trigger mode bit of the data, set for level.
    const LEVEL: u32 = 1 << 15;
}

/// A redirection entry of an IOAPIC, in the 82093AA's 64-bit layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry(u64);

impl Entry {
    /// The vector field.
    const VECTOR: u64 = 0xff;
    /// The shift of the delivery mode field.
    const DELIVERY_MODE_SHIFT: u32 = 8;
    /// The delivery mode field, shifted down.
    const DELIVERY_MODE: u64 = 0b111;
    /// The fixed delivery mode.
    const FIXED: u64 = 0b000;
    /// The lowest priority delivery mode.
    const LOWEST_PRIORITY: u64 = 0b001;
    /// The destination mode bit, set for logical.
    const LOGICAL: u64 = 1 << 11;
    /// The delivery status bit, which the guest cannot write.
    const DELIVERY_STATUS: u64 = 1 << 12;
    /// The remote IRR bit, which the guest cannot write.
    const REMOTE_IRR: u64 = 1 << 14;
    /// The trigger mode bit, set for level.
    const LEVEL: u64 = 1 << 15;
    /// The mask bit.
    const MASK: u64 = 1 << 16;
    /// The shift of the destination field.
    const DESTINATION_SHIFT: u32 = 56;
    /// The lowest vector an entry is routed with.
    ///
    /// A local APIC takes a vector below 16 as illegal.
    const FIRST_VECTOR: u64 = 0x10;

    /// The entry at reset, masked with every other field 0.
    const RESET: Self = Self(Self::MASK);

    /// Returns whether the entry masks its input.
    fn is_masked(self) -> bool {
        self.0 & Self::MASK != 0
    }

    /// Returns the low half of the entry, or the high half if `high`.
    fn half(self, high: bool) -> u32 {
        if high {
            (self.0 >> 32) as u32
        } else {
            self.0 as u32
        }
    }

    /// Returns the entry with its low half, or its high half if `high`, set to
    /// `value` as a guest writes it.
    ///
    /// The delivery status and the remote IRR stay 0, since this IOAPIC never
    /// has a send pending and serves no level-triggered EOI.
    fn with_half(self, high: bool, value: u32) -> Self {
        let bits = if high {
            (self.0 & 0xffff_ffff) | (u64::from(value) << 32)
        } else {
            (self.0 & !0xffff_ffff) | u64::from(value)
        };
        Self(bits & !(Self::DELIVERY_STATUS | Self::REMOTE_IRR))
    }

    /// Returns the MSI that delivers the entry's interrupt, or `None` when the
    /// entry has no route.
    ///
    /// An entry has a route when its delivery mode is fixed or lowest priority
    /// and its vector is 16 or more. Lowest priority sets the redirection hint,
    /// which KVM takes as lowest priority delivery. A level-triggered entry
    /// sets the trigger mode and level bits of the data. The destination is the
    /// entry's 8-bit field, with no extended destination ID. The mask and the
    /// polarity are not part of the MSI.
    fn msi(self) -> Option<Msi> {
        let vector = self.0 & Self::VECTOR;
        let delivery_mode = (self.0 >> Self::DELIVERY_MODE_SHIFT) & Self::DELIVERY_MODE;
        if !matches!(delivery_mode, Self::FIXED | Self::LOWEST_PRIORITY)
            || vector < Self::FIRST_VECTOR
        {
            return None;
        }
        let destination = (self.0 >> Self::DESTINATION_SHIFT) as u32;
        let mut address = Msi::ADDRESS | (destination << Msi::DESTINATION_SHIFT);
        if delivery_mode == Self::LOWEST_PRIORITY {
            address |= Msi::REDIRECTION_HINT;
        }
        if self.0 & Self::LOGICAL != 0 {
            address |= Msi::LOGICAL;
        }
        let mut data = vector as u32 | ((delivery_mode as u32) << Msi::DELIVERY_MODE_SHIFT);
        if self.0 & Self::LEVEL != 0 {
            data |= Msi::LEVEL | Msi::ASSERT;
        }
        Some(Msi { address, data })
    }
}

/// The registers of an [`IoApic`].
struct Registers {
    /// The index of the register the window reads and writes, IOREGSEL.
    select: u8,
    /// The 4-bit IOAPIC id.
    id: u8,
    /// The redirection entries, one per input.
    entries: [Entry; INPUTS],
    /// The MSI each input is routed with in KVM, or `None` for an input with no
    /// route.
    routes: [Option<Msi>; INPUTS],
}

impl Registers {
    /// Returns the input and the half of the redirection entry that the
    /// selected register holds, or `None` when it holds none.
    fn selected_entry(&self) -> Option<(usize, bool)> {
        let index = usize::from(self.select.checked_sub(REDIRECTION_TABLE)?);
        (index < 2 * INPUTS).then_some((index / 2, index % 2 == 1))
    }

    /// Returns the value of the selected register.
    ///
    /// A register past the redirection table reads all ones, as on KVM's
    /// in-kernel IOAPIC.
    fn read_window(&self) -> u32 {
        match self.select {
            ID | ARBITRATION => u32::from(self.id) << 24,
            VERSION => ((INPUTS as u32 - 1) << 16) | VERSION_ID,
            _ => self
                .selected_entry()
                .map_or(u32::MAX, |(input, high)| self.entries[input].half(high)),
        }
    }

    /// Writes `value` to the selected register.
    ///
    /// Returns the input whose redirection entry the write reached and whether
    /// it reached the entry's high half, or `None` when it reached no entry.
    /// Only the id and the redirection entries take a write. The arbitration
    /// register follows the id, which is what an 82093AA loads into it.
    fn write_window(&mut self, value: u32) -> Option<(usize, bool)> {
        match self.select {
            ID => {
                self.id = (value >> 24) as u8 & 0xf;
                None
            }
            _ => {
                let (input, high) = self.selected_entry()?;
                self.entries[input] = self.entries[input].with_half(high, value);
                Some((input, high))
            }
        }
    }

    /// Returns the route of every input that has one, with its GSI.
    fn route_table(&self) -> Vec<(u32, Msi)> {
        (0u32..)
            .zip(&self.routes)
            .filter_map(|(gsi, msi)| Some((gsi, (*msi)?)))
            .collect()
    }
}

/// An IOAPIC that hvi serves over KVM's split irqchip.
///
/// Its inputs are the GSIs 0 to 23, and each has an irqfd. The guest programs
/// it through two registers in its MMIO range: IOREGSEL selects a register and
/// IOWIN reads or writes it.
pub(super) struct IoApic {
    /// The registers, which the vCPUs read and write.
    registers: Mutex<Registers>,
    /// The inputs, indexed by GSI.
    inputs: Vec<Arc<Input>>,
    /// The GSI routing the routes are set in.
    routing: Arc<Routing>,
}

impl IoApic {
    /// Returns an IOAPIC with every input masked, which registers an irqfd for
    /// each input and sets routes through `routing`.
    ///
    /// # Errors
    ///
    /// Errors if an eventfd cannot be created or `routing` refuses an irqfd.
    fn new(routing: Routing) -> io::Result<Self> {
        let routing = Arc::new(routing);
        let inputs = (0..INPUTS as u32)
            .map(|gsi| Input::new(gsi, &routing).map(Arc::new))
            .collect::<io::Result<_>>()?;
        Ok(Self {
            registers: Mutex::new(Registers {
                select: 0,
                id: 0,
                entries: [Entry::RESET; INPUTS],
                routes: [None; INPUTS],
            }),
            inputs,
            routing,
        })
    }

    /// Puts the IOAPIC at its address on `mmio_bus`, and [`NoPic`] on the 8259
    /// ports of `port_bus`.
    ///
    /// # Errors
    ///
    /// Errors if a range overlaps one already on its bus.
    pub(super) fn attach(
        self: &Arc<Self>,
        mmio_bus: &mut Bus,
        port_bus: &mut Bus,
    ) -> Result<(), String> {
        mmio_bus.insert(
            u64::from(IOAPIC_ADDR),
            REGISTERS_LEN,
            Arc::clone(self) as Arc<dyn bus::Device>,
        )?;
        for port in PIC_PORTS {
            port_bus.insert(u64::from(port), 2, Arc::new(NoPic))?;
        }
        Ok(())
    }

    /// Returns input `gsi`, or `None` if the IOAPIC has no such input.
    fn input(&self, gsi: u32) -> Option<&Arc<Input>> {
        self.inputs.get(usize::try_from(gsi).ok()?)
    }

    /// Writes `value` to the register `registers` selects.
    ///
    /// It also applies a change to a redirection entry. The routes are set only
    /// when the entry's MSI differs from the one the input is routed with,
    /// since KVM waits for an SRCU grace period on each update and the guest
    /// masks and unmasks an input more often than it moves it. A write to the
    /// high half of a masked entry sets no route. Linux moves an input by
    /// masking it, then writing the high half and then the low half. KVM
    /// delivers a further eventfd on the input while it is masked, so a route
    /// set between the two writes would deliver that edge to the new
    /// destination with the old vector. The write to the low half sets the
    /// route of the whole entry.
    ///
    /// The routes are set before an unmask sends the edge the input holds, so
    /// the edge takes the new route. An input with no route stays held like a
    /// masked one, so an update KVM refused loses no edge of hvi's own devices.
    /// KVM drops a further eventfd's edge on an input with no route. The next
    /// write to the entry sets the routes again.
    fn write_window(&self, registers: &mut Registers, value: u32) {
        let Some((input, high)) = registers.write_window(value) else {
            return;
        };
        let entry = registers.entries[input];
        let msi = entry.msi();
        if msi != registers.routes[input] && !(high && entry.is_masked()) {
            let previous = std::mem::replace(&mut registers.routes[input], msi);
            if let Err(e) = (self.routing.set_routes)(&registers.route_table()) {
                registers.routes[input] = previous;
                stderrln!(
                    "{LOG_PREFIX} setting the route of IOAPIC input {input}: {e}; \
                     the routes stay as they were"
                );
            }
        }
        self.inputs[input].set_masked(entry.is_masked() || registers.routes[input].is_none());
    }
}

impl irq::Chip for IoApic {
    fn line(&self, gsi: u32) -> Arc<dyn irq::Line> {
        Arc::clone(
            self.input(gsi)
                .expect("an interrupt line should be an IOAPIC input"),
        ) as Arc<dyn irq::Line>
    }

    fn trigger(&self, gsi: u32) -> io::Result<Arc<dyn irq::Trigger>> {
        let input = self.input(gsi).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the IOAPIC has no input {gsi}"),
            )
        })?;
        Ok(Arc::clone(input) as Arc<dyn irq::Trigger>)
    }
}

impl bus::Device for IoApic {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let registers = self.registers.lock().unwrap();
        let value = match offset {
            SELECT => u32::from(registers.select),
            WINDOW => registers.read_window(),
            _ => 0,
        };
        // An access of 8 bytes reads the register zero-extended, and a narrower
        // one its low bytes.
        data.fill(0);
        let len = data.len().min(4);
        data[..len].copy_from_slice(&value.to_le_bytes()[..len]);
    }

    fn write(&self, offset: u64, data: &[u8]) -> Option<Stop> {
        let mut bytes = [0; 4];
        let len = data.len().min(4);
        bytes[..len].copy_from_slice(&data[..len]);
        let value = u32::from_le_bytes(bytes);
        let mut registers = self.registers.lock().unwrap();
        match offset {
            SELECT => registers.select = value as u8,
            WINDOW => self.write_window(&mut registers, value),
            _ => {}
        }
        None
    }
}

/// One input of an [`IoApic`], which a device holds as its interrupt line or
/// trigger.
///
/// An input takes each rise of its line as an edge, whatever trigger mode the
/// guest programs, and a fall does nothing. An edge is a write to the input's
/// irqfd. A further eventfd registered on the input delivers to the same GSI,
/// and KVM delivers it while the guest has the input masked too. Linux handles
/// an edge on a line it has disabled itself.
pub(super) struct Input {
    /// The GSI, which is the input's index.
    gsi: u32,
    /// The eventfd KVM delivers as the input's interrupt.
    irqfd: EventFd,
    /// The mask and the held edge.
    state: Mutex<InputState>,
    /// The GSI routing a further eventfd is registered through.
    routing: Arc<Routing>,
}

/// The mask of an [`Input`] and the edge it holds.
struct InputState {
    /// Whether the guest has the input masked.
    masked: bool,
    /// Whether an edge arrived while the input was masked.
    pending: bool,
}

impl Input {
    /// Returns input `gsi`, masked, with its irqfd registered through
    /// `routing`.
    ///
    /// # Errors
    ///
    /// Errors if the eventfd cannot be created or `routing` refuses it. A
    /// refusal names the input.
    fn new(gsi: u32, routing: &Arc<Routing>) -> io::Result<Self> {
        let input = Self {
            gsi,
            irqfd: EventFd::new(libc::EFD_NONBLOCK)?,
            state: Mutex::new(InputState {
                masked: true,
                pending: false,
            }),
            routing: Arc::clone(routing),
        };
        input.register(&input.irqfd)?;
        Ok(input)
    }

    /// Registers `fd` as an irqfd on the input's GSI.
    ///
    /// # Errors
    ///
    /// Errors if KVM refuses it. The error names the input.
    fn register(&self, fd: &EventFd) -> io::Result<()> {
        (self.routing.register_irqfd)(fd, self.gsi).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("registering an irqfd on IOAPIC input {}: {e}", self.gsi),
            )
        })
    }

    /// Masks or unmasks the input.
    ///
    /// When the input is unmasked, it also sends the edge it holds.
    fn set_masked(&self, masked: bool) {
        let mut state = self.state.lock().unwrap();
        state.masked = masked;
        if !masked && std::mem::take(&mut state.pending) {
            if let Err(e) = self.irqfd.write(1) {
                stderrln!(
                    "{LOG_PREFIX} sending the held edge of IOAPIC input {}: {e}",
                    self.gsi
                );
            }
        }
    }
}

impl irq::Trigger for Input {
    fn trigger(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.masked {
            state.pending = true;
            return Ok(());
        }
        self.irqfd.write(1)
    }

    fn register_irqfd(&self, fd: &EventFd) -> io::Result<()> {
        self.register(fd)
    }
}

impl irq::Line for Input {
    fn set_level(&self, level: bool) -> io::Result<()> {
        if level {
            irq::Trigger::trigger(self)
        } else {
            Ok(())
        }
    }
}

/// The ports of the absent 8259 pair beside an [`IoApic`], which read 0 and
/// ignore writes.
///
/// Linux probes for the master PIC by writing its mask register and reading it
/// back, and finds none when the value differs.
pub(super) struct NoPic;

impl bus::Device for NoPic {
    fn read(&self, _offset: u64, data: &mut [u8]) {
        data.fill(0);
    }

    fn write(&self, _offset: u64, _data: &[u8]) -> Option<Stop> {
        None
    }
}

#[cfg(test)]
mod tests {
    use bus::Device as _;
    use irq::{Chip as _, Trigger as _};

    use super::*;

    /// A line that records each level it is set to, in order.
    #[derive(Default)]
    struct RecordingLine {
        /// The levels, in the order they were set.
        levels: Mutex<Vec<bool>>,
    }

    impl irq::Line for RecordingLine {
        fn set_level(&self, level: bool) -> io::Result<()> {
            self.levels.lock().unwrap().push(level);
            Ok(())
        }
    }

    impl Pulsed<RecordingLine> {
        /// Returns the levels the line was set to, in order.
        fn levels(&self) -> Vec<bool> {
            self.line.lock().unwrap().levels.lock().unwrap().clone()
        }
    }

    #[test]
    fn pulse_raises_the_line_then_lowers_it() {
        let pulse = Pulsed::new(RecordingLine::default());
        pulse.trigger().unwrap();
        assert_eq!(pulse.levels(), [true, false]);
    }

    #[test]
    fn concurrent_pulses_do_not_interleave() {
        let pulse = Pulsed::new(RecordingLine::default());
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..1000 {
                        pulse.trigger().unwrap();
                    }
                });
            }
        });
        let levels = pulse.levels();
        assert_eq!(levels.len(), 8000);
        assert!(levels.chunks(2).all(|pair| pair == [true, false]));
    }

    /// The input the tests program, a virtio device's.
    const GSI: u32 = 5;
    /// The vector the tests program.
    const VECTOR: u32 = 0x31;

    /// What an [`IoApic`]'s routing was asked to do.
    #[derive(Default)]
    struct Recorded {
        /// Each registered irqfd, as a second handle to the eventfd, with its
        /// GSI.
        irqfds: Vec<(EventFd, u32)>,
        /// Each route table set, in order.
        routes: Vec<Vec<(u32, Msi)>>,
    }

    /// Returns an IOAPIC whose routing records what it is asked to do, and the
    /// record.
    fn recording() -> (IoApic, Arc<Mutex<Recorded>>) {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let irqfds = Arc::clone(&recorded);
        let routes = Arc::clone(&recorded);
        let ioapic = IoApic::new(Routing {
            register_irqfd: Box::new(move |fd, gsi| {
                irqfds.lock().unwrap().irqfds.push((fd.try_clone()?, gsi));
                Ok(())
            }),
            set_routes: Box::new(move |table| {
                routes.lock().unwrap().routes.push(table.to_vec());
                Ok(())
            }),
        })
        .unwrap();
        (ioapic, recorded)
    }

    impl Recorded {
        /// Returns the number of edges input `gsi`'s own irqfd holds.
        ///
        /// The read empties the irqfd.
        fn edges(&self, gsi: u32) -> u64 {
            let (fd, _) = &self.irqfds[gsi as usize];
            match fd.read() {
                Ok(count) => count,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                Err(e) => panic!("reading the irqfd: {e}"),
            }
        }
    }

    /// Writes register `index` through the window.
    fn write_register(ioapic: &IoApic, index: u8, value: u32) {
        ioapic.write(SELECT, &[index]);
        ioapic.write(WINDOW, &value.to_le_bytes());
    }

    /// Returns register `index`, read through the window.
    fn read_register(ioapic: &IoApic, index: u8) -> u32 {
        ioapic.write(SELECT, &[index]);
        let mut data = [0; 4];
        ioapic.read(WINDOW, &mut data);
        u32::from_le_bytes(data)
    }

    /// Writes the low half of input `gsi`'s redirection entry.
    fn write_low(ioapic: &IoApic, gsi: u32, value: u32) {
        write_register(ioapic, REDIRECTION_TABLE + 2 * gsi as u8, value);
    }

    /// Writes the high half of input `gsi`'s redirection entry.
    fn write_high(ioapic: &IoApic, gsi: u32, value: u32) {
        write_register(ioapic, REDIRECTION_TABLE + 2 * gsi as u8 + 1, value);
    }

    /// Returns the MSI of an entry with the given fields.
    fn msi(fields: u64) -> Option<Msi> {
        Entry(fields).msi()
    }

    #[test]
    fn every_input_has_an_irqfd_on_its_gsi() {
        let (_ioapic, recorded) = recording();
        let gsis: Vec<u32> = recorded
            .lock()
            .unwrap()
            .irqfds
            .iter()
            .map(|(_, gsi)| *gsi)
            .collect();
        assert_eq!(gsis, (0..24).collect::<Vec<_>>());
    }

    #[test]
    fn version_register_reports_version_0x11_and_23_as_the_last_entry() {
        let (ioapic, _) = recording();
        assert_eq!(read_register(&ioapic, VERSION), 0x0017_0011);
        write_register(&ioapic, VERSION, 0);
        assert_eq!(read_register(&ioapic, VERSION), 0x0017_0011);
    }

    #[test]
    fn id_keeps_four_bits_and_arbitration_follows_it() {
        let (ioapic, _) = recording();
        assert_eq!(read_register(&ioapic, ID), 0);
        write_register(&ioapic, ID, 0xff00_0000);
        assert_eq!(read_register(&ioapic, ID), 0x0f00_0000);
        assert_eq!(read_register(&ioapic, ARBITRATION), 0x0f00_0000);
        write_register(&ioapic, ARBITRATION, 0x0200_0000);
        assert_eq!(read_register(&ioapic, ARBITRATION), 0x0f00_0000);
    }

    #[test]
    fn select_keeps_eight_bits_and_reads_back() {
        let (ioapic, _) = recording();
        ioapic.write(SELECT, &0x0000_0123_u32.to_le_bytes());
        let mut data = [0xaa; 4];
        ioapic.read(SELECT, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0x23);
    }

    #[test]
    fn redirection_entry_reads_back_both_halves() {
        let (ioapic, _) = recording();
        assert_eq!(
            read_register(&ioapic, REDIRECTION_TABLE),
            1 << 16,
            "masked at reset"
        );
        write_high(&ioapic, GSI, 0x0300_0000);
        write_low(&ioapic, GSI, 0x0000_a931);
        let low = REDIRECTION_TABLE + 2 * GSI as u8;
        assert_eq!(read_register(&ioapic, low), 0x0000_a931);
        assert_eq!(read_register(&ioapic, low + 1), 0x0300_0000);
    }

    #[test]
    fn delivery_status_and_remote_irr_read_0_whatever_is_written() {
        let (ioapic, _) = recording();
        write_low(&ioapic, GSI, 0x0001_5031);
        let low = REDIRECTION_TABLE + 2 * GSI as u8;
        assert_eq!(read_register(&ioapic, low), 0x0001_0031);
    }

    #[test]
    fn register_past_the_table_reads_all_ones_and_ignores_writes() {
        let (ioapic, recorded) = recording();
        for index in [0x03, 0x0f, REDIRECTION_TABLE + 48, 0xff] {
            write_register(&ioapic, index, 0x31);
            assert_eq!(
                read_register(&ioapic, index),
                u32::MAX,
                "register {index:#x}"
            );
        }
        assert!(recorded.lock().unwrap().routes.is_empty());
        assert_eq!(read_register(&ioapic, REDIRECTION_TABLE + 47), 0);
    }

    #[test]
    fn offsets_other_than_select_and_window_read_0() {
        let (ioapic, _) = recording();
        write_register(&ioapic, ID, 0x0f00_0000);
        ioapic.write(0x20, &0x31_u32.to_le_bytes());
        let mut data = [0xaa; 4];
        ioapic.read(0x14, &mut data);
        assert_eq!(data, [0; 4]);
        assert_eq!(read_register(&ioapic, ID), 0x0f00_0000);
    }

    #[test]
    fn narrow_and_wide_accesses_take_the_low_bytes() {
        let (ioapic, _) = recording();
        ioapic.write(SELECT, &[VERSION]);
        let mut wide = [0xaa; 8];
        ioapic.read(WINDOW, &mut wide);
        assert_eq!(wide, [0x11, 0, 0x17, 0, 0, 0, 0, 0]);
        let mut byte = [0xaa];
        ioapic.read(WINDOW, &mut byte);
        assert_eq!(byte, [0x11]);
        // A one-byte write to the window writes the register zero-extended.
        ioapic.write(SELECT, &[REDIRECTION_TABLE]);
        ioapic.write(WINDOW, &[0x31]);
        assert_eq!(read_register(&ioapic, REDIRECTION_TABLE), 0x31);
    }

    #[test]
    fn fixed_physical_edge_entry_routes_its_vector_to_its_destination() {
        assert_eq!(
            msi(0x0300_0000_0000_0031),
            Some(Msi {
                address: 0xfee0_3000,
                data: 0x31
            })
        );
    }

    #[test]
    fn lowest_priority_logical_entry_sets_the_redirection_hint() {
        assert_eq!(
            msi(0x0f00_0000_0000_0931),
            Some(Msi {
                address: 0xfee0_f00c,
                data: 0x0131
            })
        );
    }

    #[test]
    fn level_entry_sets_the_trigger_and_assert_bits() {
        assert_eq!(
            msi(0x0000_0000_0000_8031),
            Some(Msi {
                address: 0xfee0_0000,
                data: 0xc031
            })
        );
    }

    #[test]
    fn mask_polarity_and_reserved_bits_leave_the_msi_alone() {
        let plain = msi(0x0200_0000_0000_0031);
        assert_eq!(msi(0x0200_0000_0001_2031), plain);
        assert_eq!(msi(0x02ff_0000_0000_0031), plain);
        assert!(plain.is_some());
    }

    #[test]
    fn exception_vectors_and_other_delivery_modes_have_no_route() {
        assert_eq!(msi(0x0000_0000_0001_0000), None, "the reset value");
        assert_eq!(msi(0x0f), None);
        for mode in [2, 3, 4, 5, 6, 7] {
            assert_eq!(msi(0x31 | (mode << 8)), None, "delivery mode {mode}");
        }
        assert!(msi(0x10).is_some());
    }

    #[test]
    fn routes_are_set_only_when_an_msi_changes() {
        let (ioapic, recorded) = recording();
        let route_sets = || recorded.lock().unwrap().routes.len();
        write_high(&ioapic, GSI, 0x0100_0000);
        assert_eq!(route_sets(), 0, "a masked entry with vector 0 has no route");
        write_low(&ioapic, GSI, VECTOR);
        assert_eq!(
            recorded.lock().unwrap().routes.last().unwrap(),
            &[(
                GSI,
                Msi {
                    address: 0xfee0_1000,
                    data: VECTOR
                }
            )]
        );
        for low in [VECTOR, VECTOR | 1 << 16, VECTOR, VECTOR | 1 << 13] {
            write_low(&ioapic, GSI, low);
        }
        write_high(&ioapic, GSI, 0x0100_0000);
        assert_eq!(route_sets(), 1, "the mask and the polarity set no route");
        write_high(&ioapic, GSI, 0x0200_0000);
        write_low(&ioapic, GSI, 0x32);
        assert_eq!(route_sets(), 3);
        write_low(&ioapic, GSI, 0x0f);
        assert!(recorded.lock().unwrap().routes.last().unwrap().is_empty());
    }

    // Linux moves an input by masking it, writing the high half, then the low
    // half, and unmasking it. A route set after the high half would pair the
    // new destination with the old vector.
    #[test]
    fn high_half_of_a_masked_entry_sets_no_route_until_the_low_half() {
        let (ioapic, recorded) = recording();
        write_high(&ioapic, GSI, 0x0100_0000);
        write_low(&ioapic, GSI, VECTOR);
        let moved = [(
            GSI,
            Msi {
                address: 0xfee0_2000,
                data: 0x32,
            },
        )];
        write_low(&ioapic, GSI, VECTOR | 1 << 16);
        write_high(&ioapic, GSI, 0x0200_0000);
        assert_eq!(recorded.lock().unwrap().routes.len(), 1, "one half written");
        write_low(&ioapic, GSI, 0x32 | 1 << 16);
        assert_eq!(recorded.lock().unwrap().routes.last().unwrap(), &moved);
        write_low(&ioapic, GSI, 0x32);
        assert_eq!(
            recorded.lock().unwrap().routes.len(),
            2,
            "the unmask set none"
        );
    }

    #[test]
    fn refused_route_holds_the_edge_and_is_set_at_the_next_write() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let irqfds = Arc::clone(&recorded);
        let routes = Arc::clone(&recorded);
        let refuse = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let refused = Arc::clone(&refuse);
        let ioapic = IoApic::new(Routing {
            register_irqfd: Box::new(move |fd, gsi| {
                irqfds.lock().unwrap().irqfds.push((fd.try_clone()?, gsi));
                Ok(())
            }),
            set_routes: Box::new(move |table| {
                if refused.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(io::Error::from_raw_os_error(libc::ENOMEM));
                }
                routes.lock().unwrap().routes.push(table.to_vec());
                Ok(())
            }),
        })
        .unwrap();
        let trigger = ioapic.trigger(GSI).unwrap();
        write_low(&ioapic, GSI, VECTOR);
        trigger.trigger().unwrap();
        assert_eq!(recorded.lock().unwrap().edges(GSI), 0, "no route yet");
        refuse.store(false, std::sync::atomic::Ordering::SeqCst);
        write_low(&ioapic, GSI, VECTOR);
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.routes.len(), 1, "the same entry set the route");
        assert_eq!(recorded.edges(GSI), 1);
    }

    #[test]
    fn route_table_holds_every_routed_input() {
        let (ioapic, recorded) = recording();
        write_low(&ioapic, 4, 0x30);
        write_low(&ioapic, GSI, VECTOR);
        let table = recorded.lock().unwrap().routes.last().unwrap().clone();
        let gsis: Vec<u32> = table.iter().map(|(gsi, _)| *gsi).collect();
        assert_eq!(gsis, [4, GSI]);
    }

    #[test]
    fn unmasked_trigger_writes_the_irqfd() {
        let (ioapic, recorded) = recording();
        write_low(&ioapic, GSI, VECTOR);
        let trigger = ioapic.trigger(GSI).unwrap();
        trigger.trigger().unwrap();
        trigger.trigger().unwrap();
        assert_eq!(recorded.lock().unwrap().edges(GSI), 2);
    }

    #[test]
    fn trigger_on_a_masked_input_is_sent_once_on_unmask() {
        let (ioapic, recorded) = recording();
        let trigger = ioapic.trigger(GSI).unwrap();
        trigger.trigger().unwrap();
        trigger.trigger().unwrap();
        write_low(&ioapic, GSI, VECTOR | 1 << 16);
        assert_eq!(recorded.lock().unwrap().edges(GSI), 0, "still masked");
        write_low(&ioapic, GSI, VECTOR);
        assert_eq!(recorded.lock().unwrap().edges(GSI), 1);
        write_low(&ioapic, GSI, VECTOR);
        write_low(&ioapic, GSI, VECTOR | 1 << 16);
        write_low(&ioapic, GSI, VECTOR);
        assert_eq!(recorded.lock().unwrap().edges(GSI), 0, "sent once");
    }

    // The unmask also moves the entry to a new vector, so the held edge must
    // wait for the new route.
    #[test]
    fn held_edge_is_sent_after_the_route_is_set() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let irqfds = Arc::clone(&recorded);
        let routes = Arc::clone(&recorded);
        let ioapic = IoApic::new(Routing {
            register_irqfd: Box::new(move |fd, gsi| {
                irqfds.lock().unwrap().irqfds.push((fd.try_clone()?, gsi));
                Ok(())
            }),
            set_routes: Box::new(move |table| {
                let mut recorded = routes.lock().unwrap();
                if !table.is_empty() {
                    assert_eq!(recorded.edges(GSI), 0, "the edge went before the route");
                }
                recorded.routes.push(table.to_vec());
                Ok(())
            }),
        })
        .unwrap();
        ioapic.trigger(GSI).unwrap().trigger().unwrap();
        write_low(&ioapic, GSI, VECTOR);
        assert_eq!(recorded.lock().unwrap().routes.len(), 1);
        assert_eq!(recorded.lock().unwrap().edges(GSI), 1);
    }

    #[test]
    fn line_sends_an_edge_on_a_rise_and_nothing_on_a_fall() {
        let (ioapic, recorded) = recording();
        write_low(&ioapic, GSI, VECTOR);
        let line = ioapic.line(GSI);
        line.set_level(false).unwrap();
        assert_eq!(recorded.lock().unwrap().edges(GSI), 0);
        line.set_level(true).unwrap();
        assert_eq!(recorded.lock().unwrap().edges(GSI), 1);
    }

    #[test]
    fn further_irqfd_is_registered_on_the_input_gsi() {
        let (ioapic, recorded) = recording();
        let call = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        ioapic.trigger(GSI).unwrap().register_irqfd(&call).unwrap();
        let recorded = recorded.lock().unwrap();
        let (fd, gsi) = recorded.irqfds.last().unwrap();
        assert_eq!(*gsi, GSI);
        call.write(7).unwrap();
        assert_eq!(fd.read().unwrap(), 7, "the call eventfd itself");
    }

    #[test]
    fn refused_irqfd_names_its_input() {
        let ioapic = IoApic::new(Routing {
            register_irqfd: Box::new(|_, gsi| match gsi {
                30 => Err(io::Error::from_raw_os_error(libc::EINVAL)),
                _ => Ok(()),
            }),
            set_routes: Box::new(|_| Ok(())),
        })
        .unwrap();
        let refused = Input::new(30, &ioapic.routing).map(|_| ()).unwrap_err();
        assert!(
            refused
                .to_string()
                .starts_with("registering an irqfd on IOAPIC input 30: "),
            "{refused}"
        );
        let missing = ioapic.trigger(30).map(|_| ()).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn pic_ports_read_0_and_the_ioapic_answers_at_its_address() {
        let (ioapic, _) = recording();
        let ioapic = Arc::new(ioapic);
        let mut mmio_bus = Bus::new();
        let mut port_bus = Bus::new();
        ioapic.attach(&mut mmio_bus, &mut port_bus).unwrap();
        for port in [0x20, 0x21, 0xa0, 0xa1] {
            port_bus.write(port, &[0xfb]).unwrap();
            let mut data = [0xaa];
            port_bus.read(port, &mut data).unwrap();
            assert_eq!(data, [0], "port {port:#x}");
        }
        let mut data = [0];
        assert!(port_bus.read(0x22, &mut data).is_err());
        let base = u64::from(IOAPIC_ADDR);
        mmio_bus.write(base, &[VERSION]).unwrap();
        let mut version = [0; 4];
        mmio_bus.read(base + WINDOW, &mut version).unwrap();
        assert_eq!(u32::from_le_bytes(version), 0x0017_0011);
        assert!(mmio_bus.read(base + REGISTERS_LEN, &mut version).is_err());
    }
}

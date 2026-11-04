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

//! The virtio-mmio transport, which serves a device's common registers.
//!
//! [`Transport`] decodes the common registers below [`CONFIG`] for one
//! [`virtio::Device`], as virtio 1.2 section 4.2.2 specifies them: the feature
//! words, the device status and the order the driver sets it in, the queue
//! registers and the interrupt registers. It passes configuration space
//! accesses, activation, queue notifications and reset to the device.
//! [`Interrupt`] holds the interrupt status and the line, which the transport
//! and the device share.
//!
//! The offsets come from `virtio-bindings`, which is bindgen output from the
//! kernel headers, so they match the kernel's. They are re-exported as `u64`
//! because that is what an MMIO dispatch matches on, and under our own names
//! where the kernel's differ: the spec calls the second and third rings
//! *driver* and *device*, which is what the register names say, while the
//! kernel header still calls them *avail* and *used*.

use std::sync::{Arc, Mutex};

use virtio_bindings::virtio_config::{
    VIRTIO_CONFIG_S_ACKNOWLEDGE as ACKNOWLEDGE, VIRTIO_CONFIG_S_DRIVER as DRIVER,
    VIRTIO_CONFIG_S_DRIVER_OK as DRIVER_OK, VIRTIO_CONFIG_S_FAILED as FAILED,
    VIRTIO_CONFIG_S_FEATURES_OK as FEATURES_OK, VIRTIO_CONFIG_S_NEEDS_RESET as NEEDS_RESET,
    VIRTIO_F_VERSION_1,
};
use virtio_bindings::virtio_mmio::*;

use crate::config::Stop;
use crate::devices::bus;
use crate::devices::irq::{Irq, IrqLine};
use crate::devices::virtio::{self, Queue};
use crate::events::Ledger;
use crate::memory::GuestRam;
use crate::LOG_PREFIX;

/// The size of one device's register range, which holds the common registers
/// below `0x100` and the device's configuration space from there.
pub const RANGE_SIZE: u64 = 0x200;

pub const MAGIC: u64 = VIRTIO_MMIO_MAGIC_VALUE as u64; // "virt"
pub const VERSION: u64 = VIRTIO_MMIO_VERSION as u64; // 2
pub const DEVICE_ID: u64 = VIRTIO_MMIO_DEVICE_ID as u64;
pub const VENDOR_ID: u64 = VIRTIO_MMIO_VENDOR_ID as u64;
pub const DEVICE_FEATURES: u64 = VIRTIO_MMIO_DEVICE_FEATURES as u64;
pub const DEVICE_FEATURES_SEL: u64 = VIRTIO_MMIO_DEVICE_FEATURES_SEL as u64;
pub const DRIVER_FEATURES: u64 = VIRTIO_MMIO_DRIVER_FEATURES as u64;
pub const DRIVER_FEATURES_SEL: u64 = VIRTIO_MMIO_DRIVER_FEATURES_SEL as u64;
pub const QUEUE_SEL: u64 = VIRTIO_MMIO_QUEUE_SEL as u64;
pub const QUEUE_NUM_MAX: u64 = VIRTIO_MMIO_QUEUE_NUM_MAX as u64;
pub const QUEUE_NUM: u64 = VIRTIO_MMIO_QUEUE_NUM as u64;
pub const QUEUE_READY: u64 = VIRTIO_MMIO_QUEUE_READY as u64;
pub const QUEUE_NOTIFY: u64 = VIRTIO_MMIO_QUEUE_NOTIFY as u64;
pub const INTERRUPT_STATUS: u64 = VIRTIO_MMIO_INTERRUPT_STATUS as u64;
pub const INTERRUPT_ACK: u64 = VIRTIO_MMIO_INTERRUPT_ACK as u64;
pub const STATUS: u64 = VIRTIO_MMIO_STATUS as u64;
pub const QUEUE_DESC_LOW: u64 = VIRTIO_MMIO_QUEUE_DESC_LOW as u64;
pub const QUEUE_DESC_HIGH: u64 = VIRTIO_MMIO_QUEUE_DESC_HIGH as u64;
pub const QUEUE_DRIVER_LOW: u64 = VIRTIO_MMIO_QUEUE_AVAIL_LOW as u64;
pub const QUEUE_DRIVER_HIGH: u64 = VIRTIO_MMIO_QUEUE_AVAIL_HIGH as u64;
pub const QUEUE_DEVICE_LOW: u64 = VIRTIO_MMIO_QUEUE_USED_LOW as u64;
pub const QUEUE_DEVICE_HIGH: u64 = VIRTIO_MMIO_QUEUE_USED_HIGH as u64;
// Shared memory regions (virtio 1.2).
pub const SHM_LEN_LOW: u64 = VIRTIO_MMIO_SHM_LEN_LOW as u64;
pub const SHM_LEN_HIGH: u64 = VIRTIO_MMIO_SHM_LEN_HIGH as u64;
pub const SHM_BASE_LOW: u64 = VIRTIO_MMIO_SHM_BASE_LOW as u64;
pub const SHM_BASE_HIGH: u64 = VIRTIO_MMIO_SHM_BASE_HIGH as u64;
pub const CONFIG_GENERATION: u64 = VIRTIO_MMIO_CONFIG_GENERATION as u64;
pub const CONFIG: u64 = VIRTIO_MMIO_CONFIG as u64;

/// The magic value, "virt" little-endian.
const MAGIC_VALUE: u32 = 0x7472_6976;
/// The vendor ID every hvi device reports, "NOIF" little-endian.
const VENDOR_ID_VALUE: u32 = 0x4649_4f4e;
/// The `VIRTIO_F_VERSION_1` feature bit, which the transport offers for every
/// device, since it is a version 2 transport.
const F_VERSION_1: u64 = 1 << VIRTIO_F_VERSION_1;

/// The device status after each step of a driver's initialization, in the order
/// virtio 1.2 section 3.1.1 lists them.
const STATUS_STEPS: [u32; 4] = [
    ACKNOWLEDGE,
    ACKNOWLEDGE | DRIVER,
    ACKNOWLEDGE | DRIVER | FEATURES_OK,
    ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
];

/// The device status field, which a driver sets one step at a time as it
/// initializes a device.
///
/// The bits are the `VIRTIO_CONFIG_S_*` values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DeviceStatus(u32);

impl DeviceStatus {
    /// Returns the status whose bits are `bits`.
    const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the bits of the status.
    const fn to_bits(self) -> u32 {
        self.0
    }

    /// Returns whether every bit of `bits` is set.
    const fn contains(self, bits: u32) -> bool {
        self.0 & bits == bits
    }

    /// Returns whether no bit of `bits` is set.
    const fn is_disjoint(self, bits: u32) -> bool {
        self.0 & bits == 0
    }

    /// Sets the bits of `bits`.
    fn insert(&mut self, bits: u32) {
        self.0 |= bits;
    }
}

/// The interrupt of one virtio device, with the interrupt status the guest
/// reads.
///
/// The status bits and the level of the line change under one lock. The line is
/// level-triggered, so a raise from a device thread and an acknowledgment from
/// a vCPU must set it in the order they changed the bits, or the line could
/// stay low with a bit set. The lock is separate from the transport state lock
/// and the device lock, so an interrupt status read or an acknowledgment never
/// waits for a device that is serving its queues.
pub(crate) struct Interrupt {
    /// The state behind the lock.
    state: Mutex<InterruptState>,
}

/// The state behind [`Interrupt`].
struct InterruptState {
    /// The pending `VIRTIO_MMIO_INT_*` bits.
    status: u32,
    /// The configuration generation, which each configuration change
    /// increments.
    config_generation: u32,
    /// Whether notifications are taken, from the DRIVER_OK write until the next
    /// reset.
    enabled: bool,
    /// The line the status drives.
    irq: Irq,
}

impl Interrupt {
    /// Returns an interrupt that drives `line`.
    pub(crate) fn new(line: Arc<dyn IrqLine>) -> Self {
        let mut irq = Irq::default();
        irq.connect(line);
        Self {
            state: Mutex::new(InterruptState {
                status: 0,
                config_generation: 0,
                enabled: false,
                irq,
            }),
        }
    }

    /// Raises a used-buffer notification.
    pub(crate) fn signal_used_buffer(&self) {
        self.raise(VIRTIO_MMIO_INT_VRING);
    }

    /// Raises a configuration change notification.
    ///
    /// The configuration generation is incremented whether or not the interrupt
    /// is enabled, since the configuration changed either way.
    pub(crate) fn signal_config_change(&self) {
        let mut state = self.state.lock().unwrap();
        state.config_generation = state.config_generation.wrapping_add(1);
        state.raise(VIRTIO_MMIO_INT_CONFIG);
    }

    /// Raises the notification `bit`.
    fn raise(&self, bit: u32) {
        self.state.lock().unwrap().raise(bit);
    }

    /// Returns the pending notification bits.
    fn status(&self) -> u32 {
        self.state.lock().unwrap().status
    }

    /// Clears the notification `bits` and lowers the line once none is left,
    /// when the interrupt is enabled.
    fn acknowledge(&self, bits: u32) {
        let mut state = self.state.lock().unwrap();
        if state.enabled {
            state.status &= !bits;
            let level = state.status != 0;
            state.irq.set(level);
        }
    }

    /// Returns the configuration generation.
    fn config_generation(&self) -> u32 {
        self.state.lock().unwrap().config_generation
    }

    /// Enables the interrupt, so notifications are raised and acknowledged.
    fn enable(&self) {
        self.state.lock().unwrap().enabled = true;
    }

    /// Drops the pending notifications, lowers the line and disables the
    /// interrupt.
    ///
    /// The configuration generation is kept.
    fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        state.enabled = false;
        state.status = 0;
        state.irq.set(false);
    }
}

impl InterruptState {
    /// Sets the notification `bit` and raises the line, when the interrupt is
    /// enabled.
    fn raise(&mut self, bit: u32) {
        if self.enabled {
            self.status |= bit;
            self.irq.set(true);
        }
    }
}

/// The virtio-mmio transport of one device, which serves the bus accesses to
/// its register range.
///
/// The transport state and the device each have a lock, taken in that order and
/// never the reverse. The state lock is released before a queue notification or
/// a configuration space access reaches the device, so a vCPU's register access
/// does not wait for another vCPU's queue work. It is held across activation
/// and reset, so two STATUS writes cannot leave the device activated under a
/// transport that reset.
pub(crate) struct Transport<D> {
    /// The device.
    device: Arc<Mutex<D>>,
    /// The device's interrupt.
    interrupt: Arc<Interrupt>,
    /// What the driver has programmed.
    state: Mutex<TransportState>,
    /// The device type, read once from the device.
    device_type: u32,
    /// The features the device offers, read once from it, with
    /// `VIRTIO_F_VERSION_1` added.
    device_features: u64,
    /// The largest size of each queue, read once from the device.
    queue_max_sizes: Vec<u16>,
    /// The guest RAM the queues are in.
    ram: Arc<GuestRam>,
    /// The ledger that receives the events the device captures.
    ledger: Arc<Ledger>,
}

/// What the driver has programmed into a [`Transport`].
struct TransportState {
    /// The device status.
    status: DeviceStatus,
    /// The feature word `DEVICE_FEATURES` reads.
    device_features_select: u32,
    /// The feature word `DRIVER_FEATURES` writes.
    driver_features_select: u32,
    /// The features the driver accepted.
    driver_features: u64,
    /// The queue the queue registers address.
    queue_select: u32,
    /// The queues, until the device is activated with them.
    queues: Vec<Queue>,
    /// Whether each queue was ready when the device was activated with it.
    ready_at_activation: Vec<bool>,
}

impl TransportState {
    /// Returns the state of a new or reset device, with a fresh queue of each
    /// size.
    fn new(queue_max_sizes: &[u16]) -> Self {
        Self {
            status: DeviceStatus::default(),
            device_features_select: 0,
            driver_features_select: 0,
            driver_features: 0,
            queue_select: 0,
            queues: queue_max_sizes.iter().map(|&max| Queue::new(max)).collect(),
            ready_at_activation: Vec::new(),
        }
    }

    /// Returns whether DRIVER_OK is set without FAILED or NEEDS_RESET.
    fn is_live(&self) -> bool {
        self.status.contains(DRIVER_OK) && self.status.is_disjoint(FAILED | NEEDS_RESET)
    }

    /// Returns whether queue `index` is ready, or `false` when the device has
    /// no such queue.
    fn is_queue_ready(&self, index: usize) -> bool {
        match self.queues.get(index) {
            Some(queue) => queue.is_ready(),
            None => self
                .ready_at_activation
                .get(index)
                .copied()
                .unwrap_or(false),
        }
    }

    /// Applies a write to a feature, selector or queue register.
    ///
    /// The driver features are taken between DRIVER and FEATURES_OK, a word at
    /// a time: a write replaces the selected word with the value masked by what
    /// the device offers. The queue registers are taken between FEATURES_OK and
    /// DRIVER_OK, for a queue the device has.
    fn write_register(&mut self, offset: u64, value: u32, device_features: u64, ram: &GuestRam) {
        match offset {
            DEVICE_FEATURES_SEL => self.device_features_select = value,
            DRIVER_FEATURES_SEL => self.driver_features_select = value,
            DRIVER_FEATURES
                if self.status.contains(DRIVER)
                    && self.status.is_disjoint(FEATURES_OK | FAILED | NEEDS_RESET) =>
            {
                let shift = match self.driver_features_select {
                    0 => 0,
                    1 => 32,
                    _ => return,
                };
                let word_mask = u64::from(u32::MAX) << shift;
                let accepted = (u64::from(value) << shift) & device_features;
                self.driver_features = (self.driver_features & !word_mask) | accepted;
            }
            QUEUE_SEL => self.queue_select = value,
            _ if self.status.contains(FEATURES_OK)
                && self.status.is_disjoint(DRIVER_OK | FAILED) =>
            {
                let select = self.queue_select as usize;
                let Some(queue) = self.queues.get_mut(select) else {
                    return;
                };
                match offset {
                    QUEUE_NUM => queue.set_num(value),
                    QUEUE_READY => queue.set_ready(value, ram),
                    QUEUE_DESC_LOW => queue.set_desc_lo(value),
                    QUEUE_DESC_HIGH => queue.set_desc_hi(value),
                    QUEUE_DRIVER_LOW => queue.set_avail_lo(value),
                    QUEUE_DRIVER_HIGH => queue.set_avail_hi(value),
                    QUEUE_DEVICE_LOW => queue.set_used_lo(value),
                    QUEUE_DEVICE_HIGH => queue.set_used_hi(value),
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

impl<D: virtio::Device> Transport<D> {
    /// Returns the transport of `device`, which raises `interrupt` and serves
    /// queues in `ram`.
    pub(crate) fn new(
        device: &Arc<Mutex<D>>,
        interrupt: &Arc<Interrupt>,
        ram: &Arc<GuestRam>,
        ledger: &Arc<Ledger>,
    ) -> Self {
        let (device_type, device_features, queue_max_sizes) = {
            let device = device.lock().unwrap();
            (
                device.device_type(),
                device.features() | F_VERSION_1,
                device.queue_max_sizes().to_vec(),
            )
        };
        Self {
            device: Arc::clone(device),
            interrupt: Arc::clone(interrupt),
            state: Mutex::new(TransportState::new(&queue_max_sizes)),
            device_type,
            device_features,
            queue_max_sizes,
            ram: Arc::clone(ram),
            ledger: Arc::clone(ledger),
        }
    }

    /// Returns the value of the common register at `offset`.
    fn read_register(&self, offset: u64) -> u32 {
        match offset {
            MAGIC => MAGIC_VALUE,
            VERSION => 2,
            DEVICE_ID => self.device_type,
            VENDOR_ID => VENDOR_ID_VALUE,
            INTERRUPT_STATUS => self.interrupt.status(),
            CONFIG_GENERATION => self.interrupt.config_generation(),
            // No device has a shared memory region, and virtio 1.2 gives a
            // missing region a length and a base of all ones. A guest built
            // with FUSE_DAX fails its probe on a zero length.
            SHM_LEN_LOW | SHM_LEN_HIGH | SHM_BASE_LOW | SHM_BASE_HIGH => u32::MAX,
            _ => {
                let state = self.state.lock().unwrap();
                match offset {
                    DEVICE_FEATURES => match state.device_features_select {
                        0 => self.device_features as u32,
                        1 => (self.device_features >> 32) as u32,
                        _ => 0,
                    },
                    QUEUE_NUM_MAX => self
                        .queue_max_sizes
                        .get(state.queue_select as usize)
                        .map_or(0, |&size| u32::from(size)),
                    QUEUE_READY => u32::from(state.is_queue_ready(state.queue_select as usize)),
                    STATUS => state.status.to_bits(),
                    _ => 0,
                }
            }
        }
    }

    /// Applies a write of `value` to the common register at `offset`.
    fn write_register(&self, offset: u64, value: u32) {
        match offset {
            INTERRUPT_ACK => self.interrupt.acknowledge(value),
            QUEUE_NOTIFY => self.notify(value),
            STATUS => self.set_status(value),
            _ => self.state.lock().unwrap().write_register(
                offset,
                value,
                self.device_features,
                &self.ram,
            ),
        }
    }

    /// Passes a notification of `queue` to the device, when the device is live
    /// and has the queue.
    fn notify(&self, queue: u32) {
        let live = self.state.lock().unwrap().is_live();
        let Some(queue) = u16::try_from(queue)
            .ok()
            .filter(|&queue| usize::from(queue) < self.queue_max_sizes.len())
        else {
            return;
        };
        if live {
            self.access_device(|device, ram| device.notify(ram, queue));
        }
    }

    /// Applies a STATUS write.
    ///
    /// A write of 0 resets the device, and one with FAILED sets FAILED. Any
    /// other write is taken only as the next step of the initialization. The
    /// step to FEATURES_OK is refused without `VIRTIO_F_VERSION_1` or when the
    /// device does not accept the features, and the step to DRIVER_OK activates
    /// the device. The queues ready at activation are then notified once, since
    /// a notification before DRIVER_OK was dropped.
    fn set_status(&self, value: u32) {
        let replay = {
            let mut state = self.state.lock().unwrap();
            let step = STATUS_STEPS.iter().position(|&step| step == value);
            let previous =
                step.map(|step| step.checked_sub(1).map_or(0, |prior| STATUS_STEPS[prior]));
            if value == 0 {
                self.reset(&mut state);
                Vec::new()
            } else if value & FAILED != 0 {
                state.status.insert(FAILED);
                Vec::new()
            } else if previous != Some(state.status.to_bits()) {
                Vec::new()
            } else if value & DRIVER_OK != 0 {
                self.activate(&mut state)
            } else {
                if value & FEATURES_OK == 0 || self.accepts_features(state.driver_features) {
                    state.status = DeviceStatus::from_bits(value);
                }
                Vec::new()
            }
        };
        for queue in replay {
            self.notify(queue);
        }
    }

    /// Returns whether `driver_features` include `VIRTIO_F_VERSION_1` and the
    /// device accepts them.
    fn accepts_features(&self, driver_features: u64) -> bool {
        driver_features & F_VERSION_1 != 0
            && self
                .device
                .lock()
                .unwrap()
                .accepts_features(driver_features)
    }

    /// Activates the device with the queues.
    ///
    /// Returns the indexes of the queues that were ready. When the device
    /// refuses, STATUS gets NEEDS_RESET, a configuration change is raised and
    /// no index is returned. STATUS gets DRIVER_OK only once the device is
    /// activated, so a notification is passed only to an activated device.
    fn activate(&self, state: &mut TransportState) -> Vec<u32> {
        let queues = std::mem::take(&mut state.queues);
        state.ready_at_activation = queues.iter().map(Queue::is_ready).collect();
        let ready = (0u32..)
            .zip(&state.ready_at_activation)
            .filter(|&(_, &ready)| ready)
            .map(|(index, _)| index)
            .collect();
        self.interrupt.enable();
        let activated = self.device.lock().unwrap().activate(
            &self.ram,
            state.driver_features,
            queues,
            Arc::clone(&self.interrupt),
        );
        match activated {
            Ok(()) => {
                state.status.insert(DRIVER_OK);
                ready
            }
            Err(e) => {
                stderrln!("{LOG_PREFIX} {e}");
                state.status.insert(NEEDS_RESET);
                self.interrupt.signal_config_change();
                Vec::new()
            }
        }
    }

    /// Resets the interrupt, the device and the transport state.
    fn reset(&self, state: &mut TransportState) {
        self.interrupt.reset();
        self.device.lock().unwrap().reset();
        *state = TransportState::new(&self.queue_max_sizes);
    }

    /// Returns the result of `serve` run on the device.
    ///
    /// Once the device lock is released, the batch of the sink the call fed
    /// ends, and then the events the device captured go to the ledger. The
    /// batch ends first, so a reader that waits on the sink does not also wait
    /// for the ledger.
    fn access_device<R>(&self, serve: impl FnOnce(&mut D, &GuestRam) -> R) -> R {
        let (served, events, sink) = {
            let mut device = self.device.lock().unwrap();
            let served = serve(&mut device, &self.ram);
            (served, device.take_events(), device.take_fed_sink())
        };
        if let Some(sink) = sink {
            sink.on_batch_end();
        }
        self.ledger.captured(&events);
        served
    }
}

impl<D: virtio::Device> bus::Device for Transport<D> {
    // A common register takes a 4-byte access only, and any other width reads
    // 0. Configuration space takes any width.
    fn read(&self, offset: u64, data: &mut [u8]) {
        if offset >= CONFIG {
            self.device
                .lock()
                .unwrap()
                .read_config(offset - CONFIG, data);
        } else if data.len() == 4 {
            data.copy_from_slice(&self.read_register(offset).to_le_bytes());
        } else {
            data.fill(0);
        }
    }

    // A configuration space write is taken once DRIVER is set and before
    // FAILED. A common register write of any width but 4 is ignored.
    fn write(&self, offset: u64, data: &[u8]) -> Option<Stop> {
        if offset >= CONFIG {
            let status = self.state.lock().unwrap().status;
            if status.contains(DRIVER) && status.is_disjoint(FAILED) {
                self.device
                    .lock()
                    .unwrap()
                    .write_config(offset - CONFIG, data);
            }
        } else if let Ok(bytes) = <[u8; 4]>::try_from(data) {
            self.write_register(offset, u32::from_le_bytes(bytes));
        }
        None
    }
}

/// Helpers for the device tests, among them a guest driver of one device.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::devices::bus::Device as _;

    /// A line that holds the level it was last set to.
    #[derive(Default)]
    pub(crate) struct LevelLine(AtomicBool);

    impl LevelLine {
        /// Returns whether the line is high.
        pub(crate) fn is_high(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl IrqLine for LevelLine {
        fn set_level(&self, level: bool) -> std::io::Result<()> {
            self.0.store(level, Ordering::SeqCst);
            Ok(())
        }
    }

    /// The size and the ring addresses of one queue.
    #[derive(Clone, Copy)]
    pub(crate) struct Rings {
        /// The queue size.
        pub(crate) size: u32,
        /// The guest address of the descriptor table.
        pub(crate) desc_table: u64,
        /// The guest address of the avail ring.
        pub(crate) avail_ring: u64,
        /// The guest address of the used ring.
        pub(crate) used_ring: u64,
    }

    /// Returns a queue of up to `max_size` descriptors, programmed at `rings`
    /// and ready, as a transport hands it over at activation.
    pub(crate) fn ready_queue(max_size: u16, rings: Rings, ram: &GuestRam) -> Queue {
        let mut queue = Queue::new(max_size);
        queue.set_num(rings.size);
        queue.set_desc_lo(rings.desc_table as u32);
        queue.set_desc_hi((rings.desc_table >> 32) as u32);
        queue.set_avail_lo(rings.avail_ring as u32);
        queue.set_avail_hi((rings.avail_ring >> 32) as u32);
        queue.set_used_lo(rings.used_ring as u32);
        queue.set_used_hi((rings.used_ring >> 32) as u32);
        queue.set_ready(1, ram);
        assert!(queue.is_ready(), "the rings should fit in guest RAM");
        queue
    }

    /// Returns an enabled interrupt and its line.
    pub(crate) fn enabled_interrupt() -> (Arc<Interrupt>, Arc<LevelLine>) {
        let line = Arc::new(LevelLine::default());
        let interrupt = Arc::new(Interrupt::new(Arc::clone(&line) as Arc<dyn IrqLine>));
        interrupt.enable();
        (interrupt, line)
    }

    /// A guest driver of one device, which programs its transport in the order
    /// Linux's `virtio_mmio` driver does.
    pub(crate) struct Driver<D> {
        /// The transport the driver accesses.
        pub(crate) transport: Transport<D>,
        /// The device behind the transport.
        pub(crate) device: Arc<Mutex<D>>,
        /// The device's line.
        pub(crate) line: Arc<LevelLine>,
    }

    impl<D: virtio::Device> Driver<D> {
        /// Returns a driver of `device`, whose queues are in `ram`.
        pub(crate) fn new(device: D, ram: &Arc<GuestRam>) -> Self {
            let device = Arc::new(Mutex::new(device));
            let line = Arc::new(LevelLine::default());
            let interrupt = Arc::new(Interrupt::new(Arc::clone(&line) as Arc<dyn IrqLine>));
            let ledger = Arc::new(Ledger::new(None, "transport-test").unwrap());
            Self {
                transport: Transport::new(&device, &interrupt, ram, &ledger),
                device,
                line,
            }
        }

        /// Returns a 4-byte read of the register at `offset`.
        pub(crate) fn read(&self, offset: u64) -> u32 {
            let mut data = [0; 4];
            self.transport.read(offset, &mut data);
            u32::from_le_bytes(data)
        }

        /// Writes `value` to the register at `offset`.
        pub(crate) fn write(&self, offset: u64, value: u32) {
            self.transport.write(offset, &value.to_le_bytes());
        }

        /// Sets ACKNOWLEDGE and DRIVER, accepts every feature the device offers
        /// and sets FEATURES_OK.
        pub(crate) fn negotiate(&self) {
            self.write(STATUS, STATUS_STEPS[0]);
            self.write(STATUS, STATUS_STEPS[1]);
            for word in 0..2 {
                self.write(DEVICE_FEATURES_SEL, word);
                let offered = self.read(DEVICE_FEATURES);
                self.write(DRIVER_FEATURES_SEL, word);
                self.write(DRIVER_FEATURES, offered);
            }
            self.write(STATUS, STATUS_STEPS[2]);
        }

        /// Programs queue `index` at `rings`, with READY last.
        pub(crate) fn program_queue(&self, index: u32, rings: Rings) {
            self.write(QUEUE_SEL, index);
            self.write(QUEUE_NUM, rings.size);
            for (low, high, address) in [
                (QUEUE_DESC_LOW, QUEUE_DESC_HIGH, rings.desc_table),
                (QUEUE_DRIVER_LOW, QUEUE_DRIVER_HIGH, rings.avail_ring),
                (QUEUE_DEVICE_LOW, QUEUE_DEVICE_HIGH, rings.used_ring),
            ] {
                self.write(low, address as u32);
                self.write(high, (address >> 32) as u32);
            }
            self.write(QUEUE_READY, 1);
        }

        /// Sets DRIVER_OK, which activates the device.
        pub(crate) fn driver_ok(&self) {
            self.write(STATUS, STATUS_STEPS[3]);
        }

        /// Negotiates, programs each queue at its entry of `queues` and sets
        /// DRIVER_OK.
        pub(crate) fn start(&self, queues: &[Rings]) {
            self.negotiate();
            for (index, rings) in (0u32..).zip(queues) {
                self.program_queue(index, *rings);
            }
            self.driver_ok();
        }

        /// Notifies queue `index`.
        pub(crate) fn notify(&self, index: u32) {
            self.write(QUEUE_NOTIFY, index);
        }

        /// Resets the device.
        pub(crate) fn reset(&self) {
            self.write(STATUS, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Weak;
    use std::time::Duration;

    use super::testing::{Driver, Rings};
    use super::*;
    use crate::devices::bus::Device as _;
    use crate::devices::virtio::{read_config_bytes, DeviceState};
    use crate::events::CapturedEvent;
    use crate::plugin::IoSink;

    const BASE: u64 = 0x4000_0000;
    /// The feature bits the stub offers besides `VIRTIO_F_VERSION_1`, one in
    /// each word.
    const OFFERED: u64 = 1 << 5 | 1 << 35;
    /// Queue 0 of the stub, inside guest RAM.
    const RINGS: Rings = Rings {
        size: 8,
        desc_table: BASE,
        avail_ring: BASE + 0x1000,
        used_ring: BASE + 0x2000,
    };

    /// A sink that counts the batches that end, and how many of them ended with
    /// its device locked.
    struct BatchSink {
        /// The device whose lock each batch end checks.
        device: Weak<Mutex<Stub>>,
        /// The batches that ended.
        batches: AtomicUsize,
        /// The batches that ended with the device locked.
        locked_at_end: AtomicUsize,
    }

    impl IoSink for BatchSink {
        fn on_block(&self, _sector: u64, _length: u64, _disk_id: u64, _write: bool) {}

        fn on_net(&self, _frame: &[u8], _egress: bool) {}

        fn on_batch_end(&self) {
            self.batches.fetch_add(1, Ordering::SeqCst);
            if let Some(device) = self.device.upgrade() {
                if device.try_lock().is_err() {
                    self.locked_at_end.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }

    /// A device with two queues, of 256 and 16 descriptors, that records what
    /// the transport hands it.
    struct Stub {
        /// The queues the stub was last activated with.
        queues: Vec<Queue>,
        /// The features the stub was last activated with.
        driver_features: u64,
        /// The activation state, with the interrupt once active.
        state: DeviceState,
        /// The queues notified, in order.
        notified: Vec<u16>,
        /// Whether activation fails.
        refuse_activation: bool,
        /// The configuration space writes, as offset and data.
        config_writes: Vec<(u64, Vec<u8>)>,
        /// The resets since the stub was built.
        resets: usize,
        /// The sink a notification feeds, when a test set one.
        sink: Option<Arc<BatchSink>>,
        /// The sink fed since the last `take_fed_sink`.
        fed_sink: Option<Arc<dyn IoSink>>,
    }

    impl Stub {
        /// Returns a stub nothing has driven.
        fn new() -> Self {
            Self {
                queues: Vec::new(),
                driver_features: 0,
                state: DeviceState::Inactive,
                notified: Vec::new(),
                refuse_activation: false,
                config_writes: Vec::new(),
                resets: 0,
                sink: None,
                fed_sink: None,
            }
        }
    }

    impl virtio::Device for Stub {
        fn device_type(&self) -> u32 {
            42
        }

        fn features(&self) -> u64 {
            OFFERED
        }

        fn queue_max_sizes(&self) -> &[u16] {
            &[256, 16]
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            read_config_bytes(b"configuration", offset, data);
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            self.config_writes.push((offset, data.to_vec()));
        }

        fn activate(
            &mut self,
            _ram: &GuestRam,
            driver_features: u64,
            queues: Vec<Queue>,
            interrupt: Arc<Interrupt>,
        ) -> io::Result<()> {
            if self.refuse_activation {
                return Err(io::Error::other("stub: activating: refused"));
            }
            self.queues = queues;
            self.driver_features = driver_features;
            self.state = DeviceState::Active(interrupt);
            Ok(())
        }

        // A notification completes a buffer and feeds the sink, as a served
        // request does.
        fn notify(&mut self, _ram: &GuestRam, queue: u16) {
            self.notified.push(queue);
            self.state.signal_used_buffer();
            if let Some(sink) = &self.sink {
                sink.on_block(0, 512, 0, false);
                self.fed_sink = Some(Arc::clone(sink) as Arc<dyn IoSink>);
            }
        }

        fn reset(&mut self) {
            self.resets += 1;
            self.queues.clear();
            self.state = DeviceState::Inactive;
        }

        fn take_events(&mut self) -> Vec<CapturedEvent> {
            Vec::new()
        }

        fn take_fed_sink(&mut self) -> Option<Arc<dyn IoSink>> {
            self.fed_sink.take()
        }
    }

    /// Returns a driver of a fresh stub, in 16 KiB of guest RAM.
    fn driver() -> Driver<Stub> {
        let ram = Arc::new(GuestRam::from_ranges(&[(BASE, 0x4000)]));
        Driver::new(Stub::new(), &ram)
    }

    #[test]
    fn probe_registers_identify_the_device() {
        let driver = driver();
        assert_eq!(&driver.read(MAGIC).to_le_bytes(), b"virt");
        assert_eq!(driver.read(VERSION), 2);
        assert_eq!(driver.read(DEVICE_ID), 42);
        assert_eq!(&driver.read(VENDOR_ID).to_le_bytes(), b"NOIF");
    }

    // virtio 1.2 section 4.2.2: word `sel` carries bits `sel * 32` to `sel * 32
    // + 31`.
    #[test]
    fn device_features_carry_version_1_and_read_zero_past_word_1() {
        let driver = driver();
        let words: Vec<u32> = (0..4)
            .map(|word| {
                driver.write(DEVICE_FEATURES_SEL, word);
                driver.read(DEVICE_FEATURES)
            })
            .collect();
        assert_eq!(words, [1 << 5, 1 << 3 | 1, 0, 0]);
    }

    #[test]
    fn driver_features_are_masked_by_the_offer_and_replaced_per_word() {
        let driver = driver();
        driver.write(STATUS, STATUS_STEPS[0]);
        driver.write(STATUS, STATUS_STEPS[1]);
        driver.write(DRIVER_FEATURES_SEL, 0);
        driver.write(DRIVER_FEATURES, u32::MAX);
        driver.write(DRIVER_FEATURES_SEL, 1);
        driver.write(DRIVER_FEATURES, 1 << 3 | 1);
        driver.write(DRIVER_FEATURES, 1);
        driver.write(DRIVER_FEATURES_SEL, 2);
        driver.write(DRIVER_FEATURES, 0);
        driver.write(STATUS, STATUS_STEPS[2]);
        driver.driver_ok();
        assert_eq!(
            driver.device.lock().unwrap().driver_features,
            1 << 5 | F_VERSION_1
        );
    }

    #[test]
    fn driver_features_outside_driver_and_features_ok_are_ignored() {
        let driver = driver();
        driver.write(DRIVER_FEATURES_SEL, 1);
        driver.write(DRIVER_FEATURES, 1);
        driver.write(STATUS, STATUS_STEPS[0]);
        driver.write(STATUS, STATUS_STEPS[1]);
        driver.write(STATUS, STATUS_STEPS[2]);
        assert_eq!(
            driver.read(STATUS),
            STATUS_STEPS[1],
            "VIRTIO_F_VERSION_1 written before DRIVER was not taken"
        );
        driver.write(DRIVER_FEATURES, 1);
        driver.write(STATUS, STATUS_STEPS[2]);
        driver.write(DRIVER_FEATURES_SEL, 0);
        driver.write(DRIVER_FEATURES, 1 << 5);
        driver.driver_ok();
        assert_eq!(driver.device.lock().unwrap().driver_features, F_VERSION_1);
    }

    #[test]
    fn features_ok_is_refused_without_version_1() {
        let driver = driver();
        driver.write(STATUS, STATUS_STEPS[0]);
        driver.write(STATUS, STATUS_STEPS[1]);
        driver.write(DRIVER_FEATURES_SEL, 0);
        driver.write(DRIVER_FEATURES, 1 << 5);
        driver.write(STATUS, STATUS_STEPS[2]);
        assert_eq!(driver.read(STATUS), STATUS_STEPS[1]);
    }

    #[test]
    fn status_steps_out_of_order_are_ignored() {
        let driver = driver();
        driver.write(STATUS, STATUS_STEPS[1]);
        assert_eq!(driver.read(STATUS), 0, "DRIVER before ACKNOWLEDGE");
        driver.write(STATUS, STATUS_STEPS[0]);
        driver.write(STATUS, STATUS_STEPS[2]);
        assert_eq!(
            driver.read(STATUS),
            STATUS_STEPS[0],
            "FEATURES_OK before DRIVER"
        );
        driver.write(STATUS, STATUS_STEPS[1]);
        driver.write(STATUS, STATUS_STEPS[3]);
        assert_eq!(
            driver.read(STATUS),
            STATUS_STEPS[1],
            "DRIVER_OK before FEATURES_OK"
        );
        assert!(!driver.device.lock().unwrap().state.is_active());
    }

    #[test]
    fn failed_is_taken_in_any_status() {
        let driver = driver();
        driver.write(STATUS, STATUS_STEPS[0]);
        driver.write(STATUS, FAILED);
        assert_eq!(driver.read(STATUS), STATUS_STEPS[0] | FAILED);
        driver.write(STATUS, STATUS_STEPS[1]);
        assert_eq!(
            driver.read(STATUS),
            STATUS_STEPS[0] | FAILED,
            "no step after FAILED"
        );
    }

    #[test]
    fn reset_after_failed_lets_the_device_start_again() {
        let driver = driver();
        driver.start(&[RINGS]);
        driver.write(STATUS, STATUS_STEPS[3] | FAILED);
        assert_eq!(driver.read(STATUS), STATUS_STEPS[3] | FAILED);
        driver.reset();
        assert_eq!(driver.read(STATUS), 0, "a reset clears FAILED");
        driver.start(&[RINGS]);
        assert_eq!(driver.read(STATUS), STATUS_STEPS[3]);
        let device = driver.device.lock().unwrap();
        assert!(device.state.is_active());
        assert_eq!(device.resets, 1);
        assert_eq!(device.queues.len(), 2);
    }

    #[test]
    fn queue_num_max_reads_the_largest_size_of_each_queue() {
        let driver = driver();
        let sizes: Vec<u32> = (0..3)
            .map(|queue| {
                driver.write(QUEUE_SEL, queue);
                driver.read(QUEUE_NUM_MAX)
            })
            .collect();
        assert_eq!(sizes, [256, 16, 0], "a missing queue reads 0");
    }

    // virtio 1.2 section 4.2.2: `QUEUE_READY` reads the last value written.
    #[test]
    fn queue_registers_read_back_after_driver_ok() {
        let driver = driver();
        driver.start(&[RINGS]);
        let read = |queue: u32| {
            driver.write(QUEUE_SEL, queue);
            (driver.read(QUEUE_NUM_MAX), driver.read(QUEUE_READY))
        };
        assert_eq!([read(0), read(1), read(2)], [(256, 1), (16, 0), (0, 0)]);
        driver.reset();
        assert_eq!(read(0), (256, 0), "a reset clears READY");
    }

    // Linux `vm_setup_vq` refuses a queue whose `QUEUE_READY` reads non-zero.
    #[test]
    fn missing_queue_reads_not_ready_and_takes_no_write() {
        let driver = driver();
        driver.negotiate();
        driver.program_queue(0, RINGS);
        driver.write(QUEUE_SEL, 2);
        assert_eq!(driver.read(QUEUE_READY), 0);
        driver.write(QUEUE_NUM, 8);
        driver.write(QUEUE_SEL, 0);
        assert_eq!(driver.read(QUEUE_READY), 1, "queue 0 kept its programming");
    }

    #[test]
    fn queue_writes_before_features_ok_are_ignored() {
        let driver = driver();
        driver.write(STATUS, STATUS_STEPS[0]);
        driver.write(STATUS, STATUS_STEPS[1]);
        driver.program_queue(0, RINGS);
        assert_eq!(driver.read(QUEUE_READY), 0);
    }

    // 0x10000 is non-zero as a u32 and zero as a u16. Taken as the size, it
    // would make a notification divide by zero.
    #[test]
    fn queue_size_past_the_largest_is_refused() {
        let driver = driver();
        driver.negotiate();
        for (queue, size) in [(0, 0x10000), (0, 512), (0, 3), (1, 32)] {
            driver.program_queue(queue, Rings { size, ..RINGS });
            assert_eq!(driver.read(QUEUE_READY), 0, "queue {queue} size {size}");
        }
        driver.program_queue(1, Rings { size: 16, ..RINGS });
        assert_eq!(driver.read(QUEUE_READY), 1);
    }

    // A descriptor table of 256 entries is 4 KiB, so the first runs off the end
    // of guest RAM, and the second starts below its base.
    #[test]
    fn rings_outside_guest_ram_are_refused() {
        let driver = driver();
        driver.negotiate();
        for desc_table in [BASE + 0x3800, BASE - 0x1000] {
            driver.program_queue(
                0,
                Rings {
                    size: 256,
                    desc_table,
                    ..RINGS
                },
            );
            assert_eq!(
                driver.read(QUEUE_READY),
                0,
                "descriptor table at {desc_table:#x}"
            );
        }
        driver.program_queue(0, Rings { size: 256, ..RINGS });
        assert_eq!(driver.read(QUEUE_READY), 1);
    }

    // Every write that feeds the bounds check clears READY, so a driver cannot
    // pass the check on one set of addresses and be served on another. Each
    // value is one the register accepts. The QUEUE_NUM value is non-zero,
    // because a queue of size 0 reads not ready even with READY set.
    #[test]
    fn reprogramming_a_ready_queue_clears_ready() {
        for (register, value) in [
            (QUEUE_NUM, 128),
            (QUEUE_DESC_LOW, 0),
            (QUEUE_DESC_HIGH, 0),
            (QUEUE_DRIVER_LOW, 0),
            (QUEUE_DRIVER_HIGH, 0),
            (QUEUE_DEVICE_LOW, 0),
            (QUEUE_DEVICE_HIGH, 0),
        ] {
            let driver = driver();
            driver.negotiate();
            driver.program_queue(0, RINGS);
            driver.write(register, value);
            assert_eq!(
                driver.read(QUEUE_READY),
                0,
                "writing {register:#05x} clears READY"
            );
        }
    }

    #[test]
    fn activation_hands_the_device_its_queues() {
        let driver = driver();
        driver.start(&[RINGS]);
        assert_eq!(driver.read(STATUS), STATUS_STEPS[3]);
        let device = driver.device.lock().unwrap();
        assert!(device.state.is_active());
        let ready: Vec<bool> = device.queues.iter().map(Queue::is_ready).collect();
        assert_eq!(ready, [true, false]);
    }

    #[test]
    fn notify_before_driver_ok_is_replayed_at_activation() {
        let driver = driver();
        driver.negotiate();
        driver.program_queue(0, RINGS);
        driver.notify(0);
        assert!(driver.device.lock().unwrap().notified.is_empty());
        driver.driver_ok();
        assert_eq!(driver.device.lock().unwrap().notified, [0]);
    }

    #[test]
    fn notify_of_a_missing_queue_is_dropped() {
        let driver = driver();
        driver.start(&[RINGS]);
        driver.device.lock().unwrap().notified.clear();
        driver.notify(2);
        driver.notify(0x1_0001);
        driver.notify(1);
        assert_eq!(driver.device.lock().unwrap().notified, [1]);
    }

    #[test]
    fn refused_activation_needs_a_reset() {
        let driver = driver();
        driver.device.lock().unwrap().refuse_activation = true;
        driver.start(&[RINGS]);
        assert_eq!(driver.read(STATUS), STATUS_STEPS[2] | NEEDS_RESET);
        assert_eq!(driver.read(INTERRUPT_STATUS), VIRTIO_MMIO_INT_CONFIG);
        assert_eq!(driver.read(CONFIG_GENERATION), 1);
        assert!(driver.line.is_high());

        driver.device.lock().unwrap().refuse_activation = false;
        driver.driver_ok();
        driver.notify(0);
        assert!(!driver.device.lock().unwrap().state.is_active());
        assert!(driver.device.lock().unwrap().notified.is_empty());

        driver.reset();
        driver.start(&[RINGS]);
        assert_eq!(
            driver.read(STATUS),
            STATUS_STEPS[3],
            "a reset clears NEEDS_RESET"
        );
    }

    #[test]
    fn reset_clears_the_device_and_keeps_the_generation() {
        let driver = driver();
        driver.write(DEVICE_FEATURES_SEL, 1);
        driver.start(&[RINGS]);
        driver.transport.interrupt.signal_config_change();
        assert!(driver.line.is_high());

        driver.reset();
        assert_eq!(driver.read(STATUS), 0);
        assert_eq!(driver.read(INTERRUPT_STATUS), 0);
        assert!(!driver.line.is_high());
        assert_eq!(driver.read(CONFIG_GENERATION), 1);
        assert_eq!(driver.read(DEVICE_FEATURES), 1 << 5, "word 0 is selected");
        driver.write(QUEUE_SEL, 0);
        assert_eq!(driver.read(QUEUE_READY), 0);
        assert_eq!(driver.device.lock().unwrap().resets, 1);
        assert!(!driver.device.lock().unwrap().state.is_active());
    }

    #[test]
    fn acknowledgment_lowers_the_line_once_no_bit_is_left() {
        let driver = driver();
        driver.start(&[RINGS]);
        driver.transport.interrupt.signal_config_change();
        assert_eq!(
            driver.read(INTERRUPT_STATUS),
            VIRTIO_MMIO_INT_VRING | VIRTIO_MMIO_INT_CONFIG,
            "the replayed notify and the configuration change"
        );
        driver.write(INTERRUPT_ACK, VIRTIO_MMIO_INT_VRING);
        assert!(driver.line.is_high());
        driver.write(INTERRUPT_ACK, VIRTIO_MMIO_INT_CONFIG);
        assert!(!driver.line.is_high());
        assert_eq!(driver.read(INTERRUPT_STATUS), 0);
    }

    #[test]
    fn interrupt_before_driver_ok_is_dropped() {
        let driver = driver();
        driver.transport.interrupt.signal_used_buffer();
        driver.transport.interrupt.signal_config_change();
        assert_eq!(driver.read(INTERRUPT_STATUS), 0);
        assert!(!driver.line.is_high());
        assert_eq!(driver.read(CONFIG_GENERATION), 1, "the change is counted");
    }

    #[test]
    fn interrupt_status_is_served_while_the_device_is_held() {
        let driver = driver();
        driver.start(&[RINGS]);
        let held = driver.device.lock().unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let status = driver.read(INTERRUPT_STATUS);
                driver.write(INTERRUPT_ACK, status);
                done.send(status).unwrap();
            });
            let status = finished.recv_timeout(Duration::from_secs(5));
            drop(held);
            assert_eq!(status, Ok(VIRTIO_MMIO_INT_VRING));
        });
        assert!(!driver.line.is_high());
    }

    #[test]
    fn configuration_space_takes_any_width_and_writes_after_driver() {
        let driver = driver();
        let mut byte = [0; 1];
        driver.transport.read(CONFIG + 1, &mut byte);
        assert_eq!(&byte, b"o");
        let mut past = [0xff; 2];
        driver.transport.read(CONFIG + 12, &mut past);
        assert_eq!(&past, b"n\0");

        driver.transport.write(CONFIG, &[1]);
        driver.write(STATUS, STATUS_STEPS[0]);
        driver.write(STATUS, STATUS_STEPS[1]);
        driver.transport.write(CONFIG + 4, &[2, 3]);
        assert_eq!(
            driver.device.lock().unwrap().config_writes,
            [(4, vec![2, 3])]
        );
    }

    #[test]
    fn common_register_access_of_another_width_is_ignored() {
        let driver = driver();
        let mut half = [0xff; 2];
        driver.transport.read(MAGIC, &mut half);
        assert_eq!(half, [0, 0]);
        driver.transport.write(STATUS, &[1, 0]);
        assert_eq!(driver.read(STATUS), 0);
    }

    // Linux `vm_get_shm_region` selects a region and reads its length and base.
    #[test]
    fn shm_registers_report_no_region() {
        let driver = driver();
        driver.write(u64::from(VIRTIO_MMIO_SHM_SEL), 0);
        let registers = [SHM_LEN_LOW, SHM_LEN_HIGH, SHM_BASE_LOW, SHM_BASE_HIGH];
        let read: Vec<u32> = registers
            .iter()
            .map(|&register| driver.read(register))
            .collect();
        assert_eq!(read, [u32::MAX; 4]);
    }

    #[test]
    fn notify_that_feeds_the_sink_ends_one_batch_with_the_device_unlocked() {
        let driver = driver();
        let sink = Arc::new(BatchSink {
            device: Arc::downgrade(&driver.device),
            batches: AtomicUsize::new(0),
            locked_at_end: AtomicUsize::new(0),
        });
        driver.device.lock().unwrap().sink = Some(Arc::clone(&sink));
        driver.start(&[RINGS]);
        driver.notify(0);
        assert_eq!(
            sink.batches.load(Ordering::SeqCst),
            2,
            "the replay and the notify"
        );
        assert_eq!(sink.locked_at_end.load(Ordering::SeqCst), 0);
        driver.read(INTERRUPT_STATUS);
        assert_eq!(
            sink.batches.load(Ordering::SeqCst),
            2,
            "a read feeds nothing"
        );
    }
}

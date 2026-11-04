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

//! The virtio devices over MMIO, and the split virtqueue they share.
//!
//! `block`, `fs`, `net` and `vsock` are the devices, and they serve their
//! queues through `Queue`, which `queue` holds. `mmio` holds the virtio-mmio
//! transport, which decodes the common registers of a `Device` and hands it its
//! queues at activation. A device the transport does not serve decodes its own
//! registers with the offsets in `mmio`, and `MmioTransport` puts it on a bus.
//! `tap` attaches virtio-net to a host tap device and holds the
//! `virtio_net_hdr_v1` framing every tap read and write carries.

pub mod block;
pub mod fs;
pub(crate) mod mmio;
pub mod net;
mod queue;
pub mod tap;
pub mod vsock;

use std::io;
use std::sync::{Arc, Mutex};
use std::task::Waker;

use mmio::Interrupt;
use queue::{Queue, QUEUE_MAX_SIZE, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

use crate::config::Stop;
use crate::devices::bus::{self, fill_le_bytes, u64_from_le_bytes};
use crate::devices::irq::IrqLine;
use crate::events::{CapturedEvent, Ledger};
use crate::memory::GuestRam;
use crate::plugin::IoSink;
use vsock::VirtioVsock;

/// A virtio device that [`mmio::Transport`] serves.
///
/// [`activate`](Self::activate) runs when the driver sets DRIVER_OK, and
/// [`notify`](Self::notify) runs only after a successful activation.
/// [`device_type`](Self::device_type), [`features`](Self::features) and
/// [`queue_max_sizes`](Self::queue_max_sizes) return the same value on every
/// call.
///
/// A device captures I/O only in [`notify`](Self::notify). A device thread that
/// feeds the sink outside `notify` ends the batch itself.
pub(crate) trait Device: Send {
    /// Returns the device type, a `VIRTIO_ID_*` value.
    fn device_type(&self) -> u32;

    /// Returns the feature bits the device offers, which need not include
    /// `VIRTIO_F_VERSION_1`.
    fn features(&self) -> u64;

    /// Returns whether the device supports `driver_features`, the features the
    /// driver accepted.
    ///
    /// `driver_features` holds only bits of [`features`](Self::features) and
    /// `VIRTIO_F_VERSION_1`.
    fn accepts_features(&self, _driver_features: u64) -> bool {
        true
    }

    /// Returns the largest size of each of the device's queues, in queue order.
    fn queue_max_sizes(&self) -> &[u16];

    /// Fills `data` from the configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Applies a write of `data` to the configuration space at `offset`.
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    /// Starts serving `queues`, one per entry of
    /// [`queue_max_sizes`](Self::queue_max_sizes).
    ///
    /// `driver_features` holds the features the driver accepted. The device
    /// signals its notifications through `interrupt`. `queues` includes any
    /// queue the driver did not make ready.
    ///
    /// # Errors
    ///
    /// Errors when the device cannot serve the queues. The error names the
    /// device. A device that fails partway undoes what it started.
    fn activate(
        &mut self,
        ram: &GuestRam,
        driver_features: u64,
        queues: Vec<Queue>,
        interrupt: Arc<Interrupt>,
    ) -> io::Result<()>;

    /// Serves a notification of `queue`, an index into
    /// [`queue_max_sizes`](Self::queue_max_sizes).
    ///
    /// A [`reset`](Self::reset) on another vCPU can run just before this call,
    /// so the device serves the queue only while it is active.
    fn notify(&mut self, ram: &GuestRam, queue: u16);

    /// Resets the device to the state it was built in.
    fn reset(&mut self);

    /// Returns the I/O the device captured since the last call.
    fn take_events(&mut self) -> Vec<CapturedEvent> {
        Vec::new()
    }

    /// Returns the sink the device fed since the last call, or `None` when it
    /// fed none.
    fn take_fed_sink(&mut self) -> Option<Arc<dyn IoSink>> {
        None
    }

    /// Returns the waker of the thread the device left queue work to since the
    /// last call, or `None` when it left none.
    ///
    /// [`notify`](Self::notify) runs with the device locked. A thread woken
    /// there would start by waiting for that lock, so the device returns its
    /// waker here instead.
    fn take_pending_wake(&mut self) -> Option<Waker> {
        None
    }
}

/// The activation state of a device, with the interrupt it raises while active.
pub(crate) enum DeviceState {
    /// The state from build or reset until a successful activation.
    Inactive,
    /// The state after a successful activation, with the interrupt the device
    /// raises.
    Active(Arc<Interrupt>),
}

impl DeviceState {
    /// Returns whether the device serves its queues.
    pub(crate) fn is_active(&self) -> bool {
        matches!(self, Self::Active(_))
    }

    /// Raises a used-buffer notification, when the device is active.
    pub(crate) fn signal_used_buffer(&self) {
        if let Self::Active(interrupt) = self {
            interrupt.signal_used_buffer();
        }
    }

    /// Returns whether the device has a notification pending.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn is_raised(&self) -> bool {
        matches!(self, Self::Active(interrupt) if interrupt.is_raised())
    }
}

/// Fills `data` from the bytes of `config` at `offset`, and with zeros past the
/// end of `config`.
pub(crate) fn read_config_bytes(config: &[u8], offset: u64, data: &mut [u8]) {
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = start
            .checked_add(i)
            .and_then(|index| config.get(index))
            .copied()
            .unwrap_or(0);
    }
}

/// The registers of a virtio device, and what an access left for the
/// ledger and for the device's sink.
pub(crate) trait VirtioMmio {
    /// Serves one access to register `offset` and returns the value read, or 0
    /// for a write.
    fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64;

    /// Returns the I/O the device captured since the last call.
    fn take_events(&mut self) -> Vec<CapturedEvent>;

    /// Returns the sink the device fed since the last call, or `None` when it
    /// fed none.
    fn take_fed_sink(&mut self) -> Option<Arc<dyn IoSink>>;

    /// Connects the device to the interrupt line it drives.
    fn connect_irq(&mut self, line: Arc<dyn IrqLine>);
}

/// A virtio device as a bus reaches it, with what a register access needs
/// beyond the device.
pub(crate) struct MmioTransport<D> {
    /// The device.
    device: Arc<Mutex<D>>,
    /// The guest RAM its queues are in.
    ram: Arc<GuestRam>,
    /// The ledger the events it captures go to.
    ledger: Arc<Ledger>,
}

impl<D> MmioTransport<D> {
    /// Returns the transport of `device`.
    pub(crate) fn new(device: &Arc<Mutex<D>>, ram: &Arc<GuestRam>, ledger: &Arc<Ledger>) -> Self {
        Self {
            device: Arc::clone(device),
            ram: Arc::clone(ram),
            ledger: Arc::clone(ledger),
        }
    }
}

impl<D: VirtioMmio> MmioTransport<D> {
    /// Serves one access to register `offset` and returns the value read, or 0
    /// for a write.
    ///
    /// Once the device lock is released, the batch of the sink the access fed
    /// ends, and then the events the device captured go to the ledger. The
    /// batch ends first, so a reader that waits on the sink does not also wait
    /// for the ledger.
    fn access(&self, offset: u64, is_write: bool, value: u64) -> u64 {
        let (read, events, sink) = {
            let mut device = self.device.lock().unwrap();
            let read = device.mmio(&self.ram, offset, is_write, value);
            (read, device.take_events(), device.take_fed_sink())
        };
        if let Some(sink) = sink {
            sink.on_batch_end();
        }
        self.ledger.captured(&events);
        read
    }
}

impl<D: VirtioMmio + Send> bus::Device for MmioTransport<D> {
    fn read(&self, offset: u64, data: &mut [u8]) {
        fill_le_bytes(data, self.access(offset, false, 0));
    }

    fn write(&self, offset: u64, data: &[u8]) -> Option<Stop> {
        self.access(offset, true, u64_from_le_bytes(data));
        None
    }
}

/// A device's sink, and the sink it fed since its batch last ended.
#[derive(Default)]
pub(crate) struct SinkSlot {
    /// The sink each record goes to, when a plugin installed one.
    sink: Option<Arc<dyn IoSink>>,
    /// The sink fed since the last [`SinkSlot::take_fed`].
    fed: Option<Arc<dyn IoSink>>,
}

impl SinkSlot {
    /// Sends the records that follow to `sink`.
    pub(crate) fn set(&mut self, sink: Arc<dyn IoSink>) {
        self.sink = Some(sink);
    }

    /// Hands the sink, when there is one, to `record`.
    ///
    /// The sink then counts as fed until the next [`SinkSlot::take_fed`].
    pub(crate) fn feed(&mut self, record: impl FnOnce(&dyn IoSink)) {
        if let Some(sink) = &self.sink {
            record(sink.as_ref());
            self.fed.get_or_insert_with(|| Arc::clone(sink));
        }
    }

    /// Returns the sink fed since the last call, or `None` when none was.
    pub(crate) fn take_fed(&mut self) -> Option<Arc<dyn IoSink>> {
        self.fed.take()
    }
}

impl VirtioMmio for VirtioVsock {
    fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        VirtioVsock::mmio(self, mem, offset, is_write, value)
    }

    fn take_events(&mut self) -> Vec<CapturedEvent> {
        Vec::new()
    }

    fn take_fed_sink(&mut self) -> Option<Arc<dyn IoSink>> {
        None
    }

    fn connect_irq(&mut self, line: Arc<dyn IrqLine>) {
        VirtioVsock::connect_irq(self, line);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Weak;

    use super::*;
    use crate::devices::bus::Device as _;

    /// A sink that counts the batches that end, and records whether its device
    /// was locked at the end of each.
    struct BatchSink {
        device: Weak<Mutex<FeedingDevice>>,
        batches: AtomicUsize,
        locked_at_end: AtomicBool,
    }

    impl IoSink for BatchSink {
        fn on_block(&self, _sector: u64, _length: u64, _disk_id: u64, _write: bool) {}

        fn on_net(&self, _frame: &[u8], _egress: bool) {}

        fn on_batch_end(&self) {
            self.batches.fetch_add(1, Ordering::SeqCst);
            let locked = self
                .device
                .upgrade()
                .is_some_and(|device| device.try_lock().is_err());
            self.locked_at_end.fetch_or(locked, Ordering::SeqCst);
        }
    }

    /// A device whose every register write feeds its sink three requests, as a
    /// queue notify with three requests on the queue does, and whose reads feed
    /// nothing.
    struct FeedingDevice {
        sink: Arc<BatchSink>,
        fed_sink: Option<Arc<dyn IoSink>>,
    }

    impl VirtioMmio for FeedingDevice {
        fn mmio(&mut self, _mem: &GuestRam, _offset: u64, is_write: bool, _value: u64) -> u64 {
            if is_write {
                for sector in 0..3 {
                    self.sink.on_block(sector, 512, 0, false);
                }
                self.fed_sink = Some(Arc::clone(&self.sink) as Arc<dyn IoSink>);
            }
            0
        }

        fn take_events(&mut self) -> Vec<CapturedEvent> {
            Vec::new()
        }

        fn take_fed_sink(&mut self) -> Option<Arc<dyn IoSink>> {
            self.fed_sink.take()
        }

        fn connect_irq(&mut self, _line: Arc<dyn IrqLine>) {}
    }

    /// Returns the transport of a device that feeds a fresh `BatchSink`, and
    /// that sink.
    fn feeding_transport() -> (MmioTransport<FeedingDevice>, Arc<BatchSink>) {
        let device = Arc::new_cyclic(|device| {
            Mutex::new(FeedingDevice {
                sink: Arc::new(BatchSink {
                    device: device.clone(),
                    batches: AtomicUsize::new(0),
                    locked_at_end: AtomicBool::new(false),
                }),
                fed_sink: None,
            })
        });
        let sink = Arc::clone(&device.lock().unwrap().sink);
        let transport = MmioTransport::new(
            &device,
            &Arc::new(GuestRam::from_ranges(&[(0, 0x1000)])),
            &Arc::new(Ledger::new(None, "test").unwrap()),
        );
        (transport, sink)
    }

    #[test]
    fn access_that_feeds_the_sink_ends_one_batch_with_the_device_unlocked() {
        let (transport, sink) = feeding_transport();
        transport.write(0, &[0; 4]);
        assert_eq!(
            sink.batches.load(Ordering::SeqCst),
            1,
            "one batch per access"
        );
        assert!(!sink.locked_at_end.load(Ordering::SeqCst));
    }

    #[test]
    fn access_that_feeds_no_sink_ends_no_batch() {
        let (transport, sink) = feeding_transport();
        transport.read(0, &mut [0; 4]);
        assert_eq!(sink.batches.load(Ordering::SeqCst), 0);
    }
}

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
//! `block`, `fs`, `net` and `vsock` are the devices. They serve their queues
//! through `Queue` and walk each chain as a `DescriptorChain`, both from
//! `queue`. `mmio` holds the virtio-mmio transport that serves a `Device` to
//! the guest, and records each queue's programming as a `QueueConfig`. `tap`
//! attaches virtio-net to a host tap device and holds the `virtio_net_hdr_v1`
//! framing every tap read and write carries.

pub mod block;
pub mod fs;
pub(crate) mod mmio;
pub mod net;
mod queue;
pub mod tap;
pub mod vsock;

use std::io;
use std::sync::Arc;
use std::task::Waker;

use mmio::Interrupt;
use queue::{DescriptorChain, Queue, QueueConfig, QUEUE_MAX_SIZE};
#[cfg(test)]
use queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

use crate::events::CapturedEvent;
use crate::memory::GuestRam;
use crate::plugin::IoSink;

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
        queues: Vec<QueueConfig>,
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

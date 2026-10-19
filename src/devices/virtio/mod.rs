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
//! `block`, `fs`, `net` and `vsock` are the devices. Each decodes
//! its own register window with the offsets in `mmio` and serves its queues
//! through `Queue`, which `queue` holds. `tap` attaches virtio-net to a host
//! tap device and holds the `virtio_net_hdr_v1` framing every tap read and
//! write carries.

pub mod block;
pub mod fs;
pub(crate) mod mmio;
pub mod net;
mod queue;
pub mod tap;
pub mod vsock;

use std::sync::Arc;

use queue::{Queue, QUEUE_NUM_MAX, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

use crate::events::CapturedEvent;
use crate::memory::GuestRam;
use crate::plugin::IoSink;
use block::VirtioBlk;
use net::VirtioNet;
use vsock::VirtioVsock;

/// The register window of a virtio device, and what an access left for the
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

impl VirtioMmio for VirtioBlk {
    fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        VirtioBlk::mmio(self, mem, offset, is_write, value)
    }

    fn take_events(&mut self) -> Vec<CapturedEvent> {
        VirtioBlk::take_events(self)
    }

    fn take_fed_sink(&mut self) -> Option<Arc<dyn IoSink>> {
        VirtioBlk::take_fed_sink(self)
    }
}

impl VirtioMmio for VirtioNet {
    fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        VirtioNet::mmio(self, mem, offset, is_write, value)
    }

    fn take_events(&mut self) -> Vec<CapturedEvent> {
        VirtioNet::take_events(self)
    }

    fn take_fed_sink(&mut self) -> Option<Arc<dyn IoSink>> {
        VirtioNet::take_fed_sink(self)
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
}

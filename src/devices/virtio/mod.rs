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

use queue::{Queue, QUEUE_NUM_MAX, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

use crate::events::CapturedEvent;
use crate::memory::GuestRam;
use block::VirtioBlk;
use net::VirtioNet;
use vsock::VirtioVsock;

/// The register window of a virtio device, and the I/O an access left for the
/// ledger.
pub(crate) trait VirtioMmio {
    /// Serves one access to register `offset` and returns the value read, or 0
    /// for a write.
    fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64;

    /// Returns the I/O the device captured since the last call.
    fn take_events(&mut self) -> Vec<CapturedEvent>;
}

impl VirtioMmio for VirtioBlk {
    fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        VirtioBlk::mmio(self, mem, offset, is_write, value)
    }

    fn take_events(&mut self) -> Vec<CapturedEvent> {
        VirtioBlk::take_events(self)
    }
}

impl VirtioMmio for VirtioNet {
    fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        VirtioNet::mmio(self, mem, offset, is_write, value)
    }

    fn take_events(&mut self) -> Vec<CapturedEvent> {
        VirtioNet::take_events(self)
    }
}

impl VirtioMmio for VirtioVsock {
    fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        VirtioVsock::mmio(self, mem, offset, is_write, value)
    }

    fn take_events(&mut self) -> Vec<CapturedEvent> {
        Vec::new()
    }
}

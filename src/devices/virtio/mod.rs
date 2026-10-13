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
//! `block`, `net`, `vsock` and, on macOS, `fs` are the devices. Each decodes
//! its own register window with the offsets in `mmio` and serves its queues
//! through `Queue`, which `queue` holds. `tap` attaches virtio-net to a host
//! tap device and holds the `virtio_net_hdr_v1` framing every tap read and
//! write carries. [`VirtioCommonState`] and [`QueueState`] are what a
//! checkpoint keeps of the transport every device shares.

pub mod block;
#[cfg(target_os = "macos")]
pub mod fs;
pub(crate) mod mmio;
pub mod net;
mod queue;
pub mod tap;
pub mod vsock;

pub use queue::QueueState;
use queue::{Queue, QUEUE_NUM_MAX, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

use serde::{Deserialize, Serialize};

use crate::devices::state::invalid;

/// The interrupt status bit every device here sets: a buffer was used. None of
/// them changes its configuration, so none sets the configuration-change bit.
const INT_USED_BUFFER: u32 = 1;

/// The transport registers a virtio-mmio device keeps, as a checkpoint keeps
/// them.
///
/// The driver's feature words are not among them: every device here ignores
/// writes to them and advertises constant features, so a restore on the same
/// build offers the guest what it negotiated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VirtioCommonState {
    /// The device status the driver last wrote.
    pub status: u32,
    /// The device feature word the driver selected.
    pub dev_feat_sel: u32,
    /// The queue the driver selected.
    pub queue_sel: u32,
    /// The interrupt bits the driver has not acknowledged.
    pub interrupt_status: u32,
}

impl VirtioCommonState {
    /// Refuses interrupt bits no device here sets.
    ///
    /// The line level is `interrupt_status != 0`, so a stray bit would hold
    /// the line high over an interrupt the driver finds no reason for and
    /// cannot acknowledge away by the bits it knows.
    ///
    /// # Errors
    ///
    /// Errors when a bit other than the used-buffer bit is set.
    fn check(&self, device: &str) -> std::io::Result<()> {
        if self.interrupt_status & !INT_USED_BUFFER != 0 {
            return Err(invalid(format_args!(
                "{device} interrupt status {:#x} has bits the device never sets",
                self.interrupt_status
            )));
        }
        Ok(())
    }
}

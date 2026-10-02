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
//! `net`, `vsock` and, on macOS, `fs` are devices. `queue` holds the split
//! virtqueue, the virtio-mmio register offsets and virtio-blk. Each device
//! decodes its own register window and serves its queues through `Queue`. `tap`
//! attaches virtio-net to a host tap device and holds the `virtio_net_hdr_v1`
//! framing every tap read and write carries.

#[cfg(target_os = "macos")]
pub mod fs;
pub mod net;
pub mod queue;
pub mod tap;
#[cfg(test)]
mod used_ring_litmus;
pub mod vsock;

pub(crate) use queue::{reg, Queue, QUEUE_NUM_MAX, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

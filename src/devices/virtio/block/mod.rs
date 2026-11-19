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

//! A virtio-blk device over virtio-mmio, and the worker thread that serves it.
//!
//! Because this VMM implements the device backend, every block request the
//! guest issues passes through its code. Serving the virtqueue therefore also
//! captures the guest's disk I/O, which the `[virtio-blk]` console lines show
//! when `HVI_BLK_TRACE` is set.
//!
//! Each disk has one queue, which a worker thread of its own serves. The
//! [`VirtioBlk`] behind the transport holds what the registers read, and a
//! notification only wakes the worker. The two share the queue, its interrupt
//! and the sink behind one lock, which is never held across a call to the
//! backing file. The worker takes a request off the ring under the lock, makes
//! its call with no lock held, and completes it under the lock, unless a reset
//! took the queue in between. One worker serves the requests in the order the
//! ring holds them.
//!
//! A read or a write moves its data between the backing file and the request's
//! buffers in guest RAM with `preadv` and `pwritev`, so no host buffer is sized
//! by the guest. The kernel writes a read's data into guest RAM during the
//! call. A reset therefore waits for the call in flight, and nothing reaches
//! guest RAM for a request of the reset device after the STATUS write returns.
//! The vCPUs' stop ends that wait, and a read still in flight then writes guest
//! RAM after the reset returns, while the VM is ending.
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this VMM's
// own.
#![allow(clippy::disallowed_methods)]

mod device;
mod request;
mod store;
mod worker;

pub use device::{disk_id, open_disks, VirtioBlk, SERIAL_LEN};
pub use worker::{DEFAULT_POLL_MAX, POLL_MAX_LIMIT};

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

//! The virtio-mmio register offsets the devices decode.
//!
//! The values come from `virtio-bindings`, which is bindgen output from the
//! kernel headers, so the offsets match the kernel's. They are re-exported as
//! `u64` because that is what an MMIO dispatch matches on, and under our own
//! names where the kernel's differ: the spec calls the second and third rings
//! *driver* and *device*, which is what the register names say, while the
//! kernel header still calls them *avail* and *used*.

use virtio_bindings::virtio_mmio::*;

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
// Shared memory regions (virtio 1.2). Only the virtio-fs devices answer them.
pub const SHM_LEN_LOW: u64 = VIRTIO_MMIO_SHM_LEN_LOW as u64;
pub const SHM_LEN_HIGH: u64 = VIRTIO_MMIO_SHM_LEN_HIGH as u64;
pub const SHM_BASE_LOW: u64 = VIRTIO_MMIO_SHM_BASE_LOW as u64;
pub const SHM_BASE_HIGH: u64 = VIRTIO_MMIO_SHM_BASE_HIGH as u64;
pub const CONFIG: u64 = VIRTIO_MMIO_CONFIG as u64;

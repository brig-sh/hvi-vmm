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

//! The device models the backends attach to a guest.
//!
//! `virtio` holds the virtio devices over MMIO and the split virtqueue they
//! share. `legacy` holds the serial ports and the CMOS RTC. A backend attaches
//! the devices its guest needs: the PL011 on arm64, the 16550 and the CMOS RTC
//! on x86-64.

pub mod legacy;
pub mod virtio;

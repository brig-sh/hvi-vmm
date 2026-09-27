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

//! virtio-fs over MMIO.
//!
//! On macOS a FUSE server inside the VMM serves the exports. `server` holds the
//! device and answers the guest's FUSE requests against the exported host
//! directories. The server holds a host descriptor for every handle the guest
//! has open, so `fdlimit` raises the process's open-file limit and derives from
//! it how many handles the guest may hold.
//!
//! On Linux a `virtiofsd` per export serves them over vhost-user. `vhost_user`
//! holds the register file the guest talks to and hands the queues to the
//! daemon, and `virtiofsd` starts the daemons.

#[cfg(target_os = "macos")]
pub mod fdlimit;
#[cfg(target_os = "macos")]
pub mod server;
pub mod vhost_user;
#[cfg(target_os = "linux")]
pub mod virtiofsd;

#[cfg(target_os = "macos")]
pub use server::set_guest_ids;

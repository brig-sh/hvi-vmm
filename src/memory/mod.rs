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

//! Guest RAM and the shareable object behind it.
//!
//! Guest RAM is a shareable object, so a plugin that only reads guest memory
//! can run in a process of its own. [`SharedRam`] allocates the object. The VMM
//! maps it as a [`GuestRam`], the writable region collection that it and the
//! rust-vmm crates take as guest memory. A tool that received the object's
//! descriptor maps it read-only as a [`GuestRamView`]. A `GuestRam`
//! dereferences to the view, so code written against the view runs on either.
//! [`RamRegion`] describes one region: where it sits in the guest and in the
//! object. Inside the crate, `io` moves data between a host file and guest RAM
//! with no host buffer.
//!
//! On Linux, a guest whose RAM no other process maps has no object. Its
//! `GuestRam` maps private anonymous memory, which gets transparent huge pages
//! under the host's default THP mode.

mod guest;
mod io;
mod region;
mod shared;

pub use guest::{GuestRam, GuestRamView};
#[cfg(any(test, target_os = "macos"))]
pub(crate) use io::IOV_MAX;
pub(crate) use io::{read_vectored_at_volatile, write_vectored_at_volatile};
pub use region::RamRegion;
pub use shared::SharedRam;

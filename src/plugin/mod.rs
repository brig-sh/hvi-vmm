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

//! The extension seam: how a tool outside the exit loop reaches a running
//! guest.
//!
//! A VMM is a useful place to stand. It holds the guest's memory, it can park
//! the vCPUs between guest entries, and it is the other end of every virtio
//! request the guest makes. Debuggers, tracers, profilers and crash-dumpers all
//! want one or more of those, and none of them belongs in the exit loop.
//!
//! So the exit loop offers them instead. A [`Plugin`] is called at two points,
//! once at boot and on the boot vCPU between guest entries. From there it can
//! read guest RAM, read that vCPU's registers, park the rest of the VM, and
//! subscribe to the device feed. [`builtin`] ships two that use this: a
//! guest-memory dumper and an I/O tracer.
//!
//! These traits describe *access*, and deliberately no more than that. They
//! hand over bytes and register values; what any of it means is the caller's
//! problem, which is what keeps a tool's idea of the guest out of the VMM.
//!
//! The whole seam is optional. With no plugin, the hooks cost a null check per
//! guest entry of the boot vCPU, per block read or write and per network frame.
//! The devices hold no sink, and no guest memory is read for any purpose but
//! running the guest.

mod api;
pub mod builtin;

pub use api::{CpuHandle, GuestArch, IoSink, Plugin, RamRegion, RegsView, VmHandle};

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

//! The guest architectures hvi boots, and the backends that run them.
//!
//! Each guest architecture has its own kernel image format, memory layout and
//! boot-time description of the machine: a devicetree on arm64, an e820 map and
//! an MP table on x86-64. Each backend runs one guest architecture on one
//! hypervisor, so it sits under its architecture and is named for its
//! hypervisor. The crate root re-exports the host target's backend as
//! `hvi::boot`.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

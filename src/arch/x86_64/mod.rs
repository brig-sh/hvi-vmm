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

//! The x86-64 guest.
//!
//! `loader` loads a `bzImage` or an uncompressed `vmlinux` and writes the zero
//! page, the e820 map and the command line. `layout` holds the guest-physical
//! address map. `mptable` describes the CPUs to a guest booted without ACPI,
//! and `acpi` writes the tables and serves the registers the guest powers off
//! through. `kvm` runs the guest on Linux.

pub mod layout;
pub mod loader;

#[cfg(target_os = "linux")]
pub mod acpi;
#[cfg(target_os = "linux")]
pub(crate) mod kvm;
#[cfg(target_os = "linux")]
pub mod mptable;

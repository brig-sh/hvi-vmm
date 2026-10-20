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

//! The arm64 guest.
//!
//! `loader` places the kernel `Image`, the initramfs and the devicetree in
//! guest RAM, `fdt` builds the devicetree, and `layout` holds the
//! guest-physical address map both work from. `kvm` runs the guest on Linux and
//! `hvf` on macOS, which `hvf_state` reads into a checkpoint and `hvf_dirty`
//! tracks the guest's writes for. `esr` decodes the
//! exception syndrome that Hypervisor.framework reports on a guest exit, and
//! `smoke` checks Hypervisor.framework without a kernel. `profile` fills the
//! parts of the machine profile both backends share, and `portable` the
//! hypervisor-neutral contract of the portable machine profile.

pub mod esr;
pub mod fdt;
pub mod layout;
pub mod loader;
pub mod portable;
pub(crate) mod profile;
pub(crate) mod rebuild;

#[cfg(target_os = "macos")]
pub(crate) mod hvf;
#[cfg(target_os = "macos")]
pub(crate) mod hvf_dirty;
#[cfg(target_os = "macos")]
pub(crate) mod hvf_state;
#[cfg(target_os = "linux")]
pub(crate) mod kvm;
#[cfg(any(test, target_os = "linux"))]
pub(crate) mod kvm_state;
#[cfg(target_os = "macos")]
pub mod smoke;
// The KVM backend's; built on macOS only for its tests.
#[cfg(any(test, target_os = "linux"))]
pub(crate) mod vgicv2;

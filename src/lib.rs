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

//! `hvi` -- a small microVMM for Linux guests, with three host
//! backends behind one entry point:
//!
//! - **macOS / Apple silicon** — Apple's Hypervisor.framework (the `applevisor`
//!   crate), arm64 guest. Needs the `com.apple.security.hypervisor` entitlement
//!   at run time.
//! - **Linux / aarch64** — KVM (`kvm-ioctls` / `kvm-bindings`), arm64 guest.
//! - **Linux / x86-64** — KVM, x86-64 guest.
//!
//! All three share everything above the hypervisor: the guest memory layout,
//! kernel image loading and the devicetree or MP table of each guest
//! architecture ([`arch`]), virtio devices ([`devices::virtio`]), the serial
//! ports ([`devices::legacy`]) and the `RawEvent` ledger ([`events`]). On any
//! other target the build stops with a compile error.
//!
//! # Plugins
//!
//! A VMM is a useful place for a tool to stand: it holds the guest's memory, it
//! can park the vCPUs between guest entries, and it is the other end of every
//! virtio request. [`plugin`] offers those three things to one, and
//! [`plugin::builtin`] ships two built on it: a guest-memory dumper and an I/O
//! tracer.
//!
//! Pass a [`plugin::Plugin`] in [`config::BootConfig::plugin`] and the backend
//! calls it; pass `None` and the hooks cost a null check per guest entry of the
//! boot vCPU, per block read or write and per network frame. A separate crate
//! can link this one and supply its own the same way, which is why the VMM is a
//! library as well as a binary. See `docs/plugins.md`.

pub mod arch;
pub mod config;
pub mod devices;
pub mod events;
pub mod hypervisor;
pub(crate) mod io_threads;
pub mod memory;
pub mod plugin;
pub mod sandbox;
pub(crate) mod signal;
pub mod sync;
pub mod teardown;
pub mod terminal;

/// The prefix of the library's log lines on stderr.
pub(crate) const LOG_PREFIX: &str = "[hvi]";

// The backend for the host's target. Each one exposes the same
// `boot(config::BootConfig) -> Result<config::Stop, _>`, and only one compiles.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use arch::aarch64::hvf::boot;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use arch::aarch64::kvm::boot;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use arch::x86_64::kvm::boot;
#[cfg(not(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
)))]
compile_error!("hvi builds for aarch64 macOS, aarch64 Linux and x86-64 Linux only");

/// This crate's version, so a binary built against it can report which VMM core
/// it carries. Two binaries reporting the same core ran the same VMM.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

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
//! All three share everything above the hypervisor: the guest memory layout
//! (`layout`), kernel image parse (`boot`, `boot_x86`), devicetree
//! builder (`fdt`), virtio devices ([`virtio`], [`virtio_net`],
//! [`virtio_vsock`]), the serial ports (`pl011`, `uart16550`) and the
//! `RawEvent` ledger ([`events`]). On any other host the crate builds without a
//! backend, so the deterministic core and its unit tests still compile
//! everywhere.
//!
//! # Plugins
//!
//! A VMM is a useful place for a tool to stand: it holds the guest's memory, it
//! can park the vCPUs between guest entries, and it is the other end of every
//! virtio request. [`plugin`] offers those three things to one, and [`plugins`]
//! ships two built on it — a guest-memory dumper and an I/O tracer.
//!
//! Pass a [`plugin::Plugin`] in [`config::BootConfig::plugin`] and the backend
//! calls it; pass `None` and the hooks are one null check on a cold path. A
//! separate crate can link this one and supply its own the same way, which is
//! why the VMM is a library as well as a binary. See `docs/plugins.md`.

/// arm64 `Image` header parse and placement.
#[cfg(target_arch = "aarch64")]
pub mod boot;
/// x86-64 `bzImage` parse, boot params and the protected-mode entry.
#[cfg(target_arch = "x86_64")]
pub mod boot_x86;
/// Backend-independent boot configuration and result types.
pub mod config;
/// arm64 exception syndrome decoding.
#[cfg(target_arch = "aarch64")]
pub mod esr;
/// The `RawEvent` NDJSON ledger.
pub mod events;
/// Raising the open-file limit hvi runs under. virtio-fs spends the guest's
/// concurrency out of this process's descriptor table.
#[cfg(target_arch = "aarch64")]
pub mod fdlimit;
/// Devicetree builder for the arm64 guest.
///
/// Gated to match `layout` below, which it builds from: an x86 guest is
/// described by the MP table instead. Left ungated, this module took
/// `crate::layout` with it into every x86 build.
#[cfg(target_arch = "aarch64")]
pub mod fdt;
/// `Send + Sync` accessor over the host's guest-RAM mapping.
pub mod guestmem;
/// Guest-physical memory layout (arm64).
#[cfg(target_arch = "aarch64")]
pub mod layout;
/// Guest-physical memory layout (x86-64).
#[cfg(target_arch = "x86_64")]
pub mod layout_x86;
/// Intel MP table, so an x86 guest finds its CPUs without ACPI.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod mptable;
/// PL011 UART (arm64 console).
#[cfg(target_arch = "aarch64")]
pub mod pl011;
/// The plugin seam: how a tool outside the exit loop reaches a guest.
pub mod plugin;
/// Plugins built on it: a memory dumper and an I/O tracer.
#[cfg(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
))]
pub mod plugins;
/// Parks every vCPU at a safe point so an observation sees a still guest.
pub mod quiesce;
/// MC146818 RTC / CMOS, which an x86 guest reads before it has a timer.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod rtc_cmos;
/// Seatbelt confinement for the macOS backend, and the selftest that proves it.
#[cfg(target_os = "macos")]
pub mod sandbox;
/// seccomp-bpf confinement for the Linux backends, and the selftest for it.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod seccomp;
/// Guest RAM backed by a shareable object, so another process can map it.
pub mod sharedmem;
/// The tap side of virtio-net, and the portable vnet-header framing.
pub mod tap;
/// 16550A UART (x86 console).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod uart16550;
/// Concurrency litmus test for the used-ring publish in `virtio::Queue`.
#[cfg(test)]
mod used_ring_litmus;
/// virtio-blk over MMIO.
pub mod virtio;
/// Virtio-fs over MMIO, serving an unpacked host directory.
#[cfg(target_os = "macos")]
pub mod virtio_fs;
/// virtio-net over MMIO, with a built-in stack, a tap, or a gateway relay.
pub mod virtio_net;
/// virtio-vsock over MMIO, bridged to a host Unix socket (guest agent).
pub mod virtio_vsock;

// The active hypervisor backend, selected by target. All three expose the same
// `boot(config::BootConfig) -> Result<config::Stop, _>` entry point.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "machine_macos.rs"]
pub mod machine;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "machine_linux.rs"]
pub mod machine;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "machine_x86.rs"]
pub mod machine;

/// M0 hvf smoke test — Apple-silicon only.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod smoke;

/// This crate's version, so a binary built against it can report which VMM core
/// it carries. Two binaries reporting the same core ran the same VMM.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Whether this host has a hypervisor backend compiled in.
pub const HAS_BACKEND: bool = cfg!(any(
    all(
        target_arch = "aarch64",
        any(target_os = "macos", target_os = "linux")
    ),
    all(target_arch = "x86_64", target_os = "linux")
));

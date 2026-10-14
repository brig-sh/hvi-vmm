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

/// Prints to stderr as `eprint!` does, without its panic on a failed write.
///
/// `eprint!` panics when the write fails, as it does on a terminal that hung up
/// or a pipe whose reader has exited. A test build prints with `eprint!`, whose
/// output the test harness captures.
macro_rules! stderr {
    ($($arg:tt)*) => {{
        #[cfg(test)]
        eprint!($($arg)*);
        #[cfg(not(test))]
        {
            use std::io::Write as _;
            let _ = write!(std::io::stderr(), $($arg)*);
        }
    }};
}

/// Prints a line to stderr as `eprintln!` does, without its panic on a failed
/// write.
///
/// `eprintln!` panics when the write fails, as it does on a terminal that hung
/// up or a pipe whose reader has exited. A test build prints with `eprintln!`,
/// whose output the test harness captures.
macro_rules! stderrln {
    ($($arg:tt)*) => {{
        #[cfg(test)]
        eprintln!($($arg)*);
        #[cfg(not(test))]
        {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr(), $($arg)*);
        }
    }};
}

/// Returns the message of the panic whose payload is `payload`.
///
/// A `panic!` produces a `&str` or a `String` payload, and any other payload
/// reads as `unknown payload`.
pub(crate) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown payload".to_string())
}

pub mod arch;
pub mod checkpoint;
pub mod config;
pub mod devices;
pub mod events;
pub mod hypervisor;
pub(crate) mod io_threads;
pub mod memory;
pub mod plugin;
pub mod run;
pub mod sandbox;
pub mod signal;
pub mod teardown;
pub mod terminal;

/// The prefix of the library's log lines on stderr.
pub(crate) const LOG_PREFIX: &str = "[hvi]";

// The backend for the host's target. Each one has the same `boot`, and only one
// compiles.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use arch::aarch64::hvf as backend;
// Only HVF restores a checkpoint so far; see `checkpoint::restore`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use arch::aarch64::hvf::restore;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use arch::aarch64::kvm as backend;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use arch::x86_64::kvm as backend;
#[cfg(not(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
)))]
compile_error!("hvi builds for aarch64 macOS, aarch64 Linux and x86-64 Linux only");

/// Boots `cfg` and runs the guest until it powers off, resets, or the host
/// requests a stop.
///
/// Returns the [`Stop`](config::Stop) that ended the run. When a vCPU fails,
/// the run ends and the call returns an error that says how. Once a panic hook
/// has started in a binary built with `panic = "abort"`, the call does not
/// return, and the abort ends the process.
///
/// Every thread this call itself starts has exited when it returns, or the call
/// returns an error naming the first that did not stop within
/// [`teardown::STOP_TIMEOUT`], a vCPU thread before a helper thread. There are
/// two exceptions. The thread that receives the stop signals, which the first
/// run after [`stop_on_signals`](signal::stop_on_signals) starts, runs for the
/// life of the process. The ledger's writer thread is not joined, and it can
/// outlive the call while a ledger write blocks in the kernel or keeps failing.
/// What remains of the VM is a `VmHandle` a plugin kept, in a field or on a
/// thread it started from `attach`.
///
/// A sandboxed run leaves its confinement in place. On Linux the seccomp filter
/// stays on the calling thread, refuses opening a file, and passes to every
/// thread that thread starts later, so a later sandboxed `boot` starts from a
/// thread outside the filter. On macOS the Seatbelt profile stays on the whole
/// process and refuses what a later run sets up.
///
/// # Errors
///
/// Errors if the guest cannot be set up, if a vCPU or a thread fails, or if a
/// thread does not stop in time. Errors at once while another run is in
/// progress in the process, and once a run has left a thread running or unwound
/// from a panic, since a process runs one guest at a time. Once the sandbox is
/// on in the process, errors at once for a run with `sandbox` off, on Linux for
/// a run from the thread that called a sandboxed `boot`, and on macOS for any
/// run.
pub fn boot(cfg: config::BootConfig) -> Result<config::Stop, config::BootError> {
    let mut claim = run::RUN_SLOT
        .claim()
        .map_err(|e| config::BootError::new(e.into()))?;
    sandbox::check_run(cfg.sandbox).map_err(|e| config::BootError::new(e.into()))?;
    let result = backend::boot(cfg).map_err(|e| {
        if e.is::<run::LeftRunning>() {
            claim.keep();
        }
        config::BootError::new(e)
    });
    run::wait_for_panic_abort();
    result
}

pub use run::spawn::{spawn, Run};

/// This crate's version, so a binary built against it can report which VMM core
/// it carries. Two binaries reporting the same core ran the same VMM.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

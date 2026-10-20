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

//! The confinement hvi enters before it serves guest I/O.
//!
//! The virtio devices parse guest-controlled data in the same process as the
//! vCPU threads, so hvi confines that process. `seccomp` installs seccomp-bpf
//! allowlists on Linux, one per thread, and `seatbelt` enters a Seatbelt
//! profile on macOS. Each has a selftest that checks the confinement holds, run
//! as `hvi seccomp-selftest` and `hvi sandbox-selftest`.

#[cfg(target_os = "macos")]
pub mod seatbelt;
#[cfg(target_os = "linux")]
pub mod seccomp;

/// Confines the calling host-side I/O thread.
///
/// On Linux the thread installs the `vmm` seccomp filter on itself. On macOS
/// the Seatbelt profile already covers the whole process.
pub(crate) fn confine_io_thread() {
    #[cfg(target_os = "linux")]
    seccomp::install_thread(seccomp::Thread::Vmm);
}

/// Confines the control socket's thread of a run that may write checkpoints.
///
/// On Linux the thread installs the `control` seccomp filter, which is `vmm`
/// with the file calls a bundle needs, on any path, since seccomp cannot
/// filter one. On macOS the Seatbelt profile already
/// covers the whole process, with the checkpoint root as its one writable
/// subtree outside the shares.
pub(crate) fn confine_control_thread() {
    #[cfg(target_os = "linux")]
    seccomp::install_thread(seccomp::Thread::Control);
}

/// Checks that a run can start in this process with the sandbox as `sandbox`
/// asks.
///
/// Once the sandbox is on, it stays on for the life of the process, since a
/// seccomp filter cannot be removed from a thread and a Seatbelt profile cannot
/// be left. On Linux a later run with the sandbox on is refused only from a
/// thread that [`check_thread`] refuses. On macOS the profile refuses what a
/// later run sets up, such as its guest RAM, so every later run is refused.
///
/// # Errors
///
/// Errors with the reason when the sandbox is on and the run cannot start.
pub(crate) fn check_run(sandbox: bool) -> Result<(), &'static str> {
    #[cfg(target_os = "linux")]
    {
        if seccomp::is_entered() && !sandbox {
            return Err("cannot start a run with the sandbox off once it is on");
        }
        check_thread()?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Every later run is refused, with the sandbox on or off.
        let _ = sandbox;
        if seatbelt::is_entered() {
            return Err("cannot start a later run once the sandbox is on");
        }
    }
    Ok(())
}

/// Checks that a run can start from the calling thread.
///
/// On Linux a thread that installed the `vmm` or `vcpu` filter, such as the one
/// that called a sandboxed `boot`, cannot start a run, since the filter ends
/// the process when the run opens a file. The check passes on a thread started
/// from a filtered thread, which inherits the filter, since nothing on that
/// thread records it.
///
/// # Errors
///
/// Errors with the reason when the thread installed a filter that ends the
/// process.
pub(crate) fn check_thread() -> Result<(), &'static str> {
    #[cfg(target_os = "linux")]
    if seccomp::is_thread_filtered() && seccomp::is_trapping() {
        return Err("cannot start a run from a thread the sandbox filters");
    }
    Ok(())
}

/// Returns whether a syscall outside the allowlists ends the process.
///
/// On Linux it does once the seccomp filters are armed, outside log mode. On
/// macOS the Seatbelt profile refuses such a call with an error, so it never
/// does.
pub(crate) fn is_trapping() -> bool {
    #[cfg(target_os = "linux")]
    let trapping = seccomp::is_trapping();
    #[cfg(not(target_os = "linux"))]
    let trapping = false;
    trapping
}

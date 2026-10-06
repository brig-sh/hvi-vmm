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

//! The signal hvi kicks its own threads with.
//!
//! A kick ends a blocking call on the thread it is sent to: `KVM_RUN` on a KVM
//! vCPU thread, and the console reader's read of stdin on every backend.

/// The signal that kicks a thread out of a blocking call.
pub(crate) const KICK_SIGNAL: libc::c_int = libc::SIGUSR1;

/// Installs a no-op handler for [`KICK_SIGNAL`].
///
/// The handler is installed without `SA_RESTART`, so a blocking call the signal
/// interrupts returns `EINTR` instead of resuming.
pub(crate) fn install_kick_handler() {
    extern "C" fn noop(_: libc::c_int) {}
    // SAFETY: installing a trivial signal handler before the I/O threads exist.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = noop as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(KICK_SIGNAL, &sa, std::ptr::null_mut());
    }
}

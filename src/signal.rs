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

/// Returns the signal that kicks a thread out of a blocking call.
///
/// Linux uses the first real-time signal, so `SIGUSR1` stays free for a program
/// that embeds hvi. macOS has no real-time signals and uses `SIGUSR1`.
pub(crate) fn kick_signal() -> libc::c_int {
    #[cfg(target_os = "linux")]
    let signal = libc::SIGRTMIN();
    #[cfg(target_os = "macos")]
    let signal = libc::SIGUSR1;
    signal
}

/// Installs a no-op handler for the [kick signal](kick_signal).
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
        libc::sigaction(kick_signal(), &sa, std::ptr::null_mut());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Returns the handler installed for `signal`.
    fn handler(signal: libc::c_int) -> libc::sighandler_t {
        // SAFETY: only reads the disposition, into a zeroed struct.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            libc::sigaction(signal, std::ptr::null(), &mut current);
            current.sa_sigaction
        }
    }

    #[test]
    fn kick_handler_leaves_sigusr1_to_the_embedder() {
        install_kick_handler();
        assert_eq!(kick_signal(), libc::SIGRTMIN());
        assert_ne!(handler(kick_signal()), libc::SIG_DFL);
        assert_eq!(handler(libc::SIGUSR1), libc::SIG_DFL);
    }
}

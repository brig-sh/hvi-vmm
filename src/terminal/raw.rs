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

//! The raw mode of the operator's terminal for the length of a run.

/// Stdin in raw mode for the guest console, restored on drop.
pub(crate) struct RawTerm {
    /// The settings stdin had before, restored on drop.
    orig: libc::termios,
}

impl RawTerm {
    /// Puts stdin in raw mode, or returns `None` when stdin is not a terminal
    /// or its settings cannot be changed.
    pub(crate) fn enable() -> Option<RawTerm> {
        // SAFETY: `termios` is plain data, so a zeroed one is valid, and the
        // calls on fd 0 only read or write it. Each result is checked.
        unsafe {
            if libc::isatty(0) == 0 {
                return None;
            }
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut orig) != 0 {
                return None;
            }
            let mut raw = orig;
            libc::cfmakeraw(&mut raw);
            if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
                return None;
            }
            Some(RawTerm { orig })
        }
    }
}

impl Drop for RawTerm {
    fn drop(&mut self) {
        // TCSAFLUSH discards unread input, so keystrokes and terminal answers
        // still queued for the guest never reach the shell.
        // SAFETY: restoring the saved settings on fd 0.
        unsafe {
            libc::tcsetattr(0, libc::TCSAFLUSH, &self.orig);
        }
    }
}

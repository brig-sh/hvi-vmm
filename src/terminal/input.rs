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

//! The thread that feeds host stdin to the guest's serial console.

use std::os::fd::AsFd;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::plugin::Plugin;
use crate::teardown::StopToken;
use crate::LOG_PREFIX;

/// The host key that asks an attached plugin for an observation, Ctrl-] (GS).
const REQUEST_KEY: u8 = 0x1d;

/// Spawns the thread that reads host stdin and hands each byte to `deliver`.
///
/// With a plugin attached, [`REQUEST_KEY`] is intercepted. It asks the plugin
/// for an observation and calls `kick` instead of reaching the guest. With no
/// plugin the key reaches the guest like any other byte.
///
/// The thread ends when `stop` is requested, at the end of stdin, or when a
/// read fails. A kick signal ends a read in progress, and the thread then sees
/// the stop.
pub(crate) fn spawn(
    plugin: Option<Arc<dyn Plugin>>,
    stop: StopToken,
    kick: impl Fn() + Send + 'static,
    mut deliver: impl FnMut(u8) + Send + 'static,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        crate::sandbox::confine_io_thread();
        let stdin = std::io::stdin();
        let mut byte = [0u8; 1];
        loop {
            match stop.wait(stdin.as_fd()) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    eprintln!("{LOG_PREFIX} console: {e}; console input stopped");
                    break;
                }
            }
            // SAFETY: reading one byte from fd 0.
            let n = unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                // The kick signal: the stop is seen at the top of the loop.
                continue;
            }
            if n <= 0 {
                break;
            }
            if byte[0] == REQUEST_KEY {
                if let Some(obs) = &plugin {
                    obs.request();
                    kick();
                    continue;
                }
            }
            deliver(byte[0]);
        }
    })
}

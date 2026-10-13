// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

//! Running a guest on a thread of its own.
//!
//! [`spawn`] boots a guest on a new thread and returns a [`Run`] at once. The
//! caller asks the run to stop through the `Run`, and waits for it to end.

use std::io;
use std::thread::JoinHandle;

use crate::config::{BootConfig, BootError, Stop};
use crate::run::StopHandle;

/// A guest that [`spawn`] booted on a thread of its own.
///
/// Dropping it leaves the guest running until it stops on its own. A process
/// that exits before the run ends skips the terminal restore and the ledger
/// flush, so it calls [`request_stop`](Self::request_stop) and then
/// [`wait`](Self::wait) first.
pub struct Run {
    /// The handle on the run's stop.
    stop: StopHandle,
    /// The thread that runs [`boot`](crate::boot).
    thread: JoinHandle<Result<Stop, BootError>>,
}

impl Run {
    /// Asks the run to stop.
    ///
    /// The run stops whatever the guest is doing, and [`wait`](Self::wait) then
    /// returns [`Stop::Requested`], unless a thread reports a failure, or a
    /// vCPU a guest stop, before the run reads how it ended.
    pub fn request_stop(&self) {
        self.stop.request_stop();
    }

    /// Returns the handle on the run's stop.
    ///
    /// A clone of it can be kept on another thread, since [`wait`](Self::wait)
    /// consumes the `Run`.
    #[must_use]
    pub fn stop_handle(&self) -> &StopHandle {
        &self.stop
    }

    /// Returns whether the run has ended.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.thread.is_finished()
    }

    /// Waits for the run to end and returns how it ended.
    ///
    /// # Errors
    ///
    /// Errors with the error [`boot`](crate::boot) returned, or if the thread
    /// that ran it panicked. A panic there stops the VM and the I/O threads
    /// without joining them, and the process cannot start another run.
    pub fn wait(self) -> Result<Stop, BootError> {
        self.thread.join().unwrap_or_else(|payload| {
            let what = crate::panic_message(payload.as_ref());
            Err(BootError::new(
                format!("the run's thread panicked: {what}").into(),
            ))
        })
    }
}

/// Boots `cfg` on a new thread and returns at once.
///
/// The thread calls [`boot`](crate::boot), and the returned [`Run`] waits for
/// it. On Linux `boot` installs its seccomp filter on the thread that calls it,
/// which here is the new thread, so the calling thread stays unfiltered. On
/// macOS the Seatbelt profile confines the whole process, the calling thread
/// included, from the start of the run until the process exits. The run keeps
/// the stop `cfg.stop` holds, or takes a new one when it is `None`, and
/// [`Run::stop_handle`] returns a handle on it either way.
///
/// # Errors
///
/// Errors if the pipe the stop request is written to cannot be created, or if
/// the thread cannot be started.
pub fn spawn(mut cfg: BootConfig) -> io::Result<Run> {
    let stop = match &cfg.stop {
        Some(registration) => registration.handle(),
        None => {
            let (stop, registration) = StopHandle::new_pair()?;
            cfg.stop = Some(registration);
            stop
        }
    };
    let thread = std::thread::Builder::new()
        .name("run".to_string())
        .spawn(move || crate::boot(cfg))?;
    Ok(Run { stop, thread })
}

#[cfg(test)]
mod tests {
    use super::spawn;
    use crate::config::BootConfig;
    use crate::run::StopHandle;

    // Every backend refuses an empty kernel before a guest runs, so this run
    // ends at once with an error.
    #[test]
    fn run_keeps_the_stop_its_config_holds() {
        let (handle, registration) = StopHandle::new_pair().unwrap();
        let cfg = BootConfig {
            kernel: Vec::new(),
            initramfs: None,
            mem_bytes: 128 << 20,
            cmdline: String::new(),
            disks: Vec::new(),
            fs_shares: Vec::new(),
            fs: Vec::new(),
            net: false,
            net_gateway: None,
            net_tap: None,
            net_mac: None,
            events: None,
            sandbox_id: "spawn-test".to_string(),
            vcpus: 1,
            agent_sock: None,
            profile_out: None,
            control_sock: None,
            plugin: None,
            sandbox: false,
            stop: Some(registration),
        };
        let run = spawn(cfg).unwrap();
        handle.request_stop();
        assert!(run.stop_handle().is_stop_requested());
        let error = run.wait().expect_err("an empty kernel booted").to_string();
        assert!(
            !error.contains("another run") && !error.contains("earlier run"),
            "{error}"
        );
    }
}

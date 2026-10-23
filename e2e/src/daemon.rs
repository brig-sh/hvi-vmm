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

//! The helper processes a test runs beside hvi, such as gvproxy and virtiofsd.

use std::fs::File;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::sockets::SocketDir;
use crate::suite::Suite;
use crate::vm::scratch_dir;

/// A helper process that serves hvi over a Unix socket, killed on drop.
///
/// Its output goes to a log in the test's scratch directory.
pub(crate) struct Daemon {
    /// What the process is, for messages.
    name: &'static str,
    /// The process, until it is killed or exits.
    child: Option<Child>,
    /// The directory holding its socket.
    sockets: SocketDir,
    /// Its log.
    log: PathBuf,
}

impl Daemon {
    /// Starts `command` as the daemon `name`, whose socket goes in `sockets`.
    ///
    /// # Panics
    ///
    /// Panics if its log cannot be created or it cannot be started.
    pub(crate) fn spawn(name: &'static str, mut command: Command, sockets: SocketDir) -> Daemon {
        static DAEMONS: AtomicUsize = AtomicUsize::new(0);
        let n = DAEMONS.fetch_add(1, Ordering::Relaxed);
        let log = scratch_dir().join(format!("{name}{n}.log"));
        let file = File::create(&log).unwrap_or_else(|e| panic!("creating {}: {e}", log.display()));
        let child = command
            .stdin(Stdio::null())
            .stdout(file.try_clone().expect("the log should clone"))
            .stderr(file)
            .spawn()
            .unwrap_or_else(|e| panic!("starting {name}: {e}"));
        Daemon {
            name,
            child: Some(child),
            sockets,
            log,
        }
    }

    /// Waits for the daemon to create its socket `file`.
    ///
    /// # Panics
    ///
    /// Panics if the socket does not appear within the time
    /// [`SocketDir::wait_for`] allows. The message names the daemon's log.
    pub(crate) fn wait_for_socket(&self, file: &str) {
        let hint = format!("; see {}", self.log.display());
        self.sockets.wait_for(file, self.name, &hint);
    }

    /// Returns the path of the daemon's socket `file`.
    pub(crate) fn socket(&self, file: &str) -> PathBuf {
        self.sockets.path().join(file)
    }

    /// Sends `signal` to the daemon.
    ///
    /// # Panics
    ///
    /// Panics if the daemon has been killed or reaped, or the signal cannot be
    /// sent.
    pub(crate) fn signal(&self, signal: libc::c_int) {
        let child = self.child.as_ref().expect("the daemon should be running");
        signal_process(child.id(), signal, self.name);
    }

    /// Kills the daemon and waits for it to exit.
    pub(crate) fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Returns whether the daemon exits on its own within `timeout`, scaled for
    /// this host.
    pub(crate) fn wait_for_exit(&mut self, timeout: Duration) -> bool {
        let Some(child) = self.child.as_mut() else {
            return true;
        };
        let deadline = Instant::now() + Suite::get().timeout(timeout);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                self.child = None;
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Sends `signal` to the process `pid`, which `name` names in the panic.
///
/// # Panics
///
/// Panics if the signal cannot be sent.
pub(crate) fn signal_process(pid: u32, signal: libc::c_int, name: &str) {
    let pid = libc::pid_t::try_from(pid).expect("a pid should fit pid_t");
    // SAFETY: kill takes plain values; the caller has not reaped the process,
    // so its pid has not been reused.
    if unsafe { libc::kill(pid, signal) } != 0 {
        panic!("signaling {name}: {}", std::io::Error::last_os_error());
    }
}

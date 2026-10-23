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

//! virtio-fs exports, served by hvi itself on macOS and by a vhost-user daemon
//! on Linux.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::daemon::Daemon;
use crate::sockets::SocketDir;
use crate::suite::Suite;
use crate::vm::scratch_dir;

/// A host directory exported to the guest under a tag, through whichever
/// virtio-fs export this host's backend supports.
///
/// On macOS hvi serves the directory itself (`--fs path=`). On Linux it is the
/// vhost-user frontend to a [`Virtiofsd`] started for the export (`--fs
/// socket=`).
pub struct FsExport {
    /// The `--fs` value hvi is given.
    spec: String,
    /// The daemon serving the export, on Linux.
    daemon: Option<Virtiofsd>,
}

impl FsExport {
    /// Exports `dir` as `tag`, writable.
    ///
    /// # Panics
    ///
    /// Panics on Linux if the host has no virtiofsd, it cannot be started, or
    /// its socket does not appear.
    pub fn new(dir: &Path, tag: &str) -> FsExport {
        if cfg!(target_os = "macos") {
            return FsExport {
                spec: format!("tag={tag},path={}", dir.display()),
                daemon: None,
            };
        }
        let daemon = Virtiofsd::start(dir);
        FsExport {
            spec: format!("tag={tag},socket={}", daemon.socket().display()),
            daemon: Some(daemon),
        }
    }

    /// Returns the `--fs` arguments for the export.
    pub(crate) fn args(&self) -> [OsString; 2] {
        ["--fs".into(), self.spec.clone().into()]
    }

    /// Returns the daemon serving the export, or `None` on macOS.
    pub fn daemon_mut(&mut self) -> Option<&mut Virtiofsd> {
        self.daemon.as_mut()
    }
}

/// A virtiofsd process serving one host directory over a vhost-user socket.
///
/// It runs as the test's user, with `--sandbox none`, since the namespace
/// sandbox needs privileges a test does not have. The daemon still confines the
/// guest to the directory it serves.
pub struct Virtiofsd {
    /// The daemon process.
    daemon: Daemon,
}

impl Virtiofsd {
    /// Starts virtiofsd for `dir`, waiting for its socket to appear.
    ///
    /// # Panics
    ///
    /// Panics if the host has no virtiofsd, it cannot be started, or its socket
    /// does not appear.
    pub fn start(dir: &Path) -> Virtiofsd {
        let virtiofsd = Virtiofsd::spawn_at(dir, SocketDir::new());
        virtiofsd.daemon.wait_for_socket(SOCKET);
        virtiofsd
    }

    /// Starts virtiofsd for `dir` on the socket `pending` reserved, without
    /// waiting for it.
    ///
    /// # Panics
    ///
    /// Panics if the host has no virtiofsd or it cannot be started.
    pub fn spawn_into(dir: &Path, pending: PendingSocket) -> Virtiofsd {
        Virtiofsd::spawn_at(dir, pending.0)
    }

    /// Starts the daemon with its socket in `sockets`.
    fn spawn_at(dir: &Path, sockets: SocketDir) -> Virtiofsd {
        let mut command = Command::new(Suite::get().virtiofsd());
        command
            .arg("--socket-path")
            .arg(sockets.path().join(SOCKET))
            .arg("--shared-dir")
            .arg(dir)
            .args(["--sandbox", "none"]);
        Virtiofsd {
            daemon: Daemon::spawn("virtiofsd", command, sockets),
        }
    }

    /// Returns the path of the daemon's vhost-user socket.
    pub fn socket(&self) -> PathBuf {
        self.daemon.socket(SOCKET)
    }

    /// Kills the daemon and waits for it to exit.
    pub fn kill(&mut self) {
        self.daemon.kill();
    }

    /// Returns whether the daemon exits on its own within `timeout`, scaled for
    /// this host.
    pub fn wait_for_exit(&mut self, timeout: Duration) -> bool {
        self.daemon.wait_for_exit(timeout)
    }
}

/// The name of the daemon's socket in its directory.
const SOCKET: &str = "virtiofsd.sock";

/// A socket path reserved for a virtiofsd that starts after hvi.
pub struct PendingSocket(SocketDir);

impl PendingSocket {
    /// Reserves the socket path for a daemon started later with
    /// [`Virtiofsd::spawn_into`].
    pub fn reserve() -> PendingSocket {
        PendingSocket(SocketDir::new())
    }

    /// Returns the path the daemon will listen on.
    pub fn path(&self) -> PathBuf {
        self.0.path().join(SOCKET)
    }
}

/// Returns the path of a new directory `name` in the test's scratch directory.
///
/// # Panics
///
/// Panics if the directory cannot be created.
pub fn export_dir(name: &str) -> PathBuf {
    let dir = scratch_dir().join(name);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
    dir
}

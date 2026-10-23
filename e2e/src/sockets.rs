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

//! Short-lived directories for Unix sockets.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::suite::Suite;

/// A directory for Unix sockets, removed on drop.
///
/// It sits in the system's temporary directory rather than a test's own, since
/// a Unix socket path is limited to about 100 bytes.
#[derive(Debug)]
pub(crate) struct SocketDir(PathBuf);

impl SocketDir {
    /// Creates the directory, readable by this user only.
    ///
    /// # Panics
    ///
    /// Panics if the directory cannot be created.
    pub(crate) fn new() -> SocketDir {
        use std::os::unix::fs::DirBuilderExt;
        static DIRS: AtomicUsize = AtomicUsize::new(0);
        let n = DIRS.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("hvi-e2e-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap_or_else(|e| panic!("creating {}: {e}", path.display()));
        SocketDir(path)
    }

    /// Returns the directory's path.
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// Waits for `program` to create the socket `name` in the directory.
    ///
    /// # Panics
    ///
    /// Panics if the socket does not appear within ten seconds, scaled for this
    /// host. `hint` ends the message.
    pub(crate) fn wait_for(&self, name: &str, program: &str, hint: &str) {
        let socket = self.0.join(name);
        let timeout = Suite::get().timeout(Duration::from_secs(10));
        let deadline = Instant::now() + timeout;
        while !socket.exists() {
            assert!(
                Instant::now() < deadline,
                "{program} did not create {} within {timeout:?}{hint}",
                socket.display()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

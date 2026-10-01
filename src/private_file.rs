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

//! Creating the files hvi writes for the operator.
//!
//! The event ledger, the I/O trace, the memory dump and the devicetree that
//! `dump-fdt --out` writes all go to a path the operator chose. That path is
//! often in a directory other local users can write, and the ledger carries
//! the guest's DNS names and TLS SNI. [`create`] is the one way these files
//! are opened, so each of them is private to the VMM's user and none of them
//! can be redirected onto another file.
// The paths here are the operator's, given on the command line; see
// clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// The mode of a file [`create`] returns.
pub const MODE: u32 = 0o600;

/// Opens `path` as an empty file for writing that only the VMM's user can
/// read.
///
/// The open does not follow a symbolic link at `path`, and it does not wait
/// for a reader on a FIFO. What it finds there decides the rest:
///
/// - Nothing. The file is created at [`MODE`].
/// - A regular file that the effective uid owns and that has one link. It is
///   set to [`MODE`] if group or other had any access, and then truncated.
/// - Anything else. It is refused and left as it was.
///
/// The link count matters because another user can hard-link one of the
/// operator's own files at `path`, and macOS does not stop them. That
/// redirects the write the same way a symbolic link would.
///
/// # Errors
///
/// Returns the open's own error, or an error naming `path` and the reason
/// when it refuses what is there.
pub fn create(path: &Path) -> io::Result<File> {
    // O_NONBLOCK keeps a FIFO from blocking the open, and O_NOCTTY keeps a
    // terminal from becoming the controlling one. Neither changes anything
    // for a regular file, the only kind this keeps.
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => refusal(path, "it is a symbolic link"),
            Some(libc::ENXIO | libc::EISDIR | libc::EOPNOTSUPP) => {
                refusal(path, "it is not a regular file")
            }
            _ => e,
        })?;
    let meta = file.metadata()?;
    check(path, &meta)?;
    if meta.mode() & 0o077 != 0 {
        file.set_permissions(Permissions::from_mode(MODE))?;
    }
    file.set_len(0)?;
    Ok(file)
}

/// Returns an error saying that hvi will not write to `path`, and why.
fn refusal(path: &Path, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("refusing to write {}: {why}", path.display()),
    )
}

/// Checks what [`create`] opened against the three conditions it truncates
/// under.
fn check(path: &Path, meta: &Metadata) -> io::Result<()> {
    let kind = meta.file_type();
    if !kind.is_file() {
        let what = if kind.is_fifo() {
            "a FIFO"
        } else if kind.is_char_device() || kind.is_block_device() {
            "a device"
        } else {
            "not a regular file"
        };
        return Err(refusal(path, &format!("it is {what}")));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(refusal(
            path,
            &format!(
                "it is owned by uid {} and hvi runs as uid {euid}",
                meta.uid()
            ),
        ));
    }
    if meta.nlink() != 1 {
        return Err(refusal(
            path,
            &format!("it has {} hard links", meta.nlink()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Returns an empty directory of the caller's own under the temp dir.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hvi-private-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // The environment variable that turns `new_file_is_0600_under_umask_0`
    // into its child half, naming the directory to create the file in.
    const UMASK_CHILD: &str = "HVI_PRIVATE_FILE_UMASK_CHILD";

    // The mode of a new file must not depend on the umask hvi inherits. The
    // umask is per process and other tests create files in parallel, so the
    // check runs in a child copy of this test binary started under umask 0.
    #[test]
    fn new_file_is_0600_under_umask_0() {
        use std::os::unix::process::CommandExt;

        if let Some(dir) = std::env::var_os(UMASK_CHILD) {
            // SAFETY: umask has no preconditions and cannot fail.
            let inherited = unsafe { libc::umask(0) };
            assert_eq!(inherited, 0, "the child runs under umask 0");
            let path = PathBuf::from(dir).join("ledger.ndjson");
            let mode = create(&path).unwrap().metadata().unwrap().mode();
            assert_eq!(mode & 0o7777, MODE, "mode {mode:o} under umask 0");
            return;
        }
        let dir = scratch("umask");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "private_file::tests::new_file_is_0600_under_umask_0",
                "--test-threads=1",
            ])
            .env(UMASK_CHILD, &dir);
        // SAFETY: umask is async-signal-safe and cannot fail.
        unsafe {
            child.pre_exec(|| {
                libc::umask(0);
                Ok(())
            });
        }
        let out = child.output().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}{stderr}");
        assert!(
            stdout.contains("1 passed"),
            "the child ran no test: {stdout}"
        );
    }

    #[test]
    fn existing_file_is_tightened_and_truncated() {
        let dir = scratch("existing");
        let path = dir.join("ledger.ndjson");
        std::fs::write(&path, "a previous run").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();

        let meta = create(&path).unwrap().metadata().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(meta.mode() & 0o777, MODE);
        assert_eq!(meta.len(), 0);
    }

    // A dangling link is the case where following it would create a file at
    // a place of the link owner's choosing.
    #[test]
    fn dangling_symlink_creates_nothing_at_its_target() {
        let dir = scratch("dangling");
        let target = dir.join("planted");
        let path = dir.join("trace.log");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let err = create(&path).unwrap_err();
        let created = target.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!created, "the open followed the link");
        assert!(err.to_string().contains("symbolic link"), "{err}");
    }

    // With no reader, a blocking open of a FIFO for writing would wait
    // forever, and the boot with it.
    #[test]
    fn fifo_is_refused_without_waiting_for_a_reader() {
        use std::os::unix::ffi::OsStrExt;

        let dir = scratch("fifo");
        let path = dir.join("ledger.ndjson");
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let err = create(&path).unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }
}

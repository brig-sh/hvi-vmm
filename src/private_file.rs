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

//! Opening the files hvi writes for the operator.
//!
//! The event ledger, the I/O trace, the memory dump and the devicetree that
//! `dump-fdt --out` writes all go to a path the operator chose. That path is
//! often in a directory other local users can write, and the ledger carries
//! the guest's DNS names and TLS SNI. [`open`] and [`create`] are the one way
//! these files are opened, and [`open`] states what they guarantee.
// The paths here are the operator's, given on the command line; see
// clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

/// The mode of a file [`open`] returns.
pub const MODE: u32 = 0o600;

/// Opens `path` for writing as a regular file at [`MODE`] that the effective
/// uid owns and no other user can read.
///
/// The open does not follow a symbolic link as the last component of `path`,
/// and it does not wait for a reader on a FIFO. What it finds at `path`
/// decides the rest:
///
/// - Nothing. A file is created at [`MODE`].
/// - A regular file that the effective uid owns and that has one name. It is
///   kept, contents included, if only the owner had access to it. If group or
///   other had any access and it is empty, it is unlinked and created anew at
///   [`MODE`], so a descriptor someone opened under the old mode does not reach
///   what hvi writes next. If they had access and it is not empty, it is
///   refused, since replacing it would lose what it holds before the caller
///   decides to write. [`create`] replaces it instead.
/// - Anything else. It is refused and left as it was.
///
/// A parent directory that is a symbolic link is followed. `O_NOFOLLOW`
/// covers the last component only, and macOS's `O_NOFOLLOW_ANY` would refuse
/// `/tmp`, `/var` and `/etc`, which are links there.
///
/// The one-name condition is a best effort. Another user can hard-link one of
/// the operator's files at `path`, and macOS does not stop them. The link
/// count is read after the open, so a second name made and removed around it
/// passes.
///
/// On macOS an access control list on the file counts as access by group or
/// other, as above. A new file that inherits a list from its
/// directory is refused and removed, since the list grants access before hvi
/// writes anything. On Linux the mode bits bound a POSIX ACL, so the mode is
/// the whole check.
///
/// # Errors
///
/// Returns the open's own error, or an error saying what is at `path` and why
/// it is refused. Neither names `path`, which the caller knows.
pub fn open(path: &Path) -> io::Result<File> {
    open_private(path, false)
}

/// Opens `path` as [`open`] does, and empties it.
///
/// A file group or other had access to is replaced whatever it holds, since
/// the caller empties it anyway.
///
/// # Errors
///
/// Returns [`open`]'s error, or the truncation's.
pub fn create(path: &Path) -> io::Result<File> {
    let file = open_private(path, true)?;
    if file.metadata()?.len() > 0 {
        file.set_len(0)?;
    }
    Ok(file)
}

/// Opens `path` for [`open`] and [`create`], replacing a file others had
/// access to when it is empty or when `replace_contents` says its contents
/// can go.
fn open_private(path: &Path, replace_contents: bool) -> io::Result<File> {
    let file = open_flags(path, false).map_err(|e| map_open_error(path, e))?;
    let meta = file.metadata()?;
    check(&meta)?;
    if meta.mode() & 0o077 == 0 && !acl::has_acl(&file)? {
        return Ok(file);
    }
    if meta.len() > 0 && !replace_contents {
        return Err(refusal(
            "others can read it and it is not empty; remove it or move it aside",
        ));
    }
    // Others had access, so someone may hold a descriptor opened under the
    // old mode, and a chmod would not revoke it. Replace the inode. The unlink
    // removes the name at `path`, never what a link there points to, and the
    // exclusive create refuses anything planted since.
    drop(file);
    std::fs::remove_file(path).map_err(|e| {
        refusal(&format!(
            "others can read it and it cannot be removed ({e}); \
             chmod it to 0600 or make its directory writable"
        ))
    })?;
    let file = open_flags(path, true).map_err(|e| {
        let e = map_open_error(path, e);
        io::Error::new(
            e.kind(),
            format!("removed it, then could not create it again: {e}"),
        )
    })?;
    check(&file.metadata()?)?;
    if acl::has_acl(&file)? {
        let _ = std::fs::remove_file(path);
        return Err(refusal(
            "its directory gives new files an access control list; \
             remove it with chmod -a or use another directory",
        ));
    }
    Ok(file)
}

/// Opens `path` for writing with the flags every open here uses, creating it
/// at [`MODE`] when `exclusive` or when nothing is there.
///
/// `O_NONBLOCK` keeps a FIFO from blocking the open, and `O_NOCTTY` keeps a
/// terminal from becoming the controlling one. Neither changes anything for
/// a regular file, the only kind [`open`] keeps.
fn open_flags(path: &Path, exclusive: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true);
    if exclusive {
        opts.create_new(true);
    } else {
        opts.create(true);
    }
    opts.mode(MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
}

/// Returns the refusal that the open's error `e` stands for, or `e` itself.
///
/// `O_NOFOLLOW` refuses a link with `ELOOP`, whose message is about a loop of
/// links. A loop in a parent directory returns `ELOOP` too, so the path is
/// checked before the message changes.
fn map_open_error(path: &Path, e: io::Error) -> io::Error {
    let is_link = || std::fs::symlink_metadata(path).is_ok_and(|m| m.is_symlink());
    match e.raw_os_error() {
        Some(libc::ELOOP) if is_link() => refusal("it is a symbolic link"),
        Some(libc::ENXIO | libc::EISDIR | libc::EOPNOTSUPP) => refusal("it is not a regular file"),
        _ => e,
    }
}

/// Returns an error saying why hvi will not write what is at the path.
fn refusal(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

/// Checks what [`open`] opened for the type, owner and link count it keeps.
fn check(meta: &Metadata) -> io::Result<()> {
    let kind = meta.file_type();
    if !kind.is_file() {
        let what = if kind.is_fifo() {
            "a FIFO"
        } else if kind.is_char_device() || kind.is_block_device() {
            "a device"
        } else {
            "not a regular file"
        };
        return Err(refusal(&format!("it is {what}")));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(refusal(&format!(
            "uid {} owns it and hvi runs as uid {euid}",
            meta.uid()
        )));
    }
    if meta.nlink() != 1 {
        return Err(refusal(&format!("it has {} names", meta.nlink())));
    }
    Ok(())
}

/// The access control list of a file, which the mode bits do not show.
#[cfg(target_os = "macos")]
mod acl {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    /// `ACL_TYPE_EXTENDED` from `sys/acl.h`, the one list type macOS has.
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

    extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
    }

    /// Returns whether `file` has an access control list.
    ///
    /// # Errors
    ///
    /// Errors when the list cannot be read. A file system without lists is
    /// a file without one.
    pub fn has_acl(file: &File) -> io::Result<bool> {
        // SAFETY: acl_get_fd_np reads the list of an open descriptor and
        // returns an allocation or null.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ENOENT | libc::ENOTSUP) => Ok(false),
                _ => Err(e),
            };
        }
        // SAFETY: `acl` came from acl_get_fd_np and is freed once.
        unsafe { acl_free(acl) };
        Ok(true)
    }
}

/// The access control list of a file, which the mode bits bound on Linux.
#[cfg(not(target_os = "macos"))]
mod acl {
    use std::fs::File;
    use std::io;

    /// Returns `false`, since a POSIX ACL grants nothing past the mode bits.
    pub fn has_acl(_file: &File) -> io::Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    /// Returns an empty directory of the caller's own under the temp dir.
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
    fn existing_file_is_replaced_and_old_descriptors_see_nothing_new() {
        use std::io::{Read, Write};
        let dir = scratch("existing");
        let path = dir.join("ledger.ndjson");
        std::fs::write(&path, "a previous run").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();

        let mut held = File::open(&path).unwrap();
        let old_ino = held.metadata().unwrap().ino();
        let mut new = create(&path).unwrap();
        new.write_all(b"new secret").unwrap();
        let meta = new.metadata().unwrap();
        let mut seen = String::new();
        held.read_to_string(&mut seen).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(meta.mode() & 0o777, MODE);
        assert_ne!(meta.ino(), old_ino, "the inode was reused");
        assert_eq!(seen, "a previous run");
    }

    #[test]
    fn private_existing_file_is_truncated_in_place() {
        let dir = scratch("private");
        let path = dir.join("ledger.ndjson");
        std::fs::write(&path, "a previous run").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        let old_ino = std::fs::metadata(&path).unwrap().ino();
        let meta = create(&path).unwrap().metadata().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(meta.len(), 0);
        assert_eq!(meta.ino(), old_ino);
    }

    // The ledger empties the file at its first record, so the contents must
    // survive `open`.
    #[test]
    fn open_keeps_the_contents_of_a_private_file() {
        let dir = scratch("keep");
        let path = dir.join("ledger.ndjson");
        std::fs::write(&path, "a previous run").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        let len = open(&path).unwrap().metadata().unwrap().len();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(len, "a previous run".len() as u64);
    }

    // The ledger empties the file only at its first record, so `open` cannot
    // replace a file that holds something, such as a disk image given as the
    // ledger by mistake.
    #[test]
    fn open_refuses_a_shared_file_that_is_not_empty_and_leaves_it() {
        let dir = scratch("shared-kept");
        let path = dir.join("ledger.ndjson");
        std::fs::write(&path, "a previous run").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        let old_ino = std::fs::metadata(&path).unwrap().ino();

        let err = open(&path).unwrap_err();
        let meta = std::fs::metadata(&path).unwrap();
        let kept = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            err.to_string()
                .starts_with("others can read it and it is not empty"),
            "{err}"
        );
        assert_eq!(meta.ino(), old_ino);
        assert_eq!(meta.mode() & 0o777, 0o644);
        assert_eq!(kept, "a previous run");
    }

    #[test]
    fn open_replaces_an_empty_shared_file() {
        let dir = scratch("shared-empty");
        let path = dir.join("ledger.ndjson");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        // Held open, so the old inode cannot be reused for the new file.
        let held = File::open(&path).unwrap();
        let old_ino = held.metadata().unwrap().ino();

        let meta = open(&path).unwrap().metadata().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(meta.mode() & 0o777, MODE);
        assert_ne!(meta.ino(), old_ino, "the inode was reused");
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
        assert_eq!(err.to_string(), "it is a symbolic link");
    }

    // macOS lets any user hard-link another user's file into a directory
    // they can write, so a second name is the same redirection as a link.
    #[test]
    fn file_with_a_second_name_is_refused() {
        let dir = scratch("hardlink");
        let target = dir.join("target.txt");
        std::fs::write(&target, "operator data that must survive").unwrap();
        let path = dir.join("ledger.ndjson");
        std::fs::hard_link(&target, &path).unwrap();

        let err = create(&path).unwrap_err();
        let survived = std::fs::read_to_string(&target).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.to_string(), "it has 2 names");
        assert_eq!(survived, "operator data that must survive");
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
        assert_eq!(err.to_string(), "it is not a regular file");
    }

    #[test]
    fn directory_is_refused() {
        let dir = scratch("dir");
        let err = create(&dir).unwrap_err();
        let kept = std::fs::metadata(&dir).is_ok_and(|m| m.is_dir());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(kept);
        assert_eq!(err.to_string(), "it is not a regular file");
    }

    #[test]
    fn device_is_refused() {
        let err = create(Path::new("/dev/null")).unwrap_err();
        assert_eq!(err.to_string(), "it is a device");
    }

    /// Runs `chmod` with `args`, which the tests use to set an access control
    /// list.
    #[cfg(target_os = "macos")]
    fn chmod(args: &[&str]) {
        let status = std::process::Command::new("/bin/chmod")
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "chmod {args:?}");
    }

    // A 0600 file with a list that lets everyone read it is as shared as a
    // 0644 one.
    #[cfg(target_os = "macos")]
    #[test]
    fn file_with_an_acl_is_replaced() {
        let dir = scratch("acl");
        let path = dir.join("ledger.ndjson");
        std::fs::write(&path, "a previous run").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        chmod(&["+a", "everyone allow read", path.to_str().unwrap()]);
        let old_ino = std::fs::metadata(&path).unwrap().ino();

        let new = create(&path).unwrap();
        let had_acl = acl::has_acl(&new).unwrap();
        let ino = new.metadata().unwrap().ino();
        let _ = std::fs::remove_dir_all(&dir);
        assert_ne!(ino, old_ino, "the inode was reused");
        assert!(!had_acl, "the new file has a list");
    }

    // A list the directory hands to new files reaches the file before hvi
    // writes to it, so there is no moment to strip it at.
    #[cfg(target_os = "macos")]
    #[test]
    fn file_inheriting_an_acl_is_refused_and_removed() {
        let dir = scratch("acl-inherit");
        chmod(&[
            "+a",
            "everyone allow read,file_inherit",
            dir.to_str().unwrap(),
        ]);
        let path = dir.join("ledger.ndjson");

        let err = create(&path).unwrap_err();
        let left = std::fs::symlink_metadata(&path).is_ok();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            err.to_string().starts_with("its directory gives new files"),
            "{err}"
        );
        assert!(!left, "the refused file was left behind");
    }
}

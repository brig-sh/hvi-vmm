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

//! The `virtiofsd` daemons behind the Linux backend's exports.
//!
//! One daemon serves one export. It is started before the guest runs and
//! before the seccomp filters go in, because starting a process and binding a
//! socket are not on the allowlist.
//!
//! The connection never touches the filesystem. We bind a listening socket in
//! the abstract namespace, connect to it ourselves, and only then hand the
//! listening descriptor to the daemon, which accepts the connection already
//! queued on it. There is no socket file to remove afterwards.
//!
//! An abstract socket has no path and so no permission check: any process in
//! the same network namespace may connect to one by name. Two things keep the
//! daemon's single accept for us. A connector that arrives after ours is
//! behind it in the queue, which is what the ordering above buys. A connector
//! that arrives before ours has to have guessed the name first, which carries
//! this process's id, the export's index and the nanosecond it was built.

// This module resolves a host path of the VMM's own: the daemon binary, named
// on the command line or found on PATH, once before any guest runs. No guest
// request reaches it. See clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::config::{CachePolicy, FsShare};

/// Where the daemon is looked for when the command line does not say.
const WELL_KNOWN: [&str; 4] = [
    "/usr/libexec/virtiofsd",
    "/usr/lib/virtiofsd",
    "/usr/lib/qemu/virtiofsd",
    "/usr/local/bin/virtiofsd",
];

/// Descriptor number the listening socket is placed on for the daemon.
///
/// The daemon is told `--fd=3`, so the number is part of the contract with it
/// rather than a free choice.
const LISTEN_FD: i32 = 3;

/// A running `virtiofsd`.
///
/// Dropping this does not stop the daemon. It exits on its own when the
/// vhost-user connection closes, and the VMM's own exit closes it. The child
/// also carries `PR_SET_PDEATHSIG`, so a VMM that dies without closing
/// anything still takes its daemons with it.
pub struct Daemon {
    child: Child,
}

impl Daemon {
    /// Returns the daemon's process id.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Daemon {
    /// Reaps the daemon, so a process that boots more than one guest does not
    /// collect a zombie per export.
    ///
    /// What makes the daemon exit is the end of the vhost-user connection,
    /// which the machine backend shuts down by descriptor when the guest
    /// stops. Dropping the device would do it too, but nothing guarantees the
    /// device is dropped: a detached thread holding a clone of the VMM's
    /// shared state keeps it alive, and an embedding that calls `boot` in a
    /// loop would then collect a live daemon per export per guest.
    ///
    /// The wait is a bounded poll rather than a blocking one. A daemon that
    /// has not exited when the budget is spent is left to `PR_SET_PDEATHSIG`,
    /// which is a delay at worst, where a blocking wait would be a hang.
    fn drop(&mut self) {
        for _ in 0..REAP_POLLS {
            match self.child.try_wait() {
                Ok(None) => std::thread::sleep(REAP_POLL_INTERVAL),
                _ => return,
            }
        }
    }
}

/// How many times a dropped [`Daemon`] asks whether the child has exited.
const REAP_POLLS: u32 = 20;
/// How long it waits between those questions, for 100 ms in total.
const REAP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// Returns the daemon binary to run, from `explicit`, then `HVI_VIRTIOFSD`,
/// then `PATH`, then the well-known locations.
///
/// # Errors
///
/// Errors when no candidate exists, listing where it looked.
pub fn find(explicit: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os("HVI_VIRTIOFSD") {
        return Ok(PathBuf::from(path));
    }
    if let Some(dirs) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&dirs) {
            let candidate = dir.join("virtiofsd");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    for candidate in WELL_KNOWN {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(not_found())
}

/// Returns the error a search with no candidate reports, which names every
/// place that was looked in.
fn not_found() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "no virtiofsd found; pass --virtiofsd <path>, set HVI_VIRTIOFSD, \
             or install it in PATH or one of {}",
            WELL_KNOWN.join(", ")
        ),
    )
}

/// Starts a daemon for `share` and returns it with the vhost-user connection
/// to it.
///
/// `index` only has to be unique within this VMM; it keeps two exports from
/// racing for one abstract socket name.
///
/// # Errors
///
/// Errors if the socket cannot be bound, or the daemon cannot be started.
pub fn spawn(binary: &Path, share: &FsShare, index: usize) -> io::Result<(Daemon, UnixStream)> {
    if !share.mode.writable() {
        // A binary that cannot be run is a different fault from one that is
        // too old, and the message a user acts on has to say which.
        let reported = version(binary).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("asking {} for its version: {e}", binary.display()),
            )
        })?;
        if !enforces_readonly(reported) {
            let (want_major, want_minor) = READONLY_SINCE;
            let found = match reported {
                Some((major, minor)) => format!("virtiofsd {major}.{minor}"),
                None => String::from("a daemon that reports no version"),
            };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is {found}, which has no --readonly; a read-only \
                     export needs {want_major}.{want_minor} or newer",
                    binary.display()
                ),
            ));
        }
    }

    let name = socket_name(index);
    let address = SocketAddr::from_abstract_name(name.as_bytes())?;
    let listener = UnixListener::bind_addr(&address)?;
    // Queue our connection before the daemon exists, so the accept it does on
    // startup can only take ours.
    let stream = UnixStream::connect_addr(&address)?;

    let mut command = Command::new(binary);
    command
        .arg(format!("--fd={LISTEN_FD}"))
        .arg("--shared-dir")
        .arg(&share.path)
        .arg("--sandbox")
        .arg(sandbox_mode())
        .args(cache_args(share.cache))
        .arg("--announce-submounts")
        .arg("--xattr")
        .arg("--log-level")
        .arg(log_level())
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    if !share.mode.writable() {
        command.arg("--readonly");
    }

    let listen_fd = std::os::fd::AsRawFd::as_raw_fd(&listener);
    // SAFETY: every call here is async-signal-safe and none allocates. What
    // gets the descriptor across the exec is the cleared close-on-exec flag,
    // which dup2 does as a side effect of duplicating.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            // dup2 onto the descriptor a file already occupies returns it
            // untouched, flags included, so a listener that std happened to
            // put on LISTEN_FD would reach the exec still close-on-exec and
            // the daemon would find nothing on --fd. Clear the flag directly
            // in that case.
            if listen_fd == LISTEN_FD {
                if libc::fcntl(listen_fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            } else if libc::dup2(listen_fd, LISTEN_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command.spawn().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("starting {} for tag {}: {e}", binary.display(), share.tag),
        )
    })?;
    Ok((Daemon { child }, stream))
}

/// First version whose daemon takes `--readonly`.
const READONLY_SINCE: (u32, u32) = (1, 11);

/// Returns whether a daemon reporting `version` enforces a read-only export.
///
/// A daemon that reports no version at all is treated as too old. The export
/// would otherwise be served writable, which is not what the command line
/// asked for.
fn enforces_readonly(version: Option<(u32, u32)>) -> bool {
    version.is_some_and(|v| v >= READONLY_SINCE)
}

/// Returns the daemon's major and minor version, or `None` when it runs and
/// reports none.
///
/// A read-only export is the reason this is asked. `--readonly` arrived in
/// 1.11, and a daemon without it serves the export writable, which is a
/// weaker guarantee than the one the command line asked for.
///
/// # Errors
///
/// Errors when the binary cannot be run at all, which is a wrong path rather
/// than an old daemon and needs to be reported as one.
fn version(binary: &Path) -> io::Result<Option<(u32, u32)>> {
    let output = Command::new(binary).arg("--version").output()?;
    Ok(parse_version(&String::from_utf8_lossy(&output.stdout)))
}

/// Returns the major and minor version in `text`, which is what the daemon
/// prints for `--version`, or `None` when it names no version.
///
/// The number is taken from after the daemon's own name. Any program answers
/// `--version` with something, and a number lifted from another one's output
/// would decide whether a read-only export is served.
fn parse_version(text: &str) -> Option<(u32, u32)> {
    let mut words = text.split_whitespace().skip_while(|w| *w != "virtiofsd");
    words.next()?;
    let mut parts = words.next()?.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Warns that a read-only export served by a foreign daemon is only as
/// read-only as that daemon was started.
///
/// hvi enforces the mode by passing `--readonly` to the daemon it starts. A
/// daemon someone else started took its arguments from them, and vhost-user
/// has no message that asks a backend what it will refuse, so this is the
/// most the VMM can do: say whose guarantee it is.
pub fn warn_foreign_readonly(share: &FsShare) {
    if share.mode.writable() {
        return;
    }
    eprintln!(
        "[hvi] WARNING: virtio-fs {:?} is read-only to this VMM, but it is \
         served by a daemon hvi did not start; whether the guest's writes are \
         refused is that daemon's --readonly, not ours",
        share.tag
    );
}

/// Returns the abstract socket name for export `index` of this process.
fn socket_name(index: usize) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!("hvi-virtiofs-{}-{index}-{nanos:08x}", std::process::id())
}

/// Returns the daemon's log level, which `HVI_VIRTIOFSD_LOG` overrides.
///
/// The default keeps the daemon off the guest's console. A mount that does
/// not come up is the case where its own log is the only thing that says why.
fn log_level() -> String {
    std::env::var("HVI_VIRTIOFSD_LOG").unwrap_or_else(|_| String::from("warn"))
}

/// Returns the daemon's sandbox mode.
///
/// The namespace sandbox needs `CAP_SYS_ADMIN` to unshare its mount and pid
/// namespaces. An unprivileged VMM does not have it, and a daemon that cannot
/// start serves nothing at all.
fn sandbox_mode() -> &'static str {
    // SAFETY: geteuid has no failure mode and touches no memory we own.
    if unsafe { libc::geteuid() } == 0 {
        "namespace"
    } else {
        "none"
    }
}

/// Returns the daemon's cache arguments for `policy`.
///
/// The three policies are the same trade the macOS device makes, so the
/// mapping is described once, in [`CachePolicy`].
fn cache_args(policy: CachePolicy) -> Vec<&'static str> {
    match policy {
        CachePolicy::Auto => vec!["--cache", "auto"],
        CachePolicy::Always => vec!["--cache", "always", "--writeback"],
        CachePolicy::None => vec!["--cache", "never"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_name_is_unique_per_export() {
        assert_ne!(socket_name(0), socket_name(1));
    }

    #[test]
    fn writeback_comes_with_the_always_policy() {
        assert_eq!(cache_args(CachePolicy::Auto), ["--cache", "auto"]);
        assert_eq!(cache_args(CachePolicy::None), ["--cache", "never"]);
        assert!(cache_args(CachePolicy::Always).contains(&"--writeback"));
    }

    #[test]
    fn a_version_is_read_from_the_daemons_own_line() {
        assert_eq!(parse_version("virtiofsd 1.14.0\n"), Some((1, 14)));
        assert_eq!(parse_version("virtiofsd 1.10.0"), Some((1, 10)));
    }

    // Any program answers --version, and one number is as parsable as
    // another. Taking one from a program that is not the daemon would decide
    // whether a read-only export is served.
    #[test]
    fn another_programs_version_is_not_read() {
        // A second word that parses as a version is the case that tells the
        // two implementations apart: without the daemon's name as the anchor,
        // this reads as 1.36. The coreutils line below does not, because its
        // second word is "(GNU".
        assert_eq!(parse_version("busybox 1.36.1"), None);
        assert_eq!(parse_version("true (GNU coreutils) 9.4"), None);
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("virtiofsd"), None);
    }

    // The threshold is a version comparison, and only the CI step exercised
    // it, in the refusing direction alone.
    #[test]
    fn readonly_is_enforced_from_1_11() {
        assert!(!enforces_readonly(Some((1, 10))));
        assert!(enforces_readonly(Some((1, 11))));
        assert!(enforces_readonly(Some((1, 14))));
        assert!(enforces_readonly(Some((2, 0))));
        assert!(!enforces_readonly(None), "an unknown version is not proof");
    }

    // The message is the only place a user learns where to put the binary.
    // Asserting on it rather than on a search keeps the case from depending
    // on whether the host running the tests has a daemon installed.
    #[test]
    fn a_missing_daemon_names_the_search_path() {
        let message = not_found().to_string();
        assert!(message.contains("--virtiofsd"), "{message}");
        assert!(message.contains("HVI_VIRTIOFSD"), "{message}");
        assert!(message.contains(WELL_KNOWN[0]), "{message}");
    }
}

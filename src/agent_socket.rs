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

//! The host end of the agent bridge, the Unix socket `--agent-sock` names.
//!
//! A connection to this socket is a session with the guest agent, so the
//! socket admits the VMM's own user and nobody else. Three parts hold that:
//!
//! - [`bind`](crate::agent_socket::bind) replaces nothing but a stale socket,
//!   and sets the node to mode 0600.
//! - [`PeerGate`](crate::agent_socket::PeerGate) closes a connection whose peer
//!   runs as another uid.
//! - [`Node::remove`](crate::agent_socket::Node::remove) unlinks the node on a
//!   clean stop, if the path still names it.
// The socket path is the operator's, given on the command line; see
// clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::fs::{Metadata, Permissions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// The mode of the socket node once [`bind`] returns.
pub const MODE: u32 = 0o600;

/// An agent socket [`bind`] set up.
pub struct Bound {
    /// The non-blocking listener the bridge accepts on.
    pub listener: UnixListener,
    /// The check the bridge runs on every accepted connection.
    pub gate: PeerGate,
    /// The node at the socket path, for [`Node::remove`] on a clean stop.
    pub node: Node,
}

/// Binds the agent socket at `path`, non-blocking, with the node at [`MODE`].
///
/// What is at `path` decides whether it binds:
///
/// - Nothing. It binds there.
/// - A socket that refuses a connection, such as one left by a VMM that
///   crashed. It removes the socket and binds in its place.
/// - A socket that accepts a connection. Another process is serving it, so the
///   bind is refused.
/// - Anything else, a symbolic link included. The bind is refused and the node
///   is left as it was.
///
/// On macOS, bind(2) follows a symbolic link at `path` and creates the socket
/// at its target. The node at `path` is checked again after the bind, so a
/// link planted between the two checks fails the boot as well.
///
/// Call it before confinement. Seatbelt denies creating the socket, and the
/// Linux filters trap `socket`, `bind` and `geteuid`. The uid the gate admits
/// is read here for that reason.
///
/// # Errors
///
/// Returns an error naming `path` when it refuses what is there, or when the
/// bind or the chmod fails.
pub fn bind(path: &str) -> io::Result<Bound> {
    let path = Path::new(path);
    clear(path)?;
    let listener = UnixListener::bind(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot bind Unix socket {}: {e}", path.display()),
        )
    })?;
    let meta = path.symlink_metadata()?;
    if !meta.file_type().is_socket() {
        return Err(refusal(path, &format!("it is {}", kind(&meta))));
    }
    // chmod(2) follows a symbolic link. The lstat above found the socket, and
    // only a user who can write the directory could replace it since. That
    // user can remove the socket whatever its mode.
    std::fs::set_permissions(path, Permissions::from_mode(MODE))?;
    listener.set_nonblocking(true)?;
    Ok(Bound {
        listener,
        // SAFETY: geteuid has no preconditions and cannot fail.
        gate: PeerGate::new(unsafe { libc::geteuid() }),
        node: Node {
            path: path.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
        },
    })
}

/// Removes a stale socket at `path`, and refuses anything else that is there.
fn clear(path: &Path) -> io::Result<()> {
    let meta = match path.symlink_metadata() {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !meta.file_type().is_socket() {
        return Err(refusal(path, &format!("it is {}", kind(&meta))));
    }
    match listening(path) {
        Ok(true) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "refusing to bind {}: another process is listening on it",
                path.display()
            ),
        )),
        Ok(false) => std::fs::remove_file(path),
        Err(e) => Err(refusal(
            path,
            &format!("cannot tell whether a process is listening on it ({e})"),
        )),
    }
}

/// Returns whether a process is listening on the socket at `path`.
///
/// The connect does not block. On Linux a blocking connect waits while the
/// listener's backlog is full, and the boot would wait with it. A full
/// backlog therefore counts as listening.
fn listening(path: &Path) -> io::Result<bool> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: sockaddr_un is plain old data, and all zeroes is a valid value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path is too long for a Unix socket",
        ));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sockaddr_un>();
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = len as u8;
    }
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a socket this function created, and nothing else owns
    // it.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: setting the status and descriptor flags of a descriptor we own.
    let flagged = unsafe {
        libc::fcntl(sock.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) == 0
            && libc::fcntl(sock.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) == 0
    };
    if !flagged {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `addr` is a valid sockaddr_un of `len` bytes.
    let rc = unsafe {
        libc::connect(
            sock.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast(),
            len as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ECONNREFUSED) => Ok(false),
        Some(libc::EAGAIN | libc::EINPROGRESS) => Ok(true),
        _ => Err(err),
    }
}

/// Returns an error saying that hvi will not bind at `path`, and why.
fn refusal(path: &Path, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("refusing to bind {}: {why}", path.display()),
    )
}

/// Returns what `meta` describes, for a refusal of anything but a socket.
fn kind(meta: &Metadata) -> &'static str {
    let kind = meta.file_type();
    if kind.is_symlink() {
        "a symbolic link"
    } else if kind.is_dir() {
        "a directory"
    } else if kind.is_file() {
        "a regular file"
    } else {
        "not a socket"
    }
}

/// The filesystem node [`bind`] created, by path, device and inode.
pub struct Node {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl Node {
    /// Removes the node if the path still names it, and leaves anything that
    /// has replaced it.
    ///
    /// Call it on a clean stop, and only where the process may still stat and
    /// unlink the path. Confinement allows neither: Seatbelt denies both
    /// outside a writable share, and the Linux filters trap both. A node left
    /// behind is stale, and the next [`bind`] at the path replaces it.
    pub fn remove(&self) {
        if let Ok(meta) = self.path.symlink_metadata() {
            if meta.dev() == self.dev && meta.ino() == self.ino {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

/// Admits a connection only when its peer runs as the VMM's effective uid.
pub struct PeerGate {
    /// The one uid admitted.
    uid: u32,
    /// Whether a refusal has been reported on stderr.
    reported: bool,
}

impl PeerGate {
    /// Returns a gate that admits peers running as `uid`.
    fn new(uid: u32) -> Self {
        PeerGate {
            uid,
            reported: false,
        }
    }

    /// Returns whether the peer of `stream` may use the bridge.
    ///
    /// The caller closes a refused connection. The first refusal is reported
    /// on stderr and later ones are not, so a client that retries cannot fill
    /// the log.
    pub fn admits(&mut self, stream: &UnixStream) -> bool {
        let who = match peer_uid(stream) {
            Ok(uid) if uid == self.uid => return true,
            Ok(uid) => format!("a peer running as uid {uid}"),
            Err(e) => format!("a peer whose uid cannot be read ({e})"),
        };
        if !self.reported {
            self.reported = true;
            eprintln!(
                "[hvi] agent socket: refused {who}; only uid {} may connect. \
                 Later refusals are not reported.",
                self.uid
            );
        }
        false
    }
}

/// Returns the effective uid of the process at the other end of `stream`.
#[cfg(target_os = "macos")]
pub(crate) fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: a live socket descriptor and two valid out-pointers.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

/// Returns the effective uid of the process at the other end of `stream`.
///
/// This is the uid the peer had when it connected. The `vmm` seccomp filter
/// allows `getsockopt` for `SOL_SOCKET` and `SO_PEERCRED` alone.
#[cfg(target_os = "linux")]
pub(crate) fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a live socket descriptor, and an out-buffer of the length passed
    // with it.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns an empty directory of the caller's own under the temp dir, and
    /// the socket path inside it.
    ///
    /// The directory name is short, because macOS caps a socket path at 104
    /// bytes and its temp dir is long.
    fn scratch(name: &str) -> (PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("hvi-as-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("agent.sock").to_str().unwrap().to_string();
        (dir, sock)
    }

    #[test]
    fn a_stale_socket_is_replaced() {
        let (dir, sock) = scratch("stale");
        drop(UnixListener::bind(&sock).unwrap());

        let bound = bind(&sock);
        let connects = UnixStream::connect(&sock).is_ok();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(bound.is_ok(), "{:?}", bound.err());
        assert!(connects, "the new listener does not accept");
    }

    #[test]
    fn a_live_listener_is_refused() {
        let (dir, sock) = scratch("live");
        let other = UnixListener::bind(&sock).unwrap();

        let err = bind(&sock).err();
        let still_there = UnixStream::connect(&sock).is_ok();
        drop(other);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::AddrInUse));
        assert!(still_there, "the other process lost its socket");
    }

    // A blocking connect to this listener would wait for a free slot in its
    // backlog for as long as nobody accepts.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_listener_with_a_full_backlog_is_refused_without_waiting() {
        let (dir, sock) = scratch("backlog");
        let other = UnixListener::bind(&sock).unwrap();
        // SAFETY: a listening socket we own. A backlog of 0 admits one
        // pending connection on Linux.
        assert_eq!(unsafe { libc::listen(other.as_raw_fd(), 0) }, 0);
        let _pending = UnixStream::connect(&sock).unwrap();

        let err = bind(&sock).err();
        drop(other);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::AddrInUse));
    }

    // On macOS, a bind through this link would create the socket at the
    // link's target.
    #[test]
    fn a_symlink_is_refused_and_kept() {
        let (dir, sock) = scratch("link");
        let target = dir.join("target");
        std::os::unix::fs::symlink(&target, &sock).unwrap();

        let err = bind(&sock).err();
        let link_kept = Path::new(&sock).symlink_metadata().unwrap().is_symlink();
        let created = target.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(err.unwrap().to_string().contains("symbolic link"));
        assert!(link_kept && !created);
    }

    #[test]
    fn a_regular_file_is_refused_and_kept() {
        let (dir, sock) = scratch("file");
        std::fs::write(&sock, "operator data").unwrap();

        let err = bind(&sock).err();
        let kept = std::fs::read_to_string(&sock).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(err.unwrap().to_string().contains("regular file"));
        assert_eq!(kept, "operator data");
    }

    #[test]
    fn the_socket_is_private_to_its_user() {
        let (dir, sock) = scratch("mode");
        let bound = bind(&sock).unwrap();
        let mode = Path::new(&sock).symlink_metadata().unwrap().mode();
        drop(bound);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(mode & 0o777, MODE, "socket mode {mode:o}");
    }

    #[test]
    fn the_gate_admits_its_own_uid_and_refuses_another() {
        let (ours, _peer) = UnixStream::pair().unwrap();
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(peer_uid(&ours).unwrap(), uid);
        assert!(PeerGate::new(uid).admits(&ours));
        let mut other = PeerGate::new(uid.wrapping_add(1));
        assert!(!other.admits(&ours));
        assert!(!other.admits(&ours), "a second refusal must still refuse");
    }

    #[test]
    fn remove_takes_its_own_node_and_leaves_a_replacement() {
        let (dir, sock) = scratch("remove");
        let first = bind(&sock).unwrap();
        first.node.remove();
        let removed = Path::new(&sock).symlink_metadata().is_err();

        let second = bind(&sock).unwrap();
        // The first VMM's teardown runs after a second one bound the path.
        first.node.remove();
        let kept = Path::new(&sock).symlink_metadata().is_ok();
        drop(second);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(removed, "the node was left behind");
        assert!(kept, "the replacement was removed");
    }
}

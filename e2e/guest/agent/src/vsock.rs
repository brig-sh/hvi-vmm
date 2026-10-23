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

//! A listening vsock socket.
//!
//! The standard library has no `AF_VSOCK`, so this makes the few calls a
//! listener needs through `libc`.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// A vsock stream socket listening on one port of any CID.
pub(crate) struct Listener {
    /// The listening socket.
    fd: OwnedFd,
}

impl Listener {
    /// Binds a listener to `port`.
    ///
    /// # Errors
    ///
    /// Errors if the socket cannot be created, bound or put in the listening
    /// state.
    pub(crate) fn bind(port: u32) -> io::Result<Self> {
        // SAFETY: socket takes plain values and returns a new descriptor or -1.
        let raw =
            unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a descriptor that socket just returned, owned by
        // nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: an all-zero sockaddr_vm is a valid value of the type.
        let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        address.svm_port = port;
        address.svm_cid = libc::VMADDR_CID_ANY;
        // SAFETY: `address` is a valid sockaddr_vm and the length is its size.
        let bound = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(address).cast(),
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if bound != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: listen takes a descriptor this listener owns and a backlog.
        if unsafe { libc::listen(fd.as_raw_fd(), 16) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Returns the next connection as a [`File`] that reads and writes the
    /// socket, waiting until one arrives.
    ///
    /// # Errors
    ///
    /// Errors if `accept4` fails. An interrupted call is retried.
    pub(crate) fn accept(&self) -> io::Result<File> {
        loop {
            // SAFETY: a null address and length ask accept4 for the connection
            // alone.
            let raw = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if raw >= 0 {
                // SAFETY: `raw` is a descriptor accept4 just returned, owned by
                // nothing else.
                return Ok(File::from(unsafe { OwnedFd::from_raw_fd(raw) }));
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

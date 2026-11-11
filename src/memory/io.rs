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

//! Reads and writes between a host file and guest RAM, with no host buffer.
//!
//! The calls take guest RAM as [`VolatileSlice`]s, as [`GuestRam::slice`]
//! returns them. A slice holds a pointer and a length, so the kernel reads or
//! writes the guest's bytes while the guest runs and no `&[u8]` or `&mut [u8]`
//! to them is made. Such a reference would claim immutable or exclusive access
//! that does not hold.
//!
//! [`GuestRam::slice`]: super::GuestRam::slice

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

use vm_memory::VolatileSlice;

/// The most buffers one `preadv` or `pwritev` takes, past which the kernel
/// fails the call with `EINVAL`.
#[cfg(target_os = "linux")]
pub(crate) const IOV_MAX: usize = libc::UIO_MAXIOV as usize;
/// The most buffers one `preadv` or `pwritev` takes.
#[cfg(target_os = "macos")]
pub(crate) const IOV_MAX: usize = libc::IOV_MAX as usize;

/// Reads from `file` at `offset` into `bufs` in order with one `preadv`.
///
/// It returns the number of bytes read. It reads into the first [`IOV_MAX`]
/// buffers at most. As with `FileExt::read_at`, a count short of the buffers'
/// length is not an error. An empty `bufs` reads nothing and makes no call. A
/// call that a signal interrupts is made again.
///
/// # Errors
///
/// Errors with what `preadv` returned, or with `EINVAL` when `offset` does not
/// fit in `off_t`, as the kernel answers a negative offset.
pub(crate) fn read_vectored_at_volatile(
    file: &File,
    bufs: &[VolatileSlice<'_>],
    offset: u64,
) -> io::Result<usize> {
    let guards: Vec<_> = bufs
        .iter()
        .take(IOV_MAX)
        .map(VolatileSlice::ptr_guard_mut)
        .collect();
    let iov: Vec<_> = guards
        .iter()
        .map(|guard| libc::iovec {
            iov_base: guard.as_ptr().cast(),
            iov_len: guard.len(),
        })
        .collect();
    vectored(&iov, offset, |count, offset| {
        // SAFETY: each iovec covers the bytes of a `VolatileSlice`, which are
        // valid for writes for the slice's lifetime, and its guard is alive.
        // The kernel writes them without a Rust reference to them.
        unsafe { libc::preadv(file.as_raw_fd(), iov.as_ptr(), count, offset) }
    })
}

/// Writes `bufs` in order to `file` at `offset` with one `pwritev`.
///
/// It returns the number of bytes written. It writes from the first [`IOV_MAX`]
/// buffers at most. As with `FileExt::write_at`, a count short of the buffers'
/// length is not an error. An empty `bufs` writes nothing and makes no call. A
/// call that a signal interrupts is made again.
///
/// # Errors
///
/// Errors with what `pwritev` returned, or with `EINVAL` when `offset` does not
/// fit in `off_t`, as the kernel answers a negative offset.
pub(crate) fn write_vectored_at_volatile(
    file: &File,
    bufs: &[VolatileSlice<'_>],
    offset: u64,
) -> io::Result<usize> {
    let guards: Vec<_> = bufs
        .iter()
        .take(IOV_MAX)
        .map(VolatileSlice::ptr_guard)
        .collect();
    let iov: Vec<_> = guards
        .iter()
        .map(|guard| libc::iovec {
            iov_base: guard.as_ptr().cast_mut().cast(),
            iov_len: guard.len(),
        })
        .collect();
    vectored(&iov, offset, |count, offset| {
        // SAFETY: each iovec covers the bytes of a `VolatileSlice`, which are
        // valid for reads for the slice's lifetime, and its guard is alive. The
        // kernel reads them without a Rust reference to them.
        unsafe { libc::pwritev(file.as_raw_fd(), iov.as_ptr(), count, offset) }
    })
}

/// Makes `call` with the length of `iov` and `offset` until no signal
/// interrupts it.
///
/// It returns the call's count. An empty `iov` returns 0 with no call.
fn vectored(
    iov: &[libc::iovec],
    offset: u64,
    call: impl Fn(libc::c_int, libc::off_t) -> libc::ssize_t,
) -> io::Result<usize> {
    if iov.is_empty() {
        return Ok(0);
    }
    let count = libc::c_int::try_from(iov.len()).expect("IOV_MAX should fit in a c_int");
    // The kernel answers a negative offset with EINVAL, so an offset past
    // `off_t` gets the same answer.
    let offset =
        libc::off_t::try_from(offset).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    loop {
        if let Ok(done) = usize::try_from(call(count, offset)) {
            return Ok(done);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. These tests make their own
// files.
#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::memory::GuestRam;

    const BASE: u64 = 0x1000_0000;

    /// Returns a file of its own holding `contents`, unlinked at once.
    fn file_with(contents: &[u8]) -> File {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("hvi-io-{}-{n}.img", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file
    }

    #[test]
    fn read_fills_the_buffers_in_order() {
        let file = file_with(b"0123456789");
        let ram = GuestRam::from_ranges(&[(BASE, 0x1000)]);
        let bufs = [
            ram.slice(BASE + 0x100, 3).unwrap(),
            ram.slice(BASE, 0).unwrap(),
            ram.slice(BASE + 0x10, 4).unwrap(),
        ];

        assert_eq!(read_vectored_at_volatile(&file, &bufs, 2).unwrap(), 7);

        let mut got = [0; 4];
        ram.read(BASE + 0x100, &mut got[..3]).unwrap();
        assert_eq!(&got[..3], b"234");
        ram.read(BASE + 0x10, &mut got).unwrap();
        assert_eq!(&got, b"5678");
    }

    #[test]
    fn write_takes_the_buffers_in_order() {
        let file = file_with(&[b'.'; 10]);
        let ram = GuestRam::from_ranges(&[(BASE, 0x1000)]);
        ram.write(BASE + 0x200, b"ab").unwrap();
        ram.write(BASE + 0x20, b"cde").unwrap();
        let bufs = [
            ram.slice(BASE + 0x200, 2).unwrap(),
            ram.slice(BASE + 0x20, 3).unwrap(),
        ];

        assert_eq!(write_vectored_at_volatile(&file, &bufs, 4).unwrap(), 5);

        let mut got = [0; 10];
        std::os::unix::fs::FileExt::read_exact_at(&file, &mut got, 0).unwrap();
        assert_eq!(&got, b"....abcde.");
    }

    // A call with more buffers than the kernel takes would fail with EINVAL, so
    // the call fills the first IOV_MAX and leaves the rest.
    #[test]
    fn read_takes_at_most_iov_max_buffers() {
        let file = file_with(&[7; IOV_MAX + 8]);
        let ram = GuestRam::from_ranges(&[(BASE, 0x4000)]);
        let bufs: Vec<_> = (0..IOV_MAX as u64 + 8)
            .map(|n| ram.slice(BASE + n, 1).unwrap())
            .collect();

        assert_eq!(read_vectored_at_volatile(&file, &bufs, 0).unwrap(), IOV_MAX);
        assert_eq!(
            write_vectored_at_volatile(&file, &bufs, 0).unwrap(),
            IOV_MAX
        );
    }

    // Each file is open in the mode that fails the call with EBADF, so a call
    // made anyway would return an error.
    #[test]
    fn empty_buffers_make_no_call() {
        let path = std::env::temp_dir().join(format!("hvi-io-empty-{}.img", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let write_only = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let read_only = File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(read_vectored_at_volatile(&write_only, &[], 0).unwrap(), 0);
        assert_eq!(write_vectored_at_volatile(&read_only, &[], 0).unwrap(), 0);
    }

    #[test]
    fn offset_past_off_t_is_refused() {
        let file = file_with(b"x");
        let ram = GuestRam::from_ranges(&[(BASE, 0x1000)]);
        let bufs = [ram.slice(BASE, 1).unwrap()];
        for offset in [1 << 63, u64::MAX] {
            let error = read_vectored_at_volatile(&file, &bufs, offset).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINVAL), "{error}");
            let error = write_vectored_at_volatile(&file, &bufs, offset).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINVAL), "{error}");
        }
    }
}

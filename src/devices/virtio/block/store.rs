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

//! The backing store a disk's worker runs requests against.

use std::fmt;
use std::fs::File;
use std::io;

use vm_memory::VolatileSlice;

use crate::memory;

/// The backing store a [`Worker`](super::worker::Worker) runs requests against.
///
/// It is the backing file, or in a test a store whose calls can be held or cut
/// short. Its reads and writes take the request's buffers in guest RAM.
pub(crate) trait BackingStore: Send + 'static {
    /// Reads from `offset` into `bufs` in order with one call.
    ///
    /// It returns the number of bytes read.
    fn read_vectored_at_volatile(
        &self,
        bufs: &[VolatileSlice<'_>],
        offset: u64,
    ) -> io::Result<usize>;

    /// Writes `bufs` in order at `offset` with one call.
    ///
    /// It returns the number of bytes written.
    fn write_vectored_at_volatile(
        &self,
        bufs: &[VolatileSlice<'_>],
        offset: u64,
    ) -> io::Result<usize>;

    /// Makes the data written so far durable.
    fn sync_data(&self) -> io::Result<()>;

    /// Reads from `offset` until `bufs` are full.
    ///
    /// A short read is followed by another from where it stopped, inside a
    /// buffer too.
    ///
    /// # Errors
    ///
    /// Errors with `UnexpectedEof` when a read returns no bytes before `bufs`
    /// are full, or with the read's own error. The error carries the number of
    /// bytes read before it.
    fn read_exact_vectored_at_volatile(
        &self,
        bufs: &[VolatileSlice<'_>],
        offset: u64,
    ) -> Result<(), TransferError> {
        transfer_all(bufs, offset, io::ErrorKind::UnexpectedEof, |left, at| {
            self.read_vectored_at_volatile(left, at)
        })
    }

    /// Writes all of `bufs` at `offset`.
    ///
    /// A short write is followed by another from where it stopped, inside a
    /// buffer too.
    ///
    /// # Errors
    ///
    /// Errors with `WriteZero` when a write returns no bytes before `bufs` are
    /// written, or with the write's own error. The error carries the number of
    /// bytes written before it.
    fn write_all_vectored_at_volatile(
        &self,
        bufs: &[VolatileSlice<'_>],
        offset: u64,
    ) -> Result<(), TransferError> {
        transfer_all(bufs, offset, io::ErrorKind::WriteZero, |left, at| {
            self.write_vectored_at_volatile(left, at)
        })
    }
}

impl BackingStore for File {
    fn read_vectored_at_volatile(
        &self,
        bufs: &[VolatileSlice<'_>],
        offset: u64,
    ) -> io::Result<usize> {
        memory::read_vectored_at_volatile(self, bufs, offset)
    }

    fn write_vectored_at_volatile(
        &self,
        bufs: &[VolatileSlice<'_>],
        offset: u64,
    ) -> io::Result<usize> {
        memory::write_vectored_at_volatile(self, bufs, offset)
    }

    fn sync_data(&self) -> io::Result<()> {
        File::sync_data(self)
    }
}

/// The error of a read or write that ended before it moved every byte.
#[derive(Debug)]
pub(crate) struct TransferError {
    /// The number of bytes moved before the error, from the first buffer on.
    pub(crate) moved: u64,
    /// What ended the read or write.
    pub(crate) source: io::Error,
}

impl From<io::Error> for TransferError {
    /// Returns the error of a call that moved no bytes.
    fn from(source: io::Error) -> Self {
        Self { moved: 0, source }
    }
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transfer stopped after {} bytes", self.moved)
    }
}

impl std::error::Error for TransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Calls `call` with the part of `bufs` not yet moved and its offset in the
/// store, starting at `offset`, until every byte of `bufs` is moved.
///
/// An empty buffer is skipped, so a call is never given buffers that are all
/// empty, and a count of 0 means that the store moved nothing.
///
/// # Errors
///
/// Errors with `stalled` when a call moves no bytes before every byte is moved,
/// or with the call's own error. The error carries the number of bytes the
/// calls before it moved.
fn transfer_all<'a>(
    bufs: &[VolatileSlice<'a>],
    offset: u64,
    stalled: io::ErrorKind,
    mut call: impl FnMut(&[VolatileSlice<'a>], u64) -> io::Result<usize>,
) -> Result<(), TransferError> {
    let mut left: Vec<_> = bufs.iter().filter(|buf| !buf.is_empty()).copied().collect();
    let mut left = left.as_mut_slice();
    let mut moved = 0;
    while !left.is_empty() {
        match call(left, offset + moved) {
            Ok(0) => {
                let source = stalled.into();
                return Err(TransferError { moved, source });
            }
            Ok(count) => {
                moved += count as u64;
                advance_slices(&mut left, count);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => return Err(TransferError { moved, source }),
        }
    }
    Ok(())
}

/// Drops the first `count` bytes of `bufs`, as `IoSliceMut::advance_slices`
/// does.
///
/// # Panics
///
/// Panics if `bufs` hold fewer than `count` bytes.
fn advance_slices(bufs: &mut &mut [VolatileSlice<'_>], mut count: usize) {
    let mut whole = 0;
    for buf in bufs.iter() {
        if count < buf.len() {
            break;
        }
        count -= buf.len();
        whole += 1;
    }
    *bufs = &mut std::mem::take(bufs)[whole..];
    match bufs.first_mut() {
        Some(first) => {
            *first = first
                .offset(count)
                .expect("a count inside the buffer should advance it");
        }
        None => assert_eq!(count, 0, "a count should not pass the end of the buffers"),
    }
}

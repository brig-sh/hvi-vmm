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

//! A guest's block request, as a worker parses it from a descriptor chain.

use std::io;

use vm_memory::VolatileSlice;

use super::device::SECTOR;
use super::store::BackingStore;
use super::worker::Worker;
use crate::devices::virtio::DescriptorChain;

/// virtio-blk request types.
pub(super) const VIRTIO_BLK_T_IN: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_IN; // read disk -> guest
pub(super) const VIRTIO_BLK_T_OUT: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_OUT; // guest -> write disk
pub(super) const VIRTIO_BLK_T_FLUSH: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_FLUSH; // flush the cache
pub(super) const VIRTIO_BLK_T_GET_ID: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_GET_ID; // read the serial

/// virtio-blk status byte.
pub(super) const VIRTIO_BLK_S_OK: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_OK as u8;
pub(super) const VIRTIO_BLK_S_IOERR: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_IOERR as u8;
/// The status of a request whose type the device does not implement (virtio
/// 1.2, 5.2.6).
///
/// Answering `S_OK` instead would tell the driver that a request it depends on,
/// such as a discard, did its work when it did nothing at all.
pub(super) const VIRTIO_BLK_S_UNSUPP: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_UNSUPP as u8;

/// A request taken off the ring, as the worker parsed it under the lock, with
/// its buffers in the guest RAM that `'a` borrows.
pub(super) struct Request<'a> {
    /// The head of the request's chain, which its used entry names.
    pub(super) head: u16,
    /// The guest address of the status byte, or `None` when the chain is too
    /// short to carry a request or its walk did not end.
    pub(super) status: Option<u64>,
    /// The request type, a `VIRTIO_BLK_T_*` value.
    pub(super) kind: u32,
    /// The sector the request starts at.
    pub(super) sector: u64,
    /// What the request asks of the backing store.
    pub(super) work: Work<'a>,
}

/// What a request asks of the backing store.
pub(super) enum Work<'a> {
    /// A read from `offset` into the request's buffers in guest RAM.
    Read {
        /// The byte offset in the backing store.
        offset: u64,
        /// The buffers, in chain order.
        buffers: Vec<VolatileSlice<'a>>,
    },
    /// A write of the request's buffers in guest RAM at `offset`.
    Write {
        /// The byte offset in the backing store.
        offset: u64,
        /// The buffers, in chain order.
        buffers: Vec<VolatileSlice<'a>>,
    },
    /// A flush of the writes so far.
    Flush,
    /// The serial, written into the guest segments.
    GetId {
        /// The guest segments, as address and length.
        segments: Vec<(u64, u32)>,
    },
    /// A request answered with a status and no call to the backing store.
    Answer(u8),
    /// A request refused for the reason given, which fails with
    /// `VIRTIO_BLK_S_IOERR`.
    Refused(String),
}

impl Request<'_> {
    /// Returns a request whose chain carries none.
    pub(super) fn malformed(head: u16) -> Self {
        Self {
            head,
            status: None,
            kind: 0,
            sector: 0,
            work: Work::Answer(VIRTIO_BLK_S_IOERR),
        }
    }

    /// Returns the number of data bytes the request moves between the guest and
    /// the backing store.
    pub(super) fn data_len(&self) -> u64 {
        match &self.work {
            Work::Read { buffers, .. } | Work::Write { buffers, .. } => {
                buffers.iter().map(|buffer| buffer.len() as u64).sum()
            }
            _ => 0,
        }
    }
}

impl<F: BackingStore> Worker<F> {
    /// Walks `chain` and parses the request it carries from guest RAM.
    ///
    /// The first readable segment is the 16-byte header (type, reserved,
    /// sector), the last writable segment is the status byte, and the segments
    /// between carry data. The walk is bounded by the largest size the queue
    /// takes, so the request holds at most that many buffers.
    pub(super) fn parse(&self, mut chain: DescriptorChain<'_>) -> Request<'_> {
        let head = chain.head_index();
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        for descriptor in chain.by_ref() {
            let segment = (descriptor.addr().0, descriptor.len());
            if descriptor.is_write_only() {
                writable.push(segment);
            } else {
                readable.push(segment);
            }
        }
        let (Some(&(header, _)), Some((&(status, _), data_in))) =
            (readable.first(), writable.split_last())
        else {
            return Request::malformed(head);
        };
        if !chain.is_complete() {
            return Request::malformed(head);
        }
        let fields = header
            .checked_add(8)
            .ok_or_else(|| other("the header's address overflows"))
            .and_then(|sector| Ok((self.ram.read_u32(header)?, self.ram.read_u64(sector)?)));
        let (kind, sector) = match fields {
            Ok(fields) => fields,
            Err(e) => {
                return Request {
                    head,
                    status: Some(status),
                    kind: 0,
                    sector: 0,
                    work: Work::Refused(e.to_string()),
                };
            }
        };
        let work = self
            .work(kind, sector, &readable[1..], data_in)
            .unwrap_or_else(|e| Work::Refused(e.to_string()));
        Request {
            head,
            status: Some(status),
            kind,
            sector,
            work,
        }
    }

    /// Returns what a request of type `kind` at `sector` asks of the backing
    /// store, with its data in the guest segments `data_out` and room for what
    /// it returns in `data_in`.
    ///
    /// # Errors
    ///
    /// Errors when a read or write falls outside the disk, or one of its
    /// segments outside guest RAM.
    pub(super) fn work(
        &self,
        kind: u32,
        sector: u64,
        data_out: &[(u64, u32)],
        data_in: &[(u64, u32)],
    ) -> io::Result<Work<'_>> {
        Ok(match kind {
            VIRTIO_BLK_T_IN => {
                let (offset, buffers) = self.buffers(sector, data_in)?;
                Work::Read { offset, buffers }
            }
            // The guest was offered VIRTIO_BLK_F_RO. A write that arrives
            // anyway fails.
            VIRTIO_BLK_T_OUT if self.read_only => Work::Answer(VIRTIO_BLK_S_IOERR),
            // Nothing was written, so there is nothing to make durable.
            VIRTIO_BLK_T_FLUSH if self.read_only => Work::Answer(VIRTIO_BLK_S_OK),
            VIRTIO_BLK_T_OUT => {
                let (offset, buffers) = self.buffers(sector, data_out)?;
                Work::Write { offset, buffers }
            }
            VIRTIO_BLK_T_FLUSH => Work::Flush,
            VIRTIO_BLK_T_GET_ID => Work::GetId {
                segments: data_in.to_vec(),
            },
            // Every request type this device does not implement, discard and
            // write-zeroes among them. None of them were negotiated, but a
            // driver that sends one anyway must learn that nothing happened.
            _ => Work::Answer(VIRTIO_BLK_S_UNSUPP),
        })
    }

    /// Returns the byte offset of a read or write of `segments` at `sector`,
    /// and the segments as buffers in guest RAM.
    ///
    /// Every segment is checked before the request reaches the backing store,
    /// so a request with one segment outside guest RAM moves no byte. A
    /// zero-length segment is checked too.
    ///
    /// # Errors
    ///
    /// Errors when the request falls outside the disk, or a segment outside
    /// guest RAM.
    pub(super) fn buffers(
        &self,
        sector: u64,
        segments: &[(u64, u32)],
    ) -> io::Result<(u64, Vec<VolatileSlice<'_>>)> {
        let total = segments.iter().map(|&(_, len)| u64::from(len)).sum();
        let offset = self.byte_range(sector, total)?;
        let buffers = segments
            .iter()
            .map(|&(addr, len)| self.ram.slice(addr, len as usize))
            .collect::<io::Result<_>>()?;
        Ok((offset, buffers))
    }

    /// Returns the byte offset of `sector`, after checking that the whole
    /// `len`-byte access falls inside the capacity advertised in config space.
    ///
    /// The guest picks `sector`, so this is what keeps a request inside the
    /// disk it was given. Without it a write past the end would extend the
    /// backing file, and the multiplication would wrap in release builds.
    pub(super) fn byte_range(&self, sector: u64, len: u64) -> std::io::Result<u64> {
        let base = sector
            .checked_mul(SECTOR)
            .ok_or_else(|| other("sector offset overflows"))?;
        let end = base
            .checked_add(len)
            .ok_or_else(|| other("request length overflows"))?;
        if end > self.capacity_sectors * SECTOR {
            return Err(other(format!(
                "request at sector {sector} (+{len} bytes) is past the {} sector capacity",
                self.capacity_sectors
            )));
        }
        Ok(base)
    }
}

pub(super) fn other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

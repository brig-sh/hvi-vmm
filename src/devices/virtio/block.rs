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

//! A virtio-blk device over virtio-mmio, and the worker thread that serves it.
//!
//! Because this VMM implements the device backend, every block request the
//! guest issues passes through our code by construction: servicing the
//! virtqueue and capturing the guest's disk I/O are the same act (see the
//! `[virtio-blk]` log lines).
//!
//! Each disk has one queue, which a worker thread of its own serves. The
//! [`VirtioBlk`] behind the transport holds what the registers read, and a
//! notification only wakes the worker. The two share the queue, its interrupt
//! and the sink behind one lock, which is never held across a call to the
//! backing file. The worker takes a request off the ring under the lock, makes
//! its call with no lock held, and completes it under the lock, unless a reset
//! took the queue in between. A reset waits for the call in flight, so nothing
//! reaches guest RAM for a request of the reset device after the STATUS write
//! returns. One worker serves the requests in the order the ring holds them.
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this
// VMM's own.
#![allow(clippy::disallowed_methods)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

#[cfg(target_os = "linux")]
use vmm_sys_util::eventfd::EventFd;

use crate::config;
use crate::memory::GuestRam;
use crate::LOG_PREFIX;

use crate::devices::virtio::mmio::Interrupt;
use crate::devices::virtio::wake::WorkerWake;
use crate::devices::virtio::{
    self, read_config_bytes, DescriptorChain, Queue, SinkSlot, QUEUE_MAX_SIZE,
};
use crate::events::{CapturedEvent, Ledger};
use crate::io_threads::HostWork;
use crate::plugin::IoSink;
use crate::sandbox::Thread;
use crate::teardown::StopToken;

/// `VIRTIO_BLK_F_FLUSH`: the guest may issue explicit cache-flush requests.
///
/// With it, an `fsync` in the guest reaches stable storage on the host.
const F_FLUSH: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_FLUSH;
/// `VIRTIO_BLK_F_RO`: the disk is read-only, and Linux marks the guest's block
/// device read-only to match.
const F_RO: u64 = 1 << virtio_bindings::virtio_blk::VIRTIO_BLK_F_RO;

/// virtio-blk request types.
const VIRTIO_BLK_T_IN: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_IN; // read disk -> guest
const VIRTIO_BLK_T_OUT: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_OUT; // guest -> write disk
const VIRTIO_BLK_T_FLUSH: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_FLUSH; // flush the cache
const VIRTIO_BLK_T_GET_ID: u32 = virtio_bindings::virtio_blk::VIRTIO_BLK_T_GET_ID; // read the serial

/// Length of the serial `GET_ID` returns, zero-padded.
pub const SERIAL_LEN: usize = virtio_bindings::virtio_blk::VIRTIO_BLK_ID_BYTES as usize;

/// virtio-blk status byte.
const VIRTIO_BLK_S_OK: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_OK as u8;
const VIRTIO_BLK_S_IOERR: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_IOERR as u8;
/// The device does not implement this request type (virtio 1.2, 5.2.6).
/// Answering `S_OK` instead tells the driver a request it depends on, such as a
/// discard, did its work when it did nothing at all.
const VIRTIO_BLK_S_UNSUPP: u8 = virtio_bindings::virtio_blk::VIRTIO_BLK_S_UNSUPP as u8;

const SECTOR: u64 = 512;

/// A virtio-blk device behind a virtio-mmio transport.
///
/// It holds what the registers read, and the state it shares with its worker,
/// which `take_worker` returns.
pub struct VirtioBlk {
    /// The backing file, until the worker takes it.
    file: Option<File>,
    /// The disk's size in 512-byte sectors.
    capacity_sectors: u64,
    /// The backing file is open read-only, and every write is refused.
    read_only: bool,
    /// What `GET_ID` returns, zero-padded.
    serial: [u8; SERIAL_LEN],
    /// The serial as given, for the ledger.
    serial_text: Arc<str>,
    /// Stable id for this backing file, so a reader can tell two disks apart.
    disk_id: u64,
    /// The state the device shares with its worker.
    shared: Arc<Shared>,
}

/// The state a disk's device and its worker share.
///
/// The state's lock is never held across a call to the backing file. It is
/// taken before the lock of the device's [`Interrupt`], never after it, and
/// after the lock that orders the records, never before it.
struct Shared {
    /// The queue, the sink and the requests in flight.
    state: Mutex<State>,
    /// The condition notified when a request leaves flight and when the vCPUs
    /// stop.
    idle: Condvar,
    /// What wakes the worker.
    wake: WorkerWake,
    /// The lock a thread holds while it moves the pending records to the
    /// ledger, so the worker and the vCPUs' stop add them in the order the
    /// requests completed.
    recording: Mutex<()>,
}

/// The state behind the lock of [`Shared`].
struct State {
    /// The queue and the interrupt, from activation until a reset or the vCPUs'
    /// stop.
    active: Option<Active>,
    /// The sink each request also feeds, when a plugin installed one.
    sink: SinkSlot,
    /// The number of requests taken off the ring whose call to the backing file
    /// has not completed.
    in_flight: u32,
    /// The records of the completed requests that are not in the ledger yet.
    events: Vec<CapturedEvent>,
    /// Whether the vCPUs have stopped, after which the queue is not served and
    /// a reset does not wait.
    stopping: bool,
}

/// The queue of an activated device, and the interrupt it raises.
struct Active {
    /// The request queue.
    queue: Queue,
    /// The interrupt a completed request raises.
    interrupt: Arc<Interrupt>,
}

impl Shared {
    /// Returns the state of a device the driver has not activated.
    ///
    /// # Errors
    ///
    /// Errors if the worker's wake cannot be made.
    fn new() -> io::Result<Self> {
        Ok(Self {
            state: Mutex::new(State {
                active: None,
                sink: SinkSlot::default(),
                in_flight: 0,
                events: Vec::new(),
                stopping: false,
            }),
            idle: Condvar::new(),
            wake: WorkerWake::new()?,
            recording: Mutex::new(()),
        })
    }

    /// Returns the state, locked, whether or not a panic poisoned the lock.
    ///
    /// A plugin's sink runs under the lock, so a panic there poisons it, and
    /// the vCPUs' stop still has to free a vCPU waiting in a reset.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts serving `queue`, which raises `interrupt`, unless the vCPUs have
    /// stopped.
    fn activate(&self, queue: Option<Queue>, interrupt: Arc<Interrupt>) {
        let mut state = self.lock();
        if !state.stopping {
            state.active = queue.map(|queue| Active { queue, interrupt });
        }
    }

    /// Stops serving the queue, and returns once no request is in flight or the
    /// vCPUs have stopped.
    ///
    /// The worker completes a request in flight only while the queue is served,
    /// so after the wait no request of the reset device reaches guest RAM or
    /// the used ring.
    fn reset(&self) {
        let mut state = self.lock();
        state.active = None;
        while state.in_flight > 0 && !state.stopping {
            state = self
                .idle
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Stops serving the queue for good, and frees a vCPU that waits in
    /// [`reset`](Self::reset).
    ///
    /// The vCPUs' stop calls it, since a vCPU waiting for a slow backing file
    /// would otherwise hold up the stop.
    fn stop(&self) {
        let mut state = self.lock();
        state.stopping = true;
        state.active = None;
        self.idle.notify_all();
    }

    /// Adds the pending records to `ledger`.
    ///
    /// The records leave the state only here, under a lock of their own, so
    /// each is added once and in the order its request completed, whichever
    /// thread adds it. The state's lock is released before the ledger is
    /// called, and both locks before a line about a full ledger is printed.
    fn record_pending(&self, ledger: &Ledger) {
        let recording = self
            .recording
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let events = std::mem::take(&mut self.lock().events);
        let report = ledger.captured_unreported(&events);
        drop(recording);
        report.print();
    }
}

/// The backing store a [`Worker`] runs requests against.
///
/// It is the backing file, or in a test a store whose calls can be held.
pub(crate) trait BackingStore: Send + 'static {
    /// Reads exactly `buf.len()` bytes at `offset`.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;

    /// Writes all of `buf` at `offset`.
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()>;

    /// Makes the data written so far durable.
    fn sync_data(&self) -> io::Result<()>;
}

impl BackingStore for File {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        FileExt::read_exact_at(self, buf, offset)
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        FileExt::write_all_at(self, buf, offset)
    }

    fn sync_data(&self) -> io::Result<()> {
        File::sync_data(self)
    }
}

/// The thread that serves one disk's requests from its backing store.
///
/// It never takes the transport's device lock. It ends the sink's batch and
/// writes what it captured to the ledger itself, after each pass. The vCPUs'
/// stop writes the records still pending then.
pub(crate) struct Worker<F = File> {
    /// The backing store.
    file: F,
    /// The disk's size in 512-byte sectors.
    capacity_sectors: u64,
    /// Whether every write is refused.
    read_only: bool,
    /// What `GET_ID` returns, zero-padded.
    serial: [u8; SERIAL_LEN],
    /// The serial as given, for the ledger.
    serial_text: Arc<str>,
    /// The disk's id, for the sink.
    disk_id: u64,
    /// Whether each request writes a `[virtio-blk]` console line.
    trace: bool,
    /// The guest RAM the queue and the buffers are in.
    ram: Arc<GuestRam>,
    /// The ledger the requests are recorded in.
    ledger: Arc<Ledger>,
    /// The state the worker shares with the device.
    shared: Arc<Shared>,
}

/// A request taken off the ring, as the worker parsed it under the lock.
struct Request {
    /// The head of the request's chain, which its used entry names.
    head: u16,
    /// The guest address of the status byte, or `None` when the chain is too
    /// short to carry a request or its walk did not end.
    status: Option<u64>,
    /// The request type, a `VIRTIO_BLK_T_*` value.
    kind: u32,
    /// The sector the request starts at.
    sector: u64,
    /// What the request asks of the backing store.
    work: Work,
}

/// What a request asks of the backing store.
enum Work {
    /// A read from `offset` into the guest segments.
    Read {
        /// The byte offset in the backing store.
        offset: u64,
        /// The guest segments, as address and length.
        segments: Vec<(u64, u32)>,
    },
    /// A write of `data`, gathered from guest RAM, at `offset`.
    Write {
        /// The byte offset in the backing store.
        offset: u64,
        /// The bytes to write.
        data: Vec<u8>,
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

/// What one pass of the worker captured, and whether the ring has more.
struct Pass {
    /// The console lines of the requests, when tracing is on.
    trace_lines: Vec<String>,
    /// The sink the pass fed, or `None` when it fed none.
    fed: Option<Arc<dyn IoSink>>,
    /// Whether the ring had a chain left when the pass ended.
    more: bool,
}

impl Request {
    /// Returns a request whose chain carries none.
    fn malformed(head: u16) -> Self {
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
    fn data_len(&self) -> u64 {
        match &self.work {
            Work::Read { segments, .. } => segments.iter().map(|&(_, len)| u64::from(len)).sum(),
            Work::Write { data, .. } => data.len() as u64,
            _ => 0,
        }
    }
}

impl VirtioBlk {
    /// Opens `path` read-write as the backing disk, with an empty serial.
    ///
    /// # Errors
    ///
    /// Errors if the file cannot be opened or its length read.
    #[cfg(test)]
    pub(crate) fn open(path: &str) -> std::io::Result<Self> {
        Self::open_as(path, false, "")
    }

    /// Opens `path` as the backing disk, read-only when `read_only` is set, and
    /// answers `GET_ID` with `serial`.
    ///
    /// A read-only disk is opened `O_RDONLY`, so an image the VMM cannot write
    /// still attaches, and the guest is told it is read-only.
    ///
    /// The file is locked for as long as it is open, shared for a read-only
    /// disk and exclusive for a writable one, so two hvi processes never write
    /// one image at once and no hvi writes an image another one reads. One
    /// read-only image can back any number of guests. A writable block device
    /// is opened `O_EXCL` on Linux as well, which claims the device itself and
    /// so holds against another device node for it and against a mount. A
    /// read-only open claims nothing, so a reader through another node is not
    /// held against a writer.
    ///
    /// # Errors
    ///
    /// Errors if `serial` is longer than [`SERIAL_LEN`] bytes, the file cannot
    /// be opened or its length read, a lock on it that this one excludes is
    /// held, or the worker's wake cannot be made.
    pub fn open_as(path: &str, read_only: bool, serial: &str) -> std::io::Result<Self> {
        if serial.len() > SERIAL_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("virtio-blk serial {serial:?} is longer than {SERIAL_LEN} bytes"),
            ));
        }
        let mut id = [0u8; SERIAL_LEN];
        id[..serial.len()].copy_from_slice(serial.as_bytes());
        let block_device = std::fs::metadata(path)?.file_type().is_block_device();
        let mut options = OpenOptions::new();
        options.read(true).write(!read_only);
        #[cfg(target_os = "linux")]
        if block_device && !read_only {
            options.custom_flags(libc::O_EXCL);
        }
        let file = options.open(path).map_err(|e| {
            // O_EXCL is what fails with EBUSY, so the message says what it
            // means rather than what errno it was.
            if block_device && e.raw_os_error() == Some(libc::EBUSY) {
                std::io::Error::new(
                    e.kind(),
                    "the device is claimed elsewhere: open for writing, or mounted",
                )
            } else {
                e
            }
        })?;
        let mut tries = if block_device {
            BLOCK_DEVICE_LOCK_TRIES
        } else {
            1
        };
        loop {
            tries -= 1;
            match lock(&file, read_only) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && tries > 0 => {
                    std::thread::sleep(BLOCK_DEVICE_LOCK_PAUSE);
                }
                taken => break taken?,
            }
        }
        let capacity_sectors = backing_len(&file)? / SECTOR;
        // The backing store is identified across the two processes that care
        // about it without agreeing on a path: hvi may have been given a
        // relative one, and the reader is given its own.
        let disk_id = disk_id(&file.metadata()?);
        Ok(VirtioBlk {
            file: Some(file),
            capacity_sectors,
            read_only,
            serial: id,
            serial_text: Arc::from(serial),
            disk_id,
            shared: Arc::new(Shared::new()?),
        })
    }

    /// Returns whether the disk is read-only.
    #[cfg(test)]
    pub(crate) fn read_only(&self) -> bool {
        self.read_only
    }

    /// Feeds each request to `sink` as well as the ledger.
    pub fn set_io_sink(&self, sink: Arc<dyn IoSink>) {
        self.shared.lock().sink.set(sink);
    }

    /// Returns the worker that serves the disk's queue in `ram` and records
    /// each request in `ledger`, or `None` when it was already taken.
    pub(crate) fn take_worker(
        &mut self,
        ram: &Arc<GuestRam>,
        ledger: &Arc<Ledger>,
    ) -> Option<Worker> {
        Some(Worker {
            file: self.file.take()?,
            capacity_sectors: self.capacity_sectors,
            read_only: self.read_only,
            serial: self.serial,
            serial_text: Arc::clone(&self.serial_text),
            disk_id: self.disk_id,
            trace: std::env::var_os("HVI_BLK_TRACE").is_some(),
            ram: Arc::clone(ram),
            ledger: Arc::clone(ledger),
            shared: Arc::clone(&self.shared),
        })
    }
}

impl<F: BackingStore> Worker<F> {
    /// Queues the worker's thread in `host`, under the `block` filter, with its
    /// hook for the vCPUs' stop.
    ///
    /// The hook frees a vCPU waiting in a reset, and writes the pending
    /// records. The stop may close the ledger before the worker's pass ends, as
    /// when the worker is left running in a slow request.
    pub(crate) fn queue_thread(self, host: &mut HostWork) {
        let shared = Arc::clone(&self.shared);
        let ledger = Arc::clone(&self.ledger);
        host.on_vcpu_stop(move || {
            shared.stop();
            shared.record_pending(&ledger);
        });
        host.spawn("virtio-blk", Thread::Block, move |stop| {
            self.run(&stop);
        });
    }

    /// Serves the queue each time the worker is woken, until the I/O threads'
    /// stop.
    fn run(&self, stop: &StopToken) {
        while self.shared.wake.wait(stop) {
            self.serve();
        }
    }

    /// Serves the requests on the ring a pass at a time, until a pass finds the
    /// ring empty or the queue no longer served.
    ///
    /// After each pass it ends the sink's batch and then writes the records to
    /// the ledger, with no lock held, so a reader that waits on the sink does
    /// not also wait for the ledger. The pass's console lines are written with
    /// no lock held too, so a console nobody reads does not hold up a reset or
    /// the vCPUs' stop.
    ///
    /// It serves nothing once the ledger is closed, which a failed run does
    /// with the worker still running, so no request starts that the ledger
    /// would hold no record of.
    fn serve(&self) {
        loop {
            if self.ledger.is_closed() {
                break;
            }
            let pass = self.pass();
            if let Some(sink) = pass.fed {
                sink.on_batch_end();
            }
            self.shared.record_pending(&self.ledger);
            for line in &pass.trace_lines {
                stderr!("{line}");
            }
            if !pass.more {
                break;
            }
        }
    }

    /// Serves up to a queue's worth of requests with the driver's notifications
    /// off, and returns what it captured.
    ///
    /// Each request is parsed under the lock and counted in flight, its call to
    /// the backing store runs with no lock held, and it completes under the
    /// lock. A pass ends early when a reset takes the queue. Notifications are
    /// back on at the end of the pass, and a chain made available while they
    /// were off is reported in [`Pass::more`].
    fn pass(&self) -> Pass {
        let mut trace_lines = Vec::new();
        let mut state = self.shared.lock();
        let Some(active) = state.active.as_mut() else {
            return Pass {
                trace_lines,
                fed: None,
                more: false,
            };
        };
        active.queue.disable_notification(&self.ram);
        let bound = active.queue.size();
        for _ in 0..bound {
            if self.ledger.is_closed() {
                break;
            }
            let Some(chain) = state
                .active
                .as_mut()
                .and_then(|active| active.queue.pop(&self.ram))
            else {
                break;
            };
            let request = self.parse(chain);
            state.in_flight += 1;
            drop(state);
            let done = self.run_request(&request.work);
            state = self.shared.lock();
            self.complete(&mut state, &request, done, &mut trace_lines);
            state.in_flight -= 1;
            self.shared.idle.notify_all();
        }
        let more = state
            .active
            .as_mut()
            .is_some_and(|active| active.queue.enable_notification(&self.ram));
        Pass {
            trace_lines,
            fed: state.sink.take_fed(),
            more,
        }
    }

    /// Walks `chain` and parses the request it carries from guest RAM.
    ///
    /// The first readable segment is the 16-byte header (type, reserved,
    /// sector), the last writable segment is the status byte, and the segments
    /// between carry data. The walk is bounded by the queue size, and a write's
    /// data is gathered here, so a request in flight reads no guest RAM.
    fn parse(&self, mut chain: DescriptorChain<'_>) -> Request {
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
    /// Errors when the request falls outside the disk, or its data cannot be
    /// read from guest RAM.
    fn work(
        &self,
        kind: u32,
        sector: u64,
        data_out: &[(u64, u32)],
        data_in: &[(u64, u32)],
    ) -> io::Result<Work> {
        Ok(match kind {
            VIRTIO_BLK_T_IN => {
                let total = data_in.iter().map(|&(_, len)| u64::from(len)).sum();
                Work::Read {
                    offset: self.byte_range(sector, total)?,
                    segments: data_in.to_vec(),
                }
            }
            // The guest was offered VIRTIO_BLK_F_RO. A write that arrives
            // anyway fails.
            VIRTIO_BLK_T_OUT if self.read_only => Work::Answer(VIRTIO_BLK_S_IOERR),
            // Nothing was written, so there is nothing to make durable.
            VIRTIO_BLK_T_FLUSH if self.read_only => Work::Answer(VIRTIO_BLK_S_OK),
            VIRTIO_BLK_T_OUT => {
                // The range is checked before the guest-sized buffer exists.
                let total: usize = data_out.iter().map(|&(_, len)| len as usize).sum();
                let offset = self.byte_range(sector, total as u64)?;
                let mut data = vec![0u8; total];
                let mut at = 0;
                for &(addr, len) in data_out {
                    self.ram
                        .read(addr, &mut data[at..at + len as usize])
                        .map_err(other)?;
                    at += len as usize;
                }
                Work::Write { offset, data }
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

    /// Byte offset of `sector`, once we know the whole `len`-byte access falls
    /// inside the capacity we advertised in config space.
    ///
    /// The guest picks `sector`, so this is what keeps a request inside the
    /// disk it was given: without it a write past the end simply extended the
    /// backing file, and the multiplication wrapped in release builds.
    fn byte_range(&self, sector: u64, len: u64) -> std::io::Result<u64> {
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

    /// Runs `work` against the backing store, and returns the bytes a read
    /// brought back.
    ///
    /// It is the one step of a request that runs with no lock held. A read
    /// lands in a host buffer, and only the completion copies it to the guest.
    fn run_request(&self, work: &Work) -> io::Result<Vec<u8>> {
        match work {
            Work::Read { offset, segments } => {
                let total = segments.iter().map(|&(_, len)| len as usize).sum();
                let mut data = vec![0u8; total];
                self.file.read_exact_at(&mut data, *offset)?;
                Ok(data)
            }
            Work::Write { offset, data } => {
                self.file.write_all_at(data, *offset).map(|()| Vec::new())
            }
            // Honor the guest's cache flush (durability for fsync).
            Work::Flush => self.file.sync_data().map(|()| Vec::new()),
            Work::GetId { .. } | Work::Answer(_) => Ok(Vec::new()),
            Work::Refused(reason) => Err(io::Error::other(reason.clone())),
        }
    }

    /// Completes `request`, whose call to the backing store returned `done`.
    ///
    /// While the queue is served, the read data and the status byte reach guest
    /// RAM, the chain goes on the used ring and the interrupt is raised, once
    /// per request, so a slow request does not hold back the ones before it.
    /// After a reset none of that happens. A read or write that went through is
    /// recorded in `events` and fed to the sink either way, since it reached
    /// the backing store. With tracing on, its console line goes in `trace`.
    fn complete(
        &self,
        state: &mut State,
        request: &Request,
        done: io::Result<Vec<u8>>,
        trace_lines: &mut Vec<String>,
    ) {
        let State {
            active,
            sink,
            events,
            ..
        } = state;
        let Some(status_at) = request.status else {
            if let Some(active) = active {
                // The ring takes no entry for a head outside it, and then the
                // driver has nothing to be interrupted for.
                if active.queue.add_used(&self.ram, request.head, 0) {
                    active.interrupt.signal_used_buffer();
                }
            }
            return;
        };
        let (status, written, failed) = match self.answer(request, done, active.is_some()) {
            Ok((status, written)) => (status, written, false),
            Err(e) => {
                if self.trace {
                    trace_lines.push(format!("\r\n[virtio-blk] request failed: {e}\r\n"));
                }
                (VIRTIO_BLK_S_IOERR, 0, true)
            }
        };
        let data_len = request.data_len();
        // Only a read or write that went through is I/O on the disk. A flush
        // carries no data range, and a refused write moved nothing.
        let moved = matches!(request.work, Work::Read { .. } | Work::Write { .. });
        let recorded = status == VIRTIO_BLK_S_OK && moved;
        let write = request.kind == VIRTIO_BLK_T_OUT;
        if recorded {
            // The sink gets the request before the driver can see it complete,
            // so its record precedes what the guest does with the data. A sink
            // that cannot keep up accounts for that itself: a lost record must
            // not fail the guest's I/O.
            sink.feed(|sink| sink.on_block(request.sector, data_len, self.disk_id, write));
        }
        if let Some(active) = active {
            // A failure writes the status byte too. An untouched byte reads
            // back as whatever the driver put there, so a refused or failed
            // request could look like a success with stale data in the buffer.
            let _ = self.ram.write_u8(status_at, status);
            if active.queue.add_used(&self.ram, request.head, written + 1) {
                active.interrupt.signal_used_buffer();
            }
        }
        // Boundary capture: the guest's disk I/O, observed at the device. The
        // console line is opt-in (HVI_BLK_TRACE), because a synchronous stderr
        // write per request would dominate the cost under a high-IOPS workload.
        if self.trace && !failed {
            let kind = match request.kind {
                VIRTIO_BLK_T_IN => "read ",
                VIRTIO_BLK_T_OUT => "write",
                VIRTIO_BLK_T_FLUSH => "flush",
                VIRTIO_BLK_T_GET_ID => "getid",
                _ => "other",
            };
            trace_lines.push(format!(
                "\r\n[virtio-blk] {kind} sector={} bytes={data_len} status={status}\r\n",
                request.sector
            ));
        }
        if recorded {
            events.push(CapturedEvent::Block {
                disk: Arc::clone(&self.serial_text),
                lba: request.sector,
                len: data_len,
                write,
            });
        }
    }

    /// Returns the status of `request`, whose call to the backing store
    /// returned `done`, and the number of data bytes written to the guest.
    ///
    /// The read data or the serial reach the guest only when `deliver` is set.
    ///
    /// # Errors
    ///
    /// Errors when the call failed, the request was refused, or the data cannot
    /// be written to guest RAM.
    fn answer(
        &self,
        request: &Request,
        done: io::Result<Vec<u8>>,
        deliver: bool,
    ) -> io::Result<(u8, u32)> {
        let data = done?;
        Ok(match &request.work {
            Work::Read { segments, .. } if deliver => {
                (VIRTIO_BLK_S_OK, scatter(&self.ram, segments, &data)?)
            }
            Work::GetId { segments } if deliver => {
                (VIRTIO_BLK_S_OK, scatter(&self.ram, segments, &self.serial)?)
            }
            Work::Answer(status) => (*status, 0),
            _ => (VIRTIO_BLK_S_OK, 0),
        })
    }
}

#[cfg(test)]
impl<F: BackingStore> Worker<F> {
    /// Takes the records that are not in the ledger yet.
    fn take_pending(&self) -> Vec<CapturedEvent> {
        std::mem::take(&mut self.shared.lock().events)
    }

    /// Returns the worker with its backing store replaced by what `wrap` makes
    /// of it, for a test that holds the store's calls.
    pub(crate) fn with_store<G: BackingStore>(self, wrap: impl FnOnce(F) -> G) -> Worker<G> {
        Worker {
            file: wrap(self.file),
            capacity_sectors: self.capacity_sectors,
            read_only: self.read_only,
            serial: self.serial,
            serial_text: self.serial_text,
            disk_id: self.disk_id,
            trace: self.trace,
            ram: self.ram,
            ledger: self.ledger,
            shared: self.shared,
        }
    }
}

impl virtio::Device for VirtioBlk {
    fn device_type(&self) -> u32 {
        virtio_bindings::virtio_ids::VIRTIO_ID_BLOCK
    }

    fn features(&self) -> u64 {
        if self.read_only {
            F_FLUSH | F_RO
        } else {
            F_FLUSH
        }
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &[QUEUE_MAX_SIZE]
    }

    // The configuration space starts with the capacity, in 512-byte sectors.
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        read_config_bytes(&self.capacity_sectors.to_le_bytes(), offset, data);
    }

    fn activate(
        &mut self,
        _ram: &GuestRam,
        _driver_features: u64,
        queues: Vec<Option<Queue>>,
        interrupt: Arc<Interrupt>,
    ) -> std::io::Result<()> {
        let queue = <[Option<Queue>; 1]>::try_from(queues)
            .ok()
            .and_then(|[queue]| queue);
        self.shared.activate(queue, interrupt);
        Ok(())
    }

    fn notify(&mut self, _ram: &GuestRam, _queue: u16) {
        self.shared.wake.signal();
    }

    #[cfg(target_os = "linux")]
    fn notify_fds(&self) -> &[EventFd] {
        std::slice::from_ref(self.shared.wake.eventfd())
    }

    // The reset waits for a request in flight, as `Shared::reset` describes.
    // The transport holds its state lock until it returns, so a later
    // activation cannot hand the worker a new queue while an old request is
    // still in flight.
    fn reset(&mut self) {
        self.shared.reset();
    }

    // The worker serves the queue from its own wake and from its poll, which
    // the transport's refusal of a notification does not reach.
    fn driver_failed(&mut self) {
        self.shared.reset();
    }
}

/// Size in bytes of whatever is behind `file`.
///
/// `metadata().len()` is the *file* size, and for a block special file that is
/// 0 -- so a disk-image path works and a block device silently advertises a
/// zero-sector virtio-blk. That failure is unpleasant to read: the guest
/// registers `/dev/vda` normally and then fails every read, so the console says
/// "unable to read superblock" rather than anything about a missing disk.
///
/// Container runtimes hand us exactly that. urunc passes the devmapper snapshot
/// of the container's rootfs (`/dev/mapper/...`), not a file. So ask the kernel
/// for the device size when the path is a block device.
fn backing_len(file: &File) -> std::io::Result<u64> {
    let meta = file.metadata()?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::FileTypeExt;
        use std::os::unix::io::AsRawFd;

        if meta.file_type().is_block_device() {
            // The device size in bytes; BLKGETSIZE counts 512-byte sectors.
            // libc declares no BLKGETSIZE64, so the request is built here.
            const BLKGETSIZE64: libc::Ioctl = libc::_IOR::<usize>(0x12, 114);
            let mut size: u64 = 0;
            // SAFETY: `file` is an open block device and `size` is a live u64
            // that the ioctl writes exactly one u64 into.
            let rc = unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64, &mut size) };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            return Ok(size);
        }
    }
    Ok(meta.len())
}

/// Takes the lock on `file` that its mode needs, without waiting.
///
/// # Errors
///
/// Errors with `WouldBlock` when a lock this one excludes is held, and with
/// what the filesystem answered otherwise, as on NFS without a lock service.
fn lock(file: &File, read_only: bool) -> std::io::Result<()> {
    let taken = if read_only {
        file.try_lock_shared()
    } else {
        file.try_lock()
    };
    match taken {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            if read_only {
                "the image is open for writing elsewhere"
            } else {
                "the image is open elsewhere"
            },
        )),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

/// How often, and how long apart, a lock on a block device is retried.
///
/// systemd-udevd holds a shared lock on a whole-disk device while it handles an
/// event for it, as after `losetup`, so a first attempt can land in that
/// window.
const BLOCK_DEVICE_LOCK_TRIES: u32 = 20;
const BLOCK_DEVICE_LOCK_PAUSE: Duration = Duration::from_millis(50);

/// Returns the id `IoSink::on_block` reports for the backing store `meta`
/// describes, which a reader derives from its own path to the same store.
///
/// For a block device it is the device number, `st_rdev`, so every node for
/// one device gives one id. For a regular file it is `st_dev` rotated left by
/// 32 bits, xor `st_ino`, so two images on different filesystems with one
/// inode number differ.
#[must_use]
pub fn disk_id(meta: &std::fs::Metadata) -> u64 {
    store_id(
        meta.file_type().is_block_device(),
        meta.dev(),
        meta.ino(),
        meta.rdev(),
    )
}

/// Returns [`disk_id`] for a node `ino` on filesystem `dev`, which is the
/// device number `rdev` when `block_device` is set.
fn store_id(block_device: bool, dev: u64, ino: u64, rdev: u64) -> u64 {
    if block_device {
        rdev
    } else {
        dev.rotate_left(32) ^ ino
    }
}

/// Opens every disk in `disks` in order, each with the [`serial_at`] its
/// position, and logs each one.
///
/// [`serial_at`]: config::DiskConfig::serial_at
///
/// # Errors
///
/// Errors when [`config::check_disks`] refuses the list, when one image backs
/// two disks of which one is writable, or when a disk does not open. The
/// message names the disk and its path.
pub fn open_disks(disks: &[config::DiskConfig]) -> Result<Vec<Arc<Mutex<VirtioBlk>>>, String> {
    config::check_disks(disks)?;
    let mut opened: Vec<(Arc<Mutex<VirtioBlk>>, u64)> = Vec::new();
    for (index, disk) in disks.iter().enumerate() {
        let serial = disk.serial_at(index);
        let fail =
            |e: &dyn std::fmt::Display| format!("virtio-blk disk {index} ({}): {e}", disk.path);
        // The lock would refuse this too, with a message about another process.
        // Here the other holder is known, so the message names it.
        let id = std::fs::metadata(&disk.path)
            .map(|meta| disk_id(&meta))
            .map_err(|e| fail(&e))?;
        if let Some(earlier) = opened.iter().position(|(_, other)| *other == id) {
            let earlier_writes = !disks[earlier].read_only;
            if earlier_writes || !disk.read_only {
                return Err(fail(&format!(
                    "the same image is disk {earlier}, {}",
                    if earlier_writes {
                        "which this guest writes"
                    } else {
                        "and only one of the two may be writable"
                    }
                )));
            }
        }
        let blk = VirtioBlk::open_as(&disk.path, disk.read_only, &serial).map_err(|e| fail(&e))?;
        let mode = if disk.read_only { "ro" } else { "rw" };
        eprintln!(
            "{LOG_PREFIX} virtio-blk[{index}]: {} ({mode}, serial {serial})",
            disk.path
        );
        opened.push((Arc::new(Mutex::new(blk)), id));
    }
    Ok(opened.into_iter().map(|(blk, _)| blk).collect())
}

/// Writes `src` across the guest segments `segs`, each up to its length, and
/// returns how many bytes were written.
///
/// A source shorter than the segments fills them in order and leaves the rest,
/// which is what `GET_ID` does with a serial shorter than the buffer.
fn scatter(mem: &GuestRam, segs: &[(u64, u32)], mut src: &[u8]) -> std::io::Result<u32> {
    let mut written = 0u32;
    for &(addr, len) in segs {
        let n = (len as usize).min(src.len());
        mem.write(addr, &src[..n]).map_err(other)?;
        src = &src[n..];
        written += n as u32;
    }
    Ok(written)
}

fn other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod backing_len_tests {
    use super::backing_len;

    /// A plain disk image still sizes from the file length.
    #[test]
    fn a_regular_file_reports_its_length() {
        let path = std::env::temp_dir().join("hvi-backing-len-test.img");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("create temp image");
        file.set_len(4 << 20).expect("size temp image");
        assert_eq!(backing_len(&file).expect("len"), 4 << 20);
        let _ = std::fs::remove_file(&path);
    }

    /// The regression: a block special file has a file length of 0, so sizing a
    /// virtio-blk from `metadata().len()` gives the guest a 0-sector disk. This
    /// needs a real block device. CI creates a loop device and names it in
    /// `HVI_BLOCK_DEV`; when the variable is set the device must be usable,
    /// because a skip there would silently drop the coverage the CI step exists
    /// to provide. Without it the test scans for one, and reports rather than
    /// fails when none is openable.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_block_device_reports_the_device_size() {
        use std::os::unix::fs::FileTypeExt;

        let picked = match std::env::var("HVI_BLOCK_DEV") {
            Ok(dev) => {
                let file = std::fs::File::open(&dev)
                    .unwrap_or_else(|e| panic!("HVI_BLOCK_DEV={dev}: {e}"));
                Some((std::path::PathBuf::from(dev), file))
            }
            Err(_) => std::fs::read_dir("/sys/block")
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    let path = std::path::Path::new("/dev").join(e.file_name());
                    let file = std::fs::File::open(&path).ok()?;
                    let is_block = file.metadata().ok()?.file_type().is_block_device();
                    is_block.then_some((path, file))
                })
                .next(),
        };
        let Some((path, file)) = picked else {
            eprintln!("skipping: no openable block device (needs root on most hosts)");
            return;
        };

        let meta_len = file.metadata().expect("metadata").len();
        let got = backing_len(&file).expect("backing_len");
        assert_eq!(meta_len, 0, "{path:?} unexpectedly has a file length");
        assert!(got > 0, "{path:?} sized as {got} bytes");
        assert_eq!(
            got % super::SECTOR,
            0,
            "{path:?} size is not sector-aligned"
        );
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;
    use crate::devices::virtio::mmio::testing::{self, Driver, Rings};
    use crate::devices::virtio::{Device as _, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

    const BASE: u64 = 0x4000_0000;

    /// A device over an empty image, so every sector is past the capacity.
    ///
    /// Each call gets a file of its own, since a writable disk locks its image
    /// and the tests run in parallel. The file is unlinked at once; the open
    /// descriptor keeps it.
    fn dev() -> VirtioBlk {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("hvi-dev-{}-{n}.img", std::process::id()));
        std::fs::write(&path, []).unwrap();
        let blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).unwrap();
        blk
    }

    /// Returns a ledger that records nothing.
    fn ledger() -> Arc<Ledger> {
        Arc::new(Ledger::new(None, "blk-test").unwrap())
    }

    /// Returns the worker of a fresh device activated with a 4-entry queue at
    /// the start of `mem`.
    fn activated(mem: &Arc<GuestRam>) -> Worker {
        let mut blk = dev();
        let worker = blk.take_worker(mem, &ledger()).unwrap();
        let rings = Rings {
            size: 4,
            desc_table: BASE,
            avail_ring: BASE + 0x1000,
            used_ring: BASE + 0x2000,
        };
        let queue = testing::ready_queue(QUEUE_MAX_SIZE, rings, mem);
        let (interrupt, _) = testing::enabled_interrupt();
        blk.activate(mem, 0, vec![Some(queue)], interrupt).unwrap();
        worker
    }

    #[test]
    fn common_registers_follow_virtio_1_2() {
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x4000)]));
        let rings = Rings {
            size: 8,
            desc_table: BASE,
            avail_ring: BASE + 0x1000,
            used_ring: BASE + 0x2000,
        };
        testing::assert_common_registers(dev(), &mem, rings);
    }

    /// Makes chain `head` available as the next entry of the avail ring of
    /// [`activated`]'s queue.
    ///
    /// It then has the worker serve the chain.
    fn serve_head(worker: &Worker, mem: &GuestRam, head: u16) {
        let avail = BASE + 0x1000;
        let idx = mem.read_u16(avail + 2).unwrap();
        mem.write_u16(avail + 4 + u64::from(idx % 4) * 2, head)
            .unwrap();
        mem.write_u16(avail + 2, idx.wrapping_add(1)).unwrap();
        worker.serve();
    }

    /// Returns `used.idx` of [`activated`]'s queue, and the length of the used
    /// entry before it.
    fn last_used(mem: &GuestRam) -> (u16, u32) {
        let used = BASE + 0x2000;
        let idx = mem.read_u16(used + 2).unwrap();
        let entry = used + 4 + u64::from(idx.wrapping_sub(1) % 4) * 8;
        (idx, mem.read_u32(entry + 4).unwrap())
    }

    /// Writes descriptor `index` of [`activated`]'s queue.
    fn write_descriptor(mem: &GuestRam, index: u64, addr: u64, flags: u16, next: u16) {
        let at = BASE + index * 16;
        mem.write_u64(at, addr).unwrap();
        mem.write_u32(at + 8, 16).unwrap();
        mem.write_u16(at + 12, flags).unwrap();
        mem.write_u16(at + 14, next).unwrap();
    }

    // A header followed by a writable descriptor that points back at itself.
    // The walk ends at the queue size, and the chain completes with a length of
    // 0. Without the bound, the read past the empty disk's capacity would write
    // an error status and complete with a length of 1.
    #[test]
    fn descriptor_cycle_ends_at_the_queue_size_unserved() {
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x4000)]));
        let worker = activated(&mem);
        write_descriptor(&mem, 0, BASE + 0x3000, VIRTQ_DESC_F_NEXT, 1);
        write_descriptor(
            &mem,
            1,
            BASE + 0x3100,
            VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
            1,
        );

        serve_head(&worker, &mem, 0);

        assert_eq!(last_used(&mem), (1, 0));
    }

    // The driver chooses the header's address, so the address of the sector
    // field, 8 bytes on, can pass the end of the address space.
    #[test]
    fn header_at_the_top_of_the_address_space_fails_the_request() {
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x4000)]));
        let worker = activated(&mem);
        write_descriptor(&mem, 0, u64::MAX - 3, VIRTQ_DESC_F_NEXT, 1);
        write_descriptor(&mem, 1, BASE + 0x3100, VIRTQ_DESC_F_WRITE, 0);

        serve_head(&worker, &mem, 0);

        assert_eq!(last_used(&mem), (1, 1));
        let mut status = [0];
        mem.read(BASE + 0x3100, &mut status).unwrap();
        assert_eq!(status[0], VIRTIO_BLK_S_IOERR);
    }

    // A `next` that leaves the ring ends the walk, rather than reading a
    // descriptor the driver never programmed. The descriptor one past the ring
    // is a valid, writable one, so a walk past the ring would find it and serve
    // the request. A head outside the ring gets no used entry at all.
    #[test]
    fn next_index_outside_the_ring_ends_the_walk() {
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x4000)]));
        let worker = activated(&mem);
        write_descriptor(&mem, 0, BASE + 0x3000, VIRTQ_DESC_F_NEXT, 4);
        write_descriptor(&mem, 4, BASE + 0x3100, VIRTQ_DESC_F_WRITE, 0);

        serve_head(&worker, &mem, 0);
        assert_eq!(last_used(&mem), (1, 0), "the walk stopped at the ring");

        serve_head(&worker, &mem, 4);
        serve_head(&worker, &mem, u16::MAX);
        assert_eq!(
            mem.read_u16(BASE + 0x2000 + 2).unwrap(),
            1,
            "a head outside the ring is not completed"
        );
    }

    /// The happy path still works: a conforming driver's read request is
    /// serviced, the data lands in guest RAM and the status byte is written.
    #[test]
    fn conforming_queue_still_services_a_request() {
        let path = std::env::temp_dir().join(format!("hvi-q-{}.img", std::process::id()));
        let mut disk = vec![0u8; 1024];
        disk[..5].copy_from_slice(b"HELLO");
        std::fs::write(&path, &disk).unwrap();
        let mut blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();

        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x8000)]));
        let worker = blk.take_worker(&mem, &ledger()).unwrap();
        let (desc, avail, used) = (BASE, BASE + 0x2000, BASE + 0x3000);
        let buffers = BASE + 0x4000;
        let driver = Driver::new(blk, &mem);
        driver.start(&[Rings {
            size: 8,
            desc_table: desc,
            avail_ring: avail,
            used_ring: used,
        }]);
        publish_read(&mem, desc, avail, buffers);
        driver.notify(0);
        worker.serve();
        let _ = std::fs::remove_file(&path);

        let mut got = [0u8; 5];
        mem.read(buffers + 0x100, &mut got).unwrap();
        assert_eq!(&got, b"HELLO", "the sector reached guest memory");
        assert_eq!(mem.read_u16(used + 2).unwrap(), 1, "used.idx advanced");
        assert_eq!(driver.trigger.count(), 1, "the used buffer was signaled");
    }

    /// Publishes one read of sector 0 on `avail`, as the next entry of an
    /// 8-entry ring at `desc`.
    ///
    /// The request header is at `buffers`, the data at `buffers + 0x100` and
    /// the status byte at `buffers + 0x400`, poisoned to `0xff` so an untouched
    /// byte is visible.
    fn publish_read(mem: &GuestRam, desc: u64, avail: u64, buffers: u64) {
        let (hdr, data, status) = (buffers, buffers + 0x100, buffers + 0x400);
        mem.write_u32(hdr, VIRTIO_BLK_T_IN).unwrap();
        mem.write_u64(hdr + 8, 0).unwrap();
        mem.write_u8(status, 0xff).unwrap();
        let write_descriptor = |i: u64, addr: u64, len: u32, flags: u16, next: u16| {
            mem.write_u64(desc + i * 16, addr).unwrap();
            mem.write_u32(desc + i * 16 + 8, len).unwrap();
            mem.write_u16(desc + i * 16 + 12, flags).unwrap();
            mem.write_u16(desc + i * 16 + 14, next).unwrap();
        };
        write_descriptor(0, hdr, 16, VIRTQ_DESC_F_NEXT, 1);
        write_descriptor(1, data, 512, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
        write_descriptor(2, status, 1, VIRTQ_DESC_F_WRITE, 0);
        let avail_idx = mem.read_u16(avail + 2).unwrap();
        mem.write_u16(avail + 4 + u64::from(avail_idx % 8) * 2, 0)
            .unwrap();
        mem.write_u16(avail + 2, avail_idx.wrapping_add(1)).unwrap();
    }

    // The driver's notification reaches the worker through its wake and its
    // poll, with no call the transport could refuse.
    #[test]
    fn queue_is_not_served_once_the_driver_sets_failed() {
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x8000)]));
        let mut blk = dev();
        let worker = blk.take_worker(&mem, &ledger()).unwrap();
        let driver = Driver::new(blk, &mem);
        driver.start(&[Rings {
            size: 8,
            desc_table: BASE,
            avail_ring: BASE + 0x1000,
            used_ring: BASE + 0x2000,
        }]);
        driver.write(crate::devices::virtio::mmio::STATUS, 0x80);
        publish_read(&mem, BASE, BASE + 0x1000, BASE + 0x6000);

        worker.serve();

        assert_eq!(mem.read_u16(BASE + 0x2000 + 2).unwrap(), 0, "used.idx");
    }

    // A run that fails closes the ledger with the worker still running.
    #[test]
    fn queue_is_not_served_once_the_ledger_is_closed() {
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x8000)]));
        let path = std::env::temp_dir().join(format!("hvi-closed-{}.ndjson", std::process::id()));
        let ledger = Arc::new(Ledger::new(path.to_str(), "blk-test").unwrap());
        let mut blk = dev();
        let worker = blk.take_worker(&mem, &ledger).unwrap();
        let driver = Driver::new(blk, &mem);
        driver.start(&[Rings {
            size: 8,
            desc_table: BASE,
            avail_ring: BASE + 0x1000,
            used_ring: BASE + 0x2000,
        }]);
        ledger
            .close_with(std::time::Instant::now() + Duration::from_secs(5), |_| {})
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        publish_read(&mem, BASE, BASE + 0x1000, BASE + 0x6000);

        worker.serve();

        assert_eq!(mem.read_u16(BASE + 0x2000 + 2).unwrap(), 0, "used.idx");
    }

    // A sink's record of a request has to be in place before the guest can act
    // on the request's completion.
    #[test]
    fn sink_is_fed_before_the_request_is_on_the_used_ring() {
        /// A sink that reads `used.idx` of the queue each time it is fed.
        struct UsedAtFeed {
            ram: Arc<GuestRam>,
            seen: Mutex<Vec<u16>>,
        }
        impl IoSink for UsedAtFeed {
            fn on_block(&self, _sector: u64, _length: u64, _disk_id: u64, _write: bool) {
                let used = self.ram.read_u16(BASE + 0x2000 + 2).unwrap();
                self.seen.lock().unwrap().push(used);
            }

            fn on_net(&self, _frame: &[u8], _egress: bool) {}
        }
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x8000)]));
        let path = std::env::temp_dir().join(format!("hvi-fed-{}.img", std::process::id()));
        std::fs::write(&path, [0; 512]).unwrap();
        let mut blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).unwrap();
        let sink = Arc::new(UsedAtFeed {
            ram: Arc::clone(&mem),
            seen: Mutex::default(),
        });
        blk.set_io_sink(Arc::clone(&sink) as Arc<dyn IoSink>);
        let worker = blk.take_worker(&mem, &ledger()).unwrap();
        let driver = Driver::new(blk, &mem);
        driver.start(&[Rings {
            size: 8,
            desc_table: BASE,
            avail_ring: BASE + 0x1000,
            used_ring: BASE + 0x2000,
        }]);
        publish_read(&mem, BASE, BASE + 0x1000, BASE + 0x6000);

        worker.serve();

        assert_eq!(*sink.seen.lock().unwrap(), [0]);
        assert_eq!(mem.read_u16(BASE + 0x2000 + 2).unwrap(), 1);
    }

    // The re-programmed queue sits at fresh ring pages with `avail.idx` back
    // at 0.
    #[test]
    fn status_reset_lets_the_re_programmed_queue_service_a_request() {
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x8000)]));
        let mut blk = dev();
        let worker = blk.take_worker(&mem, &ledger()).unwrap();
        let driver = Driver::new(blk, &mem);

        driver.start(&[Rings {
            size: 8,
            desc_table: BASE,
            avail_ring: BASE + 0x1000,
            used_ring: BASE + 0x2000,
        }]);
        publish_read(&mem, BASE, BASE + 0x1000, BASE + 0x6000);
        driver.notify(0);
        worker.serve();
        assert_eq!(
            mem.read_u16(BASE + 0x2000 + 2).unwrap(),
            1,
            "used.idx before the reset"
        );

        driver.reset();
        driver.start(&[Rings {
            size: 8,
            desc_table: BASE + 0x3000,
            avail_ring: BASE + 0x4000,
            used_ring: BASE + 0x5000,
        }]);
        publish_read(&mem, BASE + 0x3000, BASE + 0x4000, BASE + 0x7000);
        driver.notify(0);
        worker.serve();
        assert_eq!(
            mem.read_u16(BASE + 0x5000 + 2).unwrap(),
            1,
            "the request published after the reset was serviced"
        );
        // `dev()` backs the disk with an empty image, so the read fails with
        // IOERR. A written status byte shows the chain was walked.
        assert_eq!(
            mem.read_u16(BASE + 0x7000 + 0x400).unwrap() as u8,
            VIRTIO_BLK_S_IOERR
        );
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use crate::devices::virtio::mmio::testing::{self, Rings};
    use crate::devices::virtio::{Device as _, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

    const BASE: u64 = 0x4000_0000;

    struct Rig {
        path: std::path::PathBuf,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    // A reader in a container reaches the device through its own node: the
    // node differs in filesystem and inode, the device number is the same.
    #[test]
    fn two_nodes_for_one_block_device_give_one_disk_id() {
        let host = store_id(true, 6, 1200, 0x0800);
        let container = store_id(true, 0x2f, 4, 0x0800);
        assert_eq!(host, container);
        assert_ne!(
            host,
            store_id(true, 6, 1201, 0x0810),
            "another device differs"
        );
    }

    #[test]
    fn disk_id_of_an_image_follows_its_inode() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let a = dir.join(format!("hvi-id-a-{pid}.img"));
        let b = dir.join(format!("hvi-id-b-{pid}.img"));
        let c = dir.join(format!("hvi-id-c-{pid}.img"));
        for p in [&a, &b, &c] {
            let _ = std::fs::remove_file(p);
        }
        std::fs::write(&a, []).unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        std::fs::write(&c, []).unwrap();
        let id = |p: &std::path::Path| disk_id(&std::fs::metadata(p).unwrap());

        assert_eq!(id(&a), id(&b), "two paths to one image give one id");
        assert_ne!(id(&a), id(&c), "another image differs");
        assert_ne!(
            store_id(false, 1, 7, 0),
            store_id(false, 2, 7, 0),
            "one inode number on two filesystems differs"
        );
        for p in [&a, &b, &c] {
            std::fs::remove_file(p).unwrap();
        }
    }

    /// A device with its worker, whose queue is in guest RAM of its own.
    struct Disk {
        /// The device.
        blk: VirtioBlk,
        /// The device's worker, which the test runs a pass of at a time.
        worker: Worker,
        /// The guest RAM the queue and the buffers are in.
        mem: Arc<GuestRam>,
    }

    impl Disk {
        /// Returns `blk` with its worker, and its queue unprogrammed.
        fn new(mut blk: VirtioBlk) -> Self {
            let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x8000)]));
            let ledger = Arc::new(Ledger::new(None, "blk-test").unwrap());
            let worker = blk.take_worker(&mem, &ledger).unwrap();
            Self { blk, worker, mem }
        }

        /// Submits one request.
        ///
        /// The worker serves it in one pass, and the call returns the status
        /// byte the device wrote and what the pass captured. The first request
        /// activates the device with a 256-entry queue, and each request takes
        /// the next entry of the avail ring.
        fn submit(&mut self, typ: u32, sector: u64, len: u32) -> (u8, Pass) {
            let mem = &self.mem;
            let (desc, avail, used) = (BASE, BASE + 0x2000, BASE + 0x3000);
            if self.blk.shared.lock().active.is_none() {
                let rings = Rings {
                    size: 256,
                    desc_table: desc,
                    avail_ring: avail,
                    used_ring: used,
                };
                let queue = testing::ready_queue(QUEUE_MAX_SIZE, rings, mem);
                let (interrupt, _) = testing::enabled_interrupt();
                self.blk
                    .activate(mem, 0, vec![Some(queue)], interrupt)
                    .unwrap();
            }
            let (hdr, data, status) = (BASE + 0x4000, BASE + 0x5000, BASE + 0x6000);
            mem.write_u32(hdr, typ).unwrap();
            mem.write_u64(hdr + 8, sector).unwrap();
            // poison, so "untouched" is visible
            mem.write_u8(status, 0xff).unwrap();

            let write_flag = if typ == VIRTIO_BLK_T_IN || typ == VIRTIO_BLK_T_GET_ID {
                VIRTQ_DESC_F_WRITE
            } else {
                0
            };
            let d = |i: u64, addr: u64, len: u32, flags: u16, next: u16| {
                mem.write_u64(desc + i * 16, addr).unwrap();
                mem.write_u32(desc + i * 16 + 8, len).unwrap();
                mem.write_u16(desc + i * 16 + 12, flags).unwrap();
                mem.write_u16(desc + i * 16 + 14, next).unwrap();
            };
            d(0, hdr, 16, VIRTQ_DESC_F_NEXT, 1);
            d(1, data, len, VIRTQ_DESC_F_NEXT | write_flag, 2);
            d(2, status, 1, VIRTQ_DESC_F_WRITE, 0);

            let idx = mem.read_u16(avail + 2).unwrap();
            mem.write_u16(avail + 4 + u64::from(idx % 256) * 2, 0)
                .unwrap();
            mem.write_u16(avail + 2, idx.wrapping_add(1)).unwrap();

            let pass = self.worker.pass();
            (mem.read_u16(status).unwrap() as u8, pass)
        }
    }

    /// Returns a writable 1-sector disk over an image of `0xab` bytes, and the
    /// guard that removes the image.
    fn rig(tag: &str) -> (Rig, Disk) {
        let path = std::env::temp_dir().join(format!("hvi-cap-{tag}-{}.img", std::process::id()));
        std::fs::write(&path, [0xabu8; 512]).unwrap();
        let blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();
        (Rig { path }, Disk::new(blk))
    }

    /// A sink that counts the requests it is fed.
    #[derive(Default)]
    struct CountingSink(std::sync::atomic::AtomicUsize);

    impl IoSink for CountingSink {
        fn on_block(&self, _sector: u64, _length: u64, _disk_id: u64, _write: bool) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn on_net(&self, _frame: &[u8], _egress: bool) {}
    }

    #[test]
    fn request_that_reaches_the_disk_feeds_its_sink_once() {
        let (_r, mut disk) = rig("fed");
        let sink = Arc::new(CountingSink::default());
        disk.blk.set_io_sink(Arc::clone(&sink) as Arc<dyn IoSink>);
        let (status, pass) = disk.submit(VIRTIO_BLK_T_IN, 0, 512);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        let fed = pass.fed.expect("the request fed the sink");
        assert!(std::ptr::addr_eq(Arc::as_ptr(&fed), Arc::as_ptr(&sink)));
        assert!(disk.worker.pass().fed.is_none(), "the sink is taken once");
    }

    #[test]
    fn refused_request_feeds_no_sink() {
        let (_r, mut disk) = rig("unfed");
        let sink = Arc::new(CountingSink::default());
        disk.blk.set_io_sink(Arc::clone(&sink) as Arc<dyn IoSink>);
        let (status, pass) = disk.submit(VIRTIO_BLK_T_IN, 9_999, 512);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(pass.fed.is_none());
    }

    /// Regression for the guest writing outside the disk it was advertised.
    #[test]
    fn write_past_the_advertised_capacity_is_refused() {
        let (r, mut disk) = rig("out");
        assert_eq!(disk.blk.capacity_sectors, 1);

        let (st, _) = disk.submit(VIRTIO_BLK_T_OUT, 131_072, 16);
        assert_eq!(
            st, VIRTIO_BLK_S_IOERR,
            "the guest is told the request failed"
        );
        assert_eq!(
            std::fs::metadata(&r.path).unwrap().len(),
            512,
            "the backing file was not extended"
        );
    }

    #[test]
    fn read_past_the_advertised_capacity_is_refused() {
        let (_r, mut disk) = rig("in");
        let (st, _) = disk.submit(VIRTIO_BLK_T_IN, 9_999, 512);
        assert_eq!(st, VIRTIO_BLK_S_IOERR);
    }

    /// A sector that would wrap the byte offset is refused rather than aliased
    /// back into the file (release builds used to wrap silently).
    #[test]
    fn sector_offset_overflow_is_refused() {
        let (r, mut disk) = rig("ovf");
        let (st, _) = disk.submit(VIRTIO_BLK_T_OUT, u64::MAX / 256, 16);
        assert_eq!(st, VIRTIO_BLK_S_IOERR);
        assert_eq!(std::fs::metadata(&r.path).unwrap().len(), 512);
    }

    /// The last sector inside the capacity still works, so the bound is not
    /// off by one.
    #[test]
    fn request_inside_the_capacity_still_succeeds() {
        let (_r, mut disk) = rig("ok");
        let (st, _) = disk.submit(VIRTIO_BLK_T_IN, 0, 512);
        assert_eq!(st, VIRTIO_BLK_S_OK, "sector 0 of a 1-sector disk is valid");
        let mut got = [0u8; 4];
        disk.mem.read(BASE + 0x5000, &mut got).unwrap();
        assert_eq!(&got, &[0xab; 4], "the sector reached guest memory");
    }

    /// A request type the device does not implement is answered `S_UNSUPP`, not
    /// `S_OK`: a driver told its discard succeeded would trust a range that
    /// still holds the old data.
    #[test]
    fn unknown_request_type_is_unsupported() {
        let (r, mut disk) = rig("unsupp");
        let discard = virtio_bindings::virtio_blk::VIRTIO_BLK_T_DISCARD;
        let write_zeroes = virtio_bindings::virtio_blk::VIRTIO_BLK_T_WRITE_ZEROES;
        for typ in [discard, write_zeroes, 0xdead_beef] {
            let (st, _) = disk.submit(typ, 0, 16);
            // The wire value from the spec, not the constant the device uses.
            assert_eq!(st, 2, "type {typ:#x} is VIRTIO_BLK_S_UNSUPP");
            // Only the status byte was written: used.len of the newest entry.
            let used = BASE + 0x3000;
            let slot = u64::from(disk.mem.read_u16(used + 2).unwrap().wrapping_sub(1) % 256);
            assert_eq!(disk.mem.read_u32(used + 4 + slot * 8 + 4).unwrap(), 1);
            assert!(
                disk.worker.take_pending().is_empty(),
                "and no I/O was recorded"
            );
        }
        assert_eq!(
            std::fs::read(&r.path).unwrap(),
            [0xabu8; 512],
            "nothing reached the disk"
        );
    }

    /// A 1-sector read-only disk on a `0444` image, opened with `serial`.
    fn ro_rig(tag: &str, serial: &str) -> (Rig, VirtioBlk) {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("hvi-ro-{tag}-{}.img", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, [0xabu8; 512]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let blk = VirtioBlk::open_as(path.to_str().unwrap(), true, serial).unwrap();
        (Rig { path }, blk)
    }

    // The ro lower image of an overlay root is 0444 in the store; opening it
    // for writing failed the boot.
    #[test]
    fn read_only_disk_opens_an_image_nobody_may_write() {
        let (r, blk) = ro_rig("open", "disk0");
        assert!(blk.read_only());
        // The rig's handle holds the shared lock, which would refuse a writer
        // on its own; the mode is what this test is about.
        drop(blk);
        // Root writes a 0444 file anyway, so the refusal is only checked for
        // everyone else.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            match VirtioBlk::open_as(r.path.to_str().unwrap(), false, "disk0") {
                Ok(_) => panic!("a writable open of a 0444 image succeeded"),
                Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}"),
            }
        }
    }

    #[test]
    fn read_only_disk_advertises_f_ro() {
        let (_r, ro) = ro_rig("feat", "");
        // The spec's bit numbers, not the constants the device uses:
        // VIRTIO_BLK_F_FLUSH is bit 9, VIRTIO_BLK_F_RO bit 5.
        assert_eq!(ro.features(), (1 << 9) | (1 << 5));

        let (_w, rw) = rig("feat");
        assert_eq!(rw.blk.features(), 1 << 9, "a writable disk is not ro");
    }

    #[test]
    fn write_to_a_read_only_disk_is_refused() {
        let (r, blk) = ro_rig("out", "");
        let mut disk = Disk::new(blk);
        disk.mem.write(BASE + 0x5000, &[0x11; 512]).unwrap();
        let (st, _) = disk.submit(VIRTIO_BLK_T_OUT, 0, 512);
        assert_eq!(st, VIRTIO_BLK_S_IOERR);
        assert_eq!(std::fs::read(&r.path).unwrap(), [0xabu8; 512]);
        assert!(
            disk.worker.take_pending().is_empty(),
            "a refused write is not I/O"
        );

        // Reads still work.
        let (st, _) = disk.submit(VIRTIO_BLK_T_IN, 0, 512);
        assert_eq!(st, VIRTIO_BLK_S_OK);
        let mut got = [0u8; 4];
        disk.mem.read(BASE + 0x5000, &mut got).unwrap();
        assert_eq!(got, [0xab; 4]);
    }

    // `submit` chains a data segment, and Linux never sends one with a flush.
    // Either way nothing was written, so the flush succeeds.
    #[test]
    fn flush_on_a_read_only_disk_succeeds() {
        let (_r, blk) = ro_rig("flush", "");
        let (st, _) = Disk::new(blk).submit(VIRTIO_BLK_T_FLUSH, 0, 16);
        assert_eq!(st, VIRTIO_BLK_S_OK);
    }

    // Two guests writing one image corrupt it, and a guest writing an image
    // another reads changes what the reader sees. A read-only image is shared,
    // as hull shares one lower image across sandboxes.
    #[test]
    fn open_disks_lock_the_image_by_mode() {
        use std::os::unix::fs::PermissionsExt;
        let refused = |path: &str, read_only: bool| match VirtioBlk::open_as(path, read_only, "") {
            Ok(_) => panic!("{path} opened while locked"),
            Err(err) => {
                assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock, "{err}");
                err.to_string()
            }
        };
        let (r, _ro) = ro_rig("lock", "");
        let path = r.path.to_str().unwrap();
        VirtioBlk::open_as(path, true, "").expect("a second reader");
        // Root may write a 0444 file, so the writer's refusal has to come from
        // the lock, which is what this checks on every uid.
        std::fs::set_permissions(&r.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(refused(path, false).contains("open"));

        let (w, writer) = rig("lock");
        let path = w.path.to_str().unwrap();
        refused(path, false);
        assert!(refused(path, true).contains("for writing"));
        drop(writer);
        VirtioBlk::open_as(path, true, "").expect("the lock went with the writer");
    }

    #[test]
    fn disk_at_the_ledger_path_is_refused_and_left_as_it_was() {
        let (r, disk) = rig("ledger");
        drop(disk);
        let path = r.path.to_str().unwrap();
        let ledger = crate::events::Ledger::new(Some(path), "vm1").unwrap();
        let err = open_disks(&[config::DiskConfig::rw(path)]).err().unwrap();
        assert!(err.ends_with("the image is open elsewhere"), "{err}");
        ledger
            .close(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(std::fs::read(&r.path).unwrap(), [0xabu8; 512]);
    }

    #[test]
    fn open_disks_names_the_other_disk_on_one_image() {
        use std::os::unix::fs::PermissionsExt;
        let (r, blk) = ro_rig("twice", "");
        drop(blk);
        // The writer below has to get as far as the duplicate check.
        std::fs::set_permissions(&r.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = r.path.to_str().unwrap();
        let ro = |serial: &str| config::DiskConfig {
            path: path.to_string(),
            read_only: true,
            serial: Some(serial.to_string()),
        };
        assert_eq!(open_disks(&[ro("a"), ro("b")]).unwrap().len(), 2);
        let refused = |disks: &[config::DiskConfig]| match open_disks(disks) {
            Ok(_) => panic!("one image opened twice with a writer"),
            Err(err) => err,
        };
        let err = refused(&[ro("a"), config::DiskConfig::rw(path)]);
        assert!(err.contains("disk 1") && err.contains("is disk 0"), "{err}");
        let err = refused(&[config::DiskConfig::rw(path), ro("b")]);
        assert!(err.contains("which this guest writes"), "{err}");
    }

    #[test]
    fn get_id_returns_the_zero_padded_serial() {
        let (_r, blk) = ro_rig("id", "disk1");
        let mut disk = Disk::new(blk);
        disk.mem.write(BASE + 0x5000, &[0xff; 32]).unwrap();
        let (st, _) = disk.submit(VIRTIO_BLK_T_GET_ID, 0, SERIAL_LEN as u32);
        assert_eq!(st, VIRTIO_BLK_S_OK);
        let mut got = [0u8; 32];
        disk.mem.read(BASE + 0x5000, &mut got).unwrap();
        let mut want = [0u8; SERIAL_LEN];
        want[..5].copy_from_slice(b"disk1");
        assert_eq!(&got[..SERIAL_LEN], &want);
        assert_eq!(&got[SERIAL_LEN..], &[0xff; 12], "nothing past the buffer");
        assert_eq!(
            disk.mem.read_u32(BASE + 0x3000 + 8).unwrap(),
            SERIAL_LEN as u32 + 1,
            "the used length counts the serial and the status byte"
        );
    }

    #[test]
    fn get_id_stops_at_a_short_buffer() {
        let (r, disk) = rig("idshort");
        drop(disk);
        let blk = VirtioBlk::open_as(r.path.to_str().unwrap(), false, "disk3").unwrap();
        let mut disk = Disk::new(blk);
        disk.mem.write(BASE + 0x5000, &[0xff; 8]).unwrap();
        let (st, _) = disk.submit(VIRTIO_BLK_T_GET_ID, 0, 3);
        assert_eq!(st, VIRTIO_BLK_S_OK);
        let mut got = [0u8; 4];
        disk.mem.read(BASE + 0x5000, &mut got).unwrap();
        assert_eq!(&got, b"dis\xff");
    }

    // The guest finds its disks by serial, so position N in the disk list has
    // to answer GET_ID with disk<N> and keep its own access mode.
    #[test]
    fn open_disks_gives_each_position_its_serial_and_mode() {
        let (a, _) = ro_rig("argv-a", "");
        let (b, disk) = rig("argv-b");
        drop(disk);
        let disks = open_disks(&[
            config::DiskConfig::ro(a.path.to_str().unwrap()),
            config::DiskConfig::rw(b.path.to_str().unwrap()),
        ])
        .unwrap();
        assert_eq!(disks.len(), 2);
        for (index, (dev, read_only)) in disks.into_iter().zip([true, false]).enumerate() {
            let blk = Arc::into_inner(dev).unwrap().into_inner().unwrap();
            assert_eq!(blk.read_only(), read_only, "disk {index}");
            let mut disk = Disk::new(blk);
            let (st, _) = disk.submit(VIRTIO_BLK_T_GET_ID, 0, 20);
            assert_eq!(st, 0, "disk {index} answered GET_ID");
            let mut got = [0u8; 20];
            disk.mem.read(BASE + 0x5000, &mut got).unwrap();
            let mut want = [0u8; 20];
            want[..5].copy_from_slice(format!("disk{index}").as_bytes());
            assert_eq!(got, want, "disk {index}");
        }
    }

    #[test]
    fn serial_longer_than_the_id_field_is_refused() {
        let (r, disk) = rig("idlong");
        // The rig's own handle holds the image's lock.
        drop(disk);
        let long = "x".repeat(SERIAL_LEN + 1);
        assert!(VirtioBlk::open_as(r.path.to_str().unwrap(), false, &long).is_err());
        let exact = "x".repeat(SERIAL_LEN);
        VirtioBlk::open_as(r.path.to_str().unwrap(), false, &exact).expect("20 bytes fit");
    }

    /// The bound is on the bytes actually transferred, so it is exact at the
    /// end of the disk in both directions.
    #[test]
    fn byte_range_bounds_are_exact() {
        let (_r, disk) = rig("rng");
        let worker = &disk.worker;
        // 1 sector = 512 bytes of capacity.
        assert_eq!(
            worker.byte_range(0, 512).unwrap(),
            0,
            "the whole disk is fine"
        );
        assert!(worker.byte_range(0, 513).is_err(), "one byte past is not");
        assert!(
            worker.byte_range(1, 1).is_err(),
            "nor is one byte at sector 1"
        );
        // A zero-length request touches nothing, so the end offset is allowed;
        // this matches Firecracker's `sector + num_sectors > capacity` check.
        assert_eq!(worker.byte_range(1, 0).unwrap(), 512);
        assert!(
            worker.byte_range(u64::MAX, 1).is_err(),
            "overflow is refused"
        );
        assert!(worker.byte_range(u64::MAX / 256, 16).is_err());
    }
}

#[cfg(test)]
mod worker_tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Instant;

    use super::*;
    use crate::devices::virtio::mmio::testing::{Driver, Rings};
    use crate::devices::virtio::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::teardown::StopSource;

    const BASE: u64 = 0x4000_0000;
    /// The queue of every rig, a 16-entry ring at the start of guest RAM.
    const RINGS: Rings = Rings {
        size: 16,
        desc_table: BASE,
        avail_ring: BASE + 0x1000,
        used_ring: BASE + 0x2000,
    };
    /// The buffers of request `n` are in the page at `BUFFERS + n * 0x1000`.
    const BUFFERS: u64 = BASE + 0x4000;
    /// Where in its page a request has its data, and its status byte.
    const DATA: u64 = 0x200;
    const STATUS: u64 = 0xf00;
    /// How long a test waits for the worker before it fails, since a loaded
    /// host can hold the worker for seconds.
    const WAIT: Duration = Duration::from_secs(30);

    /// A backing file whose calls each wait at a gate until the test lets one
    /// through.
    struct Gated {
        /// The backing file.
        file: File,
        /// Where a call reports that it reached the gate.
        entered: mpsc::Sender<()>,
        /// What a call waits on before it runs.
        open: Mutex<mpsc::Receiver<()>>,
    }

    /// The test's side of a [`Gated`] store.
    struct Gate {
        /// Where a call reports that it reached the gate.
        entered: mpsc::Receiver<()>,
        /// What lets one call through.
        open: mpsc::Sender<()>,
    }

    impl Gated {
        /// Returns a store over `file` and the gate its calls wait at.
        fn new(file: File) -> (Self, Gate) {
            let (entered, entered_rx) = mpsc::channel();
            let (open, open_rx) = mpsc::channel();
            let store = Self {
                file,
                entered,
                open: Mutex::new(open_rx),
            };
            let gate = Gate {
                entered: entered_rx,
                open,
            };
            (store, gate)
        }

        /// Holds the call at the gate until the test lets it through, or drops
        /// the gate.
        ///
        /// It reports the call at the gate before it waits.
        fn hold(&self) {
            let _ = self.entered.send(());
            let _ = self.open.lock().unwrap().recv();
        }
    }

    impl BackingStore for Gated {
        fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
            self.hold();
            FileExt::read_exact_at(&self.file, buf, offset)
        }

        fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
            self.hold();
            FileExt::write_all_at(&self.file, buf, offset)
        }

        // The gate decides how long a flush takes, so the store syncs nothing.
        // A sync of the image can wait behind the host's other writes for
        // longer than a test waits.
        fn sync_data(&self) -> io::Result<()> {
            self.hold();
            Ok(())
        }
    }

    impl Gate {
        /// Waits until a call reaches the gate.
        fn wait_for_call(&self) {
            self.entered
                .recv_timeout(WAIT)
                .expect("a call should reach the gate");
        }

        /// Lets one call through.
        fn open(&self) {
            self.open.send(()).unwrap();
        }
    }

    /// A sink that records the requests it is fed, as disk id, sector and
    /// whether each is a write, and counts the batches that end.
    #[derive(Default)]
    struct RecordingSink {
        /// The requests, in the order they were fed.
        blocks: Mutex<Vec<(u64, u64, bool)>>,
        /// The batches that ended.
        batches: AtomicUsize,
    }

    impl IoSink for RecordingSink {
        fn on_block(&self, sector: u64, _length: u64, disk_id: u64, write: bool) {
            self.blocks.lock().unwrap().push((disk_id, sector, write));
        }

        fn on_net(&self, _frame: &[u8], _egress: bool) {}

        fn on_batch_end(&self) {
            self.batches.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A disk over an 8-sector image whose sector `n` holds the byte `n + 1`,
    /// driven through its transport, with its worker on a thread of its own.
    struct Rig {
        /// The gate the worker's calls wait at, when the rig has one.
        gate: Option<Gate>,
        /// The driver of the disk's transport.
        driver: Driver<VirtioBlk>,
        /// The guest RAM the queue and the buffers are in.
        ram: Arc<GuestRam>,
        /// The stop hooks the worker queued.
        host: HostWork,
        /// The stop of the worker's thread.
        stop: StopSource,
        /// The worker's thread.
        worker: Option<std::thread::JoinHandle<()>>,
        /// The image, removed with the rig.
        path: std::path::PathBuf,
    }

    impl Rig {
        /// Returns a rig whose disk answers `GET_ID` with `serial` and records
        /// its requests in `ledger`, with a gate on its backing file when
        /// `gated` is set.
        fn new(serial: &str, ledger: &Arc<Ledger>, gated: bool) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("hvi-blk-worker-{}-{n}.img", std::process::id()));
            let image: Vec<u8> = (0..8u8).flat_map(|sector| [sector + 1; 512]).collect();
            std::fs::write(&path, image).unwrap();
            let mut blk = VirtioBlk::open_as(path.to_str().unwrap(), false, serial).unwrap();
            let ram = Arc::new(GuestRam::from_ranges(&[(BASE, 0x10000)]));
            let mut host = HostWork::default();
            let worker = blk.take_worker(&ram, ledger).unwrap();
            let mut gate = None;
            if gated {
                worker
                    .with_store(|file| {
                        let (store, made) = Gated::new(file);
                        gate = Some(made);
                        store
                    })
                    .queue_thread(&mut host);
            } else {
                worker.queue_thread(&mut host);
            }
            let [thread] = <[_; 1]>::try_from(host.take_threads())
                .ok()
                .expect("the disk should queue one thread");
            assert_eq!(thread.filter, Thread::Block);
            let stop = StopSource::new().unwrap();
            let token = stop.token();
            let worker = std::thread::spawn(move || (thread.run)(token));
            Self {
                gate,
                driver: Driver::new(blk, &ram),
                ram,
                host,
                stop,
                worker: Some(worker),
                path,
            }
        }

        /// Returns the gate of a rig made with one.
        fn gate(&self) -> &Gate {
            self.gate.as_ref().expect("the rig should have a gate")
        }

        /// Makes request `n`, of type `kind` at `sector`, available as the next
        /// entry of the avail ring, with no notification.
        ///
        /// It takes descriptors `3n` on. A read or write carries one sector of
        /// data, filled with `0xee`, and a flush carries none. The status byte
        /// is poisoned to `0xff`, so an untouched byte is visible.
        fn publish(&self, n: u64, kind: u32, sector: u64) {
            let ram = &self.ram;
            let page = BUFFERS + n * 0x1000;
            ram.write_u32(page, kind).unwrap();
            ram.write_u64(page + 8, sector).unwrap();
            ram.write(page + DATA, &[0xee; 512]).unwrap();
            ram.write_u8(page + STATUS, 0xff).unwrap();
            let descriptor = |index: u64, addr: u64, len: u32, flags: u16| {
                let at = RINGS.desc_table + index * 16;
                ram.write_u64(at, addr).unwrap();
                ram.write_u32(at + 8, len).unwrap();
                ram.write_u16(at + 12, flags).unwrap();
                ram.write_u16(at + 14, (index + 1) as u16).unwrap();
            };
            let first = n * 3;
            descriptor(first, page, 16, VIRTQ_DESC_F_NEXT);
            let status = if kind == VIRTIO_BLK_T_FLUSH {
                first + 1
            } else {
                let flags = if kind == VIRTIO_BLK_T_IN {
                    VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
                } else {
                    VIRTQ_DESC_F_NEXT
                };
                descriptor(first + 1, page + DATA, 512, flags);
                first + 2
            };
            descriptor(status, page + STATUS, 1, VIRTQ_DESC_F_WRITE);
            let avail = RINGS.avail_ring;
            let idx = ram.read_u16(avail + 2).unwrap();
            ram.write_u16(avail + 4 + u64::from(idx % 16) * 2, first as u16)
                .unwrap();
            ram.write_u16(avail + 2, idx.wrapping_add(1)).unwrap();
        }

        /// Notifies the queue the way the hypervisor delivers a guest's
        /// notification: on Linux through the eventfd KVM registers, with no
        /// access to the transport, and on macOS through the transport.
        fn kick(&self) {
            #[cfg(target_os = "linux")]
            {
                use crate::devices::virtio::Device as _;
                self.driver.device.lock().unwrap().notify_fds()[0]
                    .write(1)
                    .unwrap();
            }
            #[cfg(target_os = "macos")]
            self.driver.notify(0);
        }

        /// Returns `used.idx`.
        fn used_idx(&self) -> u16 {
            self.ram.read_u16(RINGS.used_ring + 2).unwrap()
        }

        /// Returns the flags of the used ring.
        fn used_flags(&self) -> u16 {
            self.ram.read_u16(RINGS.used_ring).unwrap()
        }

        /// Returns the first bytes of request `n`'s data buffer.
        fn data(&self, n: u64) -> [u8; 4] {
            let mut got = [0; 4];
            self.ram
                .read(BUFFERS + n * 0x1000 + DATA, &mut got)
                .unwrap();
            got
        }

        /// Returns request `n`'s status byte.
        fn status(&self, n: u64) -> u8 {
            let mut status = [0];
            self.ram
                .read(BUFFERS + n * 0x1000 + STATUS, &mut status)
                .unwrap();
            status[0]
        }

        /// Returns the number of requests in flight.
        fn in_flight(&self) -> u32 {
            let device = self.driver.device.lock().unwrap();
            let in_flight = device.shared.lock().in_flight;
            in_flight
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            // The gate goes first, so a worker held at it after a failed
            // assertion returns and the join does not wait for it.
            self.gate = None;
            self.stop.request_stop();
            self.host.run_io_stops();
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Returns a ledger that records nothing.
    fn no_ledger() -> Arc<Ledger> {
        Arc::new(Ledger::new(None, "blk-worker-test").unwrap())
    }

    /// Waits up to [`WAIT`] for `done`.
    ///
    /// It fails with `what` when `done` does not hold by then.
    fn wait_until(what: &str, done: impl Fn() -> bool) {
        assert!(holds_in_time(done), "{what}");
    }

    /// Returns whether `done` holds within [`WAIT`].
    fn holds_in_time(done: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + WAIT;
        while !done() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }

    /// Returns a path no ledger file is at, for a test's ledger.
    fn fresh_ledger_path() -> std::path::PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hvi-blk-worker-ledger-{}-{n}.ndjson",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// Returns the `block` records of the ledger at `path`, as disk, sector and
    /// whether each is a write.
    fn block_records(path: &std::path::Path) -> Vec<(String, u64, bool)> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter_map(|line| {
                let record: serde_json::Value = serde_json::from_str(line).ok()?;
                let payload = &record["payload"];
                (record["source"] == "block").then(|| {
                    (
                        payload["disk"].as_str().unwrap().to_string(),
                        payload["lba"].as_u64().unwrap(),
                        payload["rw"] == "w",
                    )
                })
            })
            .collect()
    }

    // The guest resets the device while the worker's read is held at the gate.
    // The STATUS write returns only once the read has returned, and the read's
    // data, its status byte and a used entry never reach the guest.
    #[test]
    fn reset_waits_for_the_call_in_flight_and_completes_nothing() {
        let rig = Rig::new("disk0", &no_ledger(), true);
        rig.driver.start(&[RINGS]);
        rig.publish(0, VIRTIO_BLK_T_IN, 1);
        rig.kick();
        rig.gate().wait_for_call();

        std::thread::scope(|scope| {
            let reset = scope.spawn(|| rig.driver.reset());
            std::thread::sleep(Duration::from_millis(50));
            assert!(!reset.is_finished(), "the reset returned during the read");
            rig.gate().open();
            reset.join().unwrap();
        });

        assert_eq!(rig.in_flight(), 0, "the read has returned");
        assert_eq!(rig.data(0), [0xee; 4], "the data buffer is untouched");
        assert_eq!(rig.status(0), 0xff, "the status byte is untouched");
        assert_eq!(rig.used_idx(), 0, "no used entry was added");
        assert_eq!(rig.driver.trigger.count(), 0, "no interrupt was raised");
    }

    // A backing file that never answers would hold the vCPU in the reset
    // forever. The vCPUs' stop frees it while the read is still held, and the
    // read completes nothing once it returns.
    #[test]
    fn vcpu_stop_frees_a_vcpu_waiting_in_reset() {
        let rig = Rig::new("disk0", &no_ledger(), true);
        rig.driver.start(&[RINGS]);
        rig.publish(0, VIRTIO_BLK_T_IN, 1);
        rig.kick();
        rig.gate().wait_for_call();

        std::thread::scope(|scope| {
            let reset = scope.spawn(|| rig.driver.reset());
            std::thread::sleep(Duration::from_millis(50));
            let waited = !reset.is_finished();
            rig.host.run_vcpu_stops();
            let freed = holds_in_time(|| reset.is_finished());
            // The device lock is free only once the reset has returned.
            let held = freed.then(|| rig.in_flight());
            // A reset still waiting is freed by the read's return, so the scope
            // can end.
            rig.gate().open();
            assert!(waited, "the reset returned during the read");
            assert!(freed, "the stop did not free the reset");
            assert_eq!(held, Some(1), "the read is still held");
        });

        wait_until("the read did not return", || rig.in_flight() == 0);
        assert_eq!(rig.data(0), [0xee; 4], "the data buffer is untouched");
        assert_eq!(rig.status(0), 0xff, "the status byte is untouched");
        assert_eq!(rig.used_idx(), 0, "no used entry was added");
    }

    /// A sink whose `on_block` panics, as a plugin's sink with a bug may.
    struct PanickingSink;

    impl IoSink for PanickingSink {
        fn on_block(&self, _sector: u64, _length: u64, _disk_id: u64, _write: bool) {
            panic!("a sink panicked");
        }

        fn on_net(&self, _frame: &[u8], _egress: bool) {}
    }

    // The sink runs under the lock the worker shares with the device, so its
    // panic poisons the lock and leaves the request counted in flight. The
    // vCPUs' stop still runs, and a reset after it does not wait.
    #[test]
    fn vcpu_stop_after_a_sink_panic_frees_a_reset() {
        let rig = Rig::new("disk0", &no_ledger(), false);
        rig.driver
            .device
            .lock()
            .unwrap()
            .set_io_sink(Arc::new(PanickingSink));
        rig.driver.start(&[RINGS]);
        rig.publish(0, VIRTIO_BLK_T_IN, 1);
        rig.kick();
        wait_until("the worker did not panic", || {
            rig.worker
                .as_ref()
                .is_some_and(|worker| worker.is_finished())
        });

        let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rig.host.run_vcpu_stops();
        }));
        assert!(stopped.is_ok(), "the stop panicked on the poisoned lock");
        rig.driver.reset();
        assert_eq!(rig.in_flight(), 1, "the panic left the request in flight");
    }

    // The transport drops a notification before DRIVER_OK and notifies each
    // ready queue again after it, which is what wakes the worker here.
    #[test]
    fn notification_before_driver_ok_is_served_after_activation() {
        let rig = Rig::new("disk0", &no_ledger(), false);
        rig.driver.negotiate();
        rig.driver.program_queue(0, RINGS);
        rig.publish(0, VIRTIO_BLK_T_IN, 1);
        rig.driver.notify(0);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(rig.used_idx(), 0, "nothing is served before DRIVER_OK");

        rig.driver.driver_ok();

        wait_until("the request was not served", || rig.used_idx() == 1);
        assert_eq!(rig.data(0), [2; 4], "sector 1 reached the guest");
        assert_eq!(rig.status(0), VIRTIO_BLK_S_OK);
    }

    // A read and then a flush in one pass. The flush is held at the gate, and
    // the read's used entry and interrupt reach the guest before it returns.
    #[test]
    fn request_before_a_slow_one_completes_while_it_is_in_flight() {
        let rig = Rig::new("disk0", &no_ledger(), true);
        rig.driver.start(&[RINGS]);
        rig.publish(0, VIRTIO_BLK_T_IN, 1);
        rig.publish(1, VIRTIO_BLK_T_FLUSH, 0);
        rig.kick();
        rig.gate().wait_for_call();
        rig.gate().open();
        rig.gate().wait_for_call();

        assert_eq!(rig.used_idx(), 1, "the read is on the used ring");
        assert_eq!(rig.data(0), [2; 4], "sector 1 reached the guest");
        assert_eq!(rig.status(0), VIRTIO_BLK_S_OK);
        assert_eq!(
            rig.driver.trigger.count(),
            1,
            "the read raised the interrupt"
        );
        assert_eq!(rig.status(1), 0xff, "the flush is in flight");

        rig.gate().open();
        wait_until("the flush did not complete", || rig.used_idx() == 2);
        assert_eq!(rig.status(1), VIRTIO_BLK_S_OK);
    }

    // Both requests are on the ring when DRIVER_OK wakes the worker, so it
    // serves them in one pass. It writes their records to the ledger with no
    // access to the transport after DRIVER_OK, and the sink's batch ends once,
    // for the one pass.
    #[test]
    fn pass_records_its_requests_and_ends_the_batch_once() {
        let path = std::env::temp_dir().join(format!(
            "hvi-blk-worker-ledger-{}.ndjson",
            std::process::id()
        ));
        let ledger = Arc::new(Ledger::new(Some(path.to_str().unwrap()), "vm").unwrap());
        ledger.set_gather_interval(Duration::from_millis(1));
        let sink = Arc::new(RecordingSink::default());
        {
            let rig = Rig::new("disk0", &ledger, false);
            rig.driver
                .device
                .lock()
                .unwrap()
                .set_io_sink(Arc::clone(&sink) as Arc<dyn IoSink>);
            rig.driver.negotiate();
            rig.driver.program_queue(0, RINGS);
            rig.publish(0, VIRTIO_BLK_T_IN, 1);
            rig.publish(1, VIRTIO_BLK_T_OUT, 2);
            rig.driver.driver_ok();

            wait_until("the ledger did not get both records", || {
                block_records(&path).len() == 2
            });
            assert_eq!(
                block_records(&path),
                [
                    ("disk0".to_string(), 1, false),
                    ("disk0".to_string(), 2, true)
                ]
            );
            assert_eq!(sink.blocks.lock().unwrap().len(), 2);
            assert_eq!(sink.batches.load(Ordering::SeqCst), 1);
        }
        Arc::into_inner(ledger)
            .unwrap()
            .close(Instant::now() + Duration::from_secs(5))
            .unwrap();
        let _ = std::fs::remove_file(&path);
    }

    // A read and then a flush in one pass, with the flush held at the gate. The
    // stop may close the ledger before the flush returns and the pass ends, so
    // the stop writes the read's record itself.
    #[test]
    fn stop_writes_the_records_of_requests_completed_in_the_pass_in_progress() {
        let path = fresh_ledger_path();
        let ledger = Arc::new(Ledger::new(Some(path.to_str().unwrap()), "vm").unwrap());
        ledger.set_gather_interval(Duration::from_millis(1));
        {
            let rig = Rig::new("disk0", &ledger, true);
            rig.driver.start(&[RINGS]);
            rig.publish(0, VIRTIO_BLK_T_IN, 1);
            rig.publish(1, VIRTIO_BLK_T_FLUSH, 0);
            rig.kick();
            rig.gate().wait_for_call();
            rig.gate().open();
            rig.gate().wait_for_call();
            assert_eq!(rig.used_idx(), 1, "the read is complete");
            assert!(block_records(&path).is_empty(), "the pass has not ended");

            rig.host.run_vcpu_stops();

            wait_until("the stop did not write the read's record", || {
                block_records(&path) == [("disk0".to_string(), 1, false)]
            });
            assert_eq!(rig.status(1), 0xff, "the flush is still in flight");
            rig.gate().open();
        }
        Arc::into_inner(ledger)
            .unwrap()
            .close(Instant::now() + Duration::from_secs(5))
            .unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A sink whose `on_batch_end` waits until it is released.
    #[derive(Default)]
    struct HeldBatchEnd {
        /// Whether a batch's end has been entered.
        entered: AtomicBool,
        /// Whether the batch's end may return.
        released: AtomicBool,
    }

    impl IoSink for HeldBatchEnd {
        fn on_block(&self, _sector: u64, _length: u64, _disk_id: u64, _write: bool) {}

        fn on_net(&self, _frame: &[u8], _egress: bool) {}

        fn on_batch_end(&self) {
            self.entered.store(true, Ordering::SeqCst);
            while !self.released.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    /// Releases the batch's end of a [`HeldBatchEnd`] when dropped, so a test
    /// that fails still lets the worker's thread end.
    struct ReleaseGuard(Arc<HeldBatchEnd>);

    impl Drop for ReleaseGuard {
        fn drop(&mut self) {
            self.0.released.store(true, Ordering::SeqCst);
        }
    }

    // The pass has ended and the worker waits in the sink's `on_batch_end`,
    // with the pass's record not written yet. The stop writes it.
    #[test]
    fn stop_writes_the_records_of_a_pass_whose_batch_end_has_not_returned() {
        let path = fresh_ledger_path();
        let ledger = Arc::new(Ledger::new(Some(path.to_str().unwrap()), "vm").unwrap());
        ledger.set_gather_interval(Duration::from_millis(1));
        let sink = Arc::new(HeldBatchEnd::default());
        {
            let rig = Rig::new("disk0", &ledger, false);
            rig.driver
                .device
                .lock()
                .unwrap()
                .set_io_sink(Arc::clone(&sink) as Arc<dyn IoSink>);
            rig.driver.start(&[RINGS]);
            rig.publish(0, VIRTIO_BLK_T_IN, 1);
            let _release = ReleaseGuard(Arc::clone(&sink));
            rig.kick();
            wait_until("the batch's end was not reached", || {
                sink.entered.load(Ordering::SeqCst)
            });

            rig.host.run_vcpu_stops();

            wait_until("the stop did not write the read's record", || {
                block_records(&path) == [("disk0".to_string(), 1, false)]
            });
        }
        Arc::into_inner(ledger)
            .unwrap()
            .close(Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            block_records(&path).len(),
            1,
            "the worker wrote it no second time"
        );
        let _ = std::fs::remove_file(&path);
    }

    // Two disks share the ledger and the sink, each served by its own worker.
    #[test]
    fn two_disks_keep_their_records_apart() {
        let path =
            std::env::temp_dir().join(format!("hvi-blk-worker-two-{}.ndjson", std::process::id()));
        let ledger = Arc::new(Ledger::new(Some(path.to_str().unwrap()), "vm").unwrap());
        ledger.set_gather_interval(Duration::from_millis(1));
        let sink = Arc::new(RecordingSink::default());
        {
            let disks = [
                Rig::new("disk0", &ledger, false),
                Rig::new("disk1", &ledger, false),
            ];
            for (n, rig) in (0u64..).zip(&disks) {
                let device = rig.driver.device.lock().unwrap();
                device.set_io_sink(Arc::clone(&sink) as Arc<dyn IoSink>);
                drop(device);
                rig.driver.start(&[RINGS]);
                rig.publish(0, VIRTIO_BLK_T_IN, n + 1);
                rig.kick();
            }
            let ids = disks
                .each_ref()
                .map(|rig| rig.driver.device.lock().unwrap().disk_id);
            assert_ne!(ids[0], ids[1]);

            wait_until("the ledger did not get both records", || {
                block_records(&path).len() == 2
            });
            let mut records = block_records(&path);
            records.sort();
            assert_eq!(
                records,
                [
                    ("disk0".to_string(), 1, false),
                    ("disk1".to_string(), 2, false)
                ]
            );
            let mut fed = sink.blocks.lock().unwrap().clone();
            fed.sort_unstable();
            let mut want = vec![(ids[0], 1, false), (ids[1], 2, false)];
            want.sort_unstable();
            assert_eq!(fed, want);
            assert_eq!(disks[0].data(0), [2; 4]);
            assert_eq!(disks[1].data(0), [3; 4]);
        }
        Arc::into_inner(ledger)
            .unwrap()
            .close(Instant::now() + Duration::from_secs(5))
            .unwrap();
        let _ = std::fs::remove_file(&path);
    }

    // While the first read is held, the used ring asks the driver not to
    // notify. A driver that sees that adds the second read with no
    // notification, and the worker serves it in the same pass. Notifications
    // are asked for again once the ring is empty.
    #[test]
    fn notifications_are_off_during_a_pass() {
        let rig = Rig::new("disk0", &no_ledger(), true);
        rig.driver.start(&[RINGS]);
        rig.publish(0, VIRTIO_BLK_T_IN, 1);
        rig.kick();
        rig.gate().wait_for_call();
        assert_eq!(rig.used_flags(), 1, "VRING_USED_F_NO_NOTIFY is set");

        rig.publish(1, VIRTIO_BLK_T_IN, 2);
        rig.gate().open();
        rig.gate().wait_for_call();
        rig.gate().open();

        wait_until("the notifications were not asked for again", || {
            rig.used_flags() == 0
        });
        assert_eq!(rig.used_idx(), 2, "both reads were served");
        assert_eq!(rig.data(1), [3; 4], "sector 2 reached the guest");
    }

    // KVM registers the eventfd `notify_fds` returns, and a guest's write to
    // QueueNotify signals it with no exit to hvi.
    #[cfg(target_os = "linux")]
    #[test]
    fn write_to_the_notify_fd_wakes_the_worker() {
        use crate::devices::virtio::Device as _;
        let rig = Rig::new("disk0", &no_ledger(), false);
        rig.driver.start(&[RINGS]);
        rig.publish(0, VIRTIO_BLK_T_IN, 1);
        {
            let device = rig.driver.device.lock().unwrap();
            let fds = device.notify_fds();
            assert_eq!(fds.len(), 1, "one eventfd for the one queue");
            fds[0].write(1).unwrap();
        }
        wait_until("the request was not served", || rig.used_idx() == 1);
        assert_eq!(rig.data(0), [2; 4]);
    }
}

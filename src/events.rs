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

//! The `RawEvent` NDJSON ledger of the VMM's observations.
//!
//! Each observation is one compact JSON object per line, so a reader can
//! `tail -f` the ledger or ingest it a line at a time without a parser for the
//! whole file.
//!
//! Every line is an envelope (`sandbox_id`, `ts`, `provenance`, `source`)
//! around a payload. The VMM writes `block` (disk I/O) and `net` (flow) records
//! from its own device models, and the tests below pin the shape of both, so
//! the format stays stable for readers. The VMM also writes the run's
//! lifecycle, as `vmm.start`, `vmm.vcpu_started` and `vmm.stop`.
//!
//! [`Ledger::emit_payload`] leaves the stream open to other sources: a plugin
//! (see [`crate::plugin`]) names its own `source` and supplies its own payload,
//! and its records interleave with the VMM's in one ledger. The envelope is
//! this crate's; the payload is not.
//!
//! The ledger's own thread writes the file, so a stalled write does not hold up
//! a thread that adds a record. A record is added to a buffer under a short
//! lock. [`Ledger::emit_payload`] and [`Ledger::batch`] then wait up to 100 ms
//! for the writer to write it, and return an error when it has not. While the
//! writes fail, they return the error at once. A record they report written has
//! reached the kernel, and it survives the death of the process. The `block`
//! and `net` records do not wait. The writer takes them at once when it is
//! idle. After each write it waits 1 ms for more records before it goes idle,
//! so the records of a burst are written together, within about 1 ms, and a
//! write in progress delays them until it ends. Once the buffer holds 4 MiB, a
//! `block` or `net` record is dropped and counted, and the next record added
//! follows a `vmm.dropped` record with the number dropped. The thread whose
//! record is the first dropped prints a line on stderr. Once a `block` or `net`
//! record fits after one second with no drop, the thread that added it prints
//! the number dropped since, and so does the thread that closes the ledger. A
//! record that waits for the writer is never dropped. A write that fails is
//! tried again at the same offset every 100 ms, so a record is never left half
//! written once a try succeeds. A write that keeps failing is given up one
//! [`STOP_TIMEOUT`] after the ledger is closed.
//!
//! A payload is serialized before the lock is taken. Its envelope, with the
//! `ts`, is serialized under the lock, so the lines appear in the file in the
//! order their `ts` was taken, and each line is added whole. No caller code
//! runs under the lock, so a panic in a caller's `Serialize` cannot poison it.
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this
// VMM's own.
#![allow(clippy::disallowed_methods)]

use std::borrow::Cow;
use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::value::RawValue;

use crate::teardown::STOP_TIMEOUT;
use crate::LOG_PREFIX;

/// A captured observation a device hands to the ledger.
///
/// It holds no serialized payload and no timestamp, so the devices do not
/// depend on serde or the clock.
pub(crate) enum CapturedEvent {
    /// A virtio-blk request: the disk's serial, starting sector, data bytes,
    /// and direction.
    Block {
        disk: Arc<str>,
        lba: u64,
        len: u64,
        write: bool,
    },
    /// A guest IPv4 flow observed at virtio-net.
    NetFlow {
        proto: u8,
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        bytes: u64,
        dns: Option<String>,
        /// TLS SNI from a ClientHello, when the flow carried one.
        sni: Option<String>,
    },
}

/// The `RawEvent` envelope (v1).
///
/// Generic over the payload, so a record can be built by a caller outside this
/// crate without the envelope enumerating every possible source. Declaration
/// order here *is* the wire order — derived `Serialize` emits fields in
/// order — which is what keeps the bytes identical to the adjacently-tagged
/// shape this replaced. The tests below pin it.
#[derive(Serialize)]
struct RawEvent<'a, P: Serialize> {
    sandbox_id: &'a str,
    ts: i64,
    provenance: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    corroboration: Option<&'a str>,
    source: &'a str,
    payload: P,
}

/// The payload of a `vmm.dropped` record.
#[derive(Serialize)]
struct DroppedPayload {
    /// The number of `block` and `net` records dropped since the last
    /// `vmm.dropped` record.
    records: u64,
}

#[derive(Serialize)]
struct BlockPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    disk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lba: Option<u64>,
    len: u64,
    rw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

#[derive(Serialize)]
struct NetPayload {
    five_tuple: FiveTuple,
    direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_initiated: Option<bool>,
    bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<String>,
}

#[derive(Serialize)]
struct FiveTuple {
    proto: u8,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

/// The period after which the writer tries a failed write again, and the time
/// [`Ledger::batch`] waits for the writer.
const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// The time the writer waits for more lines after a write before it goes idle,
/// so the lines of a burst are written together and the threads that add them
/// do not wake it for each.
const GATHER_INTERVAL: Duration = Duration::from_millis(1);

/// The capacity the writer leaves a buffer with after a write, so a buffer that
/// grew during a stall gives its memory back.
const KEPT_CAPACITY: usize = 128 * 1024;

/// The buffered bytes past which a `block` or `net` record is dropped.
const MAX_BUFFERED_BYTES: usize = 4 * 1024 * 1024;

/// The time with no record dropped after which a `block` or `net` record that
/// fits ends an [`Overflow`].
const OVERFLOW_QUIET_INTERVAL: Duration = Duration::from_secs(1);

/// The ledger a run writes, shared by the VMM and its plugin.
///
/// The ledger is disabled unless a path is given. It is a file of its own,
/// apart from the guest console on stdout and the capture logs on stderr. The
/// [module documentation](self) says when a record reaches the file.
///
/// Dropping a ledger that is not closed closes it, and waits up to
/// [`STOP_TIMEOUT`] for the writer to write what it holds. A write that blocks,
/// as on a hung network file system, holds the writer thread, the file and its
/// lock until it returns, so a ledger opened at the path meanwhile is refused.
pub struct Ledger {
    /// The sandbox identifier written into every record.
    sandbox_id: String,
    /// The buffer the ledger shares with its writer, or `None` when the ledger
    /// is disabled.
    shared: Option<Arc<Shared>>,
}

impl Ledger {
    /// Opens the ledger at `path` and starts its writer, or returns a disabled
    /// ledger when `path` is `None`.
    ///
    /// The file is created when missing and truncated. A symbolic link as the
    /// last component of `path` is refused. Anything else at `path` other than
    /// a regular file is refused too, since the writer writes at an offset. The
    /// writer holds a lock on the file until it exits, so a second ledger at
    /// `path`, in this process or another, is refused while the first writer
    /// still writes it. On a file system that cannot lock files, the ledger
    /// goes without the lock.
    ///
    /// # Errors
    ///
    /// Errors if the file cannot be opened, is a symbolic link or not a regular
    /// file, is locked by another ledger's writer, a reader or a disk, or the
    /// writer thread cannot be started.
    pub fn new(path: Option<&str>, sandbox_id: &str) -> io::Result<Self> {
        let shared = match path {
            Some(path) => {
                let file = open(path).map_err(|e| {
                    io::Error::new(e.kind(), format!("opening the ledger {path}: {e}"))
                })?;
                let shared = Arc::new(Shared {
                    state: Mutex::default(),
                    to_writer: Condvar::new(),
                    from_writer: Condvar::new(),
                });
                let writer = Arc::clone(&shared);
                std::thread::Builder::new()
                    .name("ledger writer".to_string())
                    .spawn(move || writer.run_writer(file))
                    .map_err(|e| {
                        io::Error::new(e.kind(), format!("spawning the ledger writer thread: {e}"))
                    })?;
                Some(shared)
            }
            None => None,
        };
        Ok(Ledger {
            sandbox_id: sandbox_id.to_string(),
            shared,
        })
    }

    /// Returns whether the ledger writes a file.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.shared.is_some()
    }

    /// Writes `payload` as one `RawEvent` record tagged with `source`, waiting
    /// up to 100 ms for the writer.
    ///
    /// This is how a [`crate::plugin::Plugin`] puts its own records in the same
    /// ledger as the VMM's.
    ///
    /// # Errors
    ///
    /// Errors as [`Ledger::batch`] does.
    pub fn emit_payload<P: Serialize>(
        &self,
        provenance: &str,
        source: &str,
        payload: &P,
    ) -> io::Result<()> {
        self.batch(|batch| batch.emit_payload(provenance, source, payload))
    }

    /// Writes the records `f` adds to a [`Batch`], one after another, waiting
    /// up to 100 ms for the writer.
    ///
    /// The batch follows the records added before it, and no other record falls
    /// between its own. A batch with no records waits for the records added
    /// before it. `f` runs whether or not the ledger is enabled. A disabled
    /// ledger writes nothing and returns `Ok`.
    ///
    /// # Errors
    ///
    /// Errors with [`io::ErrorKind::TimedOut`] when the writer has not written
    /// the batch within 100 ms, and at once while the writer's writes fail. The
    /// batch stays buffered, and is written once the write that holds it up
    /// succeeds. Errors with [`io::ErrorKind::InvalidData`] when a payload
    /// fails to serialize, and none of the batch is added. Errors with
    /// [`io::ErrorKind::Other`] when the ledger is closed, and the batch is not
    /// written.
    pub fn batch(&self, f: impl FnOnce(&mut Batch)) -> io::Result<()> {
        self.submit(|| Instant::now() + FLUSH_INTERVAL, false, f)
    }

    /// Writes the records `f` adds to a [`Batch`], waiting for the writer until
    /// `deadline`.
    ///
    /// When `deadline` has passed, it adds the records and returns at once.
    ///
    /// # Errors
    ///
    /// Errors as [`Ledger::batch`] does, with `deadline` in place of
    /// [`FLUSH_INTERVAL`].
    pub(crate) fn batch_until(
        &self,
        deadline: Instant,
        f: impl FnOnce(&mut Batch),
    ) -> io::Result<()> {
        self.submit(|| deadline, false, f)
    }

    /// Closes the ledger, waiting until `deadline` for the writer to write the
    /// records added before the close.
    ///
    /// It takes the ledger by value, so a holder of a shared handle, such as a
    /// plugin, cannot close it.
    ///
    /// # Errors
    ///
    /// Errors with [`io::ErrorKind::TimedOut`] when the writer has not written
    /// the records by `deadline`, and they stay buffered. A writer whose writes
    /// fail tries them until one [`STOP_TIMEOUT`] after the close, then drops
    /// them, and a call still waiting errors with [`io::ErrorKind::Other`].
    pub fn close(self, deadline: Instant) -> io::Result<()> {
        self.close_with(deadline, |_| {})
    }

    /// Writes the records `f` adds to a [`Batch`] as the ledger's last, waiting
    /// for the writer until `deadline`.
    ///
    /// The ledger takes no record after these. A payload that fails to
    /// serialize leaves the batch out, and the ledger is closed without it.
    ///
    /// # Errors
    ///
    /// Errors as [`Ledger::close`] does, and with
    /// [`io::ErrorKind::InvalidData`] when a payload fails to serialize. A
    /// ledger already closed adds nothing, waits until `deadline` for the
    /// records added before it closed, and then errors.
    pub(crate) fn close_with(
        &self,
        deadline: Instant,
        f: impl FnOnce(&mut Batch),
    ) -> io::Result<()> {
        self.submit(|| deadline, true, f)
    }

    /// Adds the `block` and `net` records of `events`, with `boundary`
    /// provenance, observed by the host at the device model.
    ///
    /// It does not wait for the writer. A record that does not fit in the
    /// buffer is dropped.
    pub(crate) fn captured(&self, events: &[CapturedEvent]) {
        let Some(shared) = &self.shared else {
            return;
        };
        if events.is_empty() {
            return;
        }
        let mut batch = Batch::new(true);
        for event in events {
            batch.captured(event);
        }
        let mut state = shared.state.lock().unwrap();
        if state.closed {
            return;
        }
        let (wake, report) = self.add(&mut state, &batch, true);
        drop(state);
        if wake {
            shared.to_writer.notify_one();
        }
        report.print();
    }

    /// Returns the number of `block` and `net` records dropped because the
    /// buffer was full.
    pub(crate) fn dropped(&self) -> u64 {
        self.shared
            .as_ref()
            .map_or(0, |shared| shared.state.lock().unwrap().dropped)
    }

    /// Makes the writer wait `interval` for more lines after a write, in place
    /// of [`GATHER_INTERVAL`].
    #[cfg(test)]
    pub(crate) fn set_gather_interval(&self, interval: Duration) {
        if let Some(shared) = &self.shared {
            shared.state.lock().unwrap().gather_interval = Some(interval);
        }
    }

    /// Returns once `done` holds for the ledger's state, or after five seconds.
    #[cfg(test)]
    fn wait_until(&self, done: impl Fn(&State) -> bool) {
        let Some(shared) = &self.shared else {
            return;
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done(&shared.state.lock().unwrap()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Returns once the writer has taken lines it has not written yet, or after
    /// five seconds.
    #[cfg(test)]
    pub(crate) fn wait_until_writing(&self) {
        self.wait_until(|state| state.pending > 0);
    }

    /// Returns once the writer waits for more lines after a write, or after
    /// five seconds.
    #[cfg(test)]
    pub(crate) fn wait_until_gathering(&self) {
        self.wait_until(|state| state.gathering);
    }

    /// Returns once a batch waits for the writer, or after five seconds.
    #[cfg(test)]
    fn wait_until_urgent(&self) {
        self.wait_until(|state| state.urgent);
    }

    /// Returns once the ledger is closed, or after five seconds.
    #[cfg(test)]
    fn wait_until_closed(&self) {
        self.wait_until(|state| state.closed);
    }

    /// Makes the writer's writes block while `paused`, as a write that stalls
    /// does.
    #[cfg(test)]
    pub(crate) fn set_paused(&self, paused: bool) {
        if let Some(shared) = &self.shared {
            shared.state.lock().unwrap().paused = paused;
            shared.to_writer.notify_all();
        }
    }

    /// Makes the writer's next write fail once it has written the first
    /// `written` bytes, as a write that runs out of space does.
    #[cfg(test)]
    pub(crate) fn fail_next_write(&self, written: usize) {
        if let Some(shared) = &self.shared {
            shared.state.lock().unwrap().fail_after = Some(written);
        }
    }

    /// Returns once the writer has seen a write fail, or after five seconds.
    #[cfg(test)]
    pub(crate) fn wait_until_failing(&self) {
        self.wait_until(|state| state.failing);
    }

    /// Makes every write of the writer fail while `failing`, as a file system
    /// that has turned read-only does.
    #[cfg(test)]
    pub(crate) fn set_fail_writes(&self, failing: bool) {
        if let Some(shared) = &self.shared {
            shared.state.lock().unwrap().fail_writes = failing;
        }
    }

    /// Writes the records `f` adds to a [`Batch`], waiting for the writer until
    /// `deadline`.
    ///
    /// When `last`, the ledger is closed after them.
    ///
    /// # Errors
    ///
    /// Errors as [`Ledger::close_with`] and [`Ledger::batch`] do.
    fn submit(
        &self,
        deadline: impl FnOnce() -> Instant,
        last: bool,
        f: impl FnOnce(&mut Batch),
    ) -> io::Result<()> {
        let mut batch = Batch::new(self.is_enabled());
        f(&mut batch);
        // The wait counts from here, so the time `f` takes to serialize the
        // payloads is not taken from it.
        let deadline = deadline();
        let Some(shared) = &self.shared else {
            return Ok(());
        };
        // A batch is added whole or not at all. One that closes the ledger
        // closes it either way.
        let error = match batch.error.take() {
            Some(e) if !last => return Err(e),
            Some(e) => {
                batch.records.clear();
                Some(e)
            }
            None => None,
        };
        let mut state = shared.state.lock().unwrap();
        if state.closed {
            // Nothing is added once the ledger is closed, so the batches added
            // so far end with the one that closed it.
            if last {
                let added = state.added;
                shared.wait_for_writes(state, added, deadline, true)?;
            }
            return Err(closed_error());
        }
        // Records that are never dropped start or end no overflow, so only the
        // close has one to report.
        self.add(&mut state, &batch, false);
        let report = if last {
            state.close()
        } else {
            state.urgent = true;
            OverflowReport::default()
        };
        let added = state.added;
        shared.to_writer.notify_one();
        let state = shared.print_unlocked(state, &report);
        shared.wait_for_writes(state, added, deadline, last)?;
        error.map_or(Ok(()), Err)
    }

    /// Adds the records of `batch` to the buffer of `state`, each in its
    /// envelope and stamped with the time it is added.
    ///
    /// It returns whether the writer has to be woken, and the overflows the
    /// batch started or ended. The writer has to be woken when it waits for
    /// lines and the batch added some. When `droppable`, a record that does not
    /// fit in the buffer is dropped. The first record added after a run of
    /// drops follows a `vmm.dropped` record that counts them.
    fn add(&self, state: &mut State, batch: &Batch, droppable: bool) -> (bool, OverflowReport) {
        let before = state.lines.len();
        let mut report = OverflowReport::default();
        for record in &batch.records {
            // The lines are serialized into the buffer and cut off again when
            // the record does not fit, so the buffer never holds part of one.
            let end = state.lines.len();
            if state.unmarked > 0 {
                let marker = RawEvent {
                    sandbox_id: &self.sandbox_id,
                    ts: now_ns(),
                    provenance: "vmm",
                    corroboration: None,
                    source: "vmm.dropped",
                    payload: DroppedPayload {
                        records: state.unmarked,
                    },
                };
                serde_json::to_writer(&mut state.lines, &marker)
                    .expect("a count should serialize into memory");
                state.lines.push(b'\n');
            }
            let event = RawEvent {
                sandbox_id: &self.sandbox_id,
                ts: now_ns(),
                provenance: &record.provenance,
                corroboration: None,
                source: &record.source,
                payload: &*record.payload,
            };
            serde_json::to_writer(&mut state.lines, &event)
                .expect("an envelope around a serialized payload should serialize into memory");
            state.lines.push(b'\n');
            if droppable && state.is_over_cap() {
                state.lines.truncate(end);
                state.unmarked += 1;
                state.dropped += 1;
                let last_drop = Instant::now();
                let overflow = state.overflow.get_or_insert_with(|| {
                    report.started = true;
                    Overflow {
                        dropped: 0,
                        last_drop,
                    }
                });
                overflow.dropped += 1;
                overflow.last_drop = last_drop;
            } else {
                state.unmarked = 0;
                let is_quiet = state.overflow.as_ref().is_some_and(|overflow| {
                    overflow.last_drop.elapsed() >= OVERFLOW_QUIET_INTERVAL
                });
                if droppable && is_quiet {
                    state.end_overflow(&mut report);
                }
            }
        }
        state.added += 1;
        let after = state.lines.len();
        // Only the first thread to add lines while the writer waits wakes it.
        let wake = state.idle && after > before;
        if wake {
            state.idle = false;
        }
        (wake, report)
    }
}

impl Drop for Ledger {
    fn drop(&mut self) {
        let Some(shared) = &self.shared else {
            return;
        };
        let mut state = shared.state.lock().unwrap();
        if state.closed {
            return;
        }
        // The close counts as a batch, as a close with records does, so the
        // wait lasts until the writer has closed the file and released its
        // lock.
        let report = state.close();
        state.added += 1;
        shared.to_writer.notify_one();
        let added = state.added;
        let state = shared.print_unlocked(state, &report);
        let _ = shared.wait_for_writes(state, added, Instant::now() + STOP_TIMEOUT, true);
    }
}

/// What a [`Ledger`] shares with the thread that writes its file.
struct Shared {
    /// The buffer and the writer's progress.
    state: Mutex<State>,
    /// The condition variable that wakes the writer.
    to_writer: Condvar,
    /// The condition variable that wakes the threads waiting for the writer.
    from_writer: Condvar,
}

/// The buffer of a [`Ledger`] and the progress of its writer.
#[derive(Default)]
struct State {
    /// The lines added that the writer has not taken yet.
    lines: Vec<u8>,
    /// The number of bytes the writer has taken and not written yet.
    pending: usize,
    /// The number of batches added.
    added: u64,
    /// The number of batches written.
    written: u64,
    /// The number of `block` and `net` records dropped because the buffer was
    /// full.
    dropped: u64,
    /// The number of records dropped since the last `vmm.dropped` record.
    unmarked: u64,
    /// The overflow in progress, or `None` between overflows.
    overflow: Option<Overflow>,
    /// Whether a thread waits for lines the writer has not taken yet.
    urgent: bool,
    /// Whether the writer waits for lines, so the thread that adds some has to
    /// wake it.
    idle: bool,
    /// Whether the ledger takes no more records.
    closed: bool,
    /// Whether the writer's last write failed.
    failing: bool,
    /// Whether the writer has given up on writes that kept failing.
    gave_up: bool,
    /// Whether the writer's writes block.
    #[cfg(test)]
    paused: bool,
    /// Whether every write of the writer fails.
    #[cfg(test)]
    fail_writes: bool,
    /// The number of bytes the writer's next write writes before it fails.
    #[cfg(test)]
    fail_after: Option<usize>,
    /// The time the writer waits for more lines after a write, in place of
    /// [`GATHER_INTERVAL`].
    #[cfg(test)]
    gather_interval: Option<Duration>,
    /// Whether the writer waits for more lines after a write.
    #[cfg(test)]
    gathering: bool,
}

/// A time in which the buffer drops records.
///
/// It starts at the first drop, which a line on stderr announces. It goes on
/// while records keep being dropped, so a buffer that fills again at each write
/// makes one overflow. It ends at a `block` or `net` record that fits once
/// [`OVERFLOW_QUIET_INTERVAL`] has passed with no drop, or at the close.
struct Overflow {
    /// The number of records dropped in the overflow.
    dropped: u64,
    /// When the last record was dropped.
    last_drop: Instant,
}

/// The overflows that adding one batch started or ended, as the lines on stderr
/// report them.
#[derive(Default)]
struct OverflowReport {
    /// Whether the batch started an overflow.
    started: bool,
    /// The number of records dropped in the overflow the batch ended, or 0.
    ended: u64,
}

impl OverflowReport {
    /// Returns whether the report has nothing to print.
    fn is_empty(&self) -> bool {
        !self.started && self.ended == 0
    }

    /// Prints a line on stderr for the overflow the batch ended and the one it
    /// started.
    ///
    /// It must run with the ledger's lock released, so a stderr that blocks
    /// holds up no other thread that adds a record.
    fn print(&self) {
        if self.ended > 0 {
            stderrln!(
                "{LOG_PREFIX} the ledger dropped {} block and net records while its buffer was full",
                self.ended
            );
        }
        if self.started {
            stderrln!("{LOG_PREFIX} the ledger's buffer is full; dropping block and net records");
        }
    }
}

impl State {
    /// Returns whether the writer has to run although it has no lines, for a
    /// batch that waits or for the close.
    fn is_due(&self) -> bool {
        self.closed || self.urgent
    }

    /// Returns whether the lines buffered and those the writer has taken hold
    /// more than [`MAX_BUFFERED_BYTES`].
    fn is_over_cap(&self) -> bool {
        self.lines.len() + self.pending > MAX_BUFFERED_BYTES
    }

    /// Ends the overflow, if one goes on, so that `report` counts it.
    fn end_overflow(&mut self, report: &mut OverflowReport) {
        if let Some(overflow) = self.overflow.take() {
            // An overflow can start and end in one batch, when its records are
            // added a second or more apart.
            report.started = false;
            report.ended = overflow.dropped;
        }
    }

    /// Closes the ledger.
    ///
    /// It returns the overflow the close ends, if one goes on.
    fn close(&mut self) -> OverflowReport {
        self.closed = true;
        let mut report = OverflowReport::default();
        self.end_overflow(&mut report);
        report
    }

    /// Records, for the tests, whether the writer waits for more lines after a
    /// write.
    fn set_gathering(&mut self, gathering: bool) {
        #[cfg(test)]
        {
            self.gathering = gathering;
        }
        #[cfg(not(test))]
        let _ = gathering;
    }

    /// Returns how long the writer waits for more lines after a write.
    fn gather_interval(&self) -> Duration {
        #[cfg(test)]
        if let Some(interval) = self.gather_interval {
            return interval;
        }
        GATHER_INTERVAL
    }
}

impl Shared {
    /// Writes the buffered lines to `file` until the ledger is closed and every
    /// line is written.
    ///
    /// A write that fails is tried again every [`FLUSH_INTERVAL`] at the same
    /// offset, with the lines added since. The bytes it wrote before it failed
    /// are a prefix of what the next try writes, so no record is left half
    /// written once a try succeeds. Once the ledger is closed, the writes are
    /// tried for one more [`STOP_TIMEOUT`] and then given up: the lines are
    /// dropped, the threads that wait return an error, and the file is closed.
    /// A try given up can leave part of a line in the file.
    ///
    /// The thread can start before a run's seccomp filters are armed, so it
    /// calls [`crate::sandbox::confine_io_thread`] before each write.
    fn run_writer(&self, file: File) {
        let mut taken = Vec::new();
        // The file was truncated as it was opened, and this thread is the only
        // one that writes it.
        let mut offset = 0;
        let mut failing = false;
        let mut give_up_at = None;
        let mut wrote = false;
        loop {
            let mut state = if failing {
                std::thread::sleep(FLUSH_INTERVAL);
                self.state.lock().unwrap()
            } else {
                self.wait_for_lines(wrote)
            };
            if state.closed && state.lines.is_empty() && taken.is_empty() {
                break;
            }
            if failing && state.closed {
                let give_up_at = *give_up_at.get_or_insert_with(|| Instant::now() + STOP_TIMEOUT);
                if Instant::now() >= give_up_at {
                    let lost = taken.len() + state.lines.len();
                    state.lines = Vec::new();
                    state.pending = 0;
                    state.gave_up = true;
                    self.from_writer.notify_all();
                    drop(state);
                    stderrln!(
                        "{LOG_PREFIX} writing the ledger: giving up; {lost} bytes not written"
                    );
                    // The file is closed, and its lock released, as the thread
                    // returns. The closing batch is not reported written.
                    return;
                }
            }
            if taken.is_empty() {
                std::mem::swap(&mut state.lines, &mut taken);
            } else {
                taken.extend_from_slice(&state.lines);
                state.lines.clear();
            }
            state.pending = taken.len();
            state.urgent = false;
            let added = state.added;
            drop(state);

            crate::sandbox::confine_io_thread();
            let written = self.write_all_at(&file, &taken, offset);
            // The line is printed before the lock is taken, so a stderr that
            // blocks holds up no thread that adds a record.
            match &written {
                Ok(()) if failing => stderrln!("{LOG_PREFIX} writes to the ledger succeed again"),
                Err(e) if !failing => stderrln!(
                    "{LOG_PREFIX} writing the ledger: {e}; trying again every {FLUSH_INTERVAL:?}"
                ),
                _ => {}
            }
            failing = written.is_err();
            if failing {
                self.state.lock().unwrap().failing = true;
                // A batch that waits stops once the writes fail.
                self.from_writer.notify_all();
                continue;
            }
            offset += taken.len() as u64;
            wrote = true;
            taken.clear();
            // The buffer is shrunk before the next swap hands it to the threads
            // that add lines.
            taken.shrink_to(KEPT_CAPACITY);
            let mut state = self.state.lock().unwrap();
            state.failing = false;
            state.pending = 0;
            if state.closed && state.lines.is_empty() {
                break;
            }
            state.written = added;
            self.from_writer.notify_all();
        }
        // The file is closed, and its lock released, before the last batches
        // are reported written, so a ledger opened at the path once the close
        // returns can lock it.
        drop(file);
        let mut state = self.state.lock().unwrap();
        state.written = state.added;
        self.from_writer.notify_all();
    }

    /// Writes `bytes` to `file` at `offset`.
    ///
    /// In tests it first waits while `Ledger::set_paused` holds it, fails once
    /// it has written the first bytes `Ledger::fail_next_write` asked for, and
    /// fails while `Ledger::set_fail_writes` asks it to.
    fn write_all_at(&self, file: &File, bytes: &[u8], offset: u64) -> io::Result<()> {
        #[cfg(test)]
        {
            let state = self.state.lock().unwrap();
            let mut state = self
                .to_writer
                .wait_while(state, |state| state.paused)
                .unwrap();
            let fail_after = state.fail_after.take();
            let fail_writes = state.fail_writes;
            drop(state);
            if fail_writes {
                return Err(io::Error::other("the test failed the write"));
            }
            if let Some(written) = fail_after {
                file.write_all_at(&bytes[..written.min(bytes.len())], offset)?;
                return Err(io::Error::other("the test failed the write"));
            }
        }
        file.write_all_at(bytes, offset)
    }

    /// Returns the state once the writer has lines to take or
    /// [`State::is_due`].
    ///
    /// Lines added during the last write are taken at once. Otherwise, when
    /// `wrote` says the call follows a write, the writer first waits
    /// [`GATHER_INTERVAL`], which a `block` or `net` record does not cut short,
    /// so the lines that arrive meanwhile are written together. It then marks
    /// the writer idle and waits without a timeout, so an idle ledger costs no
    /// wakeup, and the thread that adds lines wakes it.
    fn wait_for_lines(&self, wrote: bool) -> MutexGuard<'_, State> {
        let mut state = self.state.lock().unwrap();
        if wrote {
            let gather = state.gather_interval();
            state.set_gathering(true);
            (state, _) = self
                .to_writer
                .wait_timeout_while(state, gather, |state| {
                    state.lines.is_empty() && !state.is_due()
                })
                .unwrap();
            state.set_gathering(false);
        }
        if !state.lines.is_empty() || state.is_due() {
            return state;
        }
        state.idle = true;
        let mut state = self
            .to_writer
            .wait_while(state, |state| state.lines.is_empty() && !state.is_due())
            .unwrap();
        state.idle = false;
        state
    }

    /// Prints `report`, when it has anything to print, with the lock released.
    ///
    /// It takes the lock again and returns it.
    fn print_unlocked<'a>(
        &'a self,
        state: MutexGuard<'a, State>,
        report: &OverflowReport,
    ) -> MutexGuard<'a, State> {
        if report.is_empty() {
            return state;
        }
        drop(state);
        report.print();
        self.state.lock().unwrap()
    }

    /// Waits, until `deadline` at the latest, for the writer to have written
    /// the first `added` batches.
    ///
    /// Unless the batch is the `last`, which closes the ledger, it stops
    /// waiting while the writer's writes fail, since the next try can be
    /// [`FLUSH_INTERVAL`] away.
    ///
    /// # Errors
    ///
    /// Errors with [`io::ErrorKind::TimedOut`] when the writer has not written
    /// them by `deadline`, or while its writes fail unless `last`. Errors with
    /// [`io::ErrorKind::Other`] once the writer has given up on writes that
    /// kept failing.
    fn wait_for_writes(
        &self,
        state: MutexGuard<'_, State>,
        added: u64,
        deadline: Instant,
        last: bool,
    ) -> io::Result<()> {
        let left = deadline.saturating_duration_since(Instant::now());
        let (state, _) = self
            .from_writer
            .wait_timeout_while(state, left, |state| {
                state.written < added && !state.gave_up && (last || !state.failing)
            })
            .unwrap();
        if state.written >= added {
            Ok(())
        } else if state.gave_up {
            Err(io::Error::other(
                "the ledger gave up on writes that kept failing",
            ))
        } else {
            Err(buffered_error(&state))
        }
    }
}

/// Returns the error for records the writer has not written yet.
///
/// The message says why, when the writer's writes fail or it is still in a
/// write.
fn buffered_error(state: &State) -> io::Error {
    let why = if state.failing {
        "the ledger's writes fail"
    } else if state.pending > 0 {
        "the ledger is still in a write"
    } else {
        "the records are not written yet"
    };
    io::Error::new(io::ErrorKind::TimedOut, why)
}

/// Returns the error for records added once the ledger is closed.
fn closed_error() -> io::Error {
    io::Error::other("the ledger is closed")
}

/// Opens the ledger file at `path` for writing and locks it.
///
/// The file is truncated once it is known to be a regular file. `O_NOFOLLOW`
/// refuses a symbolic link as the last component of `path`. `O_NONBLOCK` keeps
/// the open of a FIFO from waiting for a reader, so the open of one with no
/// reader fails. `O_NOCTTY` keeps a terminal from becoming the controlling one.
fn open(path: &str) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|e| {
            // `O_NOFOLLOW` refuses a link with `ELOOP`, whose message is about
            // a loop of links. A loop of links in a parent directory also
            // returns `ELOOP`, so the path itself is checked.
            let is_link = || std::fs::symlink_metadata(path).is_ok_and(|m| m.is_symlink());
            if e.raw_os_error() == Some(libc::ELOOP) && is_link() {
                io::Error::new(io::ErrorKind::InvalidInput, "a symbolic link")
            } else {
                e
            }
        })?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the file is open elsewhere",
            ))
        }
        Err(TryLockError::Error(e)) if !is_lock_unsupported(&e) => return Err(e),
        Err(TryLockError::Error(_)) => {}
    }
    // The length is read once the lock is held, since another ledger's writer
    // can grow the file until then.
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    // An empty file is left as it is, since on ext4 a truncate makes the close
    // of the file flush it, which delays the stop.
    if metadata.len() > 0 {
        file.set_len(0)?;
    }
    Ok(file)
}

/// Returns whether `error` says the file system cannot lock files.
fn is_lock_unsupported(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        code == libc::ENOLCK || code == libc::ENOTSUP || code == libc::EOPNOTSUPP
    })
}

/// Records for a [`Ledger`], which [`Ledger::batch`] writes together.
///
/// A record's payload is serialized as it is added to the batch, and its
/// envelope when the batch is added to the ledger.
pub struct Batch {
    /// Whether the ledger the batch is for writes a file.
    enabled: bool,
    /// The records added so far.
    records: Vec<Record>,
    /// The error of the first payload that failed to serialize.
    error: Option<io::Error>,
}

/// A record in a [`Batch`], with its payload already serialized.
struct Record {
    /// The record's `provenance`.
    provenance: Cow<'static, str>,
    /// The record's `source`.
    source: Cow<'static, str>,
    /// The record's payload, as JSON.
    payload: Box<RawValue>,
}

impl Batch {
    /// Returns an empty batch for a ledger that writes a file when `enabled`.
    fn new(enabled: bool) -> Self {
        Batch {
            enabled,
            records: Vec::new(),
            error: None,
        }
    }

    /// Returns whether the ledger the batch is for writes a file.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Adds one `RawEvent` record, a caller's payload tagged with the caller's
    /// `source`.
    ///
    /// A payload that fails to serialize leaves the whole batch out, and the
    /// call that writes the batch errors.
    pub fn emit_payload<P: Serialize>(&mut self, provenance: &str, source: &str, payload: &P) {
        if !self.enabled {
            return;
        }
        self.push(
            Cow::Owned(provenance.to_string()),
            Cow::Owned(source.to_string()),
            payload,
        );
    }

    /// Adds one record with `provenance`, `source` and `payload`, unless the
    /// payload fails to serialize.
    ///
    /// The first failure is kept in `error`.
    fn push<P: Serialize>(
        &mut self,
        provenance: Cow<'static, str>,
        source: Cow<'static, str>,
        payload: &P,
    ) {
        match serde_json::value::to_raw_value(payload) {
            Ok(payload) => self.records.push(Record {
                provenance,
                source,
                payload,
            }),
            Err(e) => {
                self.error.get_or_insert_with(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("serializing the {source} payload: {e}"),
                    )
                });
            }
        }
    }

    /// Adds the record of a captured device event, with `boundary` provenance.
    fn captured(&mut self, event: &CapturedEvent) {
        match event {
            CapturedEvent::Block {
                disk,
                lba,
                len,
                write,
            } => self.push(
                Cow::Borrowed("boundary"),
                Cow::Borrowed("block"),
                &BlockPayload {
                    disk: Some(disk.to_string()),
                    lba: Some(*lba),
                    len: *len,
                    rw: if *write { "w" } else { "r" }.to_string(),
                    path: None,
                },
            ),
            CapturedEvent::NetFlow {
                proto,
                src,
                src_port,
                dst,
                dst_port,
                bytes,
                dns,
                sni,
            } => self.push(
                Cow::Borrowed("boundary"),
                Cow::Borrowed("net"),
                &NetPayload {
                    five_tuple: FiveTuple {
                        proto: *proto,
                        src_ip: src.to_string(),
                        src_port: *src_port,
                        dst_ip: dst.to_string(),
                        dst_port: *dst_port,
                    },
                    direction: "egress".to_string(),
                    guest_initiated: Some(true),
                    bytes: *bytes,
                    sni: sni.clone(),
                    dns: dns.clone(),
                },
            ),
        }
    }
}

/// Host wall-clock in nanoseconds since the Unix epoch (the envelope's `ts`).
fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serialize an envelope with a fixed ts and assert the exact wire bytes,
    // pinning the RawEvent wire format. These also
    // pin the field order the generic envelope has to reproduce: `source` and
    // `payload` sit where the adjacent tag used to put them.
    fn line<P: Serialize>(provenance: &str, source: &str, payload: P) -> String {
        let ev = RawEvent {
            sandbox_id: "vm1",
            ts: 1,
            provenance,
            corroboration: None,
            source,
            payload,
        };
        serde_json::to_string(&ev).unwrap()
    }

    #[test]
    fn block_write_wire_shape() {
        let s = line(
            "boundary",
            "block",
            BlockPayload {
                disk: Some("disk0".into()),
                lba: Some(2048),
                len: 4096,
                rw: "w".into(),
                path: None,
            },
        );
        assert_eq!(
            s,
            r#"{"sandbox_id":"vm1","ts":1,"provenance":"boundary","source":"block","payload":{"disk":"disk0","lba":2048,"len":4096,"rw":"w"}}"#
        );
    }

    #[test]
    fn net_dns_wire_shape() {
        let s = line(
            "boundary",
            "net",
            NetPayload {
                five_tuple: FiveTuple {
                    proto: 17,
                    src_ip: "10.0.2.15".into(),
                    src_port: 40000,
                    dst_ip: "10.0.2.3".into(),
                    dst_port: 53,
                },
                direction: "egress".into(),
                guest_initiated: Some(true),
                bytes: 72,
                sni: None,
                dns: Some("example.com".into()),
            },
        );
        assert_eq!(
            s,
            r#"{"sandbox_id":"vm1","ts":1,"provenance":"boundary","source":"net","payload":{"five_tuple":{"proto":17,"src_ip":"10.0.2.15","src_port":40000,"dst_ip":"10.0.2.3","dst_port":53},"direction":"egress","guest_initiated":true,"bytes":72,"dns":"example.com"}}"#
        );
    }

    /// Returns a ledger path in the temporary directory, named after `name`.
    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hvi-ledger-{name}-{}.ndjson", std::process::id()))
    }

    /// Returns the lines of the ledger file at `path`.
    ///
    /// It removes the file.
    fn take_lines(path: &std::path::Path) -> Vec<String> {
        let text = std::fs::read_to_string(path).unwrap();
        let _ = std::fs::remove_file(path);
        text.lines().map(str::to_string).collect()
    }

    /// Returns the `ts` of the ledger record `line`.
    fn ts(line: &str) -> i64 {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["ts"].as_i64().unwrap()
    }

    /// Returns the `source` of the ledger record `line`.
    fn source(line: &str) -> String {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["source"].as_str().unwrap().to_string()
    }

    /// Returns a captured virtio-blk write.
    fn block() -> CapturedEvent {
        CapturedEvent::Block {
            disk: "disk0".into(),
            lba: 8,
            len: 4096,
            write: true,
        }
    }

    // `mem::forget` stands in for a death such as `SIGKILL`.
    #[test]
    fn emitted_record_is_in_the_file_without_a_destructor() {
        let path = temp_path("emit");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        let written = ledger.batch_until(Instant::now() + Duration::from_secs(5), |batch| {
            batch.emit_payload("rich", "plugin", &7);
        });
        assert!(written.is_ok());
        std::mem::forget(ledger);
        assert_eq!(take_lines(&path).len(), 1);
    }

    #[test]
    fn captured_record_reaches_the_file_with_no_record_after_it() {
        let path = temp_path("captured");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.captured(&[block()]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read_to_string(&path).unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let lines = take_lines(&path);
        assert_eq!(
            lines,
            [format!(
                r#"{{"sandbox_id":"vm1","ts":{},"provenance":"boundary","source":"block","payload":{{"disk":"disk0","lba":8,"len":4096,"rw":"w"}}}}"#,
                ts(&lines[0])
            )]
        );
    }

    // The second record is added while the writer is in a write, so nothing
    // wakes the writer for it: the writer takes it as that write returns.
    #[test]
    fn record_added_during_a_write_is_written_after_it() {
        let path = temp_path("during");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.set_paused(true);
        ledger.captured(&[block()]);
        ledger.wait_until_writing();
        ledger.captured(&[block()]);
        ledger.set_paused(false);
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::fs::read_to_string(&path).unwrap().lines().count() < 2
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        drop(ledger);
        let _ = std::fs::remove_file(&path);
        assert_eq!(lines, 2);
    }

    // The gather is long. The second record is added while the writer gathers
    // after the first, so it is written only as the gather ends. A writer woken
    // for it would write it far sooner, and one that went idle without taking
    // it would never write it.
    #[test]
    fn record_added_after_a_write_waits_for_the_gather() {
        let path = temp_path("gather");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        let gather = Duration::from_secs(1);
        ledger.set_gather_interval(gather);
        let deadline = Instant::now() + Duration::from_secs(10);
        ledger.captured(&[block()]);
        ledger.wait_until_gathering();
        let added = Instant::now();
        ledger.captured(&[block()]);
        while std::fs::read_to_string(&path).unwrap().lines().count() < 2
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        let waited = added.elapsed();
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        drop(ledger);
        let _ = std::fs::remove_file(&path);
        assert_eq!(lines, 2);
        assert!(waited > gather / 2, "{waited:?}");
    }

    #[test]
    fn emitted_record_follows_the_buffered_records() {
        let path = temp_path("order");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.captured(&[
            block(),
            CapturedEvent::NetFlow {
                proto: 17,
                src: Ipv4Addr::new(10, 0, 2, 15),
                src_port: 40000,
                dst: Ipv4Addr::new(10, 0, 2, 3),
                dst_port: 53,
                bytes: 40,
                dns: Some("crates.io".into()),
                sni: None,
            },
        ]);
        let written = ledger.batch_until(Instant::now() + Duration::from_secs(5), |batch| {
            batch.emit_payload("rich", "plugin", &7);
        });
        assert!(written.is_ok());

        let lines = take_lines(&path);
        let records: Vec<serde_json::Value> = lines
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let sources: Vec<_> = records.iter().map(|record| &record["source"]).collect();
        assert_eq!(sources, ["block", "net", "plugin"]);
        assert_eq!(records[1]["payload"]["dns"], "crates.io");
    }

    // A plugin's `Serialize` runs before the lock is taken, so its panic cannot
    // poison the lock.
    #[test]
    fn panicking_payload_leaves_the_ledger_usable() {
        struct Panics;
        impl Serialize for Panics {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                panic!("the payload panicked")
            }
        }
        let path = temp_path("panic");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = ledger.emit_payload("rich", "plugin", &Panics);
        }));
        assert!(panicked.is_err());
        let written = ledger.batch_until(Instant::now() + Duration::from_secs(5), |batch| {
            batch.emit_payload("rich", "plugin", &7);
        });
        assert!(written.is_ok());
        assert_eq!(take_lines(&path).len(), 1);
    }

    #[test]
    fn batch_stays_buffered_while_the_writer_stalls() {
        let path = temp_path("stalled");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.set_paused(true);
        ledger.captured(&[block()]);
        ledger.wait_until_writing();
        let start = Instant::now();
        let stalled = ledger
            .batch_until(start + Duration::from_millis(20), |batch| {
                batch.emit_payload("vmm", "vmm.start", &7);
            })
            .unwrap_err();
        assert_eq!(stalled.kind(), io::ErrorKind::TimedOut);
        assert!(
            stalled.to_string().contains("still in a write"),
            "{stalled}"
        );
        assert!(start.elapsed() >= Duration::from_millis(20));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");

        ledger.set_paused(false);
        assert!(ledger
            .close_with(Instant::now() + Duration::from_secs(5), |_| {})
            .is_ok());
        assert_eq!(take_lines(&path).len(), 2);
    }

    #[test]
    fn failed_write_is_tried_again_over_its_own_bytes() {
        let path = temp_path("retry");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.fail_next_write(10);
        let start = Instant::now();
        // The close waits through the failure, until the next try.
        let written = ledger.close_with(start + Duration::from_secs(5), |batch| {
            batch.emit_payload("vmm", "vmm.stop", &7);
        });
        assert!(written.is_ok());
        assert!(start.elapsed() >= FLUSH_INTERVAL);
        let lines = take_lines(&path);
        assert_eq!(lines.len(), 1);
        assert_eq!(source(&lines[0]), "vmm.stop");
    }

    #[test]
    fn dropped_ledger_writes_its_records() {
        let path = temp_path("dropped");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.captured(&[block()]);
        drop(ledger);
        assert_eq!(take_lines(&path).len(), 1);
    }

    #[test]
    fn closed_ledger_has_written_its_records() {
        let path = temp_path("close");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.captured(&[block()]);
        assert!(ledger
            .close(Instant::now() + Duration::from_secs(5))
            .is_ok());
        assert_eq!(take_lines(&path).len(), 1);
    }

    #[test]
    fn close_of_a_closed_ledger_waits_for_the_closing_batch() {
        let path = temp_path("closing");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.set_paused(true);
        let deadline = Instant::now() + Duration::from_secs(5);
        let close = || {
            ledger.close_with(deadline, |batch| {
                batch.emit_payload("vmm", "vmm.stop", &7);
            })
        };
        std::thread::scope(|scope| {
            let first = scope.spawn(close);
            ledger.wait_until_closed();
            let second = scope.spawn(close);
            std::thread::sleep(Duration::from_millis(20));
            assert!(!second.is_finished());
            ledger.set_paused(false);
            assert!(first.join().unwrap().is_ok());
            let refused = second.join().unwrap().unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::Other);
        });
        assert_eq!(take_lines(&path).len(), 1);
    }

    #[test]
    fn full_buffer_drops_captured_records_only() {
        let path = temp_path("full");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.set_paused(true);
        let events: Vec<_> = (0..1000).map(|_| block()).collect();
        for _ in 0..1000 {
            ledger.captured(&events);
            if ledger.dropped() > 0 {
                break;
            }
        }
        let dropped = ledger.dropped();
        assert!(dropped > 0);
        let written = ledger.close_with(Instant::now(), |batch| {
            batch.emit_payload("vmm", "vmm.stop", &7);
        });
        assert_eq!(written.unwrap_err().kind(), io::ErrorKind::TimedOut);

        ledger.set_paused(false);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !std::fs::read_to_string(&path).unwrap().contains("vmm.stop")
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        let lines = take_lines(&path);
        assert_eq!(source(lines.last().unwrap()), "vmm.stop");
        let marker: serde_json::Value = serde_json::from_str(&lines[lines.len() - 2]).unwrap();
        assert_eq!(marker["source"], "vmm.dropped");
        assert_eq!(marker["payload"]["records"], dropped);
    }

    #[test]
    fn run_of_drops_is_counted_before_the_next_record() {
        let path = temp_path("marked");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.set_paused(true);
        let events: Vec<_> = (0..1000).map(|_| block()).collect();
        for _ in 0..1000 {
            ledger.captured(&events);
            if ledger.dropped() > 0 {
                break;
            }
        }
        let dropped = ledger.dropped();
        assert!(dropped > 0);
        ledger.set_paused(false);
        // An empty batch waits for the buffered records, so the next one fits.
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(ledger.batch_until(deadline, |_| {}).is_ok());
        ledger.captured(&[block()]);
        assert!(ledger.close(deadline).is_ok());

        let lines = take_lines(&path);
        let sources: Vec<_> = lines.iter().map(|line| source(line)).collect();
        assert_eq!(sources.iter().filter(|s| *s == "vmm.dropped").count(), 1);
        assert_eq!(sources[sources.len() - 2..], ["vmm.dropped", "block"]);
        let marker: serde_json::Value = serde_json::from_str(&lines[lines.len() - 2]).unwrap();
        assert_eq!(marker["provenance"], "vmm");
        assert_eq!(marker["payload"]["records"], dropped);
    }

    // The writer has 4 MiB in a write. A plugin's record does not end the
    // overflow, even once the drops have stopped. A `block` record that fits
    // right after a drop, as one does once the write returns, does not end it
    // either. The time of the last drop is set rather than waited for, so the
    // test does not depend on how fast it runs.
    #[test]
    fn overflow_ends_once_drops_stop() {
        let ledger = Ledger::new(None, "vm1").unwrap();
        let mut state = State {
            pending: MAX_BUFFERED_BYTES,
            ..State::default()
        };
        let mut captured = Batch::new(true);
        captured.captured(&block());
        let mut plugin = Batch::new(true);
        plugin.emit_payload("rich", "plugin", &7);
        let report = |state: &mut State, batch, droppable| {
            let (_, report) = ledger.add(state, batch, droppable);
            (report.started, report.ended)
        };
        let set_last_drop = |state: &mut State, at: Instant| {
            state.overflow.as_mut().unwrap().last_drop = at;
        };

        assert_eq!(report(&mut state, &captured, true), (true, 0));
        set_last_drop(&mut state, Instant::now() - OVERFLOW_QUIET_INTERVAL);
        assert_eq!(report(&mut state, &plugin, false), (false, 0));
        state.pending = 0;
        set_last_drop(&mut state, Instant::now() + Duration::from_secs(60));
        assert_eq!(report(&mut state, &captured, true), (false, 0));
        state.pending = MAX_BUFFERED_BYTES;
        assert_eq!(report(&mut state, &captured, true), (false, 0));
        state.pending = 0;
        set_last_drop(&mut state, Instant::now() - OVERFLOW_QUIET_INTERVAL);
        assert_eq!(report(&mut state, &captured, true), (false, 2));
        assert_eq!(state.dropped, 2);
    }

    #[test]
    fn close_ends_the_overflow() {
        let ledger = Ledger::new(None, "vm1").unwrap();
        let mut state = State {
            pending: MAX_BUFFERED_BYTES,
            ..State::default()
        };
        let mut captured = Batch::new(true);
        captured.captured(&block());
        ledger.add(&mut state, &captured, true);
        let report = state.close();
        assert_eq!((report.started, report.ended), (false, 1));
        assert!(state.overflow.is_none());
    }

    #[test]
    fn closed_ledger_takes_no_record() {
        let path = temp_path("closed");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let close = || {
            ledger.close_with(deadline, |batch| {
                batch.emit_payload("vmm", "vmm.stop", &7);
            })
        };
        assert!(close().is_ok());
        assert_eq!(close().unwrap_err().kind(), io::ErrorKind::Other);
        let refused = ledger.emit_payload("rich", "plugin", &7).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::Other);
        assert_eq!(
            ledger.batch(|_| {}).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        ledger.captured(&[block()]);
        assert!(ledger
            .shared
            .as_ref()
            .unwrap()
            .state
            .lock()
            .unwrap()
            .lines
            .is_empty());
        assert_eq!(take_lines(&path).len(), 1);
    }

    #[test]
    fn empty_batch_waits_for_the_records_before_it() {
        let path = temp_path("empty");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.captured(&[block()]);
        let written = ledger.batch_until(Instant::now() + Duration::from_secs(5), |_| {});
        assert!(written.is_ok());
        assert_eq!(take_lines(&path).len(), 1);
    }

    // The writer has written every line and gathers for longer than the batch
    // waits. The batch adds no line, so the gather ends only because the batch
    // wakes the writer, which then reports the batch written.
    #[test]
    fn empty_batch_returns_while_the_writer_gathers() {
        let path = temp_path("empty-gather");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.set_gather_interval(Duration::from_secs(30));
        ledger.captured(&[block()]);
        ledger.wait_until_gathering();
        let written = ledger.batch_until(Instant::now() + Duration::from_secs(5), |_| {});
        assert!(written.is_ok(), "{written:?}");
        assert_eq!(take_lines(&path).len(), 1);
    }

    #[test]
    fn unserializable_payload_adds_none_of_its_batch() {
        let path = temp_path("unserializable");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        // serde_json refuses a map keyed by a tuple.
        let tuple_keys = std::collections::HashMap::from([((1u32, 2u32), 3u32)]);
        let refused = ledger
            .batch_until(Instant::now() + Duration::from_secs(5), |batch| {
                batch.emit_payload("rich", "plugin", &7);
                batch.emit_payload("rich", "plugin", &tuple_keys);
            })
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        drop(ledger);
        assert!(take_lines(&path).is_empty());
    }

    #[test]
    fn batch_does_not_wait_while_the_writes_fail() {
        let path = temp_path("failing");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.set_fail_writes(true);
        let first = ledger.batch(|batch| batch.emit_payload("rich", "plugin", &7));
        assert_eq!(first.unwrap_err().kind(), io::ErrorKind::TimedOut);
        ledger.wait_until_failing();
        // A wait for the writer would last the whole deadline.
        let start = Instant::now();
        let second = ledger
            .batch_until(start + Duration::from_secs(30), |batch| {
                batch.emit_payload("rich", "plugin", &7);
            })
            .unwrap_err();
        assert_eq!(second.kind(), io::ErrorKind::TimedOut);
        assert!(second.to_string().contains("writes fail"), "{second}");
        assert!(start.elapsed() < Duration::from_secs(10));
        ledger.set_fail_writes(false);
        assert!(ledger
            .close(Instant::now() + Duration::from_secs(5))
            .is_ok());
        assert_eq!(take_lines(&path).len(), 2);
    }

    // The batch waits before the first write fails, so only the failure can end
    // its wait before the deadline.
    #[test]
    fn waiting_batch_stops_once_the_writes_fail() {
        let path = temp_path("starts-failing");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.set_paused(true);
        ledger.set_fail_writes(true);
        ledger.captured(&[block()]);
        ledger.wait_until_writing();
        let start = Instant::now();
        let refused = std::thread::scope(|scope| {
            scope.spawn(|| {
                ledger.wait_until_urgent();
                ledger.set_paused(false);
            });
            ledger.batch_until(start + Duration::from_secs(30), |batch| {
                batch.emit_payload("rich", "plugin", &7);
            })
        })
        .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::TimedOut);
        assert!(refused.to_string().contains("writes fail"), "{refused}");
        assert!(start.elapsed() < Duration::from_secs(10));
        ledger.set_fail_writes(false);
        assert!(ledger
            .close(Instant::now() + Duration::from_secs(5))
            .is_ok());
        assert_eq!(take_lines(&path).len(), 2);
    }

    #[test]
    fn closed_ledger_gives_up_on_writes_that_keep_failing() {
        let path = temp_path("give-up");
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger.set_fail_writes(true);
        ledger.captured(&[block()]);
        // The close waits past the give-up and returns its error.
        let start = Instant::now();
        let refused = ledger
            .close_with(start + Duration::from_secs(30), |_| {})
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::Other, "{refused}");
        assert!(start.elapsed() < Duration::from_secs(10));
        // The writer releases the file's lock once it has given up.
        let deadline = Instant::now() + 3 * STOP_TIMEOUT;
        loop {
            match Ledger::new(path.to_str(), "vm1") {
                Ok(reopened) => {
                    drop(reopened);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
        let _ = std::fs::remove_file(&path);
    }

    // A boot that fails before it adds a record drops a ledger with nothing
    // pending, and the next boot opens the same path at once.
    #[test]
    fn dropped_ledger_has_released_its_file() {
        let path = temp_path("reopen");
        for _ in 0..50 {
            drop(Ledger::new(path.to_str(), "vm1").unwrap());
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn second_ledger_at_a_path_is_refused_until_the_first_is_closed() {
        let path = temp_path("locked");
        let first = Ledger::new(path.to_str(), "vm1").unwrap();
        let refused = Ledger::new(path.to_str(), "vm1").err().unwrap();
        assert_eq!(refused.kind(), io::ErrorKind::WouldBlock);
        assert!(first.close(Instant::now() + Duration::from_secs(5)).is_ok());
        let second = Ledger::new(path.to_str(), "vm1");
        assert!(second.is_ok());
        drop(second);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ledger_empties_an_existing_file() {
        let path = temp_path("existing");
        std::fs::write(&path, "a line from an earlier run\n").unwrap();
        let ledger = Ledger::new(path.to_str(), "vm1").unwrap();
        ledger
            .close(Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert!(take_lines(&path).is_empty());
    }

    #[test]
    fn ledger_refuses_a_symbolic_link() {
        let target = temp_path("link-target");
        let link = temp_path("link");
        std::fs::write(&target, "keep\n").unwrap();
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let refused = Ledger::new(link.to_str(), "vm1").err().unwrap();
        assert!(
            refused.to_string().ends_with("a symbolic link"),
            "{refused}"
        );
        let _ = std::fs::remove_file(&link);
        assert_eq!(take_lines(&target), ["keep"]);
    }

    #[test]
    fn loop_of_links_above_the_ledger_keeps_its_own_error() {
        let first = temp_path("loop-a");
        let second = temp_path("loop-b");
        let _ = std::fs::remove_file(&first);
        let _ = std::fs::remove_file(&second);
        std::os::unix::fs::symlink(&second, &first).unwrap();
        std::os::unix::fs::symlink(&first, &second).unwrap();
        let path = first.join("ledger.ndjson");
        let refused = Ledger::new(path.to_str(), "vm1").err().unwrap();
        // Each libc words the message of `ELOOP` its own way.
        let code = format!("(os error {})", libc::ELOOP);
        assert!(refused.to_string().ends_with(&code), "{refused}");
        let _ = std::fs::remove_file(&first);
        let _ = std::fs::remove_file(&second);
    }

    #[test]
    fn ledger_refuses_a_fifo() {
        let path = temp_path("fifo");
        let _ = std::fs::remove_file(&path);
        let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: `c_path` is a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        // The open of a FIFO with no reader fails before the file type is
        // checked, so a reader comes first.
        let _reader = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        let refused = Ledger::new(path.to_str(), "vm1").err().unwrap();
        assert!(
            refused.to_string().ends_with("not a regular file"),
            "{refused}"
        );
        let _ = std::fs::remove_file(&path);
    }

    // The seam a plugin uses: a payload this crate has never heard of goes
    // into the ledger under the caller's own `source`, in the same envelope.
    #[test]
    fn foreign_payload_shares_the_envelope() {
        #[derive(Serialize)]
        struct Foreign {
            whatever: u32,
        }
        let s = line("rich", "something-else", Foreign { whatever: 7 });
        assert_eq!(
            s,
            r#"{"sandbox_id":"vm1","ts":1,"provenance":"rich","source":"something-else","payload":{"whatever":7}}"#
        );
    }
}

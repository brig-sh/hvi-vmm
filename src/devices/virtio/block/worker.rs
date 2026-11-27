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

//! A disk's worker thread, and the state it shares with the device.

use std::fs::File;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use vm_memory::VolatileSlice;

use super::device::{VirtioBlk, SERIAL_LEN};
use super::request::{
    other, Request, Work, VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_FLUSH,
    VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
};
use super::store::{BackingStore, TransferError};
use crate::devices::virtio::mmio::Interrupt;
use crate::devices::virtio::wake::WorkerWake;
use crate::devices::virtio::Queue;
use crate::events::{CapturedEvent, Ledger};
use crate::io_threads::HostWork;
use crate::memory::GuestRam;
use crate::plugin::IoSink;
use crate::sandbox::Thread;
use crate::teardown::StopToken;

/// The longest a disk's worker polls an empty ring before it sleeps, unless the
/// disk sets another.
pub const DEFAULT_POLL_MAX: Duration = Duration::from_micros(32);
/// The longest poll a disk can set.
pub const POLL_MAX_LIMIT: Duration = Duration::from_millis(1);
/// The poll a worker's window grows from.
const POLL_START: Duration = Duration::from_micros(4);

/// The state a disk's device and its worker share.
///
/// The state's lock is never held across a call to the backing file or to a
/// plugin's sink. It is taken before the lock of the device's [`Interrupt`],
/// never after it, and after the lock that orders the records, never before
/// it.
pub(super) struct Shared {
    /// The queue, the sink's slot and the requests in flight.
    state: Mutex<State>,
    /// The condition notified when a request leaves flight and when the vCPUs
    /// stop.
    idle: Condvar,
    /// What wakes the worker.
    pub(super) wake: WorkerWake,
    /// The lock a thread holds while it moves the pending records to the
    /// ledger, so the worker and the vCPUs' stop add them in the order the
    /// requests completed.
    recording: Mutex<()>,
}

/// The state behind the lock of [`Shared`].
pub(super) struct State {
    /// The queue and the interrupt, from activation until a reset or the vCPUs'
    /// stop.
    active: Option<Active>,
    /// The sink each request also feeds, when a plugin installed one.
    pub(super) sink: Option<Arc<dyn IoSink>>,
    /// The number of requests taken off the ring that the worker has not
    /// completed: their call to the backing file or to the sink has not
    /// returned.
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
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self {
            state: Mutex::new(State {
                active: None,
                sink: None,
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
    /// A worker that panics under the lock poisons it, and the vCPUs' stop
    /// still has to free a vCPU waiting in a reset.
    pub(super) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts serving `queue`, which raises `interrupt`, unless the vCPUs have
    /// stopped.
    pub(super) fn activate(&self, queue: Option<Queue>, interrupt: Arc<Interrupt>) {
        let mut state = self.lock();
        if !state.stopping {
            state.active = queue.map(|queue| Active { queue, interrupt });
        }
    }

    /// Stops serving the queue.
    ///
    /// It returns once no request is in flight or the vCPUs have stopped. The
    /// worker completes a request in flight only while the queue is served, so
    /// once no request is in flight, no request of the reset device reaches
    /// guest RAM or the used ring. When the vCPUs' stop ends the wait instead,
    /// [`stop`](Self::stop) says what still reaches guest RAM.
    pub(super) fn reset(&self) {
        let mut state = self.lock();
        state.active = None;
        while state.in_flight > 0 && !state.stopping {
            state = self
                .idle
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Stops serving the queue for good.
    ///
    /// It also frees a vCPU that waits in [`reset`](Self::reset). The vCPUs'
    /// stop calls it, since a vCPU waiting for a slow backing file would
    /// otherwise hold up the stop. A read in flight still writes its buffers in
    /// guest RAM after the reset returns, while the VM is ending.
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

/// The thread that serves one disk's requests from its backing store.
///
/// It never takes the transport's device lock. It ends the sink's batch and
/// writes what it captured to the ledger itself, after each pass. The vCPUs'
/// stop writes the records still pending then.
pub(crate) struct Worker<F = File> {
    /// The backing store.
    file: F,
    /// The disk's size in 512-byte sectors.
    pub(super) capacity_sectors: u64,
    /// Whether every write is refused.
    pub(super) read_only: bool,
    /// What `GET_ID` returns, zero-padded.
    serial: [u8; SERIAL_LEN],
    /// The serial as given, for the ledger.
    serial_text: Arc<str>,
    /// The disk's id, for the sink.
    disk_id: u64,
    /// Whether each request writes a `[virtio-blk]` console line.
    trace: bool,
    /// The guest RAM the queue and the buffers are in.
    pub(super) ram: Arc<GuestRam>,
    /// The ledger the requests are recorded in.
    ledger: Arc<Ledger>,
    /// The state the worker shares with the device.
    shared: Arc<Shared>,
    /// The poll window the worker starts with.
    poll: PollWindow,
}

/// What one pass of the worker captured, and whether the ring has more.
struct Pass {
    /// The console lines of the requests, when tracing is on.
    trace_lines: Vec<String>,
    /// The sink the pass fed, or `None` when it fed none.
    fed: Option<Arc<dyn IoSink>>,
    /// Whether the pass took a chain off the ring.
    served: bool,
    /// Whether the ring had a chain left when the pass ended.
    more: bool,
}

/// How long a disk's worker polls an empty ring before it sleeps, which follows
/// how soon the driver's next chain tends to come.
///
/// The worker measures each gap from the ring going empty to the next chain. A
/// gap within the window keeps it. A gap longer than the cap sets it to zero,
/// since a poll that long would not have been worth its CPU time. Any other gap
/// doubles it, from [`POLL_START`] up to the cap. A disk that sits idle
/// therefore polls for no time, and one that takes a request right after the
/// last polls just long enough to catch it.
#[derive(Clone, Copy, Debug)]
struct PollWindow {
    /// The longest the window gets.
    cap: Duration,
    /// The window.
    len: Duration,
    /// When the ring went empty, until the next chain is found.
    empty_since: Option<Instant>,
}

impl PollWindow {
    /// Returns a window of zero that grows up to `cap`.
    fn new(cap: Duration) -> Self {
        Self {
            cap,
            len: Duration::ZERO,
            empty_since: None,
        }
    }

    /// Returns the window, after noting that the ring went empty at `now`.
    fn begin(&mut self, now: Instant) -> Duration {
        self.empty_since = Some(now);
        self.len
    }

    /// Notes that a chain was found at `at`.
    ///
    /// It adapts the window to the gap since the ring went empty.
    fn chain_found(&mut self, at: Instant) {
        if let Some(since) = self.empty_since.take() {
            self.adapt(at.saturating_duration_since(since));
        }
    }

    /// Adapts the window to a `gap` between the ring going empty and the next
    /// chain.
    fn adapt(&mut self, gap: Duration) {
        if gap <= self.len {
            return;
        }
        self.len = if gap > self.cap {
            Duration::ZERO
        } else {
            (self.len * 2).max(POLL_START).min(self.cap)
        };
    }
}

impl VirtioBlk {
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
            poll: PollWindow::new(self.poll_max),
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
        let mut window = self.poll;
        while self.shared.wake.wait(stop) {
            self.serve(&mut window);
        }
    }

    /// Serves the requests on the ring a pass at a time, until a poll ends with
    /// no chain or the queue is no longer served.
    ///
    /// It polls the ring each time a pass leaves it empty. After each pass it
    /// ends the sink's batch and then writes the pending records to the ledger,
    /// so a reader that waits on the sink does not also wait for the ledger.
    /// Both come before the poll, so the poll holds no record back. The pass's
    /// console lines come last, with no lock held, so a console nobody reads
    /// holds up neither the records nor a reset or the vCPUs' stop.
    ///
    /// It serves nothing once the ledger is closed, which a failed run does
    /// with the worker still running, so no request starts that the ledger
    /// would hold no record of.
    fn serve(&self, window: &mut PollWindow) {
        // When the chain the next pass serves became known: at this wake, and
        // after it at the end of each poll.
        let mut found = Some(Instant::now());
        loop {
            if self.ledger.is_closed() {
                break;
            }
            let pass = self.pass();
            if pass.served {
                if let Some(at) = found.take() {
                    window.chain_found(at);
                }
            }
            if let Some(sink) = pass.fed {
                sink.on_batch_end();
            }
            self.shared.record_pending(&self.ledger);
            for line in &pass.trace_lines {
                stderr!("{line}");
            }
            if pass.more {
                continue;
            }
            // A pass that served nothing, after a wake with no chain behind it,
            // is no sign that the next chain is near, so the ring is looked at
            // once and the window is left as it was.
            found = if pass.served {
                self.poll(window)
            } else {
                self.poll_for(Instant::now(), Duration::ZERO)
            };
            if found.is_none() {
                break;
            }
        }
    }

    /// Serves up to a queue's worth of requests with the driver's notifications
    /// off.
    ///
    /// It returns what it captured. Each request is parsed under the lock and
    /// counted in flight, its call to the backing store and the sink's
    /// `on_block` run with no lock held, and it completes under the lock. A
    /// sink that blocks then holds up its request, and a reset that waits for
    /// that request, but not the vCPUs' stop. A pass ends early when a reset
    /// takes the queue. Notifications stay off when the pass ends, and
    /// [`poll`](Self::poll) turns them on.
    fn pass(&self) -> Pass {
        let mut trace_lines = Vec::new();
        let mut served = false;
        let mut fed: Option<Arc<dyn IoSink>> = None;
        let mut state = self.shared.lock();
        let Some(active) = state.active.as_mut() else {
            return Pass {
                trace_lines,
                fed: None,
                served,
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
            served = true;
            let request = self.parse(chain);
            let sink = state.sink.clone();
            state.in_flight += 1;
            drop(state);
            let done = self.run_request(&request.work);
            // Only a read or write is I/O on the disk, since a flush carries no
            // data range. One that failed part way changed the disk or guest
            // RAM up to where it stopped, so its record carries the bytes it
            // moved. One that failed before its first byte moved nothing and
            // has no record.
            let record_len = match (&request.work, &done) {
                (Work::Read { .. } | Work::Write { .. }, Ok(_)) => Some(request.data_len()),
                (Work::Read { .. } | Work::Write { .. }, Err(error)) if error.moved > 0 => {
                    Some(error.moved)
                }
                _ => None,
            };
            let done = done.map_err(|error| error.source);
            if let (Some(len), Some(sink)) = (record_len, sink) {
                // The sink gets the request before the driver can see it
                // complete, so its record precedes what the guest does with the
                // data. A sink that cannot keep up accounts for that itself: a
                // lost record must not fail the guest's I/O.
                sink.on_block(
                    request.sector,
                    len,
                    self.disk_id,
                    request.kind == VIRTIO_BLK_T_OUT,
                );
                fed.get_or_insert(sink);
            }
            state = self.shared.lock();
            self.complete(&mut state, &request, done, record_len, &mut trace_lines);
            state.in_flight -= 1;
            self.shared.idle.notify_all();
        }
        let more = state
            .active
            .as_ref()
            .is_some_and(|active| !active.queue.is_empty(&self.ram));
        Pass {
            trace_lines,
            fed,
            served,
            more,
        }
    }

    /// Polls the empty ring for the length of `window`.
    ///
    /// It returns what [`poll_for`](Self::poll_for) returns. A chain the driver
    /// makes available during the poll needs no notification and no wake of the
    /// worker.
    fn poll(&self, window: &mut PollWindow) -> Option<Instant> {
        let start = Instant::now();
        let len = window.begin(start);
        self.poll_for(start, len)
    }

    /// Returns when a chain became available, or `None` when the ring is still
    /// empty.
    ///
    /// It looks at the ring until `len` after `start` with the driver's
    /// notifications still off, and then turns them on. The ring is read once
    /// more after the notifications are on, so a chain made available just
    /// before is found too. The lock is taken for each look and released
    /// between two, so a reset or the vCPUs' stop ends the wait at the next
    /// look.
    fn poll_for(&self, start: Instant, len: Duration) -> Option<Instant> {
        loop {
            let mut state = self.shared.lock();
            if state.stopping {
                return None;
            }
            let active = state.active.as_mut()?;
            if !active.queue.is_empty(&self.ram) {
                return Some(Instant::now());
            }
            if start.elapsed() >= len {
                return active
                    .queue
                    .enable_notification(&self.ram)
                    .then(Instant::now);
            }
            drop(state);
            std::hint::spin_loop();
        }
    }

    /// Runs `work` against the backing store.
    ///
    /// It returns the number of bytes it wrote to guest RAM. It runs with no
    /// lock held. A read writes the request's buffers in guest RAM during the
    /// call.
    ///
    /// # Errors
    ///
    /// Errors when the call failed or the request was refused. The error of a
    /// read or write carries the number of bytes moved before it.
    fn run_request(&self, work: &Work<'_>) -> Result<u32, TransferError> {
        match work {
            Work::Read { offset, buffers } => {
                self.file
                    .read_exact_vectored_at_volatile(buffers, *offset)?;
                let total: usize = buffers.iter().map(VolatileSlice::len).sum();
                // The buffers may overlap, so their total can pass what the
                // used length holds.
                Ok(u32::try_from(total).unwrap_or(u32::MAX))
            }
            Work::Write { offset, buffers } => self
                .file
                .write_all_vectored_at_volatile(buffers, *offset)
                .map(|()| 0),
            // Honor the guest's cache flush (durability for fsync).
            Work::Flush => {
                self.file.sync_data()?;
                Ok(0)
            }
            Work::GetId { .. } | Work::Answer(_) => Ok(0),
            Work::Refused(reason) => Err(io::Error::other(reason.clone()).into()),
        }
    }

    /// Completes `request`, whose call to the backing store returned `done`.
    ///
    /// While the queue is served, the status byte and a `GET_ID` serial reach
    /// guest RAM, the chain goes on the used ring and the interrupt is raised,
    /// once per request, so a slow request does not hold back the ones before
    /// it. After a reset none of that happens. A request with a `record_len`, a
    /// read or write that went through or failed part way, is recorded in the
    /// state with that length either way, since it reached the backing store.
    /// With tracing on, its console line goes in `trace_lines`.
    fn complete(
        &self,
        state: &mut State,
        request: &Request<'_>,
        done: io::Result<u32>,
        record_len: Option<u64>,
        trace_lines: &mut Vec<String>,
    ) {
        let State { active, events, .. } = state;
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
        if let Some(active) = active {
            // A failure writes the status byte too. An untouched byte reads
            // back as whatever the driver put there, so a refused or failed
            // request could look like a success with stale data in the buffer.
            let _ = self.ram.write_u8(status_at, status);
            if active
                .queue
                .add_used(&self.ram, request.head, written.saturating_add(1))
            {
                active.interrupt.signal_used_buffer();
            }
        }
        // Boundary capture: the guest's disk I/O, observed at the device. The
        // console line is opt-in (HVI_BLK_TRACE), because a synchronous stderr
        // write per request would dominate the cost under a high-IOPS workload.
        // A request that failed part way has a line as well, with the bytes it
        // moved.
        if self.trace && (!failed || record_len.is_some()) {
            let kind = match request.kind {
                VIRTIO_BLK_T_IN => "read ",
                VIRTIO_BLK_T_OUT => "write",
                VIRTIO_BLK_T_FLUSH => "flush",
                VIRTIO_BLK_T_GET_ID => "getid",
                _ => "other",
            };
            let bytes = record_len.unwrap_or(data_len);
            trace_lines.push(format!(
                "\r\n[virtio-blk] {kind} sector={} bytes={bytes} status={status}\r\n",
                request.sector
            ));
        }
        if let Some(len) = record_len {
            events.push(CapturedEvent::Block {
                disk: Arc::clone(&self.serial_text),
                lba: request.sector,
                len,
                write: request.kind == VIRTIO_BLK_T_OUT,
            });
        }
    }

    /// Returns the status of `request`, whose call to the backing store
    /// returned `done`, and the number of data bytes written to the guest.
    ///
    /// The serial reaches the guest only when `deliver` is set.
    ///
    /// # Errors
    ///
    /// Errors when the call failed, the request was refused, or the serial
    /// cannot be written to guest RAM.
    fn answer(
        &self,
        request: &Request<'_>,
        done: io::Result<u32>,
        deliver: bool,
    ) -> io::Result<(u8, u32)> {
        let written = done?;
        Ok(match &request.work {
            Work::GetId { segments } if deliver => {
                (VIRTIO_BLK_S_OK, scatter(&self.ram, segments, &self.serial)?)
            }
            Work::Answer(status) => (*status, 0),
            _ => (VIRTIO_BLK_S_OK, written),
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
            poll: self.poll,
        }
    }
}

/// Writes `src` across the guest segments `segs`, each up to its length.
///
/// It returns how many bytes were written. A source shorter than the segments
/// fills them in order and leaves the rest, which is what `GET_ID` does with a
/// serial shorter than the buffer.
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

#[cfg(test)]
mod queue_tests {
    use super::*;
    use crate::devices::virtio::mmio::testing::{self, Driver, Rings};
    use crate::devices::virtio::{
        Device as _, QUEUE_MAX_SIZE, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    };

    const BASE: u64 = 0x4000_0000;

    /// Returns a device over an empty image, so every sector is past the
    /// capacity.
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

    // The window is longer than the test allows, so the worker returns in time
    // only because it did not poll.
    #[test]
    fn wake_with_no_chain_does_not_poll_or_restart_the_gap() {
        let window = Duration::from_secs(120);
        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x4000)]));
        let worker = activated(&mem);
        let (done, waited) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut poll = PollWindow {
                cap: window,
                len: window,
                empty_since: None,
            };
            worker.serve(&mut poll);
            done.send(poll.empty_since).unwrap();
        });
        let empty_since = waited
            .recv_timeout(Duration::from_secs(30))
            .expect("the worker should not poll after a pass that served nothing");
        assert_eq!(empty_since, None, "the gap's start");
    }

    // The window is longer than the test allows the poll, so the poll returns
    // in time only because it saw the queue taken.
    #[test]
    fn poll_ends_once_the_queue_is_taken_or_the_vcpus_stop() {
        let window = Duration::from_secs(120);
        type Take = fn(&Shared);
        let takes: [(&str, Take); 2] = [
            ("a reset", Shared::reset),
            ("the vCPUs' stop", Shared::stop),
        ];
        for (what, take) in takes {
            let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x4000)]));
            let worker = activated(&mem);
            let shared = Arc::clone(&worker.shared);
            let taker = std::thread::spawn(move || take(&shared));
            let mut poll = PollWindow {
                cap: window,
                len: window,
                empty_since: None,
            };
            let started = Instant::now();
            assert!(
                worker.poll(&mut poll).is_none(),
                "{what}: a chain was found"
            );
            assert!(
                started.elapsed() < window / 2,
                "{what} did not end the poll"
            );
            taker.join().unwrap();
        }
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
        worker.serve(&mut PollWindow::new(Duration::ZERO));
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
        worker.serve(&mut PollWindow::new(Duration::ZERO));
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

        worker.serve(&mut PollWindow::new(Duration::ZERO));

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
            .close_with(Instant::now() + Duration::from_secs(5), |_| {})
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        publish_read(&mem, BASE, BASE + 0x1000, BASE + 0x6000);

        worker.serve(&mut PollWindow::new(Duration::ZERO));

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

        worker.serve(&mut PollWindow::new(Duration::ZERO));

        assert_eq!(*sink.seen.lock().unwrap(), [0]);
        assert_eq!(mem.read_u16(BASE + 0x2000 + 2).unwrap(), 1);
    }

    // The re-programmed queue sits at fresh ring pages with `avail.idx` back at
    // 0.
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
        worker.serve(&mut PollWindow::new(Duration::ZERO));
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
        worker.serve(&mut PollWindow::new(Duration::ZERO));
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
    use super::super::device::{disk_id, open_disks, store_id};
    use super::*;
    use crate::config;
    use crate::devices::virtio::mmio::testing::{self, Rings};
    use crate::devices::virtio::{
        Device as _, QUEUE_MAX_SIZE, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    };

    const BASE: u64 = 0x4000_0000;

    struct Rig {
        path: std::path::PathBuf,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    // A reader in a container reaches the device through its own node: the node
    // differs in filesystem and inode, the device number is the same.
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

    // A sector that would wrap the byte offset is refused rather than aliased
    // back into the file. An unchecked multiplication wraps silently in release
    // builds.
    #[test]
    fn sector_offset_overflow_is_refused() {
        let (r, mut disk) = rig("ovf");
        let (st, _) = disk.submit(VIRTIO_BLK_T_OUT, u64::MAX / 256, 16);
        assert_eq!(st, VIRTIO_BLK_S_IOERR);
        assert_eq!(std::fs::metadata(&r.path).unwrap().len(), 512);
    }

    // The last sector inside the capacity still works, so the bound is not off
    // by one.
    #[test]
    fn request_inside_the_capacity_still_succeeds() {
        let (_r, mut disk) = rig("ok");
        let (st, _) = disk.submit(VIRTIO_BLK_T_IN, 0, 512);
        assert_eq!(st, VIRTIO_BLK_S_OK, "sector 0 of a 1-sector disk is valid");
        let mut got = [0u8; 4];
        disk.mem.read(BASE + 0x5000, &mut got).unwrap();
        assert_eq!(&got, &[0xab; 4], "the sector reached guest memory");
    }

    // A request type the device does not implement is answered `S_UNSUPP`, not
    // `S_OK`: a driver told its discard succeeded would trust a range that
    // still holds the old data.
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

    /// Returns a 1-sector read-only disk on a `0444` image, opened with
    /// `serial`.
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
    // for writing would fail the boot.
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
        // VIRTIO_RING_F_INDIRECT_DESC is bit 28, VIRTIO_BLK_F_FLUSH bit 9,
        // VIRTIO_BLK_F_RO bit 5 and VIRTIO_BLK_F_SEG_MAX bit 2.
        assert_eq!(ro.features(), (1 << 28) | (1 << 9) | (1 << 5) | (1 << 2));

        let (_w, rw) = rig("feat");
        assert_eq!(
            rw.blk.features(),
            (1 << 28) | (1 << 9) | (1 << 2),
            "a writable disk is not ro"
        );
    }

    // The offsets are the spec's: the capacity at 0, `size_max` at 8 and
    // `seg_max` at 12. Linux reads the space four bytes at a time.
    #[test]
    fn config_space_holds_the_capacity_and_seg_max() {
        let (_r, disk) = rig("config");
        let read = |offset| {
            let mut field = [0xff; 4];
            disk.blk.read_config(offset, &mut field);
            u32::from_le_bytes(field)
        };
        assert_eq!((read(0), read(4)), (1, 0), "one sector");
        assert_eq!(read(8), 0, "no size_max");
        assert_eq!(read(12), 254, "a 256-entry queue less header and status");
        assert_eq!(read(16), 0, "nothing past seg_max");
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
        use std::os::unix::fs::PermissionsExt;

        let (r, disk) = rig("ledger");
        drop(disk);
        let path = r.path.to_str().unwrap();
        let set_mode = |mode| {
            std::fs::set_permissions(&r.path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        // An image others can read is refused by the ledger itself.
        set_mode(0o644);
        let refused = crate::events::Ledger::new(Some(path), "vm1").err().unwrap();
        assert!(refused.to_string().ends_with("move it aside"), "{refused}");
        assert_eq!(std::fs::read(&r.path).unwrap(), [0xabu8; 512]);
        // A private one is kept by the ledger, and its lock refuses the disk.
        set_mode(0o600);
        let ledger = crate::events::Ledger::new(Some(path), "vm1").unwrap();
        let err = open_disks(&[config::DiskConfig::rw(path)]).err().unwrap();
        assert!(err.ends_with("the image is open elsewhere"), "{err}");
        ledger
            .close(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(std::fs::read(&r.path).unwrap(), [0xabu8; 512]);
    }

    #[test]
    fn open_disks_gives_each_worker_its_disks_poll() {
        use std::os::unix::fs::PermissionsExt;
        let (r, blk) = ro_rig("poll", "");
        drop(blk);
        std::fs::set_permissions(&r.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut off = config::DiskConfig::ro(r.path.to_str().unwrap());
        off.serial = Some("off".into());
        off.poll_max = Some(Duration::ZERO);
        let default = config::DiskConfig::ro(r.path.to_str().unwrap());
        let disks = open_disks(&[off, default]).unwrap();

        let mem = Arc::new(GuestRam::from_ranges(&[(BASE, 0x8000)]));
        let ledger = Arc::new(Ledger::new(None, "blk-test").unwrap());
        let caps: Vec<Duration> = disks
            .iter()
            .map(|disk| {
                let worker = disk.lock().unwrap().take_worker(&mem, &ledger).unwrap();
                worker.poll.cap
            })
            .collect();
        assert_eq!(caps, [Duration::ZERO, DEFAULT_POLL_MAX]);
    }

    // One image may back two read-only disks of a guest. With a writer among
    // them the message names the other disk, where the lock alone would say
    // "elsewhere".
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
            poll_max: None,
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

    // The bound is on the bytes actually transferred, so it is exact at the end
    // of the disk in both directions.
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
    use crate::memory;
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
    /// A poll that outlasts any test, so a worker in one serves a chain only if
    /// the poll finds it.
    const FOREVER: Duration = Duration::from_secs(3600);

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
        fn read_vectored_at_volatile(
            &self,
            bufs: &[VolatileSlice<'_>],
            offset: u64,
        ) -> io::Result<usize> {
            self.hold();
            memory::read_vectored_at_volatile(&self.file, bufs, offset)
        }

        fn write_vectored_at_volatile(
            &self,
            bufs: &[VolatileSlice<'_>],
            offset: u64,
        ) -> io::Result<usize> {
            self.hold();
            memory::write_vectored_at_volatile(&self.file, bufs, offset)
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
            Self::with_poll(serial, ledger, gated, None)
        }

        /// Returns a rig as [`new`](Self::new) does, whose worker polls an
        /// empty ring for `poll` from its first pass on when `poll` is set.
        fn with_poll(
            serial: &str,
            ledger: &Arc<Ledger>,
            gated: bool,
            poll: Option<Duration>,
        ) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("hvi-blk-worker-{}-{n}.img", std::process::id()));
            let image: Vec<u8> = (0..8u8).flat_map(|sector| [sector + 1; 512]).collect();
            std::fs::write(&path, image).unwrap();
            let mut blk = VirtioBlk::open_as(path.to_str().unwrap(), false, serial).unwrap();
            let ram = Arc::new(GuestRam::from_ranges(&[(BASE, 0x10000)]));
            let mut host = HostWork::default();
            let mut worker = blk.take_worker(&ram, ledger).unwrap();
            if let Some(len) = poll {
                worker.poll = PollWindow {
                    cap: len,
                    len,
                    empty_since: None,
                };
            }
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
            // The vCPUs stop before the I/O threads do, which is what ends a
            // worker's poll.
            self.host.run_vcpu_stops();
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
    // The STATUS write returns only once the read has returned. The read writes
    // its buffer during the call, which is before the reset returns. After the
    // reset returns, nothing reaches guest RAM for the request: the buffer,
    // poisoned again, stays as it is until the worker has exited, the status
    // byte is untouched and no used entry is added.
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
        assert_eq!(rig.data(0), [2; 4], "the read wrote its buffer");
        rig.ram.write(BUFFERS + DATA, &[0xdd; 512]).unwrap();
        let ram = Arc::clone(&rig.ram);
        let trigger = Arc::clone(&rig.driver.trigger);
        drop(rig);
        let mut data = [0; 4];
        ram.read(BUFFERS + DATA, &mut data).unwrap();
        assert_eq!(data, [0xdd; 4], "the buffer is untouched after the reset");
        let mut status = [0];
        ram.read(BUFFERS + STATUS, &mut status).unwrap();
        assert_eq!(status, [0xff], "the status byte is untouched");
        assert_eq!(
            ram.read_u16(RINGS.used_ring + 2).unwrap(),
            0,
            "no used entry was added"
        );
        assert_eq!(trigger.count(), 0, "no interrupt was raised");
    }

    // A backing file that never answers would hold the vCPU in the reset
    // forever. The vCPUs' stop frees it while the read is still held. Once the
    // read returns it has written its buffer, after the reset returned, and it
    // completes nothing.
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
        assert_eq!(rig.data(0), [2; 4], "the read wrote its buffer");
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

    // The sink's panic ends the worker with the request counted in flight. The
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
        assert!(stopped.is_ok(), "the stop panicked");
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

    /// A sink one of whose calls waits until it is released.
    struct HeldSink {
        /// Whether `on_block` is the call that waits, in place of
        /// `on_batch_end`.
        at_block: bool,
        /// Whether the call has been entered.
        entered: AtomicBool,
        /// Whether the call may return.
        released: AtomicBool,
    }

    impl HeldSink {
        /// Returns a sink that waits in `on_block` when `at_block` is set, and
        /// in `on_batch_end` otherwise.
        fn new(at_block: bool) -> Self {
            Self {
                at_block,
                entered: AtomicBool::new(false),
                released: AtomicBool::new(false),
            }
        }

        /// Waits until the sink is released.
        fn hold(&self) {
            self.entered.store(true, Ordering::SeqCst);
            while !self.released.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    impl IoSink for HeldSink {
        fn on_block(&self, _sector: u64, _length: u64, _disk_id: u64, _write: bool) {
            if self.at_block {
                self.hold();
            }
        }

        fn on_net(&self, _frame: &[u8], _egress: bool) {}

        fn on_batch_end(&self) {
            if !self.at_block {
                self.hold();
            }
        }
    }

    /// Releases a [`HeldSink`] when dropped, so a test that fails still lets
    /// the worker's thread end.
    struct ReleaseGuard(Arc<HeldSink>);

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
        let sink = Arc::new(HeldSink::new(false));
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

    // The worker waits in the sink's `on_block`, which it calls with no lock
    // held. The vCPUs' stop returns while it waits, and a reset after the stop
    // returns too, with the request still in flight and off the used ring.
    #[test]
    fn vcpu_stop_returns_while_a_sink_holds_on_block() {
        let sink = Arc::new(HeldSink::new(true));
        let rig = Rig::new("disk0", &no_ledger(), false);
        rig.driver
            .device
            .lock()
            .unwrap()
            .set_io_sink(Arc::clone(&sink) as Arc<dyn IoSink>);
        rig.driver.start(&[RINGS]);
        rig.publish(0, VIRTIO_BLK_T_IN, 1);
        let _release = ReleaseGuard(Arc::clone(&sink));
        rig.kick();
        wait_until("the sink was not reached", || {
            sink.entered.load(Ordering::SeqCst)
        });
        // A watcher releases the sink if the stop or the reset waits for it, so
        // a failure ends the test.
        let (stopped, waited) = (AtomicBool::new(false), AtomicBool::new(false));
        std::thread::scope(|scope| {
            scope.spawn(|| {
                if !holds_in_time(|| stopped.load(Ordering::SeqCst)) {
                    waited.store(true, Ordering::SeqCst);
                    sink.released.store(true, Ordering::SeqCst);
                }
            });
            rig.host.run_vcpu_stops();
            rig.driver.reset();
            stopped.store(true, Ordering::SeqCst);
        });
        assert!(
            !waited.load(Ordering::SeqCst),
            "the stop or the reset waited for the sink"
        );
        assert_eq!(rig.in_flight(), 1, "the request is still in flight");
        sink.released.store(true, Ordering::SeqCst);
        wait_until("the request did not leave flight", || rig.in_flight() == 0);
        assert_eq!(
            rig.used_idx(),
            0,
            "a request of the reset device is not completed"
        );
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

    #[test]
    fn poll_window_follows_the_gap_to_the_next_chain() {
        let us = Duration::from_micros;
        let mut window = PollWindow::new(us(32));
        // Each row is a gap and the window it leaves.
        for (gap, len) in [
            (us(0), us(0)),
            (us(10), us(4)),
            (us(3), us(4)),
            (us(10), us(8)),
            (us(30), us(16)),
            (us(30), us(32)),
            (us(32), us(32)),
            (us(33), us(0)),
            (us(1), us(4)),
            (Duration::from_secs(1), us(0)),
        ] {
            window.adapt(gap);
            assert_eq!(window.len, len, "after a gap of {gap:?}");
        }

        let mut off = PollWindow::new(Duration::ZERO);
        off.adapt(us(1));
        assert_eq!(off.len, Duration::ZERO, "a cap of zero never polls");
    }

    #[test]
    fn poll_window_counts_a_gap_only_from_an_empty_ring() {
        let mut window = PollWindow::new(Duration::from_micros(32));
        let start = Instant::now();
        window.chain_found(start + Duration::from_micros(10));
        assert_eq!(window.len, Duration::ZERO, "no ring went empty");

        assert_eq!(window.begin(start), Duration::ZERO);
        window.chain_found(start + Duration::from_micros(10));
        assert_eq!(window.len, POLL_START);
        window.chain_found(start + Duration::from_micros(20));
        assert_eq!(window.len, POLL_START, "the gap was counted once");
    }

    // The worker polls for far longer than the test waits, so it serves the
    // second read only if the poll finds it: nothing notifies the queue.
    #[test]
    fn chain_made_available_during_a_poll_needs_no_notification() {
        let rig = Rig::with_poll("disk0", &no_ledger(), false, Some(FOREVER));
        rig.driver.start(&[RINGS]);
        rig.publish(0, VIRTIO_BLK_T_IN, 1);
        rig.kick();
        wait_until("the first read was not served", || rig.used_idx() == 1);
        assert_eq!(rig.used_flags(), 1, "notifications stay off during a poll");

        rig.publish(1, VIRTIO_BLK_T_IN, 2);
        wait_until("the poll did not find the second read", || {
            rig.used_idx() == 2
        });
        assert_eq!(rig.data(1), [3; 4], "sector 2 reached the guest");
    }

    // A reset while the worker polls returns, and the worker serves the queue
    // of the next activation.
    #[test]
    fn disk_serves_again_after_a_reset_during_a_poll() {
        let rig = Rig::with_poll("disk0", &no_ledger(), false, Some(FOREVER));
        rig.driver.start(&[RINGS]);
        rig.publish(0, VIRTIO_BLK_T_IN, 1);
        rig.kick();
        wait_until("the first read was not served", || rig.used_idx() == 1);

        rig.driver.reset();
        rig.ram.write_u16(RINGS.avail_ring + 2, 0).unwrap();
        rig.ram.write_u16(RINGS.used_ring + 2, 0).unwrap();
        rig.driver.start(&[RINGS]);
        rig.publish(0, VIRTIO_BLK_T_IN, 2);
        rig.kick();
        wait_until("the read after the reset was not served", || {
            rig.used_idx() == 1
        });
        assert_eq!(rig.data(0), [3; 4], "sector 2 reached the guest");
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

#[cfg(test)]
mod data_path_tests {
    use std::os::unix::fs::FileExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::devices::virtio::mmio::testing::{self, Rings};
    use crate::devices::virtio::{
        Device as _, QUEUE_MAX_SIZE, VIRTQ_DESC_F_INDIRECT, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    };
    use crate::memory;

    const BASE: u64 = 0x4000_0000;
    /// The queue of every disk, a 256-entry ring at the start of guest RAM.
    const RINGS: Rings = Rings {
        size: 256,
        desc_table: BASE,
        avail_ring: BASE + 0x1000,
        used_ring: BASE + 0x2000,
    };
    /// Where a request's indirect table is, with room for 1024 entries.
    const TABLE: u64 = BASE + 0x4000;
    /// Where a request has its header, and its status byte.
    const HEADER: u64 = BASE + 0x8000;
    const STATUS: u64 = BASE + 0x8100;
    /// Where the data buffers start, running to the end of guest RAM.
    const BUFFERS: u64 = BASE + 0x1_0000;
    /// The size of guest RAM.
    const RAM: usize = 0x10_0000;

    /// A backing file whose reads and writes each move at most `most` bytes,
    /// and which counts its calls.
    struct Short {
        /// The backing file.
        file: File,
        /// The most bytes one call moves.
        most: usize,
        /// The number of reads and writes made.
        calls: AtomicUsize,
    }

    impl Short {
        /// Returns the first `most` bytes of `bufs`, with the last buffer cut
        /// where they end.
        ///
        /// It counts a call. It panics at the hundredth call, so a loop that
        /// does not advance fails the test instead of hanging it.
        fn cut<'a>(&self, bufs: &[VolatileSlice<'a>]) -> Vec<VolatileSlice<'a>> {
            let calls = self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(calls < 100, "the store was called {calls} times");
            let mut left = self.most;
            let mut cut = Vec::new();
            for buf in bufs {
                if left == 0 {
                    break;
                }
                let len = buf.len().min(left);
                cut.push(buf.subslice(0, len).unwrap());
                left -= len;
            }
            cut
        }
    }

    impl BackingStore for Short {
        fn read_vectored_at_volatile(
            &self,
            bufs: &[VolatileSlice<'_>],
            offset: u64,
        ) -> io::Result<usize> {
            memory::read_vectored_at_volatile(&self.file, &self.cut(bufs), offset)
        }

        fn write_vectored_at_volatile(
            &self,
            bufs: &[VolatileSlice<'_>],
            offset: u64,
        ) -> io::Result<usize> {
            memory::write_vectored_at_volatile(&self.file, &self.cut(bufs), offset)
        }

        fn sync_data(&self) -> io::Result<()> {
            self.file.sync_data()
        }
    }

    /// A backing file on a host filesystem with room for `room` more bytes.
    ///
    /// A write takes what the room allows and uses it up. With none left, a
    /// write fails as one to a full filesystem does.
    struct Full {
        /// The backing file.
        file: File,
        /// The bytes the writes may still take.
        room: AtomicUsize,
    }

    impl BackingStore for Full {
        fn read_vectored_at_volatile(
            &self,
            bufs: &[VolatileSlice<'_>],
            offset: u64,
        ) -> io::Result<usize> {
            memory::read_vectored_at_volatile(&self.file, bufs, offset)
        }

        fn write_vectored_at_volatile(
            &self,
            bufs: &[VolatileSlice<'_>],
            offset: u64,
        ) -> io::Result<usize> {
            let mut left = self.room.load(Ordering::SeqCst);
            if left == 0 {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            let mut cut = Vec::new();
            for buf in bufs {
                if left == 0 {
                    break;
                }
                let len = buf.len().min(left);
                cut.push(buf.subslice(0, len).unwrap());
                left -= len;
            }
            self.room.store(left, Ordering::SeqCst);
            memory::write_vectored_at_volatile(&self.file, &cut, offset)
        }

        fn sync_data(&self) -> io::Result<()> {
            self.file.sync_data()
        }
    }

    /// A sink that keeps the length of each request it is fed.
    #[derive(Default)]
    struct Lengths(Mutex<Vec<u64>>);

    impl IoSink for Lengths {
        fn on_block(&self, _sector: u64, length: u64, _disk_id: u64, _write: bool) {
            self.0.lock().unwrap().push(length);
        }

        fn on_net(&self, _frame: &[u8], _egress: bool) {}
    }

    /// A backing file that records each buffer it is handed.
    struct Recording {
        /// The backing file.
        file: File,
        /// The host address and the length of each buffer handed so far.
        handed: Mutex<Vec<(usize, usize)>>,
    }

    impl Recording {
        /// Records `bufs`.
        fn record(&self, bufs: &[VolatileSlice<'_>]) {
            let handed = bufs
                .iter()
                .map(|buf| (buf.ptr_guard().as_ptr() as usize, buf.len()));
            self.handed.lock().unwrap().extend(handed);
        }
    }

    impl BackingStore for Recording {
        fn read_vectored_at_volatile(
            &self,
            bufs: &[VolatileSlice<'_>],
            offset: u64,
        ) -> io::Result<usize> {
            self.record(bufs);
            memory::read_vectored_at_volatile(&self.file, bufs, offset)
        }

        fn write_vectored_at_volatile(
            &self,
            bufs: &[VolatileSlice<'_>],
            offset: u64,
        ) -> io::Result<usize> {
            self.record(bufs);
            memory::write_vectored_at_volatile(&self.file, bufs, offset)
        }

        fn sync_data(&self) -> io::Result<()> {
            self.file.sync_data()
        }
    }

    /// Returns the path of a new `len`-byte image, whose byte `n` is `n % 251`,
    /// or which is sparse when `sparse` is set.
    fn image(len: usize, sparse: bool) -> std::path::PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hvi-blk-data-{}-{n}.img", std::process::id()));
        if sparse {
            File::create(&path).unwrap().set_len(len as u64).unwrap();
        } else {
            let bytes: Vec<u8> = (0..len).map(|n| (n % 251) as u8).collect();
            std::fs::write(&path, bytes).unwrap();
        }
        path
    }

    /// A disk whose worker the test runs a pass at a time, on the test's
    /// thread.
    struct Disk<F: BackingStore = File> {
        /// The device, activated with its rings where [`RINGS`] has them.
        _blk: VirtioBlk,
        /// The device's worker.
        worker: Worker<F>,
        /// The guest RAM the queue and the buffers are in.
        ram: Arc<GuestRam>,
        /// The number of entries the driver programmed into the queue.
        queue_size: u16,
    }

    impl Disk {
        /// Returns a writable disk over an image of `len` bytes made by
        /// [`image`], with its queue programmed at its largest size and
        /// activated.
        ///
        /// The image is unlinked at once, and the worker's descriptor keeps it.
        fn new(len: usize, sparse: bool) -> Self {
            Self::with_queue_size(len, sparse, QUEUE_MAX_SIZE)
        }

        /// Returns a disk as [`new`](Self::new) does, with `queue_size` entries
        /// programmed into its queue.
        fn with_queue_size(len: usize, sparse: bool, queue_size: u16) -> Self {
            let path = image(len, sparse);
            let mut blk = VirtioBlk::open(path.to_str().unwrap()).unwrap();
            std::fs::remove_file(&path).unwrap();
            let ram = Arc::new(GuestRam::from_ranges(&[(BASE, RAM)]));
            let ledger = Arc::new(Ledger::new(None, "blk-data-test").unwrap());
            let worker = blk.take_worker(&ram, &ledger).unwrap();
            let rings = Rings {
                size: u32::from(queue_size),
                ..RINGS
            };
            let queue = testing::ready_queue(QUEUE_MAX_SIZE, rings, &ram);
            let (interrupt, _) = testing::enabled_interrupt();
            blk.activate(&ram, 0, vec![Some(queue)], interrupt).unwrap();
            Self {
                _blk: blk,
                worker,
                ram,
                queue_size,
            }
        }

        /// Returns the disk with its backing file replaced by what `wrap` makes
        /// of it.
        fn with_store<G: BackingStore>(self, wrap: impl FnOnce(File) -> G) -> Disk<G> {
            Disk {
                _blk: self._blk,
                worker: self.worker.with_store(wrap),
                ram: self.ram,
                queue_size: self.queue_size,
            }
        }

        /// Returns the bytes of the image.
        fn image(&self) -> Vec<u8> {
            let file = &self.worker.file;
            let mut bytes = vec![0; file.metadata().unwrap().len() as usize];
            file.read_exact_at(&mut bytes, 0).unwrap();
            bytes
        }
    }

    impl<F: BackingStore> Disk<F> {
        /// Submits a request of type `kind` at `sector` with its data in the
        /// guest `segments`.
        ///
        /// The worker serves it, and the call returns the status byte the
        /// device wrote and what the pass captured. The chain starts at
        /// descriptor 0, and each request takes the next entry of the avail
        /// ring.
        fn submit(&self, kind: u32, sector: u64, segments: &[(u64, u32)]) -> (u8, Pass) {
            self.write_chain(RINGS.desc_table, kind, sector, segments);
            self.serve_head()
        }

        /// Submits a request as [`submit`](Self::submit) does, with its chain
        /// in an indirect table at [`TABLE`], as Linux lays a request out once
        /// `VIRTIO_RING_F_INDIRECT_DESC` is negotiated.
        ///
        /// Descriptor 0 of the queue refers to the table.
        fn submit_indirect(&self, kind: u32, sector: u64, segments: &[(u64, u32)]) -> (u8, Pass) {
            let entries = self.write_chain(TABLE, kind, sector, segments);
            let at = RINGS.desc_table;
            self.ram.write_u64(at, TABLE).unwrap();
            self.ram.write_u32(at + 8, entries * 16).unwrap();
            self.ram.write_u16(at + 12, VIRTQ_DESC_F_INDIRECT).unwrap();
            self.ram.write_u16(at + 14, 0).unwrap();
            self.serve_head()
        }

        /// Writes the chain of a request of type `kind` at `sector`, with its
        /// data in the guest `segments`, from entry 0 of the descriptor table
        /// at `table`.
        ///
        /// It returns the number of descriptors in the chain. The status byte
        /// is poisoned to `0xff`, so an untouched byte is visible.
        fn write_chain(&self, table: u64, kind: u32, sector: u64, segments: &[(u64, u32)]) -> u32 {
            let ram = &self.ram;
            ram.write_u32(HEADER, kind).unwrap();
            ram.write_u64(HEADER + 8, sector).unwrap();
            ram.write_u8(STATUS, 0xff).unwrap();
            let data = if kind == VIRTIO_BLK_T_IN {
                VIRTQ_DESC_F_WRITE
            } else {
                0
            };
            let chain: Vec<_> = std::iter::once((HEADER, 16, 0))
                .chain(segments.iter().map(|&(addr, len)| (addr, len, data)))
                .chain(std::iter::once((STATUS, 1, VIRTQ_DESC_F_WRITE)))
                .collect();
            for (index, &(addr, len, flags)) in (0u64..).zip(&chain) {
                let at = table + index * 16;
                let next = if index + 1 < chain.len() as u64 {
                    VIRTQ_DESC_F_NEXT
                } else {
                    0
                };
                ram.write_u64(at, addr).unwrap();
                ram.write_u32(at + 8, len).unwrap();
                ram.write_u16(at + 12, flags | next).unwrap();
                ram.write_u16(at + 14, (index + 1) as u16).unwrap();
            }
            chain.len() as u32
        }

        /// Serves the chain at descriptor 0, after making it available as the
        /// next entry of the avail ring.
        ///
        /// It returns the status byte the device wrote and what the pass
        /// captured.
        fn serve_head(&self) -> (u8, Pass) {
            let ram = &self.ram;
            let avail = RINGS.avail_ring;
            let idx = ram.read_u16(avail + 2).unwrap();
            ram.write_u16(avail + 4 + u64::from(idx % self.queue_size) * 2, 0)
                .unwrap();
            ram.write_u16(avail + 2, idx.wrapping_add(1)).unwrap();
            let pass = self.worker.pass();
            let mut status = [0];
            ram.read(STATUS, &mut status).unwrap();
            (status[0], pass)
        }

        /// Returns the length of the newest used entry.
        fn used_len(&self) -> u32 {
            let used = RINGS.used_ring;
            let idx = self.ram.read_u16(used + 2).unwrap();
            let entry = used + 4 + u64::from(idx.wrapping_sub(1) % self.queue_size) * 8;
            self.ram.read_u32(entry + 4).unwrap()
        }

        /// Returns the sector, the length and whether it is a write of each
        /// record that is not in the ledger yet.
        ///
        /// It takes the records, so a second call returns none of them.
        fn take_records(&self) -> Vec<(u64, u64, bool)> {
            let records = self.worker.take_pending().into_iter();
            records
                .map(|record| match record {
                    CapturedEvent::Block {
                        lba, len, write, ..
                    } => (lba, len, write),
                    _ => panic!("a disk should record only block requests"),
                })
                .collect()
        }

        /// Returns the bytes of the guest `segments`, joined.
        fn joined(&self, segments: &[(u64, u32)]) -> Vec<u8> {
            let mut joined = Vec::new();
            for &(addr, len) in segments {
                let mut bytes = vec![0; len as usize];
                self.ram.read(addr, &mut bytes).unwrap();
                joined.extend(bytes);
            }
            joined
        }

        /// Fills the guest `segments` with consecutive bytes after `first`.
        ///
        /// It returns the bytes, joined.
        fn fill(&self, segments: &[(u64, u32)], first: u8) -> Vec<u8> {
            let mut next = first;
            for &(addr, len) in segments {
                let bytes: Vec<u8> = (0..len)
                    .map(|_| {
                        next = next.wrapping_add(1);
                        next
                    })
                    .collect();
                self.ram.write(addr, &bytes).unwrap();
            }
            self.joined(segments)
        }
    }

    /// Segments of 100, 0, 300, 112 and 0 bytes, one sector in all, at
    /// addresses out of order.
    ///
    /// The zero-length ones sit between data segments and before the status
    /// byte.
    const WRITE_SEGMENTS: [(u64, u32); 5] = [
        (BUFFERS + 0x3000, 100),
        (BUFFERS + 0x100, 0),
        (BUFFERS + 0x1000, 300),
        (BUFFERS + 0x2000, 112),
        (BUFFERS + 0x5000, 0),
    ];
    /// Segments of 7, 0, 205 and 300 bytes, one sector in all.
    const READ_SEGMENTS: [(u64, u32); 4] = [
        (BUFFERS + 0x6000, 7),
        (BUFFERS + 0x6100, 0),
        (BUFFERS + 0x7000, 205),
        (BUFFERS + 0x4000, 300),
    ];

    #[test]
    fn read_and_write_round_trip_across_segments_of_different_sizes() {
        let disk = Disk::new(8 * 512, false);
        let written = disk.fill(&WRITE_SEGMENTS, 0x40);

        let (status, _) = disk.submit(VIRTIO_BLK_T_OUT, 2, &WRITE_SEGMENTS);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(disk.used_len(), 1, "a write returns only the status byte");
        let image = disk.image();
        assert_eq!(&image[1024..1536], &written[..]);
        assert_eq!(image[1023], (1023 % 251) as u8, "the sector before");
        assert_eq!(image[1536], (1536 % 251) as u8, "the sector after");
        assert_eq!(disk.worker.take_pending().len(), 1);

        let (status, _) = disk.submit(VIRTIO_BLK_T_IN, 2, &READ_SEGMENTS);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(disk.used_len(), 513, "the sector and the status byte");
        assert_eq!(disk.joined(&READ_SEGMENTS), written);
    }

    // The request carries 254 data segments, the `seg_max` of the configuration
    // space. With its header and its status byte it fills the 256-entry queue.
    #[test]
    fn request_of_seg_max_segments_round_trips() {
        const BYTES: u64 = 254 * 512;
        let disk = Disk::new(BYTES as usize, true);
        let segments: Vec<_> = (0..254).map(|n| (BUFFERS + n * 0x800, 512)).collect();
        let written = disk.fill(&segments, 3);

        let (status, _) = disk.submit(VIRTIO_BLK_T_OUT, 0, &segments);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(disk.image(), written);

        disk.fill(&segments, 0x77);
        let (status, _) = disk.submit(VIRTIO_BLK_T_IN, 0, &segments);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(disk.used_len(), BYTES as u32 + 1);
        assert_eq!(disk.joined(&segments), written);
        assert_eq!(disk.take_records(), [(0, BYTES, true), (0, BYTES, false)]);
    }

    // The table holds the header, 254 data segments and the status byte, and
    // the request takes one entry of the queue.
    #[test]
    fn request_through_an_indirect_table_round_trips() {
        const BYTES: u64 = 254 * 512;
        let disk = Disk::new(BYTES as usize, true);
        let segments: Vec<_> = (0..254).map(|n| (BUFFERS + n * 0x800, 512)).collect();
        let written = disk.fill(&segments, 5);

        let (status, _) = disk.submit_indirect(VIRTIO_BLK_T_OUT, 0, &segments);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(disk.image(), written);

        disk.fill(&segments, 0x99);
        let (status, _) = disk.submit_indirect(VIRTIO_BLK_T_IN, 0, &segments);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(disk.used_len(), BYTES as u32 + 1);
        assert_eq!(disk.joined(&segments), written);
        assert_eq!(disk.take_records(), [(0, BYTES, true), (0, BYTES, false)]);
    }

    // The driver programmed 16 of the 256 entries the queue takes, as Linux
    // programs fewer when it cannot allocate the rings. A request of `seg_max`
    // segments through a table is past the programmed size and within the
    // largest, so it is served.
    #[test]
    fn request_of_seg_max_segments_is_served_on_a_smaller_programmed_queue() {
        const BYTES: u64 = 254 * 512;
        let disk = Disk::with_queue_size(BYTES as usize, true, 16);
        let segments: Vec<_> = (0..254).map(|n| (BUFFERS + n * 0x800, 512)).collect();
        let written = disk.fill(&segments, 9);

        let (status, _) = disk.submit_indirect(VIRTIO_BLK_T_OUT, 0, &segments);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(disk.image(), written);
    }

    // One data segment more than `seg_max` makes a table of 257 descriptors,
    // past the largest size the queue takes. The walk ends before the status
    // byte, so the request moves nothing and its status byte is not written.
    #[test]
    fn request_of_more_than_seg_max_segments_is_not_served() {
        let disk = Disk::new(255 * 512, true);
        let segments: Vec<_> = (0..255).map(|n| (BUFFERS + n * 0x800, 512)).collect();
        disk.fill(&segments, 5);

        let (status, _) = disk.submit_indirect(VIRTIO_BLK_T_OUT, 0, &segments);
        assert_eq!(status, 0xff, "the status byte is untouched");
        assert_eq!(disk.used_len(), 0);
        assert_eq!(disk.image(), vec![0; 255 * 512]);
        assert!(disk.take_records().is_empty());
    }

    // A call given only empty buffers returns 0, which reads as the end of the
    // file. The request moves nothing and makes no call.
    #[test]
    fn request_with_only_empty_segments_succeeds() {
        let disk = Disk::new(8 * 512, false);
        for kind in [VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT] {
            let (status, _) = disk.submit(kind, 1, &[(BUFFERS, 0)]);
            assert_eq!(status, VIRTIO_BLK_S_OK, "type {kind}");
        }
    }

    // Each call moves at most 150 bytes, so calls end inside the 300-byte and
    // the 205-byte segments, and the next call starts there.
    #[test]
    fn short_transfers_resume_inside_a_segment() {
        let disk = Disk::new(8 * 512, false).with_store(|file| Short {
            file,
            most: 150,
            calls: AtomicUsize::new(0),
        });
        let written = disk.fill(&WRITE_SEGMENTS, 0x80);
        let calls = || disk.worker.file.calls.load(Ordering::SeqCst);

        let (status, _) = disk.submit(VIRTIO_BLK_T_OUT, 3, &WRITE_SEGMENTS);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(calls(), 4, "512 bytes take four calls of 150");
        let (status, _) = disk.submit(VIRTIO_BLK_T_IN, 3, &READ_SEGMENTS);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(calls(), 8);

        assert_eq!(disk.joined(&READ_SEGMENTS), written);
        let mut image = vec![0; 512];
        let file = &disk.worker.file.file;
        file.read_exact_at(&mut image, 1536).unwrap();
        assert_eq!(image, written);
    }

    // The host filesystem takes 612 bytes of a two-sector write and is then
    // full. The image holds those bytes, so the failed request is recorded,
    // fed to the sink and traced with their count.
    #[test]
    fn write_that_fails_part_way_is_recorded_with_the_bytes_written() {
        let sink = Arc::new(Lengths::default());
        let disk = Disk::new(8 * 512, false);
        disk._blk.set_io_sink(Arc::clone(&sink) as Arc<dyn IoSink>);
        let mut disk = disk.with_store(|file| Full {
            file,
            room: AtomicUsize::new(612),
        });
        disk.worker.trace = true;
        let segments = [(BUFFERS, 512), (BUFFERS + 0x1000, 512)];
        let written = disk.fill(&segments, 0x10);

        let (status, pass) = disk.submit(VIRTIO_BLK_T_OUT, 1, &segments);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        let mut image = vec![0; 1024];
        let file = &disk.worker.file.file;
        file.read_exact_at(&mut image, 512).unwrap();
        assert_eq!(&image[..612], &written[..612]);
        assert_eq!(image[612], ((512 + 612) % 251) as u8, "the byte after");
        assert_eq!(disk.take_records(), [(1, 612, true)]);
        assert_eq!(*sink.0.lock().unwrap(), [612]);
        let traced = pass.trace_lines.concat();
        assert!(
            traced.contains("write sector=1 bytes=612 status=1"),
            "{traced:?}"
        );
    }

    // The filesystem takes 100 bytes of a sector and is then full.
    #[test]
    fn transfer_error_gives_its_progress_and_keeps_its_cause() {
        let ram = GuestRam::from_ranges(&[(BASE, RAM)]);
        let disk = Disk::new(8 * 512, false).with_store(|file| Full {
            file,
            room: AtomicUsize::new(100),
        });
        let buffers = [ram.slice(BUFFERS, 512).unwrap()];

        let error = disk
            .worker
            .file
            .write_all_vectored_at_volatile(&buffers, 0)
            .unwrap_err();
        assert_eq!(error.moved, 100);
        assert_eq!(error.to_string(), "transfer stopped after 100 bytes");
        let cause = std::error::Error::source(&error)
            .and_then(|cause| cause.downcast_ref::<io::Error>())
            .expect("the cause should be the write's error");
        assert_eq!(cause.raw_os_error(), Some(libc::ENOSPC));
    }

    #[test]
    fn write_that_fails_before_its_first_byte_is_not_recorded() {
        let disk = Disk::new(8 * 512, false).with_store(|file| Full {
            file,
            room: AtomicUsize::new(0),
        });

        let (status, _) = disk.submit(VIRTIO_BLK_T_OUT, 1, &[(BUFFERS, 512)]);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        assert!(disk.take_records().is_empty());
    }

    // The image is cut to 700 bytes while the disk is attached, so a two-sector
    // read ends there. The guest's buffers hold those bytes, so the failed
    // request is recorded with their count.
    #[test]
    fn read_that_fails_part_way_is_recorded_with_the_bytes_read() {
        let disk = Disk::new(8 * 512, false);
        disk.worker.file.set_len(700).unwrap();
        let segments = [(BUFFERS, 512), (BUFFERS + 0x1000, 512)];
        disk.fill(&segments, 0);

        let (status, _) = disk.submit(VIRTIO_BLK_T_IN, 0, &segments);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        let image: Vec<u8> = (0..700).map(|n| (n % 251) as u8).collect();
        assert_eq!(disk.joined(&segments)[..700], image);
        assert_eq!(disk.take_records(), [(0, 700, false)]);
    }

    // The second segment starts at the end of guest RAM. The request is refused
    // before it reaches the backing file, so the first segment, which is in
    // guest RAM, is not written either.
    #[test]
    fn segment_outside_guest_ram_is_refused_and_moves_nothing() {
        let disk = Disk::new(8 * 512, false);
        let segments = [(BUFFERS, 256), (BASE + RAM as u64, 256)];
        disk.ram.write(BUFFERS, &[0xcc; 256]).unwrap();
        let before = disk.image();

        let (status, _) = disk.submit(VIRTIO_BLK_T_IN, 0, &segments);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        assert_eq!(
            disk.joined(&segments[..1]),
            [0xcc; 256],
            "guest RAM is untouched"
        );
        assert!(disk.worker.take_pending().is_empty());

        let (status, _) = disk.submit(VIRTIO_BLK_T_OUT, 0, &segments);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        assert_eq!(disk.image(), before, "the backing file is untouched");
        assert!(disk.worker.take_pending().is_empty());
    }

    // A chain holds at most a queue's worth of descriptors, fewer than IOV_MAX,
    // so this calls the store's loop with more buffers than one call takes.
    #[test]
    fn more_buffers_than_iov_max_are_moved_in_several_calls() {
        let ram = GuestRam::from_ranges(&[(BASE, RAM)]);
        let disk = Disk::new(0, true);
        let file = &disk.worker.file;
        let count = memory::IOV_MAX as u64 + 100;
        let buffers: Vec<_> = (0..count)
            .map(|n| ram.slice(BUFFERS + n * 4, 2).unwrap())
            .collect();
        let bytes: Vec<u8> = (0..count * 2).map(|n| n as u8).collect();
        for (n, pair) in (0..count).zip(bytes.chunks(2)) {
            ram.write(BUFFERS + n * 4, pair).unwrap();
        }

        file.write_all_vectored_at_volatile(&buffers, 8).unwrap();
        let mut image = vec![0; bytes.len()];
        file.read_exact_at(&mut image, 8).unwrap();
        assert_eq!(image, bytes);

        for n in 0..count {
            ram.write(BUFFERS + n * 4, &[0, 0]).unwrap();
        }
        file.read_exact_vectored_at_volatile(&buffers, 8).unwrap();
        for (n, pair) in (0..count).zip(bytes.chunks(2)) {
            let mut got = [0; 2];
            ram.read(BUFFERS + n * 4, &mut got).unwrap();
            assert_eq!(got, pair, "buffer {n}");
        }
    }

    // 128 data descriptors of 128 KiB each claim 16 MiB against a 16 MiB disk,
    // all at one guest buffer. The request is inside the disk and its segments
    // inside guest RAM, so it is served. Every buffer the store is handed lies
    // inside that guest buffer, so no host buffer holds the request's data.
    #[test]
    fn store_is_handed_only_the_requests_guest_buffers() {
        const SEGMENT: u32 = 128 << 10;
        let disk = Disk::new(16 << 20, true).with_store(|file| Recording {
            file,
            handed: Mutex::default(),
        });
        let segments = [(BUFFERS, SEGMENT); 128];
        disk.ram.write(BUFFERS, &[0x5a; SEGMENT as usize]).unwrap();
        let guest = disk.ram.slice(BUFFERS, SEGMENT as usize).unwrap();
        let start = guest.ptr_guard().as_ptr() as usize;
        let end = start + guest.len();

        for kind in [VIRTIO_BLK_T_OUT, VIRTIO_BLK_T_IN] {
            let (status, _) = disk.submit(kind, 0, &segments);
            assert_eq!(status, VIRTIO_BLK_S_OK, "type {kind}");
            let handed = std::mem::take(&mut *disk.worker.file.handed.lock().unwrap());
            assert!(!handed.is_empty(), "type {kind}: the store was not called");
            for (at, len) in handed {
                assert!(
                    start <= at && at + len <= end,
                    "type {kind}: a buffer of {len} bytes outside the guest's"
                );
            }
        }
        assert_eq!(disk.joined(&segments[..1]), [0x5a; SEGMENT as usize]);
    }
}

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

//! The RAM rounds of a live move: copy guest RAM while the guest runs, then
//! the pages it wrote meanwhile, until what is left is small enough to copy
//! with the guest paused.
//!
//! Round 0 sends every page that is not zero, with the guest running. Each
//! round after it sends the pages written during the round before, which
//! the `Tracker` reports: the guest's own writes from the hypervisor and
//! hvi's from guest RAM's [`DirtyLog`](crate::memory::DirtyLog). The rounds
//! stop when the pages written during the last one come to at most
//! `Policy::threshold`, after `Policy::max_rounds` rounds, or when a round
//! ends after `Policy::max_time` has passed since the start, whichever comes
//! first. The time is checked only as each round ends, so a round under way
//! runs to its end.
//! The caller then pauses the guest and sends the final round, the pages
//! not yet sent and those written since, with nothing running. A guest that
//! writes faster than the rounds copy never converges, and the round cap
//! bounds it: its last round is then as large as what it writes in one
//! round, and the pause lasts as long as that takes to send.
//!
//! A guest whose disk has a base image (`--disk-base-sha256`) moves its
//! disk in the same rounds: disk round `k`, the blocks it wrote since the
//! disk round before (round 0: since boot, which is every difference from
//! the base), goes before RAM round `k`, and the final disk round before
//! the final RAM round, paused. The blocks are read through the device's
//! lock one block at a time, so the guest's disk waits for one 64 KiB read
//! at most, and a block the guest writes while it is read is in the next
//! round either way.

use std::io::{self, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::checkpoint::disk::read_batch;
use crate::checkpoint::ram::PAGE_SIZE;
use crate::checkpoint::stream::{
    ChunkEncoder, DiskEncoder, PageSpace, StreamRegion, StreamWriter, CHUNK_PAGES,
    DISK_CHUNK_BLOCKS,
};
use crate::devices::virtio::block::{DirtySince, VirtioBlk, DIRTY_BLOCK_BYTES};
use crate::memory::{DirtyPages, GuestRam, GuestWriteLog};
use crate::sync::lock_or_recover;

/// When the rounds stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    /// The most rounds taken with the guest running, round 0 included.
    pub(crate) max_rounds: u32,
    /// The time after which no new round starts before the pause. A round
    /// under way when it passes runs to its end.
    pub(crate) max_time: Duration,
    /// The smallest dirty set that ends the rounds, whatever the guest's
    /// size.
    pub(crate) floor_bytes: u64,
    /// The share of present RAM, in percent, that ends the rounds when it is
    /// larger than the floor.
    pub(crate) percent: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_rounds: 5,
            max_time: Duration::from_secs(60),
            floor_bytes: 8 << 20,
            percent: 2,
        }
    }
}

impl Policy {
    /// Returns the dirty set, in bytes, at or below which the rounds stop
    /// for a guest with `present_bytes` of RAM that is not zero.
    #[must_use]
    pub(crate) fn threshold(&self, present_bytes: u64) -> u64 {
        self.floor_bytes
            .max(present_bytes.saturating_mul(self.percent) / 100)
    }
}

/// Both records of who wrote guest RAM, read as one.
pub(crate) struct Tracker<'a> {
    /// Guest RAM, whose own log records hvi's writes.
    ram: &'a GuestRam,
    /// The hypervisor's record of the guest's.
    guest: &'a dyn GuestWriteLog,
}

impl<'a> Tracker<'a> {
    /// Returns the tracker of `ram` and the guest's writes `guest` records.
    pub(crate) fn new(ram: &'a GuestRam, guest: &'a dyn GuestWriteLog) -> Self {
        Self { ram, guest }
    }

    /// Starts both records clean. A page written after this is reported by
    /// the next collect.
    ///
    /// # Errors
    ///
    /// Errors when the hypervisor refuses.
    pub(crate) fn start(&self) -> io::Result<()> {
        self.guest.start()?;
        self.ram.dirty_log().clear();
        Ok(())
    }

    /// Returns the pages written since the start or the last collect.
    ///
    /// # Errors
    ///
    /// Errors when the hypervisor refuses.
    pub(crate) fn collect(&self) -> io::Result<DirtyPages> {
        let mut set = DirtyPages::new(&self.ram.regions());
        self.guest.collect(&mut set)?;
        self.ram.dirty_log().take_into(&mut set)?;
        Ok(set)
    }

    /// Stops the guest's record and gives it its RAM back as it was.
    pub(crate) fn stop(&self) {
        self.guest.stop();
    }
}

/// What one round sent, as the reply reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RoundStats {
    /// The round, from 0.
    pub round: u32,
    /// Whether the guest was paused for it.
    pub in_pause: bool,
    /// The pages it covered: every page for round 0, the dirty set after.
    pub pages: u64,
    /// The pages it sent bytes for, the rest being zero.
    pub data_pages: u64,
    /// The bytes it put on the stream, compressed, chunk headers included.
    pub bytes: u64,
    /// How long it took to send, in milliseconds.
    pub ms: u64,
    /// Pages written per second during the round before, which this round
    /// sends; 0 for round 0.
    pub dirty_pages_per_s: u64,
}

impl RoundStats {
    /// Returns the bytes of page data the round carried before compression.
    #[must_use]
    pub fn raw_bytes(&self) -> u64 {
        self.data_pages * PAGE_SIZE
    }
}

/// What one disk round sent, as the reply reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DiskRoundStats {
    /// Its component in the stream: `disk-round-K`, or `disk-round-final`.
    pub name: String,
    /// The round as the device and `disk.json` count it, from 0.
    pub round: u32,
    /// Whether the guest was paused for it.
    pub in_pause: bool,
    /// The blocks it sent.
    pub blocks: u64,
    /// Their bytes before compression.
    pub raw_bytes: u64,
    /// The bytes it put on the stream, chunk headers included.
    pub bytes: u64,
    /// How long it took to read and send, in milliseconds.
    pub ms: u64,
    /// The disk's generation when the round was read.
    pub generation: u64,
    /// The longest the guest's disk waited for one block's read, in
    /// microseconds.
    pub max_lock_us: u64,
}

/// Sends the disk blocks `since` asks for, read from `dev`, as the next
/// disk round of `stream`, and records the round's stream digest in the
/// device, so `disk.json` lists it.
///
/// # Errors
///
/// Errors when the device refuses the read, a block cannot be read, the
/// stream fails, or `stopping` returns true.
pub(crate) fn send_disk<W: Write>(
    stream: &mut StreamWriter<W>,
    dev: &Mutex<VirtioBlk>,
    since: DirtySince,
    in_pause: bool,
    stopping: &dyn Fn() -> bool,
) -> io::Result<DiskRoundStats> {
    let started = Instant::now();
    let read = lock_or_recover(dev).read_dirty(since)?;
    let mut round = stream.disk_round(in_pause);
    let mut enc = DiskEncoder::default();
    let mut buf = Vec::with_capacity((DISK_CHUNK_BLOCKS * DIRTY_BLOCK_BYTES) as usize);
    let mut max_lock_us = 0;
    let mut chunks = 0u64;
    let mut send = |first: u64, count: u64| -> io::Result<()> {
        if chunks % 64 == 0 && stopping() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "the run is stopping",
            ));
        }
        chunks += 1;
        buf.clear();
        max_lock_us = max_lock_us.max(read_batch(dev, first, count, &mut buf)?);
        round.chunk(&mut enc, first, count, &buf)
    };
    // Runs of adjacent blocks, at most a chunk's each, taken from the
    // bitmap as it is walked: a list of every block of a large disk would
    // be large itself.
    let mut run: Option<(u64, u64)> = None;
    for block in read.dirty.iter() {
        run = match run {
            Some((first, count)) if first + count == block && count < DISK_CHUNK_BLOCKS => {
                Some((first, count + 1))
            }
            Some((first, count)) => {
                send(first, count)?;
                Some((block, 1))
            }
            None => Some((block, 1)),
        };
    }
    if let Some((first, count)) = run {
        send(first, count)?;
    }
    let (summary, sha256) = round.finish()?;
    lock_or_recover(dev).record_sent(read.round, sha256);
    Ok(DiskRoundStats {
        name: summary.name,
        round: read.round,
        in_pause,
        blocks: summary.blocks,
        raw_bytes: summary.raw_bytes,
        bytes: summary.bytes,
        ms: started.elapsed().as_millis() as u64,
        generation: read.generation,
        max_lock_us,
    })
}

/// How the rounds with the guest running ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The pages written during the last round came to at most the
    /// threshold.
    Converged,
    /// The round cap was reached.
    RoundCap,
    /// The time cap was reached.
    TimeCap,
}

/// The rounds sent with the guest running, and what the final round still
/// has to send.
pub(crate) struct Precopy {
    /// Each round sent.
    pub(crate) rounds: Vec<RoundStats>,
    /// Each disk round sent, when the disk moves by its blocks.
    pub(crate) disk_rounds: Vec<DiskRoundStats>,
    /// The pages written during the last round, not sent yet.
    pub(crate) pending: DirtyPages,
    /// When the pages in `pending` started being recorded.
    pub(crate) pending_since: Instant,
    /// Why the rounds stopped.
    pub(crate) reason: StopReason,
    /// The bytes of RAM that are not zero, from round 0.
    pub(crate) present_bytes: u64,
    /// The threshold the rounds were held to.
    pub(crate) threshold_bytes: u64,
}

/// Returns guest RAM's layout as a stream lists it.
#[must_use]
pub(crate) fn regions_of(ram: &GuestRam) -> Vec<StreamRegion> {
    ram.regions()
        .into_iter()
        .map(|r| StreamRegion {
            gpa: r.gpa,
            size: r.size,
        })
        .collect()
}

/// Sends the pages of `set` from `ram` as the next round of `stream`. With
/// `skip_empty`, a chunk of zero pages is left out, as round 0 may: fresh
/// RAM is zero on the destination.
fn send<W: Write>(
    stream: &mut StreamWriter<W>,
    ram: &GuestRam,
    space: &PageSpace,
    set: &DirtyPages,
    skip_empty: bool,
    in_pause: bool,
    stopping: &dyn Fn() -> bool,
) -> io::Result<RoundStats> {
    let started = Instant::now();
    let mut enc = ChunkEncoder::default();
    let mut buf = vec![0u8; (CHUNK_PAGES * PAGE_SIZE) as usize];
    let mut round = stream.round(in_pause);
    for (n, (region, first, count)) in set.runs(CHUNK_PAGES).into_iter().enumerate() {
        if n % 256 == 0 && stopping() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "the run is stopping",
            ));
        }
        let bytes = &mut buf[..(count * PAGE_SIZE) as usize];
        ram.read(space.gpa(region, first), bytes)?;
        round.chunk(&mut enc, space.global(region, first), bytes, skip_empty)?;
    }
    let summary = round.finish()?;
    Ok(RoundStats {
        round: summary.round,
        in_pause,
        pages: summary.pages,
        data_pages: summary.data_pages,
        bytes: summary.bytes,
        ms: started.elapsed().as_millis() as u64,
        dirty_pages_per_s: 0,
    })
}

/// Returns `pages` over `period` as pages per second.
fn per_second(pages: u64, period: Duration) -> u64 {
    let ns = period.as_nanos().max(1);
    (u128::from(pages) * 1_000_000_000 / ns) as u64
}

/// Starts `tracker` and sends the rounds taken with the guest running, by
/// `policy`, then returns what the final round still has to send. With
/// `disk`, each RAM round is preceded by the disk round of the same number.
/// The tracker is left running for the final round; on an error the caller
/// stops it.
///
/// # Errors
///
/// Errors when the tracker, the disk or the stream fails, or `stopping`
/// returns true.
pub(crate) fn precopy<W: Write>(
    stream: &mut StreamWriter<W>,
    ram: &GuestRam,
    tracker: &Tracker<'_>,
    disk: Option<&Mutex<VirtioBlk>>,
    policy: &Policy,
    stopping: &dyn Fn() -> bool,
) -> io::Result<Precopy> {
    let space = PageSpace::new(&regions_of(ram))?;
    let started = Instant::now();
    tracker.start()?;
    let mut disk_rounds = Vec::new();
    if let Some(dev) = disk {
        disk_rounds.push(send_disk(stream, dev, DirtySince::Boot, false, stopping)?);
    }
    let mut since = Instant::now();
    let all = DirtyPages::all(&ram.regions());
    let first = send(stream, ram, &space, &all, true, false, stopping)?;
    let present_bytes = first.data_pages * PAGE_SIZE;
    let threshold_bytes = policy.threshold(present_bytes);
    let mut rounds = vec![first];
    loop {
        let set = tracker.collect()?;
        let now = Instant::now();
        let rate = per_second(set.count(), now - since);
        let reason = if set.count() * PAGE_SIZE <= threshold_bytes {
            Some(StopReason::Converged)
        } else if rounds.len() as u32 >= policy.max_rounds.max(1) {
            Some(StopReason::RoundCap)
        } else if started.elapsed() >= policy.max_time {
            Some(StopReason::TimeCap)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Ok(Precopy {
                rounds,
                disk_rounds,
                pending: set,
                pending_since: since,
                reason,
                present_bytes,
                threshold_bytes,
            });
        }
        since = now;
        if let Some(dev) = disk {
            disk_rounds.push(send_disk(stream, dev, DirtySince::Round, false, stopping)?);
        }
        let mut stats = send(stream, ram, &space, &set, false, false, stopping)?;
        stats.dirty_pages_per_s = rate;
        rounds.push(stats);
    }
}

/// Sends the final round, with the guest paused: with `disk`, the final
/// disk round, the blocks written since the last one; then the pages
/// `precopy` left pending and every page written since. The disk round is
/// added to `precopy`'s.
///
/// # Errors
///
/// Errors when the tracker, the disk or the stream fails, or `stopping`
/// returns true.
pub(crate) fn final_round<W: Write>(
    stream: &mut StreamWriter<W>,
    ram: &GuestRam,
    tracker: &Tracker<'_>,
    disk: Option<&Mutex<VirtioBlk>>,
    precopy: &mut Precopy,
    stopping: &dyn Fn() -> bool,
) -> io::Result<RoundStats> {
    if let Some(dev) = disk {
        let last = send_disk(stream, dev, DirtySince::Round, true, stopping)?;
        precopy.disk_rounds.push(last);
    }
    let space = PageSpace::new(&regions_of(ram))?;
    let more = tracker.collect()?;
    let period = precopy.pending_since.elapsed();
    precopy.pending.union(&more)?;
    let mut stats = send(stream, ram, &space, &precopy.pending, false, true, stopping)?;
    stats.dirty_pages_per_s = per_second(precopy.pending.count(), period);
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::profile::HviBuild;
    use crate::checkpoint::stream::{receive, StreamReader};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    const BASE: u64 = 0x4000_0000;
    const PAGES: u64 = 2048;

    /// A hypervisor log that, at each collect, first runs the "guest": it
    /// writes `per_round` pages of RAM, starting where it stopped, and
    /// records them as the guest's own.
    struct FakeGuest {
        ram: Arc<GuestRam>,
        per_round: u64,
        next: Mutex<u64>,
        written: Mutex<Vec<u64>>,
        collects: AtomicU32,
        stopped: AtomicU32,
    }

    impl FakeGuest {
        fn new(ram: &Arc<GuestRam>, per_round: u64) -> Self {
            Self {
                ram: Arc::clone(ram),
                per_round,
                next: Mutex::new(0),
                written: Mutex::new(Vec::new()),
                collects: AtomicU32::new(0),
                stopped: AtomicU32::new(0),
            }
        }

        /// Writes the next `per_round` pages, each with the round number.
        fn run(&self) {
            let round = self.collects.load(Ordering::SeqCst) as u8 + 1;
            let mut next = self.next.lock().unwrap();
            for _ in 0..self.per_round {
                let page = *next % PAGES;
                let gpa = BASE + page * PAGE_SIZE;
                // Not through `GuestRam::write`, which would mark the host
                // log: the guest's own stores do not.
                let ptr = self.ram.host_ptr(gpa, 4096).unwrap();
                // SAFETY: host_ptr bounds-checked the page.
                unsafe { std::ptr::write_bytes(ptr, round, 4096) };
                self.written.lock().unwrap().push(page);
                *next += 1;
            }
        }
    }

    impl GuestWriteLog for FakeGuest {
        fn start(&self) -> io::Result<()> {
            Ok(())
        }
        fn collect(&self, into: &mut DirtyPages) -> io::Result<()> {
            self.run();
            self.collects.fetch_add(1, Ordering::SeqCst);
            for page in self.written.lock().unwrap().drain(..) {
                into.set_range(0, page, 1);
            }
            Ok(())
        }
        fn stop(&self) {
            self.stopped.fetch_add(1, Ordering::SeqCst);
        }
        fn granule(&self) -> u64 {
            4096
        }
    }

    fn guest() -> Arc<GuestRam> {
        Arc::new(GuestRam::from_ranges(&[(
            BASE,
            (PAGES * PAGE_SIZE) as usize,
        )]))
    }

    /// Runs a whole move of `src` with `fake` writing, and returns the
    /// rounds and the destination's RAM.
    fn migrate(
        src: &Arc<GuestRam>,
        fake: &FakeGuest,
        policy: Policy,
    ) -> (Precopy, Vec<RoundStats>, Arc<GuestRam>) {
        let mut out = Vec::new();
        let mut stream = StreamWriter::new(&mut out);
        stream.write_doc("profile.json", b"{}").unwrap();
        let tracker = Tracker::new(src, fake);
        let mut pre = precopy(&mut stream, src, &tracker, None, &policy, &|| false).unwrap();
        // The pause: the guest writes once more before it stops.
        let last = final_round(&mut stream, src, &tracker, None, &mut pre, &|| false).unwrap();
        tracker.stop();
        for name in ["cpu.json", "platform.json", "devices.json", "session.json"] {
            stream.write_doc(name, b"{}").unwrap();
        }
        stream
            .seal(
                HviBuild {
                    version: "0".into(),
                    git_sha: "t".into(),
                },
                regions_of(src),
                vec![],
                0,
            )
            .unwrap();
        let mut rounds = pre.rounds.clone();
        rounds.push(last);
        let dst = guest();
        let target = Arc::clone(&dst);
        let mut reader = StreamReader::new(io::BufReader::new(&out[..]));
        receive(
            &mut reader,
            |_| Ok((PageSpace::new(&regions_of(&target))?, target)),
            None,
        )
        .unwrap();
        (pre, rounds, dst)
    }

    fn same(a: &GuestRam, b: &GuestRam) -> bool {
        let mut x = vec![0u8; (PAGES * PAGE_SIZE) as usize];
        let mut y = x.clone();
        a.read(BASE, &mut x).unwrap();
        b.read(BASE, &mut y).unwrap();
        x == y
    }

    #[test]
    fn an_idle_guest_takes_round_0_and_the_final_round() {
        let src = guest();
        src.write(BASE + 10 * PAGE_SIZE, &[1; 4096]).unwrap();
        let fake = FakeGuest::new(&src, 0);
        let (pre, rounds, dst) = migrate(&src, &fake, Policy::default());
        assert_eq!(pre.reason, StopReason::Converged);
        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[0].data_pages, 1);
        assert_eq!(rounds[1].pages, 0);
        assert!(rounds[1].in_pause && !rounds[0].in_pause);
        assert!(same(&src, &dst));
    }

    // A guest that writes more each round than the threshold never
    // converges: the round cap ends the rounds, the final round carries what
    // it wrote last, and the destination still holds every page.
    #[test]
    fn a_busy_guest_stops_at_the_round_cap_and_still_arrives_whole() {
        let src = guest();
        // 600 pages a round, over the floor of 64 pages below.
        let fake = FakeGuest::new(&src, 600);
        let policy = Policy {
            floor_bytes: 64 * PAGE_SIZE,
            ..Policy::default()
        };
        let (pre, rounds, dst) = migrate(&src, &fake, policy);
        assert_eq!(pre.reason, StopReason::RoundCap);
        assert_eq!(rounds.len(), 6, "5 rounds running, then the final");
        for r in &rounds[1..5] {
            assert_eq!(r.pages, 600, "{r:?}");
        }
        // The final round: what was written during the fifth round and what
        // the guest wrote before it paused.
        assert_eq!(rounds[5].pages, 1200);
        assert!(same(&src, &dst), "every page written arrived");
        assert_eq!(fake.stopped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_guest_under_the_threshold_converges_after_one_round() {
        let src = guest();
        let fake = FakeGuest::new(&src, 10);
        let (pre, rounds, dst) = migrate(&src, &fake, Policy::default());
        assert_eq!(pre.reason, StopReason::Converged);
        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[1].pages, 20);
        assert!(same(&src, &dst));
    }

    #[test]
    fn the_time_cap_ends_the_rounds() {
        let src = guest();
        let fake = FakeGuest::new(&src, 600);
        let policy = Policy {
            floor_bytes: PAGE_SIZE,
            max_time: Duration::ZERO,
            ..Policy::default()
        };
        let (pre, rounds, dst) = migrate(&src, &fake, policy);
        assert_eq!(pre.reason, StopReason::TimeCap);
        assert_eq!(rounds.len(), 2);
        assert!(same(&src, &dst));
    }

    // hvi's own writes, through `GuestRam::write`, reach the rounds through
    // guest RAM's log with no hypervisor record at all.
    #[test]
    fn host_writes_between_rounds_are_sent() {
        let src = guest();
        let fake = FakeGuest::new(&src, 0);
        let mut out = Vec::new();
        let mut stream = StreamWriter::new(&mut out);
        let tracker = Tracker::new(&src, &fake);
        stream.write_doc("profile.json", b"{}").unwrap();
        let mut pre = precopy(
            &mut stream,
            &src,
            &tracker,
            None,
            &Policy::default(),
            &|| false,
        )
        .unwrap();
        src.write(BASE + 77 * PAGE_SIZE + 5, b"device").unwrap();
        let last = final_round(&mut stream, &src, &tracker, None, &mut pre, &|| false).unwrap();
        assert_eq!(last.pages, 1);
        assert_eq!(last.data_pages, 1);
    }

    #[test]
    fn a_stop_ends_a_round() {
        let src = guest();
        let fake = FakeGuest::new(&src, 0);
        let mut stream = StreamWriter::new(Vec::new());
        let tracker = Tracker::new(&src, &fake);
        let err = precopy(
            &mut stream,
            &src,
            &tracker,
            None,
            &Policy::default(),
            &|| true,
        )
        .err()
        .expect("stopped");
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn the_threshold_is_the_floor_or_the_share_whichever_is_larger() {
        let p = Policy::default();
        assert_eq!(p.threshold(0), 8 << 20);
        assert_eq!(p.threshold(100 << 20), 8 << 20);
        assert_eq!(p.threshold(1000 << 20), 20 << 20);
        assert_eq!(per_second(100, Duration::from_millis(500)), 200);
    }
}

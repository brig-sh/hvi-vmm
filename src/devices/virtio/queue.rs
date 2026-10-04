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

//! The split virtqueue the virtio devices share.
//!
//! A [`Queue`] holds what the driver programs into one queue and checks it
//! against guest RAM. It also publishes completed buffers to the used ring.

use crate::memory::GuestRam;

/// Descriptor flags.
pub(super) const VIRTQ_DESC_F_NEXT: u16 = virtio_bindings::virtio_ring::VRING_DESC_F_NEXT as u16;
pub(super) const VIRTQ_DESC_F_WRITE: u16 = virtio_bindings::virtio_ring::VRING_DESC_F_WRITE as u16;

/// Largest queue size we advertise in `QUEUE_NUM_MAX`, and so the largest a
/// driver may legally program.
pub(super) const QUEUE_NUM_MAX: u32 = 256;

/// One virtqueue's driver-programmed state.
///
/// Every field here is driver-controlled, so the fields are private and the
/// validation lives in the setters: this is the single place where a hostile
/// queue programming is rejected. In particular `num` is only ever stored if it
/// is a non-zero power of two no greater than [`QUEUE_NUM_MAX`], which is what
/// makes [`Queue::size`] a `u16` that can be used as a modulus. Storing the raw
/// `u32` and truncating at the point of use was a guest-triggerable panic
/// (`0x10000` is non-zero as a `u32` and zero as a `u16`).
#[derive(Default)]
pub(super) struct Queue {
    num: u32,
    ready: bool,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
}

impl Queue {
    /// Records the driver's queue size, ignoring anything the spec does not
    /// allow. A rejected size leaves the queue unusable rather than trusted.
    pub(crate) fn set_num(&mut self, v: u32) {
        self.num = if v != 0 && v <= QUEUE_NUM_MAX && v.is_power_of_two() {
            v
        } else {
            0
        };
        self.ready = false; // resizing invalidates the ring bounds we checked
    }

    /// The validated ring size. Zero means the driver has not programmed a
    /// usable queue, and every caller must treat it as "do nothing".
    pub(crate) fn size(&self) -> u16 {
        self.num as u16 // <= QUEUE_NUM_MAX by construction in `set_num`
    }

    /// Marks the queue ready, but only once the size is valid and all three
    /// rings fit inside guest RAM at the addresses the driver gave us.
    pub(crate) fn set_ready(&mut self, v: u32, mem: &GuestRam) {
        self.ready = v & 1 == 1 && self.rings_fit(mem);
    }

    /// True once the driver has a usable, in-bounds queue.
    pub(crate) fn is_ready(&self) -> bool {
        self.ready && self.num != 0
    }

    /// Clears the size, ready flag, ring addresses and consumed index.
    ///
    /// A driver initializing the device again programs fresh rings whose
    /// `avail.idx` starts at 0. A consumed index kept from the previous
    /// programming would make [`Queue::pending`] refuse every notify, and a
    /// ready flag kept from it would make the driver's probe refuse the queue.
    pub(crate) fn reset(&mut self) {
        *self = Queue::default();
    }

    /// Split-virtqueue ring extents: descriptor table `16*n`, avail ring
    /// `6+2*n`, used ring `6+8*n` (each includes the 2-byte event suffix).
    fn rings_fit(&self, mem: &GuestRam) -> bool {
        let n = u64::from(self.num);
        n != 0
            && mem.contains(self.desc, 16 * n)
            && mem.contains(self.avail, 6 + 2 * n)
            && mem.contains(self.used, 6 + 8 * n)
    }

    /// Address of descriptor `d`, or `None` if the driver referenced an index
    /// outside the ring it programmed.
    pub(crate) fn desc_addr(&self, d: u16) -> Option<u64> {
        (u32::from(d) < self.num).then(|| self.desc + u64::from(d) * 16)
    }

    /// Address of the avail ring's `idx`-th slot, wrapped into the ring.
    pub(crate) fn avail_slot(&self, idx: u16) -> Option<u64> {
        let n = self.size();
        (n != 0).then(|| self.avail + 4 + u64::from(idx % n) * 2)
    }

    /// How many buffers the driver has published since `last_avail`.
    ///
    /// `None` if `avail.idx` is unreadable, or if it claims more than a ring's
    /// worth -- which no conforming driver can do, and which would otherwise
    /// let a single notify drive up to 65535 descriptor-chain walks.
    pub(crate) fn pending(&self, mem: &GuestRam) -> Option<u16> {
        let idx = mem.read_u16(self.avail + 2).ok()?;
        // Acquire against the guest's `virtio_wmb()`: the driver fills the
        // avail ring slot and the descriptor table before it bumps
        // `avail.idx`, and the ring slot is an unrelated address, so without
        // this the host may read the slot before it reads the index and get
        // the previous wrap's head. Free on x86, a `dmb ishld` on arm64, and
        // only once per drain pass rather than per chain.
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        let n = idx.wrapping_sub(self.last_avail);
        (n <= self.size()).then_some(n)
    }

    pub(crate) fn last_avail(&self) -> u16 {
        self.last_avail
    }
    pub(crate) fn set_last_avail(&mut self, v: u16) {
        self.last_avail = v;
    }

    pub(crate) fn set_desc_lo(&mut self, v: u32) {
        self.desc = set_lo(self.desc, v);
        self.ready = false;
    }
    pub(crate) fn set_desc_hi(&mut self, v: u32) {
        self.desc = set_hi(self.desc, v);
        self.ready = false;
    }
    pub(crate) fn set_avail_lo(&mut self, v: u32) {
        self.avail = set_lo(self.avail, v);
        self.ready = false;
    }
    pub(crate) fn set_avail_hi(&mut self, v: u32) {
        self.avail = set_hi(self.avail, v);
        self.ready = false;
    }
    pub(crate) fn set_used_lo(&mut self, v: u32) {
        self.used = set_lo(self.used, v);
        self.ready = false;
    }
    pub(crate) fn set_used_hi(&mut self, v: u32) {
        self.used = set_hi(self.used, v);
        self.ready = false;
    }

    /// Appends a completed buffer to the used ring and advances its index.
    pub(crate) fn push_used(&self, mem: &GuestRam, head: u16, len: u32) {
        let Some(n) = Some(self.size()).filter(|&n| n != 0) else {
            return;
        };
        let Ok(used_idx) = mem.read_u16(self.used + 2) else {
            return;
        };
        let entry = self.used + 4 + u64::from(used_idx % n) * 8;
        let _ = mem.write_u32(entry, u32::from(head));
        let _ = mem.write_u32(entry + 4, len);
        // Release against the guest's `virtio_rmb()` in
        // `virtqueue_get_buf_ctx_split`. The element and `used.idx` are
        // separate addresses with no dependency between them, so on arm64
        // the guest -- running on another core the whole time a host worker
        // thread is completing requests -- may observe the bumped index
        // while the element still holds the previous wrap's contents. It
        // then takes a descriptor id it has already freed, prints
        // "id %u is not a head!", sets `vq->broken` and fails every later
        // enqueue with -EIO.
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        let _ = mem.write_u16(self.used + 2, used_idx.wrapping_add(1));
    }
}

fn set_lo(v: u64, lo: u32) -> u64 {
    (v & 0xffff_ffff_0000_0000) | u64::from(lo)
}
fn set_hi(v: u64, hi: u32) -> u64 {
    (v & 0x0000_0000_ffff_ffff) | (u64::from(hi) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x4000_0000;

    #[test]
    fn queue_rejects_zero_non_power_of_two_and_over_max() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x4000)]);
        for bad in [0, 3, 100, QUEUE_NUM_MAX + 1, 0x1_0000, u32::MAX] {
            let mut q = Queue::default();
            q.set_num(bad);
            assert_eq!(q.size(), 0, "{bad} should be refused");
            q.set_ready(1, &mem);
            assert!(!q.is_ready(), "{bad} must not become ready");
        }
        for good in [1, 2, 4, 128, QUEUE_NUM_MAX] {
            let mut q = Queue::default();
            q.set_num(good);
            assert_eq!(u32::from(q.size()), good, "{good} should be accepted");
        }
    }

    #[test]
    fn descriptor_index_outside_the_ring_is_refused() {
        let mut q = Queue::default();
        q.set_num(8);
        q.set_desc_lo(0x1000);
        assert_eq!(q.desc_addr(0), Some(0x1000));
        assert_eq!(q.desc_addr(7), Some(0x1000 + 7 * 16));
        assert_eq!(q.desc_addr(8), None, "index == size is out of the ring");
        assert_eq!(q.desc_addr(u16::MAX), None);
    }

    /// `avail.idx` claiming more than a ring's worth is a bogus ring, not
    /// 65535 chain walks.
    #[test]
    fn avail_idx_beyond_the_ring_is_refused() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x4000)]);
        let mut q = Queue::default();
        q.set_num(8);
        q.set_avail_lo((BASE + 0x1000) as u32);
        q.set_avail_hi(((BASE + 0x1000) >> 32) as u32);

        mem.write_u16(BASE + 0x1000 + 2, 8).unwrap();
        assert_eq!(q.pending(&mem), Some(8), "a full ring is fine");
        mem.write_u16(BASE + 0x1000 + 2, 9).unwrap();
        assert_eq!(q.pending(&mem), None, "one past the ring is refused");
        mem.write_u16(BASE + 0x1000 + 2, 0xffff).unwrap();
        assert_eq!(q.pending(&mem), None);
    }
}

// A litmus test for the used-ring publish in `Queue::push_used`. It models what
// `spawn_fs_worker` in the macOS backend does: a host thread that is not the
// vCPU thread appends completions to the used ring while the guest is running
// and consuming that same ring.
#[cfg(test)]
mod ordering_tests {
    use super::Queue;
    use crate::memory::GuestRam;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering as AOrd};

    const BASE: u64 = 0x4000_0000;
    const N: u32 = 256;
    const ITERS: u32 = 4_000_000;

    /// How long each arm may run for. The iteration count is the ceiling; this
    /// is what actually ends the run anywhere the two threads cannot spin
    /// freely.
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

    /// Back off while waiting on the other thread.
    ///
    /// A bare `spin_loop` assumes the other thread is running on another core
    /// right now. On a runner with fewer cores than that it is a way to hold a
    /// core doing nothing until the scheduler takes it away, which is how this
    /// test went from half a second to tens of minutes on a hosted macOS
    /// runner. Spin briefly for the common case, then yield so progress never
    /// depends on there being a spare core.
    fn wait(idle: &mut u32) {
        *idle += 1;
        if *idle < 64 {
            std::hint::spin_loop();
        } else {
            *idle = 0;
            std::thread::yield_now();
        }
    }

    /// The head descriptor id the device hands back for completion `i`. A real
    /// guest allocates heads from a free list, so the id in a given used slot
    /// differs from one wrap of the ring to the next; making it `slot` would
    /// make a stale id indistinguishable from a fresh one.
    fn expected_head(i: u32) -> u32 {
        (i % N + i / N) % N
    }

    /// The real thing. This is what the test guards: if the release in
    /// `Queue::push_used` is ever removed, this arm starts tearing on any
    /// weakly ordered host.
    fn publish_real(q: &Queue, mem: &GuestRam, _used: u64, head: u16, len: u32) {
        q.push_used(mem, head, len);
    }

    /// The publish as it was before the fence: element stores, then the index
    /// store, with nothing in between.
    ///
    /// This is the harness's positive control, and it is deliberately a local
    /// copy rather than a call into `Queue`. Pointing it at `push_used` would
    /// make it track whatever `push_used` does, so the moment the fence landed
    /// the control would stop tearing and the test would be asserting against
    /// itself.
    fn publish_unfenced(_q: &Queue, mem: &GuestRam, used: u64, head: u16, len: u32) {
        let n = N as u16;
        let Ok(used_idx) = mem.read_u16(used + 2) else {
            return;
        };
        let entry = used + 4 + u64::from(used_idx % n) * 8;
        let _ = mem.write_u32(entry, u32::from(head));
        let _ = mem.write_u32(entry + 4, len);
        let _ = mem.write_u16(used + 2, used_idx.wrapping_add(1));
    }

    /// Runs the device thread against a guest thread that consumes the used
    /// ring the way `virtqueue_get_buf_ctx_split` does: an acquire on
    /// `used.idx` (the guest's `virtio_rmb`), then a read of the element it
    /// claims to describe. Returns how many elements the guest observed stale
    /// (i.e. how many times it would have printed "is not a head!"), how many
    /// of those were a bogus descriptor id, and how many completions it got
    /// through. That last count is below `ITERS` when the time budget ended the
    /// run first.
    fn run(publish: fn(&Queue, &GuestRam, u64, u16, u32)) -> (u32, u32, u32) {
        let start = std::time::Instant::now();
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let used = BASE + 0x1000;

        let mut q = Queue::default();
        q.set_num(N);
        q.set_used_lo(used as u32);
        q.set_used_hi((used >> 32) as u32);

        // Pre-stamp every slot with a generation the guest recognises as stale.
        for s in 0..N {
            let e = used + 4 + u64::from(s) * 8;
            mem.write_u32(e, 0xdead_beef).unwrap();
            mem.write_u32(e + 4, u32::MAX).unwrap();
        }
        mem.write_u16(used + 2, 0).unwrap();

        let done = AtomicBool::new(false);
        let stale = AtomicU32::new(0);
        // A real device can never publish more than a ring's worth ahead of the
        // guest: the descriptors are not free again until the guest consumes
        // the used element. Without this the guest simply laps and every read
        // is stale for reasons that have nothing to do with ordering.
        let consumed = AtomicU32::new(0);
        let bad_head = AtomicU32::new(0);
        // used.idx as the guest sees it: an acquire load, not a plain read.
        let idx_addr = mem.host_ptr(used + 2, 2).unwrap() as usize;

        std::thread::scope(|s| {
            let start = &start;
            let q = &q;
            let mem = &mem;
            let done = &done;
            let stale = &stale;
            let consumed = &consumed;
            let bad_head = &bad_head;

            // The guest driver: poll used.idx, consume every new element.
            s.spawn(move || {
                let atomic_idx = unsafe { &*(idx_addr as *const AtomicU16) };
                let mut seen: u32 = 0;
                let mut idle = 0u32;
                loop {
                    let cur = atomic_idx.load(AOrd::Acquire);
                    // How far ahead the device claims to be, as a count rather
                    // than by chasing equality. Chasing it deadlocks: the
                    // control arm exists to make `used.idx` observable stale,
                    // so `cur` can appear *behind* `seen`, and "consume until
                    // they are equal" then walks 65535 phantom entries.
                    // `consumed` overshoots the device, its `i - consumed`
                    // underflows to a huge number, and it waits for a guest
                    // that has already run away. That is a real deadlock. It
                    // needs a torn read to trigger, so it happens only on
                    // arm64, which is where this test is meant to run.
                    let avail = cur.wrapping_sub(seen as u16);
                    // A real device is held to a ring's depth by the flow
                    // control below, so anything beyond that is a stale index
                    // rather than work. Re-read instead of chasing it.
                    if u32::from(avail) > N {
                        wait(&mut idle);
                        continue;
                    }
                    for _ in 0..avail {
                        let e = used + 4 + u64::from(seen % N) * 8;
                        let id = mem.read_u32(e).unwrap();
                        let len = mem.read_u32(e + 4).unwrap();
                        let want_id = expected_head(seen);
                        if len != seen || id != want_id {
                            stale.fetch_add(1, AOrd::Relaxed);
                        }
                        if id != want_id {
                            // The guest just read a descriptor id it was not
                            // given for this slot: BAD_RING "id %u is not a
                            // head!" and vq->broken = true.
                            bad_head.fetch_add(1, AOrd::Relaxed);
                        }
                        seen = seen.wrapping_add(1);
                        consumed.store(seen, AOrd::Release);
                    }
                    if done.load(AOrd::Acquire) && (seen as u16) == atomic_idx.load(AOrd::Acquire) {
                        break;
                    }
                    // Independent of the device's own budget. A deadlock is a
                    // state neither thread can end on its own, so each carries
                    // its own way out.
                    if start.elapsed() > BUDGET {
                        break;
                    }
                    wait(&mut idle);
                }
            });

            // The device: what the fs worker's drain does, one completion per
            // iteration, with `len` carrying the generation.
            s.spawn(move || {
                let mut idle = 0u32;
                for i in 0..ITERS {
                    // Wall clock, not just an iteration count. These two
                    // threads are tightly coupled, because the device may not
                    // run more than a ring ahead. On a small virtualized runner
                    // that costs a context switch per batch rather than a few
                    // nanoseconds. Left unbounded it turned a 0.5-second test
                    // into a CI job still going 47 minutes later. Whatever it
                    // manages in the budget is enough: the assertion is that
                    // the guarded arm never tears, and the control reports
                    // whether it tore at all.
                    if i % 4096 == 0 && start.elapsed() > BUDGET {
                        break;
                    }
                    while i.wrapping_sub(consumed.load(AOrd::Acquire)) >= N - 1 {
                        // The budget has to be inside this loop, not only at
                        // the top of the iteration: this is where the device
                        // blocks, so a check it never reaches is not a bound at
                        // all.
                        if start.elapsed() > BUDGET {
                            done.store(true, AOrd::Release);
                            return;
                        }
                        wait(&mut idle);
                    }
                    publish(q, mem, used, expected_head(i) as u16, i);
                }
                done.store(true, AOrd::Release);
            });
        });

        (
            stale.load(AOrd::Relaxed),
            bad_head.load(AOrd::Relaxed),
            consumed.load(AOrd::Relaxed),
        )
    }

    /// Not part of the default suite. Run it with:
    ///
    /// ```text
    /// cargo test --release ordering_tests -- --ignored --nocapture
    /// ```
    ///
    /// It is a stress test, and it is kept out of CI on purpose. Two reasons,
    /// both learned the hard way:
    ///
    /// It is low-signal. On an M-series Mac the unfenced control is observed
    /// torn 0 to 3 times in 4,000,000 completions, so a green run mostly means
    /// the race did not happen to land, not that the ordering is right. An
    /// earlier version of this test appeared to be far more sensitive, with
    /// hundreds of tearings per run, but that was the harness miscounting: it
    /// chased `used.idx` by equality, so one stale index sent it walking 65535
    /// phantom slots and it flagged every one.
    ///
    /// And a stress test that spins two coupled threads is a bad CI citizen.
    /// That same phantom walk deadlocked against the device's flow control and
    /// left a hosted macOS job running for 47 minutes on a step that takes 36
    /// seconds.
    ///
    /// What it is good for is what it was written for: showing the defect
    /// exists, and showing a fix removes it. Remove the `fence(Release)` from
    /// `Queue::push_used` and this fails.
    #[ignore = "timing-dependent stress test; run explicitly with --ignored"]
    #[test]
    fn push_used_is_never_observed_torn() {
        let (torn, bad, n) = run(publish_real);
        eprintln!(
            "push_used        : {torn} torn elements, {bad} bogus descriptor ids, in {n} completions"
        );
        let (ctl_torn, ctl_bad, ctl_n) = run(publish_unfenced);
        eprintln!(
            "unfenced control : {ctl_torn} torn elements, {ctl_bad} bogus descriptor ids, in {ctl_n} completions"
        );

        // The guard. A bogus id is the fatal one: the guest takes a descriptor
        // it has already freed, prints "id %u is not a head!", sets vq->broken,
        // and every later enqueue returns -EIO for the life of the guest.
        assert_eq!(
            bad, 0,
            "push_used handed the guest a descriptor id it had already freed"
        );
        assert_eq!(torn, 0, "push_used was observed torn");

        // The control says whether this host can detect the race at all. A
        // strongly ordered one (x86) will not tear even unfenced, and then the
        // assertions above have not been exercised -- say so rather than let a
        // green result imply more than it does.
        if ctl_torn == 0 {
            eprintln!(
                "note: the unfenced control did not tear on this host, so the check \
                 above did not exercise the ordering it is guarding. Run it on arm64."
            );
        }
    }
}

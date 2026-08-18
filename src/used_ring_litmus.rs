//! Litmus test for the used-ring publish in `Queue::push_used`.
//!
//! Models exactly what `spawn_fs_worker` does on `origin/main`: a host thread
//! that is not the vCPU thread appends completions to the used ring while the
//! guest is running and consuming that same ring.

use crate::guestmem::GuestRam;
use crate::virtio::Queue;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering as AOrd};

const BASE: u64 = 0x4000_0000;
const N: u32 = 256;
const ITERS: u32 = 4_000_000;

/// How long each arm may run for. The iteration count is the ceiling; this is
/// what actually ends the run anywhere the two threads cannot spin freely.
const BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

/// Back off while waiting on the other thread.
///
/// A bare `spin_loop` assumes the other thread is running on another core
/// right now. On a runner with fewer cores than that it is a way to hold a
/// core doing nothing until the scheduler takes it away, which is how this
/// test went from half a second to tens of minutes on a hosted macOS runner.
/// Spin briefly for the common case, then yield so progress never depends on
/// there being a spare core.
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
/// differs from one wrap of the ring to the next; making it `slot` would make
/// a stale id indistinguishable from a fresh one.
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

/// Runs the device thread against a guest thread that consumes the used ring
/// the way `virtqueue_get_buf_ctx_split` does -- acquire on `used.idx` (the
/// guest's `virtio_rmb`), then read the element it claims to describe.
/// Returns how many elements the guest observed stale (i.e. how many times it
/// would have printed "is not a head!"), how many of those were a bogus
/// descriptor id, and how many completions it actually got through -- which is
/// not `ITERS` when the time budget ended the run first.
fn run(publish: fn(&Queue, &GuestRam, u64, u16, u32)) -> (u32, u32, u32) {
    let start = std::time::Instant::now();
    let mut backing = vec![0u8; 0x8000];
    let host = backing.as_mut_ptr();
    let mem = GuestRam::new(host, BASE, backing.len());
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
    // guest: the descriptors are not free again until the guest consumes the
    // used element. Without this the guest simply laps and every read is
    // stale for reasons that have nothing to do with ordering.
    let consumed = AtomicU32::new(0);
    let bad_head = AtomicU32::new(0);
    // used.idx as the guest sees it: an acquire load, not a plain read.
    let idx_off = (used - BASE) as usize + 2;
    let idx_addr = host as usize + idx_off;

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
                // than by chasing equality. Chasing it deadlocks: the control
                // arm exists to make `used.idx` observable stale, so `cur` can
                // appear *behind* `seen`, and "consume until they are equal"
                // then walks 65535 phantom entries. `consumed` overshoots the
                // device, its `i - consumed` underflows to a huge number, and
                // it waits for a guest that has already run away. That is a
                // real deadlock, it needs a torn read to trigger, and it is
                // therefore arm64-only -- which is exactly where this test is
                // meant to run.
                let avail = cur.wrapping_sub(seen as u16);
                // A real device is held to a ring's depth by the flow control
                // below, so anything beyond that is a stale index rather than
                // work. Re-read instead of chasing it.
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
                // Independent of the device's own budget. Neither thread may
                // be able to end this on its own -- that is what a deadlock
                // is -- so each carries its own way out.
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
                // Wall clock, not just an iteration count. These two threads
                // are tightly coupled -- the device may not run more than a
                // ring ahead -- and on a small virtualised runner that costs a
                // context switch per batch rather than a few nanoseconds. Left
                // unbounded it turned a 0.5-second test into a CI job still
                // going 47 minutes later. Whatever it manages in the budget is
                // enough: the assertion is that the guarded arm never tears,
                // and the control reports whether it tore at all.
                if i % 4096 == 0 && start.elapsed() > BUDGET {
                    break;
                }
                while i.wrapping_sub(consumed.load(AOrd::Acquire)) >= N - 1 {
                    // The budget has to be inside this loop, not only at the
                    // top of the iteration: this is where the device blocks,
                    // so a check it never reaches is not a bound at all.
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
/// cargo test --release used_ring -- --ignored --nocapture
/// ```
///
/// It is a stress test, and it is kept out of CI on purpose. Two reasons,
/// both learned the hard way:
///
/// It is low-signal. On an M-series Mac the unfenced control is observed torn
/// 0 to 3 times in 4,000,000 completions, so a green run mostly means the race
/// did not happen to land, not that the ordering is right. An earlier version
/// of this file appeared to be far more sensitive -- hundreds of tearings per
/// run -- but that was the harness miscounting: it chased `used.idx` by
/// equality, so one stale index sent it walking 65535 phantom slots and it
/// flagged every one.
///
/// And a stress test that spins two coupled threads is a bad CI citizen. That
/// same phantom walk deadlocked against the device's flow control and left a
/// hosted macOS job running for 47 minutes on a step that takes 36 seconds.
///
/// What it is good for is what it was written for: showing the defect exists,
/// and showing a fix removes it. Remove the `fence(Release)` from
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

    // The guard. A bogus id is the fatal one: the guest takes a descriptor it
    // has already freed, prints "id %u is not a head!", sets vq->broken, and
    // every later enqueue returns -EIO for the life of the guest.
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

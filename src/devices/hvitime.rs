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

//! `hvi-time`: the clock and timer device of the portable machine profile.
//!
//! A portable guest cannot use the architected timer for time, because the
//! counter under it runs at 24 MHz on Apple silicon and at 54 MHz on a
//! Raspberry Pi 5, and a guest that moves between them would see its clock
//! jump in rate. `hvi-time` gives it a clock in nanoseconds instead, and one
//! one-shot timer per vCPU that fires at an absolute guest nanosecond. The
//! guest side is the `hvi,time-v1` driver of the portable guest kernel; see
//! `docs/portable-profile.md` for the contract.
//!
//! The device has two windows:
//!
//! - The **pvclock page**, 64 KiB of memory hvi writes and the guest maps
//!   read-only. It maps the guest's counter `cnt` (`CNTVCT_EL0`) to guest
//!   nanoseconds:
//!
//!   ```text
//!   ns = base_ns + ((cnt - base_counter) * mult) >> shift
//!   ```
//!
//!   hvi writes it at boot, at every restore and after the host sleeps,
//!   under a sequence count the guest retries on, and never otherwise. A
//!   guest reads it without an exit.
//! - The **timer blocks**, one 0x100-byte MMIO block per vCPU at `cpu * 0x100`,
//!   `cpu` being the vCPU index (`MPIDR_EL1.Aff0`):
//!
//!   | offset | register | access |
//!   | --- | --- | --- |
//!   | 0x00 | `DEADLINE_NS` | read/write: a write arms a one-shot at that guest ns, `u64::MAX` disarms |
//!   | 0x08 | `NOW_NS` | read-only: guest ns now, as hvi computes it |
//!   | 0x10 | `STATUS` | write 1 to clear: bit 0 `EXPIRED`, bit 1 `GEN_CHANGED` |
//!   | 0x18 | `CTRL` | read/write: bit 0 `ENABLE` |
//!
//!   Each register is 64 bits wide and also takes 32-bit accesses to either
//!   half. Other offsets read as zero and ignore writes. A 32-bit
//!   `DEADLINE_NS` is written low half first: the low half is held, and the
//!   timer disarmed, until the high half arrives and arms the whole value,
//!   so no half-written deadline can fire early. A high half written alone
//!   keeps the low half the deadline had.
//!
//! A vCPU's interrupt line, PPI 4 (INTID 20), is high while its timer is
//! enabled and its `STATUS` is not zero. With `ENABLE` clear an armed
//! deadline waits, and a status bit set meanwhile holds the line low until
//! the guest enables the timer again.
//!
//! One thread per VM, [`HviTime::run_timer`], sleeps until the earliest armed
//! deadline, sets `EXPIRED` and raises the line. A deadline at or before now
//! fires at once, on the vCPU that wrote it. A deadline never fires early:
//! after every wake the thread reads the counter again and goes back to sleep
//! for what is left.
//!
//! The same thread watches for a host sleep. The guest's counter does not run
//! while a Mac sleeps, so guest nanoseconds stop with it and the wall clock
//! the guest derives from the page falls behind the host's by the sleep. The
//! thread wakes at least once a second and compares a host clock that runs
//! only while the host sleeps ([`HostClock::slept_ns`]) with its value at the
//! last publish. When it grew by [`SLEEP_REPUBLISH_NS`] or more, the page is
//! published again with only its wall clock changed: the counter, the rate
//! and the base stay, so guest nanoseconds read the same on the old page and
//! the new, and the wall clock is the host's again. Every vCPU gets
//! `GEN_CHANGED`, so the guest driver sets its wall clock to the host's.
//!
//! The device knows nothing of the hypervisor. The backend supplies the
//! guest's counter ([`GuestCounter`]) and the interrupt line ([`TimerLine`]),
//! maps [`HviTime::page`] into the guest, and routes the timer window here.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::ptr::NonNull;
use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::hypervisor::vcpus::{Kick, Vcpus};
use crate::memory::SharedRam;
use crate::sync::lock_or_recover;

/// The size of the pvclock page window. The page proper is 64 bytes; the
/// window is 64 KiB so that it is a whole page on every host (the Pi runs
/// 16 KiB pages, a KVM memslot needs host-page alignment).
pub const PAGE_SIZE: u64 = 0x1_0000;
/// The size of the timer window: room for the eight vCPUs a GICv2 reaches,
/// in a 64 KiB window.
pub const TIMERS_SIZE: u64 = 0x1_0000;
/// The stride of the per-vCPU timer blocks.
pub const BLOCK_STRIDE: u64 = 0x100;
/// The PPI the timers raise: PPI 4, INTID 20.
pub const PPI: u32 = 4;
/// [`PPI`] as a GIC interrupt ID.
pub const INTID: u32 = 16 + PPI;

/// `"HVTM"`, little-endian, at offset 0 of the page.
pub const MAGIC: u32 = 0x4d54_5648;
/// The page layout this device writes.
pub const VERSION: u32 = 1;
/// The shift the page carries at every counter rate. With 24, `mult` stays
/// below 2^32 for any counter faster than [`MIN_COUNTER_HZ`].
pub const SHIFT: u32 = 24;
/// The slowest counter `hvi-time` serves, in Hz. At 3,906,250 Hz exactly,
/// `(10^9 << SHIFT) / freq` is 2^32, one more than `mult` holds.
pub const MIN_COUNTER_HZ: u32 = 3_906_251;

/// How much the host must have slept since the last publish before the
/// timer thread publishes the page again: 50 ms. The sleep clock grows only
/// while the host sleeps, so anything short of this is the error of reading
/// two clocks one after the other, and a real sleep is far longer.
pub const SLEEP_REPUBLISH_NS: u64 = 50_000_000;
/// The longest the timer thread waits without looking at the sleep clock.
const SLEEP_CHECK_EVERY: Duration = Duration::from_secs(1);

/// `DEADLINE_NS` of a disarmed timer.
pub const DISARMED: u64 = u64::MAX;
/// `STATUS.EXPIRED`: the armed deadline has passed.
pub const STATUS_EXPIRED: u64 = 1 << 0;
/// `STATUS.GEN_CHANGED`: hvi published a new page, after a restore or a
/// host sleep.
pub const STATUS_GEN_CHANGED: u64 = 1 << 1;
/// `CTRL.ENABLE`.
pub const CTRL_ENABLE: u64 = 1 << 0;

/// Page field offsets.
mod page {
    pub const MAGIC: usize = 0x00;
    pub const VERSION: usize = 0x04;
    pub const GENERATION: usize = 0x08;
    pub const COUNTER_FREQ_HZ: usize = 0x0c;
    pub const BASE_COUNTER: usize = 0x10;
    pub const BASE_NS: usize = 0x18;
    pub const MULT: usize = 0x20;
    pub const SHIFT: usize = 0x24;
    pub const WALL_NS: usize = 0x28;
    pub const DOWNTIME_TOTAL_NS: usize = 0x30;
    pub const FLAGS: usize = 0x38;
    pub const HOST_SLEEPS: usize = 0x3c;
}

/// Timer register offsets within a vCPU's block.
mod reg {
    pub const DEADLINE_NS: u64 = 0x00;
    pub const NOW_NS: u64 = 0x08;
    pub const STATUS: u64 = 0x10;
    pub const CTRL: u64 = 0x18;
    /// The end of the decoded registers.
    pub const END: u64 = 0x20;
}

/// Returns the `mult` of the page for a counter of `freq` Hz: the nearest
/// integer to `(10^9 << SHIFT) / freq`, or `None` when `freq` is 0 or so
/// slow that `mult` does not fit in 32 bits.
///
/// The guest kernel's pvclock test pins 699050667 at 24 MHz and 310689185 at
/// 54 MHz, so hvi and the guest round the same way.
#[must_use]
pub fn mult_for(freq: u32) -> Option<u32> {
    if freq == 0 {
        return None;
    }
    let freq = u128::from(freq);
    let num = 1_000_000_000u128 << SHIFT;
    u32::try_from((num + freq / 2) / freq).ok()
}

/// Returns the counter rate `freq_hz` as the page carries it, with its
/// `mult`.
///
/// # Errors
///
/// Errors when the rate is 0, does not fit the page's 32-bit field, or is
/// below [`MIN_COUNTER_HZ`]. The guest would refuse a page with rate 0
/// and never tick, and a slower counter would make `mult` overflow and
/// guest time run at the wrong rate.
pub fn counter_rate(freq_hz: u64) -> Result<(u32, u32), String> {
    let refuse = || {
        format!(
            "the host counter runs at {freq_hz} Hz (CNTFRQ_EL0), and hvi-time needs \
             {MIN_COUNTER_HZ} to {} Hz",
            u32::MAX
        )
    };
    let freq = u32::try_from(freq_hz).map_err(|_| refuse())?;
    let mult = mult_for(freq).ok_or_else(refuse)?;
    Ok((freq, mult))
}

/// `mul_u64_u32_shr`, as the guest computes it: the 96-bit product of `a`
/// and `mult`, shifted right by `shift`.
#[must_use]
pub fn mul_shr(a: u64, mult: u32, shift: u32) -> u64 {
    ((u128::from(a) * u128::from(mult)) >> shift) as u64
}

/// The guest's counter, `CNTVCT_EL0` as the guest reads it.
pub trait GuestCounter: Send + Sync {
    /// Returns the guest's counter now.
    fn now(&self) -> u64;
}

/// The vCPUs' `hvi-time` interrupt lines, as the backend wires them to the
/// guest's interrupt controller.
pub trait TimerLine: Send + Sync {
    /// Sets vCPU `cpu`'s line to `level`, and returns the vCPUs, one bit
    /// each, that must be woken to see it.
    ///
    /// The device calls it under its own lock, so two changes of one line
    /// reach the interrupt controller in the order they were made. A backend
    /// whose interrupt controller wakes the vCPUs itself returns 0.
    fn set(&self, cpu: usize, level: bool) -> u8;

    /// Wakes the vCPUs in `mask`, which an earlier [`set`](Self::set)
    /// returned. The device calls it after releasing its lock.
    fn wake(&self, mask: u8) {
        let _ = mask;
    }
}

/// The host clocks the device reads beside the guest's counter.
pub trait HostClock: Send + Sync {
    /// Returns the host's `CLOCK_REALTIME`, in nanoseconds.
    fn realtime_ns(&self) -> u64;

    /// Returns how long the host has slept, in nanoseconds, since some
    /// fixed point: a clock that runs only while the host sleeps.
    fn slept_ns(&self) -> u64;
}

/// The host's own clocks, shifted by a simulated host sleep when
/// `HVI_TIME_TEST_SLEEP` asks for one.
pub struct SystemClock {
    test: Option<TestSleep>,
}

impl SystemClock {
    /// Returns the host's clocks, shifted as `HVI_TIME_TEST_SLEEP` asks.
    #[must_use]
    pub fn from_env() -> Self {
        let test = TestSleep::from_env();
        if let Some(t) = &test {
            eprintln!(
                "{} hvi-time test sleep: the host clocks move {:.3} s ahead {:.3} s from now",
                crate::LOG_PREFIX,
                t.slept.as_secs_f64(),
                t.at.as_secs_f64()
            );
        }
        Self { test }
    }

    /// What the sleep test adds to both clocks now, in nanoseconds.
    fn shift_ns(&self) -> u64 {
        self.test.as_ref().map_or(0, TestSleep::shift_ns)
    }
}

impl HostClock for SystemClock {
    fn realtime_ns(&self) -> u64 {
        realtime_ns().saturating_add(self.shift_ns())
    }

    fn slept_ns(&self) -> u64 {
        host_slept_ns().saturating_add(self.shift_ns())
    }
}

/// A host sleep simulated in one process: `HVI_TIME_TEST_SLEEP=<at>,<secs>`.
///
/// `at` seconds after the device is made, the host's wall clock and its
/// sleep clock, as the device reads them, move `secs` seconds ahead at once.
/// To the device that is what a host sleep of `secs` with the guest's counter
/// stopped looks like: the host slept, and its wall clock is `secs` past the
/// one the guest derives from the page. The guest's REALTIME then moves
/// `secs` ahead of the real host's, which is how a test sees it re-align.
/// It cannot stop the guest's counter, which a real sleep on a Mac does.
///
/// Debugging only: it is read from the environment so that no CLI flag
/// promises it.
struct TestSleep {
    /// When the device was made.
    start: Instant,
    at: Duration,
    slept: Duration,
}

impl TestSleep {
    /// Reads `HVI_TIME_TEST_SLEEP`, or `None` when it is unset or not two
    /// numbers of seconds.
    fn from_env() -> Option<Self> {
        Self::parse(&std::env::var("HVI_TIME_TEST_SLEEP").ok()?)
    }

    fn parse(value: &str) -> Option<Self> {
        let (at, slept) = value.split_once(',')?;
        Some(Self {
            start: Instant::now(),
            at: Duration::try_from_secs_f64(at.trim().parse().ok()?).ok()?,
            slept: Duration::try_from_secs_f64(slept.trim().parse().ok()?).ok()?,
        })
    }

    fn shift_ns(&self) -> u64 {
        if self.start.elapsed() < self.at {
            0
        } else {
            u64::try_from(self.slept.as_nanos()).unwrap_or(u64::MAX)
        }
    }
}

/// Returns how long the host has slept since it booted: on macOS the
/// continuous clock, which runs in sleep, less the uptime clock, which does
/// not (`mach_continuous_time` less `mach_absolute_time`); on Linux
/// `CLOCK_BOOTTIME` less `CLOCK_MONOTONIC`. Both pairs share their rate and
/// their adjustments, so the difference moves only while the host sleeps,
/// and drifts with nothing.
///
/// The two clocks are read one after the other, so the awake clock is read
/// on both sides of the other and the read is taken again, up to three
/// times, when more than 1 ms passed in between.
fn host_slept_ns() -> u64 {
    #[cfg(target_os = "macos")]
    let (awake, continuous) = (libc::CLOCK_UPTIME_RAW, libc::CLOCK_MONOTONIC_RAW);
    #[cfg(not(target_os = "macos"))]
    let (awake, continuous) = (libc::CLOCK_MONOTONIC, libc::CLOCK_BOOTTIME);
    let mut slept = 0;
    for _ in 0..3 {
        let before = clock_ns(awake);
        let total = clock_ns(continuous);
        let after = clock_ns(awake);
        slept = total.saturating_sub(before / 2 + after / 2);
        if after.saturating_sub(before) < 1_000_000 {
            break;
        }
    }
    slept
}

/// Returns clock `id` in nanoseconds, or 0 when it cannot be read.
fn clock_ns(id: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer for the call.
    if unsafe { libc::clock_gettime(id, &mut ts) } != 0 {
        return 0;
    }
    u64::try_from(ts.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(ts.tv_nsec).unwrap_or(0))
}

/// The contents of the pvclock page.
///
/// It is also the `page` part of the canonical checkpoint state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageState {
    /// The sequence count: even when the page is stable, and 2 more at every
    /// publish.
    pub generation: u32,
    /// The rate of the counter `base_counter` counts, in Hz.
    pub counter_freq_hz: u32,
    /// The guest's counter at the boot publish or the last restore. A
    /// host-sleep publish keeps it.
    pub base_counter: u64,
    /// Guest nanoseconds at `base_counter`.
    pub base_ns: u64,
    /// Nanoseconds per counter tick, scaled by `2^shift`.
    pub mult: u32,
    /// See `mult`.
    pub shift: u32,
    /// The host's `CLOCK_REALTIME`, in nanoseconds, at guest nanosecond
    /// `base_ns`: the guest's wall clock is `wall_ns` plus the guest
    /// nanoseconds since `base_ns`.
    pub wall_ns: u64,
    /// How long the guest has been stopped across restores and host
    /// sleeps, in total.
    pub downtime_total_ns: u64,
    /// How many of the publishes so far followed a host sleep. The guest
    /// driver counts the publishes it handles, and tells the host-sleep
    /// ones from the restores by this count. A restore carries it on. A
    /// state without it reads as 0.
    #[serde(default)]
    pub host_sleeps: u32,
}

impl PageState {
    /// Returns guest nanoseconds at guest counter value `cnt`.
    #[must_use]
    pub fn guest_ns(&self, cnt: u64) -> u64 {
        self.base_ns.wrapping_add(mul_shr(
            cnt.wrapping_sub(self.base_counter),
            self.mult,
            self.shift,
        ))
    }
}

/// One vCPU's timer in the canonical checkpoint state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuTimerState {
    /// The armed deadline in guest ns, or `None` when disarmed.
    pub deadline_ns: Option<u64>,
    /// `STATUS`.
    pub status: u64,
    /// `CTRL`.
    pub ctrl: u64,
}

/// The canonical checkpoint state of `hvi-time` (`platform.json`, `timer`,
/// kind `hvi-time`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HviTimeState {
    /// The page the guest was reading.
    pub page: PageState,
    /// Guest nanoseconds at the capture.
    pub guest_ns_at_capture: u64,
    /// The guest's architected counter, `CNTVCT_EL0`, at the same moment,
    /// ticking at `page.counter_freq_hz`. A restore sets the destination's
    /// counter so that it never reads less (see
    /// [`counter_target`](Self::counter_target)).
    #[serde(default)]
    pub counter_at_capture: u64,
    /// Each vCPU's timer, in vCPU order.
    pub cpus: Vec<CpuTimerState>,
}

impl HviTimeState {
    /// Returns each vCPU's line level as the state has it: high while its
    /// timer is enabled and its `STATUS` is not 0.
    #[must_use]
    pub fn lines(&self) -> Vec<bool> {
        self.cpus
            .iter()
            .map(|c| c.ctrl & CTRL_ENABLE != 0 && c.status != 0)
            .collect()
    }

    /// Returns the value the guest's counter must start from on a host
    /// whose counter runs at `freq_hz`, so that a guest that reads the raw
    /// counter never sees it go back: `counter_at_capture` scaled from the
    /// source's rate to `freq_hz`, rounded up. On the same rate it is
    /// `counter_at_capture` itself.
    #[must_use]
    pub fn counter_target(&self, freq_hz: u64) -> u64 {
        let from = u128::from(self.page.counter_freq_hz.max(1));
        let scaled = (u128::from(self.counter_at_capture) * u128::from(freq_hz)).div_ceil(from);
        u64::try_from(scaled).unwrap_or(u64::MAX)
    }
}

/// The pvclock page: a shareable object of [`PAGE_SIZE`] bytes and hvi's
/// writable mapping of it.
///
/// The guest gets a read-only mapping of the same memory. Its fields are
/// written with atomic stores, so a guest vCPU on another host CPU reads
/// each field whole.
pub struct PvclockPage {
    /// The object, kept for the mapping's lifetime.
    ram: SharedRam,
    /// hvi's mapping of the object.
    ptr: NonNull<u8>,
}

// SAFETY: the mapping is shared memory that hvi only reaches through atomic
// accessors, and it lives as long as the value.
unsafe impl Send for PvclockPage {}
// SAFETY: as above.
unsafe impl Sync for PvclockPage {}

impl PvclockPage {
    /// Allocates the page, zeroed but for its magic and version.
    ///
    /// # Errors
    ///
    /// Errors when the object cannot be created or mapped.
    pub fn new() -> io::Result<Self> {
        let len = PAGE_SIZE as usize;
        let ram = SharedRam::new(len)?;
        // SAFETY: a fresh shared mapping of the whole object, which `ram`
        // keeps open.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                ram.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(ptr.cast::<u8>()).ok_or_else(|| io::Error::other("mmap"))?;
        let page = Self { ram, ptr };
        page.u32_at(page::MAGIC).store(MAGIC, Ordering::Relaxed);
        page.u32_at(page::VERSION).store(VERSION, Ordering::Relaxed);
        Ok(page)
    }

    /// Returns hvi's mapping of the page, [`PAGE_SIZE`] bytes, for the
    /// backend to map into the guest read-only.
    #[must_use]
    pub fn host_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Returns the backing object.
    #[must_use]
    pub fn file(&self) -> &Arc<File> {
        self.ram.file()
    }

    fn u32_at(&self, offset: usize) -> &AtomicU32 {
        debug_assert!(offset % 4 == 0 && offset + 4 <= PAGE_SIZE as usize);
        // SAFETY: an aligned offset inside the live mapping; every access to
        // the page goes through atomics.
        unsafe { AtomicU32::from_ptr(self.ptr.as_ptr().add(offset).cast()) }
    }

    fn u64_at(&self, offset: usize) -> &AtomicU64 {
        debug_assert!(offset % 8 == 0 && offset + 8 <= PAGE_SIZE as usize);
        // SAFETY: as in `u32_at`.
        unsafe { AtomicU64::from_ptr(self.ptr.as_ptr().add(offset).cast()) }
    }

    /// Writes `state` under the sequence count: the generation goes odd,
    /// then the fields, then the even `state.generation`. A guest that reads
    /// an odd generation, or a different one after the fields, reads again.
    fn publish(&self, state: &PageState) {
        let generation = self.u32_at(page::GENERATION);
        generation.store(state.generation.wrapping_sub(1) | 1, Ordering::Relaxed);
        // The odd generation is visible before any field changes.
        fence(Ordering::Release);
        self.u32_at(page::COUNTER_FREQ_HZ)
            .store(state.counter_freq_hz, Ordering::Relaxed);
        self.u64_at(page::BASE_COUNTER)
            .store(state.base_counter, Ordering::Relaxed);
        self.u64_at(page::BASE_NS)
            .store(state.base_ns, Ordering::Relaxed);
        self.u32_at(page::MULT).store(state.mult, Ordering::Relaxed);
        self.u32_at(page::SHIFT)
            .store(state.shift, Ordering::Relaxed);
        self.u64_at(page::WALL_NS)
            .store(state.wall_ns, Ordering::Relaxed);
        self.u64_at(page::DOWNTIME_TOTAL_NS)
            .store(state.downtime_total_ns, Ordering::Relaxed);
        self.u32_at(page::FLAGS).store(0, Ordering::Relaxed);
        self.u32_at(page::HOST_SLEEPS)
            .store(state.host_sleeps, Ordering::Relaxed);
        // Every field is visible before the even generation.
        fence(Ordering::Release);
        generation.store(state.generation, Ordering::Relaxed);
    }

    /// Reads the page as a guest does, retrying while it is being written.
    #[must_use]
    pub fn read(&self) -> PageState {
        loop {
            let generation = self.u32_at(page::GENERATION).load(Ordering::Acquire);
            let state = PageState {
                generation,
                counter_freq_hz: self.u32_at(page::COUNTER_FREQ_HZ).load(Ordering::Relaxed),
                base_counter: self.u64_at(page::BASE_COUNTER).load(Ordering::Relaxed),
                base_ns: self.u64_at(page::BASE_NS).load(Ordering::Relaxed),
                mult: self.u32_at(page::MULT).load(Ordering::Relaxed),
                shift: self.u32_at(page::SHIFT).load(Ordering::Relaxed),
                wall_ns: self.u64_at(page::WALL_NS).load(Ordering::Relaxed),
                downtime_total_ns: self.u64_at(page::DOWNTIME_TOTAL_NS).load(Ordering::Relaxed),
                host_sleeps: self.u32_at(page::HOST_SLEEPS).load(Ordering::Relaxed),
            };
            fence(Ordering::Acquire);
            if generation & 1 == 0
                && self.u32_at(page::GENERATION).load(Ordering::Relaxed) == generation
            {
                return state;
            }
            std::hint::spin_loop();
        }
    }

    /// Returns the magic and version words.
    #[must_use]
    pub fn ident(&self) -> (u32, u32) {
        (
            self.u32_at(page::MAGIC).load(Ordering::Relaxed),
            self.u32_at(page::VERSION).load(Ordering::Relaxed),
        )
    }
}

impl Drop for PvclockPage {
    fn drop(&mut self) {
        // SAFETY: unmapping the mapping `new` made, which nothing borrows
        // past the value.
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), PAGE_SIZE as usize) };
    }
}

/// One vCPU's timer.
#[derive(Debug, Clone, Copy)]
struct Timer {
    deadline: u64,
    status: u64,
    ctrl: u64,
    /// The level hvi last gave the line.
    line: bool,
    /// A 32-bit write to the low half of `DEADLINE_NS`, held until the
    /// high half arrives.
    low: Option<u32>,
}

impl Timer {
    const RESET: Timer = Timer {
        deadline: DISARMED,
        status: 0,
        ctrl: 0,
        line: false,
        low: None,
    };

    fn enabled(&self) -> bool {
        self.ctrl & CTRL_ENABLE != 0
    }

    /// Whether the line should be high.
    fn level(&self) -> bool {
        self.enabled() && self.status != 0
    }

    /// Whether an armed deadline waits on an enabled timer.
    fn armed(&self) -> Option<u64> {
        (self.enabled() && self.deadline != DISARMED).then_some(self.deadline)
    }
}

/// The device state behind [`HviTime`]'s lock.
struct Inner {
    /// What the page holds.
    clock: PageState,
    timers: Vec<Timer>,
    /// Set by [`HviTime::freeze`]: no deadline fires until the restore.
    frozen: bool,
    /// Set by [`HviTime::stop`]: the timer thread returns.
    stopped: bool,
    /// [`HostClock::slept_ns`] at the last publish, or when the device was
    /// made.
    slept_at_publish: u64,
}

/// The `hvi-time` device of one VM. See the module documentation.
pub struct HviTime {
    page: PvclockPage,
    counter: Box<dyn GuestCounter>,
    line: Box<dyn TimerLine>,
    host: Box<dyn HostClock>,
    /// The host counter's rate, which every publish on this host carries.
    freq: u32,
    /// [`mult_for`] of `freq`.
    mult: u32,
    /// The number of vCPUs, one timer block each.
    vcpus: usize,
    inner: Mutex<Inner>,
    /// Signals the timer thread that a deadline, the freeze or the stop
    /// changed.
    changed: Condvar,
}

impl HviTime {
    /// Returns the device for `vcpus` vCPUs on a host whose guest counter
    /// runs at `freq_hz`, with every timer disarmed and disabled.
    ///
    /// The page carries its magic and version and generation 0, which the
    /// guest driver refuses, until [`publish_boot`](Self::publish_boot).
    ///
    /// # Errors
    ///
    /// Errors when [`counter_rate`] refuses `freq_hz`, and when the page
    /// cannot be allocated.
    pub fn new(
        vcpus: usize,
        freq_hz: u64,
        counter: Box<dyn GuestCounter>,
        line: Box<dyn TimerLine>,
    ) -> io::Result<Self> {
        Self::with_host_clock(
            vcpus,
            freq_hz,
            counter,
            line,
            Box::new(SystemClock::from_env()),
        )
    }

    /// Returns the device as [`new`](Self::new) does, reading the host's
    /// wall and sleep clocks from `host`.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn with_host_clock(
        vcpus: usize,
        freq_hz: u64,
        counter: Box<dyn GuestCounter>,
        line: Box<dyn TimerLine>,
        host: Box<dyn HostClock>,
    ) -> io::Result<Self> {
        let (freq, mult) =
            counter_rate(freq_hz).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let slept_at_publish = host.slept_ns();
        Ok(Self {
            page: PvclockPage::new()?,
            counter,
            line,
            host,
            freq,
            mult,
            vcpus,
            inner: Mutex::new(Inner {
                clock: PageState {
                    generation: 0,
                    counter_freq_hz: freq,
                    base_counter: 0,
                    base_ns: 0,
                    mult,
                    shift: SHIFT,
                    wall_ns: 0,
                    downtime_total_ns: 0,
                    host_sleeps: 0,
                },
                timers: vec![Timer::RESET; vcpus],
                frozen: false,
                stopped: false,
                slept_at_publish,
            }),
            changed: Condvar::new(),
        })
    }

    /// Returns the pvclock page, for the backend to map into the guest.
    #[must_use]
    pub fn page(&self) -> &PvclockPage {
        &self.page
    }

    /// Returns the host counter rate the device publishes.
    #[must_use]
    pub fn counter_freq_hz(&self) -> u32 {
        self.freq
    }

    /// Publishes the boot page: guest nanoseconds start at 0 now. The
    /// backend calls it right before the boot vCPU's first entry.
    pub fn publish_boot(&self) {
        let mut g = lock_or_recover(&self.inner);
        g.clock = PageState {
            generation: g.clock.generation.wrapping_add(2) & !1,
            counter_freq_hz: self.freq,
            base_counter: self.counter.now(),
            base_ns: 0,
            mult: self.mult,
            shift: SHIFT,
            wall_ns: self.host.realtime_ns(),
            downtime_total_ns: 0,
            host_sleeps: 0,
        };
        self.page.publish(&g.clock);
        g.slept_at_publish = self.host.slept_ns();
    }

    /// Returns guest nanoseconds now.
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        let g = lock_or_recover(&self.inner);
        g.clock.guest_ns(self.counter.now())
    }

    /// Sets `cpu`'s line from its timer, and returns the vCPUs to wake.
    fn update_line(&self, g: &mut Inner, cpu: usize) -> u8 {
        let t = &mut g.timers[cpu];
        let level = t.level();
        if level == t.line {
            return 0;
        }
        t.line = level;
        self.line.set(cpu, level)
    }

    /// Expires `cpu`'s timer if it is armed and due at guest ns `now`, and
    /// returns the vCPUs to wake.
    fn fire_if_due(&self, g: &mut Inner, cpu: usize, now: u64) -> u8 {
        let t = &mut g.timers[cpu];
        match t.armed() {
            Some(deadline) if deadline <= now && !g.frozen => {
                t.deadline = DISARMED;
                t.status |= STATUS_EXPIRED;
                trace::fired(now - deadline);
                self.update_line(g, cpu)
            }
            _ => 0,
        }
    }

    /// Reads `width` bytes at `offset` of the timer window, as a vCPU's load.
    #[must_use]
    pub fn mmio_read(&self, offset: u64, width: u8) -> u64 {
        let Some((cpu, reg, half)) = self.decode(offset, width) else {
            return 0;
        };
        let g = lock_or_recover(&self.inner);
        let t = &g.timers[cpu];
        let value = match reg {
            reg::DEADLINE_NS => t.deadline,
            reg::NOW_NS => g.clock.guest_ns(self.counter.now()),
            reg::STATUS => t.status,
            _ => t.ctrl,
        };
        match half {
            None => value,
            Some(shift) => (value >> shift) & 0xffff_ffff,
        }
    }

    /// Writes `value`, `width` bytes, at `offset` of the timer window, as a
    /// vCPU's store.
    pub fn mmio_write(&self, offset: u64, width: u8, value: u64) {
        let Some((cpu, reg, half)) = self.decode(offset, width) else {
            return;
        };
        // The bits of the register this access covers, and the value moved
        // into place.
        let (mask, bits) = match half {
            None => (u64::MAX, value),
            Some(shift) => (0xffff_ffff << shift, (value & 0xffff_ffff) << shift),
        };
        let mut g = lock_or_recover(&self.inner);
        let mut wake = 0;
        match reg {
            reg::DEADLINE_NS => {
                let t = &mut g.timers[cpu];
                match half {
                    // The low half alone: merged into the armed deadline
                    // it could make one in the past, so it waits for the
                    // high half, and the old deadline is off meanwhile.
                    Some(0) => {
                        t.low = Some(value as u32);
                        t.deadline = DISARMED;
                    }
                    // The high half: arms the whole value. Without a held
                    // low half it keeps the deadline's; after a capture
                    // that fell between the halves that is the disarmed
                    // value's, so the deadline is late, never early.
                    Some(_) => {
                        let low = t.low.take().unwrap_or(t.deadline as u32);
                        t.deadline = bits | u64::from(low);
                    }
                    None => {
                        t.low = None;
                        t.deadline = value;
                    }
                }
                // A deadline already due fires here, on the writer; a later
                // one is the timer thread's.
                let now = g.clock.guest_ns(self.counter.now());
                wake |= self.fire_if_due(&mut g, cpu, now);
                self.changed.notify_all();
            }
            reg::STATUS => {
                g.timers[cpu].status &= !bits;
                wake |= self.update_line(&mut g, cpu);
            }
            reg::CTRL => {
                let t = &mut g.timers[cpu];
                t.ctrl = ((t.ctrl & !mask) | bits) & CTRL_ENABLE;
                let now = g.clock.guest_ns(self.counter.now());
                wake |= self.fire_if_due(&mut g, cpu, now);
                wake |= self.update_line(&mut g, cpu);
                self.changed.notify_all();
            }
            // NOW_NS is read-only.
            _ => {}
        }
        drop(g);
        if wake != 0 {
            self.line.wake(wake);
        }
    }

    /// Splits a timer-window access into the vCPU, the register and, for a
    /// 32-bit access, the shift of the half it covers. `None` for an access
    /// that reads as zero and ignores writes.
    fn decode(&self, offset: u64, width: u8) -> Option<(usize, u64, Option<u32>)> {
        let cpu = usize::try_from(offset / BLOCK_STRIDE).ok()?;
        let within = offset % BLOCK_STRIDE;
        if cpu >= self.vcpus() || within >= reg::END {
            return None;
        }
        match width {
            8 if within % 8 == 0 => Some((cpu, within, None)),
            4 if within % 4 == 0 => Some((cpu, within & !7, Some(((within & 4) * 8) as u32))),
            _ => None,
        }
    }

    /// Returns the number of vCPUs.
    #[must_use]
    pub fn vcpus(&self) -> usize {
        self.vcpus
    }

    /// Runs the device's timer until [`stop`](Self::stop): sleeps until the
    /// earliest armed deadline, then expires every timer that is due.
    ///
    /// The backend runs it on a thread of its own, with whatever scheduling
    /// that thread needs to wake on time (see [`spawn_timer`]). The sleep is
    /// a condition-variable wait, so an earlier deadline armed meanwhile
    /// ends it.
    pub fn run_timer(&self) {
        let trace_every = trace::interval();
        let mut next_report = trace_every.map(|every| Instant::now() + every);
        let mut g = lock_or_recover(&self.inner);
        loop {
            if g.stopped {
                return;
            }
            if let Some(woke) = self.republish_if_host_slept(&mut g) {
                drop(g);
                woke.log();
                if woke.wake != 0 {
                    self.line.wake(woke.wake);
                }
                g = lock_or_recover(&self.inner);
                continue;
            }
            let now = g.clock.guest_ns(self.counter.now());
            let mut wake = 0;
            let mut earliest: Option<u64> = None;
            for cpu in 0..g.timers.len() {
                wake |= self.fire_if_due(&mut g, cpu, now);
                if let Some(deadline) = g.timers[cpu].armed() {
                    earliest = Some(earliest.map_or(deadline, |e| e.min(deadline)));
                }
            }
            if wake != 0 {
                drop(g);
                self.line.wake(wake);
                g = lock_or_recover(&self.inner);
                continue;
            }
            if let (Some(at), Some(every)) = (next_report, trace_every) {
                if Instant::now() >= at {
                    drop(g);
                    trace::report(every);
                    next_report = Some(at + every);
                    g = lock_or_recover(&self.inner);
                    continue;
                }
            }
            // Guest nanoseconds run at the host's rate, to the page's
            // rounding, so the remainder is the host time to sleep.
            let mut sleep = earliest
                .filter(|_| !g.frozen)
                .map(|deadline| Duration::from_nanos(deadline.saturating_sub(now)));
            if let Some(at) = next_report {
                let until_report = at.saturating_duration_since(Instant::now());
                sleep = Some(sleep.map_or(until_report, |s| s.min(until_report)));
            }
            // Never longer than a second, so a host sleep is seen soon after
            // the wake even when no deadline is armed.
            let d = sleep.map_or(SLEEP_CHECK_EVERY, |s| s.min(SLEEP_CHECK_EVERY));
            g = match self.changed.wait_timeout(g, d) {
                Ok((g, _)) => g,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    /// Publishes the page again when the host slept [`SLEEP_REPUBLISH_NS`]
    /// or more since the last publish, and returns what it did. The guest's
    /// counter stops while a Mac sleeps, so the wall clock the guest derives
    /// from the page is behind the host's by the sleep.
    ///
    /// The new page keeps the counter, the rate, `base_counter` and
    /// `base_ns`: the vCPUs run while it is written, and a guest that reads
    /// the old page and then the new one at the same counter value reads the
    /// same nanoseconds, which a page based at the current counter would
    /// round down by up to 1 ns. Only `wall_ns` moves, to the host's wall
    /// clock less the guest nanoseconds since `base_ns`, so the guest's wall
    /// clock is the host's again. The downtime grows by how far the guest's
    /// wall clock was behind; a guest ahead of the host is stepped back by
    /// its driver, and adds nothing. Every vCPU's `STATUS` gains
    /// `GEN_CHANGED`, and the deadlines stay as they are, since guest
    /// nanoseconds did not jump. A host whose counter ran through the sleep
    /// gets the same publish, with the wall clock 0 behind.
    ///
    /// Nothing is published while the device is frozen, since a capture is
    /// reading it, or before the first publish, when a restored VM waits
    /// for its [`PendingPublish`]: that publish takes the sleep clock again.
    fn republish_if_host_slept(&self, g: &mut Inner) -> Option<Woke> {
        if g.frozen || g.clock.generation == 0 {
            return None;
        }
        let slept_now = self.host.slept_ns();
        let slept = slept_now.saturating_sub(g.slept_at_publish);
        if slept < SLEEP_REPUBLISH_NS {
            return None;
        }
        let counter = self.counter.now();
        let now = g.clock.guest_ns(counter);
        let wall = self.host.realtime_ns();
        let guest_wall = g
            .clock
            .wall_ns
            .wrapping_add(now.wrapping_sub(g.clock.base_ns));
        let behind = wall.saturating_sub(guest_wall);
        g.clock = PageState {
            generation: g.clock.generation.wrapping_add(2),
            // The guest's wall clock is wall_ns plus the guest nanoseconds
            // since base_ns: the host's wall clock now.
            wall_ns: wall.wrapping_sub(now.wrapping_sub(g.clock.base_ns)),
            downtime_total_ns: g.clock.downtime_total_ns.saturating_add(behind),
            host_sleeps: g.clock.host_sleeps.wrapping_add(1),
            ..g.clock
        };
        self.page.publish(&g.clock);
        g.slept_at_publish = slept_now;
        let mut wake = 0;
        for cpu in 0..g.timers.len() {
            g.timers[cpu].status |= STATUS_GEN_CHANGED;
            wake |= self.update_line(g, cpu);
        }
        Some(Woke {
            slept,
            behind,
            generation: g.clock.generation,
            wake,
        })
    }

    /// Ends [`run_timer`](Self::run_timer).
    pub fn stop(&self) {
        lock_or_recover(&self.inner).stopped = true;
        self.changed.notify_all();
    }

    /// Returns the level hvi last gave each vCPU's line, for a capture of
    /// the interrupt controller, which on KVM cannot read it.
    #[must_use]
    pub fn lines(&self) -> Vec<bool> {
        lock_or_recover(&self.inner)
            .timers
            .iter()
            .map(|t| t.line)
            .collect()
    }

    /// Holds every deadline until [`restore`](Self::restore) or
    /// [`thaw`](Self::thaw), so a capture reads timers and lines that do not
    /// change under it.
    pub fn freeze(&self) {
        lock_or_recover(&self.inner).frozen = true;
        self.changed.notify_all();
    }

    /// Ends a [`freeze`](Self::freeze) without publishing anything: the
    /// guest goes on as it was, and a deadline that came due while frozen
    /// fires at once. For a capture after which the guest continues.
    pub fn thaw(&self) {
        let mut g = lock_or_recover(&self.inner);
        if !g.frozen {
            return;
        }
        g.frozen = false;
        drop(g);
        self.changed.notify_all();
    }

    /// Returns whether the device is frozen.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        lock_or_recover(&self.inner).frozen
    }

    /// Returns the device's canonical checkpoint state.
    #[must_use]
    pub fn state(&self) -> HviTimeState {
        let g = lock_or_recover(&self.inner);
        let counter = self.counter.now();
        HviTimeState {
            page: g.clock,
            guest_ns_at_capture: g.clock.guest_ns(counter),
            counter_at_capture: counter,
            cpus: g
                .timers
                .iter()
                .map(|t| CpuTimerState {
                    deadline_ns: (t.deadline != DISARMED).then_some(t.deadline),
                    status: t.status,
                    ctrl: t.ctrl,
                })
                .collect(),
        }
    }

    /// Restores `state`, captured here or on another host.
    ///
    /// The page is published again: guest nanoseconds go on from
    /// `guest_ns_at_capture` from this host's counter now, at this host's
    /// rate, the wall clock is this host's, and the time since the capture
    /// is added to the downtime. Every vCPU's `STATUS` gains `GEN_CHANGED`,
    /// each deadline is armed again (one already due fires at once), and
    /// each line follows its restored state.
    ///
    /// # Errors
    ///
    /// Errors when `state` has another number of vCPUs or an odd
    /// generation.
    pub fn restore(&self, state: &HviTimeState) -> Result<(), String> {
        let mut g = lock_or_recover(&self.inner);
        if state.cpus.len() != g.timers.len() {
            return Err(format!(
                "the hvi-time state has {} vCPU timers, this guest has {}",
                state.cpus.len(),
                g.timers.len()
            ));
        }
        if state.page.generation & 1 != 0 {
            return Err(format!(
                "the hvi-time state has an odd generation ({})",
                state.page.generation
            ));
        }
        let wall = self.host.realtime_ns();
        // The host wall clock at the capture, as the guest computed it.
        let captured_wall = state
            .page
            .wall_ns
            .wrapping_add(state.guest_ns_at_capture.wrapping_sub(state.page.base_ns));
        let downtime = wall.saturating_sub(captured_wall);
        g.clock = PageState {
            generation: state.page.generation.wrapping_add(2),
            counter_freq_hz: self.freq,
            base_counter: self.counter.now(),
            base_ns: state.guest_ns_at_capture,
            mult: self.mult,
            shift: SHIFT,
            wall_ns: wall,
            downtime_total_ns: state.page.downtime_total_ns.saturating_add(downtime),
            host_sleeps: state.page.host_sleeps,
        };
        self.page.publish(&g.clock);
        g.slept_at_publish = self.host.slept_ns();
        g.frozen = false;
        for (t, s) in g.timers.iter_mut().zip(&state.cpus) {
            t.deadline = s.deadline_ns.unwrap_or(DISARMED);
            t.low = None;
            t.status = s.status | STATUS_GEN_CHANGED;
            t.ctrl = s.ctrl & CTRL_ENABLE;
        }
        let now = g.clock.guest_ns(self.counter.now());
        let mut wake = 0;
        for cpu in 0..g.timers.len() {
            // The line is set from scratch: whatever level it had belongs
            // to the state before the restore.
            g.timers[cpu].line = !g.timers[cpu].level();
            wake |= self.update_line(&mut g, cpu);
            wake |= self.fire_if_due(&mut g, cpu, now);
        }
        drop(g);
        self.changed.notify_all();
        if wake != 0 {
            self.line.wake(wake);
        }
        Ok(())
    }
}

/// What [`HviTime::republish_if_host_slept`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Woke {
    /// How long the host slept since the last publish, in nanoseconds.
    slept: u64,
    /// How far the guest's wall clock was behind the host's.
    behind: u64,
    /// The generation it published.
    generation: u32,
    /// The vCPUs to wake.
    wake: u8,
}

impl Woke {
    fn log(&self) {
        eprintln!(
            "{} hvi-time: the host slept {:.3} s; published generation {}, the guest's wall \
             clock was {:.3} s behind",
            crate::LOG_PREFIX,
            self.slept as f64 / 1e9,
            self.generation,
            self.behind as f64 / 1e9
        );
    }
}

/// A captured `hvi-time` state that a restored VM publishes once, before
/// any vCPU first enters the guest after `resume`.
///
/// Publishing it then rather than when the VM is built means guest
/// nanoseconds go on from the capture however long the VM waited
/// restored-paused. Every vCPU calls [`publish`](Self::publish) before its
/// first entry: the first to call it publishes, and the others wait for it
/// and get its result, so none reads the device's empty page.
pub(crate) struct PendingPublish {
    /// The state at the capture.
    state: HviTimeState,
    /// How the publish went, once it has been made.
    done: std::sync::OnceLock<Result<(), String>>,
}

// Only the arm64 backends restore.
#[cfg_attr(target_arch = "x86_64", allow(dead_code))]
impl PendingPublish {
    /// Returns the publish of `state`, not made yet.
    pub(crate) fn new(state: HviTimeState) -> Self {
        Self {
            state,
            done: std::sync::OnceLock::new(),
        }
    }

    /// Returns the state when it has not been published yet: the guest has
    /// not run since the restore, so a capture now must write this state,
    /// not the device's, which holds nothing until the publish.
    pub(crate) fn unpublished(&self) -> Option<&HviTimeState> {
        self.done.get().is_none().then_some(&self.state)
    }

    /// Restores the state into `device`, once, and logs the page it
    /// published.
    ///
    /// # Errors
    ///
    /// Errors, for every caller, when the device refused the state.
    pub(crate) fn publish(&self, device: &HviTime) -> Result<(), String> {
        self.done
            .get_or_init(|| {
                device
                    .restore(&self.state)
                    .map_err(|e| format!("hvi-time: {e}"))?;
                let page = device.page().read();
                eprintln!(
                    "{} hvi-time: published generation {} at guest {} ns, counter {} Hz, \
                     downtime total {} ns",
                    crate::LOG_PREFIX,
                    page.generation,
                    page.base_ns,
                    page.counter_freq_hz,
                    page.downtime_total_ns
                );
                Ok(())
            })
            .clone()
    }
}

/// Returns the host's `CLOCK_REALTIME` in nanoseconds.
fn realtime_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Starts `device`'s timer thread, named `hvi-time`.
///
/// `setup` runs first on the new thread: the backend gives the thread the
/// scheduling it needs to wake on time and, on Linux, its seccomp filter.
///
/// # Errors
///
/// Errors when the thread cannot be spawned.
pub fn spawn_timer(
    device: &Arc<HviTime>,
    setup: impl FnOnce() + Send + 'static,
) -> io::Result<JoinHandle<()>> {
    let device = Arc::clone(device);
    std::thread::Builder::new()
        .name("hvi-time".into())
        .spawn(move || {
            setup();
            device.run_timer();
        })
}

/// Gives the calling thread the scheduling a timer thread needs, and says
/// what it got.
///
/// On macOS a default thread wakes from a 1 ms timed wait about 0.5 ms
/// late, and a thread under `THREAD_TIME_CONSTRAINT_POLICY` about 9 µs late
/// (measured on an M5 Pro for this device, with a condition-variable wait
/// and with `mach_wait_until` alike). On Linux the thread's timer slack drops
/// from the default 50 µs to 1 ns. Neither is a correctness matter: a late
/// wake makes a guest timer late, never early.
#[must_use]
pub fn timer_thread_setup() -> String {
    #[cfg(target_os = "macos")]
    {
        #[repr(C)]
        struct Timebase {
            numer: u32,
            denom: u32,
        }
        extern "C" {
            fn mach_timebase_info(info: *mut Timebase) -> libc::c_int;
        }
        let mut tb = Timebase { numer: 0, denom: 0 };
        // SAFETY: `tb` is a valid out-pointer.
        if unsafe { mach_timebase_info(&mut tb) } != 0 || tb.numer == 0 {
            return "time-constraint policy not set: no timebase".into();
        }
        let ticks = |ns: u64| (ns * u64::from(tb.denom) / u64::from(tb.numer)) as u32;
        let mut policy = libc::thread_time_constraint_policy {
            period: 0,
            computation: ticks(50_000),
            constraint: ticks(1_000_000),
            preemptible: 1,
        };
        // SAFETY: the calling thread's own port and a policy of the size
        // the count says.
        let ret = unsafe {
            libc::thread_policy_set(
                libc::pthread_mach_thread_np(libc::pthread_self()),
                libc::THREAD_TIME_CONSTRAINT_POLICY as libc::thread_policy_flavor_t,
                std::ptr::addr_of_mut!(policy).cast(),
                libc::THREAD_TIME_CONSTRAINT_POLICY_COUNT,
            )
        };
        if ret == 0 {
            "time-constraint policy".into()
        } else {
            format!("time-constraint policy refused ({ret}), timers may wake late")
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: a prctl on the calling thread that takes no pointer.
        let ret = unsafe { libc::prctl(libc::PR_SET_TIMERSLACK, 1 as libc::c_ulong) };
        if ret == 0 {
            "timer slack 1 ns".into()
        } else {
            format!(
                "timer slack not set ({}), timers may wake up to 50 us late",
                io::Error::last_os_error()
            )
        }
    }
}

/// A test of the restore path in one process:
/// `HVI_TIME_TEST_RESTORE=<at>,<downtime>`.
///
/// `at` seconds after the guest starts, the vCPUs are paused as the control
/// socket pauses them, the device is frozen and its state captured, and
/// `downtime` seconds later the state is restored and the vCPUs resumed. The
/// guest then sees what it sees after a real restore on this host: a new
/// page generation, `GEN_CHANGED` on every vCPU, guest nanoseconds that did
/// not advance across the pause, and a wall clock that did. It cannot show a
/// change of counter rate, which needs a second host.
///
/// Debugging only: it is read from the environment so that no CLI flag
/// promises it.
// The x86-64 guest has no `hvi-time`.
#[cfg_attr(target_arch = "x86_64", allow(dead_code))]
pub(crate) struct TestRestore {
    at: Duration,
    downtime: Duration,
}

#[cfg_attr(target_arch = "x86_64", allow(dead_code))]
impl TestRestore {
    /// Reads `HVI_TIME_TEST_RESTORE`, or `None` when it is unset or not two
    /// numbers of seconds.
    pub(crate) fn from_env() -> Option<Self> {
        let value = std::env::var("HVI_TIME_TEST_RESTORE").ok()?;
        let (at, downtime) = value.split_once(',')?;
        Some(Self {
            at: Duration::from_secs_f64(at.trim().parse().ok()?),
            downtime: Duration::from_secs_f64(downtime.trim().parse().ok()?),
        })
    }

    /// Runs the test on a thread of its own, after `setup` (the backend's
    /// seccomp filter on Linux). `hold` runs while the vCPUs are held, after
    /// the capture: the backend's own capture and restore of what else it
    /// can, the KVM vGIC. The thread ends early when the VM stops.
    pub(crate) fn spawn<K: Kick + 'static>(
        self,
        device: Arc<HviTime>,
        vcpus: Arc<Vcpus<K>>,
        setup: impl FnOnce() + Send + 'static,
        hold: impl FnOnce() + Send + 'static,
    ) -> io::Result<JoinHandle<()>> {
        std::thread::Builder::new()
            .name("hvi-time-test".into())
            .spawn(move || {
                setup();
                let prefix = crate::LOG_PREFIX;
                if !sleep_while_running(&vcpus, self.at) {
                    return;
                }
                if let Err(e) = vcpus.pause_from_control(Duration::from_secs(5)) {
                    eprintln!("{prefix} hvi-time test restore: the pause failed: {e:?}");
                    return;
                }
                device.freeze();
                let state = device.state();
                eprintln!(
                    "{prefix} hvi-time test restore: captured generation {} at guest {} ns, \
                     holding the vCPUs for {:.3} s",
                    state.page.generation,
                    state.guest_ns_at_capture,
                    self.downtime.as_secs_f64()
                );
                hold();
                let held = sleep_while_running(&vcpus, self.downtime);
                match device.restore(&state) {
                    Ok(()) => {
                        let page = device.page().read();
                        eprintln!(
                            "{prefix} hvi-time test restore: restored generation {} at guest {} ns, \
                             downtime total {} ns",
                            page.generation, page.base_ns, page.downtime_total_ns
                        );
                    }
                    Err(e) => eprintln!("{prefix} hvi-time test restore: {e}"),
                }
                if held {
                    let _ = vcpus.resume_from_control();
                }
            })
    }
}

/// Sleeps for `d` in short steps, and returns `false` as soon as the VM
/// stops.
#[cfg_attr(target_arch = "x86_64", allow(dead_code))]
fn sleep_while_running<K: Kick>(vcpus: &Vcpus<K>, d: Duration) -> bool {
    let end = Instant::now() + d;
    loop {
        if !vcpus.is_running() {
            return false;
        }
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(Duration::from_millis(100)));
    }
}

/// Exit and timer counters behind `HVI_TIME_TRACE`, for measuring what the
/// portable clock costs.
///
/// With `HVI_TIME_TRACE` set (to a report interval in seconds, or anything
/// else for one second), the backend counts every guest exit it handles by
/// kind, the timer counts its fires and how late each was, and the timer
/// thread prints the rates once per interval. Unset, each count is one
/// relaxed load of a flag.
pub mod trace {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    /// The kinds of exit the backends count.
    #[derive(Debug, Clone, Copy)]
    pub enum Exit {
        /// An access to the software GIC (macOS).
        Gic = 0,
        /// An access to the `hvi-time` timer window.
        Timer,
        /// An access to any other device.
        Mmio,
        /// A guest WFI (macOS).
        Wfi,
        /// A PSCI or SMCCC call (macOS).
        Hvc,
        /// A trapped system register (macOS).
        SysReg,
        /// A run that a kick ended.
        Kicked,
        /// A virtual timer exit (macOS).
        Vtimer,
        /// Anything else.
        Other,
    }

    const KINDS: usize = Exit::Other as usize + 1;
    const NAMES: [&str; KINDS] = [
        "gic", "hvi-time", "mmio", "wfi", "hvc", "sysreg", "kicked", "vtimer", "other",
    ];

    static ENABLED: AtomicBool = AtomicBool::new(false);
    /// Report interval in milliseconds, set with `ENABLED`.
    static INTERVAL_MS: AtomicU64 = AtomicU64::new(1000);
    static EXITS: [AtomicU64; KINDS] = [const { AtomicU64::new(0) }; KINDS];
    static FIRES: AtomicU64 = AtomicU64::new(0);
    static LATE_SUM_NS: AtomicU64 = AtomicU64::new(0);
    static LATE_MAX_NS: AtomicU64 = AtomicU64::new(0);

    /// Turns the counters on when `HVI_TIME_TRACE` is set, and returns
    /// whether they are on.
    pub fn enable_from_env() -> bool {
        let Some(value) = std::env::var_os("HVI_TIME_TRACE") else {
            return false;
        };
        let secs = value
            .to_str()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|s| *s >= 0.1)
            .unwrap_or(1.0);
        INTERVAL_MS.store((secs * 1000.0) as u64, Ordering::Relaxed);
        ENABLED.store(true, Ordering::SeqCst);
        true
    }

    /// The report interval, when the counters are on.
    pub(super) fn interval() -> Option<Duration> {
        ENABLED
            .load(Ordering::SeqCst)
            .then(|| Duration::from_millis(INTERVAL_MS.load(Ordering::Relaxed)))
    }

    /// Counts one exit of `kind`.
    #[inline]
    pub fn exit(kind: Exit) {
        if ENABLED.load(Ordering::Relaxed) {
            EXITS[kind as usize].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts one timer fire, `late_ns` after its deadline.
    pub(super) fn fired(late_ns: u64) {
        if ENABLED.load(Ordering::Relaxed) {
            FIRES.fetch_add(1, Ordering::Relaxed);
            LATE_SUM_NS.fetch_add(late_ns, Ordering::Relaxed);
            LATE_MAX_NS.fetch_max(late_ns, Ordering::Relaxed);
        }
    }

    /// Prints the rates since the last report, `every` ago, and starts the
    /// next interval.
    pub(super) fn report(every: Duration) {
        let secs = every.as_secs_f64();
        let counts: Vec<u64> = EXITS.iter().map(|c| c.swap(0, Ordering::Relaxed)).collect();
        let total: u64 = counts.iter().sum();
        let fires = FIRES.swap(0, Ordering::Relaxed);
        let late_sum = LATE_SUM_NS.swap(0, Ordering::Relaxed);
        let late_max = LATE_MAX_NS.swap(0, Ordering::Relaxed);
        let kinds: Vec<String> = NAMES
            .iter()
            .zip(&counts)
            .filter(|(_, n)| **n != 0)
            .map(|(name, n)| format!("{name} {:.0}", *n as f64 / secs))
            .collect();
        let late_avg = late_sum.checked_div(fires).unwrap_or(0);
        eprintln!(
            "{} hvi-time trace: exits/s {:.0} ({}) fires/s {:.0} late avg {} us max {} us",
            crate::LOG_PREFIX,
            total as f64 / secs,
            kinds.join(", "),
            fires as f64 / secs,
            late_avg / 1000,
            late_max / 1000
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    /// A guest counter the test sets by hand.
    #[derive(Clone, Default)]
    struct Counter(Arc<AtomicU64>);

    impl Counter {
        fn set(&self, v: u64) {
            self.0.store(v, Ordering::SeqCst);
        }
    }

    impl GuestCounter for Counter {
        fn now(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// The lines the device set, in order.
    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<(usize, bool)>>>);

    impl Lines {
        fn take(&self) -> Vec<(usize, bool)> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    impl TimerLine for Lines {
        fn set(&self, cpu: usize, level: bool) -> u8 {
            self.0.lock().unwrap().push((cpu, level));
            1 << cpu
        }
    }

    /// A 2-vCPU device on a 24 MHz counter that reads `counter`, published
    /// at counter 1000.
    fn device(counter: &Counter, lines: &Lines) -> HviTime {
        counter.set(1000);
        let dev = HviTime::new(
            2,
            24_000_000,
            Box::new(counter.clone()),
            Box::new(lines.clone()),
        )
        .unwrap();
        dev.publish_boot();
        dev
    }

    /// Counter ticks for `ns` at 24 MHz.
    fn ticks(ns: u64) -> u64 {
        ns * 24 / 1000
    }

    /// [`mult_for`] of a rate it serves.
    fn mult(freq: u32) -> u32 {
        mult_for(freq).expect("a rate hvi-time serves")
    }

    #[test]
    fn a_counter_rate_the_page_cannot_carry_is_refused() {
        assert_eq!(mult_for(0), None);
        assert!(counter_rate(0).is_err());
        // The boundary, from the arithmetic itself: the slowest rate whose
        // mult fits, and the one below it.
        assert_eq!(mult_for(MIN_COUNTER_HZ - 1), None);
        assert!(mult_for(MIN_COUNTER_HZ).is_some());
        assert!(counter_rate(u64::from(MIN_COUNTER_HZ) - 1).is_err());
        assert_eq!(
            counter_rate(u64::from(MIN_COUNTER_HZ)).map(|(f, _)| f),
            Ok(MIN_COUNTER_HZ)
        );
        assert!(counter_rate(u64::from(u32::MAX)).is_ok());
        let e = counter_rate(u64::from(u32::MAX) + 1).unwrap_err();
        assert!(e.contains("4294967296 Hz"), "{e}");
        assert_eq!(counter_rate(24_000_000), Ok((24_000_000, 699_050_667)));
        // The device refuses the rate, so no backend boots a guest that
        // never ticks.
        let counter = Counter::default();
        let lines = Lines::default();
        let e = HviTime::new(1, 0, Box::new(counter), Box::new(lines))
            .err()
            .expect("rate 0 refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn mult_matches_the_guest_kernel_test() {
        assert_eq!(mult_for(24_000_000), Some(699_050_667));
        assert_eq!(mult_for(54_000_000), Some(310_689_185));
        // One second of ticks is one second, to the rounding.
        let one = mul_shr(24_000_000, mult(24_000_000), SHIFT);
        assert!(one.abs_diff(1_000_000_000) <= 1, "{one}");
        let one = mul_shr(54_000_000, mult(54_000_000), SHIFT);
        assert!(one.abs_diff(1_000_000_000) <= 1, "{one}");
    }

    #[test]
    fn an_hour_of_ticks_does_not_overflow() {
        // 3600 s at 54 MHz times mult is above 2^64; the product is 96-bit.
        let ns = mul_shr(54_000_000 * 3600, mult(54_000_000), SHIFT);
        assert!(ns.abs_diff(3_600_000_000_000) < 3000, "{ns}");
    }

    #[test]
    fn the_boot_page_starts_at_zero() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let dev = device(&counter, &lines);
        assert_eq!(dev.page().ident(), (MAGIC, VERSION));
        let page = dev.page().read();
        assert_eq!(page.generation, 2);
        assert_eq!(page.counter_freq_hz, 24_000_000);
        assert_eq!((page.base_counter, page.base_ns), (1000, 0));
        assert_eq!((page.mult, page.shift), (699_050_667, 24));
        assert!(page.wall_ns > 1_700_000_000_000_000_000);
        counter.set(1000 + 24_000_000);
        assert_eq!(dev.now_ns(), 1_000_000_000);
    }

    #[test]
    fn registers_decode_by_vcpu_and_width() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let dev = device(&counter, &lines);
        // Every timer starts disarmed and disabled.
        assert_eq!(dev.mmio_read(0x00, 8), DISARMED);
        assert_eq!(dev.mmio_read(0x18, 8), 0);
        dev.mmio_write(0x100, 8, 0x1234_5678_9abc_def0);
        assert_eq!(dev.mmio_read(0x100, 8), 0x1234_5678_9abc_def0);
        assert_eq!(dev.mmio_read(0x100, 4), 0x9abc_def0);
        assert_eq!(dev.mmio_read(0x104, 4), 0x1234_5678);
        // vCPU 0's block is apart from vCPU 1's.
        assert_eq!(dev.mmio_read(0x00, 8), DISARMED);
        // A 32-bit write changes only its half.
        dev.mmio_write(0x104, 4, 0x1);
        assert_eq!(dev.mmio_read(0x100, 8), 0x0000_0001_9abc_def0);
        // NOW_NS follows the counter and ignores writes.
        counter.set(1000 + ticks(5_000));
        assert_eq!(dev.mmio_read(0x08, 8), 5_000);
        dev.mmio_write(0x08, 8, 7);
        assert_eq!(dev.mmio_read(0x108, 8), 5_000);
        // Unaligned, narrow, past the registers, past the vCPUs: zero.
        assert_eq!(dev.mmio_read(0x102, 4), 0);
        assert_eq!(dev.mmio_read(0x100, 2), 0);
        assert_eq!(dev.mmio_read(0x120, 8), 0);
        assert_eq!(dev.mmio_read(0x200, 8), 0);
        dev.mmio_write(0x218, 8, 1);
        assert_eq!(dev.mmio_read(0x218, 8), 0);
        // CTRL keeps only ENABLE.
        dev.mmio_write(0x18, 8, 0xff);
        assert_eq!(dev.mmio_read(0x18, 8), CTRL_ENABLE);
        assert!(lines.take().is_empty(), "nothing fired");
    }

    /// A deadline rewritten in 32-bit halves, low half first, fires at the
    /// value both halves make and never at the mix of old and new.
    #[test]
    fn a_deadline_written_in_halves_never_fires_early() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let dev = device(&counter, &lines);
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        // Armed at 2^32 + 0xffff_0000 ns, now 2^32 + 0x1000 ns.
        dev.mmio_write(0x00, 8, 0x1_ffff_0000);
        counter.set(1000 + ticks(0x1_0000_1000));
        // The guest moves it to 2^33 + 0x10 ns. Merged into the armed value
        // the low half would make 2^32 + 0x10, in the past.
        dev.mmio_write(0x00, 4, 0x10);
        assert!(lines.take().is_empty(), "the low half fired the timer");
        assert_eq!(dev.mmio_read(0x10, 8), 0);
        assert_eq!(dev.mmio_read(0x00, 8), DISARMED);
        dev.mmio_write(0x04, 4, 0x2);
        assert!(lines.take().is_empty(), "fired before its deadline");
        assert_eq!(dev.mmio_read(0x00, 8), 0x2_0000_0010);
        // It fires at that value, not before.
        counter.set(1000 + ticks(0x2_0000_0000));
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        assert!(lines.take().is_empty());
        counter.set(1000 + ticks(0x2_0000_0010) + 1);
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        assert_eq!(lines.take(), vec![(0, true)]);
        assert_eq!(dev.mmio_read(0x10, 8), STATUS_EXPIRED);
        // Both halves of a deadline already due fire it at the high half.
        dev.mmio_write(0x10, 8, STATUS_EXPIRED);
        assert_eq!(lines.take(), vec![(0, false)]);
        dev.mmio_write(0x00, 4, 0x5);
        assert!(lines.take().is_empty());
        dev.mmio_write(0x04, 4, 0x2);
        assert_eq!(lines.take(), vec![(0, true)]);
        // A 64-bit write drops a held low half.
        dev.mmio_write(0x100, 4, 0x7);
        dev.mmio_write(0x100, 8, 0x9_0000_0000);
        dev.mmio_write(0x104, 4, 0xa);
        assert_eq!(dev.mmio_read(0x100, 8), 0xa_0000_0000);
    }

    #[test]
    fn a_deadline_in_the_past_fires_at_once() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let dev = device(&counter, &lines);
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        counter.set(1000 + ticks(10_000));
        dev.mmio_write(0x00, 8, 9_000);
        assert_eq!(dev.mmio_read(0x10, 8), STATUS_EXPIRED);
        assert_eq!(dev.mmio_read(0x00, 8), DISARMED, "a one-shot is spent");
        assert_eq!(lines.take(), vec![(0, true)]);
        // So does one at exactly now.
        dev.mmio_write(0x118, 8, CTRL_ENABLE);
        dev.mmio_write(0x100, 8, 10_000);
        assert_eq!(lines.take(), vec![(1, true)]);
    }

    #[test]
    fn status_is_write_one_to_clear_and_drops_the_line_at_zero() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let dev = device(&counter, &lines);
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        dev.mmio_write(0x00, 8, 0);
        let state = HviTimeState {
            cpus: vec![
                CpuTimerState {
                    deadline_ns: None,
                    status: STATUS_EXPIRED,
                    ctrl: CTRL_ENABLE,
                },
                CpuTimerState {
                    deadline_ns: None,
                    status: 0,
                    ctrl: 0,
                },
            ],
            ..dev.state()
        };
        dev.restore(&state).unwrap();
        assert_eq!(dev.mmio_read(0x10, 8), STATUS_EXPIRED | STATUS_GEN_CHANGED);
        lines.take();
        // Writing 0, or the bit that is clear, changes nothing.
        dev.mmio_write(0x10, 8, 0);
        dev.mmio_write(0x10, 8, 1 << 5);
        assert_eq!(dev.mmio_read(0x10, 8), STATUS_EXPIRED | STATUS_GEN_CHANGED);
        // One bit cleared: the other holds the line.
        dev.mmio_write(0x10, 8, STATUS_EXPIRED);
        assert_eq!(dev.mmio_read(0x10, 8), STATUS_GEN_CHANGED);
        assert!(lines.take().is_empty());
        // A 32-bit write to the low half clears the last one.
        dev.mmio_write(0x10, 4, STATUS_GEN_CHANGED);
        assert_eq!(dev.mmio_read(0x10, 8), 0);
        assert_eq!(lines.take(), vec![(0, false)]);
    }

    #[test]
    fn arm_disarm_and_enable() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let dev = Arc::new(device(&counter, &lines));
        let thread = spawn_timer(&dev, || {}).unwrap();
        // Armed while disabled: nothing fires, even once due.
        dev.mmio_write(0x00, 8, 1_000);
        counter.set(1000 + ticks(2_000));
        dev.mmio_write(0x100, 8, DISARMED); // wakes the thread
        std::thread::sleep(Duration::from_millis(20));
        assert!(lines.take().is_empty());
        // Enabling a due timer fires it.
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        assert_eq!(lines.take(), vec![(0, true)]);
        dev.mmio_write(0x10, 8, STATUS_EXPIRED);
        assert_eq!(lines.take(), vec![(0, false)]);
        // Armed, then disarmed before it is due: nothing fires.
        dev.mmio_write(0x00, 8, 50_000);
        dev.mmio_write(0x00, 8, DISARMED);
        counter.set(1000 + ticks(60_000));
        dev.mmio_write(0x100, 8, DISARMED);
        std::thread::sleep(Duration::from_millis(20));
        assert!(lines.take().is_empty());
        // Armed in the future: the thread fires it once the counter passes
        // it, and not before.
        dev.mmio_write(0x00, 8, 70_000);
        std::thread::sleep(Duration::from_millis(20));
        assert!(lines.take().is_empty(), "fired early");
        counter.set(1000 + ticks(70_000));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let seen = lines.take();
            if !seen.is_empty() {
                assert_eq!(seen, vec![(0, true)]);
                break;
            }
            assert!(Instant::now() < deadline, "the timer never fired");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(dev.mmio_read(0x10, 8), STATUS_EXPIRED);
        dev.stop();
        thread.join().unwrap();
    }

    /// A page whose every field is derived from its generation, so a read
    /// that mixes two publishes shows.
    fn derived(generation: u32) -> PageState {
        let g = u64::from(generation);
        PageState {
            generation,
            counter_freq_hz: generation.wrapping_mul(3),
            base_counter: g * 5,
            base_ns: g * 7,
            mult: generation.wrapping_mul(11),
            shift: generation % 32,
            wall_ns: g * 13,
            downtime_total_ns: g * 17,
            host_sleeps: generation.wrapping_mul(19),
        }
    }

    #[test]
    fn the_generation_is_odd_while_the_page_is_written() {
        let page = Arc::new(PvclockPage::new().unwrap());
        page.publish(&derived(2));
        let stop = Arc::new(AtomicBool::new(false));
        // A reader that follows the guest's protocol while the writer
        // publishes as fast as it can: every page it accepts is whole.
        let reader = {
            let (page, stop) = (Arc::clone(&page), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut reads = 0u64;
                let mut odd = 0u64;
                while !stop.load(Ordering::SeqCst) {
                    let state = page.read();
                    assert_eq!(state, derived(state.generation), "a torn read");
                    assert_eq!(state.generation & 1, 0);
                    if page.u32_at(page::GENERATION).load(Ordering::Acquire) & 1 == 1 {
                        odd += 1;
                    }
                    reads += 1;
                }
                (reads, odd)
            })
        };
        let mut generation = 2u32;
        for _ in 0..200_000 {
            generation += 2;
            page.publish(&derived(generation));
        }
        stop.store(true, Ordering::SeqCst);
        let (reads, odd) = reader.join().unwrap();
        assert!(reads > 0);
        // Not asserted, as it depends on the scheduler: how often the
        // reader caught the writer mid-publish.
        eprintln!("{reads} whole reads, {odd} odd generations seen");
        assert_eq!(page.read(), derived(generation));

        // A writer stopped halfway leaves an odd generation, which a reader
        // waits out.
        page.u32_at(page::GENERATION)
            .store(generation + 1, Ordering::Relaxed);
        let waiting = {
            let page = Arc::clone(&page);
            std::thread::spawn(move || page.read())
        };
        std::thread::sleep(Duration::from_millis(20));
        assert!(!waiting.is_finished(), "a reader took an odd generation");
        page.publish(&derived(generation + 2));
        assert_eq!(waiting.join().unwrap(), derived(generation + 2));
    }

    #[test]
    fn the_page_bytes_are_where_the_guest_reads_them() {
        let page = PvclockPage::new().unwrap();
        page.publish(&PageState {
            generation: 8,
            counter_freq_hz: 54_000_000,
            base_counter: 0x1111,
            base_ns: 0x2222,
            mult: 310_689_185,
            shift: 24,
            wall_ns: 0x3333,
            downtime_total_ns: 0x4444,
            host_sleeps: 0x55,
        });
        // SAFETY: reading the live mapping.
        let bytes = unsafe { std::slice::from_raw_parts(page.host_ptr(), 0x40) };
        let le32 = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        let le64 = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        assert_eq!(&bytes[0..4], b"HVTM");
        assert_eq!(le32(0x00), 0x4d54_5648);
        assert_eq!(le32(0x04), 1);
        assert_eq!(le32(0x08), 8);
        assert_eq!(le32(0x0c), 54_000_000);
        assert_eq!(le64(0x10), 0x1111);
        assert_eq!(le64(0x18), 0x2222);
        assert_eq!(le32(0x20), 310_689_185);
        assert_eq!(le32(0x24), 24);
        assert_eq!(le64(0x28), 0x3333);
        assert_eq!(le64(0x30), 0x4444);
        assert_eq!(le32(0x38), 0);
        assert_eq!(le32(0x3c), 0x55);
    }

    #[test]
    fn a_state_round_trips_and_a_restore_carries_guest_time_on() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let dev = device(&counter, &lines);
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        dev.mmio_write(0x118, 8, CTRL_ENABLE);
        dev.mmio_write(0x00, 8, 5_000_000_000);
        counter.set(1000 + ticks(3_000_000_000));
        let state = dev.state();
        // Three seconds, to the page's rounding.
        let at = state.guest_ns_at_capture;
        assert!(at.abs_diff(3_000_000_000) <= 2, "{at}");
        assert_eq!(state.cpus[0].deadline_ns, Some(5_000_000_000));
        assert_eq!(state.cpus[1].deadline_ns, None);
        assert_eq!(state.cpus[1].ctrl, CTRL_ENABLE);
        // The canonical form: field names as the spec has them.
        let json = serde_json::to_string(&state).unwrap();
        for key in [
            "\"page\"",
            "\"generation\"",
            "\"counter_freq_hz\"",
            "\"base_counter\"",
            "\"base_ns\"",
            "\"mult\"",
            "\"shift\"",
            "\"wall_ns\"",
            "\"downtime_total_ns\"",
            "\"host_sleeps\"",
            "\"guest_ns_at_capture\"",
            "\"cpus\"",
            "\"deadline_ns\":null",
            "\"status\"",
            "\"ctrl\"",
        ] {
            assert!(json.contains(key), "{key} missing from {json}");
        }
        let back: HviTimeState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);

        // Restore on a "54 MHz host" whose counter reads 777.
        let counter54 = Counter::default();
        counter54.set(777);
        let lines54 = Lines::default();
        let other = HviTime::new(
            2,
            54_000_000,
            Box::new(counter54.clone()),
            Box::new(lines54.clone()),
        )
        .unwrap();
        other.restore(&back).unwrap();
        let page = other.page().read();
        assert_eq!(page.generation, state.page.generation + 2);
        assert_eq!(page.counter_freq_hz, 54_000_000);
        assert_eq!(page.mult, 310_689_185);
        assert_eq!((page.base_counter, page.base_ns), (777, at));
        // Guest time goes on from the capture, at the new rate.
        assert_eq!(other.now_ns(), at);
        counter54.set(777 + 54_000_000);
        assert!(other.now_ns().abs_diff(at + 1_000_000_000) <= 1);
        // Every vCPU is told, and every enabled line goes high.
        for cpu in 0..2 {
            assert_eq!(
                other.mmio_read(cpu * BLOCK_STRIDE + 0x10, 8),
                STATUS_GEN_CHANGED
            );
        }
        assert_eq!(lines54.take(), vec![(0, true), (1, true)]);
        assert_eq!(other.mmio_read(0x00, 8), 5_000_000_000);
        // The restored state captures back as it was, plus the new page.
        let again = other.state();
        assert_eq!(again.cpus[0].deadline_ns, Some(5_000_000_000));
        // A state for another number of vCPUs is refused.
        let mut three = back.clone();
        three.cpus.push(three.cpus[1]);
        assert!(other.restore(&three).is_err());
    }

    #[test]
    fn a_restored_deadline_already_due_fires_at_once() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let dev = device(&counter, &lines);
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        dev.mmio_write(0x00, 8, 2_000);
        counter.set(1000 + ticks(1_000));
        let mut state = dev.state();
        dev.freeze();
        // Captured after the deadline passed but before it fired.
        state.guest_ns_at_capture = 3_000;
        lines.take();
        dev.restore(&state).unwrap();
        assert_eq!(dev.mmio_read(0x10, 8), STATUS_EXPIRED | STATUS_GEN_CHANGED);
        assert_eq!(dev.mmio_read(0x00, 8), DISARMED);
    }

    #[test]
    fn a_frozen_device_fires_nothing_until_the_restore() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let dev = device(&counter, &lines);
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        let state = dev.state();
        dev.freeze();
        counter.set(1000 + ticks(1_000_000));
        dev.mmio_write(0x00, 8, 10);
        assert_eq!(dev.mmio_read(0x10, 8), 0);
        assert!(lines.take().is_empty());
        dev.restore(&state).unwrap();
        // The restore drops what was armed during the freeze.
        assert_eq!(dev.mmio_read(0x00, 8), DISARMED);
        assert_eq!(dev.mmio_read(0x10, 8), STATUS_GEN_CHANGED);
    }

    // A capture after which the guest continues thaws the device: what
    // came due while it was frozen fires then, and nothing is published.
    #[test]
    fn a_thawed_device_fires_what_came_due_and_publishes_nothing() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let dev = device(&counter, &lines);
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        dev.mmio_write(0x00, 8, 5_000);
        dev.freeze();
        assert!(dev.is_frozen());
        let page = dev.page().read();
        counter.set(1000 + ticks(10_000));
        let state = dev.state();
        assert_eq!(state.counter_at_capture, 1000 + ticks(10_000));
        // Frozen, the due deadline waits.
        dev.mmio_write(0x00, 8, 5_000);
        assert_eq!(dev.mmio_read(0x10, 8), 0);
        dev.thaw();
        assert!(!dev.is_frozen());
        assert_eq!(dev.page().read(), page);
        // The timer thread's pass fires it; the next write does too.
        dev.mmio_write(0x00, 8, 5_000);
        assert_eq!(dev.mmio_read(0x10, 8), STATUS_EXPIRED);
        dev.thaw();
    }

    #[test]
    fn the_counter_target_never_goes_back() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let mut state = device(&counter, &lines).state();
        state.page.counter_freq_hz = 24_000_000;
        state.counter_at_capture = 24_000_001;
        // 24 MHz to 54 MHz: 1 s and one tick is 54 000 002.25 ticks, rounded
        // up.
        assert_eq!(state.counter_target(54_000_000), 54_000_003);
        assert_eq!(state.counter_target(24_000_000), 24_000_001);
        state.page.counter_freq_hz = 54_000_000;
        state.counter_at_capture = 54_000_000;
        assert_eq!(state.counter_target(24_000_000), 24_000_000);
    }

    // Every vCPU of a restored VM asks for the publish before it first
    // enters the guest; the page is published once, and a refusal reaches
    // each of them.
    #[test]
    fn a_pending_publish_is_made_once_for_every_vcpu() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let source = device(&counter, &lines);
        let state = source.state();
        let dest = Arc::new(
            HviTime::new(
                2,
                24_000_000,
                Box::new(counter.clone()),
                Box::new(lines.clone()),
            )
            .unwrap(),
        );
        let pending = Arc::new(PendingPublish::new(state.clone()));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let (pending, dest) = (Arc::clone(&pending), Arc::clone(&dest));
                std::thread::spawn(move || pending.publish(&dest))
            })
            .collect();
        for t in threads {
            t.join().unwrap().unwrap();
        }
        assert_eq!(dest.page().read().generation, state.page.generation + 2);
        assert_eq!(dest.page().read().base_ns, state.guest_ns_at_capture);
        assert!(pending.unpublished().is_none());
        assert_eq!(
            PendingPublish::new(state.clone()).unpublished(),
            Some(&state)
        );
        let mut three = state;
        three.cpus.push(three.cpus[0]);
        let refused = PendingPublish::new(three);
        assert!(refused.publish(&dest).is_err());
        assert!(refused
            .publish(&dest)
            .unwrap_err()
            .contains("3 vCPU timers"));
    }

    #[test]
    fn a_state_gives_its_lines() {
        let (counter, lines) = (Counter::default(), Lines::default());
        let mut state = device(&counter, &lines).state();
        state.cpus[0] = CpuTimerState {
            deadline_ns: None,
            status: STATUS_EXPIRED,
            ctrl: CTRL_ENABLE,
        };
        state.cpus[1] = CpuTimerState {
            deadline_ns: None,
            status: STATUS_EXPIRED,
            ctrl: 0,
        };
        assert_eq!(state.lines(), vec![true, false]);
    }

    /// Host clocks the test moves by hand.
    #[derive(Clone)]
    struct Host {
        realtime: Arc<AtomicU64>,
        slept: Arc<AtomicU64>,
    }

    impl Host {
        /// Clocks at a 2026 wall clock, with 7 s of sleep since the boot.
        fn new() -> Self {
            Self {
                realtime: Arc::new(AtomicU64::new(1_780_000_000_000_000_000)),
                slept: Arc::new(AtomicU64::new(7_000_000_000)),
            }
        }

        /// The host is awake for `ns`: the wall clock moves, the sleep
        /// clock does not.
        fn run(&self, ns: u64) {
            self.realtime.fetch_add(ns, Ordering::SeqCst);
        }

        /// The host sleeps for `ns`: both move.
        fn sleep(&self, ns: u64) {
            self.realtime.fetch_add(ns, Ordering::SeqCst);
            self.slept.fetch_add(ns, Ordering::SeqCst);
        }

        fn realtime(&self) -> u64 {
            self.realtime.load(Ordering::SeqCst)
        }
    }

    impl HostClock for Host {
        fn realtime_ns(&self) -> u64 {
            self.realtime()
        }

        fn slept_ns(&self) -> u64 {
            self.slept.load(Ordering::SeqCst)
        }
    }

    /// [`device`] on host clocks the test moves, not yet published.
    fn device_on(counter: &Counter, lines: &Lines, host: &Host) -> HviTime {
        counter.set(1000);
        HviTime::with_host_clock(
            2,
            24_000_000,
            Box::new(counter.clone()),
            Box::new(lines.clone()),
            Box::new(host.clone()),
        )
        .unwrap()
    }

    /// The guest's wall clock as its driver derives it from the page.
    fn guest_wall(dev: &HviTime) -> u64 {
        let page = dev.page().read();
        page.wall_ns + (dev.now_ns() - page.base_ns)
    }

    // A Mac that sleeps stops the guest's counter: after the wake, the page
    // is published again with the host's wall clock, guest time goes on,
    // and every vCPU is told.
    #[test]
    fn a_host_sleep_publishes_the_page_again() {
        let (counter, lines, host) = (Counter::default(), Lines::default(), Host::new());
        let dev = device_on(&counter, &lines, &host);
        dev.publish_boot();
        dev.mmio_write(0x18, 8, CTRL_ENABLE);
        dev.mmio_write(0x00, 8, 9_000_000_000);
        // Awake for 2 s: the counter and the wall clock move together.
        counter.set(1000 + ticks(2_000_000_000));
        host.run(2_000_000_000);
        let before = dev.page().read();
        assert_eq!(guest_wall(&dev), host.realtime());
        // Asleep for 30 s: the wall clock moves and the counter does not.
        host.sleep(30_000_000_000);
        assert_eq!(host.realtime() - guest_wall(&dev), 30_000_000_000);
        let woke = dev
            .republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .expect("a 30 s sleep publishes");
        assert_eq!(
            woke,
            Woke {
                slept: 30_000_000_000,
                behind: 30_000_000_000,
                generation: before.generation + 2,
                wake: 0b01,
            }
        );
        let page = dev.page().read();
        assert_eq!(page.generation, before.generation + 2);
        assert_eq!((page.counter_freq_hz, page.mult), (24_000_000, 699_050_667));
        // Guest nanoseconds go on where they were, on the same base; the
        // wall clock is the host's again, and the sleep counts as downtime.
        assert_eq!(
            (page.base_counter, page.base_ns),
            (before.base_counter, before.base_ns)
        );
        assert_eq!(
            page.wall_ns,
            host.realtime() - (dev.now_ns() - page.base_ns)
        );
        assert_eq!(page.downtime_total_ns, 30_000_000_000);
        assert_eq!((before.host_sleeps, page.host_sleeps), (0, 1));
        assert_eq!(guest_wall(&dev), host.realtime());
        // Both vCPUs are told; the enabled one's line goes high, and its
        // deadline is left as it was.
        assert_eq!(dev.mmio_read(0x10, 8), STATUS_GEN_CHANGED);
        assert_eq!(dev.mmio_read(0x110, 8), STATUS_GEN_CHANGED);
        assert_eq!(lines.take(), vec![(0, true)]);
        assert_eq!(dev.mmio_read(0x00, 8), 9_000_000_000);
        // Published once: the same sleep does not publish again.
        assert!(dev
            .republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .is_none());
    }

    // The vCPUs run while a host-sleep publish is written, so a guest can
    // read the old page and then the new one at the same counter value. Both
    // must give the same nanoseconds: a page based at the publish's counter
    // would give floor(a) + floor(b) where the old one gave floor(a + b), up
    // to 1 ns less. And the driver's wall clock, wall_ns plus the guest
    // nanoseconds since base_ns, is the host's from the publish on.
    #[test]
    fn a_host_sleep_publish_keeps_guest_nanoseconds_continuous() {
        let (counter, lines, host) = (Counter::default(), Lines::default(), Host::new());
        let dev = device_on(&counter, &lines, &host);
        dev.publish_boot();
        // 2 s in: the exact nanoseconds there are 2e9 + 0.95, so a base at
        // this counter rounds the next tick's 41.67 ns away from the old
        // page's sum.
        let at = 1000 + ticks(2_000_000_000);
        counter.set(at);
        host.run(2_000_000_000);
        let before = dev.page().read();
        host.sleep(30_000_000_000);
        dev.republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .expect("a 30 s sleep publishes");
        let after = dev.page().read();
        assert_eq!(after.generation, before.generation + 2);
        for c in at..at + 64 {
            assert_eq!(after.guest_ns(c), before.guest_ns(c), "counter {c}");
        }
        assert_eq!(
            after.wall_ns + (after.guest_ns(at) - after.base_ns),
            host.realtime()
        );
        counter.set(at + ticks(1_000_000_000));
        host.run(1_000_000_000);
        assert!(guest_wall(&dev).abs_diff(host.realtime()) <= 1);
    }

    // What the timer thread does not take for a sleep: a short one, and a
    // process stopped with SIGSTOP, whose counter runs on with the host's
    // wall clock.
    #[test]
    fn a_short_sleep_or_a_stopped_process_publishes_nothing() {
        let (counter, lines, host) = (Counter::default(), Lines::default(), Host::new());
        let dev = device_on(&counter, &lines, &host);
        dev.publish_boot();
        let page = dev.page().read();
        host.sleep(SLEEP_REPUBLISH_NS - 1);
        assert!(dev
            .republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .is_none());
        // Stopped for 10 s: the counter, the wall clock and nothing else.
        counter.set(1000 + ticks(10_000_000_000));
        host.run(10_000_000_000);
        assert!(dev
            .republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .is_none());
        assert_eq!(dev.page().read(), page);
        assert!(lines.take().is_empty());
        // The short sleeps add up: the one that passes the threshold
        // publishes them all.
        host.sleep(1);
        let woke = dev
            .republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .expect("the sleeps add up to the threshold");
        assert_eq!(woke.slept, SLEEP_REPUBLISH_NS);
    }

    // Before the first publish the page holds nothing a restore could go on
    // from, and a frozen device is being captured: neither publishes. A
    // restore takes the sleep clock again, so a sleep while restored-paused
    // is not published a second time.
    #[test]
    fn a_host_sleep_waits_for_the_publish_and_the_thaw() {
        let (counter, lines, host) = (Counter::default(), Lines::default(), Host::new());
        let dev = device_on(&counter, &lines, &host);
        host.sleep(60_000_000_000);
        assert!(dev
            .republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .is_none());
        assert_eq!(dev.page().read().generation, 0);
        dev.publish_boot();
        assert!(dev
            .republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .is_none());

        dev.freeze();
        host.sleep(60_000_000_000);
        assert!(dev
            .republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .is_none());
        // A capture after which the guest goes on: the sleep is published
        // once the device thaws.
        dev.thaw();
        assert!(dev
            .republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .is_some());

        // Frozen for a capture, the host sleeps, and the state is restored.
        let state = dev.state();
        dev.freeze();
        host.sleep(60_000_000_000);
        dev.restore(&state).unwrap();
        assert!(dev
            .republish_if_host_slept(&mut lock_or_recover(&dev.inner))
            .is_none());
        assert_eq!(dev.page().read().generation, state.page.generation + 2);
        // The restore carries the host-sleep count on, so the driver's
        // count of the publishes since stays right.
        assert_eq!(state.page.host_sleeps, 1);
        assert_eq!(dev.page().read().host_sleeps, 1);
    }

    // The timer thread looks at the sleep clock at least once a second,
    // even with no deadline armed.
    #[test]
    fn the_timer_thread_publishes_after_a_host_sleep() {
        let (counter, lines, host) = (Counter::default(), Lines::default(), Host::new());
        let dev = Arc::new(device_on(&counter, &lines, &host));
        dev.publish_boot();
        let generation = dev.page().read().generation;
        let thread = spawn_timer(&dev, || {}).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        host.sleep(5_000_000_000);
        let deadline = Instant::now() + Duration::from_secs(5);
        while dev.page().read().generation == generation {
            assert!(Instant::now() < deadline, "no publish after the sleep");
            std::thread::sleep(Duration::from_millis(10));
        }
        let page = dev.page().read();
        assert_eq!(page.generation, generation + 2);
        assert_eq!(page.downtime_total_ns, 5_000_000_000);
        dev.stop();
        thread.join().unwrap();
    }

    #[test]
    fn the_sleep_test_moves_both_clocks_at_its_time() {
        assert!(TestSleep::parse("1").is_none());
        assert!(TestSleep::parse("x,1").is_none());
        assert!(TestSleep::parse("-1,1").is_none());
        let now = TestSleep::parse("0, 2.5").unwrap();
        assert_eq!(now.shift_ns(), 2_500_000_000);
        let later = TestSleep::parse("3600,2.5").unwrap();
        assert_eq!(later.shift_ns(), 0);
        let clock = SystemClock { test: Some(now) };
        let real = SystemClock { test: None };
        let shifted = clock.realtime_ns() - real.realtime_ns();
        assert!(shifted.abs_diff(2_500_000_000) < 1_000_000_000, "{shifted}");
        let slept = clock.slept_ns() - real.slept_ns();
        assert!(slept.abs_diff(2_500_000_000) < 1_000_000, "{slept}");
    }

    // The host's own sleep clock does not move while the host is awake,
    // to well within the threshold.
    #[test]
    fn the_host_sleep_clock_holds_still_while_the_host_is_awake() {
        let a = host_slept_ns();
        std::thread::sleep(Duration::from_millis(50));
        let b = host_slept_ns();
        assert!(b.abs_diff(a) < SLEEP_REPUBLISH_NS / 10, "{a} then {b}");
    }
}

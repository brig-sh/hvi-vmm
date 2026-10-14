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

//! The guest's writes to its RAM on Hypervisor.framework, which keeps no
//! dirty log.
//!
//! [`HvfWriteLog`] makes one. It write-protects guest RAM in the stage-2
//! tables with `hv_vm_protect`, leaving reads and instruction fetches alone.
//! The first write to each granule then exits as a data abort at its IPA,
//! which the vCPU's own thread hands to [`HvfWriteLog::fault`]: that records
//! the granule and makes it writable again, and the vCPU re-runs the store,
//! its PC unchanged. A collect takes the granules recorded and protects them
//! again, so each granule costs one exit per round in which it is written.
//!
//! The record and the protection change together under one lock. A collect
//! that took a granule protects it before a vCPU can mark it again, and a
//! vCPU that marks a granule makes it writable before a collect can take
//! it, so no granule is ever writable without being in the record.
//!
//! That rests on `hv_vm_protect` taking effect on a vCPU running in the guest
//! before it returns, which Apple does not document. The ignored test
//! `no_store_lands_after_a_collect_returns` checks it: a store that landed
//! after a collect's protect returned would be a write no round sends.
//!
//! The granule is the VM's IPA granule, 16 KiB on Apple silicon, which
//! [`ipa_granule`] asks the framework for; it is never smaller than the host
//! page `hv_vm_protect` works in.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use crate::memory::{DirtyPages, GuestWriteLog, RamRegion};

/// The IPA granule the framework uses when the VM's configuration names
/// none, read from `hv_vm_config_get_default_ipa_granule` (macOS 26), and
/// never less than the host page. Older systems have no call, and their
/// granule is the host page.
#[must_use]
pub(crate) fn ipa_granule() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(16 << 10);
    // Looked up at run time, so hvi still loads on a macOS without it.
    // SAFETY: a NUL-terminated name looked up in the loaded images.
    let sym = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"hv_vm_config_get_default_ipa_granule".as_ptr(),
        )
    };
    if sym.is_null() {
        return page;
    }
    // SAFETY: the symbol is the framework's `hv_return_t
    // hv_vm_config_get_default_ipa_granule(hv_ipa_granule_t *)`, whose
    // granule is a `uint32_t` enum.
    let get: extern "C" fn(*mut u32) -> i32 = unsafe { std::mem::transmute(sym) };
    let mut granule = u32::MAX;
    let bytes = match (get(&mut granule), granule) {
        (0, 0) => 4 << 10,
        (0, 1) => 16 << 10,
        _ => page,
    };
    bytes.max(page)
}

/// Sets the stage-2 permissions of `[ipa, ipa+size)`.
fn protect(ipa: u64, size: u64, flags: u64) -> io::Result<()> {
    let len = usize::try_from(size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "range too large"))?;
    // SAFETY: changes permissions of guest-physical memory the VM mapped; no
    // host memory is touched.
    let ret = unsafe { applevisor_sys::hv_vm_protect(ipa, len, flags) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "hv_vm_protect({ipa:#x}+{size:#x}, {flags:#x}) failed: {ret:#x}"
        )))
    }
}

/// Returns the runs of set bits in `bits` as `(first, count)`.
fn bit_runs(bits: &[u64]) -> Vec<(u64, u64)> {
    let mut runs = Vec::new();
    let mut start: Option<u64> = None;
    let total = bits.len() as u64 * 64;
    for bit in 0..=total {
        let set = bit < total && bits[(bit / 64) as usize] & (1 << (bit % 64)) != 0;
        match (set, start) {
            (true, None) => start = Some(bit),
            (false, Some(s)) => {
                runs.push((s, bit - s));
                start = None;
            }
            _ => {}
        }
    }
    runs
}

/// Read and execute, the protection a tracked granule waits under.
const READ_EXEC: u64 = applevisor_sys::HV_MEMORY_READ | applevisor_sys::HV_MEMORY_EXEC;

/// Read, write and execute, as guest RAM is mapped.
const READ_WRITE_EXEC: u64 = READ_EXEC | applevisor_sys::HV_MEMORY_WRITE;

/// What the lock guards: whether a move tracks writes, and the granules
/// written since the last collect.
struct Inner {
    /// Whether RAM is protected and writes are recorded.
    tracking: bool,
    /// One bitmap per region, a bit per granule.
    bits: Vec<Vec<u64>>,
}

/// The write faults served, for the reply's account of their cost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FaultStats {
    /// Faults served while tracking.
    pub(crate) faults: u64,
    /// Host time spent serving them, in nanoseconds.
    pub(crate) host_ns: u64,
}

/// The dirty log hvi keeps for a Hypervisor.framework guest by protecting
/// its RAM; see the module documentation.
pub(crate) struct HvfWriteLog {
    /// Guest RAM, in address order.
    regions: Vec<RamRegion>,
    /// The bytes each bit covers.
    granule: u64,
    /// The record and whether one is kept.
    inner: Mutex<Inner>,
    /// Faults served while tracking.
    faults: AtomicU64,
    /// Host nanoseconds spent serving them.
    fault_ns: AtomicU64,
}

impl HvfWriteLog {
    /// Returns a log over `regions` at the VM's IPA granule, not tracking.
    #[must_use]
    pub(crate) fn new(regions: &[RamRegion]) -> Self {
        Self::with_granule(regions, ipa_granule())
    }

    /// Returns a log over `regions` at `granule`.
    fn with_granule(regions: &[RamRegion], granule: u64) -> Self {
        let mut regions = regions.to_vec();
        regions.sort_by_key(|r| r.gpa);
        let bits = regions
            .iter()
            .map(|r| vec![0; r.size.div_ceil(granule).div_ceil(64) as usize])
            .collect();
        Self {
            regions,
            granule,
            inner: Mutex::new(Inner {
                tracking: false,
                bits,
            }),
            faults: AtomicU64::new(0),
            fault_ns: AtomicU64::new(0),
        }
    }

    /// Serves a data abort at `ipa` on the faulting vCPU's thread.
    ///
    /// Returns `Ok(false)` when `ipa` is not guest RAM, and the exit is the
    /// caller's to serve. Otherwise the fault was a write to a protected
    /// granule: it is recorded, made writable again, and the caller re-runs
    /// the vCPU without moving its PC. A fault while no move tracks, which
    /// only a fault taken just before the stop can be, only makes the
    /// granule writable.
    ///
    /// # Errors
    ///
    /// Errors when the framework refuses the new permissions; the vCPU would
    /// fault again at once, so the caller ends the run.
    pub(crate) fn fault(&self, ipa: u64) -> io::Result<bool> {
        let Some((index, region)) = self
            .regions
            .iter()
            .enumerate()
            .find(|(_, r)| ipa >= r.gpa && ipa - r.gpa < r.size)
        else {
            return Ok(false);
        };
        let started = Instant::now();
        let granule = (ipa - region.gpa) / self.granule;
        let mut inner = self.inner.lock().unwrap();
        if inner.tracking {
            inner.bits[index][(granule / 64) as usize] |= 1 << (granule % 64);
        }
        protect(
            region.gpa + granule * self.granule,
            self.granule.min(region.size - granule * self.granule),
            READ_WRITE_EXEC,
        )?;
        let tracking = inner.tracking;
        drop(inner);
        if tracking {
            self.faults.fetch_add(1, Ordering::Relaxed);
            self.fault_ns
                .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
        Ok(true)
    }

    /// Returns the faults served so far and their host time.
    pub(crate) fn fault_stats(&self) -> FaultStats {
        FaultStats {
            faults: self.faults.load(Ordering::Relaxed),
            host_ns: self.fault_ns.load(Ordering::Relaxed),
        }
    }

    /// Protects every region with `flags`.
    fn protect_all(&self, flags: u64) -> io::Result<()> {
        for region in &self.regions {
            protect(region.gpa, region.size, flags)?;
        }
        Ok(())
    }
}

impl GuestWriteLog for HvfWriteLog {
    fn start(&self) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        for bits in &mut inner.bits {
            bits.fill(0);
        }
        self.faults.store(0, Ordering::Relaxed);
        self.fault_ns.store(0, Ordering::Relaxed);
        if let Err(e) = self.protect_all(READ_EXEC) {
            let _ = self.protect_all(READ_WRITE_EXEC);
            return Err(e);
        }
        inner.tracking = true;
        Ok(())
    }

    fn collect(&self, into: &mut DirtyPages) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let taken: Vec<Vec<u64>> = inner
            .bits
            .iter_mut()
            .map(|bits| std::mem::replace(bits, vec![0; bits.len()]))
            .collect();
        // Every granule taken was made writable by its fault; protect it
        // again before a vCPU can write it unrecorded.
        for (region, bits) in self.regions.iter().zip(&taken) {
            for (first, count) in bit_runs(bits) {
                let start = first * self.granule;
                protect(
                    region.gpa + start,
                    (count * self.granule).min(region.size - start),
                    READ_EXEC,
                )?;
            }
        }
        drop(inner);
        for (index, bits) in taken.iter().enumerate() {
            into.or_granules(index, bits, self.granule)?;
        }
        Ok(())
    }

    fn stop(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.tracking = false;
        for bits in &mut inner.bits {
            bits.fill(0);
        }
        if let Err(e) = self.protect_all(READ_WRITE_EXEC) {
            eprintln!("{} {e}", crate::LOG_PREFIX);
        }
    }

    fn granule(&self) -> u64 {
        self.granule
    }

    fn fault_stats(&self) -> Option<(u64, u64)> {
        let stats = HvfWriteLog::fault_stats(self);
        Some((stats.faults, stats.host_ns))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::aarch64::esr::Ec;
    use applevisor::prelude::{Reg, VirtualMachine};

    const BASE: u64 = 0x4000_0000;

    /// `str x0, [x1]; add x1, x1, x2; subs x3, x3, #1; b.ne .-12; hvc #0`:
    /// stores x0 at x1, x1 + x2, ... x3 times, then exits.
    const STRIDE_STUB: [u32; 5] = [
        0xf900_0020,
        0x8b02_0021,
        0xf100_0463,
        0x54ff_ffa1,
        0xd400_0002,
    ];

    /// `str x0, [x1]; b .-4`: stores x0 at x1 for ever.
    const SPIN_STUB: [u32; 2] = [0xf900_0020, 0x17ff_ffff];

    /// `str x0, [x1]; add x0, x0, #1; b .-8`: stores a rising count at x1
    /// for ever.
    const COUNT_STUB: [u32; 3] = [0xf900_0020, 0x9100_0400, 0x17ff_fffe];

    /// Anonymous host memory of `len` bytes, mapped at `BASE` for the guest.
    struct Ram {
        host: *mut u8,
        len: usize,
    }

    impl Ram {
        fn new(len: usize, stub: &[u32]) -> Self {
            // SAFETY: a fresh anonymous mapping.
            let host = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            assert_ne!(host, libc::MAP_FAILED);
            // SAFETY: the stub fits at the start of the mapping.
            unsafe { std::ptr::copy_nonoverlapping(stub.as_ptr(), host.cast(), stub.len()) };
            // SAFETY: a live mapping of `len` bytes.
            let ret = unsafe { applevisor_sys::hv_vm_map(host, BASE, len, READ_WRITE_EXEC) };
            assert_eq!(ret, 0, "hv_vm_map");
            Self {
                host: host.cast(),
                len,
            }
        }

        fn word(&self, offset: u64) -> u64 {
            // SAFETY: an aligned word inside the mapping.
            unsafe { self.host.add(offset as usize).cast::<u64>().read_volatile() }
        }

        fn region(&self) -> RamRegion {
            RamRegion {
                gpa: BASE,
                size: self.len as u64,
                file_offset: 0,
            }
        }
    }

    impl Drop for Ram {
        fn drop(&mut self) {
            // SAFETY: unmapping what `new` mapped, from the VM then the host.
            unsafe {
                applevisor_sys::hv_vm_unmap(BASE, self.len);
                libc::munmap(self.host.cast(), self.len);
            }
        }
    }

    /// Runs the stride stub over `count` granules from the second one, and
    /// returns the data aborts it took and how long the run took.
    fn stride(
        vcpu: &applevisor::prelude::Vcpu,
        log: &HvfWriteLog,
        count: u64,
        value: u64,
    ) -> (u64, std::time::Duration) {
        let granule = log.granule;
        vcpu.set_reg(Reg::PC, BASE).unwrap();
        vcpu.set_reg(Reg::CPSR, 0x3c5).unwrap();
        vcpu.set_reg(Reg::X0, value).unwrap();
        vcpu.set_reg(Reg::X1, BASE + granule).unwrap();
        vcpu.set_reg(Reg::X2, granule).unwrap();
        vcpu.set_reg(Reg::X3, count).unwrap();
        let mut aborts = 0;
        let started = Instant::now();
        loop {
            vcpu.run().unwrap();
            let exit = vcpu.get_exit_info();
            match Ec::from_syndrome(exit.exception.syndrome) {
                Ec::DataAbort => {
                    assert!(log.fault(exit.exception.physical_address).unwrap());
                    aborts += 1;
                    assert!(aborts <= count, "a granule faulted twice");
                }
                Ec::Hvc => return (aborts, started.elapsed()),
                other => panic!("unexpected exit {other:?}"),
            }
        }
    }

    // The mechanism the HVF dirty log rests on: a protected granule faults
    // once at its IPA, the store completes when the vCPU re-runs it
    // unprotected, and a collect reports each granule's pages and protects
    // them again. It also measures what a fault costs.
    #[test]
    fn bit_runs_finds_each_run() {
        assert_eq!(
            bit_runs(&[0b1011_0000, 1 << 63, 1]),
            vec![(4, 2), (7, 1), (127, 2)]
        );
        assert_eq!(bit_runs(&[0, 0]), vec![]);
    }

    #[test]
    #[ignore = "needs a signed test binary with the hypervisor entitlement"]
    fn a_protected_granule_faults_once_and_the_store_completes() {
        let granule = ipa_granule();
        println!("IPA granule {granule} bytes");
        assert!(granule >= 4096 && granule.is_power_of_two());
        const COUNT: u64 = 4096;
        // The VM must exist before RAM is mapped into it.
        let vm = VirtualMachine::new().unwrap();
        let ram = Ram::new(((COUNT + 1) * granule) as usize, &STRIDE_STUB);
        let log = HvfWriteLog::new(&[ram.region()]);
        let vcpu = vm.vcpu_create().unwrap();

        // Unprotected: no aborts. Twice, so the second is warm.
        let _ = stride(&vcpu, &log, COUNT, 1);
        let (aborts, plain) = stride(&vcpu, &log, COUNT, 2);
        assert_eq!(aborts, 0);

        log.start().unwrap();
        let (aborts, tracked) = stride(&vcpu, &log, COUNT, 0x5a5a);
        assert_eq!(aborts, COUNT, "one abort per granule written");
        for i in 1..=COUNT {
            assert_eq!(ram.word(i * granule), 0x5a5a, "granule {i} holds the store");
        }
        let mut set = DirtyPages::new(&[ram.region()]);
        log.collect(&mut set).unwrap();
        assert_eq!(set.count(), COUNT * (granule / 4096));
        assert!(!set.contains(0, 0), "the stub's granule was not written");
        assert!(set.contains(0, granule / 4096));

        // Collected and protected again: the next round faults again.
        let (again, _) = stride(&vcpu, &log, COUNT, 0x6b6b);
        assert_eq!(again, COUNT);
        let stats = log.fault_stats();
        log.stop();
        let (after, _) = stride(&vcpu, &log, COUNT, 3);
        assert_eq!(after, 0, "stop gives the guest its RAM back");
        let per_fault = (tracked.saturating_sub(plain)).as_nanos() as f64 / COUNT as f64;
        println!(
            "{COUNT} granules: {plain:?} unprotected, {tracked:?} protected: {per_fault:.0} ns \
             per fault end to end, {:.0} ns of it in the handler ({} faults)",
            stats.host_ns as f64 / stats.faults as f64,
            stats.faults
        );
    }

    // A collect runs on the control thread while the vCPUs run, so the
    // protection must reach a vCPU in the guest: a vCPU spinning on a store
    // faults once another thread protects its granule.
    #[test]
    #[ignore = "needs a signed test binary with the hypervisor entitlement"]
    fn a_protection_from_another_thread_reaches_a_running_vcpu() {
        let granule = ipa_granule();
        let vm = VirtualMachine::new().unwrap();
        let ram = Ram::new((2 * granule) as usize, &SPIN_STUB);
        let log = std::sync::Arc::new(HvfWriteLog::new(&[ram.region()]));
        let (tx, rx) = std::sync::mpsc::channel();
        let vcpu_log = std::sync::Arc::clone(&log);
        let target = BASE + granule + 8;
        let vcpu_vm = vm.clone();
        let runner = std::thread::spawn(move || {
            let vcpu = vcpu_vm.vcpu_create().unwrap();
            vcpu.set_reg(Reg::PC, BASE).unwrap();
            vcpu.set_reg(Reg::CPSR, 0x3c5).unwrap();
            vcpu.set_reg(Reg::X0, 7).unwrap();
            vcpu.set_reg(Reg::X1, target).unwrap();
            tx.send(()).unwrap();
            vcpu.run().unwrap();
            let exit = vcpu.get_exit_info();
            let ec = Ec::from_syndrome(exit.exception.syndrome);
            let ipa = exit.exception.physical_address;
            let ours = vcpu_log.fault(ipa).unwrap();
            (ec, ipa, ours)
        });
        rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let protected_at = Instant::now();
        log.start().unwrap();
        let (ec, ipa, ours) = runner.join().unwrap();
        println!(
            "the spinning vCPU faulted {:?} after the protect",
            protected_at.elapsed()
        );
        assert_eq!(ec, Ec::DataAbort);
        assert_eq!(ipa, target);
        assert!(ours);
        let mut set = DirtyPages::new(&[ram.region()]);
        log.collect(&mut set).unwrap();
        assert_eq!(set.runs(64), vec![(0, granule / 4096, granule / 4096)]);
        log.stop();
        drop(ram);
        drop(vm);
    }

    // The record holds every write only if `hv_vm_protect` stops a vCPU
    // running in the guest before it returns. A vCPU stores a rising count;
    // each pass collects (which protects the granule again), reads the word,
    // then holds the vCPU at its next fault and reads it again. A store
    // that landed after the collect returned shows as a changed word, and
    // would be a write that no round sends. A macOS release that made the
    // protect take effect later would fail here.
    #[test]
    #[ignore = "needs a signed test binary with the hypervisor entitlement"]
    fn no_store_lands_after_a_collect_returns() {
        use std::sync::atomic::AtomicBool;
        use std::sync::mpsc;
        const PASSES: u32 = 2000;
        let granule = ipa_granule();
        let vm = VirtualMachine::new().unwrap();
        let ram = Ram::new((2 * granule) as usize, &COUNT_STUB);
        let log = std::sync::Arc::new(HvfWriteLog::new(&[ram.region()]));
        let held = std::sync::Arc::new(AtomicBool::new(false));
        let target = BASE + granule + 8;
        let (fault_tx, fault_rx) = mpsc::channel::<()>();
        let (go_tx, go_rx) = mpsc::channel::<bool>();
        let (vcpu_log, vcpu_held, vcpu_vm) = (
            std::sync::Arc::clone(&log),
            std::sync::Arc::clone(&held),
            vm.clone(),
        );
        log.start().unwrap();
        let runner = std::thread::spawn(move || {
            let vcpu = vcpu_vm.vcpu_create().unwrap();
            vcpu.set_reg(Reg::PC, BASE).unwrap();
            vcpu.set_reg(Reg::CPSR, 0x3c5).unwrap();
            vcpu.set_reg(Reg::X0, 1).unwrap();
            vcpu.set_reg(Reg::X1, target).unwrap();
            loop {
                vcpu.run().unwrap();
                let exit = vcpu.get_exit_info();
                assert_eq!(Ec::from_syndrome(exit.exception.syndrome), Ec::DataAbort);
                if vcpu_held.load(Ordering::SeqCst) {
                    fault_tx.send(()).unwrap();
                    if !go_rx.recv().unwrap() {
                        return;
                    }
                }
                assert!(vcpu_log.fault(exit.exception.physical_address).unwrap());
            }
        });
        let (mut late, mut most) = (0u64, 0u64);
        for pass in 0..PASSES {
            let before = ram.word(granule + 8);
            let started = Instant::now();
            while ram.word(granule + 8) == before {
                assert!(started.elapsed().as_secs() < 5, "the vCPU is not storing");
            }
            held.store(true, Ordering::SeqCst);
            let mut set = DirtyPages::new(&[ram.region()]);
            log.collect(&mut set).unwrap();
            let at_return = ram.word(granule + 8);
            fault_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the vCPU never faulted after the collect");
            let at_fault = ram.word(granule + 8);
            if at_fault != at_return {
                late += 1;
                most = most.max(at_fault.wrapping_sub(at_return));
            }
            held.store(false, Ordering::SeqCst);
            go_tx.send(pass + 1 < PASSES).unwrap();
        }
        runner.join().unwrap();
        log.stop();
        println!(
            "{PASSES} collects: {late} with stores after the collect returned, at most {most}"
        );
        assert_eq!(late, 0, "stores landed after the protect returned");
    }
}

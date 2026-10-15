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

//! The arm64 guest on Hypervisor.framework, SMP-capable.
//!
//! One thread per vCPU (an `applevisor::Vcpu` is thread-bound). vcpu0 boots at
//! the kernel entry; secondaries park until the guest brings them up via PSCI
//! `CPU_ON`. Guest RAM is a `GuestRam` shared by every vCPU thread; devices,
//! the event emitter, and the vCPU-handle list are shared behind locks. A
//! plugin, if the caller supplied one, is called on vcpu0 between guest
//! entries. See [`crate::plugin`].
//!
//! The exit-loop's timer/WFI/PC handling and the SMP hand-off are the
//! boot-debug frontier.
//!
//! Two machines run here. The native one creates Apple's in-kernel GICv3
//! (`hv_gic`), which also waits out a guest WFI. The portable profile
//! (`--profile portable-arm64-v1`, see `docs/portable-profile.md`) creates
//! no GIC: the guest gets the software GICv2 of [`crate::devices::gicv2`],
//! each vCPU thread sets the vCPU's IRQ line from it before every guest
//! entry, and a guest WFI exits to hvi, which sleeps the thread until the
//! GIC has an interrupt for it or the guest's virtual timer is due. The
//! portable guest's clock and timers are [`crate::devices::hvitime`]: its
//! page is mapped read-only, its timer window is served here, and its timer
//! thread raises PPI 20 in the software GIC, which wakes a vCPU sleeping in
//! a WFI.

// Resolved once while the VM is built, before any guest request; see
// clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, TryLockError};
use std::time::{Duration, Instant};

use applevisor::prelude::{
    ExitReason, FeatureReg, GicConfig, GicDisabled, GicEnabled, InterruptType, Reg, SysReg, Vcpu,
    VcpuConfig, VcpuHandle, VirtualMachine, VirtualMachineConfig, VirtualMachineInstance,
};

use crate::arch::aarch64::esr::{DataAbort, Ec};
use crate::arch::aarch64::fdt::{self, ArchTimer};
use crate::arch::aarch64::hvf_dirty::HvfWriteLog;
use crate::arch::aarch64::hvf_state;
use crate::arch::aarch64::layout::{
    virtio_fs_base, virtio_fs_spi, GicLayout, GicVersion, DEVICE_WINDOW_END, HVI_TIME_PAGE_BASE,
    HVI_TIME_TIMERS_BASE, RAM_BASE, UART_BASE, UART_SIZE, UART_SPI, VIRTIO_BASE, VIRTIO_NET_BASE,
    VIRTIO_NET_SPI, VIRTIO_SIZE, VIRTIO_SPI, VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_SPI,
};
use crate::arch::aarch64::loader;
use crate::arch::aarch64::portable::{self, fw};
use crate::arch::aarch64::profile::{self as arm64_profile, Arm64Machine};
use crate::arch::aarch64::rebuild;
use crate::checkpoint::bundle::IrqLevels;
use crate::checkpoint::capture::Console;
use crate::checkpoint::cpu::{Aarch64Vcpu, ImportPlan, Power, VcpuState, Work};
use crate::checkpoint::platform::{TimerState, HVF_GIC_STATE, HVF_GIC_STATE_CAPABILITY};
use crate::checkpoint::profile::{device, hex, MachineProfile, ProfileCell, UNKNOWN};
use crate::checkpoint::restore::{self, import, Refused, Restorer};
use crate::checkpoint::server::ControlSocket;
use crate::config::{check_export_overlap, BootConfig, MachineProfileKind, RestoreConfig, Stop};
use crate::devices::gicv2::Gicv2;
use crate::devices::hvitime::{self, trace, GuestCounter, HviTime, PendingPublish, TimerLine};
use crate::devices::irq::IrqLine;
use crate::devices::legacy::pl011::Pl011;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::fs::fdlimit;
use crate::devices::virtio::fs::server::{self, VirtioFs};
use crate::devices::virtio::mmio;
use crate::devices::virtio::net::{self, VirtioNet};
use crate::devices::virtio::vsock::{VirtioVsock, VsockBridge};
use crate::events::Emitter;
use crate::hypervisor::guest::{Guest, PluginThread, PluginThreads, SafepointVcpu};
use crate::hypervisor::vcpus::{Kick, Outcome, Vcpus};
use crate::io_threads::{IoThreads, NetSource};
use crate::memory::{GuestRam, GuestWriteLog, SharedRam};
use crate::plugin::{GuestArch, Plugin, RegsView};
use crate::run::{record_start, run_to_stop, StopHandle};
use crate::sandbox::seatbelt;
use crate::signal::install_kick_handler;
use crate::sync::lock_or_recover;
use crate::teardown::{StopSource, StopToken};
use crate::terminal;
use crate::LOG_PREFIX;
use vm_memory::{Address, GuestMemoryBackend, GuestMemoryRegion};

/// The VM handle once the GICv3 is configured (Send/Sync; cloned per thread).
type VmGic = VirtualMachineInstance<GicEnabled>;

/// The VM handle the vCPU threads and the kicks use, with or without the
/// in-kernel GIC.
type Vm = VirtualMachineInstance<GicDisabled>;

/// GIC INTIDs: SPIs start at 32.
const UART_INTID: u32 = 32 + UART_SPI;
const VIRTIO_INTID: u32 = 32 + VIRTIO_SPI;
const VIRTIO_NET_INTID: u32 = 32 + VIRTIO_NET_SPI;
const VIRTIO_VSOCK_INTID: u32 = 32 + VIRTIO_VSOCK_SPI;
/// The virtual timer's PPI (PPI 11 in the devicetree).
const VTIMER_INTID: u32 = 27;

/// The vCPU's IRQ line for `hv_vcpu_set_pending_interrupt`:
/// `HV_INTERRUPT_TYPE_IRQ`, value 0 in the SDK's `hv_vcpu_types.h`.
///
/// applevisor-sys 1.0.0 declares the enum's two values in the other order,
/// so its `FIQ` variant is the one with the SDK's IRQ value. Its `IRQ` would
/// raise an FIQ, which Linux panics on ("FIQ taken without a root FIQ
/// handler").
const IRQ_LINE: InterruptType = InterruptType::FIQ;

/// PSCI function IDs (SMC64/HVC calling convention) we recognise.
mod psci {
    pub const VERSION: u64 = 0x8400_0000;
    pub const CPU_OFF: u64 = 0x8400_0002;
    pub const SYSTEM_OFF: u64 = 0x8400_0008;
    pub const SYSTEM_RESET: u64 = 0x8400_0009;
    pub const FEATURES: u64 = 0x8400_000a;
    pub const CPU_ON_64: u64 = 0xc400_0003;
    pub const SUCCESS: u64 = 0;
    pub const NOT_SUPPORTED: u64 = (-1i64) as u64;
}

/// A secondary vCPU's start mailbox, filled by a PSCI `CPU_ON`.
struct Secondary {
    mbox: Mutex<Option<(u64, u64)>>, // (entry point, context id)
    cv: Condvar,
}

/// A guest interrupt line on the in-kernel GIC.
///
/// A line that rises on an I/O thread also kicks the vCPUs, so a guest in WFI
/// takes the interrupt promptly. A vCPU thread raises a line between its own
/// guest entries and kicks no one, and neither does the console UART's line.
struct HvfIrqLine {
    /// The VM whose GIC has the line.
    vm: VmGic,
    /// The line's interrupt ID.
    intid: u32,
    /// The vCPUs a rise on an I/O thread kicks, or `None` for a line that kicks
    /// none.
    kick: Option<Arc<Vcpus<Kicker>>>,
}

impl IrqLine for HvfIrqLine {
    fn set_level(&self, level: bool) -> std::io::Result<()> {
        self.vm
            .gic_set_spi(self.intid, level)
            .map_err(std::io::Error::other)?;
        let Some(vcpus) = self.kick.as_ref().filter(|_| level) else {
            return Ok(());
        };
        // After the stop no vCPU is left to wake.
        if vcpus.is_running() && OWN_VCPU.with(std::cell::Cell::get).is_none() {
            vcpus.kicker().kick_all();
        }
        Ok(())
    }
}

/// A portable vCPU's emulated WFI: the thread sleeps on `cv` with `asleep`
/// set.
struct Idle {
    /// Whether the vCPU's thread is in [`wait_for_interrupt`]. Whoever wakes
    /// it takes this lock to notify, so a wake cannot land between the
    /// thread's last check and its wait.
    asleep: Mutex<bool>,
    cv: Condvar,
}

/// A guest interrupt line on the portable profile's software GICv2.
///
/// Unlike [`HvfIrqLine`], every rise wakes the vCPUs the GIC routes it to,
/// from whichever thread it comes: the GIC model is not in the hypervisor,
/// so nothing else would tell a vCPU in an emulated WFI, or one in a run.
struct SoftIrqLine {
    /// The machine whose GIC has the line.
    portable: Arc<Portable>,
    /// The line's interrupt ID, an SPI.
    intid: u32,
    /// The vCPUs to wake.
    vcpus: Arc<Vcpus<Kicker>>,
}

impl IrqLine for SoftIrqLine {
    fn set_level(&self, level: bool) -> std::io::Result<()> {
        // The GIC lock is released before any vCPU is woken: a vCPU going
        // to sleep takes its `Idle` lock and then the GIC's.
        let out = lock_or_recover(&self.portable.gic).set_spi_line(self.intid, level);
        if out.wake != 0 && self.vcpus.is_running() {
            self.vcpus.kicker().wake_mask(out.wake);
        }
        Ok(())
    }
}

/// The `hvi-time` lines on the software GICv2: PPI 20 of each vCPU.
///
/// As for [`SoftIrqLine`], a rise wakes the vCPU from whichever thread it
/// comes: the timer thread, or another vCPU that wrote a deadline already
/// due into this vCPU's block.
struct HvfTimerLine {
    /// The machine whose GIC has the lines.
    portable: Arc<Portable>,
    /// The vCPUs to wake.
    vcpus: Arc<Vcpus<Kicker>>,
}

impl TimerLine for HvfTimerLine {
    fn set(&self, cpu: usize, level: bool) -> u8 {
        // The device holds its own lock here, and takes the GIC's after it;
        // nothing takes them the other way round.
        lock_or_recover(&self.portable.gic)
            .set_ppi_line(cpu, hvitime::INTID, level)
            .wake
    }

    fn wake(&self, mask: u8) {
        if self.vcpus.is_running() {
            self.vcpus.kicker().wake_mask(mask);
        }
    }
}

/// The portable guest's counter: `mach_absolute_time` less the virtual
/// timer offset every vCPU of the VM is given.
struct HvfCounter {
    offset: u64,
}

impl GuestCounter for HvfCounter {
    fn now(&self) -> u64 {
        // SAFETY: `mach_absolute_time` takes no arguments and cannot fail.
        unsafe { mach_absolute_time() }.wrapping_sub(self.offset)
    }
}

/// Where the guest's device lines go.
#[derive(Clone)]
enum Irqchip {
    /// Apple's in-kernel GICv3, on the native machine.
    InKernel(VmGic),
    /// The software GICv2, on the portable one.
    Soft(Arc<Portable>),
}

/// The portable profile's machine on this host: the software GICv2 and what
/// the vCPU threads share to drive it.
struct Portable {
    /// The guest's interrupt controller.
    gic: Mutex<Gicv2>,
    /// Where the guest finds the distributor and the CPU interface.
    layout: GicLayout,
    /// Host counter ticks to nanoseconds, as `(numer, denom)`.
    timebase: (u64, u64),
    /// Which vCPUs PSCI reports on: cpu0 from the start, a secondary from
    /// its `CPU_ON`.
    on: Vec<AtomicBool>,
    /// Why the boot was refused, when a vCPU thread refused it.
    refused: Mutex<Option<String>>,
}

/// The [`Kick`] implementation for Hypervisor.framework vCPUs.
///
/// It holds each vCPU's handle and the secondaries' `CPU_ON` mailboxes. A kick
/// is `hv_vcpus_exit`. It ends a run in progress, and one that reaches a vCPU
/// outside its run stays pending and ends its next run at once. A secondary
/// that waits for `CPU_ON` is in no run, so the stop also wakes its mailbox.
/// Under the portable profile a vCPU can also sleep in an emulated WFI, in no
/// run either, so every kick also wakes its [`Idle`].
struct Kicker {
    /// The VM the vCPUs belong to.
    vm: Vm,
    /// Each vCPU's handle indexed by vCPU id, `None` until its thread has
    /// created the vCPU and again once its registration is dropped.
    handles: Mutex<Vec<Option<VcpuHandle>>>,
    /// The `CPU_ON` mailboxes of the secondaries.
    secondaries: Vec<Secondary>,
    /// Each vCPU's emulated WFI under the portable profile; empty on the
    /// native machine, whose WFI waits inside the hypervisor.
    idle: Vec<Idle>,
}

impl Kicker {
    /// Returns a table for `count` vCPUs of `vm`, none of them registered,
    /// with an [`Idle`] for each when `emulated_wfi`.
    fn new(vm: Vm, count: u32, secondaries: Vec<Secondary>, emulated_wfi: bool) -> Self {
        let idle = if emulated_wfi { count } else { 0 };
        Self {
            vm,
            handles: Mutex::new((0..count).map(|_| None).collect()),
            secondaries,
            idle: (0..idle)
                .map(|_| Idle {
                    asleep: Mutex::new(false),
                    cv: Condvar::new(),
                })
                .collect(),
        }
    }

    /// Registers `vcpu`, which the calling thread created, as vCPU `cpu`.
    ///
    /// It also records the vCPU as the calling thread's own, so a kick from
    /// this thread leaves it out. The returned guard removes the entry when
    /// dropped, and must drop before the vCPU does.
    fn register(&self, cpu: u32, vcpu: &Vcpu) -> Registration<'_> {
        OWN_VCPU.with(|own| own.set(Some(vcpu.id())));
        OWN_CPU.with(|own| own.set(Some(cpu)));
        if let Some(slot) = lock_or_recover(&self.handles).get_mut(cpu as usize) {
            *slot = Some(vcpu.get_handle());
        }
        Registration { kicker: self, cpu }
    }

    /// Wakes vCPU `cpu` from an emulated WFI, if it sleeps in one.
    fn notify_idle(&self, cpu: usize) -> bool {
        let Some(idle) = self.idle.get(cpu) else {
            return false;
        };
        let asleep = lock_or_recover(&idle.asleep);
        if *asleep {
            idle.cv.notify_all();
        }
        *asleep
    }

    /// Makes every vCPU in `mask` but the calling thread's own see the
    /// interrupt the software GIC now has for it.
    ///
    /// One asleep in an emulated WFI is woken. Any other is kicked out of
    /// its run, or its next run ends at once; it then sets its IRQ line from
    /// the GIC at its next entry. The calling thread's own vCPU does that
    /// anyway.
    fn wake_mask(&self, mask: u8) {
        let own = OWN_CPU.with(std::cell::Cell::get);
        for cpu in 0..self.idle.len() {
            if mask & (1 << cpu) == 0 || own == Some(cpu as u32) || self.notify_idle(cpu) {
                continue;
            }
            if let Some(Some(handle)) = lock_or_recover(&self.handles).get(cpu) {
                let _ = self.vm.vcpus_exit(std::slice::from_ref(handle));
            }
        }
    }
}

/// A vCPU's entry in a [`Kicker`], removed when dropped.
///
/// A kick sends `hv_vcpus_exit` one list of handles, so a handle to a destroyed
/// vCPU in the table would fail the kick of every other vCPU in the list.
struct Registration<'a> {
    /// The table the entry is in.
    kicker: &'a Kicker,
    /// The vCPU id of the entry.
    cpu: u32,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Some(slot) = lock_or_recover(&self.kicker.handles).get_mut(self.cpu as usize) {
            *slot = None;
        }
    }
}

impl Kick for Kicker {
    fn kick(&self, cpu: u32) {
        self.notify_idle(cpu as usize);
        let own = OWN_VCPU.with(std::cell::Cell::get);
        if let Some(Some(handle)) = lock_or_recover(&self.handles).get(cpu as usize) {
            if Some(handle.id()) != own {
                let _ = self.vm.vcpus_exit(std::slice::from_ref(handle));
            }
        }
    }

    fn kick_all(&self) {
        for cpu in 0..self.idle.len() {
            self.notify_idle(cpu);
        }
        // A cancel a vCPU sends itself stays pending and ends its next run
        // before the guest ran, so a plugin that kicked from `safepoint` would
        // run again at once. The table stays locked through the kick, so no
        // vCPU in the list is destroyed before it.
        let own = OWN_VCPU.with(std::cell::Cell::get);
        let handles = lock_or_recover(&self.handles);
        let others: Vec<VcpuHandle> = handles
            .iter()
            .flatten()
            .filter(|handle| Some(handle.id()) != own)
            .cloned()
            .collect();
        let _ = self.vm.vcpus_exit(&others);
    }

    fn pending_start(&self, cpu: u32) -> Option<(u64, u64)> {
        // Read under the lock its thread takes the request under, so a
        // request is either still here or taken by a vCPU that has started.
        self.secondaries
            .get(cpu as usize)
            .and_then(|sec| *lock_or_recover(&sec.mbox))
    }

    fn kick_halted(&self) {
        for sec in self.secondaries.iter() {
            // The lock is taken so a secondary cannot be between its check of
            // the running flag and its wait when the notify lands.
            let _mbox = lock_or_recover(&sec.mbox);
            sec.cv.notify_all();
        }
    }
}

/// One tagged virtio-fs export, its dynamically assigned transport slot, and
/// the wake signal its dedicated worker thread (`run_fs_worker`) parks on.
#[derive(Clone)]
struct SharedFs {
    base: u64,
    intid: u32,
    dev: Arc<Mutex<VirtioFs>>,
    wake: Arc<FsWake>,
}

/// A virtio-fs device's coalescing wake signal, which its worker thread parks
/// on.
///
/// `service_fs` calls [`FsWake::wake`] when its inline drain leaves work. The
/// worker's [`FsWake::park`] checks a predicate under a `Condvar`, so a wake
/// that lands between the worker's last drain and its park is seen rather than
/// lost. `run_fs_worker` has the full argument.
struct FsWake {
    state: Mutex<FsWakeState>,
    ready: Condvar,
}

/// The flags behind [`FsWake`].
#[derive(Default)]
struct FsWakeState {
    /// A notify arrived since the worker last drained.
    woken: bool,
    /// The stop has been requested.
    stopped: bool,
}

impl FsWake {
    fn new() -> Self {
        Self {
            state: Mutex::new(FsWakeState::default()),
            ready: Condvar::new(),
        }
    }

    /// Signals the worker. Safe to call whether or not it is currently
    /// parked -- a signal that arrives mid-drain is simply picked up on the
    /// worker's next pass, never lost.
    fn wake(&self) {
        let mut state = lock_or_recover(&self.state);
        state.woken = true;
        self.ready.notify_one();
    }

    /// Requests that the worker exit at its next pass.
    fn stop(&self) {
        let mut state = lock_or_recover(&self.state);
        state.stopped = true;
        self.ready.notify_one();
    }

    /// Blocks until the next [`FsWake::wake`] or [`FsWake::stop`].
    ///
    /// Clears the wake flag on return and returns `false` once stopped. Must
    /// not be called with the virtio-fs device mutex held.
    fn park(&self) -> bool {
        let mut state = lock_or_recover(&self.state);
        while !state.woken && !state.stopped {
            state = self.ready.wait(state).unwrap();
        }
        state.woken = false;
        !state.stopped
    }
}

/// How many virtio-fs chains a vCPU services in its own exit before handing
/// the rest to the device's worker thread. Chosen so a single guest syscall's
/// worth of requests never pays a thread handoff, while a guest that has
/// queued deeply still gets serviced off the vCPU.
const FS_INLINE_BUDGET: u16 = 8;

/// Has the vCPU threads create their vCPUs one at a time, in index order.
///
/// The framework numbers vCPUs in the order they are created, and the
/// `hv_gic_state` blob a checkpoint carries may hold each one's GIC state by
/// that number. Created in index order, the number is the index on every
/// boot and every restore, which the export checks.
#[derive(Default)]
struct CreateOrder {
    /// The index of the vCPU whose turn it is.
    next: Mutex<u32>,
    /// Signals the end of a turn.
    turn: Condvar,
    /// How many vCPUs exist, each with its affinity set. A failed create
    /// ends its turn but is not counted, so a restore that waits for every
    /// vCPU to exist does not take a failure for the last one.
    created: AtomicU32,
}

impl CreateOrder {
    /// Waits until it is vCPU `cpu`'s turn, and returns false instead when
    /// `running` turns false first.
    fn wait_turn(&self, cpu: u32, running: impl Fn() -> bool) -> bool {
        let mut next = lock_or_recover(&self.next);
        while *next != cpu {
            if !running() {
                return false;
            }
            // The stop does not signal this condition variable, so the wait
            // is cut into slices.
            next = self
                .turn
                .wait_timeout(next, std::time::Duration::from_millis(50))
                .map_or_else(|e| e.into_inner().0, |(next, _)| next);
        }
        true
    }

    /// Ends the turn of the vCPU whose turn it is, created or not.
    fn done(&self) {
        *lock_or_recover(&self.next) += 1;
        self.turn.notify_all();
    }

    /// Counts one more vCPU as existing, once its thread has set it up.
    fn mark_created(&self) {
        self.created.fetch_add(1, Ordering::SeqCst);
    }

    /// Returns how many vCPUs exist.
    fn created(&self) -> u32 {
        self.created.load(Ordering::SeqCst)
    }
}

/// What the vCPU threads of a restored VM need to know.
struct Restoring {
    /// Per vCPU, whether it runs as soon as the guest resumes, as one that
    /// ran at the capture does, instead of waiting for its `CPU_ON`.
    runs: Vec<bool>,
    /// The native guest's counter, which goes on from the capture. A
    /// portable guest's counter offset is fixed when its vCPUs are created.
    clock: Option<hvf_state::RestoreClock>,
    /// The source's `MIDR_EL1`, which vCPU 0 compares with its own.
    midr: Option<u64>,
    /// Why a vCPU thread ended the restore, when one did.
    failure: Mutex<Option<String>>,
    /// The portable guest's `hvi-time` at the capture, which the first
    /// vCPU to enter the guest after `resume` publishes.
    hvitime: Option<PendingPublish>,
}

/// State shared across all vCPU threads.
#[derive(Clone)]
struct Shared {
    vm: Vm,
    /// Where the device lines go, and on the native machine the GIC whose
    /// state a checkpoint reads.
    irqchip: Irqchip,
    /// The order the vCPU threads create their vCPUs in.
    create_order: Arc<CreateOrder>,
    /// What a restore needs of the vCPU threads, when this VM is one.
    restoring: Option<Arc<Restoring>>,
    /// The guest's RAM, virtio devices and vCPUs.
    guest: Arc<Guest<Kicker>>,
    pl011: Arc<Mutex<Pl011>>,
    fs: Vec<SharedFs>,
    kernel_addr: u64,
    dtb_addr: u64,
    /// Whoever is watching this guest, if anyone.
    plugin: Option<Arc<dyn Plugin>>,
    /// The machine profile, which the boot vCPU completes with `MIDR_EL1`.
    profile: Arc<ProfileCell>,
    /// The portable profile's machine, or `None` on the native one.
    portable: Option<Arc<Portable>>,
    /// The portable guest's `hvi-time`, or `None` on the native machine.
    hvitime: Option<Arc<HviTime>>,
    /// The virtual timer offset of every portable vCPU, so that each reads
    /// the one counter the `hvi-time` page maps.
    vtimer_offset: u64,
    /// The record of the guest's writes to RAM a live move keeps, whose
    /// faults each vCPU serves on its own thread.
    write_log: Arc<HvfWriteLog>,
}

/// The feature registers the profile records, by the name it records them
/// under.
///
/// They are read from a default vCPU configuration, the one every vCPU here is
/// created with, so no vCPU has to exist yet.
const FEATURE_REGS: [(&str, FeatureReg); 14] = [
    ("ID_AA64DFR0_EL1", FeatureReg::ID_AA64DFR0_EL1),
    ("ID_AA64DFR1_EL1", FeatureReg::ID_AA64DFR1_EL1),
    ("ID_AA64ISAR0_EL1", FeatureReg::ID_AA64ISAR0_EL1),
    ("ID_AA64ISAR1_EL1", FeatureReg::ID_AA64ISAR1_EL1),
    ("ID_AA64MMFR0_EL1", FeatureReg::ID_AA64MMFR0_EL1),
    ("ID_AA64MMFR1_EL1", FeatureReg::ID_AA64MMFR1_EL1),
    ("ID_AA64MMFR2_EL1", FeatureReg::ID_AA64MMFR2_EL1),
    ("ID_AA64PFR0_EL1", FeatureReg::ID_AA64PFR0_EL1),
    ("ID_AA64PFR1_EL1", FeatureReg::ID_AA64PFR1_EL1),
    ("ID_AA64SMFR0_EL1", FeatureReg::ID_AA64SMFR0_EL1),
    ("ID_AA64ZFR0_EL1", FeatureReg::ID_AA64ZFR0_EL1),
    ("CTR_EL0", FeatureReg::CTR_EL0),
    ("CLIDR_EL1", FeatureReg::CLIDR_EL1),
    ("DCZID_EL0", FeatureReg::DCZID_EL0),
];

/// Returns the machine profile of this boot, complete but for `MIDR_EL1`,
/// which only a vCPU's own thread can read.
fn boot_profile(cfg: &BootConfig, machine: &Arm64Machine<'_>, fs: &[SharedFs]) -> MachineProfile {
    let mut p = arm64_profile::profile("hvf", machine);
    fill_hvf(&mut p);
    if cfg.profile == MachineProfileKind::PortableArm64V1 {
        fill_portable_hvf(&mut p);
    }
    for (fs, share) in fs.iter().zip(&cfg.fs_shares) {
        let mut entry = device("virtio-fs", fs.base, Some(fs.intid), None);
        entry.mode = Some(if share.mode.writable() { "rw" } else { "ro" }.to_string());
        p.devices.push(entry);
    }
    p.agent_sock = cfg.agent_sock.is_some();
    p.fs_shares = u32::try_from(cfg.fs_shares.len()).unwrap_or(u32::MAX);
    p.disk_base_sha256.clone_from(&cfg.disk_base_sha256);
    p
}

/// Fills what only this backend reads into `p`: the ID registers and the
/// PSCI version.
fn fill_hvf(p: &mut MachineProfile) {
    let config = VcpuConfig::new();
    for (name, reg) in FEATURE_REGS {
        // A register this macOS does not serve is recorded as unread, which
        // the compatibility check refuses on either side.
        let value = config
            .get_feature_reg(reg)
            .map_or_else(|_| UNKNOWN.to_string(), hex);
        p.cpu.id_regs.insert(name.to_string(), value);
    }
    // `service_psci` answers PSCI_VERSION with 1.0.
    p.firmware.psci_version = Some("1.0".to_string());
}

/// Fills what the portable profile changes in `p`, a profile [`fill_hvf`]
/// filled: the ID registers the guest reads and the PSCI version.
fn fill_portable_hvf(p: &mut MachineProfile) {
    // The guest reads the baseline, which each vCPU writes and checks before
    // its first instruction. MIDR_EL1 is the profile's ident.
    for (name, value) in portable::BASELINE.into_iter().skip(1) {
        p.cpu.id_regs.insert(name.to_string(), hex(value));
    }
    // `service_firmware` answers PSCI_VERSION with 1.1.
    p.firmware.psci_version = Some("1.1".to_string());
}

/// What the HVF restore loads.
const RESTORER: Restorer = Restorer {
    arch: GuestArch::Aarch64,
    backend: "hvf",
    sources: &["hvf"],
    profiles: &["native"],
    irq_kinds: &["hv-gic-v3"],
    timer_kinds: &["arch-timer"],
    adjunct: Some(HVF_GIC_STATE),
    capabilities: &[HVF_GIC_STATE_CAPABILITY],
};

/// What the HVF restore of a portable guest loads, from either backend.
const RESTORER_PORTABLE: Restorer = restore::portable("hvf");

/// Resumes the checkpoint bundle `cfg` names in this process, and runs it
/// until the guest powers off or a client stops it.
///
/// It refuses with every reason it finds before it creates anything: a
/// bundle that does not hold all a restore loads, flags that do not match
/// the guest's devices, and a machine profile this host does not match (but
/// `MIDR_EL1`, which vCPU 0 compares as soon as it exists). It then builds
/// the VM and its GIC as a boot does, copies guest RAM from the bundle,
/// rebuilds the devices from their state over the host resources the flags
/// name, and confines the process. The vCPU threads load the bundle's state
/// in the steps of `checkpoint::restore`, the device lines are
/// driven again, and the guest waits restored-paused on the control socket
/// for `resume`.
///
/// # Errors
///
/// Errors on any refusal, on a host resource that cannot be opened, and on
/// a vCPU that cannot load its state, after stopping whatever had started.
// One function so the order of the steps, which the hypervisor and the
// confinement constrain, reads top to bottom.
#[allow(clippy::too_many_lines)]
pub fn restore(cfg: RestoreConfig) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    let mut opened = restore::open_config(&cfg).map_err(|e| format!("{}: {e}", cfg.from))?;
    let source_profile = opened.profile().clone();
    let source = &source_profile;
    let is_portable = source.profile == MachineProfileKind::PortableArm64V1.name();
    let can = if is_portable {
        &RESTORER_PORTABLE
    } else {
        &RESTORER
    };
    let mut why = restore::refusals(&opened, &cfg, can);
    // A machine this restore does not rebuild is refused for that alone:
    // set against the native machine below, every part of its profile
    // would read as a difference.
    if !can.profiles.contains(&source.profile.as_str()) {
        return Err(Box::new(Refused(why)));
    }
    let ram_size = match source.ram_regions.as_slice() {
        [region] if region.gpa == RAM_BASE => Some(region.size),
        _ => {
            why.push(format!(
                "profile.json: the hvf guest has one RAM region at {RAM_BASE:#x}, not {:?}",
                source.ram_regions
            ));
            None
        }
    };
    let max = applevisor::prelude::Vcpu::get_max_count().unwrap_or(0);
    if source.vcpus > max {
        why.push(format!(
            "profile.json: {} vCPUs, and this host's VMs take {max}",
            source.vcpus
        ));
    }
    let runs: Vec<bool> = opened
        .plan
        .vcpus
        .iter()
        .map(|v| matches!(v, VcpuState::Aarch64(v) if v.power == Power::On))
        .collect();
    if runs.first() != Some(&true) {
        why.push("cpu.json: vCPU 0 is not on".to_string());
    }
    let gic = gic_layout(is_portable, source.vcpus)?;
    let present = fdt::VirtioDevices {
        blk: cfg.disk.is_some(),
        net: cfg.net || cfg.net_gateway.is_some(),
        vsock: cfg.agent_sock.is_some(),
        fs_count: 0,
        // The native guest has the timer's interrupts, the portable one
        // hvi-time. Only the profile's device list reads these.
        timer: ArchTimer::Interrupts,
        hvi_time: is_portable,
    };
    let net_mode = if cfg.net_gateway.is_some() {
        Some("gateway")
    } else if cfg.net {
        Some("stub")
    } else {
        None
    };
    let kind = if is_portable {
        MachineProfileKind::PortableArm64V1
    } else {
        MachineProfileKind::Native
    };
    let mut local = arm64_profile::restored("hvf", &gic, present, net_mode, source, kind);
    fill_hvf(&mut local);
    if is_portable {
        fill_portable_hvf(&mut local);
        // Before any vCPU exists, as at boot.
        if let Err(e) = check_baseline_on_host() {
            why.push(format!("host: {e}"));
        }
    }
    local.agent_sock = cfg.agent_sock.is_some();
    // vCPU 0 reads this host's MIDR_EL1 and compares it once it exists;
    // until then the profile carries the source's, so the comparison here
    // covers everything else.
    local.cpu.ident.clone_from(&source.cpu.ident);
    why.extend(restore::profile_refusals(source, &local));
    let Some(ram_size) = ram_size.filter(|_| why.is_empty()) else {
        return Err(Box::new(Refused(why)));
    };
    let midr = source
        .cpu
        .ident
        .as_deref()
        .and_then(|ident| u64::from_str_radix(ident.trim_start_matches("0x"), 16).ok());
    // The native guest's counter goes on from the capture once it
    // resumes; the portable guest's is set when its vCPUs are created, so
    // that it reads no less than at the capture, and hvi-time's page is
    // published at the resume.
    let (clock, hvitime_state, vtimer_offset) = match &opened.plan.platform.timer {
        TimerState::ArchTimer(timer) if !is_portable => (
            Some(hvf_state::RestoreClock::new(timer.counter_at_capture)),
            None,
            0,
        ),
        TimerState::HviTime(state) if is_portable => {
            let target = state.counter_target(crate::checkpoint::profile::counter_freq_hz());
            (
                None,
                Some((**state).clone()),
                hvf_state::host_counter().wrapping_sub(target),
            )
        }
        other => {
            return Err(format!(
                "platform.json: a {} counter for a {} guest",
                other.kind(),
                source.profile
            )
            .into())
        }
    };
    let num_cpus = source.vcpus;
    eprintln!(
        "{LOG_PREFIX} restoring {} ({} vCPU(s), {} MiB, captured by {} at epoch {})",
        cfg.from,
        num_cpus,
        ram_size >> 20,
        opened.session.sandbox_id,
        opened.session.epoch
    );

    let portable = is_portable.then(|| {
        Arc::new(Portable {
            gic: Mutex::new(Gicv2::new(num_cpus)),
            layout: gic,
            timebase: host_timebase(),
            // A vCPU whose CPU_ON was pending reports on, as it did.
            on: opened
                .plan
                .vcpus
                .iter()
                .map(|v| {
                    AtomicBool::new(matches!(v, VcpuState::Aarch64(v) if v.power != Power::Off))
                })
                .collect(),
            refused: Mutex::new(None),
        })
    });
    let (vm, irqchip) = create_vm(&gic, portable.clone())?;
    // A bundle directory's ram.bin is hashed here, as it is copied, and
    // refused like the open refuses a component: named with the bundle. A
    // stream's RAM was filled and checked as it was read.
    let (shared_ram, ram) = opened
        .guest_ram()
        .map_err(|e| format!("{}: {e}", cfg.from))?;
    map_guest_ram(&ram)?;

    // The devices, from their state, over this host's resources.
    let rebuild::Devices {
        block: virtio,
        net,
        net_reader,
        vsock,
        pl011,
    } = rebuild::devices(&opened, &cfg, &ram)?;
    let levels = opened.devices.irq_levels;
    let bridge = match (&cfg.agent_sock, &vsock) {
        (Some(path), Some(dev)) => {
            Some(VsockBridge::bind(path, Arc::clone(dev), Arc::clone(&ram))?)
        }
        _ => None,
    };
    let stop_source = StopSource::new()?;
    let sandbox_id = cfg
        .sandbox_id
        .clone()
        .unwrap_or_else(|| opened.session.sandbox_id.clone());
    let emitter = Emitter::new(cfg.events.as_deref(), &sandbox_id)?;
    let profile = Arc::new(ProfileCell::new(local, cfg.profile_out.as_deref())?);

    let secondaries: Vec<Secondary> = opened
        .plan
        .vcpus
        .iter()
        .map(|state| Secondary {
            mbox: Mutex::new(match state {
                VcpuState::Aarch64(Aarch64Vcpu {
                    power: Power::PendingOn { entry, ctx },
                    ..
                }) => Some((entry.0, ctx.0)),
                _ => None,
            }),
            cv: Condvar::new(),
        })
        .collect();
    let kicker = Kicker::new(vm.clone(), num_cpus, secondaries, is_portable);
    let vcpus = Arc::new(Vcpus::new(num_cpus, kicker, StopHandle::new_pair()?.0));
    let hvitime = match &portable {
        Some(p) => Some(attach_hvitime(p, &vcpus, num_cpus, vtimer_offset)?),
        None => None,
    };
    let write_log = Arc::new(HvfWriteLog::new(&ram.regions()));
    let shared = Shared {
        vm: vm.clone(),
        irqchip,
        create_order: Arc::default(),
        restoring: Some(Arc::new(Restoring {
            runs,
            clock,
            midr,
            failure: Mutex::new(None),
            hvitime: hvitime_state.map(PendingPublish::new),
        })),
        guest: Arc::new(Guest {
            arch: GuestArch::Aarch64,
            sandbox_id,
            ram,
            shared_ram,
            ledger: Arc::new(Mutex::new(emitter)),
            block: virtio,
            net,
            vsock,
            vcpus,
            write_log: Some(Arc::clone(&write_log) as Arc<dyn GuestWriteLog>),
            plugin_threads: PluginThreads::new(),
        }),
        pl011: Arc::new(Mutex::new(pl011)),
        fs: Vec::new(),
        kernel_addr: 0,
        dtb_addr: 0,
        plugin: None,
        profile,
        portable,
        hvitime,
        vtimer_offset,
        write_log,
    };
    connect_lines(&shared);
    let control = bind_control(
        Some(&cfg.control_sock),
        cfg.checkpoint_root.as_deref(),
        cfg.disk.clone(),
        &shared,
    )?
    .map(ControlSocket::restored);
    let _raw = terminal::RawTerm::enable();
    confine(cfg.sandbox, &[], control.as_ref())?;
    let io = IoStart {
        stop_source,
        bridge,
        net_reader,
        control,
        plugin_threads: Vec::new(),
        sandbox: cfg.sandbox,
    };
    let restore = RestoreRun {
        plan: Arc::clone(&opened.plan),
        irq_levels: levels,
    };
    let stop = run(shared, num_cpus, io, Some(restore))?;
    Ok(stop)
}

/// Boots `cfg` on Hypervisor.framework, as [`crate::boot`] describes.
pub(crate) fn boot(mut cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    cfg.validate()?;
    // Refuse a kernel that is not a flat Image before the VM, its RAM, the
    // devices and the event ledger exist.
    loader::LoadedKernel::from_header(&cfg.kernel)?;
    // And exports that contradict each other, for the same reason: this is a
    // statement about the configuration, decidable before anything is built.
    check_export_overlap(&cfg.fs_shares)?;
    let num_cpus = cfg.vcpus.max(1);
    let is_portable = cfg.profile == MachineProfileKind::PortableArm64V1;

    let gic = gic_layout(is_portable, num_cpus)?;
    if is_portable {
        eprintln!(
            "{LOG_PREFIX} {num_cpus} vCPU(s)  profile {}  software GICv2: GICD {:#x}+{:#x}  GICC {:#x}+{:#x}  UART {:#x}",
            cfg.profile.name(),
            gic.gicd_base,
            gic.gicd_size,
            gic.gicr_base,
            gic.gicr_size,
            UART_BASE
        );
    } else {
        eprintln!(
            "{LOG_PREFIX} {num_cpus} vCPU(s)  GICD {:#x}+{:#x}  GICR {:#x}+{:#x}  UART {:#x}",
            gic.gicd_base, gic.gicd_size, gic.gicr_base, gic.gicr_size, UART_BASE
        );
    }
    // The native machine's lines go to the in-kernel GIC. The portable one
    // creates none: its GIC is the model in `portable`.
    let portable = is_portable.then(|| {
        Arc::new(Portable {
            gic: Mutex::new(Gicv2::new(num_cpus)),
            layout: gic,
            timebase: host_timebase(),
            on: (0..num_cpus).map(|cpu| AtomicBool::new(cpu == 0)).collect(),
            refused: Mutex::new(None),
        })
    });
    let (vm, irqchip) = create_vm(&gic, portable.clone())?;
    if is_portable {
        // Before any vCPU exists, so a host that cannot back the baseline
        // fails the boot with every missing field named.
        check_baseline_on_host()?;
    }
    let (shared_ram, ram) = map_ram(cfg.mem_bytes)?;
    let gic_end = gic.gicr_base.saturating_add(gic.gicr_size);
    // Every portable vCPU gets one virtual timer offset, taken now, so that
    // they all read one counter, which starts near 0 as a KVM guest's does.
    // SAFETY: `mach_absolute_time` takes no arguments and cannot fail.
    let vtimer_offset = if is_portable {
        unsafe { mach_absolute_time() }
    } else {
        0
    };

    let virtio = match &cfg.disk {
        Some(path) => {
            eprintln!("{LOG_PREFIX} virtio-blk: {path}");
            Some(Arc::new(Mutex::new(VirtioBlk::open_with_base(
                path,
                cfg.disk_base_sha256.is_some(),
                cfg.disk_written.as_deref(),
            )?)))
        }
        None => None,
    };
    // virtio-net: gateway relay (real egress) when a gateway socket is given,
    // else the built-in user-space stack. `net_reader` carries the gateway read
    // side to the RX reader thread, spawned once the shared state exists.
    //
    // Tap attach needs /dev/net/tun, which macOS does not have. Refusing beats
    // silently booting on another backend: a guest on the wrong network is
    // indistinguishable from success from the outside.
    if let Some(ifname) = &cfg.net_tap {
        return Err(
            format!("--net-tap {ifname}: no /dev/net/tun on macOS; use --net-gateway").into(),
        );
    }
    let mut net_reader: Option<std::os::unix::net::UnixStream> = None;
    let net_dev = if let Some(sock) = &cfg.net_gateway {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(stream) => match stream.try_clone() {
                Ok(reader) => {
                    eprintln!("{LOG_PREFIX} virtio-net: gvisor-tap gateway relay via {sock} (guest 10.87.0.2, gw/DNS 10.87.0.1)");
                    net_reader = Some(reader);
                    Some(VirtioNet::with_gateway(stream))
                }
                Err(e) => {
                    eprintln!(
                        "{LOG_PREFIX} WARNING: cannot clone gateway socket ({e}); net disabled"
                    );
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "{LOG_PREFIX} WARNING: gateway {sock} unreachable ({e}); falling back to the {}",
                    net::stub_stack_line()
                );
                Some(VirtioNet::new())
            }
        }
    } else if cfg.net {
        eprintln!("{LOG_PREFIX} virtio-net: {}", net::stub_stack_line());
        Some(VirtioNet::new())
    } else {
        None
    };

    let net = net::share(net_dev, cfg.net_mac);

    let vsock = cfg.agent_sock.as_ref().map(|sock| {
        eprintln!("{LOG_PREFIX} virtio-vsock: agent bridge on {sock} (guest cid 3, port 1024)");
        Arc::new(Mutex::new(VirtioVsock::new()))
    });
    // Bind before Seatbelt is installed. Accepting on this already-open
    // listener remains allowed afterwards; acquiring a new socket does not.
    let bridge = match (&cfg.agent_sock, &vsock) {
        (Some(path), Some(dev)) => {
            Some(VsockBridge::bind(path, Arc::clone(dev), Arc::clone(&ram))?)
        }
        _ => None,
    };
    // The stop source's socket pair is created before Seatbelt for the same
    // reason.
    let stop_source = StopSource::new()?;
    let mut fs = Vec::with_capacity(cfg.fs_shares.len());
    let mut fs_access = Vec::with_capacity(cfg.fs_shares.len());
    let mut fs_tags = std::collections::HashSet::new();
    for (index, share) in cfg.fs_shares.iter().enumerate() {
        if !fs_tags.insert(share.tag.as_str()) {
            return Err(format!("duplicate virtio-fs tag {:?}", share.tag).into());
        }
        let base = virtio_fs_base(index).ok_or("too many virtio-fs devices")?;
        let spi = virtio_fs_spi(index).ok_or("too many virtio-fs devices")?;
        let end = base
            .checked_add(VIRTIO_SIZE)
            .ok_or("virtio-fs MMIO address overflow")?;
        // Same two bounds as the fixed windows above; these move with the
        // share count, so they are checked per share.
        if base < gic_end || end > DEVICE_WINDOW_END {
            return Err(format!(
                "virtio-fs device {index} at {base:#x}..{end:#x} does not fit \
                 between the GIC (ends {gic_end:#x}) and {DEVICE_WINDOW_END:#x}"
            )
            .into());
        }
        let root = std::fs::canonicalize(&share.path)?;
        let access = if share.mode.writable() {
            "read-write"
        } else {
            "read-only"
        };
        // Raise the descriptor limit before the first share exists, and say
        // what we got.
        //
        // virtio-fs pins one host fd per open guest handle, so the guest's
        // concurrency is spent out of this process's table. macOS gives a
        // process launched outside a terminal 256, which a build inside the
        // guest exhausts without trying -- and what the guest then saw was
        // "Input/output error" on random unrelated files, because every
        // unmapped host errno was reported as EIO.
        //
        // Logging the number is deliberate and unconditional: diagnosing this
        // from the guest side took a session of guessing, and one line here
        // would have ended it in a single run.
        if index == 0 {
            match fdlimit::raise_open_file_limit() {
                Ok(limit) => eprintln!("{LOG_PREFIX} open-file limit: {limit}"),
                Err(e) => eprintln!(
                    "{LOG_PREFIX} open-file limit: could not raise it ({e}); \
                     a busy guest may see EMFILE as I/O errors"
                ),
            }
        }
        eprintln!(
            "{LOG_PREFIX} virtio-fs[{index}]: {} as {:?} ({access})",
            root.display(),
            share.tag
        );
        fs_access.push((root.clone(), share.mode.writable()));
        fs.push(SharedFs {
            base,
            intid: 32 + spi,
            dev: Arc::new(Mutex::new(VirtioFs::new(
                root,
                &share.tag,
                share.mode.writable(),
                share.cache,
            )?)),
            wake: Arc::new(FsWake::new()),
        });
    }
    let has_blk = virtio.is_some();
    let has_net = net.is_some();
    let has_vsock = vsock.is_some();
    // The portable guest's devicetree comes from the same inputs on every
    // backend: the GICv2, the kernel arguments that keep it off what its
    // baseline hides, `/timer` without interrupts and `hvi-time`.
    let (gic, cmdline, fdt_devices) = if is_portable {
        let dt = portable::devicetree(&cfg, num_cpus, has_blk, has_net, has_vsock)?;
        (dt.gic, dt.cmdline, dt.devices)
    } else {
        let devices = fdt::VirtioDevices {
            blk: has_blk,
            net: has_net,
            vsock: has_vsock,
            fs_count: fs.len(),
            timer: ArchTimer::Interrupts,
            hvi_time: false,
        };
        (gic, cfg.cmdline.clone(), devices)
    };

    let emitter = Emitter::new(cfg.events.as_deref(), &cfg.sandbox_id)?;
    if emitter.enabled() {
        eprintln!(
            "{LOG_PREFIX} event ledger: {}",
            cfg.events.as_deref().unwrap_or("")
        );
    }

    let layout = loader::Payload {
        kernel: &cfg.kernel,
        initramfs: cfg.initramfs.as_deref(),
        cmdline: &cmdline,
    }
    .load(ram.memory(), cfg.mem_bytes, &gic, num_cpus, fdt_devices)?;

    // The profile file is created here, before Seatbelt, and written by the
    // boot vCPU once it has read MIDR_EL1.
    let machine = Arm64Machine {
        gic: &gic,
        layout: &layout,
        vcpus: num_cpus,
        cmdline: &cmdline,
        devices: fdt_devices,
        net_mode: match (&net, &net_reader) {
            (Some(_), Some(_)) => Some("gateway"),
            (Some(_), None) => Some("stub"),
            (None, _) => None,
        },
        ram_regions: ram.regions(),
        profile: cfg.profile,
    };
    let profile = Arc::new(ProfileCell::new(
        boot_profile(&cfg, &machine, &fs),
        cfg.profile_out.as_deref(),
    )?);

    let secondaries: Vec<Secondary> = (0..num_cpus)
        .map(|_| Secondary {
            mbox: Mutex::new(None),
            cv: Condvar::new(),
        })
        .collect();
    let kicker = Kicker::new(vm.clone(), num_cpus, secondaries, is_portable);
    let vcpus = Arc::new(Vcpus::new(num_cpus, kicker, cfg.take_stop_handle()?));

    // The portable guest's clock and timers.
    let hvitime = match &portable {
        Some(p) => Some(attach_hvitime(p, &vcpus, num_cpus, vtimer_offset)?),
        None => None,
    };
    let write_log = Arc::new(HvfWriteLog::new(&ram.regions()));

    let shared = Shared {
        vm: vm.clone(),
        irqchip,
        create_order: Arc::default(),
        restoring: None,
        guest: Arc::new(Guest {
            arch: GuestArch::Aarch64,
            sandbox_id: cfg.sandbox_id.clone(),
            ram,
            shared_ram,
            ledger: Arc::new(Mutex::new(emitter)),
            block: virtio,
            net,
            vsock,
            vcpus,
            write_log: Some(Arc::clone(&write_log) as Arc<dyn GuestWriteLog>),
            plugin_threads: PluginThreads::new(),
        }),
        pl011: Arc::new(Mutex::new(Pl011::new())),
        fs,
        kernel_addr: layout.kernel_addr,
        dtb_addr: layout.dtb_addr,
        plugin: cfg.plugin.clone(),
        profile,
        portable,
        hvitime,
        vtimer_offset,
        write_log,
    };

    connect_lines(&shared);

    // Bound before Seatbelt for the same reason as the agent socket.
    let control = bind_control(
        cfg.control_sock.as_deref(),
        cfg.checkpoint_root.as_deref(),
        cfg.disk.clone(),
        &shared,
    )?;

    // Hand the plugin the guest before any vCPU runs, so nothing happens
    // between the first instruction and the attach.
    let plugin_threads = shared.guest.attach(shared.plugin.as_ref())?;

    // A binary's stop signals get their handlers, and the thread that receives
    // them starts, before the terminal goes into raw mode, so a first stop
    // signal stops the run rather than ending the process with the terminal
    // raw. The sandbox below confines the whole process, that thread included.
    crate::signal::start_stop_signal_thread()?;

    let _raw = terminal::RawTerm::enable();

    confine(cfg.sandbox, &fs_access, control.as_ref())?;

    let io = IoStart {
        stop_source,
        bridge,
        net_reader,
        control,
        plugin_threads,
        sandbox: cfg.sandbox,
    };
    run(shared, num_cpus, io, None)
}

/// Creates the portable guest's `hvi-time` on `p`'s software GIC, with
/// the guest counter `mach_absolute_time` less `offset`, and maps its page
/// into the VM read-only: the guest reads it without an exit and cannot
/// write it.
///
/// # Errors
///
/// Errors when the device cannot be created or its page mapped.
fn attach_hvitime(
    p: &Arc<Portable>,
    vcpus: &Arc<Vcpus<Kicker>>,
    num_cpus: u32,
    offset: u64,
) -> Result<Arc<HviTime>, Box<dyn std::error::Error + Send + Sync>> {
    let device = Arc::new(HviTime::new(
        num_cpus as usize,
        crate::checkpoint::profile::counter_freq_hz(),
        Box::new(HvfCounter { offset }),
        Box::new(HvfTimerLine {
            portable: Arc::clone(p),
            vcpus: Arc::clone(vcpus),
        }),
    )?);
    // SAFETY: the page is a live, page-aligned mapping of
    // `PAGE_SIZE` bytes that lives as long as `device`, which
    // outlives the VM.
    let ret = unsafe {
        applevisor_sys::hv_vm_map(
            device.page().host_ptr().cast::<std::ffi::c_void>(),
            HVI_TIME_PAGE_BASE,
            hvitime::PAGE_SIZE as usize,
            applevisor_sys::HV_MEMORY_READ,
        )
    };
    if ret != 0 {
        return Err(format!(
            "hv_vm_map(hvi-time page -> {HVI_TIME_PAGE_BASE:#x}, read-only) failed: {ret:#x}"
        )
        .into());
    }
    eprintln!(
        "{LOG_PREFIX} hvi-time: page {HVI_TIME_PAGE_BASE:#x}+{:#x} (read-only), timers {HVI_TIME_TIMERS_BASE:#x}+{:#x}, PPI {} (INTID {}), counter {} Hz",
        hvitime::PAGE_SIZE,
        hvitime::TIMERS_SIZE,
        hvitime::PPI,
        hvitime::INTID,
        device.counter_freq_hz()
    );
    if trace::enable_from_env() {
        eprintln!("{LOG_PREFIX} hvi-time: HVI_TIME_TRACE on, exits counted");
    }
    Ok(device)
}

/// Returns the GIC's placement once every fixed device window is checked to
/// clear it: on the native machine the in-kernel GICv3's, with sizes from
/// the framework so the devicetree matches `hv_gic`, and under the portable
/// profile the software GICv2's, at QEMU virt's v2 addresses.
fn gic_layout(
    portable: bool,
    num_cpus: u32,
) -> Result<GicLayout, Box<dyn std::error::Error + Send + Sync>> {
    let gic = if portable {
        GicLayout::for_vcpus(GicVersion::V2, num_cpus)?
    } else {
        let gicd_align = GicConfig::get_distributor_base_alignment()? as u64;
        let gicr_align = GicConfig::get_redistributor_base_alignment()? as u64;
        GicLayout {
            // Apple's hv_gic is a GICv3; unlike KVM there is nothing to
            // negotiate.
            version: GicVersion::V3,
            gicd_base: align_down(GicLayout::QEMU_VIRT.gicd_base, gicd_align),
            gicd_size: GicConfig::get_distributor_size()? as u64,
            gicr_base: align_down(GicLayout::QEMU_VIRT.gicr_base, gicr_align),
            gicr_size: GicConfig::get_redistributor_region_size()? as u64,
        }
    };
    // Every device window has to clear the GIC, and only here is it known how
    // much GIC there is: the framework sizes the redistributor region, and it
    // is far larger than QEMU's. The fixed windows are checked here, and the
    // virtio-fs ones in `boot` as each share is placed, because those climb
    // with the share count.
    let gic_end = gic.gicr_base.saturating_add(gic.gicr_size);
    let mut fixed = vec![
        ("UART", UART_BASE, UART_SIZE),
        ("virtio-blk", VIRTIO_BASE, VIRTIO_SIZE),
        ("virtio-net", VIRTIO_NET_BASE, VIRTIO_SIZE),
        ("virtio-vsock", VIRTIO_VSOCK_BASE, VIRTIO_SIZE),
    ];
    if portable {
        fixed.push(("hvi-time page", HVI_TIME_PAGE_BASE, hvitime::PAGE_SIZE));
        fixed.push((
            "hvi-time timers",
            HVI_TIME_TIMERS_BASE,
            hvitime::TIMERS_SIZE,
        ));
    }
    for (name, base, size) in fixed {
        let end = base.saturating_add(size);
        if base < gic_end || end > DEVICE_WINDOW_END {
            return Err(format!(
                "{name} at {base:#x}..{end:#x} does not fit between the GIC \
                 (ends {gic_end:#x}) and {DEVICE_WINDOW_END:#x}"
            )
            .into());
        }
    }
    Ok(gic)
}

/// Creates the VM: on the native machine with its GICv3 at `gic`, and with
/// no GIC when `portable` is given, whose model is then the guest's.
fn create_vm(
    gic: &GicLayout,
    portable: Option<Arc<Portable>>,
) -> Result<(Vm, Irqchip), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(portable) = portable {
        return Ok((VirtualMachine::new()?, Irqchip::Soft(portable)));
    }
    let mut gic_config = GicConfig::new();
    gic_config.set_distributor_base(gic.gicd_base)?;
    gic_config.set_redistributor_base(gic.gicr_base)?;
    let vm_gic = VirtualMachine::with_gic(VirtualMachineConfig::new(), gic_config)?;
    Ok((Vm::from(vm_gic.clone()), Irqchip::InKernel(vm_gic)))
}

/// Allocates `mem_bytes` of guest RAM and maps it at `RAM_BASE`.
fn map_ram(
    mem_bytes: u64,
) -> Result<(SharedRam, Arc<GuestRam>), Box<dyn std::error::Error + Send + Sync>> {
    // Guest RAM: one region mapped at RAM_BASE, backed by a shareable object
    // rather than allocated by applevisor, so an out-of-process plugin can
    // map the same pages. applevisor's memory_create uses hv_vm_allocate,
    // which hands back a pointer with no nameable backing object; hv_vm_map
    // accepts any page-aligned host pointer, so the guest gets the mapping
    // `GuestRam` made of the object. This is the path `hvi smoke --shm`
    // exercises.
    let shared_ram = SharedRam::new(mem_bytes as usize)?;
    let ram = Arc::new(GuestRam::new(
        &shared_ram,
        &[shared_ram.region_at(RAM_BASE)],
    )?);
    map_guest_ram(&ram)?;
    Ok((shared_ram, ram))
}

/// Maps every region of `ram` into the VM at its address, read, write and
/// execute.
fn map_guest_ram(ram: &GuestRam) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for region in ram.memory().iter() {
        let ipa = region.start_addr().raw_value();
        // SAFETY: the region is a live, page-aligned mapping of `len()` bytes
        // that lives as long as `ram`, which outlives the VM.
        let ret = unsafe {
            applevisor_sys::hv_vm_map(
                region.as_ptr().cast::<std::ffi::c_void>(),
                ipa,
                region.len() as usize,
                applevisor_sys::HV_MEMORY_READ
                    | applevisor_sys::HV_MEMORY_WRITE
                    | applevisor_sys::HV_MEMORY_EXEC,
            )
        };
        if ret != 0 {
            return Err(format!("hv_vm_map(guest RAM -> {ipa:#x}) failed: {ret:#x}").into());
        }
    }
    Ok(())
}

/// The most times in a row one vCPU may fault on the same RAM granule
/// before hvi ends the run: the log made it writable after the first, so a
/// granule that keeps faulting is one the framework will not unprotect, and
/// re-running it would spin for ever.
const RAM_FAULT_REPEATS: u32 = 64;

/// The RAM faults one vCPU took in a row at one granule, with no other
/// exit between them.
#[derive(Default)]
struct RamFaults {
    /// The granule of the last fault.
    last: Option<u64>,
    /// How many faults in a row were there after the first.
    repeats: u32,
}

impl RamFaults {
    /// Counts a fault in the granule at `granule`.
    fn note(&mut self, granule: u64) {
        if self.last == Some(granule) {
            self.repeats += 1;
        } else {
            self.last = Some(granule);
            self.repeats = 0;
        }
    }
}

/// Connects the UART, the virtio devices and the virtio-fs devices to their
/// GIC lines.
fn connect_lines(shared: &Shared) {
    // Each device sets its own interrupt line, from the methods that change its
    // level and so under the lock that decides it.
    // On the portable machine every line wakes the vCPUs it reaches, the
    // console's included: there is no in-kernel GIC to do it.
    let line = |intid, kick: bool| -> Arc<dyn IrqLine> {
        match &shared.irqchip {
            Irqchip::InKernel(vm_gic) => Arc::new(HvfIrqLine {
                vm: vm_gic.clone(),
                intid,
                kick: kick.then(|| Arc::clone(&shared.guest.vcpus)),
            }),
            Irqchip::Soft(portable) => Arc::new(SoftIrqLine {
                portable: Arc::clone(portable),
                intid,
                vcpus: Arc::clone(&shared.guest.vcpus),
            }),
        }
    };
    lock_or_recover(&shared.pl011).connect_irq(line(UART_INTID, false));
    shared.guest.connect_irqs(
        line(VIRTIO_INTID, true),
        line(VIRTIO_NET_INTID, true),
        line(VIRTIO_VSOCK_INTID, true),
    );
    for fs in &shared.fs {
        lock_or_recover(&fs.dev).connect_irq(line(fs.intid, true));
    }
}

/// Binds the control socket at `path`, before confinement, with
/// `checkpoint_root` for its checkpoints and the disk opened at `disk`.
fn bind_control(
    path: Option<&str>,
    checkpoint_root: Option<&str>,
    disk: Option<String>,
    shared: &Shared,
) -> Result<Option<ControlSocket>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(path
        .map(|path| {
            ControlSocket::bind(path, Arc::clone(&shared.profile), checkpoint_root).map(|control| {
                let console = Console::Pl011(Arc::clone(&shared.pl011));
                control.capturing("hvf", disk, console)
            })
        })
        .transpose()?)
}

/// Confines the process before the first I/O thread exists, when `sandbox`
/// is set.
fn confine(
    sandbox: bool,
    fs_access: &[(std::path::PathBuf, bool)],
    control: Option<&ControlSocket>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Everything before this acquires host authority (the VM, the guest-RAM
    // mapping, the block file, the ledger, the gateway connection, the
    // listeners, the terminal), and everything after only services guest I/O
    // with what is already open. An error here returns before there is an
    // I/O thread to stop. See `sandbox::seatbelt`.
    //
    // Failing closed: a profile that will not install is a profile nobody has
    // tested, and continuing would hand a guest-facing process the host's full
    // ambient authority under a log line claiming it was sandboxed.
    if sandbox {
        let checkpoint_root = control.and_then(ControlSocket::checkpoint_root);
        seatbelt::enter_for(fs_access, checkpoint_root)
            .map_err(|e| format!("{e}; re-run with --no-sandbox to boot unconfined"))?;
        stderrln!("{LOG_PREFIX} seatbelt sandbox: on (deny default)");
    } else {
        stderrln!(
            "{LOG_PREFIX} seatbelt sandbox: OFF (--no-sandbox) — the VMM keeps full host authority"
        );
    }
    Ok(())
}

/// What `run` starts the I/O threads with.
struct IoStart {
    /// The stop the threads poll.
    stop_source: StopSource,
    /// The agent bridge, bound before confinement.
    bridge: Option<VsockBridge>,
    /// The read side of the gateway connection.
    net_reader: Option<std::os::unix::net::UnixStream>,
    /// The control socket, bound before confinement.
    control: Option<ControlSocket>,
    /// The threads the plugin asked for in `attach`.
    plugin_threads: Vec<PluginThread>,
    /// Whether the process is confined, which the run's start record says.
    sandbox: bool,
}

impl IoStart {
    /// Starts the I/O threads, each virtio-fs device's worker and readahead
    /// threads, and the portable guest's hvi-time timer thread. Each polls its
    /// stop token beside its own descriptor, or takes the stop through its
    /// `FsWake`, its `ReadaheadStop` or its device, and is joined after the
    /// vCPUs.
    fn start(self, shared: &Shared) -> IoThreads<Kicker> {
        let mut io_threads = IoThreads::start(
            self.stop_source,
            &shared.guest,
            shared.plugin.clone(),
            {
                let pl011 = Arc::clone(&shared.pl011);
                move |byte| lock_or_recover(&pl011).push_rx(byte)
            },
            self.bridge,
            self.net_reader.map(NetSource::Gateway),
            self.control,
            self.plugin_threads,
        );
        // Each virtio-fs device gets its own worker thread, which serves the
        // requests a vCPU leaves past `FS_INLINE_BUDGET`. See `run_fs_worker`.
        for fs in &shared.fs {
            let (dev, ram, wake) = (
                Arc::clone(&fs.dev),
                Arc::clone(&shared.guest.ram),
                Arc::clone(&fs.wake),
            );
            io_threads.spawn("virtio-fs worker", move |stop| {
                run_fs_worker(&dev, &ram, &wake, &stop);
            });
            let wake = Arc::clone(&fs.wake);
            io_threads.on_stop(move || wake.stop());
            let (workers, stop) = lock_or_recover(&fs.dev).readahead_workers();
            for worker in workers {
                io_threads.spawn("virtio-fs readahead", move |_| worker());
            }
            io_threads.on_stop(move || stop.stop());
        }
        if let Some(device) = &shared.hvitime {
            // The hvi-time timer thread, on the scheduling that wakes it on
            // time.
            let timer = Arc::clone(device);
            io_threads.spawn("hvi-time timer", move |_| {
                eprintln!(
                    "{LOG_PREFIX} hvi-time: timer thread on {}",
                    hvitime::timer_thread_setup()
                );
                timer.run_timer();
            });
            let timer = Arc::clone(device);
            io_threads.on_stop(move || timer.stop());
            // The in-process restore test, when `HVI_TIME_TEST_RESTORE` asks
            // for it.
            if let Some(test) = hvitime::TestRestore::from_env() {
                let (device, vcpus) = (Arc::clone(device), Arc::clone(&shared.guest.vcpus));
                io_threads.spawn("hvi-time test restore", move |_| {
                    test.run(&device, &vcpus, || {});
                });
            }
        }
        io_threads
    }
}

/// What a restore loads into the vCPUs once their threads run, and the line
/// levels it drives afterwards.
struct RestoreRun {
    /// The vCPUs' states and the platform.
    plan: Arc<ImportPlan>,
    /// Each device's line level at the capture.
    irq_levels: IrqLevels,
}

/// How long a restore waits for the vCPUs to start and for each import step.
const IMPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Starts the I/O threads and one thread per vCPU, and runs the guest until
/// it stops.
///
/// With `restore`, the guest is one a restore built: the I/O threads are held
/// at the gate and the vCPUs by the control socket before any starts, the
/// vCPUs load the bundle's state, the device lines are driven again, and only
/// then do the I/O threads start, with the control socket reporting the VM
/// restored-paused.
fn run(
    shared: Shared,
    num_cpus: u32,
    io: IoStart,
    restore: Option<RestoreRun>,
) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    install_kick_handler();
    if restore.is_some() {
        io.stop_source
            .gate()
            .pause(std::time::Duration::ZERO)
            .map_err(|inside| format!("{inside} I/O thread(s) inside the gate before any ran"))?;
        shared
            .guest
            .vcpus
            .pause_from_control(std::time::Duration::ZERO)
            .map_err(|e| format!("holding the vCPUs for the restore: {e}"))?;
    }
    let sandbox = io.sandbox;
    let (mut io, mut started) = match restore {
        None => (None, Some(io.start(&shared))),
        Some(_) => (Some(io), None),
    };

    record_start(&shared.guest, sandbox);
    // One thread per vCPU. From here on a failure stops the guest and is
    // reported once every thread has been joined or left running, and the first
    // failure is the one reported.
    let (threads, spawned) = shared
        .guest
        .vcpus
        .spawn((0..num_cpus).map(|_| shared.clone()), run_cpu);
    let mut failure: Option<Box<dyn std::error::Error + Send + Sync>> =
        spawned.err().map(Into::into);
    if let (Some(restore), None) = (&restore, &failure) {
        match load(&shared, restore) {
            Ok(()) => started = io.take().map(|io| io.start(&shared)),
            Err(e) => {
                // What a vCPU found wrong is the cause; the import only saw
                // the stop that followed.
                let why = shared
                    .restoring
                    .as_ref()
                    .and_then(|r| lock_or_recover(&r.failure).take())
                    .unwrap_or(e);
                failure = Some(format!("restore: {why}").into());
            }
        }
    }
    let result = run_to_stop(&shared.guest, threads, failure, started);

    // What the guest actually spent, reported once on the way out. #34 asks
    // for this number before any limit is tightened: a ceiling picked without
    // knowing what a real build needs is a ceiling that breaks one.
    for (index, fs) in shared.fs.iter().enumerate() {
        report_fs_usage(index, &fs.dev);
    }

    // `boot` keeps the run's claim when it sees a `LeftRunning` error, so the
    // error goes back as `run_to_stop` returned it.
    let stop = result?;
    if let Some(reason) = shared
        .portable
        .as_ref()
        .and_then(|p| lock_or_recover(&p.refused).take())
    {
        return Err(reason.into());
    }
    Ok(stop)
}

/// Prints the peak handle count, the operation counts and times, and the
/// readahead counts of virtio-fs device `index`.
///
/// A worker left running at the stop deadline can still hold the device, stuck
/// in a host call, so the lock is only tried. When the device is held, one line
/// says so and the statistics are skipped.
fn report_fs_usage(index: usize, dev: &Mutex<VirtioFs>) {
    let dev = match dev.try_lock() {
        Ok(dev) => dev,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => {
            stderrln!(
                "{LOG_PREFIX} virtio-fs[{index}]: statistics skipped, the device is still in use"
            );
            return;
        }
    };
    stderrln!(
        "{LOG_PREFIX} virtio-fs[{index}]: peak {} of {} guest handles",
        dev.peak_handles(),
        dev.handle_limit()
    );
    let hist: Vec<String> = dev
        .op_stats()
        .into_iter()
        .map(|(o, c, n)| {
            format!(
                "{}({})={}/{:.1}ms",
                server::opcode_name(o),
                o,
                c,
                n as f64 / 1e6
            )
        })
        .collect();
    stderrln!("{LOG_PREFIX} virtio-fs[{index}] ops: {}", hist.join(" "));
    let (hits, waits, misses) = dev.readahead_stats();
    stderrln!(
        "{LOG_PREFIX} virtio-fs[{index}] readahead: hits={hits} waits={waits} misses={misses}"
    );
}

/// Loads `restore` into the vCPUs, which park at their first checkpoint,
/// then drives each device's line as the capture left it.
///
/// `hv_gic_set_state` in the import's second step sets the GIC's view of
/// every line, so the lines are driven again after the last step: to the
/// level each restored device holds, which is the captured one except where
/// ending the vsock connections queued packets for the guest.
fn load(shared: &Shared, restore: &RestoreRun) -> Result<(), String> {
    import(&shared.guest.vcpus, &restore.plan, IMPORT_TIMEOUT, || {
        shared.create_order.created()
    })?;
    let vm_gic = match &shared.irqchip {
        Irqchip::InKernel(vm_gic) => vm_gic,
        Irqchip::Soft(_) => {
            // The platform step replaced the software GIC with the captured
            // one, lines and all. Each device's line goes to its level,
            // which is the captured one but where ending the vsock
            // connections queued packets for the guest, and each device's
            // record of its line with it.
            lock_or_recover(&shared.pl011).redrive_irq();
            shared.guest.redrive_irqs();
            return Ok(());
        }
    };
    let levels = &restore.irq_levels;
    let lines = [
        (
            "uart",
            UART_INTID,
            levels.uart,
            Some(lock_or_recover(&shared.pl011).irq_level()),
        ),
        (
            "virtio-blk",
            VIRTIO_INTID,
            levels.blk,
            shared
                .guest
                .block
                .as_ref()
                .map(|d| lock_or_recover(d).irq_level()),
        ),
        (
            "virtio-net",
            VIRTIO_NET_INTID,
            levels.net,
            shared
                .guest
                .net
                .as_ref()
                .map(|d| lock_or_recover(d).irq_level()),
        ),
        (
            "virtio-vsock",
            VIRTIO_VSOCK_INTID,
            levels.vsock,
            shared
                .guest
                .vsock
                .as_ref()
                .map(|d| lock_or_recover(d).irq_level()),
        ),
    ];
    for (name, intid, saved, now) in lines {
        let Some(now) = now else { continue };
        vm_gic
            .gic_set_spi(intid, saved || now)
            .map_err(|e| format!("driving the {name} line: {e:?}"))?;
    }
    Ok(())
}

thread_local! {
    /// The reason this thread's vCPU last left the guest.
    ///
    /// Recorded so the panic report in [`run_cpu`] can name it. `catch_unwind`
    /// runs on the thread that panicked, so a thread-local survives the unwind
    /// and is readable there, and it costs the other vCPU threads nothing.
    static LAST_EXIT: std::cell::Cell<Option<ExitReason>> =
        const { std::cell::Cell::new(None) };

    /// The handle id of this thread's vCPU, so a kick can leave it out.
    static OWN_VCPU: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };

    /// The index of this thread's vCPU, so a wake from the software GIC can
    /// leave it out.
    static OWN_CPU: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// What this thread's vCPU last exited for, if it has run at all.
fn last_exit() -> Option<ExitReason> {
    LAST_EXIT.with(std::cell::Cell::get)
}

/// A single vCPU: create it, position it (boot entry, or wait for CPU_ON), and
/// run its exit loop until the VM stops.
fn run_cpu(cpu_id: u32, sh: Shared) {
    if !sh
        .create_order
        .wait_turn(cpu_id, || sh.guest.vcpus.is_running())
    {
        return;
    }
    let created = sh.vm.vcpu_create();
    sh.create_order.done();
    let vcpu = match created {
        Ok(v) => v,
        Err(e) => {
            sh.guest.vcpus.report(Outcome::Failed(format!(
                "vcpu{cpu_id}: vcpu_create failed: {e:?}"
            )));
            return;
        }
    };
    let _ = vcpu.set_trap_debug_exceptions(false);
    let _ = vcpu.set_trap_debug_reg_accesses(false);
    // GICv3 affinity: aff0 = cpu id, RES1 bit 31 set. A GICv2 reads the
    // same aff0.
    let _ = vcpu.set_sys_reg(SysReg::MPIDR_EL1, 0x8000_0000 | u64::from(cpu_id));
    if let Some(p) = &sh.portable {
        // Before the profile reads MIDR_EL1 and before the guest's first
        // instruction.
        let set = set_baseline(&vcpu, cpu_id, cpu_id == 0)
            .and_then(|()| set_vtimer_offset(&vcpu, sh.vtimer_offset));
        if let Err(e) = set {
            eprintln!("{LOG_PREFIX} cpu{cpu_id}: {e}");
            lock_or_recover(&p.refused).get_or_insert(e);
            return;
        }
    }
    // Declared after the vCPU, so it drops first.
    let _registration = sh.guest.vcpus.kicker().register(cpu_id, &vcpu);
    // A restore loads the GIC only once every vCPU, the ones that were off
    // as well, exists. See `checkpoint::restore::import`.
    sh.create_order.mark_created();

    if cpu_id == 0 {
        // Only this thread can read the register, and the guest has not run
        // yet, so the profile is complete before its first instruction.
        let midr = vcpu.get_sys_reg(SysReg::MIDR_EL1).ok();
        // A restore compares it with the bundle's here, since no other thread
        // could read it before the VM existed.
        if let Some(restoring) = &sh.restoring {
            if midr != restoring.midr {
                *lock_or_recover(&restoring.failure) = Some(format!(
                    "profile: cpu.ident: {} on the source, {} on the destination",
                    restoring.midr.map_or_else(|| "unread".to_string(), hex),
                    midr.map_or_else(|| "unread".to_string(), hex)
                ));
                return;
            }
        }
        if let Err(e) = sh.profile.complete(|p| p.cpu.ident = midr.map(hex)) {
            eprintln!("{LOG_PREFIX} {e}");
        }
    }
    let runs_at_once = sh
        .restoring
        .as_ref()
        .map_or(cpu_id == 0, |r| r.runs.get(cpu_id as usize) == Some(&true));
    if sh.restoring.is_some() && runs_at_once {
        // Its registers come from the bundle, in the import.
        sh.guest.vcpus.mark_started(cpu_id);
    } else if cpu_id == 0 {
        let _ = vcpu.set_reg(Reg::PC, sh.kernel_addr);
        let _ = vcpu.set_reg(Reg::X0, sh.dtb_addr);
        let _ = vcpu.set_reg(Reg::X1, 0);
        let _ = vcpu.set_reg(Reg::X2, 0);
        let _ = vcpu.set_reg(Reg::X3, 0);
        let _ = vcpu.set_reg(Reg::CPSR, 0x3c5); // EL1h, DAIF masked
        sh.guest.vcpus.mark_started(cpu_id);
    } else {
        // Park until the guest brings this cpu up via PSCI CPU_ON. A restore
        // fills the mailbox of a secondary whose CPU_ON the capture found
        // waiting, so it starts as it would have.
        let sec = &sh.guest.vcpus.kicker().secondaries[cpu_id as usize];
        let mut mbox = sec.mbox.lock().unwrap();
        while mbox.is_none() && sh.guest.vcpus.is_running() {
            mbox = sec.cv.wait(mbox).unwrap();
        }
        let Some((entry, ctx)) = *mbox else {
            return; // stopped while waiting
        };
        let _ = vcpu.set_reg(Reg::PC, entry);
        let _ = vcpu.set_reg(Reg::X0, ctx);
        let _ = vcpu.set_reg(Reg::CPSR, 0x3c5);
        // Taken and started under the mailbox lock, which a checkpoint
        // reads it under: the request is in the mailbox or this vCPU counts
        // as started, never neither.
        *mbox = None;
        sh.guest.vcpus.mark_started(cpu_id);
        drop(mbox);
        stderrln!("{LOG_PREFIX} vcpu{cpu_id}: PSCI CPU_ON -> {entry:#x}");
    }
    let clock = sh.restoring.as_ref().and_then(|r| r.clock.as_ref());
    // A restored vCPU sets the counter offset once, before it first enters
    // the guest, which is after `resume`. See `hvf_state::RestoreClock`.
    let mut clock_set = clock.is_none();

    if cpu_id == 0 && sh.restoring.is_none() {
        // Guest nanoseconds start at 0 at the boot vCPU's first entry.
        if let Some(device) = &sh.hvitime {
            device.publish_boot();
        }
    }
    // A restored portable guest's clock is published before its first
    // entry after `resume`.
    let mut published = sh.restoring.is_none();
    // The plugin runs on vcpu0, between guest entries, because only this thread
    // can read this vCPU's registers.
    let plugin = sh.plugin.as_deref().filter(|_| cpu_id == 0);
    let portable = sh.portable.as_deref();
    let mut vtimer = Vtimer {
        offset: vcpu.get_vtimer_offset().unwrap_or(0),
        raised: false,
    };
    let mut ram_faults = RamFaults::default();
    // The loop runs inside `catch_unwind` only for the report. A panic is
    // reported with where the guest was and what it last did, and the thread
    // then reports its exit like any other.
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        while sh.guest.vcpus.is_running() {
            // Safe point for every vCPU: park here while vcpu0 lets a plugin
            // look at the guest, or the control socket captures it, doing
            // on this thread the work only it can.
            let mut read_platform = false;
            sh.guest.pass_safepoint(&vcpu, cpu_id, plugin, |work| {
                match (&sh.irqchip, &sh.hvitime) {
                    (Irqchip::InKernel(vm_gic), _) => {
                        hvf_state::serve(cpu_id, &vcpu, vm_gic, clock, work)
                    }
                    (Irqchip::Soft(p), Some(device)) => {
                        read_platform |= matches!(work, Work::ExportPlatform);
                        let pending = sh.restoring.as_ref().and_then(|r| r.hvitime.as_ref());
                        hvf_state::serve_portable(cpu_id, &vcpu, &p.gic, device, pending, work)
                    }
                    (Irqchip::Soft(_), None) => {
                        Err(std::io::Error::other("the portable guest has no hvi-time"))
                    }
                }
            });
            // A capture froze hvi-time to read it. A guest that goes on
            // after it, as `then: "continue"` has it, gets its timers back.
            if read_platform {
                if let Some(device) = &sh.hvitime {
                    device.thaw();
                }
            }
            if !published {
                let pending = sh.restoring.as_ref().and_then(|r| r.hvitime.as_ref());
                if let (Some(pending), Some(device)) = (pending, &sh.hvitime) {
                    if let Err(e) = pending.publish(device) {
                        eprintln!("{LOG_PREFIX} cpu{cpu_id}: {e}");
                        if let Some(p) = portable {
                            lock_or_recover(&p.refused).get_or_insert(e);
                        }
                        break;
                    }
                }
                published = true;
            }
            if !clock_set {
                if let Some(clock) = clock {
                    if let Err(e) = vcpu.set_vtimer_offset(clock.offset()) {
                        eprintln!("{LOG_PREFIX} cpu{cpu_id}: setting the vtimer offset: {e:?}");
                        break;
                    }
                }
                clock_set = true;
            }

            // The software GIC's verdict for this vCPU. Hypervisor.framework
            // drops the pending IRQ after every run, so it is set before each
            // one.
            if let Some(p) = portable {
                resample_vtimer(&vcpu, p, cpu_id, &mut vtimer);
                let pending = lock_or_recover(&p.gic).irq_pending(cpu_id as usize);
                let _ = vcpu.set_pending_interrupt(IRQ_LINE, pending);
            }

            let flow = match vcpu.run() {
                Ok(()) => handle_exit(&vcpu, &sh, cpu_id, &mut vtimer, &mut ram_faults),
                Err(e) => ControlFlow::Break(Outcome::Failed(format!(
                    "vcpu{cpu_id}: vcpu run failed: {e:?}"
                ))),
            };
            if let ControlFlow::Break(outcome) = flow {
                sh.guest.vcpus.report(outcome);
                break;
            }
        }
    }));

    if let Err(payload) = unwound {
        // The report names where the guest was and what it last did, so it is
        // usable without a debugger.
        sh.guest.vcpus.report(Outcome::Failed(format!(
            "vcpu{cpu_id}: panicked ({}); last exit {:?}, pc {:#x}",
            crate::panic_message(payload.as_ref()),
            last_exit(),
            vcpu.get_reg(Reg::PC).unwrap_or(0)
        )));
    }
}

/// Services one exit of vCPU `cpu_id`.
///
/// Returns `ControlFlow::Break` with the run's outcome when the exit ends the
/// run, and `ControlFlow::Continue` otherwise. The outcome is a guest-requested
/// stop or a failure.
// One match over the exits, as the hypervisor reports them.
#[allow(clippy::too_many_lines)]
fn handle_exit(
    vcpu: &Vcpu,
    sh: &Shared,
    cpu_id: u32,
    vtimer: &mut Vtimer,
    ram_faults: &mut RamFaults,
) -> ControlFlow<Outcome> {
    let portable = sh.portable.as_deref();
    let exit = vcpu.get_exit_info();
    LAST_EXIT.with(|last| last.set(Some(exit.reason)));
    // Only RAM faults in a row count towards the repeat cap.
    if !matches!(exit.reason, ExitReason::EXCEPTION)
        || Ec::from_syndrome(exit.exception.syndrome) != Ec::DataAbort
    {
        *ram_faults = RamFaults::default();
    }
    match exit.reason {
        ExitReason::EXCEPTION => {
            let syn = exit.exception.syndrome;
            match Ec::from_syndrome(syn) {
                Ec::Hvc | Ec::Smc => {
                    trace::exit(trace::Exit::Hvc);
                    // Not restartable: the saved PC is already past HVC/SMC.
                    if let Some(p) = portable {
                        match service_firmware(vcpu, sh, p) {
                            Firmware::Continue => {}
                            Firmware::Stop(stop) => {
                                return ControlFlow::Break(Outcome::Stopped(stop))
                            }
                            Firmware::Suspend => {
                                wait_for_interrupt(vcpu, sh, p, cpu_id, vtimer);
                            }
                        }
                    } else {
                        service_psci(vcpu, sh)?;
                    }
                }
                Ec::DataAbort => {
                    let ipa = exit.exception.physical_address;
                    // A write to guest RAM a live move protected: the log
                    // records it and makes the granule writable again, and the
                    // store runs again, with the PC where it was.
                    let ram_write = match sh.write_log.fault(ipa) {
                        Ok(served) => served,
                        Err(e) => {
                            return ControlFlow::Break(Outcome::Failed(format!(
                                "vcpu{cpu_id}: {e}"
                            )));
                        }
                    };
                    if ram_write {
                        ram_faults.note(ipa & !(sh.write_log.granule() - 1));
                        if ram_faults.repeats > RAM_FAULT_REPEATS {
                            return ControlFlow::Break(Outcome::Failed(format!(
                                "vcpu{cpu_id}: guest RAM at {ipa:#x} faults again after it was \
                                 made writable (pc {:#x})",
                                vcpu.get_reg(Reg::PC).unwrap_or(0)
                            )));
                        }
                    } else if (UART_BASE..UART_BASE + UART_SIZE).contains(&ipa) {
                        trace::exit(trace::Exit::Mmio);
                        service_uart(vcpu, sh, ipa - UART_BASE, syn);
                        advance_pc(vcpu);
                    } else if (VIRTIO_BASE..VIRTIO_BASE + VIRTIO_SIZE).contains(&ipa) {
                        trace::exit(trace::Exit::Mmio);
                        if let Some(dev) = &sh.guest.block {
                            service_dev(vcpu, sh, dev, ipa - VIRTIO_BASE, syn);
                        }
                        advance_pc(vcpu);
                    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&ipa) {
                        trace::exit(trace::Exit::Mmio);
                        if let Some(dev) = &sh.guest.net {
                            service_net(vcpu, sh, dev, ipa - VIRTIO_NET_BASE, syn);
                        }
                        advance_pc(vcpu);
                    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&ipa) {
                        trace::exit(trace::Exit::Mmio);
                        if let Some(dev) = &sh.guest.vsock {
                            service_vsock(vcpu, sh, dev, ipa - VIRTIO_VSOCK_BASE, syn);
                        }
                        advance_pc(vcpu);
                    } else if let Some(fs) = sh
                        .fs
                        .iter()
                        .find(|fs| (fs.base..fs.base + VIRTIO_SIZE).contains(&ipa))
                    {
                        service_fs(vcpu, sh, fs, ipa - fs.base, syn);
                        advance_pc(vcpu);
                    } else if let Some(p) = portable.filter(|p| p.in_gic(ipa)) {
                        trace::exit(trace::Exit::Gic);
                        service_gic(vcpu, sh, p, cpu_id, ipa, syn, vtimer);
                        advance_pc(vcpu);
                    } else if let Some(device) = sh.hvitime.as_deref().filter(|_| {
                        (HVI_TIME_TIMERS_BASE..HVI_TIME_TIMERS_BASE + hvitime::TIMERS_SIZE)
                            .contains(&ipa)
                    }) {
                        trace::exit(trace::Exit::Timer);
                        service_hvitime(vcpu, device, ipa - HVI_TIME_TIMERS_BASE, syn);
                        advance_pc(vcpu);
                    } else if sh.hvitime.is_some()
                        && (HVI_TIME_PAGE_BASE..HVI_TIME_PAGE_BASE + hvitime::PAGE_SIZE)
                            .contains(&ipa)
                    {
                        // A write to the read-only page: dropped, as KVM drops
                        // one to a read-only memory slot.
                        trace::exit(trace::Exit::Mmio);
                        advance_pc(vcpu);
                    } else {
                        return ControlFlow::Break(Outcome::Failed(format!(
                            "vcpu{cpu_id}: unhandled MMIO at {ipa:#x} (pc {:#x})",
                            vcpu.get_reg(Reg::PC).unwrap_or(0)
                        )));
                    }
                }
                Ec::SysReg => {
                    trace::exit(trace::Exit::SysReg);
                    // RAZ/WI: unmodeled system register. Without hv_gic the
                    // physical counter traps too, and reads the guest's
                    // counter.
                    let iss = syn & 0x1ff_ffff;
                    if iss & 1 == 1 {
                        let value = match portable {
                            Some(_) if is_physical_counter(iss) => vtimer.counter(),
                            _ => 0,
                        };
                        write_gpr(vcpu, ((iss >> 5) & 0x1f) as u8, value);
                    }
                    advance_pc(vcpu);
                }
                // WFx. The native machine's hv_gic handled the wait. Without it
                // a WFI exits at once with the PC on it, so hvi steps past it
                // and waits here.
                Ec::Other(0x01) => {
                    trace::exit(trace::Exit::Wfi);
                    if let Some(p) = portable {
                        advance_pc(vcpu);
                        if syn & 0b11 == 0 {
                            wait_for_interrupt(vcpu, sh, p, cpu_id, vtimer);
                        }
                    }
                }
                other => {
                    return ControlFlow::Break(Outcome::Failed(format!(
                        "vcpu{cpu_id}: unhandled exception {other:?} (pc {:#x})",
                        vcpu.get_reg(Reg::PC).unwrap_or(0)
                    )));
                }
            }
        }
        ExitReason::VTIMER_ACTIVATED => {
            trace::exit(trace::Exit::Vtimer);
            let _ = vcpu.set_vtimer_mask(true);
            // Without hv_gic the timer reaches the guest only as this exit.
            // The line stays high, and the timer masked, until the guest ends
            // the interrupt (`end_vtimer_interrupt`).
            if let Some(p) = portable {
                vtimer.raised = true;
                lock_or_recover(&p.gic).set_ppi_line(cpu_id as usize, VTIMER_INTID, true);
            }
        }
        // Kicked: for a snapshot, a stop or an interrupt.
        ExitReason::CANCELED => trace::exit(trace::Exit::Kicked),
        ExitReason::UNKNOWN => {
            // hvf could not say why it exited, so there is nothing to resume
            // into.
            return ControlFlow::Break(Outcome::Failed(format!(
                "vcpu{cpu_id}: unknown exit reason (pc {:#x})",
                vcpu.get_reg(Reg::PC).unwrap_or(0)
            )));
        }
    }
    ControlFlow::Continue(())
}

impl SafepointVcpu for Vcpu {
    fn regs(&self) -> RegsView {
        let ttbr1 = self.get_sys_reg(SysReg::TTBR1_EL1).unwrap_or(0);
        RegsView {
            // arm64's kernel-half page-table base is the walk root.
            root: ttbr1,
            pc: self.get_reg(Reg::PC).unwrap_or(0),
            cpsr: self.get_reg(Reg::CPSR).unwrap_or(0),
            ttbr0: self.get_sys_reg(SysReg::TTBR0_EL1).unwrap_or(0),
            ttbr1,
            sctlr: self.get_sys_reg(SysReg::SCTLR_EL1).unwrap_or(0),
            sp_el1: self.get_sys_reg(SysReg::SP_EL1).unwrap_or(0),
            tcr: self.get_sys_reg(SysReg::TCR_EL1).unwrap_or(0),
            current_task: self.get_sys_reg(SysReg::SP_EL0).unwrap_or(0),
        }
    }
}

/// Handles a PSCI call.
///
/// Returns `ControlFlow::Break` with the stop for `SYSTEM_OFF` and
/// `SYSTEM_RESET`, and `ControlFlow::Continue` otherwise.
fn service_psci(vcpu: &Vcpu, sh: &Shared) -> ControlFlow<Outcome> {
    let fid = vcpu.get_reg(Reg::X0).unwrap_or(0);
    match fid {
        psci::VERSION => {
            let _ = vcpu.set_reg(Reg::X0, 0x0001_0000); // v1.0
            ControlFlow::Continue(())
        }
        psci::SYSTEM_OFF => ControlFlow::Break(Outcome::Stopped(Stop::SystemOff)),
        psci::SYSTEM_RESET => ControlFlow::Break(Outcome::Stopped(Stop::SystemReset)),
        psci::FEATURES => {
            let q = vcpu.get_reg(Reg::X1).unwrap_or(0);
            let known = matches!(
                q,
                psci::VERSION
                    | psci::SYSTEM_OFF
                    | psci::SYSTEM_RESET
                    | psci::FEATURES
                    | psci::CPU_ON_64
            );
            let _ = vcpu.set_reg(
                Reg::X0,
                if known {
                    psci::SUCCESS
                } else {
                    psci::NOT_SUPPORTED
                },
            );
            ControlFlow::Continue(())
        }
        psci::CPU_ON_64 => {
            let target = vcpu.get_reg(Reg::X1).unwrap_or(0);
            let entry = vcpu.get_reg(Reg::X2).unwrap_or(0);
            let ctx = vcpu.get_reg(Reg::X3).unwrap_or(0);
            let idx = (target & 0xff) as usize; // aff0
            let secondaries = &sh.guest.vcpus.kicker().secondaries;
            let ret = if idx != 0 && idx < secondaries.len() {
                let sec = &secondaries[idx];
                *sec.mbox.lock().unwrap() = Some((entry, ctx));
                sec.cv.notify_all();
                psci::SUCCESS
            } else {
                psci::NOT_SUPPORTED
            };
            let _ = vcpu.set_reg(Reg::X0, ret);
            ControlFlow::Continue(())
        }
        psci::CPU_OFF => {
            let _ = vcpu.set_reg(Reg::X0, psci::SUCCESS);
            ControlFlow::Continue(())
        }
        _ => {
            let _ = vcpu.set_reg(Reg::X0, psci::NOT_SUPPORTED);
            ControlFlow::Continue(())
        }
    }
}

// ----- The portable machine ------------------------------------------------

impl Portable {
    /// Returns whether `ipa` is in the distributor or CPU interface window.
    fn in_gic(&self, ipa: u64) -> bool {
        let l = &self.layout;
        (l.gicd_base..l.gicd_base + l.gicd_size).contains(&ipa)
            || (l.gicr_base..l.gicr_base + l.gicr_size).contains(&ipa)
    }
}

/// The host's `mach_absolute_time`, which runs at the rate guest counters
/// read, and its conversion to nanoseconds. libc marks its declarations
/// deprecated in favour of another crate, so they are declared here.
#[repr(C)]
struct MachTimebase {
    numer: u32,
    denom: u32,
}

extern "C" {
    fn mach_absolute_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebase) -> libc::c_int;
}

/// Returns host counter ticks to nanoseconds as `(numer, denom)`; 125/3 on
/// a 24 MHz Apple counter.
fn host_timebase() -> (u64, u64) {
    let mut tb = MachTimebase { numer: 0, denom: 0 };
    // SAFETY: `tb` is a valid out-pointer for the call.
    let ok = unsafe { mach_timebase_info(&mut tb) } == 0 && tb.denom != 0;
    if ok {
        (u64::from(tb.numer), u64::from(tb.denom))
    } else {
        (125, 3)
    }
}

/// One portable vCPU's virtual timer, as its thread drives it.
///
/// Without hv_gic the timer reaches the guest only as a `VTIMER_ACTIVATED`
/// exit, which also masks it. hvi then raises PPI 27 and keeps the timer
/// masked until the guest ends that interrupt.
struct Vtimer {
    /// The vCPU's `CNTVCT_EL0` offset from `mach_absolute_time`.
    offset: u64,
    /// Whether hvi raised the timer's line and masked the timer.
    raised: bool,
}

impl Vtimer {
    /// The guest's counter now: `CNTVCT_EL0`, which `CNTPCT_EL0` reads too.
    fn counter(&self) -> u64 {
        // SAFETY: `mach_absolute_time` takes no arguments and cannot fail.
        unsafe { mach_absolute_time() }.wrapping_sub(self.offset)
    }

    /// When the guest's timer fires, if it is armed and not masked by the
    /// guest; now if it has fired already.
    fn deadline(&self, vcpu: &Vcpu, (numer, denom): (u64, u64)) -> Option<Instant> {
        let ctl = vcpu.get_sys_reg(SysReg::CNTV_CTL_EL0).ok()?;
        // ENABLE set and IMASK clear.
        if ctl & 0b11 != 0b01 {
            return None;
        }
        let now = Instant::now();
        if ctl & 0b100 != 0 {
            return Some(now);
        }
        let cval = vcpu.get_sys_reg(SysReg::CNTV_CVAL_EL0).ok()?;
        let ticks = cval.saturating_sub(self.counter());
        let ns = u128::from(ticks) * u128::from(numer) / u128::from(denom.max(1));
        now.checked_add(Duration::from_nanos(u64::try_from(ns).ok()?))
    }
}

/// Sleeps a portable vCPU's thread after a guest WFI.
///
/// It returns once the software GIC has an interrupt for the vCPU, the
/// guest's timer is due, a pause asks the vCPU to park, or the VM stops. The
/// guest then resumes after its WFI, which may always complete early.
fn wait_for_interrupt(vcpu: &Vcpu, sh: &Shared, p: &Portable, cpu: u32, vtimer: &mut Vtimer) {
    let vcpus = &sh.guest.vcpus;
    let Some(idle) = vcpus.kicker().idle.get(cpu as usize) else {
        return;
    };
    // A guest that stopped its timer before it took the interrupt sleeps
    // until its next deadline, not on a stale line.
    resample_vtimer(vcpu, p, cpu, vtimer);
    // A raised timer line is the GIC's to report.
    let deadline = if vtimer.raised {
        None
    } else {
        vtimer.deadline(vcpu, p.timebase)
    };
    let mut asleep = lock_or_recover(&idle.asleep);
    *asleep = true;
    loop {
        // Lock order: `Idle`, then the GIC. A waker releases the GIC first.
        if !vcpus.is_running()
            || vcpus.quiesce_requested()
            || lock_or_recover(&p.gic).irq_pending(cpu as usize)
        {
            break;
        }
        asleep = match deadline {
            None => idle
                .cv
                .wait(asleep)
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(at) => {
                let now = Instant::now();
                if now >= at {
                    break;
                }
                match idle.cv.wait_timeout(asleep, at - now) {
                    Ok((guard, _)) => guard,
                    Err(poisoned) => poisoned.into_inner().0,
                }
            }
        };
    }
    *asleep = false;
}

/// Services a guest access to the software GIC.
fn service_gic(
    vcpu: &Vcpu,
    sh: &Shared,
    p: &Portable,
    cpu: u32,
    ipa: u64,
    syndrome: u64,
    vtimer: &mut Vtimer,
) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    let c = cpu as usize;
    let l = &p.layout;
    let dist = ipa < l.gicr_base;
    let offset = if dist {
        ipa - l.gicd_base
    } else {
        ipa - l.gicr_base
    };
    if !da.is_write {
        let v = {
            let mut gic = lock_or_recover(&p.gic);
            if dist {
                gic.dist_read(c, offset, da.width)
            } else {
                gic.cpu_read(c, offset, da.width)
            }
        };
        write_gpr(vcpu, da.reg, u64::from(v) & width_mask(da.width));
        return;
    }
    // The registers are 32 bits wide.
    let value = read_gpr(vcpu, da.reg) as u32;
    let out = {
        let mut gic = lock_or_recover(&p.gic);
        if dist {
            gic.dist_write(c, offset, da.width, value)
        } else {
            gic.cpu_write(c, offset, da.width, value)
        }
    };
    if out.wake != 0 {
        sh.guest.vcpus.kicker().wake_mask(out.wake);
    }
    if out.deactivated == Some(VTIMER_INTID) {
        end_vtimer_interrupt(vcpu, p, cpu, vtimer);
    }
}

/// Services a guest access to the `hvi-time` timer window, `offset` bytes
/// in.
fn service_hvitime(vcpu: &Vcpu, device: &HviTime, offset: u64, syndrome: u64) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    if da.is_write {
        device.mmio_write(offset, da.width, read_gpr(vcpu, da.reg));
    } else {
        let v = device.mmio_read(offset, da.width) & width_mask(da.width);
        write_gpr(vcpu, da.reg, v);
    }
}

/// Gives `vcpu` the VM's virtual timer offset and checks that it took, so
/// every portable vCPU reads the counter the `hvi-time` page maps.
///
/// # Errors
///
/// Errors when the offset cannot be set or reads back otherwise.
fn set_vtimer_offset(vcpu: &Vcpu, offset: u64) -> Result<(), String> {
    vcpu.set_vtimer_offset(offset)
        .map_err(|e| format!("the virtual timer offset cannot be set ({e:?})"))?;
    match vcpu.get_vtimer_offset() {
        Ok(back) if back == offset => Ok(()),
        Ok(back) => Err(format!(
            "the virtual timer offset reads {back:#x}, not {offset:#x}"
        )),
        Err(e) => Err(format!(
            "the virtual timer offset does not read back ({e:?})"
        )),
    }
}

/// Drops the timer line hvi raised if the guest has not taken the
/// interrupt and the timer no longer fires.
///
/// The NO_HZ idle path stops the timer with IRQs masked, after the
/// `VTIMER_ACTIVATED` exit raised the line. KVM re-evaluates the timer on
/// every guest entry, so a guest on the Pi never takes that interrupt; this
/// does the same while PPI 27 is raised and not active. Once it is active,
/// the guest's deactivation decides (`end_vtimer_interrupt`).
fn resample_vtimer(vcpu: &Vcpu, p: &Portable, cpu: u32, vtimer: &mut Vtimer) {
    if !vtimer.raised || lock_or_recover(&p.gic).is_active(cpu as usize, VTIMER_INTID) {
        return;
    }
    end_vtimer_interrupt(vcpu, p, cpu, vtimer);
}

/// Handles the guest's end of the timer interrupt hvi raised.
///
/// The line stays high while the timer still fires: enabled, its condition
/// met and not masked by the guest. Otherwise it drops and the timer is
/// unmasked, so its next expiry exits again.
fn end_vtimer_interrupt(vcpu: &Vcpu, p: &Portable, cpu: u32, vtimer: &mut Vtimer) {
    if !vtimer.raised {
        return;
    }
    let ctl = vcpu.get_sys_reg(SysReg::CNTV_CTL_EL0).unwrap_or(0);
    // ENABLE and ISTATUS set, IMASK clear.
    if ctl & 0b111 == 0b101 {
        return;
    }
    vtimer.raised = false;
    lock_or_recover(&p.gic).set_ppi_line(cpu as usize, VTIMER_INTID, false);
    let _ = vcpu.set_vtimer_mask(false);
}

/// Returns whether a trapped system-register access (its ISS) is a read of
/// `CNTPCT_EL0` or `CNTPCTSS_EL0`, which trap without hv_gic.
fn is_physical_counter(iss: u64) -> bool {
    let op0 = (iss >> 20) & 3;
    let op2 = (iss >> 17) & 7;
    let op1 = (iss >> 14) & 7;
    let crn = (iss >> 10) & 0xf;
    let crm = (iss >> 1) & 0xf;
    (op0, op1, crn, crm) == (3, 3, 14, 0) && (op2 == 1 || op2 == 5) && iss & 1 == 1
}

/// The system registers of [`portable::BASELINE`], in its order.
const BASELINE_REGS: [SysReg; 12] = [
    SysReg::MIDR_EL1,
    SysReg::ID_AA64PFR0_EL1,
    SysReg::ID_AA64PFR1_EL1,
    SysReg::ID_AA64ZFR0_EL1,
    SysReg::ID_AA64SMFR0_EL1,
    SysReg::ID_AA64ISAR0_EL1,
    SysReg::ID_AA64ISAR1_EL1,
    SysReg::ID_AA64MMFR0_EL1,
    SysReg::ID_AA64MMFR1_EL1,
    SysReg::ID_AA64MMFR2_EL1,
    SysReg::ID_AA64DFR0_EL1,
    SysReg::ID_AA64DFR1_EL1,
];

/// Checks that this host can back the portable CPU baseline: no field of
/// it claims more than the default vCPU configuration has.
///
/// Hypervisor.framework accepts a raised field and the guest then reads it
/// (P0 HVF probe e2: `ID_AA64PFR0_EL1.SVE=1` and `ID_AA64ISAR0_EL1.SM3=1`
/// on an M5 Pro, which has neither), so neither the write nor its readback
/// can catch a raise. This comparison is what does. `MIDR_EL1` is identity,
/// not a feature, and is not compared.
///
/// # Errors
///
/// Errors naming every field the host cannot back, and every register it
/// cannot read.
fn check_baseline_on_host() -> Result<(), String> {
    let config = VcpuConfig::new();
    let mut wrong = Vec::new();
    for (name, value) in portable::BASELINE.into_iter().skip(1) {
        let Some((_, reg)) = FEATURE_REGS.iter().find(|(n, _)| *n == name) else {
            wrong.push(format!("{name} has no host value to compare with"));
            continue;
        };
        match config.get_feature_reg(*reg) {
            Ok(host) => wrong.extend(portable::excess_fields(name, value, host)),
            Err(e) => wrong.push(format!("{name} cannot be read ({e:?})")),
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "this host cannot back the portable-arm64-v1 CPU baseline: {}",
            wrong.join("; ")
        ))
    }
}

/// Gives `vcpu`, which is vCPU `cpu`, the portable CPU baseline and its
/// `MPIDR_EL1`, and logs the baseline when `log`.
///
/// `check_baseline_on_host` has already compared the baseline with the
/// host, which is what catches a raised field. Each register is still read
/// back, to catch a write that did not take.
///
/// # Errors
///
/// Errors naming every register that does not read back as written, or a
/// `DCZID_EL0` (which no backend can set) other than the profile's.
///
/// `MPIDR_EL1` is checked as the baseline is: `CPU_ON` and `AFFINITY_INFO`
/// find a vCPU by its affinity 0, and a write that did not take would leave
/// every vCPU at Hypervisor.framework's default of 0x80000000.
fn set_baseline(vcpu: &Vcpu, cpu: u32, log: bool) -> Result<(), String> {
    let mut wrong = Vec::new();
    let mpidr = ("MPIDR_EL1", 0x8000_0000 | u64::from(cpu));
    let regs = portable::BASELINE.into_iter().zip(BASELINE_REGS);
    for ((name, value), reg) in regs.chain([(mpidr, SysReg::MPIDR_EL1)]) {
        if let Err(e) = vcpu.set_sys_reg(reg, value) {
            wrong.push(format!("{name} cannot be set ({e:?})"));
            continue;
        }
        match vcpu.get_sys_reg(reg) {
            Ok(back) if back == value => {}
            Ok(back) => wrong.push(format!("{name} reads {back:#x}, not {value:#x}")),
            Err(e) => wrong.push(format!("{name} does not read back ({e:?})")),
        }
    }
    let config = VcpuConfig::new();
    let dczid = config.get_feature_reg(FeatureReg::DCZID_EL0).unwrap_or(0);
    if dczid != portable::DCZID_EL0 {
        wrong.push(format!(
            "DCZID_EL0 is {dczid:#x} here, not {:#x}",
            portable::DCZID_EL0
        ));
    }
    if !wrong.is_empty() {
        return Err(format!(
            "the portable-arm64-v1 CPU baseline does not hold on this host: {}",
            wrong.join("; ")
        ));
    }
    if log {
        let regs: Vec<String> = portable::BASELINE
            .iter()
            .map(|(name, value)| format!("{name}={value:#x}"))
            .collect();
        let ctr = config.get_feature_reg(FeatureReg::CTR_EL0).unwrap_or(0);
        eprintln!(
            "{LOG_PREFIX} portable-arm64-v1 CPU baseline: {} (host CTR_EL0={ctr:#x} DCZID_EL0={dczid:#x}, not settable)",
            regs.join(" ")
        );
    }
    Ok(())
}

/// How a firmware call of the portable profile ended.
enum Firmware {
    /// The guest goes on after its HVC.
    Continue,
    /// `SYSTEM_OFF` or a reset: the VM stops, as the guest asked.
    Stop(Stop),
    /// `CPU_SUSPEND`: the vCPU waits as for a WFI, then goes on.
    Suspend,
}

/// Answers a PSCI or SMCCC call as KVM on a Pi 5 does, so a portable guest
/// sees one firmware on every host.
///
/// The answers were measured on rp2 with the firmware bitmaps lowered, as
/// the portable profile sets them on KVM (`portable::psci_features`,
/// `portable::smccc_arch_features`). As there, the function ID is 32 bits
/// and an SMC32 call's arguments are too.
fn service_firmware(vcpu: &Vcpu, sh: &Shared, p: &Portable) -> Firmware {
    let fid = vcpu.get_reg(Reg::X0).unwrap_or(0) as u32;
    let narrow = fid & 0x4000_0000 == 0;
    let arg = |reg| {
        let v = vcpu.get_reg(reg).unwrap_or(0);
        if narrow {
            v & 0xffff_ffff
        } else {
            v
        }
    };
    let ret = match fid {
        fw::SMCCC_VERSION | fw::PSCI_VERSION => fw::VERSION_1_1,
        fw::SMCCC_ARCH_FEATURES => portable::smccc_arch_features(arg(Reg::X1) as u32),
        fw::SMCCC_ARCH_WORKAROUND_1 | fw::SMCCC_ARCH_WORKAROUND_3 => fw::SUCCESS,
        fw::PSCI_FEATURES => portable::psci_features(arg(Reg::X1) as u32),
        fw::CPU_SUSPEND_32 | fw::CPU_SUSPEND_64 => {
            // KVM treats every power state as a standby, a WFI.
            let _ = vcpu.set_reg(Reg::X0, fw::SUCCESS);
            return Firmware::Suspend;
        }
        // As on the native machine, the vCPU goes on running.
        fw::CPU_OFF => fw::SUCCESS,
        fw::CPU_ON_32 | fw::CPU_ON_64 => cpu_on(sh, p, arg(Reg::X1), arg(Reg::X2), arg(Reg::X3)),
        fw::AFFINITY_INFO_32 | fw::AFFINITY_INFO_64 => affinity_info(p, arg(Reg::X1), arg(Reg::X2)),
        fw::MIGRATE_INFO_TYPE => fw::MIGRATE_NOT_REQUIRED,
        fw::SYSTEM_OFF => return Firmware::Stop(Stop::SystemOff),
        fw::SYSTEM_RESET => return Firmware::Stop(Stop::SystemReset),
        fw::SYSTEM_RESET2_32 | fw::SYSTEM_RESET2_64 => {
            // The architectural warm reset (0) or a vendor reset.
            let kind = arg(Reg::X1);
            if kind == 0 || kind >= 0x8000_0000 {
                return Firmware::Stop(Stop::SystemReset);
            }
            fw::INVALID_PARAMETERS
        }
        _ => fw::NOT_SUPPORTED,
    };
    let _ = vcpu.set_reg(Reg::X0, ret);
    Firmware::Continue
}

/// The affinity bits of an MPIDR.
const MPIDR_HWID: u64 = 0xff_00ff_ffff;

/// `CPU_ON`: starts the secondary whose MPIDR is `target`.
fn cpu_on(sh: &Shared, p: &Portable, target: u64, entry: u64, ctx: u64) -> u64 {
    if target & !MPIDR_HWID != 0 {
        return fw::INVALID_PARAMETERS;
    }
    // Each vCPU's affinity is its index in aff0.
    let idx = target as usize;
    let Some(on) = p.on.get(idx) else {
        return fw::INVALID_PARAMETERS;
    };
    if on.swap(true, Ordering::SeqCst) {
        return fw::ALREADY_ON;
    }
    let sec = &sh.guest.vcpus.kicker().secondaries[idx];
    *lock_or_recover(&sec.mbox) = Some((entry, ctx));
    sec.cv.notify_all();
    fw::SUCCESS
}

/// `AFFINITY_INFO`: whether any vCPU whose MPIDR matches `target` from
/// affinity level `level` up is on, as KVM's `kvm_psci_vcpu_affinity_info`
/// answers it.
fn affinity_info(p: &Portable, target: u64, level: u64) -> u64 {
    if level > 3 || target & !MPIDR_HWID != 0 {
        return fw::INVALID_PARAMETERS;
    }
    // Levels 0-2 are bytes 0-2 of the MPIDR, level 3 is byte 4.
    let shift = ((1u64 << level) >> 1) << 3;
    let mask = MPIDR_HWID & !((1u64 << shift) - 1);
    let matching: Vec<&AtomicBool> =
        p.on.iter()
            .enumerate()
            .filter(|(cpu, _)| (*cpu as u64 & mask) == (target & mask))
            .map(|(_, on)| on)
            .collect();
    if matching.is_empty() {
        fw::INVALID_PARAMETERS
    } else if matching.iter().any(|on| on.load(Ordering::SeqCst)) {
        fw::AFFINITY_ON
    } else {
        fw::AFFINITY_OFF
    }
}

/// Services a PL011 MMIO access.
fn service_uart(vcpu: &Vcpu, sh: &Shared, offset: u64, syndrome: u64) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    let mut p = lock_or_recover(&sh.pl011);
    if da.is_write {
        let v = read_gpr(vcpu, da.reg);
        p.mmio(offset, true, v);
    } else {
        let v = p.mmio(offset, false, 0) & width_mask(da.width);
        write_gpr(vcpu, da.reg, v);
    }
}

/// Services a virtio-blk MMIO access and drains its captured events.
fn service_dev(vcpu: &Vcpu, sh: &Shared, dev: &Arc<Mutex<VirtioBlk>>, offset: u64, syndrome: u64) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    let events = {
        let mut d = lock_or_recover(dev);
        if da.is_write {
            let v = read_gpr(vcpu, da.reg);
            d.mmio(&sh.guest.ram, offset, true, v);
        } else {
            let v = d.mmio(&sh.guest.ram, offset, false, 0) & width_mask(da.width);
            write_gpr(vcpu, da.reg, v);
        }
        d.take_events()
    };
    if !events.is_empty() {
        let mut e = lock_or_recover(&sh.guest.ledger);
        for ev in &events {
            e.captured(ev);
        }
    }
}

/// Services a virtio-net MMIO access (same shape as `service_dev`).
fn service_net(vcpu: &Vcpu, sh: &Shared, dev: &Arc<Mutex<VirtioNet>>, offset: u64, syndrome: u64) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    let events = {
        let mut d = lock_or_recover(dev);
        if da.is_write {
            let v = read_gpr(vcpu, da.reg);
            d.mmio(&sh.guest.ram, offset, true, v);
        } else {
            let v = d.mmio(&sh.guest.ram, offset, false, 0) & width_mask(da.width);
            write_gpr(vcpu, da.reg, v);
        }
        d.take_events()
    };
    if !events.is_empty() {
        let mut e = lock_or_recover(&sh.guest.ledger);
        for ev in &events {
            e.captured(ev);
        }
    }
}

/// Services a virtio-vsock MMIO access.
fn service_vsock(
    vcpu: &Vcpu,
    sh: &Shared,
    dev: &Arc<Mutex<VirtioVsock>>,
    offset: u64,
    syndrome: u64,
) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    let mut d = lock_or_recover(dev);
    if da.is_write {
        let v = read_gpr(vcpu, da.reg);
        d.mmio(&sh.guest.ram, offset, true, v);
    } else {
        let v = d.mmio(&sh.guest.ram, offset, false, 0) & width_mask(da.width);
        write_gpr(vcpu, da.reg, v);
    }
}

/// Services a virtio-fs MMIO transport access.
///
/// Every register is served here under the device mutex, as for the other
/// virtio devices. A `QUEUE_NOTIFY` write only records the queue index in
/// `mmio`, so this then serves a shallow queue at once and wakes the device's
/// worker thread, `run_fs_worker`, for the rest.
///
/// The device sets its line in `mmio` and at the end of every drain. Both run
/// under the device mutex, so the line follows the last change to the interrupt
/// status.
fn service_fs(vcpu: &Vcpu, sh: &Shared, fs: &SharedFs, offset: u64, syndrome: u64) {
    let da = DataAbort::from_syndrome(syndrome);
    if !da.isv {
        return;
    }
    let is_notify = da.is_write && offset == mmio::QUEUE_NOTIFY;
    {
        let mut d = lock_or_recover(&fs.dev);
        if da.is_write {
            let v = read_gpr(vcpu, da.reg);
            d.mmio(&sh.guest.ram, offset, true, v);
        } else {
            let v = d.mmio(&sh.guest.ram, offset, false, 0) & width_mask(da.width);
            write_gpr(vcpu, da.reg, v);
        }
    }
    if is_notify {
        // Service a shallow queue right here rather than paying a thread
        // handoff for it. Waking the worker costs ~20us of park/unpark and
        // context switch, against ~7us of host time for a 4 KiB write, so
        // handing every request over made small-write workloads 2.6x slower
        // than the pre-worker code. Anything past the budget goes to the
        // worker, which is where a deep queue belongs: the handoff is
        // amortised and the vCPU gets to run the guest while it drains.
        let remaining =
            lock_or_recover(&fs.dev).drain_notified_bounded(&sh.guest.ram, FS_INLINE_BUDGET);
        if remaining {
            fs.wake.wake();
        }
    }
}

/// Runs a virtio-fs device's FUSE servicing on the calling thread, the device's
/// worker thread.
///
/// `service_fs` serves a shallow queue on the vCPU and wakes this thread for
/// the rest, which makes every host syscall those requests need. A deep queue
/// then never holds a vCPU on the host filesystem, and the guest can keep more
/// than one request in flight.
///
/// Each device has one worker, since a single mutex guards all of its
/// `VirtioFs` state. `drain_notified` empties every flagged queue under that
/// mutex, and the device sets its line at the end of the pass. So a pass raises
/// the line and kicks the vCPUs at most once, however many requests it served.
///
/// `wake.park()` waits on a predicate and a `Condvar` (see `FsWake`), and the
/// vCPU thread signals whenever its inline drain leaves work. A notify that
/// races the loop is either served by the drain in progress, since both sides
/// take the device mutex, or seen by the next `park()`. The mutex is held only
/// for the drain, never across `park()`.
///
/// [`FsWake::stop`], which runs once the vCPUs have exited or been left
/// running, ends the loop at the next `park`. The worker then drains the chains
/// announced by a wake that arrived with the stop.
///
/// Each drain passes the pause gate of `stop` first, so a pause holds the
/// worker back between drains. The worker parks outside the gate.
fn run_fs_worker(dev: &Mutex<VirtioFs>, mem: &GuestRam, wake: &FsWake, stop: &StopToken) {
    while wake.park() {
        let _in = stop.enter();
        lock_or_recover(dev).drain_notified(mem);
    }
    // A wake that arrived with the stop was cleared by that last `park`, and
    // the chains it announced are still in the ring, so one unbounded pass
    // drains them. A vCPU left running at its join deadline that is still in
    // `service_fs` can leave chains past its inline budget after this pass,
    // with no worker to serve them. Only a run that already fails does that.
    lock_or_recover(dev).drain_notified(mem);
}

/// Zero-extension mask for a load of `width` bytes.
fn width_mask(width: u8) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (width * 8)) - 1
    }
}

/// Reads general-purpose register `idx` (31 = XZR, reads as 0).
fn read_gpr(vcpu: &Vcpu, idx: u8) -> u64 {
    gpr(idx).map_or(0, |r| vcpu.get_reg(r).unwrap_or(0))
}

/// Writes `value` to general-purpose register `idx` (31 = XZR, discarded).
fn write_gpr(vcpu: &Vcpu, idx: u8, value: u64) {
    if let Some(r) = gpr(idx) {
        let _ = vcpu.set_reg(r, value);
    }
}

/// Advances PC past a 4-byte instruction (restartable exceptions only).
fn advance_pc(vcpu: &Vcpu) {
    let pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
    let _ = vcpu.set_reg(Reg::PC, pc + 4);
}

/// Rounds `v` down to a multiple of `align` (a power of two).
fn align_down(v: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    v & !(align - 1)
}

/// Maps a data-abort source-register index (`SRT`) to an `applevisor` register.
fn gpr(idx: u8) -> Option<Reg> {
    Some(match idx {
        0 => Reg::X0,
        1 => Reg::X1,
        2 => Reg::X2,
        3 => Reg::X3,
        4 => Reg::X4,
        5 => Reg::X5,
        6 => Reg::X6,
        7 => Reg::X7,
        8 => Reg::X8,
        9 => Reg::X9,
        10 => Reg::X10,
        11 => Reg::X11,
        12 => Reg::X12,
        13 => Reg::X13,
        14 => Reg::X14,
        15 => Reg::X15,
        16 => Reg::X16,
        17 => Reg::X17,
        18 => Reg::X18,
        19 => Reg::X19,
        20 => Reg::X20,
        21 => Reg::X21,
        22 => Reg::X22,
        23 => Reg::X23,
        24 => Reg::X24,
        25 => Reg::X25,
        26 => Reg::X26,
        27 => Reg::X27,
        28 => Reg::X28,
        29 => Reg::X29,
        30 => Reg::X30,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ISS of a guest `mrs x3, cntpct_el0` without hv_gic, as measured on
    /// an M5 (`S3_3_C14_C0_1`, Rt 3, read).
    const CNTPCT_READ_X3: u64 = 0x032_f861;

    #[test]
    fn physical_counter_reads_are_recognised() {
        assert!(is_physical_counter(CNTPCT_READ_X3));
        // CNTPCTSS_EL0 is op2 5.
        let cntpctss = (CNTPCT_READ_X3 & !(7 << 17)) | (5 << 17);
        assert!(is_physical_counter(cntpctss));
        // CNTVCT_EL0 (op2 2) and a write are not.
        assert!(!is_physical_counter(
            (CNTPCT_READ_X3 & !(7 << 17)) | (2 << 17)
        ));
        assert!(!is_physical_counter(CNTPCT_READ_X3 & !1));
        assert_eq!((CNTPCT_READ_X3 >> 5) & 0x1f, 3);
    }

    /// The SDK's `HV_INTERRUPT_TYPE_IRQ` is 0. If applevisor-sys ever fixes
    /// its order, this fails before a guest gets an FIQ for every interrupt.
    #[test]
    fn the_irq_line_has_the_sdk_value_of_irq() {
        assert_eq!(IRQ_LINE as u32, 0);
    }

    #[test]
    fn baseline_registers_are_written_in_the_order_they_are_named() {
        for ((name, _), reg) in portable::BASELINE.iter().zip(BASELINE_REGS) {
            assert_eq!(format!("{reg:?}"), *name);
        }
    }

    /// A portable machine with one vCPU per entry of `on`, which says
    /// whether PSCI reports it on.
    fn machine(on: &[bool]) -> Portable {
        Portable {
            gic: Mutex::new(Gicv2::new(on.len() as u32)),
            layout: GicLayout::QEMU_VIRT_V2,
            timebase: (125, 3),
            on: on.iter().map(|&b| AtomicBool::new(b)).collect(),
            refused: Mutex::new(None),
        }
    }

    #[test]
    fn the_gic_window_covers_the_distributor_and_the_cpu_interface() {
        let p = machine(&[true]);
        assert!(p.in_gic(0x0800_0000) && p.in_gic(0x0801_ffff));
        assert!(!p.in_gic(0x0802_0000) && !p.in_gic(0x07ff_fffc));
    }

    use crate::config::CachePolicy;
    use std::time::{Duration, Instant};

    // A worker stuck in a host call holds the device past the stop deadline.
    // The report must not wait for it, or `boot` never returns the error that
    // names the worker.
    #[test]
    fn report_fs_usage_skips_a_device_another_thread_holds() {
        let dir = std::env::temp_dir().join(format!("hvi-fs-usage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();
        let dev = Arc::new(Mutex::new(
            VirtioFs::new(root, "share", false, CachePolicy::Auto).unwrap(),
        ));
        let (held, holding) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let worker = {
            let dev = Arc::clone(&dev);
            std::thread::spawn(move || {
                let _device = dev.lock().unwrap();
                held.send(()).unwrap();
                let _ = released.recv();
            })
        };
        holding.recv().unwrap();
        let report = {
            let dev = Arc::clone(&dev);
            std::thread::spawn(move || report_fs_usage(0, &dev))
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        while !report.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let finished = report.is_finished();
        release.send(()).unwrap();
        worker.join().unwrap();
        report.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(finished, "the report waited for the device");
    }

    #[test]
    fn affinity_info_follows_the_affinity_level() {
        let p = machine(&[true, false]);
        assert_eq!(affinity_info(&p, 0, 0), fw::AFFINITY_ON);
        assert_eq!(affinity_info(&p, 1, 0), fw::AFFINITY_OFF);
        // At level 1 the target names the whole cluster, which cpu0 is in.
        assert_eq!(affinity_info(&p, 1, 1), fw::AFFINITY_ON);
        assert_eq!(affinity_info(&p, 0, 4), fw::INVALID_PARAMETERS);
        // No vCPU has that affinity, or the target has bits outside it.
        assert_eq!(affinity_info(&p, 5, 0), fw::INVALID_PARAMETERS);
        assert_eq!(affinity_info(&p, 0x8000_0000, 0), fw::INVALID_PARAMETERS);
    }
}

//! The extension seam: how a tool outside the exit loop reaches a running
//! guest.
//!
//! A VMM is a useful place to stand. It holds the guest's memory, it can park
//! the vCPUs between guest entries, and it is the other end of every virtio
//! request the guest makes. Debuggers, tracers, profilers and crash-dumpers all
//! want one or more of those, and none of them belongs in the exit loop.
//!
//! So the exit loop offers them instead. An
//! [`Plugin`](crate::plugin::Plugin) is called at two points — once at
//! boot, and on the boot vCPU between guest entries — and from there it can
//! read guest RAM, read that vCPU's registers, park the rest of the VM, and
//! subscribe to the device feed. [`crate::plugins`] ships two that use this:
//! a guest-memory dumper and an I/O tracer.
//!
//! These traits describe *access*, and deliberately no more than that. They
//! hand over bytes and register values; what any of it means is the caller's
//! problem, which is what keeps a tool's idea of the guest out of the VMM.
//!
//! The whole seam is optional. With no plugin the hooks are one null check
//! on a cold path, the devices hold no sink, and no guest memory is read for
//! any purpose but running the guest.

use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

use crate::events::Emitter;
use crate::guestmem::GuestRam;

/// The guest architecture a backend is running, so a tool can interpret
/// [`RegsView`] correctly without guessing it from the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestArch {
    /// arm64 guest (Hypervisor.framework on macOS, or KVM on Linux).
    Aarch64,
    /// x86-64 guest (KVM on Linux).
    X86_64,
}

/// A guest-physical span of the VM's RAM and where it sits in the backing
/// object, so a process that maps the same object sees the same bytes.
#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    /// Guest-physical address this span starts at.
    pub gpa: u64,
    /// Length in bytes.
    pub size: u64,
    /// Offset of `gpa` within the shareable backing object.
    pub file_offset: u64,
}

/// A parked vCPU's register state, as much of it as a tool outside the exit
/// loop has any business seeing.
///
/// `root` is the architectural translation-base register — TTBR1_EL1 on arm64,
/// CR3 on x86-64 — named once here so a tool needs no per-backend special
/// case. The arm64-specific registers are zero on x86-64.
#[derive(Default, Clone, Copy)]
pub struct RegsView {
    /// Translation-base register: TTBR1_EL1 (arm64) or CR3 (x86-64).
    pub root: u64,
    pub pc: u64,
    pub cpsr: u64,
    pub ttbr0: u64,
    pub ttbr1: u64,
    pub sctlr: u64,
    pub sp_el1: u64,
    /// Translation control: TCR_EL1 (arm64), naming the granule and address
    /// size an out-of-VMM walker needs to size the page tables rather than
    /// assume a layout. Zero on x86-64.
    pub tcr: u64,
    /// The task the vCPU is running: `SP_EL0` on arm64 (Linux keeps `current`
    /// there while in the kernel), from which a walker recovers the KASLR slide
    /// by climbing `real_parent` to `init_task`. Zero on x86-64.
    pub current_task: u64,
}

/// What the VMM offers a plugin once, during boot, before any vCPU starts.
///
/// This is where a plugin picks up the guest RAM (and the descriptor for it,
/// if it intends to share it with another process) and installs its device
/// sinks.
///
/// It is handed over as an `Arc`, so a plugin that runs its own threads --
/// a timer, a doorbell -- can keep it and call [`VmHandle::kick`] from them.
pub trait VmHandle: Send + Sync {
    /// The guest architecture this VM is running.
    fn arch(&self) -> GuestArch;

    /// The sandbox identifier this VM was started with.
    fn sandbox_id(&self) -> &str;

    /// Accessor over the guest's RAM. Valid for the lifetime of the VM.
    fn ram(&self) -> &GuestRam;

    /// Descriptor of the object backing guest RAM.
    ///
    /// Guest RAM is allocated from something nameable (see
    /// [`crate::sharedmem`]), so a tool can map its own view of it rather than
    /// borrowing the VMM's. [`crate::plugins::MemoryDump`] maps a read-only
    /// one, which is what makes it structurally unable to corrupt the guest it
    /// is dumping.
    fn ram_fd(&self) -> RawFd;

    /// Where the guest's RAM sits, in guest-physical terms and in the backing
    /// object. More than one region on backends that punt a hole in RAM.
    fn ram_regions(&self) -> Vec<MemRegion>;

    /// The `RawEvent` ledger, so a plugin's own records land in the same
    /// stream as the VMM's device observations.
    fn ledger(&self) -> &Arc<Mutex<Emitter>>;

    /// Whether this VM has a virtio-blk device.
    fn has_block(&self) -> bool;

    /// Whether this VM has a virtio-net device.
    fn has_net(&self) -> bool;

    /// Feeds every virtio-blk request to `sink`. No-op with no block device.
    fn set_block_sink(&self, sink: Arc<dyn IoSink>);

    /// Feeds every virtio-net frame to `sink`. No-op with no net device.
    fn set_net_sink(&self, sink: Arc<dyn IoSink>);

    /// Breaks every vCPU out of the hypervisor so each reaches its next safe
    /// point promptly.
    ///
    /// A plugin that sets a pending flag from its own thread **must** call
    /// this afterwards: an idle guest sits in WFI/HLT indefinitely, and
    /// [`Plugin::safepoint`] is only reached between guest entries. Without
    /// the kick a request against an idle guest waits for the next timer tick,
    /// or never lands at all.
    fn kick(&self);
}

/// What the VMM offers a plugin at a vCPU safe point.
///
/// Only the boot vCPU calls [`Plugin::safepoint`], and only between guest
/// entries — so the vCPU is parked, and reading its registers is sound.
pub trait CpuHandle {
    /// The guest architecture this vCPU is running.
    fn arch(&self) -> GuestArch;

    /// Accessor over the guest's RAM.
    fn ram(&self) -> &GuestRam;

    /// This vCPU's registers. Cheap: no other vCPU is parked for it, so the
    /// values are consistent for this CPU only. Call [`CpuHandle::pause`] first
    /// if you need the whole VM to be still.
    fn regs(&self) -> RegsView;

    /// Parks every *other* vCPU at its safe point and returns `true` once they
    /// are all there.
    ///
    /// Returns `false` if they did not all park, in which case the quiesce has
    /// already been released and the caller owes nothing. On `true` the caller
    /// owes exactly one [`CpuHandle::resume`] — including on any early return
    /// between the two, or the VM stays parked forever.
    fn pause(&self) -> bool;

    /// Releases the vCPUs parked by a successful [`CpuHandle::pause`].
    fn resume(&self);

    /// The `RawEvent` ledger.
    fn ledger(&self) -> &Arc<Mutex<Emitter>>;
}

/// A tool attached to a running guest.
///
/// Both hooks default to doing nothing, so an implementation takes only what it
/// needs. The VMM calls [`Plugin::safepoint`] on the boot vCPU between guest
/// entries; it is on the hot path, so an implementation that has nothing to do
/// this time round should say so with a single atomic load and return.
pub trait Plugin: Send + Sync {
    /// Called once during boot, before any vCPU runs.
    ///
    /// # Errors
    ///
    /// Returning an error fails the boot: a plugin that cannot attach is
    /// reported rather than silently producing nothing.
    fn attach(&self, vmm: Arc<dyn VmHandle>) -> std::io::Result<()> {
        let _ = vmm;
        Ok(())
    }

    /// Called on the boot vCPU between guest entries, with the vCPU parked.
    fn safepoint(&self, cpu: &dyn CpuHandle) {
        let _ = cpu;
    }

    /// An out-of-band trigger asked for an observation now — the console's
    /// interrupt key today. The VMM only calls this; deciding what "now" means
    /// (and kicking the vCPUs, via [`VmHandle::kick`]) is the plugin's.
    fn request(&self) {}
}

/// A per-request feed of a virtio device's I/O.
///
/// The VMM already records these in its ledger; a sink is for a tool that wants
/// them live and unaggregated, as [`crate::plugins::IoTrace`] does. Both
/// methods are called from the vCPU thread with the device lock held, so an
/// implementation must not block.
pub trait IoSink: Send + Sync {
    /// A virtio-blk request: starting `sector`, `length` data bytes, and
    /// direction. `disk_id` distinguishes backing devices.
    fn block(&self, sector: u64, length: u64, disk_id: u64, write: bool);

    /// A virtio-net frame, as it crosses the device. `egress` is guest-to-host.
    fn net(&self, frame: &[u8], egress: bool);
}

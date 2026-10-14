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

//! The guest, as every backend holds it and as a plugin reaches it.
//!
//! [`Guest`] holds what each backend keeps about the VM it runs, apart from the
//! hypervisor's own handle and the devices not every backend has: guest RAM and
//! the object behind it, the event ledger, the virtio devices, the vCPUs, the
//! threads a plugin asked for and the identity of the run. It is the
//! [`VmHandle`] a plugin gets at attach. [`Cpu`] is the [`CpuHandle`] it gets
//! at a safe point, where only the registers depend on the backend.

use std::cell::Cell;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::checkpoint::cpu::{Output, Work};
use crate::devices::irq::IrqLine;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::net::VirtioNet;
use crate::devices::virtio::vsock::VirtioVsock;
use crate::events::Emitter;
use crate::hypervisor::vcpus::{Kick, Vcpus};
use crate::memory::{GuestRam, GuestWriteLog, SharedRam};
use crate::plugin::{CpuHandle, GuestArch, IoSink, Plugin, RamRegion, RegsView, VmHandle};
use crate::sync::lock_or_recover;
use crate::teardown::StopToken;

/// The guest a backend runs, apart from the hypervisor's handle to it.
pub(crate) struct Guest<K> {
    /// The guest architecture.
    pub(crate) arch: GuestArch,
    /// The sandbox identifier the VM was started with.
    pub(crate) sandbox_id: String,
    /// Guest RAM.
    pub(crate) ram: Arc<GuestRam>,
    /// The object backing guest RAM, for a plugin that hands the same pages to
    /// another process.
    pub(crate) shared_ram: SharedRam,
    /// The `RawEvent` ledger.
    pub(crate) ledger: Arc<Mutex<Emitter>>,
    /// The virtio-blk device, when the VM has a disk.
    pub(crate) block: Option<Arc<Mutex<VirtioBlk>>>,
    /// The virtio-net device, when the VM has a network.
    pub(crate) net: Option<Arc<Mutex<VirtioNet>>>,
    /// The virtio-vsock device, when the VM has an agent socket.
    pub(crate) vsock: Option<Arc<Mutex<VirtioVsock>>>,
    /// The vCPU threads, the stop and the quiesce that parks them.
    pub(crate) vcpus: Arc<Vcpus<K>>,
    /// The hypervisor's record of the guest's own writes to RAM, which a
    /// live move reads beside guest RAM's log of hvi's.
    pub(crate) write_log: Option<Arc<dyn GuestWriteLog>>,
    /// The threads a plugin asks for in `attach`, until the attach is over.
    pub(crate) plugin_threads: PluginThreads,
}

/// A thread a plugin asked for with [`VmHandle::spawn`], not yet started.
pub(crate) struct PluginThread {
    /// The name of the thread, which its failure report also uses.
    pub(crate) name: &'static str,
    /// What the thread runs, given the token of the stop that ends it.
    pub(crate) run: Box<dyn FnOnce(StopToken) + Send>,
}

/// The threads a plugin asks for while it attaches.
///
/// `attach` runs before the seccomp filters are armed, and a thread started
/// then would run unfiltered. So the threads are queued, and the queue is taken
/// once the attach is over. A request after that is refused.
pub(crate) struct PluginThreads(Mutex<Option<Vec<PluginThread>>>);

impl PluginThreads {
    /// Returns an empty queue that takes requests.
    pub(crate) fn new() -> Self {
        Self(Mutex::new(Some(Vec::new())))
    }

    /// Queues `thread`.
    ///
    /// # Errors
    ///
    /// Errors once the queue has been taken, and for a name with a NUL byte,
    /// which a thread cannot be given.
    fn queue(&self, thread: PluginThread) -> std::io::Result<()> {
        if thread.name.contains('\0') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("plugin thread {:?}: a name with a NUL byte", thread.name),
            ));
        }
        match lock_or_recover(&self.0).as_mut() {
            Some(queued) => {
                queued.push(thread);
                Ok(())
            }
            None => Err(std::io::Error::other(format!(
                "plugin thread {}: a plugin starts its threads from attach",
                thread.name
            ))),
        }
    }

    /// Returns the queued threads.
    ///
    /// A request after this call is refused.
    pub(crate) fn take(&self) -> Vec<PluginThread> {
        lock_or_recover(&self.0).take().unwrap_or_default()
    }
}

impl<K> Guest<K> {
    /// Connects the virtio devices the VM has to their interrupt lines.
    ///
    /// It takes a line for each virtio device a guest can hold, whether or not
    /// this VM has it, so a backend that leaves one out does not build. The
    /// line of a device the VM does not have is dropped.
    pub(crate) fn connect_irqs(
        &self,
        block: Arc<dyn IrqLine>,
        net: Arc<dyn IrqLine>,
        vsock: Arc<dyn IrqLine>,
    ) {
        if let Some(dev) = &self.block {
            lock_or_recover(dev).connect_irq(block);
        }
        if let Some(dev) = &self.net {
            lock_or_recover(dev).connect_irq(net);
        }
        if let Some(dev) = &self.vsock {
            lock_or_recover(dev).connect_irq(vsock);
        }
    }

    /// Sets each virtio device's line to the device's level, once a restore
    /// has loaded the interrupt controller. See `Irq::redrive`.
    // The HVF restore, which connects the devices before it loads the GIC,
    // calls it; the KVM one connects and drives each line itself.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn redrive_irqs(&self) {
        if let Some(dev) = &self.block {
            lock_or_recover(dev).redrive_irq();
        }
        if let Some(dev) = &self.net {
            lock_or_recover(dev).redrive_irq();
        }
        if let Some(dev) = &self.vsock {
            lock_or_recover(dev).redrive_irq();
        }
    }
}

impl<K: Kick> Guest<K> {
    /// Holds the calling vCPU, `cpu`, at its safe point between guest entries.
    ///
    /// The vCPU parks while a pause is in effect, and does through `serve` the
    /// work the control socket posts to it meanwhile. Then `plugin`, if given,
    /// looks at the guest. Either way the vCPU tells the guest of the time it
    /// sat out. It is on the hot path: with no plugin and no pause, it loads
    /// the quiesce flag and checks a zero duration.
    pub(crate) fn pass_safepoint<V: SafepointVcpu>(
        &self,
        vcpu: &V,
        cpu: u32,
        plugin: Option<&dyn Plugin>,
        serve: impl FnMut(Work<'_>) -> std::io::Result<Option<Output>>,
    ) {
        // A plugin's pause parks only the other vCPUs, so vcpu0 parks here only
        // for the control socket's.
        vcpu.notify_guest_paused(self.vcpus.checkpoint_with(cpu, serve));
        if let Some(plugin) = plugin {
            let cpu = Cpu::new(vcpu, self);
            plugin.safepoint(&cpu);
            // vcpu0 holds each pause rather than parking, so it sat out their
            // time.
            vcpu.notify_guest_paused(cpu.paused_time());
        }
    }
}

impl<K: Kick + 'static> Guest<K> {
    /// Hands `plugin` the guest, when there is one, and returns the threads it
    /// asked for in `attach`.
    ///
    /// The queue is taken whether or not the attach succeeds, so a queued
    /// thread, which can hold the guest, never outlives a failed boot.
    ///
    /// # Errors
    ///
    /// Errors with the plugin's error when it refuses the guest.
    pub(crate) fn attach(
        self: &Arc<Self>,
        plugin: Option<&Arc<dyn Plugin>>,
    ) -> std::io::Result<Vec<PluginThread>> {
        let attached = plugin.map_or(Ok(()), |plugin| {
            plugin.attach(Arc::clone(self) as Arc<dyn VmHandle>)
        });
        let threads = self.plugin_threads.take();
        attached.map(|()| threads)
    }
}

impl<K: Kick> VmHandle for Guest<K> {
    fn arch(&self) -> GuestArch {
        self.arch
    }

    fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    fn ram(&self) -> &GuestRam {
        &self.ram
    }

    fn ram_fd(&self) -> BorrowedFd<'_> {
        self.shared_ram.as_fd()
    }

    fn ram_regions(&self) -> Vec<RamRegion> {
        // Every region, which on x86-64 is both halves around the MMIO hole.
        // Reporting only the low one leaves a plugin mapping less than the
        // guest has and reading nothing above the hole, which looks like an
        // empty guest rather than a missing region.
        self.ram.regions()
    }

    fn ledger(&self) -> &Arc<Mutex<Emitter>> {
        &self.ledger
    }

    fn has_block(&self) -> bool {
        self.block.is_some()
    }

    fn has_net(&self) -> bool {
        self.net.is_some()
    }

    fn set_block_sink(&self, sink: Arc<dyn IoSink>) {
        if let Some(dev) = &self.block {
            lock_or_recover(dev).set_io_sink(sink);
        }
    }

    fn set_net_sink(&self, sink: Arc<dyn IoSink>) {
        if let Some(dev) = &self.net {
            lock_or_recover(dev).set_io_sink(sink);
        }
    }

    fn kick(&self) {
        // vcpu0 is the one that reaches the plugin hook.
        self.vcpus.kicker().kick(0);
    }

    fn request_stop(&self) {
        self.vcpus.stop_handle().request_stop();
    }

    fn spawn(
        &self,
        name: &'static str,
        run: Box<dyn FnOnce(StopToken) + Send>,
    ) -> std::io::Result<()> {
        self.plugin_threads.queue(PluginThread { name, run })
    }
}

/// The vCPU operations a safe point uses, reading its registers for a plugin
/// and telling the guest of a pause.
pub(crate) trait SafepointVcpu {
    /// Returns the registers a plugin walks guest memory with.
    fn regs(&self) -> RegsView;

    /// Notifies the guest that this vCPU was held out of the guest for
    /// `paused_for`, so the guest does not report that time as a lockup.
    ///
    /// Does nothing on a backend that has no way to notify it, or for a time
    /// too short to look like a lockup.
    fn notify_guest_paused(&self, _paused_for: Duration) {}
}

/// The [`CpuHandle`] over the boot vCPU at a safe point.
///
/// It borrows rather than clones, since it lives only for the duration of one
/// `Plugin::safepoint` call.
pub(crate) struct Cpu<'a, K, V> {
    /// The boot vCPU, on its own thread.
    vcpu: &'a V,
    /// The guest it runs.
    guest: &'a Guest<K>,
    /// When the pause in effect began, while one is.
    paused_at: Cell<Option<Instant>>,
    /// The time of the pauses that ended during this safe point.
    paused: Cell<Duration>,
}

impl<'a, K, V> Cpu<'a, K, V> {
    /// Returns the handle over `vcpu`, the boot vCPU of `guest`.
    fn new(vcpu: &'a V, guest: &'a Guest<K>) -> Self {
        Self {
            vcpu,
            guest,
            paused_at: Cell::new(None),
            paused: Cell::new(Duration::ZERO),
        }
    }

    /// Returns the time of the pauses that ended during this safe point.
    fn paused_time(&self) -> Duration {
        self.paused.get()
    }
}

impl<K: Kick, V: SafepointVcpu> CpuHandle for Cpu<'_, K, V> {
    fn arch(&self) -> GuestArch {
        self.guest.arch
    }

    fn ram(&self) -> &GuestRam {
        &self.guest.ram
    }

    fn regs(&self) -> RegsView {
        self.vcpu.regs()
    }

    fn pause(&self) -> bool {
        let start = Instant::now();
        let paused = self.guest.vcpus.pause();
        // A pause inside one in effect keeps the first one's start.
        if paused && self.paused_at.get().is_none() {
            self.paused_at.set(Some(start));
        }
        paused
    }

    fn resume(&self) {
        if let Some(at) = self.paused_at.take() {
            self.paused.set(self.paused.get() + at.elapsed());
        }
        self.guest.vcpus.resume();
    }

    fn is_stopping(&self) -> bool {
        !self.guest.vcpus.is_running()
    }

    fn ledger(&self) -> &Arc<Mutex<Emitter>> {
        &self.guest.ledger
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::run::StopHandle;

    /// A kicker that reaches no thread.
    pub(crate) struct NoopKicker;

    impl Kick for NoopKicker {
        fn kick(&self, _cpu: u32) {}

        fn kick_all(&self) {}
    }

    /// Returns a guest with `count` vCPUs, one megabyte of RAM, no devices and
    /// a ledger that writes nowhere.
    pub(crate) fn guest(count: u32) -> Guest<NoopKicker> {
        let shared_ram = SharedRam::new(RamRegion::ALIGN as usize).unwrap();
        let ram = GuestRam::new(&shared_ram, &[shared_ram.region_at(0)]).unwrap();
        Guest {
            arch: GuestArch::X86_64,
            sandbox_id: String::new(),
            ram: Arc::new(ram),
            shared_ram,
            ledger: Arc::new(Mutex::new(Emitter::new(None, "test").unwrap())),
            block: None,
            net: None,
            vsock: None,
            plugin_threads: PluginThreads::new(),
            vcpus: Arc::new(Vcpus::new(
                count,
                NoopKicker,
                StopHandle::new_pair().unwrap().0,
            )),
            write_log: None,
        }
    }

    /// A boot vCPU that records what the guest is told.
    #[derive(Default)]
    struct RecordingVcpu {
        /// The time of each notice, in order.
        notices: Mutex<Vec<Duration>>,
    }

    impl SafepointVcpu for RecordingVcpu {
        fn regs(&self) -> RegsView {
            RegsView::default()
        }

        fn notify_guest_paused(&self, paused_for: Duration) {
            self.notices.lock().unwrap().push(paused_for);
        }
    }

    /// A plugin that holds two pauses of 10 ms at its safe point.
    struct TwoPauses;

    impl Plugin for TwoPauses {
        fn safepoint(&self, cpu: &dyn CpuHandle) {
            for _ in 0..2 {
                assert!(cpu.pause());
                std::thread::sleep(Duration::from_millis(10));
                cpu.resume();
            }
        }
    }

    #[test]
    fn boot_vcpu_is_told_of_the_pauses_its_safepoint_held() {
        // With one vCPU, the boot vCPU, a pause has no other vCPU to wait for.
        let guest = guest(1);
        let vcpu = RecordingVcpu::default();
        guest.pass_safepoint(&vcpu, 0, Some(&TwoPauses), |_| Ok(None));
        let notices = vcpu.notices.lock().unwrap();
        assert_eq!(notices.len(), 2, "{notices:?}");
        assert_eq!(
            notices[0],
            Duration::ZERO,
            "the checkpoint notice, with no time parked, comes first"
        );
        assert!(notices[1] >= Duration::from_millis(20), "{notices:?}");
    }

    // A thread asked for after `attach` would start under no filter and outside
    // the join, so the request is refused.
    #[test]
    fn plugin_thread_is_refused_once_the_queue_is_taken() {
        let threads = PluginThreads::new();
        threads
            .queue(PluginThread {
                name: "early",
                run: Box::new(|_| {}),
            })
            .unwrap();
        let taken = threads.take();
        assert_eq!(taken.len(), 1);
        let error = threads
            .queue(PluginThread {
                name: "late",
                run: Box::new(|_| {}),
            })
            .expect_err("a thread was queued after the attach");
        assert!(
            error.to_string().starts_with("plugin thread late"),
            "{error}"
        );
        assert!(threads.take().is_empty());
    }

    // `std::thread::Builder` panics on such a name, in `boot`, after other
    // threads have started.
    #[test]
    fn plugin_thread_with_a_nul_in_its_name_is_refused() {
        let threads = PluginThreads::new();
        let error = threads
            .queue(PluginThread {
                name: "bad\0name",
                run: Box::new(|_| {}),
            })
            .expect_err("a name with a NUL byte was queued");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(threads.take().is_empty());
    }
}

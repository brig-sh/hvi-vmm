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
//! the object behind it, the event ledger, the virtio devices, the vCPUs and
//! the identity of the run. It is the [`VmHandle`] a plugin gets at attach.
//! [`Cpu`] is the [`CpuHandle`] it gets at a safe point, where only the
//! registers depend on the backend.

use std::os::fd::{AsFd, BorrowedFd};
use std::sync::{Arc, Mutex};

use crate::devices::irq::IrqLine;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::net::VirtioNet;
use crate::devices::virtio::vsock::VirtioVsock;
use crate::events::Emitter;
use crate::hypervisor::vcpus::{Kick, Vcpus};
use crate::memory::{GuestRam, SharedRam};
use crate::plugin::{CpuHandle, GuestArch, IoSink, RamRegion, RegsView, VmHandle};
use crate::sync::lock_or_recover;

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
        // cpu0 is the one that reaches the plugin hook.
        self.vcpus.kicker().kick(0);
    }
}

/// Access to a vCPU's registers for a plugin at a safe point.
pub(crate) trait VcpuRegs {
    /// Returns the registers a plugin walks guest memory with.
    fn regs(&self) -> RegsView;
}

/// The [`CpuHandle`] over the boot vCPU at a safe point.
///
/// It borrows rather than clones, since it lives only for the duration of one
/// `Plugin::safepoint` call.
pub(crate) struct Cpu<'a, K, V> {
    /// The boot vCPU, on its own thread.
    pub(crate) vcpu: &'a V,
    /// The guest it runs.
    pub(crate) guest: &'a Guest<K>,
}

impl<K: Kick, V: VcpuRegs> CpuHandle for Cpu<'_, K, V> {
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
        self.guest.vcpus.pause()
    }

    fn resume(&self) {
        self.guest.vcpus.resume();
    }

    fn ledger(&self) -> &Arc<Mutex<Emitter>> {
        &self.guest.ledger
    }
}

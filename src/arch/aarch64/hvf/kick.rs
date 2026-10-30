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

//! The kick of Hypervisor.framework vCPUs, with their handles, the secondaries'
//! `CPU_ON` mailboxes, and the vCPU each thread runs.

use std::sync::{Condvar, Mutex};

use applevisor::prelude::{Vcpu, VcpuHandle};

use super::gic::VmGic;
use crate::hypervisor::vcpus::Kick;

/// A secondary vCPU's start mailbox, filled by a PSCI `CPU_ON`.
struct Secondary {
    /// The posted entry point and context id, `None` until a `CPU_ON`.
    mbox: Mutex<Option<(u64, u64)>>,
    /// The condition variable notified when the mailbox changes or at the stop.
    cv: Condvar,
}

/// The [`Kick`] implementation for Hypervisor.framework vCPUs.
///
/// A kick is `hv_vcpus_exit`. It ends a run in progress, and one that reaches a
/// vCPU outside its run stays pending and ends its next run at once. A
/// secondary that waits for `CPU_ON` is in no run, so the stop also wakes its
/// mailbox.
pub(super) struct Kicker {
    /// The VM the vCPUs belong to.
    vm: VmGic,
    /// Each vCPU's handle indexed by vCPU id, `None` until its thread has
    /// created the vCPU and again once its registration is dropped.
    handles: Mutex<Vec<Option<VcpuHandle>>>,
    /// The `CPU_ON` mailboxes of the secondaries.
    secondaries: Vec<Secondary>,
}

impl Kicker {
    /// Returns a table for `count` vCPUs of `vm`, none of them registered and
    /// no `CPU_ON` posted.
    pub(super) fn new(vm: VmGic, count: u32) -> Self {
        Self {
            vm,
            handles: Mutex::new((0..count).map(|_| None).collect()),
            secondaries: (0..count)
                .map(|_| Secondary {
                    mbox: Mutex::new(None),
                    cv: Condvar::new(),
                })
                .collect(),
        }
    }

    /// Posts a PSCI `CPU_ON` to vCPU `cpu`.
    ///
    /// It wakes the secondary, which starts at `entry` with context id
    /// `context`. It returns `false` and posts nothing for vCPU 0, which is not
    /// a secondary, and for an id past the last vCPU.
    pub(super) fn cpu_on(&self, cpu: u32, entry: u64, context: u64) -> bool {
        let Some(secondary) = self.secondaries.get(cpu as usize).filter(|_| cpu != 0) else {
            return false;
        };
        *secondary.mbox.lock().unwrap() = Some((entry, context));
        secondary.cv.notify_all();
        true
    }

    /// Returns the entry point and context id of secondary `cpu`'s `CPU_ON`
    /// once one is posted, or `None` if `running` returns `false` first.
    ///
    /// A `CPU_ON` posted before the stop is still returned after it. The stop
    /// wakes the wait through [`Kick::kick_halted`] or [`Kick::try_kick_all`].
    pub(super) fn wait_for_cpu_on(
        &self,
        cpu: u32,
        running: impl Fn() -> bool,
    ) -> Option<(u64, u64)> {
        let secondary = &self.secondaries[cpu as usize];
        let mut mbox = secondary.mbox.lock().unwrap();
        while mbox.is_none() && running() {
            mbox = secondary.cv.wait(mbox).unwrap();
        }
        mbox.take()
    }

    /// Registers `vcpu`, which the calling thread created, as vCPU `cpu`.
    ///
    /// It also records the vCPU as the calling thread's own, so a kick from
    /// this thread leaves it out. The returned guard removes the entry when
    /// dropped, and must drop before the vCPU does.
    pub(super) fn register(&self, cpu: u32, vcpu: &Vcpu) -> Registration<'_> {
        OWN_VCPU.with(|own| own.set(Some(vcpu.id())));
        if let Some(slot) = self.handles.lock().unwrap().get_mut(cpu as usize) {
            *slot = Some(vcpu.get_handle());
        }
        Registration { kicker: self, cpu }
    }

    /// Ends the current or next run of every vCPU in `handles` but the caller's
    /// own.
    ///
    /// `handles` is the locked table, so no vCPU in the list is destroyed
    /// before the kick.
    fn kick_others(&self, handles: &[Option<VcpuHandle>]) {
        // A cancel a vCPU sends itself stays pending and ends its next run
        // before the guest ran, so a plugin that kicked from `on_safepoint`
        // would run again at once.
        let own = OWN_VCPU.get();
        let others: Vec<VcpuHandle> = handles
            .iter()
            .flatten()
            .filter(|handle| Some(handle.id()) != own)
            .cloned()
            .collect();
        let _ = self.vm.vcpus_exit(&others);
    }
}

/// A vCPU's entry in a [`Kicker`], removed when dropped.
///
/// A kick sends `hv_vcpus_exit` one list of handles, so a handle to a destroyed
/// vCPU in the table would fail the kick of every other vCPU in the list.
pub(super) struct Registration<'a> {
    /// The table the entry is in.
    kicker: &'a Kicker,
    /// The vCPU id of the entry.
    cpu: u32,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self
            .kicker
            .handles
            .lock()
            .unwrap()
            .get_mut(self.cpu as usize)
        {
            *slot = None;
        }
    }
}

impl Kick for Kicker {
    fn kick(&self, cpu: u32) {
        let own = OWN_VCPU.with(std::cell::Cell::get);
        if let Some(Some(handle)) = self.handles.lock().unwrap().get(cpu as usize) {
            if Some(handle.id()) != own {
                let _ = self.vm.vcpus_exit(std::slice::from_ref(handle));
            }
        }
    }

    fn kick_all(&self) {
        self.kick_others(&self.handles.lock().unwrap());
    }

    fn kick_halted(&self) {
        for secondary in self.secondaries.iter() {
            // The lock is taken so a secondary cannot be between its check of
            // the running flag and its wait when the notify lands.
            let _mbox = secondary.mbox.lock().unwrap();
            secondary.cv.notify_all();
        }
    }

    fn try_kick_all(&self) -> bool {
        let mut kicked = match self.handles.try_lock() {
            Ok(handles) => {
                self.kick_others(&handles);
                true
            }
            Err(_) => false,
        };
        for secondary in self.secondaries.iter() {
            match secondary.mbox.try_lock() {
                Ok(_mbox) => secondary.cv.notify_all(),
                Err(_) => kicked = false,
            }
        }
        kicked
    }
}

thread_local! {
    /// The handle id of this thread's vCPU, so a kick can leave it out.
    static OWN_VCPU: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Returns whether the calling thread runs a vCPU.
pub(super) fn on_vcpu_thread() -> bool {
    OWN_VCPU.with(std::cell::Cell::get).is_some()
}

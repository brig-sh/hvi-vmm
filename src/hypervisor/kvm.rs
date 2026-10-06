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

//! The code the two KVM backends share.
//!
//! [`Kicker`] ends a vCPU's `KVM_RUN` from another thread. The kick signal
//! alone is not enough: one that lands while the thread is in user space,
//! between its check of the running flag and its `KVM_RUN`, is consumed by the
//! handler and the run goes ahead. So a kick first sets the vCPU's
//! `kvm_run.immediate_exit` byte, which makes the next `KVM_RUN` return `EINTR`
//! at once, and then sends the signal for a run already in progress.

use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use kvm_ioctls::{VcpuFd, VmFd};

use crate::hypervisor::guest::{Cpu, Guest};
use crate::hypervisor::vcpus::Kick;
use crate::plugin::Plugin;
use crate::sandbox::seccomp;
use crate::signal::kick_signal;
use crate::sync::lock_or_recover;

/// The [`Kick`] implementation for KVM vCPUs.
///
/// It holds each vCPU's thread and a second handle to the vCPU. A kick sets
/// `immediate_exit` through the handle and then signals the thread.
pub(crate) struct Kicker {
    /// The vCPU threads indexed by vCPU id, each `None` until its thread
    /// registers and again once the registration is dropped.
    threads: Mutex<Vec<Option<VcpuThread>>>,
}

impl Kicker {
    /// Returns a table for `count` vCPU threads, none of them registered.
    pub(crate) fn new(count: u32) -> Self {
        Self {
            threads: Mutex::new((0..count).map(|_| None).collect()),
        }
    }

    /// Registers the calling thread as vCPU `cpu`, to be kicked through `vcpu`.
    ///
    /// `vcpu` is a second handle to the vCPU, from [`kick_handle`]. The
    /// returned guard removes the entry when dropped. The thread must clear its
    /// own `immediate_exit` byte before each read of the running flag, so a
    /// kick that lands after the clear ends the run that follows.
    pub(crate) fn register(&self, cpu: u32, vcpu: VcpuFd) -> Registration<'_> {
        let thread = VcpuThread {
            // SAFETY: pthread_self is always valid on the current thread.
            tid: unsafe { libc::pthread_self() } as u64,
            vcpu,
        };
        if let Some(slot) = lock_or_recover(&self.threads).get_mut(cpu as usize) {
            *slot = Some(thread);
        }
        Registration { kicker: self, cpu }
    }
}

impl Kick for Kicker {
    fn kick(&self, cpu: u32) {
        if let Some(Some(thread)) = lock_or_recover(&self.threads).get_mut(cpu as usize) {
            thread.kick();
        }
    }

    fn kick_all(&self) {
        for thread in lock_or_recover(&self.threads).iter_mut().flatten() {
            thread.kick();
        }
    }
}

/// A vCPU thread as the other threads reach it.
struct VcpuThread {
    /// The pthread handle the signal goes to, as an integer.
    tid: u64,
    /// The second handle to the vCPU, from [`kick_handle`].
    vcpu: VcpuFd,
}

impl VcpuThread {
    /// Ends the thread's current or next `KVM_RUN`, unless the caller is the
    /// thread itself.
    fn kick(&mut self) {
        // A kick from the thread itself, from a plugin's `safepoint` or a sink
        // on the exit path, would end its next run before the guest ran and
        // call the hook again at once.
        // SAFETY: pthread_self is always valid on the current thread.
        if self.tid == unsafe { libc::pthread_self() } as u64 {
            return;
        }
        immediate_exit(&mut self.vcpu).store(1, Ordering::SeqCst);
        // SAFETY: pthread_kill to a live thread handle; no-op handler.
        unsafe { libc::pthread_kill(self.tid as libc::pthread_t, kick_signal()) };
    }
}

/// A vCPU thread's entry in a [`Kicker`], removed when dropped.
///
/// The removal runs on a panic as on a return, so a kick from a plugin thread
/// that outlives `boot` never signals a thread that no longer exists.
pub(crate) struct Registration<'a> {
    /// The table the entry is in.
    kicker: &'a Kicker,
    /// The vCPU id of the entry.
    cpu: u32,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Some(slot) = lock_or_recover(&self.kicker.threads).get_mut(self.cpu as usize) {
            *slot = None;
        }
    }
}

/// Runs vCPU `cpu` on the calling thread until the VM stops.
///
/// Each pass clears the vCPU's `immediate_exit` byte, checks the running flag,
/// parks at the quiesce checkpoint, lets `plugin` look at the guest from the
/// boot vCPU, and then calls `run`. `run` enters the guest once, services the
/// exit, and returns `false` to end the loop. Every way out of the loop ends
/// the VM, a panic included.
pub(crate) fn run_vcpu(
    cpu: u32,
    mut vcpu: VcpuFd,
    kick_handle: VcpuFd,
    guest: &Guest<Kicker>,
    plugin: Option<&dyn Plugin>,
    mut run: impl FnMut(&mut VcpuFd) -> bool,
) {
    // The vCPU filter goes in before this thread touches anything the guest
    // controls. MMIO exits are serviced on this thread, so the virtio device
    // models, which parse guest descriptors, run under it.
    seccomp::install_thread(seccomp::Thread::Vcpu);
    // The guard lives for the whole run, so every way out ends the VM. A
    // secondary that ended alone would leave the VM running with one vCPU fewer
    // and the join in `boot` blocked. It is declared before the registration,
    // so the registration drops first and the entry is gone before the stop
    // kicks.
    let _stop = guest.vcpus.stop_on_drop();
    let _registration = guest.vcpus.kicker().register(cpu, kick_handle);
    // Every KVM vCPU enters `KVM_RUN` at once. One the guest has not brought up
    // yet waits inside the run, where a kick reaches it.
    guest.vcpus.mark_started();
    let is_boot = cpu == 0;

    loop {
        // The byte is cleared before the running flag is read, so a kick that
        // lands from here on ends the run below at once.
        immediate_exit(&mut vcpu).store(0, Ordering::SeqCst);
        if !guest.vcpus.is_running() {
            break;
        }
        // Safe point for every vCPU: park here while cpu0 lets a plugin look at
        // the guest.
        guest.vcpus.checkpoint();
        // The plugin runs on cpu0, between guest entries, because only this
        // thread can read this vCPU's registers. It is on the hot path: with no
        // plugin this is a null check.
        if is_boot {
            if let Some(plugin) = plugin {
                plugin.safepoint(&Cpu { vcpu: &vcpu, guest });
            }
        }
        if !run(&mut vcpu) {
            break;
        }
    }
}

/// Returns the `kvm_run.immediate_exit` byte of `vcpu`.
///
/// The vCPU thread, a thread that kicks it and the kernel each reach the byte
/// through a mapping of their own, so it is read and written as an atomic.
pub(crate) fn immediate_exit(vcpu: &mut VcpuFd) -> &AtomicU8 {
    let byte: *mut u8 = &mut vcpu.get_kvm_run().immediate_exit;
    // SAFETY: `byte` points into the mapping `vcpu` owns, which outlives the
    // borrow, and an `AtomicU8` has the layout of the `u8` it points to.
    unsafe { AtomicU8::from_ptr(byte) }
}

/// Returns a second handle to `vcpu`, with its own mapping of the run struct.
///
/// # Errors
///
/// Errors if the descriptor cannot be duplicated or the run struct cannot be
/// mapped.
pub(crate) fn kick_handle(vm: &VmFd, vcpu: &VcpuFd) -> std::io::Result<VcpuFd> {
    // SAFETY: `vcpu` owns the descriptor and outlives the borrow.
    let descriptor = unsafe { BorrowedFd::borrow_raw(vcpu.as_raw_fd()) }.try_clone_to_owned()?;
    // SAFETY: `descriptor` is a vCPU of `vm`, and the handle takes it over.
    unsafe { vm.create_vcpu_from_rawfd(descriptor.into_raw_fd()) }.map_err(std::io::Error::from)
}

#[cfg(test)]
mod stop_tests {
    use super::*;
    use crate::signal::install_kick_handler;
    use kvm_ioctls::Kvm;

    // Ignored by default, as it needs a usable `/dev/kvm`.
    #[test]
    #[ignore]
    fn kick_before_the_run_ends_it_at_once() {
        let kvm = Kvm::new().expect("/dev/kvm is not usable");
        let vm = kvm.create_vm().unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        #[cfg(target_arch = "aarch64")]
        {
            let mut kvi = kvm_bindings::kvm_vcpu_init::default();
            vm.get_preferred_target(&mut kvi).unwrap();
            vcpu.vcpu_init(&kvi).unwrap();
        }
        install_kick_handler();
        let kicker = Kicker::new(1);
        let _registration = kicker.register(0, kick_handle(&vm, &vcpu).unwrap());
        // Kicked from another thread, as a kick to itself is dropped. The
        // signal lands here before the run starts, the case a signal alone
        // loses.
        std::thread::scope(|scope| {
            scope.spawn(|| kicker.kick(0));
        });
        let error = vcpu.run().expect_err("the run went ahead after the kick");
        assert_eq!(error.errno(), libc::EINTR);
        immediate_exit(&mut vcpu).store(0, Ordering::SeqCst);
        let mut threads = lock_or_recover(&kicker.threads);
        let registered = threads[0].as_mut().expect("the thread is registered");
        assert_eq!(
            immediate_exit(&mut registered.vcpu).load(Ordering::SeqCst),
            0
        );
    }
}

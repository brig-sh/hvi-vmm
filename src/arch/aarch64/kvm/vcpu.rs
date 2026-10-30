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

//! A vCPU thread of an arm64 guest on KVM, with its exit loop and the MMIO
//! dispatch to the devices.

use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};

use kvm_ioctls::{VcpuExit, VcpuFd};

use super::regs::{
    get_u64, REG_PC, REG_PSTATE, REG_SCTLR_EL1, REG_SP_EL0, REG_SP_EL1, REG_TCR_EL1, REG_TTBR0_EL1,
    REG_TTBR1_EL1,
};
use crate::arch::aarch64::layout::{
    RTC_BASE, RTC_SIZE, UART_BASE, UART_SIZE, VIRTIO_NET_BASE, VIRTIO_SIZE, VIRTIO_VSOCK_BASE,
};
use crate::devices::legacy::pl011::Pl011;
use crate::devices::legacy::rtc_pl031::Pl031;
use crate::devices::virtio::fs::vhost_user::{export_at, serve_mmio, Export};
use crate::hypervisor::guest::{Guest, SafepointVcpu};
use crate::hypervisor::kvm::{run_vcpu, unhandled_exit, Kicker};
use crate::plugin::{Plugin, RegsView};

/// The state a vCPU thread needs beyond its own vCPU.
#[derive(Clone)]
pub(super) struct VcpuContext {
    /// The guest's RAM, virtio devices and vCPUs.
    pub(super) guest: Arc<Guest<Kicker>>,
    /// The console UART.
    pub(super) pl011: Arc<Mutex<Pl011>>,
    /// The PL031 RTC, which has no interrupt line because the alarm never
    /// fires.
    pub(super) rtc: Arc<Mutex<Pl031>>,
    /// One entry per virtio-fs export, in the order the exports were given.
    pub(super) fs: Arc<Vec<Export>>,
    /// The plugin, if the caller supplied one.
    pub(super) plugin: Option<Arc<dyn Plugin>>,
}

/// Runs one vCPU until the VM stops, servicing its MMIO exits.
pub(super) fn run_cpu(cpu_id: u32, vcpu: VcpuFd, kick_handle: VcpuFd, context: VcpuContext) {
    run_vcpu(
        cpu_id,
        vcpu,
        kick_handle,
        &context.guest,
        context.plugin.as_deref(),
        |exit| {
            match exit {
                VcpuExit::MmioRead(addr, data) => on_mmio(&context, addr, true, data),
                VcpuExit::MmioWrite(addr, data) => {
                    // Copy out first: `data` borrows the run struct.
                    let mut buf = [0u8; 8];
                    let n = data.len().min(8);
                    buf[..n].copy_from_slice(&data[..n]);
                    on_mmio_write(&context, addr, &buf[..n]);
                }
                // Kicked for a snapshot or a stop; the loop checks which.
                VcpuExit::Intr => {}
                other => return unhandled_exit(cpu_id, &other),
            }
            ControlFlow::Continue(())
        },
    );
}

impl SafepointVcpu for VcpuFd {
    fn regs(&self) -> RegsView {
        let ttbr1 = get_u64(self, REG_TTBR1_EL1);
        RegsView {
            // arm64's kernel-half page-table base is the walk root.
            root: ttbr1,
            pc: get_u64(self, REG_PC),
            cpsr: get_u64(self, REG_PSTATE),
            ttbr0: get_u64(self, REG_TTBR0_EL1),
            ttbr1,
            sctlr: get_u64(self, REG_SCTLR_EL1),
            sp_el1: get_u64(self, REG_SP_EL1),
            tcr: get_u64(self, REG_TCR_EL1),
            current_task: get_u64(self, REG_SP_EL0),
        }
    }
}

/// Fills `data` with the value of the device register at `addr`.
fn on_mmio(context: &VcpuContext, addr: u64, _read: bool, data: &mut [u8]) {
    let width = data.len();
    let val = mmio_read(context, addr, width);
    let bytes = val.to_le_bytes();
    let n = width.min(8);
    data[..n].copy_from_slice(&bytes[..n]);
}

/// Reads the device register at `addr`.
fn mmio_read(context: &VcpuContext, addr: u64, width: usize) -> u64 {
    if (UART_BASE..UART_BASE + UART_SIZE).contains(&addr) {
        context
            .pl011
            .lock()
            .unwrap()
            .mmio(addr - UART_BASE, false, 0)
    } else if (RTC_BASE..RTC_BASE + RTC_SIZE).contains(&addr) {
        context
            .rtc
            .lock()
            .unwrap()
            .mmio(addr - RTC_BASE, width, false, 0)
    } else if let Some((dev, off)) = context.guest.disk_at(addr, VIRTIO_SIZE) {
        context.guest.read_device(dev, off)
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        let off = addr - VIRTIO_NET_BASE;
        context
            .guest
            .net
            .as_ref()
            .map_or(0, |dev| context.guest.read_device(dev, off))
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        let off = addr - VIRTIO_VSOCK_BASE;
        context
            .guest
            .vsock
            .as_ref()
            .map_or(0, |dev| context.guest.read_device(dev, off))
    } else if let Some(export) = export_at(&context.fs, addr, VIRTIO_SIZE) {
        serve_mmio(
            &export.dev,
            &context.guest.ram,
            addr - export.base,
            false,
            0,
        )
    } else {
        0
    }
}

/// Writes `data` to the device register at `addr`.
fn on_mmio_write(context: &VcpuContext, addr: u64, data: &[u8]) {
    let mut b = [0u8; 8];
    b[..data.len()].copy_from_slice(data);
    let val = u64::from_le_bytes(b);
    if (UART_BASE..UART_BASE + UART_SIZE).contains(&addr) {
        context
            .pl011
            .lock()
            .unwrap()
            .mmio(addr - UART_BASE, true, val);
    } else if (RTC_BASE..RTC_BASE + RTC_SIZE).contains(&addr) {
        context
            .rtc
            .lock()
            .unwrap()
            .mmio(addr - RTC_BASE, data.len(), true, val);
    } else if let Some((dev, off)) = context.guest.disk_at(addr, VIRTIO_SIZE) {
        context.guest.write_device(dev, off, val);
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        if let Some(dev) = &context.guest.net {
            context.guest.write_device(dev, addr - VIRTIO_NET_BASE, val);
        }
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        if let Some(dev) = &context.guest.vsock {
            context
                .guest
                .write_device(dev, addr - VIRTIO_VSOCK_BASE, val);
        }
    } else if let Some(export) = export_at(&context.fs, addr, VIRTIO_SIZE) {
        serve_mmio(
            &export.dev,
            &context.guest.ram,
            addr - export.base,
            true,
            val,
        );
    }
}

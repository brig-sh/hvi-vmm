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

//! The in-kernel GIC of an arm64 guest on Hypervisor.framework, with the VM
//! handle it comes with, the INTIDs of the fixed devices, the interrupt lines
//! and the GIC's placement.

use std::sync::Arc;

use applevisor::prelude::{GicConfig, GicEnabled, HypervisorError, VirtualMachineInstance};

use super::kick::{on_vcpu_thread, Kicker};
use crate::arch::aarch64::layout::{
    GicLayout, GicVersion, UART_SPI, VIRTIO_NET_SPI, VIRTIO_VSOCK_SPI,
};
use crate::devices::irq::IrqLine;
use crate::hypervisor::vcpus::{Kick, Vcpus};

/// The VM handle once the GICv3 is configured (Send/Sync; cloned per thread).
pub(super) type VmGic = VirtualMachineInstance<GicEnabled>;

// The fixed devices' GIC INTIDs, where SPIs start at 32.
pub(super) const UART_INTID: u32 = 32 + UART_SPI;
pub(super) const VIRTIO_NET_INTID: u32 = 32 + VIRTIO_NET_SPI;
pub(super) const VIRTIO_VSOCK_INTID: u32 = 32 + VIRTIO_VSOCK_SPI;

/// A guest interrupt line on the in-kernel GIC.
///
/// A line that rises on an I/O thread also kicks the vCPUs, so a guest in WFI
/// takes the interrupt promptly. A vCPU thread raises a line between its own
/// guest entries and kicks no one, and neither does the console UART's line.
pub(super) struct HvfIrqLine {
    /// The VM whose GIC has the line.
    vm: VmGic,
    /// The line's interrupt ID.
    intid: u32,
    /// The vCPUs a rise on an I/O thread kicks, or `None` for a line that kicks
    /// none.
    kick: Option<Arc<Vcpus<Kicker>>>,
}

impl HvfIrqLine {
    /// Returns the line `intid` of `vm`, which kicks `kick` on a rise.
    pub(super) fn new(vm: VmGic, intid: u32, kick: Option<Arc<Vcpus<Kicker>>>) -> Self {
        Self { vm, intid, kick }
    }
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
        if vcpus.is_running() && !on_vcpu_thread() {
            vcpus.kicker().kick_all();
        }
        Ok(())
    }
}

/// Returns where the in-kernel GICv3 sits and how large it is.
///
/// The sizes come from the framework, so the devicetree matches `hv_gic`, and
/// the bases are QEMU virt's, aligned down to what the framework asks for.
pub(super) fn gic_layout() -> Result<GicLayout, HypervisorError> {
    let gicd_align = GicConfig::get_distributor_base_alignment()? as u64;
    let gicr_align = GicConfig::get_redistributor_base_alignment()? as u64;
    Ok(GicLayout {
        // Apple's hv_gic is always a GICv3.
        version: GicVersion::V3,
        gicd_base: align_down(GicLayout::QEMU_VIRT.gicd_base, gicd_align),
        gicd_size: GicConfig::get_distributor_size()? as u64,
        gicr_base: align_down(GicLayout::QEMU_VIRT.gicr_base, gicr_align),
        gicr_size: GicConfig::get_redistributor_region_size()? as u64,
    })
}

/// Returns the GIC configuration that places the distributor and the
/// redistributors where `layout` puts them.
///
/// Hypervisor.framework takes it when it creates the VM.
pub(super) fn gic_config(layout: &GicLayout) -> Result<GicConfig, HypervisorError> {
    let mut config = GicConfig::new();
    config.set_distributor_base(layout.gicd_base)?;
    config.set_redistributor_base(layout.gicr_base)?;
    Ok(config)
}

/// Rounds `v` down to a multiple of `align` (a power of two).
fn align_down(v: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    v & !(align - 1)
}

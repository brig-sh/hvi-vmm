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
//! handle it comes with, its interrupt lines and triggers, and its placement.

use std::sync::Arc;

use applevisor::prelude::{GicConfig, GicEnabled, HypervisorError, VirtualMachineInstance};

use crate::arch::aarch64::layout::{GicLayout, GicVersion, SPI_BASE};
use crate::devices::irq;

/// The VM handle once the GICv3 is configured (Send/Sync; cloned per thread).
pub(super) type VmGic = VirtualMachineInstance<GicEnabled>;

/// A guest interrupt line on the in-kernel GIC, which is also the trigger of an
/// edge-triggered SPI.
///
/// The framework delivers the interrupt to its vCPU from whichever thread sets
/// the line, and wakes a vCPU that waits in WFI for it.
pub(super) struct Line {
    /// The VM whose GIC has the line.
    vm: VmGic,
    /// The line's interrupt ID.
    intid: u32,
}

impl Line {
    /// Returns the line of SPI `spi` of `vm`.
    pub(super) fn new(vm: VmGic, spi: u32) -> Self {
        Self {
            vm,
            intid: SPI_BASE + spi,
        }
    }
}

impl irq::Line for Line {
    fn set_level(&self, level: bool) -> std::io::Result<()> {
        self.vm
            .gic_set_spi(self.intid, level)
            .map_err(std::io::Error::other)
    }
}

// The framework takes each rise of an edge-triggered SPI as one interrupt, and
// ignores a fall.
impl irq::Trigger for Line {
    fn trigger(&self) -> std::io::Result<()> {
        irq::Line::set_level(self, true)
    }
}

/// The in-kernel GIC of an arm64 guest on Hypervisor.framework, whose lines and
/// triggers are its SPIs.
pub(super) struct Gic {
    /// The VM whose GIC has the lines.
    pub(super) vm: VmGic,
}

impl irq::Chip for Gic {
    fn line(&self, spi: u32) -> Arc<dyn irq::Line> {
        Arc::new(Line::new(self.vm.clone(), spi))
    }

    fn trigger(&self, spi: u32) -> std::io::Result<Arc<dyn irq::Trigger>> {
        Ok(Arc::new(Line::new(self.vm.clone(), spi)))
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

/// Returns how many interrupts the framework's GIC has, from INTID 0 up to its
/// last SPI.
pub(super) fn gic_num_irqs() -> Result<u32, HypervisorError> {
    let (base, count) = GicConfig::get_spi_interrupt_range()?;
    Ok(base + count)
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

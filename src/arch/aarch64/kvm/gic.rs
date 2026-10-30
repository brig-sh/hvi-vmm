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

//! The in-kernel vGIC of an arm64 guest on KVM, and the GSI that names one of
//! its SPIs.

use kvm_bindings::{
    kvm_create_device, kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
    kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, KVM_ARM_IRQ_TYPE_SHIFT, KVM_ARM_IRQ_TYPE_SPI,
    KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL,
    KVM_DEV_ARM_VGIC_GRP_NR_IRQS, KVM_VGIC_V2_ADDR_TYPE_CPU, KVM_VGIC_V2_ADDR_TYPE_DIST,
    KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST,
};
use kvm_ioctls::{DeviceFd, VmFd};

use crate::arch::aarch64::layout::{GicLayout, GicVersion};
use crate::LOG_PREFIX;

/// Returns the KVM GSI of SPI `spi`, whose INTID is `32 + spi`.
pub(super) fn spi_gsi(spi: u32) -> u32 {
    (KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) | (32 + spi)
}

/// A VM's in-kernel vGIC, and the version KVM created.
///
/// KVM takes the setup in three steps, [`Vgic::create`], [`Vgic::set_regions`]
/// and [`Vgic::finalize`], in that order.
pub(super) struct Vgic {
    /// The vGIC device.
    fd: DeviceFd,
    /// The version KVM created.
    version: GicVersion,
}

impl Vgic {
    /// Creates the vGIC of `vm`, a v3 if the host serves one and a v2
    /// otherwise.
    ///
    /// KVM's vGIC uses the host's CPU interface, so a GICv3 host serves vGICv3
    /// and a GIC-400 host (Raspberry Pi 5 and most Cortex-A72/A76 SoCs) serves
    /// only vGICv2. A rejected `KVM_CREATE_DEVICE` creates nothing, so asking
    /// for v3 first costs one ioctl.
    ///
    /// It does not use `KVM_CREATE_DEVICE_TEST`. With that flag the kernel
    /// leaves `fd` at 0, and kvm-ioctls would wrap descriptor 0 in a `DeviceFd`
    /// that closes stdin when dropped.
    pub(super) fn create(vm: &VmFd) -> Result<Self, kvm_ioctls::Error> {
        let (fd, version) = match vm.create_device(&mut kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        }) {
            Ok(fd) => (fd, GicVersion::V3),
            Err(e) => {
                eprintln!("{LOG_PREFIX} vGICv3 unavailable ({e}); falling back to vGICv2");
                let fd = vm.create_device(&mut kvm_create_device {
                    type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
                    fd: 0,
                    flags: 0,
                })?;
                (fd, GicVersion::V2)
            }
        };
        Ok(Self { fd, version })
    }

    /// Returns the version KVM created.
    pub(super) fn version(&self) -> GicVersion {
        self.version
    }

    /// Places the distributor and the redistributors or CPU interface where
    /// `layout` puts them.
    ///
    /// A v2 vGIC has a CPU interface where a v3 has redistributors.
    pub(super) fn set_regions(&self, layout: &GicLayout) -> Result<(), kvm_ioctls::Error> {
        let (distributor, cpu_or_redistributor) = match self.version {
            GicVersion::V3 => (KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST),
            GicVersion::V2 => (KVM_VGIC_V2_ADDR_TYPE_DIST, KVM_VGIC_V2_ADDR_TYPE_CPU),
        };
        self.set_attr(
            KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(distributor),
            std::ptr::addr_of!(layout.gicd_base) as u64,
        )?;
        self.set_attr(
            KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(cpu_or_redistributor),
            std::ptr::addr_of!(layout.gicr_base) as u64,
        )
    }

    /// Finalizes the vGIC with `nr_irqs` interrupts, a multiple of 32 that
    /// counts the 32 private ones.
    ///
    /// This has to follow the last vCPU, because KVM refuses a new vCPU once
    /// the vGIC is initialized.
    pub(super) fn finalize(&self, nr_irqs: u32) -> Result<(), kvm_ioctls::Error> {
        self.set_attr(
            KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            std::ptr::addr_of!(nr_irqs) as u64,
        )?;
        self.set_attr(
            KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
        )
    }

    /// Sets attribute `attr` of group `group`, whose value is at host address
    /// `addr`, or 0 for an attribute that takes none.
    fn set_attr(&self, group: u32, attr: u64, addr: u64) -> Result<(), kvm_ioctls::Error> {
        self.fd.set_device_attr(&kvm_device_attr {
            flags: 0,
            group,
            attr,
            addr,
        })
    }
}

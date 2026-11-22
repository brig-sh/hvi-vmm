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

//! The in-kernel vGIC of an arm64 guest on KVM, and the interrupt lines and
//! triggers on its SPIs.
//!
//! A line is set with `KVM_IRQ_LINE`. A trigger is a write to an eventfd that
//! KVM delivers as an irqfd on the SPI. KVM refuses an irqfd with `EAGAIN`
//! until the vGIC is initialized. [`Vgic::finalize`] initializes it after the
//! devices are attached, so [`Irqfds`] keeps the eventfds until then.

use std::io;
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    kvm_create_device, kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
    kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, KVM_ARM_IRQ_TYPE_SHIFT, KVM_ARM_IRQ_TYPE_SPI,
    KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL,
    KVM_DEV_ARM_VGIC_GRP_NR_IRQS, KVM_VGIC_V2_ADDR_TYPE_CPU, KVM_VGIC_V2_ADDR_TYPE_DIST,
    KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST,
};
use kvm_ioctls::{DeviceFd, VmFd};
use vmm_sys_util::eventfd::EventFd;

use crate::arch::aarch64::layout::{GicLayout, GicVersion, SPI_BASE};
use crate::devices::irq;
use crate::hypervisor::kvm;
use crate::LOG_PREFIX;

/// Returns the number `KVM_IRQ_LINE` takes for SPI `spi`, whose INTID is
/// [`SPI_BASE`] + `spi`.
fn spi_gsi(spi: u32) -> u32 {
    (KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) | (SPI_BASE + spi)
}

/// The eventfds a VM's SPIs are delivered through, as irqfds.
///
/// An eventfd registered before the vGIC is initialized is kept, and
/// [`register_pending`](Self::register_pending) registers it at the
/// initialization. One registered after that is registered at once.
struct Irqfds {
    /// The function that registers an irqfd with KVM.
    ///
    /// It takes the SPI number, which is the SPI's GSI in the routing KVM sets
    /// up when the vGIC is initialized.
    registrar: kvm::IrqfdRegistrar,
    /// The eventfds kept until the vGIC is initialized, each with its SPI, or
    /// `None` once it is.
    pending: Mutex<Option<Vec<(EventFd, u32)>>>,
}

impl Irqfds {
    /// Returns a list with nothing pending, which registers through `registrar`
    /// once the vGIC is initialized.
    fn new(registrar: kvm::IrqfdRegistrar) -> Self {
        Self {
            registrar,
            pending: Mutex::new(Some(Vec::new())),
        }
    }

    /// Registers `fd` as an irqfd on SPI `spi`, at once if the vGIC is
    /// initialized and at the initialization otherwise.
    ///
    /// # Errors
    ///
    /// Errors if `fd` cannot be duplicated to be kept, or if KVM refuses it. A
    /// refusal names the SPI.
    fn register(&self, fd: &EventFd, spi: u32) -> io::Result<()> {
        let mut pending = self.pending.lock().unwrap();
        match pending.as_mut() {
            Some(pending) => {
                pending.push((fd.try_clone()?, spi));
                Ok(())
            }
            None => self.register_now(fd, spi),
        }
    }

    /// Registers the kept eventfds.
    ///
    /// # Errors
    ///
    /// Errors if KVM refuses an eventfd. The error names its SPI.
    fn register_pending(&self) -> io::Result<()> {
        let pending = self.pending.lock().unwrap().take().unwrap_or_default();
        for (fd, spi) in pending {
            self.register_now(&fd, spi)?;
        }
        Ok(())
    }

    /// Registers `fd` as an irqfd on SPI `spi` with KVM.
    ///
    /// # Errors
    ///
    /// Errors if KVM refuses it. The error names the SPI.
    fn register_now(&self, fd: &EventFd, spi: u32) -> io::Result<()> {
        (self.registrar)(fd, spi).map_err(|e| {
            io::Error::new(e.kind(), format!("registering an irqfd on SPI {spi}: {e}"))
        })
    }
}

/// A VM's in-kernel vGIC, and the version KVM created.
///
/// The devices' lines and triggers are its SPIs. KVM takes the setup in three
/// steps, [`Vgic::create`], [`Vgic::set_regions`] and [`Vgic::finalize`], in
/// that order.
pub(super) struct Vgic {
    /// The VM the vGIC is in.
    vm: Arc<VmFd>,
    /// The vGIC device.
    fd: DeviceFd,
    /// The version KVM created.
    version: GicVersion,
    /// The irqfds of the triggers, which the triggers share.
    irqfds: Arc<Irqfds>,
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
    pub(super) fn create(vm: Arc<VmFd>) -> Result<Self, kvm_ioctls::Error> {
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
        let irqfds = Arc::new(Irqfds::new(Box::new({
            let vm = Arc::clone(&vm);
            move |fd, spi| Ok(vm.register_irqfd(fd, spi)?)
        })));
        Ok(Self {
            vm,
            fd,
            version,
            irqfds,
        })
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
    /// the vGIC is initialized. The irqfds of the triggers are registered once
    /// it is.
    ///
    /// # Errors
    ///
    /// Errors if KVM refuses the interrupt count, the initialization or an
    /// irqfd.
    pub(super) fn finalize(&self, nr_irqs: u32) -> io::Result<()> {
        self.set_attr(
            KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            std::ptr::addr_of!(nr_irqs) as u64,
        )?;
        self.set_attr(
            KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
        )?;
        self.irqfds.register_pending()
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

impl irq::Chip for Vgic {
    fn line(&self, spi: u32) -> Arc<dyn irq::Line> {
        Arc::new(kvm::IrqLine::new(Arc::clone(&self.vm), spi_gsi(spi)))
    }

    fn trigger(&self, spi: u32) -> io::Result<Arc<dyn irq::Trigger>> {
        let fd = EventFd::new(libc::EFD_NONBLOCK)?;
        self.irqfds.register(&fd, spi)?;
        Ok(Arc::new(Trigger {
            fd,
            spi,
            irqfds: Arc::clone(&self.irqfds),
        }))
    }
}

/// The trigger of an edge-triggered SPI, an eventfd KVM delivers as an irqfd.
///
/// The vGIC latches the SPI as pending on each write. A further eventfd
/// registered on the trigger delivers the same SPI.
struct Trigger {
    /// The eventfd, registered as an irqfd on the SPI.
    fd: EventFd,
    /// The SPI.
    spi: u32,
    /// The list a further eventfd is registered through.
    irqfds: Arc<Irqfds>,
}

impl irq::Trigger for Trigger {
    fn trigger(&self) -> io::Result<()> {
        self.fd.write(1)
    }

    fn register_irqfd(&self, fd: &EventFd) -> io::Result<()> {
        self.irqfds.register(fd, self.spi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SPIs and counts an [`Irqfds`] registered, in order.
    type Registered = Arc<Mutex<Vec<(u32, u64)>>>;

    /// Returns an irqfd list whose registrar records each SPI with the count it
    /// reads from the eventfd, and the records.
    fn recording() -> (Irqfds, Registered) {
        let registered = Registered::default();
        let records = Arc::clone(&registered);
        let irqfds = Irqfds::new(Box::new(move |fd: &EventFd, spi| {
            records.lock().unwrap().push((spi, fd.read()?));
            Ok(())
        }));
        (irqfds, registered)
    }

    /// Returns an eventfd that holds `count`.
    fn eventfd_holding(count: u64) -> EventFd {
        let fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        fd.write(count).unwrap();
        fd
    }

    // Each eventfd holds a count of its own, so a record shows which eventfd
    // the registrar was given.
    #[test]
    fn irqfds_are_registered_at_the_initialization_and_at_once_after_it() {
        let (irqfds, registered) = recording();
        let fds = [1, 2, 3].map(eventfd_holding);
        irqfds.register(&fds[0], 4).unwrap();
        irqfds.register(&fds[1], 9).unwrap();
        assert!(registered.lock().unwrap().is_empty());
        irqfds.register_pending().unwrap();
        assert_eq!(*registered.lock().unwrap(), [(4, 1), (9, 2)]);
        irqfds.register(&fds[2], 4).unwrap();
        assert_eq!(*registered.lock().unwrap(), [(4, 1), (9, 2), (4, 3)]);
    }

    #[test]
    fn refused_irqfd_names_its_spi_at_and_after_the_initialization() {
        let irqfds = Irqfds::new(Box::new(|_: &EventFd, spi| match spi {
            9 => Err(io::Error::from_raw_os_error(libc::EINVAL)),
            _ => Ok(()),
        }));
        for spi in [4, 9] {
            irqfds.register(&eventfd_holding(1), spi).unwrap();
        }
        let at = irqfds.register_pending().unwrap_err();
        let after = irqfds.register(&eventfd_holding(1), 9).unwrap_err();
        for error in [at, after] {
            assert!(
                error
                    .to_string()
                    .starts_with("registering an irqfd on SPI 9: "),
                "{error}"
            );
        }
    }
}

// These tests need a usable `/dev/kvm` on an arm64 host, so they are ignored by
// default.
#[cfg(test)]
mod irqfd_tests {
    use irq::Chip as _;
    use kvm_bindings::kvm_vcpu_init;
    use kvm_ioctls::{Kvm, VcpuFd};

    use super::*;
    use crate::arch::aarch64::layout::{GIC_NUM_IRQS, VIRTIO_SPI};

    /// Returns a VM with one vCPU and its vGIC, set up as a boot sets them up
    /// before [`Vgic::finalize`].
    fn vm_with_vgic() -> (Arc<VmFd>, VcpuFd, Vgic) {
        let kvm = Kvm::new().expect("/dev/kvm should be usable");
        let vm = Arc::new(kvm.create_vm().unwrap());
        let vgic = Vgic::create(Arc::clone(&vm)).unwrap();
        vgic.set_regions(&GicLayout::for_vcpus(vgic.version(), 1).unwrap())
            .unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();
        (vm, vcpu, vgic)
    }

    #[test]
    #[ignore]
    fn irqfd_is_refused_until_the_vgic_is_initialized() {
        let (vm, _vcpu, vgic) = vm_with_vgic();
        let fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let refused = vm.register_irqfd(&fd, VIRTIO_SPI).unwrap_err();
        assert_eq!(refused.errno(), libc::EAGAIN);
        vgic.finalize(GIC_NUM_IRQS).unwrap();
        vm.register_irqfd(&fd, VIRTIO_SPI).unwrap();
    }

    // KVM refuses an eventfd that is already an irqfd with `EBUSY`, so the
    // refusal shows that each eventfd was registered.
    #[test]
    #[ignore]
    fn eventfds_given_before_and_after_finalize_are_registered() {
        let (vm, _vcpu, vgic) = vm_with_vgic();
        let trigger = vgic.trigger(VIRTIO_SPI).unwrap();
        let early = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        trigger.register_irqfd(&early).unwrap();
        vgic.finalize(GIC_NUM_IRQS).unwrap();
        let late = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        trigger.register_irqfd(&late).unwrap();
        for fd in [&early, &late] {
            let refused = vm.register_irqfd(fd, VIRTIO_SPI).unwrap_err();
            assert_eq!(refused.errno(), libc::EBUSY);
        }
        trigger.trigger().unwrap();
    }
}

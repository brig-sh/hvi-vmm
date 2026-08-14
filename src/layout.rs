//! Guest physical-address-space layout for the arm64 `virt`-style machine.
//!
//! The addresses below mirror QEMU's `virt` board so a guest kernel configured
//! for QEMU/virt (the arm64 build of the repo guest kernel) boots unmodified:
//! RAM at 1 GiB, the GICv3 and a PL011 UART in the low MMIO window beneath it.
//! M1 uses the PL011 for first-boot serial output (`earlycon`); virtio-mmio
//! devices arrive in M2. The GIC base/size must agree with what `hv_gic`
//! actually claims, so
//! [`GicLayout::QEMU_VIRT`](crate::layout::GicLayout::QEMU_VIRT) is treated as
//! the default and reconciled against `applevisor`'s GIC size getters when the
//! VM is built.

/// Base of guest RAM (1 GiB), 2 MiB-aligned as the arm64 boot protocol wants.
pub const RAM_BASE: u64 = 0x4000_0000;

/// PL011 UART MMIO base and size. Placed *below* the GIC (which sits at
/// `0x0800_0000`+) rather than at QEMU virt's `0x0900_0000`: Apple's `hv_gic`
/// reports a much larger redistributor region than QEMU's, and that region —
/// which Linux reserves from the DTB `reg` — extends up past `0x0900_0000` and
/// steals the UART's MMIO range, so `ttyAMA0` fails to bind (`amba_device_add
/// -16`). `0x0100_0000` is safely clear of both the GIC and guest RAM.
pub const UART_BASE: u64 = 0x0100_0000;
pub const UART_SIZE: u64 = 0x1000;
/// UART interrupt as a GIC SPI number (INTID = 32 + SPI = 33).
pub const UART_SPI: u32 = 1;

/// virtio-mmio device windows and interrupts, below the GIC and clear of the
/// UART. Slot 0 = virtio-blk, slot 1 = virtio-net; each is one 0x200 page.
pub const VIRTIO_SIZE: u64 = 0x0200;
pub const VIRTIO_BASE: u64 = 0x0200_0000;
pub const VIRTIO_SPI: u32 = 2;
pub const VIRTIO_NET_BASE: u64 = 0x0200_0200;
pub const VIRTIO_NET_SPI: u32 = 3;
pub const VIRTIO_VSOCK_BASE: u64 = 0x0200_0400;
pub const VIRTIO_VSOCK_SPI: u32 = 4;
pub const VIRTIO_FS_BASE: u64 = 0x0200_0600;
pub const VIRTIO_FS_SPI: u32 = 5;

/// Placement of the `index`th virtio-fs device. Each export gets an
/// independent transport and interrupt because one virtio-fs device carries
/// exactly one mount tag.
#[must_use]
pub fn virtio_fs_base(index: usize) -> Option<u64> {
    let offset = (index as u64).checked_mul(VIRTIO_SIZE)?;
    VIRTIO_FS_BASE.checked_add(offset)
}

#[must_use]
pub fn virtio_fs_spi(index: usize) -> Option<u32> {
    VIRTIO_FS_SPI.checked_add(u32::try_from(index).ok()?)
}

/// GICv3 placement, defaulting to the QEMU virt values.
/// Which GIC architecture the guest is given.
///
/// This is not a free choice: KVM can only offer a virtual GIC that matches the
/// host's own interrupt controller, because the vGIC borrows the hardware's CPU
/// interface. A GICv3 host serves vGICv3; a GIC-400 host — Raspberry Pi 5
/// (BCM2712) and most Cortex-A72/A76 SoCs — serves vGICv2 only, and asking it
/// for vGICv3 fails with `ENODEV`. The macOS backend is always [`Self::V3`],
/// since Apple's `hv_gic` is a GICv3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicVersion {
    V3,
    V2,
}

/// Placement of the guest's GIC regions.
///
/// Both versions have exactly two MMIO regions, so one struct covers them: the
/// second pair is the **redistributor** under [`GicVersion::V3`] and the **CPU
/// interface** (GICC) under [`GicVersion::V2`]. The `gicr_*` names are kept for
/// the v3 reading, which is the primary target.
#[derive(Debug, Clone, Copy)]
pub struct GicLayout {
    pub version: GicVersion,
    pub gicd_base: u64,
    pub gicd_size: u64,
    pub gicr_base: u64,
    pub gicr_size: u64,
}

impl GicLayout {
    /// QEMU virt GICv3: distributor at 0x0800_0000, redistributor region at
    /// 0x080A_0000. `gicr_size` here is one 128 KiB redistributor frame (per
    /// vCPU); the machine multiplies it by the vCPU count and checks it against
    /// `applevisor`'s redistributor-size getter before use.
    pub const QEMU_VIRT: GicLayout = GicLayout {
        version: GicVersion::V3,
        gicd_base: 0x0800_0000,
        gicd_size: 0x0001_0000,
        gicr_base: 0x080A_0000,
        gicr_size: 0x0002_0000,
    };

    /// QEMU virt GICv2: distributor at 0x0800_0000, CPU interface at
    /// 0x0801_0000 (carried in the `gicr_*` fields). Unlike the v3
    /// redistributor, the CPU interface is a single shared window that does not
    /// scale with the vCPU count.
    pub const QEMU_VIRT_V2: GicLayout = GicLayout {
        version: GicVersion::V2,
        gicd_base: 0x0800_0000,
        gicd_size: 0x0001_0000,
        gicr_base: 0x0801_0000,
        gicr_size: 0x0001_0000,
    };

    /// GICv2 addresses at most 8 CPU interfaces, so a v2 guest cannot exceed
    /// eight vCPUs.
    pub const V2_MAX_CPUS: u32 = 8;
}

/// Rounds `v` up to the next multiple of `align` (a power of two).
#[must_use]
pub fn align_up(v: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (v + align - 1) & !(align - 1)
}

/// The resolved placement of the three images the loader writes into guest RAM:
/// the kernel, the flattened devicetree, and (optionally) the initramfs.
///
/// The kernel lands at `RAM_BASE + text_offset`; the DTB follows it 2 MiB-
/// aligned; the initramfs follows the DTB page-aligned. Keeping them packed
/// from the bottom of RAM makes the layout independent of total RAM size, and
/// [`GuestLayout::validate`] checks nothing runs past the end of RAM.
#[derive(Debug, Clone, Copy)]
pub struct GuestLayout {
    pub ram_base: u64,
    pub ram_size: u64,
    pub kernel_addr: u64,
    pub kernel_size: u64,
    pub dtb_addr: u64,
    pub dtb_size: u64,
    pub initrd_addr: u64,
    pub initrd_size: u64,
}

impl GuestLayout {
    /// 2 MiB kernel alignment required by the arm64 boot protocol.
    const KERNEL_ALIGN: u64 = 0x20_0000;

    /// Computes the layout from the kernel `text_offset`/size, the built DTB
    /// length, and the optional initramfs length. `dtb_size` is the actual
    /// finished-blob length; the loader builds the DTB first (it needs the
    /// initrd address for `/chosen`, so pass `initrd_size` to reserve the slot,
    /// then rebuild once the address is known — see `boot::load`).
    #[must_use]
    pub fn new(
        ram_size: u64,
        text_offset: u64,
        kernel_size: u64,
        dtb_size: u64,
        initrd_size: u64,
    ) -> Self {
        let kernel_addr = RAM_BASE + text_offset;
        let dtb_addr = align_up(kernel_addr + kernel_size, Self::KERNEL_ALIGN);
        let initrd_addr = align_up(dtb_addr + dtb_size, 0x1000);
        GuestLayout {
            ram_base: RAM_BASE,
            ram_size,
            kernel_addr,
            kernel_size,
            dtb_addr,
            dtb_size,
            initrd_addr,
            initrd_size,
        }
    }

    /// End of the last placed image; everything below must fit in RAM.
    #[must_use]
    pub fn top(&self) -> u64 {
        self.initrd_addr + self.initrd_size
    }

    /// Errors if the packed images would run past the end of guest RAM.
    pub fn validate(&self) -> Result<(), String> {
        let ram_end = self.ram_base + self.ram_size;
        if self.top() > ram_end {
            return Err(format!(
                "guest images overflow RAM: top {:#x} > ram_end {:#x} \
                 (kernel {:#x}+{:#x}, dtb {:#x}+{:#x}, initrd {:#x}+{:#x})",
                self.top(),
                ram_end,
                self.kernel_addr,
                self.kernel_size,
                self.dtb_addr,
                self.dtb_size,
                self.initrd_addr,
                self.initrd_size,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_up_rounds() {
        assert_eq!(align_up(0, 0x1000), 0);
        assert_eq!(align_up(1, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x20_0000), 0x20_0000);
    }

    #[test]
    fn layout_packs_without_overlap() {
        // 512 MiB RAM, text_offset 0, 16 MiB kernel, 8 KiB dtb, 4 MiB initrd.
        let l = GuestLayout::new(512 << 20, 0, 16 << 20, 0x2000, 4 << 20);
        assert_eq!(l.kernel_addr, RAM_BASE);
        assert!(l.dtb_addr >= l.kernel_addr + l.kernel_size);
        assert_eq!(l.dtb_addr % 0x20_0000, 0, "dtb must be 2 MiB-aligned");
        assert!(l.initrd_addr >= l.dtb_addr + l.dtb_size);
        assert_eq!(l.initrd_addr % 0x1000, 0, "initrd must be page-aligned");
        l.validate().expect("512 MiB is plenty for these images");
    }

    #[test]
    fn layout_detects_overflow() {
        // 8 MiB RAM cannot hold a 16 MiB kernel.
        let l = GuestLayout::new(8 << 20, 0, 16 << 20, 0x2000, 0);
        assert!(l.validate().is_err());
    }
}

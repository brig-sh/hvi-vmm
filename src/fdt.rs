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

//! Flattened-devicetree builder for the arm64 `virt`-style machine.
//!
//! Describes exactly the hardware M1 presents: RAM, the vCPUs (PSCI
//! enable-method), a GIC (v3 or v2), the architected timer, and a PL011 UART
//! for `earlycon`. The addresses come from [`crate::layout`] so the DTB and the
//! actual device placement cannot drift. Interrupt encodings follow the GICv3
//! convention (`<type number flags>`, type 0=SPI/1=PPI, flag 4=level-high);
//! the timer PPI flags in particular are the classic first-boot tuning knob,
//! flagged inline.
//!
//! Phandles are fixed: `1` = GIC (the root `interrupt-parent`), `2` = the UART
//! reference clock.

use vm_fdt::{Error, FdtWriter};

use crate::layout::{
    GicLayout, GicVersion, GuestLayout, UART_BASE, UART_SIZE, UART_SPI, VIRTIO_BASE,
    VIRTIO_NET_BASE, VIRTIO_NET_SPI, VIRTIO_SIZE, VIRTIO_SPI, VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_SPI,
};

const PHANDLE_GIC: u32 = 1;
const PHANDLE_CLK: u32 = 2;

/// GIC interrupt type cell.
const IRQ_SPI: u32 = 0;
const IRQ_PPI: u32 = 1;
/// GIC interrupt flag cell.
const IRQ_LEVEL_HIGH: u32 = 4;

/// Architected timer PPIs (INTID - 16), in the order the `arm,armv8-timer`
/// binding lists them. They have to match the INTIDs Hypervisor.framework
/// raises the timers on; the macOS backend checks the ones it can query
/// against `hv_gic_get_intid` before a guest that owns EL2 boots. Under nVHE,
/// the only mode the framework offers, that guest's kernel uses the EL1
/// physical timer (PPI 14); only a VHE kernel would take the hypervisor PPI.
pub const TIMER_PPI_SECURE_PHYS: u32 = 13;
pub const TIMER_PPI_PHYS: u32 = 14;
pub const TIMER_PPI_VIRT: u32 = 11;
pub const TIMER_PPI_HYP_PHYS: u32 = 10;

/// How the guest makes PSCI calls (`/psci` `method`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PsciConduit {
    /// `HVC`, which traps to the VMM from a guest kernel at EL1.
    #[default]
    Hvc,
    /// `SMC`. A guest kernel that owns EL2 takes its own `HVC` in its own
    /// vectors, so the VMM never sees it; `SMC` still traps to the VMM. QEMU's
    /// `virt` machine switches to `smc` for the same reason when it gives the
    /// guest EL2.
    Smc,
}

/// Devicetree choices that depend on how the guest is booted rather than on
/// the device set.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub psci_conduit: PsciConduit,
    /// The PPI number (INTID - 16) of the GIC maintenance interrupt, set only
    /// when the guest owns EL2. KVM's vgic-v3 in the guest needs it described
    /// on the GIC node and refuses to initialise without it. `None` leaves the
    /// property out, which is right for a guest at EL1: the interrupt does
    /// not exist there.
    pub gic_maintenance_ppi: Option<u32>,
}

/// The virtio-mmio nodes backed by this boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct VirtioDevices {
    pub blk: bool,
    pub net: bool,
    pub vsock: bool,
    pub fs_count: usize,
}

/// Builds the DTB for `layout` with `num_cpus` vCPUs and the given kernel
/// command line. When `layout.initrd_size` is non-zero, `/chosen` gets the
/// initramfs range. `options` picks the PSCI conduit and whether the GIC node
/// describes a maintenance interrupt.
///
/// # Errors
///
/// Propagates `vm-fdt` writer errors (only on internal inconsistency; the fixed
/// structure here does not hit them in practice).
pub fn build(
    layout: &GuestLayout,
    gic: &GicLayout,
    num_cpus: u32,
    bootargs: &str,
    devices: VirtioDevices,
    options: Options,
) -> Result<Vec<u8>, Error> {
    let mut fdt = FdtWriter::new()?;

    let root = fdt.begin_node("")?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    fdt.property_u32("interrupt-parent", PHANDLE_GIC)?;

    // /chosen: kernel command line, console, + optional initramfs range.
    // stdout-path ties a bare `earlycon` to the PL011 DT node and hands the
    // resource cleanly to the real ttyAMA0 driver, avoiding the region conflict
    // an address-based `earlycon=pl011,<addr>` causes (amba_device_add -16).
    let chosen = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", bootargs)?;
    fdt.property_string("stdout-path", &format!("/pl011@{UART_BASE:x}"))?;
    if layout.initrd_size != 0 {
        fdt.property_u64("linux,initrd-start", layout.initrd_addr)?;
        fdt.property_u64("linux,initrd-end", layout.initrd_end())?;
    }
    fdt.end_node(chosen)?;

    // /memory
    let mem_name = format!("memory@{:x}", layout.ram_base);
    let mem = fdt.begin_node(&mem_name)?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &[layout.ram_base, layout.ram_size])?;
    fdt.end_node(mem)?;

    // /psci: the exit loop services either conduit; see `PsciConduit` for
    // why a guest that owns EL2 must be told `smc`.
    let psci = fdt.begin_node("psci")?;
    fdt.property_string_list(
        "compatible",
        vec!["arm,psci-1.0".into(), "arm,psci-0.2".into()],
    )?;
    let method = match options.psci_conduit {
        PsciConduit::Hvc => "hvc",
        PsciConduit::Smc => "smc",
    };
    fdt.property_string("method", method)?;
    fdt.end_node(psci)?;

    // /cpus
    let cpus = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 1)?;
    fdt.property_u32("#size-cells", 0)?;
    for cpu in 0..num_cpus {
        let cpu_node = fdt.begin_node(&format!("cpu@{cpu:x}"))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        fdt.property_u32("reg", cpu)?;
        if num_cpus > 1 {
            // Secondaries are brought up via PSCI CPU_ON.
            fdt.property_string("enable-method", "psci")?;
        }
        fdt.end_node(cpu_node)?;
    }
    fdt.end_node(cpus)?;

    // /timer: architected timer PPIs. flags = LEVEL_HIGH here; if the guest's
    // timer never fires on first boot, this is the field to try LEVEL_LOW (8)
    // on — the canonical arm64 first-boot tuning knob.
    let timer = fdt.begin_node("timer")?;
    fdt.property_string("compatible", "arm,armv8-timer")?;
    fdt.property_array_u32(
        "interrupts",
        &[
            IRQ_PPI,
            TIMER_PPI_SECURE_PHYS,
            IRQ_LEVEL_HIGH,
            IRQ_PPI,
            TIMER_PPI_PHYS,
            IRQ_LEVEL_HIGH,
            IRQ_PPI,
            TIMER_PPI_VIRT,
            IRQ_LEVEL_HIGH,
            IRQ_PPI,
            TIMER_PPI_HYP_PHYS,
            IRQ_LEVEL_HIGH,
        ],
    )?;
    fdt.end_node(timer)?;

    // /intc: GICv3 distributor + redistributor, or GICv2 distributor + CPU
    // interface. The `reg` shape is the same two regions either way; only the
    // `compatible` string picks which driver Linux binds.
    let gic_name = format!("intc@{:x}", gic.gicd_base);
    let intc = fdt.begin_node(&gic_name)?;
    match gic.version {
        GicVersion::V3 => fdt.property_string("compatible", "arm,gic-v3")?,
        // What QEMU virt advertises for its vGICv2; binds the `arm,gic` driver.
        GicVersion::V2 => fdt.property_string("compatible", "arm,cortex-a15-gic")?,
    }
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_array_u64(
        "reg",
        &[gic.gicd_base, gic.gicd_size, gic.gicr_base, gic.gicr_size],
    )?;
    if let Some(ppi) = options.gic_maintenance_ppi {
        fdt.property_array_u32("interrupts", &[IRQ_PPI, ppi, IRQ_LEVEL_HIGH])?;
    }
    fdt.property_phandle(PHANDLE_GIC)?;
    fdt.end_node(intc)?;

    // /apb-pclk: fixed clock the PL011 references.
    let clk = fdt.begin_node("apb-pclk")?;
    fdt.property_string("compatible", "fixed-clock")?;
    fdt.property_u32("#clock-cells", 0)?;
    fdt.property_u32("clock-frequency", 24_000_000)?;
    fdt.property_string("clock-output-names", "clk24mhz")?;
    fdt.property_phandle(PHANDLE_CLK)?;
    fdt.end_node(clk)?;

    // /pl011: the earlycon UART.
    let uart_name = format!("pl011@{UART_BASE:x}");
    let uart = fdt.begin_node(&uart_name)?;
    fdt.property_string_list(
        "compatible",
        vec!["arm,pl011".into(), "arm,primecell".into()],
    )?;
    fdt.property_array_u64("reg", &[UART_BASE, UART_SIZE])?;
    fdt.property_array_u32("interrupts", &[IRQ_SPI, UART_SPI, IRQ_LEVEL_HIGH])?;
    fdt.property_array_u32("clocks", &[PHANDLE_CLK, PHANDLE_CLK])?;
    fdt.property_string_list("clock-names", vec!["uartclk".into(), "apb_pclk".into()])?;
    fdt.end_node(uart)?;

    // /virtio_mmio slots the guest probes — one per backed device (blk, net).
    // Omitted when absent so the guest never touches an unbacked MMIO region.
    let mut virtio_node = |base: u64, spi: u32| -> Result<(), Error> {
        let node = fdt.begin_node(&format!("virtio_mmio@{base:x}"))?;
        fdt.property_string("compatible", "virtio,mmio")?;
        fdt.property_array_u64("reg", &[base, VIRTIO_SIZE])?;
        fdt.property_array_u32("interrupts", &[IRQ_SPI, spi, IRQ_LEVEL_HIGH])?;
        fdt.end_node(node)
    };
    if devices.blk {
        virtio_node(VIRTIO_BASE, VIRTIO_SPI)?;
    }
    if devices.net {
        virtio_node(VIRTIO_NET_BASE, VIRTIO_NET_SPI)?;
    }
    if devices.vsock {
        virtio_node(VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_SPI)?;
    }
    for index in 0..devices.fs_count {
        // The machine validates these placements before it asks us to build;
        // checked helpers keep a pathological library caller from wrapping.
        if let (Some(base), Some(spi)) = (
            crate::layout::virtio_fs_base(index),
            crate::layout::virtio_fs_spi(index),
        ) {
            virtio_node(base, spi)?;
        }
    }

    fdt.end_node(root)?;
    fdt.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_layout(initrd: u64) -> GuestLayout {
        GuestLayout::new(512 << 20, 0, 16 << 20, 0x2000, initrd)
    }

    #[test]
    fn builds_valid_blob() {
        let l = sample_layout(4 << 20);
        let blob = build(
            &l,
            &GicLayout::QEMU_VIRT,
            1,
            "earlycon=pl011,0x09000000",
            VirtioDevices::default(),
            Options::default(),
        )
        .unwrap();
        // FDT magic 0xd00dfeed, big-endian, at the front of the header.
        assert_eq!(&blob[0..4], &[0xd0, 0x0d, 0xfe, 0xed]);
        // The totalsize field (offset 4, big-endian) matches the blob length.
        let total = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
        assert_eq!(total, blob.len());
    }

    #[test]
    fn builds_without_initrd() {
        let l = sample_layout(0);
        let blob = build(
            &l,
            &GicLayout::QEMU_VIRT,
            2,
            "console=ttyAMA0",
            VirtioDevices::default(),
            Options::default(),
        )
        .unwrap();
        assert_eq!(&blob[0..4], &[0xd0, 0x0d, 0xfe, 0xed]);
    }

    #[test]
    fn advertises_virtio_fs_only_when_backed() {
        let l = sample_layout(0);
        let absent = build(
            &l,
            &GicLayout::QEMU_VIRT,
            1,
            "",
            VirtioDevices::default(),
            Options::default(),
        )
        .unwrap();
        let present = build(
            &l,
            &GicLayout::QEMU_VIRT,
            1,
            "",
            VirtioDevices {
                fs_count: 2,
                ..VirtioDevices::default()
            },
            Options::default(),
        )
        .unwrap();
        let first = format!("virtio_mmio@{:x}", crate::layout::VIRTIO_FS_BASE);
        let second = format!(
            "virtio_mmio@{:x}",
            crate::layout::VIRTIO_FS_BASE + crate::layout::VIRTIO_SIZE
        );
        assert!(!contains(&absent, &first));
        assert!(contains(&present, &first));
        assert!(contains(&present, &second));
    }

    /// Returns true if `needle` appears in the blob's strings/structure, which
    /// is enough to tell the two `compatible` strings apart.
    fn contains(blob: &[u8], needle: &str) -> bool {
        blob.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    /// The GIC version must reach the DTB: a v2 guest has to be told to bind
    /// the `arm,gic` driver, not the v3 one, or it gets no interrupts at all.
    #[test]
    fn intc_compatible_follows_gic_version() {
        let l = sample_layout(0);
        let v3 = build(
            &l,
            &GicLayout::QEMU_VIRT,
            1,
            "",
            VirtioDevices::default(),
            Options::default(),
        )
        .unwrap();
        assert!(contains(&v3, "arm,gic-v3"));
        assert!(!contains(&v3, "arm,cortex-a15-gic"));

        let v2 = build(
            &l,
            &GicLayout::QEMU_VIRT_V2,
            1,
            "",
            VirtioDevices::default(),
            Options::default(),
        )
        .unwrap();
        assert!(contains(&v2, "arm,cortex-a15-gic"));
        assert!(!contains(&v2, "arm,gic-v3"));
    }

    /// Both regions must land in `reg` for v2 as well — the second pair is the
    /// CPU interface there, and a guest that cannot find GICC will not boot.
    #[test]
    fn v2_reg_describes_dist_and_cpu_interface() {
        let l = sample_layout(0);
        let g = GicLayout::QEMU_VIRT_V2;
        let blob = build(&l, &g, 1, "", VirtioDevices::default(), Options::default()).unwrap();
        let mut want = Vec::new();
        for v in [g.gicd_base, g.gicd_size, g.gicr_base, g.gicr_size] {
            want.extend_from_slice(&v.to_be_bytes());
        }
        assert!(
            blob.windows(want.len()).any(|w| w == want.as_slice()),
            "GICv2 reg cell not found in the blob"
        );
    }

    /// Returns the value of property `name` on the first node whose name
    /// starts with `node`, walking the structure block of `blob`.
    fn prop(blob: &[u8], node: &str, name: &str) -> Option<Vec<u8>> {
        let be = |at: usize| u32::from_be_bytes(blob[at..at + 4].try_into().unwrap()) as usize;
        let (off_struct, off_strings) = (be(8), be(12));
        let mut at = off_struct;
        let mut current = String::new();
        loop {
            let token = be(at);
            at += 4;
            match token {
                1 => {
                    let end = at + blob[at..].iter().position(|&b| b == 0).unwrap();
                    current = String::from_utf8_lossy(&blob[at..end]).into_owned();
                    at = (end + 1 + 3) & !3;
                }
                3 => {
                    let (len, nameoff) = (be(at), be(at + 4));
                    let value = &blob[at + 8..at + 8 + len];
                    let key_at = off_strings + nameoff;
                    let key_end = key_at + blob[key_at..].iter().position(|&b| b == 0).unwrap();
                    if current.starts_with(node) && &blob[key_at..key_end] == name.as_bytes() {
                        return Some(value.to_vec());
                    }
                    at = (at + 8 + len + 3) & !3;
                }
                2 | 4 => {}
                _ => return None, // 9 = FDT_END
            }
        }
    }

    fn cells(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
            .collect()
    }

    fn build_with(options: Options) -> Vec<u8> {
        build(
            &sample_layout(0),
            &GicLayout::QEMU_VIRT,
            2,
            "",
            VirtioDevices::default(),
            options,
        )
        .unwrap()
    }

    /// The default guest keeps the HVC conduit and a GIC node with no
    /// interrupts property: nothing about a guest at EL1 changes.
    #[test]
    fn default_options_keep_hvc_and_no_maintenance_interrupt() {
        let blob = build_with(Options::default());
        assert_eq!(prop(&blob, "psci", "method").unwrap(), b"hvc\0");
        let intc = format!("intc@{:x}", GicLayout::QEMU_VIRT.gicd_base);
        assert!(prop(&blob, &intc, "interrupt-controller").is_some());
        assert!(prop(&blob, &intc, "interrupts").is_none());
    }

    /// A guest that owns EL2 is told to use SMC, which still reaches the VMM,
    /// and gets the maintenance interrupt KVM's vgic needs.
    #[test]
    fn nested_options_select_smc_and_describe_maintenance_ppi() {
        let blob = build_with(Options {
            psci_conduit: PsciConduit::Smc,
            gic_maintenance_ppi: Some(9),
        });
        assert_eq!(prop(&blob, "psci", "method").unwrap(), b"smc\0");
        let intc = format!("intc@{:x}", GicLayout::QEMU_VIRT.gicd_base);
        assert_eq!(
            cells(&prop(&blob, &intc, "interrupts").unwrap()),
            [IRQ_PPI, 9, IRQ_LEVEL_HIGH]
        );
    }

    /// The two options are independent: SMC alone adds no interrupt.
    #[test]
    fn smc_alone_adds_no_maintenance_interrupt() {
        let blob = build_with(Options {
            psci_conduit: PsciConduit::Smc,
            gic_maintenance_ppi: None,
        });
        assert_eq!(prop(&blob, "psci", "method").unwrap(), b"smc\0");
        let intc = format!("intc@{:x}", GicLayout::QEMU_VIRT.gicd_base);
        assert!(prop(&blob, &intc, "interrupts").is_none());
    }

    /// The timer node lists the four PPIs in binding order, from the
    /// constants the macOS backend checks against the framework.
    #[test]
    fn timer_ppis_come_from_the_named_constants() {
        let blob = build_with(Options::default());
        assert_eq!(
            cells(&prop(&blob, "timer", "interrupts").unwrap()),
            [
                IRQ_PPI,
                TIMER_PPI_SECURE_PHYS,
                IRQ_LEVEL_HIGH,
                IRQ_PPI,
                TIMER_PPI_PHYS,
                IRQ_LEVEL_HIGH,
                IRQ_PPI,
                TIMER_PPI_VIRT,
                IRQ_LEVEL_HIGH,
                IRQ_PPI,
                TIMER_PPI_HYP_PHYS,
                IRQ_LEVEL_HIGH,
            ]
        );
        assert_eq!(
            (
                TIMER_PPI_SECURE_PHYS,
                TIMER_PPI_PHYS,
                TIMER_PPI_VIRT,
                TIMER_PPI_HYP_PHYS
            ),
            (13, 14, 11, 10)
        );
    }
}

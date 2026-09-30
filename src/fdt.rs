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

/// Length of `/chosen/rng-seed`, in bytes. 64 bytes is 512 bits, twice what
/// the kernel needs before it calls its CRNG initialised.
pub const RNG_SEED_LEN: usize = 64;

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
/// initramfs range. `rng_seed` and `kaslr_seed` go into `/chosen/rng-seed`
/// and `/chosen/kaslr-seed` as they are; the caller draws both fresh for
/// every boot.
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
    rng_seed: &[u8; RNG_SEED_LEN],
    kaslr_seed: u64,
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
    // Under HVF the guest has no RNDR and no SMCCC TRNG, so without a seed
    // its CRNG stays uninitialized until something blocks on getrandom, and
    // then waits seconds for jitter entropy. Linux mixes this in at boot,
    // credits it (random.trust_bootloader), and overwrites the property in
    // its copy of the blob, so the bytes do not stay in guest RAM.
    fdt.property("rng-seed", rng_seed)?;
    // The arm64 kernel takes its KASLR offset only from this property or from
    // RNDR, which an HVF guest does not have and a KVM guest has only on a
    // host with FEAT_RNG. The kernel zeroes the property when it uses it.
    fdt.property_u64("kaslr-seed", kaslr_seed)?;
    fdt.end_node(chosen)?;

    // /memory
    let mem_name = format!("memory@{:x}", layout.ram_base);
    let mem = fdt.begin_node(&mem_name)?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &[layout.ram_base, layout.ram_size])?;
    fdt.end_node(mem)?;

    // /psci: we service the HVC conduit in the exit loop.
    let psci = fdt.begin_node("psci")?;
    fdt.property_string_list(
        "compatible",
        vec!["arm,psci-1.0".into(), "arm,psci-0.2".into()],
    )?;
    fdt.property_string("method", "hvc")?;
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
            13,
            IRQ_LEVEL_HIGH, // secure physical
            IRQ_PPI,
            14,
            IRQ_LEVEL_HIGH, // non-secure physical
            IRQ_PPI,
            11,
            IRQ_LEVEL_HIGH, // virtual
            IRQ_PPI,
            10,
            IRQ_LEVEL_HIGH, // hypervisor physical
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
pub(crate) mod tests {
    use super::*;

    /// A fixed seed, so a test blob is the same every run.
    const SEED: [u8; RNG_SEED_LEN] = [0xa5; RNG_SEED_LEN];
    const KASLR_SEED: u64 = 0x5a5a_5a5a_5a5a_5a5a;

    fn sample_layout(initrd: u64) -> GuestLayout {
        GuestLayout::new(512 << 20, 0, 16 << 20, 0x2000, initrd).unwrap()
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
            &SEED,
            KASLR_SEED,
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
            &SEED,
            KASLR_SEED,
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
            &SEED,
            KASLR_SEED,
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
            &SEED,
            KASLR_SEED,
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
            &SEED,
            KASLR_SEED,
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
            &SEED,
            KASLR_SEED,
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
        let blob = build(&l, &g, 1, "", VirtioDevices::default(), &SEED, KASLR_SEED).unwrap();
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
    pub(crate) fn prop(blob: &[u8], node: &str, name: &str) -> Option<Vec<u8>> {
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

    /// `/chosen` carries the seed it was given, all 64 bytes of it.
    #[test]
    fn chosen_carries_the_rng_seed() {
        let seed: [u8; RNG_SEED_LEN] = std::array::from_fn(|i| i as u8 ^ 0x5a);
        let blob = build(
            &sample_layout(0),
            &GicLayout::QEMU_VIRT,
            1,
            "",
            VirtioDevices::default(),
            &seed,
            KASLR_SEED,
        )
        .unwrap();
        assert_eq!(prop(&blob, "chosen", "rng-seed").unwrap(), seed);
    }

    // Big-endian, as every devicetree cell is; the kernel reads it with
    // fdt64_to_cpu.
    #[test]
    fn chosen_carries_the_kaslr_seed() {
        let blob = build(
            &sample_layout(0),
            &GicLayout::QEMU_VIRT,
            1,
            "",
            VirtioDevices::default(),
            &SEED,
            0x0123_4567_89ab_cdef,
        )
        .unwrap();
        assert_eq!(
            prop(&blob, "chosen", "kaslr-seed").unwrap(),
            0x0123_4567_89ab_cdef_u64.to_be_bytes()
        );
    }
}

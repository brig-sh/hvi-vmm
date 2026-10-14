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

//! The parts of the machine profile both arm64 backends fill the same way:
//! the interrupt controller, the fixed devices and the devicetree digest.
//!
//! Each backend adds what only it can read: the ID registers, `MIDR_EL1` and
//! the PSCI version.

use crate::arch::aarch64::fdt::{self, VirtioDevices};
use crate::arch::aarch64::layout::{
    virtio_blk_base, virtio_blk_spi, GicLayout, GicVersion, GuestLayout, HVI_TIME_PAGE_BASE,
    HVI_TIME_TIMERS_BASE, UART_BASE, UART_SPI, VIRTIO_NET_BASE, VIRTIO_NET_SPI, VIRTIO_VSOCK_BASE,
    VIRTIO_VSOCK_SPI,
};
use crate::arch::aarch64::portable;
use crate::checkpoint::profile::{
    counter_freq_hz, device, hex, sha256_hex, Device, Gic, Irq, MachineProfile, RamRegion, Time,
};
use crate::config::MachineProfileKind;
use crate::devices::hvitime;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::net::VirtioNet;
use crate::devices::virtio::vsock::VirtioVsock;

/// What an arm64 boot settled that the profile records.
pub(crate) struct Arm64Machine<'a> {
    /// The interrupt controller's version and placement.
    pub(crate) gic: &'a GicLayout,
    /// Where the loader put the kernel, devicetree and initramfs.
    pub(crate) layout: &'a GuestLayout,
    /// The number of vCPUs.
    pub(crate) vcpus: u32,
    /// The kernel command line the devicetree carries.
    pub(crate) cmdline: &'a str,
    /// The virtio devices the devicetree describes.
    pub(crate) devices: VirtioDevices,
    /// How the network reaches the host, when the guest has one.
    pub(crate) net_mode: Option<&'a str>,
    /// Guest RAM.
    pub(crate) ram_regions: Vec<crate::memory::RamRegion>,
    /// The machine profile the guest was given.
    pub(crate) profile: MachineProfileKind,
}

/// Returns the profile of an arm64 guest on `backend`, with everything but
/// the CPU's identity, its ID registers and the PSCI version filled.
pub(crate) fn profile(backend: &str, machine: &Arm64Machine<'_>) -> MachineProfile {
    let ram_regions = machine
        .ram_regions
        .iter()
        .copied()
        .map(RamRegion::from)
        .collect();
    let mut p = base(
        backend,
        machine.gic,
        machine.vcpus,
        machine.devices,
        machine.net_mode,
        ram_regions,
    );
    p.firmware.dtb_sha256 = dtb_sha256(machine);
    fill_profile_kind(&mut p, machine.profile);
    p
}

/// Fills the fields of the machine profile `kind` into `p`: under the
/// portable profile its name, its CPU baseline, its GICv2 and `hvi-time`.
fn fill_profile_kind(p: &mut MachineProfile, kind: MachineProfileKind) {
    if kind != MachineProfileKind::PortableArm64V1 {
        return;
    }
    p.profile = kind.name().to_string();
    p.baseline = Some(
        portable::BASELINE
            .iter()
            .map(|(name, value)| ((*name).to_string(), hex(*value)))
            .collect(),
    );
    p.irq = p.gic.clone().map(|layout| Irq {
        kind: "gicv2".into(),
        layout,
    });
    p.time = Some(Time {
        kind: "hvi-time".into(),
        counter_freq_hz: p.counter_freq_hz,
        page_base: HVI_TIME_PAGE_BASE,
        timers_base: HVI_TIME_TIMERS_BASE,
        intid: hvitime::INTID,
    });
}

/// Returns the profile of an arm64 guest a restore builds on `backend`, as
/// [`profile`] does for a boot, from what the restore has instead of a
/// loaded kernel.
///
/// The machine is this host's: its counter, the GIC the backend placed, the
/// devices the restore's flags give the guest. The RAM, the vCPU count and
/// the devicetree's digest are the bundle's, `source`'s. A restore loads no
/// kernel and builds no devicetree, since guest RAM already holds both, so
/// there is no layout here to hash; the restore makes the RAM and the vCPUs
/// exactly as the bundle has them.
pub(crate) fn restored(
    backend: &str,
    gic: &GicLayout,
    devices: VirtioDevices,
    net_mode: Option<&str>,
    source: &MachineProfile,
    kind: MachineProfileKind,
) -> MachineProfile {
    let mut p = base(
        backend,
        gic,
        source.vcpus,
        devices,
        net_mode,
        source.ram_regions.clone(),
    );
    p.firmware
        .dtb_sha256
        .clone_from(&source.firmware.dtb_sha256);
    fill_profile_kind(&mut p, kind);
    p
}

/// Returns the parts of an arm64 profile a boot and a restore fill the same
/// way.
fn base(
    backend: &str,
    gic: &GicLayout,
    vcpus: u32,
    present: VirtioDevices,
    net_mode: Option<&str>,
    ram_regions: Vec<RamRegion>,
) -> MachineProfile {
    let mut p = MachineProfile::for_this_host("aarch64", backend);
    p.counter_freq_hz = counter_freq_hz();
    p.gic = Some(Gic {
        version: match gic.version {
            GicVersion::V2 => 2,
            GicVersion::V3 => 3,
        },
        gicd_base: gic.gicd_base,
        gicd_size: gic.gicd_size,
        gicr_base: gic.gicr_base,
        gicr_size: gic.gicr_size,
    });
    p.ram_regions = ram_regions;
    p.vcpus = vcpus;
    p.devices = devices(present, net_mode);
    p
}

/// Returns the devices of an arm64 guest, in the order the profile lists
/// them: the UART, then the virtio devices the guest has.
fn devices(present: VirtioDevices, net_mode: Option<&str>) -> Vec<Device> {
    let mut devices = vec![device("pl011", UART_BASE, Some(32 + UART_SPI), None)];
    for index in 0..present.blk_count {
        if let (Some(base), Some(spi)) = (virtio_blk_base(index), virtio_blk_spi(index)) {
            devices.push(device(
                "virtio-blk",
                base,
                Some(32 + spi),
                Some(VirtioBlk::FEATURES),
            ));
        }
    }
    if present.net {
        let mut net = device(
            "virtio-net",
            VIRTIO_NET_BASE,
            Some(32 + VIRTIO_NET_SPI),
            Some(VirtioNet::FEATURES),
        );
        net.mode = net_mode.map(str::to_string);
        devices.push(net);
    }
    if present.vsock {
        devices.push(device(
            "virtio-vsock",
            VIRTIO_VSOCK_BASE,
            Some(32 + VIRTIO_VSOCK_SPI),
            Some(VirtioVsock::FEATURES),
        ));
    }
    if present.hvi_time {
        devices.push(device("hvi-time-page", HVI_TIME_PAGE_BASE, None, None));
        devices.push(device(
            "hvi-time",
            HVI_TIME_TIMERS_BASE,
            Some(hvitime::INTID),
            None,
        ));
    }
    devices
}

/// Returns the SHA-256 of the guest's devicetree with its two seeds zeroed.
///
/// The loader draws fresh seeds for every boot, so a digest of the tree in
/// RAM would differ between any two guests. The rest of the tree is the
/// layout the guest kernel holds, which is what a restore must match.
fn dtb_sha256(machine: &Arm64Machine<'_>) -> Option<String> {
    fdt::build(
        machine.layout,
        machine.gic,
        machine.vcpus,
        machine.cmdline,
        machine.devices,
        &[0; fdt::RNG_SEED_LEN],
        0,
    )
    .ok()
    .map(|dtb| sha256_hex(&dtb))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine<'a>(gic: &'a GicLayout, layout: &'a GuestLayout) -> Arm64Machine<'a> {
        Arm64Machine {
            gic,
            layout,
            vcpus: 2,
            cmdline: "console=ttyAMA0",
            devices: VirtioDevices {
                blk_count: 1,
                net: true,
                vsock: false,
                fs_count: 0,
                timer: fdt::ArchTimer::Interrupts,
                hvi_time: false,
            },
            net_mode: Some("stub"),
            ram_regions: vec![crate::memory::RamRegion {
                gpa: 0x4000_0000,
                size: 512 << 20,
                file_offset: 0,
            }],
            profile: MachineProfileKind::Native,
        }
    }

    fn layout() -> GuestLayout {
        GuestLayout::new(512 << 20, 0x4020_0000, 0x200_0000, 0x1000, 0)
    }

    // Two boots of one configuration draw different seeds; their profiles
    // must still match, or no guest could ever be restored.
    #[test]
    fn the_devicetree_digest_ignores_the_seeds_and_follows_the_layout() {
        let (gic, layout) = (GicLayout::QEMU_VIRT, layout());
        let a = profile("kvm", &machine(&gic, &layout));
        let b = profile("kvm", &machine(&gic, &layout));
        assert!(a.firmware.dtb_sha256.is_some());
        assert_eq!(a.firmware.dtb_sha256, b.firmware.dtb_sha256);
        let mut other = machine(&gic, &layout);
        other.cmdline = "console=ttyAMA0 quiet";
        let c = profile("kvm", &other);
        assert_ne!(a.firmware.dtb_sha256, c.firmware.dtb_sha256);
    }

    /// The portable profile's devicetree and its digest do not depend on
    /// the backend's name or its network mode: `portable::devicetree` given
    /// one configuration, under either name, yields one digest, and the
    /// profile records the same baseline, GIC and `hvi-time` windows.
    ///
    /// This feeds both names the same layout through the shared helper, so
    /// it cannot catch a backend that hands the loader other inputs (the
    /// command line, the vCPU count, the devices). The evidence for that
    /// is the boots: a 1-vCPU guest on this Mac and on rp2 records the same
    /// `dtb_sha256`, and so does a 2-vCPU guest.
    #[test]
    fn portable_devicetree_inputs_do_not_depend_on_the_backend() {
        use crate::config::BootConfig;
        let cfg = |cmdline: &str, timer: Option<bool>| BootConfig {
            kernel: Vec::new(),
            initramfs: None,
            mem_bytes: 512 << 20,
            cmdline: cmdline.into(),
            disks: Vec::new(),
            fs_shares: Vec::new(),
            fs: Vec::new(),
            net: true,
            net_gateway: None,
            net_tap: None,
            net_mac: None,
            events: None,
            sandbox_id: String::new(),
            vcpus: 2,
            agent_sock: None,
            profile_out: None,
            control_sock: None,
            checkpoint_root: None,
            plugin: None,
            sandbox: false,
            profile: MachineProfileKind::PortableArm64V1,
            arch_timer_irq: timer,
            stop: None,
        };
        let layout = layout();
        let digest = |backend: &str, cfg: &BootConfig| {
            let dt = portable::devicetree(cfg, 2, 1, true, false).unwrap();
            let machine = Arm64Machine {
                gic: &dt.gic,
                layout: &layout,
                vcpus: 2,
                cmdline: &dt.cmdline,
                devices: dt.devices,
                net_mode: Some(if backend == "kvm" { "tap" } else { "stub" }),
                ram_regions: vec![crate::memory::RamRegion {
                    gpa: 0x4000_0000,
                    size: 512 << 20,
                    file_offset: 0,
                }],
                profile: cfg.profile,
            };
            profile(backend, &machine)
        };
        let base = cfg("console=ttyAMA0", None);
        let (hvf, kvm) = (digest("hvf", &base), digest("kvm", &base));
        assert!(hvf.firmware.dtb_sha256.is_some());
        assert_eq!(hvf.firmware.dtb_sha256, kvm.firmware.dtb_sha256);
        assert_eq!(hvf.profile, "portable-arm64-v1");
        assert_eq!(hvf.baseline, kvm.baseline);
        assert_eq!(hvf.irq, kvm.irq);
        assert_eq!(hvf.irq.as_ref().map(|i| i.layout.version), Some(2));
        let time = hvf.time.as_ref().unwrap();
        assert_eq!(
            (time.page_base, time.timers_base, time.intid),
            (0x0d10_0000, 0x0d11_0000, 20)
        );
        let kinds: Vec<_> = hvf.devices.iter().map(|d| d.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "pl011",
                "virtio-blk",
                "virtio-net",
                "hvi-time-page",
                "hvi-time"
            ]
        );
        // The tree is the portable one: hvi-time, the prefixed command line
        // and a timer without interrupts. Each change moves the digest.
        let tree = |cfg: &BootConfig| {
            let dt = portable::devicetree(cfg, 2, 1, true, false).unwrap();
            fdt::build(
                &layout,
                &dt.gic,
                2,
                &dt.cmdline,
                dt.devices,
                &[0; fdt::RNG_SEED_LEN],
                0,
            )
            .unwrap()
        };
        let blob = tree(&base);
        let has = |needle: &str| blob.windows(needle.len()).any(|w| w == needle.as_bytes());
        assert!(has("hvi,time-v1"));
        assert!(has(
            "arm64.nopauth arm64.nobti arm64.nosve arm64.nosme arm64.nomte console=ttyAMA0"
        ));
        assert!(fdt::tests::prop(&blob, "timer", "interrupts").is_none());
        assert_eq!(sha256_hex(&blob), hvf.firmware.dtb_sha256.clone().unwrap());
        let debug = digest("kvm", &cfg("console=ttyAMA0", Some(true)));
        assert_ne!(debug.firmware.dtb_sha256, hvf.firmware.dtb_sha256);
    }

    #[test]
    fn devices_are_listed_with_their_windows_and_lines() {
        let (gic, layout) = (GicLayout::QEMU_VIRT, layout());
        let p = profile("kvm", &machine(&gic, &layout));
        let kinds: Vec<_> = p.devices.iter().map(|d| d.kind.as_str()).collect();
        assert_eq!(kinds, ["pl011", "virtio-blk", "virtio-net"]);
        assert_eq!(p.devices[1].irq, Some(32 + virtio_blk_spi(0).unwrap()));
        assert_eq!(p.devices[2].mode.as_deref(), Some("stub"));
        assert_eq!(p.gic.as_ref().map(|g| g.version), Some(3));
        assert_eq!(p.counter_freq_hz, counter_freq_hz());
        assert_eq!(p.vcpus, 2);
    }
}

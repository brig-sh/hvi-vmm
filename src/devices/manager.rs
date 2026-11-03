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

//! The devices of a VM, attached one call per device.
//!
//! A backend makes a [`DeviceManager`] with the machine's [`Placement`] and a
//! maker of its interrupt lines, and attaches the virtio devices the
//! configuration asks for in one call. An attach opens the device, places it,
//! puts it on the MMIO bus, connects its interrupt and records it. The records
//! describe the virtio devices to the guest's firmware, and
//! [`DeviceManager::finish`] hands the bus and the devices to the guest.
//!
//! The firmware lists the virtio devices in the order they were attached, and
//! Linux probes them in that order, so the guest probes the disks in argv
//! order. It still has to tell them apart by serial.

use std::ops::Range;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use crate::config::FsConfig;
#[cfg(target_os = "macos")]
use crate::config::FsShare;
use crate::config::{BootConfig, DiskConfig};
use crate::devices::bus::{self, Bus};
use crate::devices::irq::IrqLine;
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::{pl011::Pl011, rtc_pl031::Pl031};
use crate::devices::virtio::block::{self, VirtioBlk};
#[cfg(target_os = "linux")]
use crate::devices::virtio::fs::vhost_user;
#[cfg(target_os = "macos")]
use crate::devices::virtio::fs::worker::{self, FsTransport};
use crate::devices::virtio::mmio::RANGE_SIZE;
use crate::devices::virtio::net::{self, VirtioNet};
use crate::devices::virtio::vsock::{self, VsockBridge};
use crate::devices::virtio::{MmioTransport, VirtioMmio};
use crate::events::Ledger;
use crate::io_threads::NetSource;
use crate::memory::GuestRam;

/// The error an attach returns.
type Error = Box<dyn std::error::Error + Send + Sync>;

/// The base of a device's MMIO range and its interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Slot {
    /// The first address of the range.
    pub(crate) base: u64,
    /// The interrupt, a GSI on x86-64 and an SPI on arm64, as the machine's
    /// firmware numbers it.
    pub(crate) irq: u32,
}

/// Where each virtio device sits on one machine.
pub(crate) trait Placement {
    /// Returns the slot of disk `index`, or `None` past the last one.
    fn disk(&self, index: usize) -> Option<Slot>;

    /// Returns the slot of the network device.
    fn net(&self) -> Slot;

    /// Returns the slot of the vsock device.
    fn vsock(&self) -> Slot;

    /// Returns the slot of virtio-fs export `index`.
    ///
    /// # Errors
    ///
    /// Errors when the machine has no slot left for it.
    fn export(&self, index: usize) -> Result<Slot, String>;
}

/// What a virtio device is, as the guest's firmware describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceKind {
    /// A virtio-blk disk.
    Block,
    /// The virtio-net device.
    Net,
    /// The virtio-vsock device.
    Vsock,
    /// A virtio-fs export.
    Fs,
}

/// A virtio device on the MMIO bus, as the guest's firmware describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceRecord {
    /// What the device is.
    pub(crate) kind: DeviceKind,
    /// The addresses it answers on.
    pub(crate) range: Range<u64>,
    /// Its interrupt, as in [`Slot::irq`].
    pub(crate) irq: u32,
}

/// The bus and the devices a [`DeviceManager`] attached, which the guest takes.
pub(crate) struct Devices {
    /// The devices a vCPU reaches through MMIO.
    pub(crate) mmio_bus: Bus,
    /// The virtio-blk disks, in the order of `BootConfig::disks`.
    pub(crate) disks: Vec<Arc<Mutex<VirtioBlk>>>,
    /// The virtio-net device, when the VM has a network.
    pub(crate) net: Option<Arc<Mutex<VirtioNet>>>,
    /// Where the network relay reads the host's frames, when it reads any.
    pub(crate) net_source: Option<NetSource>,
    /// The bridge that serves the agent socket, when the VM has one.
    pub(crate) bridge: Option<VsockBridge>,
    /// The virtio-fs exports, each served by the caller's daemon.
    #[cfg(target_os = "linux")]
    pub(crate) exports: Vec<vhost_user::Export>,
    /// The virtio-fs exports, served in this process.
    #[cfg(target_os = "macos")]
    pub(crate) exports: Vec<worker::Export>,
}

/// The devices of a VM as a backend attaches them.
pub(crate) struct DeviceManager {
    /// Guest RAM, which the devices' queues are in.
    ram: Arc<GuestRam>,
    /// The ledger the devices' events go to.
    ledger: Arc<Ledger>,
    /// Where each device sits.
    placement: Box<dyn Placement>,
    /// Makes the line for an interrupt, numbered as in [`Slot::irq`].
    line: Box<dyn Fn(u32) -> Arc<dyn IrqLine>>,
    /// A record per virtio device, in the order they were attached.
    records: Vec<DeviceRecord>,
    /// What has been attached.
    devices: Devices,
}

impl DeviceManager {
    /// Returns a manager with no devices, which places them by `placement` and
    /// connects them to the lines `line` makes.
    pub(crate) fn new(
        ram: &Arc<GuestRam>,
        ledger: &Arc<Ledger>,
        placement: impl Placement + 'static,
        line: impl Fn(u32) -> Arc<dyn IrqLine> + 'static,
    ) -> Self {
        Self {
            ram: Arc::clone(ram),
            ledger: Arc::clone(ledger),
            placement: Box::new(placement),
            line: Box::new(line),
            records: Vec::new(),
            devices: Devices {
                mmio_bus: Bus::new(),
                disks: Vec::new(),
                net: None,
                net_source: None,
                bridge: None,
                exports: Vec::new(),
            },
        }
    }

    /// Returns a record per virtio device, in the order they were attached.
    pub(crate) fn records(&self) -> &[DeviceRecord] {
        &self.records
    }

    /// Returns the bus and the devices.
    pub(crate) fn finish(self) -> Devices {
        self.devices
    }

    /// Attaches the virtio devices `cfg` asks for, the disks first and in argv
    /// order, then the network, the agent device and the exports.
    ///
    /// On Linux the exports' daemons map guest RAM through `ram_fd`.
    ///
    /// # Errors
    ///
    /// Errors when a device does not open, the machine has no slot left for it,
    /// or a range overlaps one already on the bus.
    pub(crate) fn attach_virtio_devices(
        &mut self,
        cfg: &BootConfig,
        #[cfg(target_os = "linux")] ram_fd: RawFd,
    ) -> Result<(), Error> {
        self.attach_disks(&cfg.disks)?;
        self.attach_net(cfg)?;
        self.attach_vsock(cfg.agent_sock.as_deref())?;
        #[cfg(target_os = "linux")]
        self.attach_exports(&cfg.fs, ram_fd)?;
        #[cfg(target_os = "macos")]
        self.attach_exports(&cfg.fs_shares)?;
        Ok(())
    }

    /// Attaches a disk for each entry of `disks`, in order.
    ///
    /// # Errors
    ///
    /// Errors when `block::open_disks` refuses the disks, or a range overlaps
    /// one already on the bus.
    fn attach_disks(&mut self, disks: &[DiskConfig]) -> Result<(), Error> {
        for (index, disk) in block::open_disks(disks)?.into_iter().enumerate() {
            // `open_disks` refuses more disks than any machine has slots for.
            let slot = self
                .placement
                .disk(index)
                .expect("every disk should have a slot");
            self.attach_virtio(DeviceKind::Block, slot, &disk)?;
            self.devices.disks.push(disk);
        }
        Ok(())
    }

    /// Attaches the network `cfg` asks for, when it asks for one.
    ///
    /// # Errors
    ///
    /// Errors when `net::open` does, or the range overlaps one already on the
    /// bus.
    fn attach_net(&mut self, cfg: &BootConfig) -> Result<(), Error> {
        let Some(network) = net::open(cfg)? else {
            return Ok(());
        };
        self.attach_virtio(DeviceKind::Net, self.placement.net(), &network.device)?;
        self.devices.net = Some(network.device);
        self.devices.net_source = network.source;
        Ok(())
    }

    /// Attaches the agent device and binds its host socket at `path`, when
    /// there is one.
    ///
    /// # Errors
    ///
    /// Errors when the socket cannot be bound, or the range overlaps one
    /// already on the bus.
    fn attach_vsock(&mut self, path: Option<&str>) -> Result<(), Error> {
        let Some(agent) = vsock::open(path, &self.ram)? else {
            return Ok(());
        };
        self.attach_virtio(DeviceKind::Vsock, self.placement.vsock(), &agent.device)?;
        self.devices.bridge = Some(agent.bridge);
        Ok(())
    }

    /// Attaches an export for each of `exports`, served by the daemon on its
    /// socket, with guest RAM shared through `ram_fd`.
    ///
    /// Every export is placed before any daemon is connected, so a machine with
    /// too few slots is refused before a daemon sees a connection.
    ///
    /// # Errors
    ///
    /// Errors when the machine has no slot for an export, `vhost_user::attach`
    /// fails, or a range overlaps one already on the bus.
    #[cfg(target_os = "linux")]
    fn attach_exports(&mut self, exports: &[FsConfig], ram_fd: RawFd) -> Result<(), Error> {
        let slots = self.export_slots(exports.len())?;
        for (export, slot) in vhost_user::attach(exports, ram_fd)?.into_iter().zip(slots) {
            self.attach_virtio(DeviceKind::Fs, slot, &export.dev)?;
            self.devices.exports.push(export);
        }
        Ok(())
    }

    /// Attaches an export for each of `shares`, served in this process.
    ///
    /// # Errors
    ///
    /// Errors when the machine has no slot for an export, `worker::attach`
    /// fails, or a range overlaps one already on the bus.
    #[cfg(target_os = "macos")]
    fn attach_exports(&mut self, shares: &[FsShare]) -> Result<(), Error> {
        let slots = self.export_slots(shares.len())?;
        for (export, slot) in worker::attach(shares)?.into_iter().zip(slots) {
            export
                .dev
                .lock()
                .unwrap()
                .connect_irq((self.line)(slot.irq));
            self.insert(
                DeviceKind::Fs,
                slot,
                Arc::new(FsTransport::new(&export, &self.ram)),
            )?;
            self.devices.exports.push(export);
        }
        Ok(())
    }

    /// Returns the slots of `count` exports.
    ///
    /// # Errors
    ///
    /// Errors when the machine has no slot left for one.
    fn export_slots(&self, count: usize) -> Result<Vec<Slot>, String> {
        (0..count)
            .map(|index| self.placement.export(index))
            .collect()
    }

    /// Puts the PL011 UART and the PL031 RTC on the bus at their fixed ranges,
    /// and returns the UART, whose line the backend connects.
    ///
    /// # Errors
    ///
    /// Errors when a range overlaps one already on the bus.
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn attach_uart_and_rtc(&mut self) -> Result<Arc<Mutex<Pl011>>, Error> {
        use crate::arch::aarch64::layout::{RTC_BASE, RTC_SIZE, UART_BASE, UART_SIZE};
        let pl011 = Arc::new(Mutex::new(Pl011::new()));
        let bus = &mut self.devices.mmio_bus;
        bus.insert(
            UART_BASE,
            UART_SIZE,
            Arc::clone(&pl011) as Arc<dyn bus::Device>,
        )?;
        bus.insert(RTC_BASE, RTC_SIZE, Arc::new(Mutex::new(Pl031::new())))?;
        Ok(pl011)
    }

    /// Connects the virtio `device` of `kind` to the line of `slot`, puts it on
    /// the bus there and records it.
    fn attach_virtio<D: VirtioMmio + Send + 'static>(
        &mut self,
        kind: DeviceKind,
        slot: Slot,
        device: &Arc<Mutex<D>>,
    ) -> Result<(), String> {
        device.lock().unwrap().connect_irq((self.line)(slot.irq));
        self.insert(
            kind,
            slot,
            Arc::new(MmioTransport::new(device, &self.ram, &self.ledger)),
        )
    }

    /// Puts the virtio `device` of `kind` on the bus at `slot` and records it.
    fn insert(
        &mut self,
        kind: DeviceKind,
        slot: Slot,
        device: Arc<dyn bus::Device>,
    ) -> Result<(), String> {
        self.devices
            .mmio_bus
            .insert(slot.base, RANGE_SIZE, device)?;
        self.records.push(DeviceRecord {
            kind,
            range: slot.base..slot.base + RANGE_SIZE,
            irq: slot.irq,
        });
        Ok(())
    }
}

// The tests make disk images and an agent socket of their own; see
// clippy.toml.
#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    /// A placement that puts each device on a page of its own, numbered by
    /// kind, with the interrupt equal to the page.
    struct Pages {
        /// Whether vsock takes the network's slot.
        vsock_on_net: bool,
    }

    impl Pages {
        fn slot(page: u64) -> Slot {
            Slot {
                base: page * 0x1000,
                irq: page as u32,
            }
        }
    }

    impl Placement for Pages {
        fn disk(&self, index: usize) -> Option<Slot> {
            Some(Self::slot(10 + index as u64))
        }

        fn net(&self) -> Slot {
            Self::slot(20)
        }

        fn vsock(&self) -> Slot {
            Self::slot(if self.vsock_on_net { 20 } else { 30 })
        }

        fn export(&self, index: usize) -> Result<Slot, String> {
            Ok(Self::slot(40 + index as u64))
        }
    }

    /// A line that sets nothing.
    struct NoLine;

    impl IrqLine for NoLine {
        fn set_level(&self, _level: bool) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Returns a manager on `placement` and the interrupts it made lines for.
    fn manager(placement: Pages) -> (DeviceManager, Arc<Mutex<Vec<u32>>>) {
        let ram = Arc::new(GuestRam::from_ranges(&[(0x4000_0000, 0x10000)]));
        let ledger = Arc::new(Ledger::new(None, "manager-test").unwrap());
        let lines = Arc::new(Mutex::new(Vec::new()));
        let made = Arc::clone(&lines);
        let manager = DeviceManager::new(&ram, &ledger, placement, move |irq| {
            made.lock().unwrap().push(irq);
            Arc::new(NoLine) as Arc<dyn IrqLine>
        });
        (manager, lines)
    }

    /// Returns a path under the temporary directory for the file `name`, unique
    /// to this process, with nothing at it.
    fn scratch(name: &str) -> String {
        let path = std::env::temp_dir().join(format!("hvi-manager-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path.to_str().expect("a UTF-8 temporary path").to_string()
    }

    /// Returns the configuration of a writable disk at a fresh 1 MiB image.
    fn disk(name: &str) -> DiskConfig {
        let path = scratch(name);
        std::fs::File::create(&path)
            .unwrap()
            .set_len(1 << 20)
            .unwrap();
        DiskConfig {
            path,
            read_only: false,
            serial: None,
        }
    }

    #[test]
    fn devices_take_their_slots_and_lines_in_attach_order() {
        let (mut devices, lines) = manager(Pages {
            vsock_on_net: false,
        });
        let disks = vec![disk("disk0"), disk("disk1")];
        let agent = scratch("agent");
        let cfg = BootConfig {
            disks: disks.clone(),
            net: true,
            agent_sock: Some(agent.clone()),
            ..BootConfig::with_no_devices(1)
        };
        #[cfg(target_os = "linux")]
        devices.attach_virtio_devices(&cfg, -1).unwrap();
        #[cfg(target_os = "macos")]
        devices.attach_virtio_devices(&cfg).unwrap();
        let page = |page: u64, kind| DeviceRecord {
            kind,
            range: page * 0x1000..page * 0x1000 + RANGE_SIZE,
            irq: page as u32,
        };
        assert_eq!(
            devices.records(),
            [
                page(10, DeviceKind::Block),
                page(11, DeviceKind::Block),
                page(20, DeviceKind::Net),
                page(30, DeviceKind::Vsock),
            ]
        );
        assert_eq!(*lines.lock().unwrap(), [10, 11, 20, 30]);

        let attached = devices.finish();
        assert_eq!(attached.disks.len(), 2);
        assert!(attached.net.is_some());
        assert!(attached.bridge.is_some());
        let mut magic = [0; 4];
        attached
            .mmio_bus
            .read(
                11 * 0x1000 + crate::devices::virtio::mmio::MAGIC,
                &mut magic,
            )
            .unwrap();
        assert_eq!(&magic, b"virt");
        for path in disks.iter().map(|disk| &disk.path).chain([&agent]) {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn device_on_a_taken_slot_is_refused() {
        let (mut devices, _) = manager(Pages { vsock_on_net: true });
        let agent = scratch("taken");
        devices
            .attach_net(&BootConfig {
                net: true,
                ..BootConfig::with_no_devices(1)
            })
            .unwrap();
        let err = devices.attach_vsock(Some(&agent)).unwrap_err().to_string();
        let _ = std::fs::remove_file(&agent);
        assert!(err.contains("overlaps"), "{err}");
        assert_eq!(devices.records().len(), 1);
    }
}

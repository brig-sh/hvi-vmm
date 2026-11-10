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
//! A backend makes a [`DeviceManager`] with the machine's [`SlotAllocator`] and
//! its [`irq::Chip`], and attaches the virtio devices the configuration asks
//! for in one call. An attach opens the device, places it, puts it on the MMIO
//! bus behind a transport, gives it an interrupt on its slot's line and records
//! it. The records describe the virtio devices to the guest's firmware, and
//! [`DeviceManager::finish`] hands the bus and the devices to the guest.
//!
//! The firmware lists the virtio devices in the order they were attached, and
//! Linux probes them in that order, so the guest probes the disks in argv
//! order. It still has to tell them apart by serial.

#[cfg(target_os = "linux")]
use std::io;
use std::ops::Range;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use vmm_sys_util::eventfd::EventFd;

#[cfg(target_os = "linux")]
use crate::config::FsConfig;
#[cfg(target_os = "macos")]
use crate::config::FsShare;
use crate::config::{BootConfig, DiskConfig};
use crate::devices::bus::{self, Bus};
use crate::devices::irq;
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::{pl011::Pl011, rtc_pl031::Pl031};
use crate::devices::virtio;
use crate::devices::virtio::block::{self, VirtioBlk};
#[cfg(target_os = "linux")]
use crate::devices::virtio::fs::vhost_user;
#[cfg(target_os = "macos")]
use crate::devices::virtio::fs::worker;
use crate::devices::virtio::mmio::{self, Interrupt, RANGE_SIZE};
use crate::devices::virtio::net::{self, VirtioNet};
use crate::devices::virtio::vsock;
use crate::events::Ledger;
use crate::io_threads::HostWork;
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

/// The slots of a machine's virtio devices, handed out in order.
///
/// Each slot takes the next range of [`RANGE_SIZE`] addresses from the start of
/// a window, and the next interrupt from a list. Every kind of virtio device
/// takes its slot from the same allocator.
pub(crate) struct SlotAllocator {
    /// The addresses the ranges come from.
    window: Range<u64>,
    /// The interrupts, in the order they are handed out.
    irqs: Vec<u32>,
    /// How many slots have been handed out.
    taken: usize,
}

impl SlotAllocator {
    /// Returns an allocator that hands out the ranges of `window` with the
    /// interrupts of `irqs`, in order.
    pub(crate) fn new(window: Range<u64>, irqs: impl IntoIterator<Item = u32>) -> Self {
        Self {
            window,
            irqs: irqs.into_iter().collect(),
            taken: 0,
        }
    }

    /// Returns how many slots the machine has in all.
    pub(crate) fn capacity(&self) -> usize {
        let ranges = (self.window.end.saturating_sub(self.window.start) / RANGE_SIZE) as usize;
        ranges.min(self.irqs.len())
    }

    /// Refuses `count` virtio devices when the machine has fewer slots.
    ///
    /// # Errors
    ///
    /// Errors when `count` is past [`capacity`](Self::capacity).
    pub(crate) fn check_room(&self, count: usize) -> Result<(), String> {
        let capacity = self.capacity();
        if count > capacity {
            return Err(format!(
                "{count} virtio devices given; at most {capacity} fit"
            ));
        }
        Ok(())
    }

    /// Returns the next slot.
    ///
    /// # Errors
    ///
    /// Errors when the window has no range left or the list no interrupt.
    pub(crate) fn allocate(&mut self) -> Result<Slot, String> {
        let base = self.window.start + self.taken as u64 * RANGE_SIZE;
        if base.saturating_add(RANGE_SIZE) > self.window.end {
            return Err(format!(
                "no address range left below {:#x} after {} virtio devices",
                self.window.end, self.taken
            ));
        }
        let irq = *self
            .irqs
            .get(self.taken)
            .ok_or_else(|| format!("no interrupt left after {} virtio devices", self.taken))?;
        self.taken += 1;
        Ok(Slot { base, irq })
    }
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
    /// What the devices run on the host beside the vCPUs.
    pub(crate) host: HostWork,
    /// The virtio-fs exports, served in this process.
    #[cfg(target_os = "macos")]
    pub(crate) exports: Vec<worker::Export>,
}

/// A function that registers an eventfd for a guest's 4-byte write of a value
/// to an address, so the write signals the eventfd with no exit to hvi.
#[cfg(target_os = "linux")]
type IoeventfdRegistrar = Box<dyn Fn(&EventFd, u64, u32) -> io::Result<()>>;

/// The devices of a VM as a backend attaches them.
pub(crate) struct DeviceManager<C> {
    /// Guest RAM, which the devices' queues are in.
    ram: Arc<GuestRam>,
    /// The ledger the devices' events go to.
    ledger: Arc<Ledger>,
    /// The slots the virtio devices take.
    slots: SlotAllocator,
    /// The interrupt controller the devices' lines are on.
    irq_chip: C,
    /// The backend's function that registers an ioeventfd.
    #[cfg(target_os = "linux")]
    register_ioeventfd: IoeventfdRegistrar,
    /// A record per virtio device, in the order they were attached.
    records: Vec<DeviceRecord>,
    /// What has been attached.
    devices: Devices,
}

impl<C: irq::Chip> DeviceManager<C> {
    /// Returns a manager with no devices, which places them in `slots` and
    /// connects them to lines of `irq_chip`.
    ///
    /// On Linux, `register_ioeventfd` registers the eventfds of each device's
    /// `notify_fds`.
    pub(crate) fn new(
        ram: &Arc<GuestRam>,
        ledger: &Arc<Ledger>,
        slots: SlotAllocator,
        irq_chip: C,
        #[cfg(target_os = "linux")] register_ioeventfd: impl Fn(&EventFd, u64, u32) -> io::Result<()>
            + 'static,
    ) -> Self {
        Self {
            ram: Arc::clone(ram),
            ledger: Arc::clone(ledger),
            slots,
            irq_chip,
            #[cfg(target_os = "linux")]
            register_ioeventfd: Box::new(register_ioeventfd),
            records: Vec::new(),
            devices: Devices {
                mmio_bus: Bus::new(),
                disks: Vec::new(),
                net: None,
                host: HostWork::default(),
                #[cfg(target_os = "macos")]
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
    /// Errors when `block::open_disks` refuses the disks, no slot is left for a
    /// disk, or a range overlaps one already on the bus.
    fn attach_disks(&mut self, disks: &[DiskConfig]) -> Result<(), Error> {
        for (index, disk) in block::open_disks(disks)?.into_iter().enumerate() {
            let slot = self
                .slots
                .allocate()
                .map_err(|e| format!("virtio-blk disk {index}: {e}"))?;
            self.attach_virtio(DeviceKind::Block, slot, &disk)?;
            self.devices.disks.push(disk);
        }
        Ok(())
    }

    /// Attaches the network `cfg` asks for, when it asks for one.
    ///
    /// # Errors
    ///
    /// Errors when `net::open` does, no slot is left, or the range overlaps one
    /// already on the bus.
    fn attach_net(&mut self, cfg: &BootConfig) -> Result<(), Error> {
        let Some(network) = net::open(cfg)? else {
            return Ok(());
        };
        let slot = self
            .slots
            .allocate()
            .map_err(|e| format!("virtio-net: {e}"))?;
        self.attach_virtio(DeviceKind::Net, slot, &network.device)?;
        if let Some(source) = network.source {
            source.queue_relay(&network.device, &self.ram, &mut self.devices.host);
        }
        self.devices.net = Some(network.device);
        Ok(())
    }

    /// Attaches the agent device and binds its host socket at `path`, when
    /// there is one.
    ///
    /// # Errors
    ///
    /// Errors when the socket cannot be bound, no slot is left, or the range
    /// overlaps one already on the bus.
    fn attach_vsock(&mut self, path: Option<&str>) -> Result<(), Error> {
        let Some(agent) = vsock::open(path, &self.ram)? else {
            return Ok(());
        };
        let slot = self
            .slots
            .allocate()
            .map_err(|e| format!("virtio-vsock: {e}"))?;
        self.attach_virtio(DeviceKind::Vsock, slot, &agent.device)?;
        let bridge = agent.bridge;
        self.devices
            .host
            .spawn("agent bridge", move |stop| bridge.run(&stop));
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
    /// Errors when no slot is left for an export, `vhost_user::attach` fails,
    /// or a range overlaps one already on the bus.
    #[cfg(target_os = "linux")]
    fn attach_exports(&mut self, exports: &[FsConfig], ram_fd: RawFd) -> Result<(), Error> {
        let slots = self.export_slots(exports.len())?;
        let exports = vhost_user::attach(exports, ram_fd)?;
        for (export, slot) in exports.iter().zip(slots) {
            let interrupt = self.attach_virtio(DeviceKind::Fs, slot, &export.dev)?;
            export.queue_interrupts(&interrupt, &mut self.devices.host);
        }
        // A vCPU in an export's activation or reset waits on its daemon, where
        // no kick reaches it. Ending the connections at the stop frees it.
        self.devices
            .host
            .on_vcpu_stop(move || vhost_user::shut_down(&exports));
        Ok(())
    }

    /// Attaches an export for each of `shares`, served in this process.
    ///
    /// # Errors
    ///
    /// Errors when no slot is left for an export, `worker::attach` fails, or a
    /// range overlaps one already on the bus.
    #[cfg(target_os = "macos")]
    fn attach_exports(&mut self, shares: &[FsShare]) -> Result<(), Error> {
        let slots = self.export_slots(shares.len())?;
        for (export, slot) in worker::attach(shares)?.into_iter().zip(slots) {
            self.attach_virtio(DeviceKind::Fs, slot, &export.dev)?;
            export.queue_threads(&self.ram, &mut self.devices.host);
            self.devices.exports.push(export);
        }
        Ok(())
    }

    /// Returns the slots of `count` exports.
    ///
    /// # Errors
    ///
    /// Errors when the machine has no slot left for one.
    fn export_slots(&mut self, count: usize) -> Result<Vec<Slot>, String> {
        (0..count)
            .map(|index| {
                self.slots
                    .allocate()
                    .map_err(|e| format!("virtio-fs export {index}: {e}"))
            })
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

    /// Puts the virtio `device` of `kind` on the bus at `slot` behind a
    /// transport and records it.
    ///
    /// Returns the device's interrupt, which drives the line of `slot`.
    ///
    /// # Errors
    ///
    /// Errors when the range of `slot` overlaps one already on the bus, or the
    /// hypervisor refuses a notification eventfd.
    fn attach_virtio<D: virtio::Device + 'static>(
        &mut self,
        kind: DeviceKind,
        slot: Slot,
        device: &Arc<Mutex<D>>,
    ) -> Result<Arc<Interrupt>, String> {
        let interrupt = Arc::new(Interrupt::new(self.irq_chip.line(slot.irq)));
        self.insert(
            kind,
            slot,
            Arc::new(mmio::Transport::new(
                device,
                &interrupt,
                &self.ram,
                &self.ledger,
            )),
        )?;
        #[cfg(target_os = "linux")]
        for (fd, address, value) in mmio::notify_ioeventfds(&*device.lock().unwrap(), slot.base) {
            (self.register_ioeventfd)(fd, address, value)
                .map_err(|e| format!("registering a queue notification at {address:#x}: {e}"))?;
        }
        Ok(interrupt)
    }

    /// Puts `device`, the transport of a virtio device of `kind`, on the bus at
    /// `slot` and records it.
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
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;

    use super::*;
    #[cfg(target_os = "linux")]
    use crate::devices::virtio::mmio::testing::EventfdDevice;

    /// A line that sets nothing.
    struct NoLine;

    impl irq::Line for NoLine {
        fn set_level(&self, _level: bool) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// An interrupt controller whose lines set nothing, which records the lines
    /// it made.
    #[derive(Default)]
    struct RecordingIrqChip {
        /// The interrupts it made lines for, in order.
        lines: Mutex<Vec<u32>>,
    }

    impl irq::Chip for RecordingIrqChip {
        fn line(&self, irq: u32) -> Arc<dyn irq::Line> {
            self.lines.lock().unwrap().push(irq);
            Arc::new(NoLine)
        }
    }

    /// Returns the guest RAM and the ledger of a manager under test.
    fn ram_and_ledger() -> (Arc<GuestRam>, Arc<Ledger>) {
        (
            Arc::new(GuestRam::from_ranges(&[(0x4000_0000, 0x10000)])),
            Arc::new(Ledger::new(None, "manager-test").unwrap()),
        )
    }

    /// Returns a manager on `slots`.
    #[cfg(target_os = "macos")]
    fn manager(slots: SlotAllocator) -> DeviceManager<RecordingIrqChip> {
        let (ram, ledger) = ram_and_ledger();
        DeviceManager::new(&ram, &ledger, slots, RecordingIrqChip::default())
    }

    /// Returns a manager on `slots`.
    #[cfg(target_os = "linux")]
    fn manager(slots: SlotAllocator) -> DeviceManager<RecordingIrqChip> {
        manager_with_ioeventfds(slots).0
    }

    /// The eventfd, address and value of each ioeventfd a manager registered,
    /// in order.
    #[cfg(target_os = "linux")]
    type Ioeventfds = Arc<Mutex<Vec<(RawFd, u64, u32)>>>;

    /// Returns a manager on `slots`, with the ioeventfds it registers.
    #[cfg(target_os = "linux")]
    fn manager_with_ioeventfds(
        slots: SlotAllocator,
    ) -> (DeviceManager<RecordingIrqChip>, Ioeventfds) {
        let (ram, ledger) = ram_and_ledger();
        let ioeventfds = Ioeventfds::default();
        let registered = Arc::clone(&ioeventfds);
        let manager = DeviceManager::new(
            &ram,
            &ledger,
            slots,
            RecordingIrqChip::default(),
            move |fd: &EventFd, address, value| {
                registered
                    .lock()
                    .unwrap()
                    .push((fd.as_raw_fd(), address, value));
                Ok(())
            },
        );
        (manager, ioeventfds)
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

    // The interrupt list skips 8, as the x86-64 one skips the CMOS RTC's line.
    #[test]
    fn devices_take_their_slots_and_lines_in_attach_order() {
        let mut devices = manager(SlotAllocator::new(0x10_0000..0x10_1000, [5, 6, 7, 9, 10]));
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
        let slot = |base: u64, irq, kind| DeviceRecord {
            kind,
            range: base..base + RANGE_SIZE,
            irq,
        };
        assert_eq!(
            devices.records(),
            [
                slot(0x10_0000, 5, DeviceKind::Block),
                slot(0x10_0200, 6, DeviceKind::Block),
                slot(0x10_0400, 7, DeviceKind::Net),
                slot(0x10_0600, 9, DeviceKind::Vsock),
            ]
        );
        assert_eq!(*devices.irq_chip.lines.lock().unwrap(), [5, 6, 7, 9]);

        let attached = devices.finish();
        assert_eq!(attached.disks.len(), 2);
        assert!(attached.net.is_some());
        let mut magic = [0; 4];
        attached
            .mmio_bus
            .read(0x10_0200 + crate::devices::virtio::mmio::MAGIC, &mut magic)
            .unwrap();
        assert_eq!(&magic, b"virt");
        for path in disks.iter().map(|disk| &disk.path).chain([&agent]) {
            let _ = std::fs::remove_file(path);
        }
    }

    // The device takes the second slot, so the address is the slot's own.
    #[cfg(target_os = "linux")]
    #[test]
    fn notify_fds_are_registered_at_the_slot_with_their_queue() {
        let (mut devices, ioeventfds) =
            manager_with_ioeventfds(SlotAllocator::new(0x10_0000..0x10_1000, [5, 6]));
        let device = Arc::new(Mutex::new(EventfdDevice {
            fds: [EventFd::new(0).unwrap(), EventFd::new(0).unwrap()],
        }));
        devices.slots.allocate().unwrap();
        let slot = devices.slots.allocate().unwrap();
        devices
            .attach_virtio(DeviceKind::Fs, slot, &device)
            .unwrap();
        let [first, second] = device
            .lock()
            .unwrap()
            .fds
            .each_ref()
            .map(AsRawFd::as_raw_fd);
        assert_eq!(
            *ioeventfds.lock().unwrap(),
            [(first, 0x10_0250, 0), (second, 0x10_0250, 1)]
        );
    }

    #[test]
    fn device_past_the_last_interrupt_is_refused() {
        let mut devices = manager(SlotAllocator::new(0x10_0000..0x10_1000, [5]));
        let agent = scratch("refused");
        devices
            .attach_net(&BootConfig {
                net: true,
                ..BootConfig::with_no_devices(1)
            })
            .unwrap();
        let err = devices.attach_vsock(Some(&agent)).unwrap_err().to_string();
        let _ = std::fs::remove_file(&agent);
        assert_eq!(
            err,
            "virtio-vsock: no interrupt left after 1 virtio devices"
        );
        assert_eq!(devices.records().len(), 1);
    }

    #[test]
    fn slots_end_with_the_window() {
        let mut slots = SlotAllocator::new(0x1000..0x1400, 0..4);
        assert_eq!(
            slots.allocate(),
            Ok(Slot {
                base: 0x1000,
                irq: 0
            })
        );
        assert_eq!(
            slots.allocate(),
            Ok(Slot {
                base: 0x1200,
                irq: 1
            })
        );
        assert_eq!(
            slots.allocate(),
            Err("no address range left below 0x1400 after 2 virtio devices".to_string())
        );
    }

    // The window holds two ranges and the list four interrupts, so the window
    // decides.
    #[test]
    fn room_is_the_smaller_of_the_ranges_and_the_interrupts() {
        let slots = SlotAllocator::new(0x1000..0x1400, 0..4);
        assert_eq!(slots.capacity(), 2);
        slots.check_room(2).unwrap();
        assert_eq!(
            slots.check_room(3),
            Err("3 virtio devices given; at most 2 fit".to_string())
        );
        assert_eq!(SlotAllocator::new(0x1000..0x2000, [7]).capacity(), 1);
    }
}

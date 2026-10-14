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

//! What a `checkpoint` captures, once the control thread has the guest still.
//!
//! [`Capture`] holds the parts of the VM a bundle is made of: guest RAM, the
//! devices and the console UART. [`Capture::write`] gathers every device's
//! state with every device mutex held, refuses a state a restore would
//! refuse before it writes a byte, syncs the disk, and then writes and seals
//! the bundle. The caller keeps the guest still throughout: the I/O threads
//! held at the pause gate and every vCPU parked, its state exported.

use std::io;
use std::sync::{Arc, Mutex};

use crate::checkpoint::bundle::{
    unix_ms, BundleWriter, Component, DevicesDoc, DiskState, IrqLevels, Sealed, Session,
    DOC_VERSION,
};
use crate::checkpoint::control::Then;
use crate::checkpoint::cpu::{CpuState, VcpuState};
use crate::checkpoint::platform::PlatformState;
use crate::checkpoint::profile::MachineProfile;
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::pl011::Pl011;
#[cfg(target_arch = "x86_64")]
use crate::devices::legacy::rtc_cmos::RtcCmos;
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::rtc_pl031::Pl031;
#[cfg(target_arch = "x86_64")]
use crate::devices::legacy::uart16550::Uart16550;
use crate::devices::state::{DeviceStates, DEVICE_STATES_VERSION};
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::net::VirtioNet;
use crate::devices::virtio::vsock::VirtioVsock;
use crate::memory::{GuestRam, GuestWriteLog};
use crate::plugin::GuestArch;
use crate::LOG_PREFIX;

/// The console devices a backend attaches.
#[derive(Clone)]
pub(crate) enum Console {
    /// None, as in the tests.
    #[cfg(test)]
    None,
    /// The arm64 PL011 and, on the native machine, the PL031 RTC.
    #[cfg(target_arch = "aarch64")]
    Pl011 {
        /// The PL011.
        uart: Arc<Mutex<Pl011>>,
        /// The PL031, which the portable profile does not have.
        rtc: Option<Arc<Mutex<Pl031>>>,
    },
    /// The x86-64 COM1 16550 and the CMOS RTC beside it.
    #[cfg(target_arch = "x86_64")]
    Com1 {
        /// COM1.
        uart: Arc<Mutex<Uart16550>>,
        /// The CMOS RTC.
        rtc: Arc<Mutex<RtcCmos>>,
    },
}

/// What a backend hands the control socket so it can write checkpoints.
#[derive(Clone)]
pub(crate) struct Capture {
    /// The guest architecture.
    pub(crate) arch: GuestArch,
    /// `hvf` or `kvm`.
    pub(crate) backend: &'static str,
    /// The sandbox id the VM runs under.
    pub(crate) sandbox_id: String,
    /// Guest RAM.
    pub(crate) ram: Arc<GuestRam>,
    /// The virtio-blk device, and the path its disk was opened at.
    pub(crate) block: Option<(Arc<Mutex<VirtioBlk>>, String)>,
    /// The virtio-net device.
    pub(crate) net: Option<Arc<Mutex<VirtioNet>>>,
    /// The virtio-vsock device.
    pub(crate) vsock: Option<Arc<Mutex<VirtioVsock>>>,
    /// The console UART, and the RTC on x86-64.
    pub(crate) console: Console,
    /// The hypervisor's record of the guest's writes to RAM, which a live
    /// move reads; `None` where the backend keeps none.
    pub(crate) write_log: Option<Arc<dyn GuestWriteLog>>,
    /// Run after each component is written, so a test can fail or stop a
    /// capture part way.
    #[cfg(test)]
    pub(crate) after_component: Option<AfterComponent>,
}

/// A test's hook into [`Capture::write`], see [`Capture::after_component`].
#[cfg(test)]
pub(crate) type AfterComponent = Arc<dyn Fn(Component) -> io::Result<()> + Send + Sync>;

/// What the vCPUs exported, on their own threads, for [`Capture::write`].
pub(crate) struct Exported {
    /// Every vCPU's state, by index.
    pub(crate) vcpus: Vec<VcpuState>,
    /// The interrupt controller and the counter.
    pub(crate) platform: PlatformState,
    /// What a restore must be able to load, for the manifest.
    pub(crate) capabilities: Vec<String>,
}

/// What the caller of [`Capture::write`] supplies about the request.
pub(crate) struct Request<'a> {
    /// What the source does after the capture.
    pub(crate) then: Then,
    /// The caller's transaction id.
    pub(crate) txid: Option<&'a str>,
    /// The caller's epoch.
    pub(crate) epoch: u64,
}

impl Capture {
    /// Runs the test hook, when there is one, after `component` is written.
    #[cfg(test)]
    fn after(&self, component: Component) -> io::Result<()> {
        self.after_component
            .as_ref()
            .map_or(Ok(()), |hook| hook(component))
    }

    /// Does nothing: only the tests hook into the write.
    #[cfg(not(test))]
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn after(&self, _component: Component) -> io::Result<()> {
        Ok(())
    }

    /// Releases the disk's lock once a checkpoint has fenced the VM, so the
    /// restore that takes the guest over can open the disk before this
    /// process is stopped. The fenced guest never runs again, so nothing
    /// here writes the disk again. See `VirtioBlk::release_lock`.
    pub(crate) fn release_disk(&self) {
        if let Some((dev, path)) = &self.block {
            if dev.lock().unwrap().release_lock() {
                eprintln!("{LOG_PREFIX} virtio-blk: fenced; released the lock on {path}");
            }
        }
    }

    /// Gathers every device's state and line level, with every device mutex
    /// held at once, and refuses a state a restore would refuse.
    ///
    /// # Errors
    ///
    /// Errors, as `InvalidData`, when [`DeviceStates::check`] refuses the
    /// states, naming the device.
    pub(crate) fn device_states(&self) -> io::Result<DevicesDoc> {
        let blk = self.block.as_ref().map(|(dev, _)| dev.lock().unwrap());
        let net = self.net.as_ref().map(|dev| dev.lock().unwrap());
        let vsock = self.vsock.as_ref().map(|dev| dev.lock().unwrap());
        let mut states = DeviceStates {
            version: DEVICE_STATES_VERSION,
            blk: blk.as_ref().map(|d| d.state()),
            net: net.as_ref().map(|d| d.state()),
            vsock: vsock.as_ref().map(|d| d.state()),
            pl011: None,
            pl031: None,
            uart: None,
            rtc: None,
        };
        let mut irq_levels = IrqLevels {
            blk: blk.as_ref().is_some_and(|d| d.irq_level()),
            net: net.as_ref().is_some_and(|d| d.irq_level()),
            vsock: vsock.as_ref().is_some_and(|d| d.irq_level()),
            uart: false,
        };
        match &self.console {
            #[cfg(test)]
            Console::None => {}
            #[cfg(target_arch = "aarch64")]
            Console::Pl011 { uart, rtc } => {
                let pl011 = uart.lock().unwrap();
                states.pl011 = Some(pl011.state());
                states.pl031 = rtc.as_ref().map(|rtc| rtc.lock().unwrap().state());
                irq_levels.uart = pl011.irq_level();
            }
            #[cfg(target_arch = "x86_64")]
            Console::Com1 { uart, rtc } => {
                let (uart, rtc) = (uart.lock().unwrap(), rtc.lock().unwrap());
                states.uart = Some(uart.state());
                states.rtc = Some(rtc.state());
                irq_levels.uart = uart.irq_level();
            }
        }
        drop((blk, net, vsock));
        states.check(&self.ram).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("a restore would refuse the device state: {e}"),
            )
        })?;
        Ok(DevicesDoc { states, irq_levels })
    }

    /// Syncs the disk, when the guest has one, and returns its state.
    ///
    /// # Errors
    ///
    /// Errors when the sync fails.
    pub(crate) fn disk_state(&self) -> io::Result<Option<DiskState>> {
        let Some((dev, path)) = &self.block else {
            return Ok(None);
        };
        let dev = dev.lock().unwrap();
        dev.sync_data()
            .map_err(|e| io::Error::new(e.kind(), format!("syncing the disk: {e}")))?;
        Ok(Some(DiskState {
            version: DOC_VERSION,
            path_hint: path.clone(),
            size_bytes: dev.size_bytes(),
            sha256_sparse: None,
            generation: dev.generation(),
            synced: true,
        }))
    }

    /// Returns `session.json` for `request`.
    pub(crate) fn session(&self, request: &Request<'_>) -> Session {
        Session {
            version: DOC_VERSION,
            sandbox_id: self.sandbox_id.clone(),
            epoch: request.epoch,
            txid: request.txid.map(str::to_string),
            captured_at_unix_ms: unix_ms(),
            then: match request.then {
                Then::Continue => "continue",
                Then::Fence => "fence",
            }
            .to_string(),
        }
    }

    /// Writes the bundle of the still guest into `writer` and seals it.
    ///
    /// The device states are gathered and checked first, and the disk synced
    /// second, so a refusal or a sync failure leaves no file written.
    /// `exported` is what the vCPUs exported. `stopping` is asked between
    /// components and between reads of guest RAM.
    ///
    /// # Errors
    ///
    /// Errors when a device state is refused, the disk cannot be synced, a
    /// file fails, or `stopping` returns true. The writer removes what it
    /// wrote.
    pub(crate) fn write(
        &self,
        mut writer: BundleWriter,
        profile: &MachineProfile,
        exported: Exported,
        request: &Request<'_>,
        stopping: &dyn Fn() -> bool,
    ) -> io::Result<Sealed> {
        let devices = self.device_states()?;
        let disk = self.disk_state()?;
        let check = || {
            if stopping() {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "the run is stopping",
                ))
            } else {
                Ok(())
            }
        };
        writer.write_bytes(Component::Profile, profile.to_json().as_bytes())?;
        self.after(Component::Profile)?;
        check()?;
        writer.write_ram(&self.ram, stopping)?;
        self.after(Component::RamMap)?;
        check()?;
        writer.write_json(Component::Cpu, &CpuState::new(self.arch, exported.vcpus))?;
        self.after(Component::Cpu)?;
        writer.write_json(Component::Platform, &exported.platform)?;
        self.after(Component::Platform)?;
        writer.write_bytes(Component::Devices, &devices.to_json()?)?;
        self.after(Component::Devices)?;
        if let Some(disk) = &disk {
            writer.write_json(Component::Disk, disk)?;
            self.after(Component::Disk)?;
        }
        writer.write_json(Component::Session, &self.session(request))?;
        self.after(Component::Session)?;
        check()?;
        writer.seal(exported.capabilities)
    }
}

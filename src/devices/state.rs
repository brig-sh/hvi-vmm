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

//! The device state a checkpoint carries, and the checks every restore shares.
//!
//! Each device's state is a plain serde struct beside the device, in a form
//! that names no host and no backend: integers of a fixed width, bytes as byte
//! lists, enums by name. What only the host holds (files, sockets, the
//! interrupt line, the event ledger) stays out, and a restore reattaches it.
//! Every struct refuses fields it does not know, so a newer format fails to
//! load instead of losing what it added. [`DeviceStates`] gathers them into
//! the one document a checkpoint writes for the devices.

use std::io;

use serde::{Deserialize, Serialize};

use crate::devices::legacy::pl011::{Pl011State, PL011_STATE_VERSION};
use crate::devices::legacy::rtc_cmos::{RtcState, RTC_STATE_VERSION};
use crate::devices::legacy::rtc_pl031::{Pl031State, PL031_STATE_VERSION};
use crate::devices::legacy::uart16550::{UartState, UART_STATE_VERSION};
use crate::devices::virtio::block::{BlkState, BLK_STATE_VERSION};
use crate::devices::virtio::net::{NetState, NET_STATE_VERSION};
use crate::devices::virtio::vsock::{VsockState, VSOCK_STATE_VERSION};
use crate::memory::GuestRam;

/// The [`DeviceStates`] format this build writes and reads.
///
/// Version 2 added the PL031. A restore refuses version 1, which has no slot
/// for it, so a native arm64 guest is never restored without its RTC.
pub const DEVICE_STATES_VERSION: u32 = 2;

/// The state of every device a guest has, as a checkpoint writes it.
///
/// A device the guest does not have is `null`, and its key is still
/// required, which keeps one shape for every guest and every backend: the
/// arm64 backends attach a PL011, and on the native machine a PL031, the
/// x86-64 one a 16550 and the CMOS RTC.
/// There is no slot for virtio-fs. Its FUSE session is a mirror of a host
/// directory, held as host descriptors, locks and inode numbers that do not
/// exist on another host, so a guest with a share is not checkpointed at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceStates {
    /// [`DEVICE_STATES_VERSION`] when written by this build.
    pub version: u32,
    // Serde reads a missing `Option` field as `None`, so without
    // `deserialize_with` a document that lost a key would restore a guest
    // without that device, and raise no error.
    /// The virtio-blk device.
    #[serde(deserialize_with = "Option::deserialize")]
    pub blk: Option<BlkState>,
    /// The virtio-net device.
    #[serde(deserialize_with = "Option::deserialize")]
    pub net: Option<NetState>,
    /// The virtio-vsock device.
    #[serde(deserialize_with = "Option::deserialize")]
    pub vsock: Option<VsockState>,
    /// The arm64 console UART.
    #[serde(deserialize_with = "Option::deserialize")]
    pub pl011: Option<Pl011State>,
    /// The arm64 PL031 RTC, which the portable profile does not have.
    #[serde(deserialize_with = "Option::deserialize")]
    pub pl031: Option<Pl031State>,
    /// The x86-64 COM1.
    #[serde(deserialize_with = "Option::deserialize")]
    pub uart: Option<UartState>,
    /// The x86-64 CMOS RTC.
    #[serde(deserialize_with = "Option::deserialize")]
    pub rtc: Option<RtcState>,
}

impl Default for DeviceStates {
    fn default() -> Self {
        DeviceStates {
            version: DEVICE_STATES_VERSION,
            blk: None,
            net: None,
            vsock: None,
            pl011: None,
            pl031: None,
            uart: None,
            rtc: None,
        }
    }
}

impl DeviceStates {
    /// Encodes the states as the JSON a checkpoint stores.
    ///
    /// # Errors
    ///
    /// Errors as `serde_json` does, which for these types it does not.
    pub fn to_json(&self) -> io::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(io::Error::other)
    }

    /// Decodes the JSON [`DeviceStates::to_json`] writes, and refuses a
    /// document or a device state of a version this build does not read.
    ///
    /// Only the shape and the versions are checked here, since the rest needs
    /// guest RAM, see [`DeviceStates::check`]. The caller bounds the
    /// document's size.
    ///
    /// # Errors
    ///
    /// Errors when `json` is not a device-state document, lacks a device key
    /// or has a field this build does not know, or is of another version.
    pub fn from_json(json: &[u8]) -> io::Result<Self> {
        let states: DeviceStates = serde_json::from_slice(json).map_err(invalid)?;
        states.check_versions()?;
        Ok(states)
    }

    /// Refuses states this build could not restore over guest RAM `mem`,
    /// without building a device or touching `mem`.
    ///
    /// It runs every check each device's restore runs on its state, so a
    /// restore that calls it before building any device is not refused part
    /// way through by a bad state. A capture calls it before it writes or
    /// stops the source for good, so a state a restore would refuse fails the
    /// checkpoint while the guest can still run on: the vsock device does not
    /// keep within its restore limits by itself, see
    /// [`VsockState::check`].
    ///
    /// Two checks need the host resources a restore opens, and stay in the
    /// restore: the disk's size ([`VirtioBlk::restore`]) and the network
    /// backend's mode ([`VirtioNet::restore`]). Neither restore writes guest
    /// RAM, so a refusal there leaves RAM as the checkpoint has it, whatever
    /// order the devices are built in. Which devices the guest must have is
    /// the machine profile's to say, not this document's.
    ///
    /// [`VirtioBlk::restore`]: crate::devices::virtio::block::VirtioBlk::restore
    /// [`VirtioNet::restore`]: crate::devices::virtio::net::VirtioNet::restore
    ///
    /// # Errors
    ///
    /// Errors when the document or a device state is of another version, or a
    /// device state is one that device's restore refuses.
    pub fn check(&self, mem: &GuestRam) -> io::Result<()> {
        check_version("device", self.version, DEVICE_STATES_VERSION)?;
        if let Some(blk) = &self.blk {
            blk.check(mem)?;
        }
        if let Some(net) = &self.net {
            net.check(mem)?;
        }
        if let Some(vsock) = &self.vsock {
            vsock.check(mem)?;
        }
        if let Some(pl011) = &self.pl011 {
            pl011.check()?;
        }
        if let Some(pl031) = &self.pl031 {
            pl031.check()?;
        }
        if let Some(uart) = &self.uart {
            uart.check()?;
        }
        if let Some(rtc) = &self.rtc {
            rtc.check()?;
        }
        Ok(())
    }

    /// Refuses a document or a device state of another version.
    pub(crate) fn check_versions(&self) -> io::Result<()> {
        check_version("device", self.version, DEVICE_STATES_VERSION)?;
        let versions = [
            (
                "virtio-blk",
                self.blk.as_ref().map(|s| s.version),
                BLK_STATE_VERSION,
            ),
            (
                "virtio-net",
                self.net.as_ref().map(|s| s.version),
                NET_STATE_VERSION,
            ),
            (
                "virtio-vsock",
                self.vsock.as_ref().map(|s| s.version),
                VSOCK_STATE_VERSION,
            ),
            (
                "pl011",
                self.pl011.as_ref().map(|s| s.version),
                PL011_STATE_VERSION,
            ),
            (
                "pl031",
                self.pl031.as_ref().map(|s| s.version),
                PL031_STATE_VERSION,
            ),
            (
                "16550",
                self.uart.as_ref().map(|s| s.version),
                UART_STATE_VERSION,
            ),
            (
                "cmos rtc",
                self.rtc.as_ref().map(|s| s.version),
                RTC_STATE_VERSION,
            ),
        ];
        for (device, version, want) in versions {
            if let Some(version) = version {
                check_version(device, version, want)?;
            }
        }
        Ok(())
    }
}

/// Returns the error a restore refuses a corrupt or foreign state with.
pub(crate) fn invalid(what: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("device state: {what}"))
}

/// Refuses a state whose `version` this build does not read.
///
/// # Errors
///
/// Errors when `version` is not `want`.
pub(crate) fn check_version(device: &str, version: u32, want: u32) -> io::Result<()> {
    if version == want {
        Ok(())
    } else {
        Err(invalid(format_args!(
            "{device} state version {version}, this build reads {want}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::legacy::pl011::Pl011;
    use crate::devices::legacy::rtc_cmos::RtcCmos;
    use crate::devices::legacy::rtc_pl031::Pl031;
    use crate::devices::legacy::uart16550::Uart16550;
    use crate::devices::virtio::net::VirtioNet;
    use crate::devices::virtio::vsock::VirtioVsock;
    use crate::devices::virtio::{QueueState, VirtioCommonState};

    /// The document for a guest with every device, each in its boot state.
    fn every_device() -> DeviceStates {
        let queue = QueueState {
            num: 0,
            ready: false,
            desc: 0,
            avail: 0,
            used: 0,
            last_avail: 0,
        };
        DeviceStates {
            blk: Some(BlkState {
                version: BLK_STATE_VERSION,
                common: VirtioCommonState {
                    status: 0xf,
                    dev_feat_sel: 1,
                    queue_sel: 0,
                    interrupt_status: 1,
                },
                queue,
                capacity_sectors: 2048,
                serial: "disk0".to_string(),
                read_only: false,
            }),
            net: Some(VirtioNet::new().state()),
            vsock: Some(VirtioVsock::new().state()),
            pl011: Some(Pl011::new().state()),
            pl031: Some(Pl031::new().state()),
            uart: Some(Uart16550::new().state()),
            rtc: Some(RtcCmos::new().state()),
            ..DeviceStates::default()
        }
    }

    #[test]
    fn every_device_round_trips_through_json() {
        let states = every_device();
        let json = states.to_json().unwrap();
        let back = DeviceStates::from_json(&json).unwrap();
        assert_eq!(back, states);
        assert_eq!(back.to_json().unwrap(), json, "one state, one encoding");
    }

    /// The document's top level is what a reader of another build sees first,
    /// so its shape is pinned.
    #[test]
    fn a_guest_without_devices_has_a_fixed_shape() {
        assert_eq!(
            String::from_utf8(DeviceStates::default().to_json().unwrap()).unwrap(),
            r#"{"version":2,"blk":null,"net":null,"vsock":null,"pl011":null,"pl031":null,"uart":null,"rtc":null}"#
        );
    }

    #[test]
    fn a_document_or_device_of_another_version_is_refused() {
        let mut other = every_device();
        other.version = 1;
        let mut device = every_device();
        if let Some(rtc) = device.rtc.as_mut() {
            rtc.version = 9;
        }
        for states in [other, device] {
            let json = serde_json::to_vec(&states).unwrap();
            let err = DeviceStates::from_json(&json).err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
        }
    }

    /// A document that lost a device's key is refused rather than read as a
    /// guest without that device. A device written as `null` still reads.
    #[test]
    fn a_missing_device_key_is_refused() {
        let json = String::from_utf8(every_device().to_json().unwrap()).unwrap();
        let start = json.find(r#","vsock":"#).unwrap();
        let end = json.find(r#","pl011":"#).unwrap();
        let without_vsock = format!("{}{}", &json[..start], &json[end..]);
        for edited in [r#"{"version":2}"#, without_vsock.as_str()] {
            let err = DeviceStates::from_json(edited.as_bytes()).err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
        }
        let none = DeviceStates::default().to_json().unwrap();
        assert_eq!(
            DeviceStates::from_json(&none).unwrap(),
            DeviceStates::default()
        );
    }

    /// `check` runs each device's restore checks over guest RAM, and refuses
    /// what `from_json` lets through because it needs RAM or a limit to see.
    #[test]
    fn check_refuses_what_a_device_restore_would() {
        let mem = GuestRam::from_ranges(&[(0x4000_0000, 0x10000)]);
        every_device().check(&mem).unwrap();
        DeviceStates::default().check(&mem).unwrap();

        let mut outside = every_device();
        if let Some(blk) = outside.blk.as_mut() {
            blk.queue = QueueState {
                num: 8,
                ready: true,
                desc: 0x1000,
                avail: 0x2000,
                used: 0x3000,
                last_avail: 0,
            };
        }
        let mut flooded = every_device();
        if let Some(vsock) = flooded.vsock.as_mut() {
            vsock.conns = (0..=crate::devices::virtio::vsock::RESTORE_MAX_CONNS as u32)
                .map(|port| {
                    let mut c = vsock_conn();
                    c.port = port;
                    c
                })
                .collect();
            vsock.next_port = u32::MAX;
        }
        let mut uart = every_device();
        if let Some(u) = uart.uart.as_mut() {
            u.rx = vec![0; 65];
        }
        for bad in [outside, flooded, uart] {
            let json = bad.to_json().unwrap();
            let states = DeviceStates::from_json(&json).unwrap();
            let err = states.check(&mem).err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
        }
    }

    /// A connection the guest accepted, with nothing in flight.
    fn vsock_conn() -> crate::devices::virtio::vsock::VsockConnState {
        use crate::devices::virtio::vsock::{VsockConnPhase, VsockConnState};
        VsockConnState {
            port: 0,
            state: VsockConnPhase::Connected,
            rx_cnt: 0,
            to_host: Vec::new(),
            backlog: Vec::new(),
            host_closed: false,
            host_gone: false,
            guest_closed: false,
            guest_reset: false,
            guest_full_close: false,
            guest_told: false,
            reset_sent: false,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
            tx_cnt: 0,
        }
    }

    /// A field this build does not know is a format it does not read, at the
    /// top level and inside a device alike.
    #[test]
    fn an_unknown_field_is_refused() {
        let json = String::from_utf8(every_device().to_json().unwrap()).unwrap();
        for edited in [
            json.replacen(r#"{"version":2,"#, r#"{"version":2,"fs":null,"#, 1),
            json.replacen(
                r#""capacity_sectors":2048"#,
                r#""capacity_sectors":2048,"ro":true"#,
                1,
            ),
        ] {
            assert_ne!(edited, json);
            let err = DeviceStates::from_json(edited.as_bytes()).err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
        }
    }
}

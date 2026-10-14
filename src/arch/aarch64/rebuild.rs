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

//! The arm64 guest's devices, rebuilt from a bundle by `hvi restore` on
//! either backend.

use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use crate::checkpoint::restore::Opened;
use crate::config::{MachineProfileKind, RestoreConfig};
use crate::devices::legacy::pl011::Pl011;
use crate::devices::legacy::rtc_pl031::Pl031;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::net::{self, NetBackend, VirtioNet};
use crate::devices::virtio::vsock::VirtioVsock;
use crate::memory::GuestRam;
use crate::LOG_PREFIX;

/// The devices of a restored arm64 guest.
pub(crate) struct Devices {
    /// The virtio-blk device, over the disk `--disk` names.
    pub(crate) block: Option<Arc<Mutex<VirtioBlk>>>,
    /// The virtio-net device.
    pub(crate) net: Option<Arc<Mutex<VirtioNet>>>,
    /// The read side of the gateway connection, for its reader thread.
    pub(crate) net_reader: Option<UnixStream>,
    /// The virtio-vsock device.
    pub(crate) vsock: Option<Arc<Mutex<VirtioVsock>>>,
    /// The console UART.
    pub(crate) pl011: Pl011,
    /// The PL031 RTC of the native machine. The portable one has none.
    pub(crate) pl031: Option<Pl031>,
}

/// How long a restore from a stream waits for the source to release the
/// disk's lock.
const DISK_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Rebuilds the devices of `opened` over the host resources `cfg` names,
/// with their queues in `ram`, which already holds the bundle's RAM.
///
/// Each device's interrupt level must be the one the capture recorded, or
/// the bundle contradicts itself. Then the agent connections whose host end
/// stayed on the source end, which may queue packets for the guest and
/// raise the vsock line: the one level that may differ from the capture's.
/// Nothing is written to guest RAM before every device is built.
///
/// # Errors
///
/// Errors when a device cannot be rebuilt, its host resource cannot be
/// opened (a gateway that cannot be reached is an error: the guest holds an
/// address on its network), or a level contradicts the capture.
pub(crate) fn devices(
    opened: &Opened,
    cfg: &RestoreConfig,
    ram: &GuestRam,
) -> Result<Devices, Box<dyn std::error::Error + Send + Sync>> {
    let states = &opened.devices.states;
    let block = match (&cfg.disk, &states.blk) {
        (Some(disk), Some(state)) => {
            let path = disk.path.as_str();
            eprintln!(
                "{LOG_PREFIX} virtio-blk[0]: {path} (rw, serial {})",
                state.serial
            );
            // The refusals made sure disk.json is there.
            let generation = opened.disk.as_ref().map_or(0, |d| d.generation);
            // A streaming source releases the disk's lock as it fences,
            // just after it sends the manifest, so a restore that read the
            // stream quickly can find it still held. It waits a little for
            // that; a disk another guest holds stays refused.
            let deadline = std::time::Instant::now() + DISK_LOCK_WAIT;
            let dev = loop {
                match VirtioBlk::restore(path, ram, state, generation) {
                    Err(e)
                        if opened.streamed()
                            && e.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    other => break other?,
                }
            };
            Some(Arc::new(Mutex::new(dev)))
        }
        _ => None,
    };
    let mut net_reader = None;
    let net_dev = match &states.net {
        Some(state) => {
            let backend = match &cfg.net_gateway {
                Some(sock) => {
                    // No fallback to the stub, as a boot has: the guest holds
                    // an address on the gateway's network.
                    let stream = UnixStream::connect(sock)
                        .map_err(|e| format!("--net-gateway {sock}: {e}"))?;
                    net_reader = Some(stream.try_clone()?);
                    eprintln!("{LOG_PREFIX} virtio-net: gvisor-tap gateway relay via {sock}");
                    NetBackend::Gateway(stream)
                }
                None => {
                    eprintln!("{LOG_PREFIX} virtio-net: {}", net::stub_stack_line());
                    NetBackend::Stub
                }
            };
            Some(VirtioNet::restore(backend, ram, state)?)
        }
        None => None,
    };
    let net = net::share(net_dev, None);
    let vsock = match &states.vsock {
        Some(state) => Some(Arc::new(Mutex::new(VirtioVsock::restore(ram, state)?))),
        None => None,
    };
    let pl011 = Pl011::restore(states.pl011.as_ref().ok_or("devices.json: no PL011")?)?;
    // The native machine's PL031 reads this host's wall clock once restored.
    let portable = opened.profile().profile == MachineProfileKind::PortableArm64V1.name();
    let pl031 = match (&states.pl031, portable) {
        (Some(state), false) => Some(Pl031::restore(state)?),
        (None, false) => return Err("devices.json: no PL031".into()),
        (Some(_), true) => {
            return Err("devices.json: a PL031, which the portable machine does not have".into())
        }
        (None, true) => None,
    };
    let levels = opened.devices.irq_levels;
    for (name, saved, now) in [
        ("uart", levels.uart, Some(pl011.irq_level())),
        (
            "virtio-blk",
            levels.blk,
            block.as_ref().map(|d| d.lock().unwrap().irq_level()),
        ),
        (
            "virtio-net",
            levels.net,
            net.as_ref().map(|d| d.lock().unwrap().irq_level()),
        ),
        (
            "virtio-vsock",
            levels.vsock,
            vsock.as_ref().map(|d| d.lock().unwrap().irq_level()),
        ),
    ] {
        if let Some(now) = now.filter(|now| *now != saved) {
            return Err(format!(
                "devices.json: the {name} line was {saved} at the capture, and its state \
                 drives it {now}"
            )
            .into());
        }
    }
    // Nothing is left to refuse the bundle, so the connections whose host
    // end stayed on the source can end now, before the lines are connected.
    if let Some(dev) = &vsock {
        dev.lock().unwrap().end_restored_conns(ram);
        eprintln!(
            "{LOG_PREFIX} virtio-vsock: agent bridge on {} (guest cid 3, port 1024)",
            cfg.agent_sock.as_deref().unwrap_or("")
        );
    }
    Ok(Devices {
        block,
        net,
        net_reader,
        vsock,
        pl011,
        pl031,
    })
}

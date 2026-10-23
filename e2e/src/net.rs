// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

//! The gvisor-tap-vsock gateway and the tap device a guest network reaches.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;

use crate::daemon::Daemon;
use crate::sockets::SocketDir;
use crate::suite::Suite;

/// The name of gvproxy's socket in its directory.
const SOCKET: &str = "gateway.sock";

/// A gvisor-tap-vsock gateway for one test, with gvproxy's default network.
///
/// gvproxy hands out addresses in 192.168.127.0/24 over DHCP, answers DNS at
/// [`Gateway::ADDRESS`], and forwards connections to [`Gateway::HOST`] to the
/// host's loopback, so a test reaches a listener on 127.0.0.1 without an
/// outside network.
pub struct Gateway {
    /// The gvproxy process.
    daemon: Daemon,
}

impl Gateway {
    /// The gateway's own address, which serves DHCP and DNS.
    pub const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 1);

    /// The address gvproxy forwards to the host's loopback.
    pub const HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 254);

    /// The first three octets of every address gvproxy hands out.
    pub const SUBNET_PREFIX: &'static str = "192.168.127.";

    /// Starts gvproxy, waiting for its socket to appear.
    ///
    /// Its SSH forward, which would take a fixed host port, is turned off, so
    /// gateways for tests that run at once do not collide.
    ///
    /// # Panics
    ///
    /// Panics if gvproxy cannot be started or its socket does not appear.
    pub fn start() -> Gateway {
        let sockets = SocketDir::new();
        let mut command = Command::new(&Suite::get().gvproxy);
        command
            .arg("-listen-qemu")
            .arg(format!("unix://{}", sockets.path().join(SOCKET).display()))
            .args(["-ssh-port", "-1"]);
        let gateway = Gateway {
            daemon: Daemon::spawn("gvproxy", command, sockets),
        };
        gateway.daemon.wait_for_socket(SOCKET);
        gateway
    }

    /// Returns the path of the socket hvi connects to.
    pub fn socket(&self) -> PathBuf {
        self.daemon.socket(SOCKET)
    }

    /// Sends `signal` to gvproxy.
    ///
    /// # Panics
    ///
    /// Panics if gvproxy has been killed or the signal cannot be sent.
    pub fn signal(&self, signal: libc::c_int) {
        self.daemon.signal(signal);
    }

    /// Kills gvproxy and waits for it to exit.
    pub fn kill(&mut self) {
        self.daemon.kill();
    }
}

/// The tap device `e2e/tools/provision.sh` creates.
#[derive(Clone, Debug)]
pub struct Tap {
    /// The device's name.
    pub name: String,
    /// The host's address on the device.
    pub host: Ipv4Addr,
    /// The prefix length of the device's subnet.
    pub prefix_len: u8,
}

impl Tap {
    /// Returns the address a guest on the tap takes, the one after the host's.
    pub fn guest(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.host) + 1)
    }

    /// Returns the tap `name` at `address`, an `<ip>/<prefix length>` string,
    /// or `None` if `address` does not parse.
    pub(crate) fn parse(name: String, address: &str) -> Option<Tap> {
        let (host, prefix_len) = address.split_once('/')?;
        Some(Tap {
            name,
            host: host.parse().ok()?,
            prefix_len: prefix_len.parse().ok()?,
        })
    }
}

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

//! The guest's network, through each of hvi's three modes: the built-in stub
//! stack, a gvisor-tap-vsock gateway, and a Linux tap.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hvi_e2e::{pattern, scratch_dir, sha256, Gateway, Suite, Vm};

/// A locally administered MAC address for the tests that set one.
const MAC: &str = "52:54:00:e2:e0:01";

/// What hvi prints when it falls back from a gateway to the stub.
///
/// When hvi cannot reach a gateway it warns and keeps booting, so a gateway
/// test checks for this line. The full phrase is needed, since an arm64 host
/// that falls back to vGICv2 also prints "falling back to".
const FALLBACK: &str = "falling back to the built-in stub stack";

/// Returns the address and default route DHCP gives `eth0`, as `ip` prints
/// them.
///
/// It brings `eth0` up first.
fn dhcp(vm: &Vm) -> String {
    vm.sh(
        "ip link set eth0 up && udhcpc -i eth0 -n -q -t 5 -T 1 >/dev/null 2>&1 && \
         ip -4 -o address show dev eth0 && ip route show default",
    )
    .assert_success()
    .stdout
}

/// Returns the MAC address of the guest's `eth0`.
fn guest_mac(vm: &Vm) -> String {
    vm.sh("cat /sys/class/net/eth0/address")
        .assert_success()
        .stdout
        .trim()
        .to_string()
}

/// Accepts one connection on `listener`, waiting thirty seconds, scaled for
/// this host, for the guest to connect.
///
/// # Panics
///
/// Panics if accepting fails or the guest does not connect by then, so a thread
/// joined on this fails rather than waits forever.
fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Suite::get().timeout(Duration::from_secs(30));
    listener.set_nonblocking(true).unwrap();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "the guest did not connect");
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accepting the guest's connection: {e}"),
        }
    }
}

/// Spawns a thread that accepts one connection on `listener` and reads it to
/// its end.
fn receive_one(listener: TcpListener) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut stream = accept(&listener);
        stream
            .set_read_timeout(Some(Suite::get().timeout(Duration::from_secs(30))))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        bytes
    })
}

/// Spawns a thread that accepts one connection on `listener` and writes `bytes`
/// to it.
fn send_one(listener: TcpListener, bytes: Vec<u8>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut stream = accept(&listener);
        stream.write_all(&bytes).unwrap();
    })
}

/// Checks that 4 MiB sent from the guest to a listener on `host`, and 4 MiB
/// sent back, arrive whole.
///
/// `listen` is the address the host binds. It differs from `host` when a
/// gateway forwards the connection.
fn transfers_both_ways(vm: &Vm, host: Ipv4Addr, listen: Ipv4Addr) {
    let to_host = TcpListener::bind((listen, 0)).unwrap();
    let port = to_host.local_addr().unwrap().port();
    let received = receive_one(to_host);
    let sent_digest = vm
        .sh(&format!(
            "dd if=/dev/urandom of=/tmp/out bs=1M count=4 2>/dev/null && \
             nc -w 10 {host} {port} < /tmp/out && sha256sum /tmp/out"
        ))
        .assert_success()
        .stdout;
    let received = received.join().unwrap();
    assert!(
        sent_digest.starts_with(&sha256(&received)),
        "the host received {} bytes that differ from what the guest sent",
        received.len()
    );

    let to_guest = TcpListener::bind((listen, 0)).unwrap();
    let port = to_guest.local_addr().unwrap().port();
    let bytes = pattern(4 << 20, 7);
    let digest = sha256(&bytes);
    let sender = send_one(to_guest, bytes);
    let received_digest = vm
        .sh(&format!(
            "nc -w 10 {host} {port} > /tmp/in; sha256sum /tmp/in"
        ))
        .assert_success()
        .stdout;
    sender.join().unwrap();
    assert!(
        received_digest.starts_with(&digest),
        "the guest received different bytes: {received_digest}"
    );
}

#[test]
fn no_network_flag_means_no_nic() {
    let vm = Vm::builder().boot();
    let missing = vm.sh("test ! -e /sys/class/net/eth0");
    vm.power_off();
    missing.assert_success();
}

mod stub {
    use super::*;

    #[test]
    fn dhcp_gives_the_documented_lease() {
        let vm = Vm::builder().net_stub().boot();
        let lease = dhcp(&vm);
        let resolv = vm.sh("cat /etc/resolv.conf").assert_success().stdout;
        vm.power_off();
        assert!(lease.contains("inet 10.0.2.15/24"), "{lease}");
        assert!(lease.contains("default via 10.0.2.2"), "{lease}");
        assert!(resolv.contains("nameserver 10.0.2.3"), "{resolv}");
    }

    #[test]
    fn gateway_answers_ping_and_no_other_address_does() {
        let vm = Vm::builder().net_stub().boot();
        dhcp(&vm);
        let gateway = vm.sh("ping -c 3 -W 2 10.0.2.2");
        let other = vm.sh("ping -c 1 -W 1 10.0.2.9");
        vm.power_off();
        gateway.assert_success();
        assert!(
            !other.is_success(),
            "an address the stub does not own answered"
        );
    }

    #[test]
    fn tcp_is_recorded_and_not_forwarded() {
        let vm = Vm::builder().net_stub().boot();
        dhcp(&vm);
        let connect = vm.sh("nc -w 2 10.0.2.2 8080 < /dev/null");
        let ended = vm.power_off();
        assert!(
            !connect.is_success(),
            "a TCP connection through the stub succeeded"
        );
        assert!(
            ended.ledger.records_from("net").any(|record| {
                let flow = &record["payload"]["five_tuple"];
                flow["proto"] == 6 && flow["dst_port"] == 8080
            }),
            "the ledger has no record of the connection\n{}",
            ended.context()
        );
    }

    // The lookup's result is ignored, since a name under `.example` has no
    // address.
    #[test]
    #[cfg_attr(
        target_os = "linux",
        ignore = "fails until a guest DNS query no longer ends a confined stub on Linux (#124)"
    )]
    fn dns_question_is_recorded_and_hvi_keeps_running() {
        let vm = Vm::builder().net_stub().boot();
        dhcp(&vm);
        vm.sh("nslookup hvi-e2e.example 10.0.2.3 >/dev/null 2>&1; true")
            .assert_success();
        vm.sh("true").assert_success();
        let ended = vm.power_off();
        assert!(
            ended
                .ledger
                .records_from("net")
                .any(|record| record["payload"]["dns"] == "hvi-e2e.example"),
            "the ledger has no record of the question\n{}",
            ended.context()
        );
    }

    #[test]
    fn mac_is_the_one_given() {
        let vm = Vm::builder().net_stub().net_mac(MAC).boot();
        let mac = guest_mac(&vm);
        vm.power_off();
        assert_eq!(mac, MAC);
    }

    #[test]
    fn deprecated_net_flag_attaches_the_stub_with_a_note() {
        let vm = Vm::builder().arg("--net").boot();
        let lease = dhcp(&vm);
        let ended = vm.power_off();
        assert!(lease.contains("inet 10.0.2.15/24"), "{lease}");
        assert!(
            ended.stderr.contains("--net is now --net-stub"),
            "{}",
            ended.context()
        );
    }
}

mod gateway {
    use super::*;

    #[test]
    fn dhcp_gives_an_address_from_the_gateway() {
        let gateway = Gateway::start();
        let vm = Vm::builder().net_gateway(&gateway).boot();
        let lease = dhcp(&vm);
        let ended = vm.power_off();
        assert!(!ended.stderr.contains(FALLBACK), "{}", ended.context());
        assert!(
            lease.contains(&format!("inet {}", Gateway::SUBNET_PREFIX)),
            "{lease}"
        );
        assert!(
            lease.contains(&format!("default via {}", Gateway::ADDRESS)),
            "{lease}"
        );
    }

    #[test]
    fn guest_and_host_exchange_data() {
        let gateway = Gateway::start();
        let vm = Vm::builder().net_gateway(&gateway).boot();
        dhcp(&vm);
        transfers_both_ways(&vm, Gateway::HOST, Ipv4Addr::LOCALHOST);
        let ended = vm.power_off();
        assert!(!ended.stderr.contains(FALLBACK), "{}", ended.context());
    }

    #[test]
    fn dns_is_answered_by_the_gateway() {
        let gateway = Gateway::start();
        let vm = Vm::builder().net_gateway(&gateway).boot();
        dhcp(&vm);
        let answer = vm.sh(&format!(
            "nslookup gateway.containers.internal {}",
            Gateway::ADDRESS
        ));
        let ended = vm.power_off();
        assert!(!ended.stderr.contains(FALLBACK), "{}", ended.context());
        let answer = answer.assert_success();
        // nslookup prints the server it asked, the gateway, before the answer,
        // so only an address under the answer's `Name:` line counts.
        let resolved = answer
            .stdout
            .split_once("Name:")
            .map(|(_, after)| after)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.strip_prefix("Address:"))
            .any(|address| address.trim() == Gateway::ADDRESS.to_string());
        assert!(
            resolved,
            "the name did not resolve to the gateway\n{}",
            answer.stdout
        );
    }

    #[test]
    fn mac_is_the_one_given() {
        let gateway = Gateway::start();
        let vm = Vm::builder().net_gateway(&gateway).net_mac(MAC).boot();
        let mac = guest_mac(&vm);
        let ended = vm.power_off();
        assert!(!ended.stderr.contains(FALLBACK), "{}", ended.context());
        assert_eq!(mac, MAC);
    }

    #[test]
    fn missing_socket_falls_back_to_the_stub_with_a_warning() {
        let missing = scratch_dir().join("missing.sock");
        let vm = Vm::builder().arg("--net-gateway").arg(&missing).boot();
        let lease = dhcp(&vm);
        let ended = vm.power_off();
        assert!(ended.stderr.contains(FALLBACK), "{}", ended.context());
        assert!(lease.contains("inet 10.0.2.15/24"), "{lease}");
    }

    // A path past the platform's `sockaddr_un` limit cannot be connected to.
    #[test]
    fn socket_path_too_long_falls_back_to_the_stub() {
        let long = scratch_dir().join(format!("{}.sock", "x".repeat(120)));
        let vm = Vm::builder().arg("--net-gateway").arg(&long).boot();
        let ended = vm.power_off();
        assert!(ended.stderr.contains(FALLBACK), "{}", ended.context());
    }

    #[test]
    fn wins_over_the_stub() {
        let gateway = Gateway::start();
        let vm = Vm::builder().net_gateway(&gateway).net_stub().boot();
        let lease = dhcp(&vm);
        vm.power_off();
        assert!(
            lease.contains(&format!("inet {}", Gateway::SUBNET_PREFIX)),
            "{lease}"
        );
    }

    #[test]
    fn killed_gateway_leaves_the_guest_running() {
        let mut gateway = Gateway::start();
        let vm = Vm::builder().net_gateway(&gateway).boot();
        dhcp(&vm);
        gateway.kill();
        vm.sh(&format!(
            "ping -c 2 -W 1 {} >/dev/null 2>&1; true",
            Gateway::ADDRESS
        ))
        .assert_success();
        vm.sh("true").assert_success();
        let ended = vm.power_off();
        assert!(!ended.stderr.contains(FALLBACK), "{}", ended.context());
    }

    // A ping goes out whether or not it is answered, so 4000 large ones fill
    // the socket to the stopped gateway many times over. The ping before the
    // stop puts the gateway's MAC in the guest's ARP cache. Without it, the
    // guest would hold every ping back waiting for an ARP reply.
    #[test]
    #[ignore = "fails until a stalled gateway no longer blocks the vCPU in the virtio-net device (#125)"]
    fn stalled_gateway_leaves_the_guest_running() {
        let gateway = Gateway::start();
        let vm = Vm::builder().net_gateway(&gateway).boot();
        dhcp(&vm);
        vm.sh(&format!("ping -c 1 -W 2 {}", Gateway::ADDRESS))
            .assert_success();
        gateway.signal(libc::SIGSTOP);
        vm.sh(&format!(
            "ping -q -c 4000 -s 1400 -i 0.001 {} >/dev/null 2>&1; true",
            Gateway::ADDRESS
        ))
        .assert_success();
        vm.sh("true").assert_success();
        gateway.signal(libc::SIGCONT);
        let ended = vm.power_off();
        assert!(!ended.stderr.contains(FALLBACK), "{}", ended.context());
    }
}

#[cfg(target_os = "linux")]
mod tap {
    use super::*;

    /// Brings the guest's `eth0` up with the guest's address on the tap.
    fn configure(vm: &Vm, tap: &hvi_e2e::Tap) {
        vm.sh(&format!(
            "ip address add {}/{} dev eth0 && ip link set eth0 up",
            tap.guest(),
            tap.prefix_len
        ))
        .assert_success();
    }

    #[test]
    fn guest_and_host_exchange_data() {
        let tap = Suite::get().tap();
        let vm = Vm::builder().net_tap(&tap.name).boot();
        configure(&vm, tap);
        vm.sh(&format!("ping -c 3 -W 2 {}", tap.host))
            .assert_success();
        transfers_both_ways(&vm, tap.host, tap.host);
        vm.power_off();
    }

    #[test]
    fn host_connects_to_a_guest_listener() {
        let tap = Suite::get().tap();
        let vm = Vm::builder().net_tap(&tap.name).boot();
        configure(&vm, tap);
        vm.sh("(nc -l -p 5555 > /tmp/in) >/dev/null 2>&1 &")
            .assert_success();
        let bytes = pattern(1 << 20, 8);
        let deadline = Instant::now() + Suite::get().timeout(Duration::from_secs(5));
        let mut stream = loop {
            match TcpStream::connect((tap.guest(), 5555)) {
                Ok(stream) => break stream,
                Err(e) if Instant::now() >= deadline => {
                    panic!("connecting to the guest's listener: {e}")
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        };
        stream.write_all(&bytes).unwrap();
        drop(stream);
        let digest = vm.file_sha256("/tmp/in", bytes.len());
        vm.power_off();
        assert!(
            digest.starts_with(&sha256(&bytes)),
            "the guest has {digest}"
        );
    }

    #[test]
    fn host_sees_the_mac_given() {
        let tap = Suite::get().tap();
        let vm = Vm::builder().net_tap(&tap.name).net_mac(MAC).boot();
        configure(&vm, tap);
        vm.sh(&format!("ping -c 1 -W 2 {}", tap.host))
            .assert_success();
        let neighbors = std::process::Command::new("ip")
            .args(["neigh", "show", "dev", &tap.name])
            .output()
            .unwrap();
        vm.power_off();
        let neighbors = String::from_utf8_lossy(&neighbors.stdout);
        assert!(
            neighbors.contains(&format!("{} lladdr {MAC}", tap.guest())),
            "{neighbors}"
        );
    }

    #[test]
    fn wins_over_the_gateway_and_the_stub() {
        let tap = Suite::get().tap();
        let gateway = Gateway::start();
        let vm = Vm::builder()
            .net_stub()
            .net_gateway(&gateway)
            .net_tap(&tap.name)
            .boot();
        configure(&vm, tap);
        vm.sh(&format!("ping -c 2 -W 2 {}", tap.host))
            .assert_success();
        vm.power_off();
    }

    #[test]
    fn unusable_tap_is_refused_and_named() {
        Vm::builder()
            .net_tap("hvi-e2e-nope")
            .spawn()
            .wait(Duration::from_secs(10))
            .assert_refused("hvi-e2e-nope");
    }

    #[test]
    fn name_longer_than_fifteen_bytes_is_refused() {
        Vm::builder()
            .net_tap("hvi-e2e-much-too-long")
            .spawn()
            .wait(Duration::from_secs(10))
            .assert_refused("tap name must be 1..15 bytes");
    }
}

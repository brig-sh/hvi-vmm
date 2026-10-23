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

//! The agent socket, which hvi bridges to the guest over virtio-vsock.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use hvi_e2e::{pattern, sha256, Stop, Vm};
use hvi_e2e_protocol::{Request, Response};

/// Returns what the agent's echo sends back for `bytes`.
///
/// A thread writes while this one reads, so neither side waits on a full buffer
/// for the other.
fn echo(vm: &Vm, bytes: Vec<u8>) -> Vec<u8> {
    let mut agent = vm.connect_agent();
    let len = bytes.len() as u64;
    assert_eq!(
        agent.request(&Request::Echo { len }).unwrap(),
        Response::Ready
    );
    let mut stream = agent.into_stream();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let sender = std::thread::spawn(move || writer.write_all(&bytes));
    let mut back = vec![0u8; len as usize];
    stream.read_exact(&mut back).unwrap();
    sender.join().unwrap().unwrap();
    back
}

#[test]
fn small_message_echoes_back() {
    let vm = Vm::builder().boot();
    let sent = pattern(1024, 1);
    let back = echo(&vm, sent.clone());
    vm.power_off();
    assert_eq!(back, sent);
}

// The transfer spans many receive buffers in both directions.
#[test]
fn eight_mebibytes_echo_back_intact() {
    let vm = Vm::builder().boot();
    let sent = pattern(8 << 20, 2);
    let back = echo(&vm, sent.clone());
    vm.power_off();
    assert!(back == sent, "the echo differs from what was sent");
}

#[test]
fn concurrent_connections_each_carry_their_own_bytes() {
    let vm = Vm::builder().cpus(2).boot();
    std::thread::scope(|scope| {
        let echoes: Vec<_> = (0..8)
            .map(|seed| {
                let vm = &vm;
                scope.spawn(move || {
                    let sent = pattern(1 << 20, seed);
                    echo(vm, sent.clone()) == sent
                })
            })
            .collect();
        for (seed, handle) in echoes.into_iter().enumerate() {
            assert!(
                handle.join().unwrap(),
                "connection {seed} came back different"
            );
        }
    });
    vm.power_off();
}

/// Returns the `sha256sum` line for the guest file `path` after writing `bytes`
/// to it through the agent's sink.
///
/// The host closes the connection right after the write, and the hash waits
/// until the file has its full length.
fn sink(vm: &Vm, path: &str, bytes: &[u8]) -> String {
    let mut agent = vm.connect_agent();
    let request = Request::Sink { path: path.into() };
    assert_eq!(agent.request(&request).unwrap(), Response::Ready);
    let mut stream = agent.into_stream();
    stream.write_all(bytes).unwrap();
    drop(stream);
    vm.file_sha256(path, bytes.len())
}

#[test]
fn bytes_sent_before_the_host_closes_all_reach_the_guest() {
    let vm = Vm::builder().boot();
    let sent = pattern(4 << 20, 3);
    let digest = sink(&vm, "/tmp/sink", &sent);
    vm.power_off();
    assert!(digest.starts_with(&sha256(&sent)), "the guest has {digest}");
}

// `rdinit` runs `sleep` in place of the agent, so nothing listens in the guest.
#[test]
fn connection_with_no_guest_listener_ends_at_once() {
    let vm = Vm::builder()
        .cmdline_arg("rdinit=/bin/busybox -- sleep 600")
        .spawn();
    vm.wait_for_console("Run /bin/busybox as init process", Duration::from_secs(30));
    let mut stream = UnixStream::connect(vm.agent_socket()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let started = Instant::now();
    let mut byte = [0u8; 1];
    let read = stream.read(&mut byte);
    let waited = started.elapsed();
    vm.signal(libc::SIGTERM);
    vm.wait(Duration::from_secs(10))
        .assert_stopped(Stop::Requested(libc::SIGTERM));
    assert!(
        matches!(read, Ok(0)),
        "the connection did not end: {read:?}"
    );
    assert!(waited < Duration::from_secs(1), "the end took {waited:?}");
}

#[test]
fn host_close_delivers_every_byte_on_each_of_thirty_two_rounds() {
    let vm = Vm::builder().cpus(2).boot();
    for round in 0..32 {
        let sent = pattern(4 << 20, round);
        let digest = sink(&vm, "/tmp/sink", &sent);
        assert!(
            digest.starts_with(&sha256(&sent)),
            "round {round}: the guest has {digest}"
        );
    }
    vm.power_off();
}

#[test]
fn hundred_connections_dropped_mid_transfer_leave_the_bridge_serving() {
    let vm = Vm::builder().cpus(2).boot();
    for _ in 0..100 {
        let mut agent = vm.connect_agent();
        let request = Request::Echo { len: 1 << 20 };
        assert_eq!(agent.request(&request).unwrap(), Response::Ready);
        let mut stream = agent.into_stream();
        stream.write_all(&pattern(64 << 10, 4)).unwrap();
    }
    let sent = pattern(1 << 20, 5);
    assert!(
        echo(&vm, sent.clone()) == sent,
        "the last echo came back different"
    );
    vm.power_off();
}

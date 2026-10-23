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

//! What a booted guest finds when it comes up.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hvi_e2e::{Suite, Vm};

#[test]
fn guest_reaches_userspace_and_powers_off() {
    let vm = Vm::builder().boot();
    vm.wait_for_console("hvi-e2e: init", Duration::from_secs(5));
    let ended = vm.power_off();
    let start = ended
        .ledger
        .start_record()
        .expect("the ledger should have a vmm.start");
    assert_eq!(start["arch"], std::env::consts::ARCH);
    assert_eq!(start["vcpus"], 1);
}

#[test]
fn two_vcpus_come_online() {
    let vm = Vm::builder().cpus(2).boot();
    let online = vm.sh("nproc").assert_success().stdout.trim().to_string();
    let ended = vm.power_off();
    assert_eq!(online, "2");
    let start = ended
        .ledger
        .start_record()
        .expect("the ledger should have a vmm.start");
    assert_eq!(start["vcpus"], 2);
    assert_eq!(ended.ledger.records_from("vmm.vcpu_started").count(), 2);
}

#[test]
fn guest_sees_the_memory_it_was_given() {
    let mem_mib = 768;
    let vm = Vm::builder().mem_mib(mem_mib).boot();
    let meminfo = vm.sh("cat /proc/meminfo").assert_success().stdout;
    vm.power_off();
    let total_kib: u64 = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("meminfo should have a MemTotal line");
    // The kernel keeps some of RAM for itself, so MemTotal is a little under
    // what the guest was given, never over it.
    let given_kib = u64::from(mem_mib) * 1024;
    assert!(
        total_kib <= given_kib && total_kib >= given_kib * 85 / 100,
        "MemTotal is {total_kib} kB for {given_kib} kB of RAM"
    );
}

#[test]
fn guest_clock_starts_at_host_time() {
    let vm = Vm::builder().boot();
    let guest: i64 = vm
        .sh("date +%s")
        .assert_success()
        .stdout
        .trim()
        .parse()
        .expect("date +%s should print a number");
    let host = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    vm.power_off();
    assert!(
        (guest - host).abs() <= 5,
        "the guest's clock reads {guest}, the host's {host}"
    );
}

// RAM past the MMIO hole starts again at 4 GiB, and the guest's e820 map must
// show the two regions.
#[cfg(target_arch = "x86_64")]
#[test]
fn ram_above_the_mmio_hole_is_a_second_region() {
    let vm = Vm::builder().mem_mib(4096).boot();
    let console = vm.console();
    vm.power_off();
    for range in [
        "0x0000000000000000-0x000000000009fbff",
        "0x0000000000100000-0x00000000cfffffff",
        "0x0000000100000000-0x000000012fffffff",
    ] {
        assert!(
            console.contains(&format!("BIOS-e820: [mem {range}] usable")),
            "the e820 map has no usable range {range}"
        );
    }
}

// An arm64 host that offers only vGICv2 takes at most 8 vCPUs. There hvi must
// refuse 32, and the test boots 8 instead. When the runner states its host's
// vGIC, the test expects that vGIC, so a vGICv3 host cannot pass with 8.
#[test]
fn thirty_two_vcpus_come_online() {
    let mut vm = Vm::builder().cpus(32).mem_mib(1024).spawn();
    let only_vgic_v2 = match Suite::get().vgic.as_deref() {
        Some(vgic) => vgic == "v2",
        // Only arm64 KVM can lack vGICv3.
        None => {
            cfg!(all(target_arch = "aarch64", target_os = "linux"))
                && vm.stderr_shows(
                    "only vGICv2, which supports at most 8",
                    Duration::from_secs(5),
                )
        }
    };
    let mut wanted = 32;
    if only_vgic_v2 {
        vm.wait(Duration::from_secs(10))
            .assert_refused("supports at most 8 vCPUs (asked for 32)");
        wanted = 8;
        vm = Vm::builder().cpus(8).mem_mib(1024).spawn();
    }
    vm.wait_for_guest();
    let online = vm.sh("nproc").assert_success().stdout.trim().to_string();
    vm.power_off();
    assert_eq!(online, wanted.to_string());
}

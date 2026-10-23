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

//! How a run ends, whether by the guest, a stop signal or a failure.

use std::time::Duration;

use hvi_e2e::{sparse_file, Stop, Suite, Vm};

#[test]
fn guest_reset_ends_the_run() {
    Vm::builder().boot().reset();
}

// The guests boot with `panic=-1`, so a kernel panic resets at once, and hvi
// ends the run on a reset.
#[test]
fn guest_kernel_panic_ends_the_run_as_a_reset() {
    let vm = Vm::builder().boot();
    trigger(&vm, "echo c > /proc/sysrq-trigger");
    let ended = vm.wait(Duration::from_secs(30));
    ended.assert_stopped(Stop::SystemReset);
    assert!(
        ended.console.contains("Kernel panic"),
        "the console shows no panic\n{}",
        ended.context()
    );
}

// On HVF, a guest access to an address in the MMIO window that no device claims
// fails the run.
#[cfg(target_os = "macos")]
#[test]
fn unhandled_mmio_fails_the_run() {
    let vm = Vm::builder().boot();
    trigger(&vm, "hvi-e2e-agent devmem 0x0e000000");
    vm.wait(Duration::from_secs(30))
        .assert_stopped(Stop::Failed("unhandled MMIO at 0xe000000"));
}

/// What hvi's error says when an MMIO load without a syndrome, from the vsock
/// device's registers, fails the run. On KVM it is the `ENOSYS` that `KVM_RUN`
/// returns for the load.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
const LOAD_WITHOUT_SYNDROME_FAILURE: &str = "KVM_RUN error: Function not implemented (os error 38)";
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
const LOAD_WITHOUT_SYNDROME_FAILURE: &str = "MMIO at 0xd000400";

// A load pair from the vsock device's registers traps with no instruction
// syndrome, so the hypervisor cannot tell which registers to fill. KVM refuses
// to run the vCPU on, and hvi fails the run.
#[cfg(target_arch = "aarch64")]
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "fails until HVF fails the run on an MMIO access it cannot decode (#118)"
)]
fn mmio_load_without_syndrome_fails_the_run() {
    let vm = Vm::builder().boot();
    trigger(&vm, "hvi-e2e-agent load-pair 0x0d000400");
    vm.wait(Duration::from_secs(30))
        .assert_stopped(Stop::Failed(LOAD_WITHOUT_SYNDROME_FAILURE));
}

/// Starts `command` in the guest's background, a moment after the agent
/// answers, so a command that ends the run does not end it before the answer.
///
/// The command's output goes to the console, so a run that does not end shows
/// why in its context.
fn trigger(vm: &Vm, command: &str) {
    let delay = Suite::get()
        .timeout(Duration::from_millis(200))
        .as_secs_f64();
    vm.sh(&format!("(sleep {delay}; {command}) >/dev/console 2>&1 &"))
        .assert_success();
}

#[test]
fn sigterm_stops_the_run() {
    stops_on(libc::SIGTERM);
}

#[test]
fn sigint_stops_the_run() {
    stops_on(libc::SIGINT);
}

#[test]
fn sighup_stops_the_run() {
    stops_on(libc::SIGHUP);
}

/// Checks that a booted guest's run stops on `signal` sent to hvi.
fn stops_on(signal: libc::c_int) {
    let vm = Vm::builder().boot();
    vm.signal(signal);
    vm.wait(Duration::from_secs(10))
        .assert_stopped(Stop::Requested(signal));
}

// The stop has to reach a vCPU that is busy in the block device.
#[test]
fn stop_signal_during_disk_writes_ends_the_run_cleanly() {
    let disk = sparse_file("disk.img", 512 << 20);
    let vm = Vm::builder().disk(&disk).boot();
    vm.sh("dd if=/dev/zero of=/dev/vda bs=1M count=500 oflag=direct >/dev/null 2>&1 &")
        .assert_success();
    // The fifth field of the disk's stat counts the writes it completed.
    vm.sh("while [ \"$(awk '{ print $5 }' /sys/block/vda/stat)\" = 0 ]; do sleep 0.05; done")
        .assert_success();
    vm.signal(libc::SIGTERM);
    let ended = vm.wait(Duration::from_secs(10));
    ended.assert_stopped(Stop::Requested(libc::SIGTERM));
    // The ledger records each block request, so a write record shows the guest
    // was writing when the signal came.
    assert!(
        ended
            .ledger
            .records_from("block")
            .any(|record| record["payload"]["rw"] == "w"),
        "the guest wrote nothing before the stop\n{}",
        ended.context()
    );
}

// Without ACPI the guest resets through the i8042 and finds no virtio device,
// so init is busybox's `reboot` in place of the agent. A guest whose i8042
// reset does nothing falls back to a triple fault, which ends the run as a
// reset too, so hvi's trace must show the reset command reaching port 0x64.
#[cfg(target_arch = "x86_64")]
#[test]
fn reset_without_acpi_ends_the_run() {
    let ended = Vm::builder()
        .cmdline_arg("acpi=off rdinit=/bin/busybox -- reboot -f")
        .env("HVI_X86_TRACE", "1")
        .spawn()
        .wait(Duration::from_secs(30));
    ended.assert_stopped(Stop::SystemReset);
    assert!(
        ended.stderr.contains("IoOut 0x64 = [fe]"),
        "the reset did not come through the i8042\n{}",
        ended.context()
    );
}

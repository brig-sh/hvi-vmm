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

//! What the `hvi boot` command line refuses and what it passes on.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hvi_e2e::{pattern, scratch_dir, sparse_file, RunOutput, Suite, Vm};

/// The kernel format hvi loads, which it names when it refuses a kernel.
#[cfg(target_arch = "x86_64")]
const KERNEL_FORMAT: &str = "bzImage";
#[cfg(target_arch = "aarch64")]
const KERNEL_FORMAT: &str = "arm64 Image";

/// Checks that hvi refused the run with an error that names the kernel format.
///
/// hvi names the format on other stderr lines too, such as the x86 line that
/// reports a loaded kernel, so the error line itself has to name it.
fn assert_kernel_refused(ended: &RunOutput) {
    ended.assert_refused("hvi: ");
    assert!(
        ended
            .stderr
            .lines()
            .any(|line| line.starts_with("hvi: ") && line.contains(KERNEL_FORMAT)),
        "hvi's error does not name the {KERNEL_FORMAT}\n{}",
        ended.context()
    );
}

/// Returns the exit code and stderr of `hvi` run with `args` alone.
///
/// # Panics
///
/// Panics, after killing hvi, if it does not exit within ten seconds, scaled
/// for this host.
fn hvi(args: &[&str]) -> (Option<i32>, String) {
    let timeout = Suite::get().timeout(Duration::from_secs(10));
    let mut child = Command::new(&Suite::get().hvi)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hvi should start");
    // A thread reads stderr, so hvi cannot block on a full pipe while the loop
    // below waits for it.
    let mut pipe = child.stderr.take().expect("stderr should be piped");
    let reader = std::thread::spawn(move || {
        let mut stderr = Vec::new();
        let _ = pipe.read_to_end(&mut stderr);
        String::from_utf8_lossy(&stderr).into_owned()
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("waiting for hvi") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stderr = reader.join().expect("the stderr reader should not panic");
    let Some(status) = status else {
        panic!("hvi did not exit within {timeout:?}\nstderr:\n{stderr}");
    };
    (status.code(), stderr)
}

#[test]
fn boot_without_a_kernel_is_refused() {
    let (code, stderr) = hvi(&["boot"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("hvi: boot needs --kernel <Image>"),
        "{stderr}"
    );
}

#[test]
fn unknown_flag_is_refused() {
    let kernel = Suite::get().kernel.to_str().unwrap();
    let (code, stderr) = hvi(&["boot", "--kernel", kernel, "--nope"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("hvi: unknown boot arg \"--nope\""),
        "{stderr}"
    );
}

#[test]
fn kernel_that_is_not_an_image_is_refused() {
    let garbage = scratch_dir().join("garbage");
    std::fs::write(&garbage, pattern(1 << 20, 1)).unwrap();
    let ended = Vm::builder()
        .kernel(&garbage)
        .spawn()
        .wait(Duration::from_secs(10));
    assert_kernel_refused(&ended);
}

// A kernel cut short still has a valid header, so hvi boots what is there and
// the guest faults.
#[test]
#[ignore = "fails until hvi checks that a kernel image holds what its header describes (#337)"]
fn truncated_kernel_is_refused() {
    let kernel = std::fs::read(&Suite::get().kernel).unwrap();
    let truncated = scratch_dir().join("truncated");
    std::fs::write(&truncated, &kernel[..64 << 10]).unwrap();
    let ended = Vm::builder()
        .kernel(&truncated)
        .spawn()
        .wait(Duration::from_secs(10));
    assert_kernel_refused(&ended);
}

#[test]
fn initramfs_larger_than_ram_is_refused() {
    let initramfs = sparse_file("initramfs", 256 << 20);
    let ended = Vm::builder()
        .mem_mib(128)
        .initramfs(&initramfs)
        .spawn()
        .wait(Duration::from_secs(10));
    ended.assert_refused("hvi: ");
    // The x86-64 loader calls it the initramfs, and the arm64 loader calls it
    // the initrd.
    assert!(
        ended.stderr.contains("initramfs") || ended.stderr.contains("initrd"),
        "the refusal does not name the initramfs\n{}",
        ended.context()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn more_vcpus_than_the_backend_supports_are_refused() {
    Vm::builder()
        .cpus(600)
        .spawn()
        .wait(Duration::from_secs(10))
        .assert_refused("vCPUs");
}

#[test]
fn zero_vcpus_boots_one() {
    let vm = Vm::builder().cpus(0).boot();
    let online = vm.sh("nproc").assert_success().stdout.trim().to_string();
    vm.power_off();
    assert_eq!(online, "1");
}

// On x86-64 hvi splices `console=ttyS0` into the command line, and it must go
// before the separator, or init gets it as an argument.
#[test]
fn init_arguments_after_the_separator_reach_init() {
    let vm = Vm::builder().cmdline_arg("-- first second").boot();
    vm.wait_for_console("hvi-e2e: init [first second]", Duration::from_secs(5));
    let cmdline = vm.sh("cat /proc/cmdline").assert_success().stdout;
    vm.power_off();
    let (_, init_part) = cmdline
        .split_once(" -- ")
        .expect("the command line should have a ` -- ` separator");
    assert_eq!(init_part.trim(), "first second");
}

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

// The sandbox cannot be turned off again, so this test turns it on in a test
// process of its own rather than in the library's.

use hvi::config::BootConfig;

/// Returns a config with an empty kernel, which every backend refuses before a
/// guest runs.
fn config(sandbox: bool) -> BootConfig {
    BootConfig {
        kernel: Vec::new(),
        initramfs: None,
        mem_bytes: 128 << 20,
        cmdline: String::new(),
        disks: Vec::new(),
        disk_base_sha256: None,
        disk_written: None,
        fs_shares: Vec::new(),
        fs: Vec::new(),
        net: false,
        net_gateway: None,
        net_tap: None,
        net_mac: None,
        events: None,
        sandbox_id: "sandbox-test".to_string(),
        vcpus: 1,
        agent_sock: None,
        profile_out: None,
        control_sock: None,
        checkpoint_root: None,
        plugin: None,
        sandbox,
        profile: hvi::config::MachineProfileKind::Native,
        arch_timer_irq: None,
        stop: None,
    }
}

// The sandbox is turned on as a sandboxed run turns it on, by arming the
// seccomp filters or entering the Seatbelt profile. On Linux the sandboxed run
// then starts and fails on the empty kernel, and on macOS it is refused too.
#[test]
fn later_run_is_refused_once_the_sandbox_is_on() {
    #[cfg(target_os = "linux")]
    hvi::sandbox::seccomp::arm().unwrap();
    #[cfg(target_os = "macos")]
    hvi::sandbox::seatbelt::enter().unwrap();
    let later = "cannot start a later run once the sandbox is on";
    let unsandboxed = hvi::boot(config(false))
        .expect_err("an empty kernel should not boot")
        .to_string();
    let refused = if cfg!(target_os = "macos") {
        later
    } else {
        "cannot start a run with the sandbox off once it is on"
    };
    assert!(unsandboxed.contains(refused), "{unsandboxed}");
    let sandboxed = hvi::boot(config(true))
        .expect_err("an empty kernel should not boot")
        .to_string();
    assert_eq!(
        sandboxed.contains(refused),
        cfg!(target_os = "macos"),
        "{sandboxed}"
    );
    // The first run gave the run slot back when it was refused.
    assert!(
        !sandboxed.contains("another run") && !sandboxed.contains("earlier run"),
        "{sandboxed}"
    );
    // A thread that installed the `vmm` filter, as the thread that called a
    // sandboxed `boot` has, cannot open the files a run opens, so a run from it
    // is refused before it starts.
    #[cfg(target_os = "linux")]
    {
        hvi::sandbox::seccomp::install_thread(hvi::sandbox::seccomp::Thread::Vmm);
        let refused = "cannot start a run from a thread the sandbox filters";
        let filtered = hvi::boot(config(true))
            .expect_err("an empty kernel should not boot")
            .to_string();
        assert!(filtered.contains(refused), "{filtered}");
        let spawned = hvi::spawn(config(true))
            .err()
            .expect("spawning from a filtered thread should fail")
            .to_string();
        assert!(spawned.contains(refused), "{spawned}");
    }
}

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

// The sandbox cannot be turned off again, and `HVI_SECCOMP` is read from the
// process environment, so this test runs in a test process of its own.
#![cfg(target_os = "linux")]

use hvi::config::BootConfig;

/// Returns a sandboxed config with an empty kernel, which every backend refuses
/// before a guest runs.
fn config() -> BootConfig {
    BootConfig {
        kernel: Vec::new(),
        initramfs: None,
        mem_bytes: 128 << 20,
        cmdline: String::new(),
        disks: Vec::new(),
        fs_shares: Vec::new(),
        fs: Vec::new(),
        net: false,
        net_gateway: None,
        net_tap: None,
        net_mac: None,
        events: None,
        sandbox_id: "sandbox-log-test".to_string(),
        vcpus: 1,
        agent_sock: None,
        plugin: None,
        sandbox: true,
        stop: None,
    }
}

// Log mode lets an off-list syscall run, but the filter stays on the thread.
#[test]
fn run_from_a_filtered_thread_is_refused_in_log_mode() {
    std::env::set_var(hvi::sandbox::seccomp::LOG_ENV, "log");
    hvi::sandbox::seccomp::arm().unwrap();
    hvi::sandbox::seccomp::install_thread(hvi::sandbox::seccomp::Thread::Vmm);
    let refused = "cannot start a run from a thread the sandbox filters";
    let filtered = hvi::boot(config())
        .expect_err("an empty kernel should not boot")
        .to_string();
    assert!(filtered.contains(refused), "{filtered}");
    let spawned = hvi::spawn(config())
        .err()
        .expect("spawning from a filtered thread should fail")
        .to_string();
    assert!(spawned.contains(refused), "{spawned}");
}

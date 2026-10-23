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

//! The confinement hvi runs under, seccomp on Linux and Seatbelt on macOS.
//!
//! Every other test runs confined, and `RunOutput::assert_stopped` checks that
//! the ledger says so. A filter that refuses a syscall a device needs then
//! fails the test that drives the device. These tests check the switch itself
//! and what hvi says about it.

use hvi_e2e::Vm;

/// The line hvi prints when the confinement is on.
const CONFINED_LINE: &str = if cfg!(target_os = "macos") {
    "seatbelt sandbox: on"
} else {
    "seccomp: on"
};

/// The line hvi prints when `--no-sandbox` turns the confinement off.
const UNCONFINED_LINE: &str = if cfg!(target_os = "macos") {
    "seatbelt sandbox: OFF (--no-sandbox)"
} else {
    "seccomp: OFF (--no-sandbox)"
};

#[test]
fn run_is_confined_by_default() {
    let ended = Vm::builder().boot().power_off();
    assert!(ended.stderr.contains(CONFINED_LINE), "{}", ended.context());
}

#[test]
fn no_sandbox_runs_unconfined_and_says_so() {
    let ended = Vm::builder().no_sandbox().boot().power_off();
    assert!(
        ended.stderr.contains(UNCONFINED_LINE),
        "{}",
        ended.context()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn seccomp_log_mode_says_enforcement_is_off() {
    let ended = Vm::builder().seccomp_log().boot().power_off();
    assert!(
        ended.stderr.contains("seccomp: LOGGING ONLY"),
        "{}",
        ended.context()
    );
}

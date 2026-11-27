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

//! Helpers that the unit tests of more than one module use.

use std::io::Read as _;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Runs the test named `test` in a process of its own, with the environment
/// variable `var` set to `value`, and returns how the process ended and what it
/// wrote to stdout and to stderr.
///
/// A test that changes what belongs to the whole process, such as a signal's
/// action or the open-file limit, runs its body this way, so that no test
/// running beside it sees the change. `test` is the full path of a test in this
/// binary that returns at once unless `var` is set.
///
/// The child runs with `--nocapture`, since it can end the process before the
/// test harness prints what it captured.
///
/// # Panics
///
/// Panics if the child has not ended after `limit`, so a child that hangs fails
/// the test and does not hold it up.
pub(crate) fn run_child_test(
    test: &str,
    var: &str,
    value: &str,
    limit: Duration,
) -> (ExitStatus, String, String) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(var, value)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the child for {test} ({var}={value}) did not end");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    (status, out, err)
}

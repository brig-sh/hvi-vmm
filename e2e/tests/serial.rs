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

//! The serial console, which hvi connects to its own stdin and stdout.

use std::time::Duration;

use hvi_e2e::Vm;

#[test]
fn console_input_reaches_the_guest() {
    let mut vm = Vm::builder().boot();
    vm.sh(
        "(read -r line < /dev/console; echo \"hvi-e2e-got:$line\" > /dev/console) \
         >/dev/null 2>&1 &",
    )
    .assert_success();
    // The reader starts in the background and needs time to open the tty.
    std::thread::sleep(Duration::from_millis(300));
    vm.write_console(b"hello-from-the-host\n");
    vm.wait_for_console("hvi-e2e-got:hello-from-the-host", Duration::from_secs(10));
    vm.power_off();
}

// Another vCPU can take the UART's interrupt while the first writes, so the
// guest has two. `loglevel=1` keeps kernel messages, such as a clocksource
// warning on a loaded host, from landing in the middle of the stream.
#[test]
fn long_console_output_arrives_whole_and_in_order() {
    let lines = 20_000;
    let vm = Vm::builder().cpus(2).cmdline_arg("loglevel=1").boot();
    vm.sh(&format!(
        "{{ echo hvi-e2e-seq-start; seq 1 {lines}; echo hvi-e2e-seq-end; }} > /dev/console"
    ))
    .assert_success();
    vm.wait_for_console("hvi-e2e-seq-end", Duration::from_secs(30));
    let console = vm.console();
    vm.power_off();
    let start = console.find("hvi-e2e-seq-start").unwrap();
    let end = console.find("hvi-e2e-seq-end").unwrap();
    let numbers: Vec<&str> = console[start..end]
        .lines()
        .skip(1)
        .map(|line| line.trim_end_matches('\r'))
        .collect();
    let expected: Vec<String> = (1..=lines).map(|n| n.to_string()).collect();
    if let Some(first) = (0..expected.len()).find(|&i| numbers.get(i) != Some(&&*expected[i])) {
        let around = &numbers[first.saturating_sub(3)..(first + 3).min(numbers.len())];
        panic!(
            "the console lost or reordered lines: {} of {lines} arrived, the first \
             difference at line {}, around it {around:?}",
            numbers.len(),
            first + 1
        );
    }
    assert_eq!(
        numbers.len(),
        expected.len(),
        "the console carried {} lines where {lines} were sent",
        numbers.len()
    );
}

// hvi writes the console to stdout on the vCPU thread that drives the UART, so
// a stdout nobody reads fills its pipe and stops that vCPU. The output here is
// several times a pipe's buffer.
#[test]
#[ignore = "fails until the console's stdout writes leave the vCPU thread (#336)"]
fn unread_console_does_not_stall_the_guest() {
    let vm = Vm::builder().console_unread().boot();
    vm.sh("seq 1 100000 > /dev/console").assert_success();
    vm.power_off();
}

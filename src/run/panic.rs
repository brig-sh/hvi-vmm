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

//! The report of a panic, on stderr and as the `vmm.stop` record of the run in
//! progress.
//!
//! A binary built with `panic = "abort"` ends at the panic, before the stop's
//! teardown can stop the vCPUs and write the run's `vmm.stop` record, so the
//! panic hook does both. The first panic in the process writes the record, and
//! a panic on another thread waits for that write before it aborts. In a binary
//! built to unwind, a panic on a vCPU, I/O or plugin thread, or on the thread
//! that called `boot`, stops the run, and the teardown writes the record as it
//! does for any other failure.

use std::backtrace::Backtrace;
use std::fmt::Write as _;
use std::panic::{Location, PanicHookInfo};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::hypervisor::vcpus::panic_detail;
use crate::run::CURRENT_RUN;
use crate::terminal::RawTerm;
use crate::LOG_PREFIX;

/// Whether a panic hook has started in a binary built with `panic = "abort"`.
static ABORTING: AtomicBool = AtomicBool::new(false);

/// Sets the process's panic hook to one that reports a panic on stderr and, in
/// a binary built with `panic = "abort"`, writes it to the ledger of the run in
/// progress.
///
/// The report names the thread, the message and where the panic happened. On a
/// vCPU thread it also names the vCPU's program counter and, once the vCPU has
/// run, its last exit. It carries a backtrace when `RUST_BACKTRACE` asks for
/// one. Once the Linux seccomp filters are armed, outside `HVI_SECCOMP=log`, it
/// carries none on any thread, since resolving a backtrace opens files and
/// reads links, which the filters do not allow. Under `HVI_SECCOMP=log` a glibc
/// build still refuses those opens on the threads hvi filters, so their frames
/// come out unresolved. In a binary built with `panic = "abort"`, the hook
/// stops the vCPUs and restores the terminal before it prints the report, since
/// the abort skips the restore `boot` makes. It then writes the run's
/// `vmm.stop` record as [`record_panic`] does.
///
/// It replaces the hook the process had, so a binary calls it once, before
/// `boot`. A binary that keeps a hook of its own calls [`record_panic`] from
/// it.
pub fn set_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        if cfg!(panic = "abort") {
            ABORTING.store(true, Ordering::Release);
        }
        // The report is built while the other vCPUs still run. On KVM it reads
        // the vCPU through the kick table, which each exiting vCPU locks. The
        // vCPUs then stop before the report is printed, so the guest stops even
        // when stderr blocks.
        let report = report(info);
        if cfg!(panic = "abort") {
            CURRENT_RUN.stop_vcpus(&report);
            RawTerm::restore_saved();
        }
        // The report is printed, and the backtrace captured, before the record
        // is written, since a panic on another thread can abort the process
        // once the record is in. Resolving the backtrace is slow, so it waits
        // until after the record.
        stderrln!("{LOG_PREFIX} {report}");
        let backtrace = (!crate::sandbox::is_trapping())
            .then(capture_backtrace)
            .flatten();
        if cfg!(panic = "abort") {
            CURRENT_RUN.record_failure(&report);
        }
        match backtrace {
            Some((backtrace, BacktraceStyle::Full)) => stderrln!("{backtrace:#}"),
            Some((backtrace, BacktraceStyle::Short)) => stderrln!("{backtrace}"),
            None => {}
        }
    }));
}

/// Writes a `vmm.stop` record for the panic in `info` to the ledger of the run
/// in progress, in a binary built with `panic = "abort"`.
///
/// It stops the vCPUs first. It waits at most
/// [`STOP_TIMEOUT`](crate::teardown::STOP_TIMEOUT) in all for them to exit, for
/// the ledger's writer, and for the record of a panic on another thread that
/// closed the ledger first. In a binary built to unwind, it does nothing, since
/// a panic on a thread of the run stops it and the teardown writes the record.
///
/// A hook calls it after printing its own report, since a panic on another
/// thread can abort the process once the record is in. It leaves the terminal
/// in raw mode, which
/// [`restore_on_fatal_signals`](crate::terminal::restore_on_fatal_signals)
/// restores when the abort raises `SIGABRT`.
pub fn record_panic(info: &PanicHookInfo<'_>) {
    if cfg!(panic = "abort") {
        ABORTING.store(true, Ordering::Release);
        CURRENT_RUN.record_failure(&report(info));
    }
}

/// Parks the calling thread forever once a panic hook has started in a binary
/// built with `panic = "abort"`, so the abort ends the process.
///
/// A thread that would end the process another way calls it first, so the
/// process ends with the abort's status and core file. It returns at once when
/// no hook has started, and in a binary built to unwind.
pub fn wait_for_panic_abort() {
    if ABORTING.load(Ordering::Acquire) {
        loop {
            std::thread::park();
        }
    }
}

/// Returns the report of the panic `info` describes.
fn report(info: &PanicHookInfo<'_>) -> String {
    let thread = std::thread::current();
    format_report(
        thread.name().unwrap_or("<unnamed>"),
        &crate::panic_message(info.payload()),
        info.location(),
        panic_detail().as_deref(),
    )
}

/// Returns the report of a panic on `thread` with `message` at `location`, with
/// the `detail` of the thread's vCPU.
fn format_report(
    thread: &str,
    message: &str,
    location: Option<&Location<'_>>,
    detail: Option<&str>,
) -> String {
    let mut report = format!("{thread}: panicked ({message})");
    if let Some(location) = location {
        let _ = write!(report, " at {location}");
    }
    if let Some(detail) = detail {
        let _ = write!(report, "; {detail}");
    }
    report
}

/// The form `RUST_BACKTRACE` asks a backtrace to be printed in.
enum BacktraceStyle {
    /// The default form, for any value but `0` and `full`.
    Short,
    /// Every frame in full, for `full`.
    Full,
}

/// Returns a backtrace of the calling thread in the form `RUST_BACKTRACE` asks
/// for, or `None` when it asks for none.
///
/// It reads the variable as the default hook does: unset or `0` asks for none,
/// `full` for the full form, and any other value for the short one.
fn capture_backtrace() -> Option<(Backtrace, BacktraceStyle)> {
    let value = std::env::var_os("RUST_BACKTRACE")?;
    let style = match value.to_str() {
        Some("0") => return None,
        Some("full") => BacktraceStyle::Full,
        _ => BacktraceStyle::Short,
    };
    Some((Backtrace::force_capture(), style))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_names_the_thread_the_location_and_the_vcpu() {
        let location = Location::caller();
        assert_eq!(
            format_report(
                "vcpu0",
                "boom",
                Some(location),
                Some("last exit reason 6, pc 0x1000")
            ),
            format!("vcpu0: panicked (boom) at {location}; last exit reason 6, pc 0x1000")
        );
        assert_eq!(
            format_report("main", "boom", None, None),
            "main: panicked (boom)"
        );
    }
}

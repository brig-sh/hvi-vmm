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

//! The open-file limit hvi runs under, raised for the descriptors virtio-fs
//! holds.
//!
//! virtio-fs pins one host file descriptor per open guest handle: a `File` in
//! `handles` for every OPEN, another in `dir_handles` for every OPENDIR,
//! released only when the guest sends RELEASE or RELEASEDIR. That is the right
//! design -- the guest's fd is a host fd -- but it means the guest's
//! concurrency is spent out of hvi's own descriptor table.
//!
//! macOS gives a process launched outside a terminal a soft `RLIMIT_NOFILE` of
//! 256. A build inside the guest goes through that without trying: an idle
//! guest running only bash already holds ~30, a tree walk holds one per open
//! directory, and a compiler holds its inputs, its output and every mapped
//! shared library at once.
//!
//! What the guest saw when that happened was not "too many open files". It was
//! `Input/output error`, on random unrelated files, because virtio-fs reported
//! every unmapped host errno as EIO -- a Go build failing to open package
//! archives it had just written, gcc unable to execute its own cc1. Booting the
//! same image twice, at `ulimit -n 256` the guest fails all over and hvi peaks
//! at 258 descriptors; at 8192 the identical workload is clean and peaks at
//! 2134.
//!
//! So: ask for as much as the kernel will give, once, at startup. virtiofsd
//! does the same thing and exposes it as `--rlimit-nofile`.

use std::sync::OnceLock;

/// Descriptors held back for the parts of the VMM whose count is fixed when
/// it starts.
///
/// The descriptor table belongs to the process, not to one device: the block
/// device, the event ledger, the control socket, the network connection,
/// stdio and the devices' notification descriptors all draw on it, and so
/// does a virtio-fs request while it is served. A guest that spends the last
/// descriptor therefore breaks parts of the VMM it never talks to, and only
/// virtio-fs translates the failure into an errno the guest can understand
/// -- everything else fails with no clear cause.
///
/// So the guest never gets the last of them. This is the fixed part of the
/// reserve; see [`reserve`] for the rest.
const RESERVED_FOR_THE_VMM: u64 = 128;

/// The descriptors a VM with `exports` exports, and an agent bridge if
/// `agent`, holds beside its exports' budget.
///
/// Beside a fixed part, `RESERVED_FOR_THE_VMM`, two parts grow while the VM
/// runs, and each is bounded where it is made: an export's readahead workers
/// hold up to `server::READAHEAD_DESCRIPTORS`, and the agent bridge relays
/// up to `vsock::MAX_HOST_CONNECTIONS` connections of
/// `vsock::DESCRIPTORS_PER_CONNECTION` each. With every part reserved, the
/// host refuses a descriptor below the budget only when the system-wide
/// table is full or a program that embeds hvi holds the room.
#[must_use]
pub fn reserve(exports: usize, agent: bool) -> u64 {
    let readahead = exports.saturating_mul(super::server::READAHEAD_DESCRIPTORS);
    let bridge = if agent {
        crate::devices::virtio::vsock::MAX_HOST_CONNECTIONS
            * crate::devices::virtio::vsock::DESCRIPTORS_PER_CONNECTION
    } else {
        0
    };
    RESERVED_FOR_THE_VMM
        .saturating_add(u64::try_from(readahead.saturating_add(bridge)).unwrap_or(u64::MAX))
}

/// The fewest descriptors a guest is given, whatever the reserve: fewer
/// cannot run a shell.
pub const MIN_BUDGET: usize = 64;

/// The most this module asks the kernel for.
const CEILING: u64 = 65_536;

/// How many host descriptors a VM's exports may pin between them, when the
/// rest of the VM holds `reserve`.
///
/// Derived from the limit actually in force rather than written down, which
/// is the point: a fixed number is either so low that it breaks a real build
/// or so high that it is not a limit. This one is what the process can
/// really open, less the reserve, so raising `RLIMIT_NOFILE` raises it too.
/// See `clamp_soft_limit` for what the process can really open.
///
/// The guest sees ENFILE on the request that would have crossed it, which is
/// the errno for "the host is out", and the VMM keeps working.
///
/// The budget is the VM's, shared by all its exports, because the table is
/// the process's: see `server::DescriptorBudget`.
#[must_use]
pub fn guest_handle_budget(reserve: u64) -> usize {
    let soft = current_open_file_limit().unwrap_or(256);
    budget_within(clamp_soft_limit(soft, per_process_cap()), reserve)
}

/// What a process that can hold `usable` descriptors gives the guest when the
/// rest of the VM holds `reserve`: the difference, but never less than
/// [`MIN_BUDGET`]. When the floor applies, the guest's handles eat into the
/// reserve, and the caller says so.
#[must_use]
pub fn budget_within(usable: u64, reserve: u64) -> usize {
    usize::try_from(usable.saturating_sub(reserve))
        .unwrap_or(usize::MAX)
        .max(MIN_BUDGET)
}

/// Returns how many descriptors a process with the soft limit `soft` can hold
/// when the kernel's per-process cap is `cap`: the lower of the two.
///
/// A soft limit inherited from a shell can be far above the cap, and macOS
/// accepts it. A budget taken from the soft limit alone is then never reached:
/// the kernel answers EMFILE first, before any limit or eviction in the device
/// has run.
///
/// When the cap cannot be read, the soft limit is trusted only up to
/// [`CEILING`], because a soft limit can be above what the kernel lets one
/// process open.
fn clamp_soft_limit(soft: u64, cap: Option<u64>) -> u64 {
    match cap {
        Some(cap) => soft.min(cap),
        None => soft.min(CEILING),
    }
}

/// Returns `kern.maxfilesperproc`, which is read once.
///
/// First read by `raise_open_file_limit`, before the Seatbelt sandbox is
/// entered: the deny-default profile does not list `sysctl-read`. Exports are
/// built before the sandbox too, but caching it means a later caller does not
/// depend on that order.
fn per_process_cap() -> Option<u64> {
    static CAP: OnceLock<Option<u64>> = OnceLock::new();
    *CAP.get_or_init(read_per_process_cap)
}

fn read_per_process_cap() -> Option<u64> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is NUL-terminated and the output is a c_int we own, with
    // its size passed alongside.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&raw mut value).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    u64::try_from(value).ok().filter(|&cap| cap > 0)
}

/// The soft `RLIMIT_NOFILE` in force right now.
fn current_open_file_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into a struct we own and fully initialized.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return None;
    }
    Some(lim.rlim_cur)
}

/// Raises the soft open-file limit to the hard limit, and reports what was
/// obtained.
///
/// Returns how many descriptors the process can now hold, whether or not the
/// limit was raised, so the caller can log it; see `clamp_soft_limit`. A
/// failure to raise is not fatal: hvi still works, it simply cannot serve as
/// many open files at once, and saying so is more useful than refusing to
/// start.
pub fn raise_open_file_limit() -> Result<u64, String> {
    let cap = per_process_cap();
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into a struct we own and fully initialized.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(format!(
            "could not read the open-file limit: {}",
            std::io::Error::last_os_error()
        ));
    }
    let current: u64 = lim.rlim_cur;
    let wanted = desired_limit(lim.rlim_max);
    if current >= wanted {
        return Ok(clamp_soft_limit(current, cap));
    }

    let mut next = lim;
    next.rlim_cur = wanted;
    // SAFETY: setrlimit reads a struct we own and fully initialized.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &next) } == 0 {
        return Ok(clamp_soft_limit(wanted, cap));
    }
    // Raising to the hard limit can still be refused. Try the largest value
    // that is accepted rather than giving up on the first refusal: a partial
    // raise is worth having, and on macOS the hard limit is reported as
    // unlimited while the kernel enforces kern.maxfilesperproc.
    let mut best = current;
    let mut candidate = wanted;
    while candidate > current {
        let mut attempt = lim;
        attempt.rlim_cur = candidate;
        // SAFETY: as above.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &attempt) } == 0 {
            best = candidate;
            break;
        }
        candidate /= 2;
    }
    if best > current {
        Ok(clamp_soft_limit(best, cap))
    } else {
        Err(format!(
            "could not raise the open-file limit above {current}: {}",
            std::io::Error::last_os_error()
        ))
    }
}

/// The limit to ask for.
///
/// `RLIM_INFINITY` is not a number of descriptors, and asking for it on macOS
/// is refused: the kernel caps a process at `kern.maxfilesperproc` regardless
/// of what the hard limit claims. Clamp to something large but real, and let
/// the halving loop above find the ceiling if even that is refused.
fn desired_limit(hard: u64) -> u64 {
    if hard == u64::MAX || hard == libc::RLIM_INFINITY {
        return CEILING;
    }
    hard.min(CEILING)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    #[test]
    fn an_unlimited_hard_limit_is_clamped_to_something_real() {
        // RLIM_INFINITY is not a descriptor count. Asking the kernel for it is
        // how the first version of this failed on macOS.
        assert_eq!(desired_limit(u64::MAX), 65_536);
        assert_eq!(desired_limit(libc::RLIM_INFINITY), 65_536);
    }

    #[test]
    fn a_finite_hard_limit_is_respected() {
        assert_eq!(desired_limit(1024), 1024);
        assert_eq!(desired_limit(200_000), 65_536);
    }

    /// Returns `kern.maxfilesperproc`, read directly so the test does not trust
    /// the code it checks.
    fn kernel_per_process_cap() -> u64 {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>();
        // SAFETY: the name is NUL-terminated and the output is a c_int we own,
        // with its size passed alongside.
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.maxfilesperproc".as_ptr(),
                (&raw mut value).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, 0, "could not read kern.maxfilesperproc");
        u64::try_from(value).unwrap()
    }

    /// The environment variable that marks the child process
    /// [`budget_above_cap_child`] runs in.
    const ABOVE_CAP_CHILD: &str = "HVI_FDLIMIT_ABOVE_CAP_CHILD";

    // The budget must fit under the kernel's per-process cap even when the soft
    // limit is above it; see `clamp_soft_limit`.
    //
    // The child puts its process in that state itself. Started from the default
    // soft limit, `raise_open_file_limit` asks for `CEILING`, which can be
    // below the cap. A budget taken from the soft limit alone then fits too, so
    // the check would pass without the clamp.
    //
    // Run in a process of its own: the open-file limit is the process's, and
    // the tests running alongside this one read it.
    #[test]
    fn budget_fits_under_what_the_kernel_gives_one_process() {
        let (status, out, err) = crate::testing::run_child_test(
            "devices::virtio::fs::fdlimit::tests::budget_above_cap_child",
            ABOVE_CAP_CHILD,
            "1",
            Duration::from_secs(20),
        );
        assert!(status.success(), "the child failed:\n{out}\n{err}");
        if out.contains("above-cap-child: skipped") {
            // Passing, but without having checked the clamp: say so in the log.
            // Written to stderr directly, since the harness captures what
            // `eprintln!` prints from a test that passes.
            use std::io::Write as _;
            let _ = writeln!(
                std::io::stderr(),
                "budget_fits_under_what_the_kernel_gives_one_process:\n{out}"
            );
        } else {
            assert!(
                out.contains("above-cap-child: checked"),
                "the child did not run its checks:\n{out}\n{err}"
            );
        }
    }

    #[test]
    fn budget_above_cap_child() {
        if std::env::var_os(ABOVE_CAP_CHILD).is_none() {
            return;
        }
        let cap = kernel_per_process_cap();
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into a struct we own and fully initialized.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
        lim.rlim_cur = cap + 1024;
        // SAFETY: setrlimit reads a struct we own and fully initialized.
        let set = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } == 0;
        // Read back, since a host may hold the soft limit at the cap rather
        // than refuse, and a hard limit below the cap refuses it outright.
        let above = set && current_open_file_limit().is_some_and(|soft| soft > cap);

        let reported = raise_open_file_limit();
        let budget = u64::try_from(guest_handle_budget(RESERVED_FOR_THE_VMM)).unwrap();
        assert!(
            budget + RESERVED_FOR_THE_VMM <= cap,
            "budget {budget} plus the reserve exceeds kern.maxfilesperproc {cap}"
        );
        if above {
            assert_eq!(reported, Ok(cap), "the startup log would not show the cap");
            println!("above-cap-child: checked");
        } else {
            // This host will not hold a soft limit above the cap, so the state
            // the check needs cannot be set up here.
            println!("above-cap-child: skipped, the soft limit could not go above the cap");
        }
    }

    #[test]
    fn usable_limit_is_the_lower_of_soft_and_cap() {
        assert_eq!(clamp_soft_limit(1_048_576, Some(92_160)), 92_160);
        assert_eq!(clamp_soft_limit(256, Some(92_160)), 256);
    }

    #[test]
    fn unreadable_cap_trusts_the_soft_limit_only_up_to_the_ceiling() {
        assert_eq!(clamp_soft_limit(1_048_576, None), CEILING);
        assert_eq!(clamp_soft_limit(1024, None), 1024);
    }

    #[test]
    fn raising_gives_at_least_what_we_started_with() {
        // The point of the exercise: after this call the process can hold more
        // open files than the macOS default of 256, or we learn why not.
        let before = {
            let mut lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: as in raise_open_file_limit.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
            lim.rlim_cur
        };
        // `raise_open_file_limit` reports the usable limit, so compare it with
        // the usable limit before the raise.
        let before = clamp_soft_limit(before, per_process_cap());
        match raise_open_file_limit() {
            Ok(now) => assert!(now >= before, "the limit went down: {before} -> {now}"),
            Err(e) => panic!("could not raise the open-file limit: {e}"),
        }
    }

    // The reserve grows with what the VM can hold beside its budget, so a
    // second export or an agent bridge takes its descriptors from the guest's
    // budget rather than from the room the rest of the VMM needs.
    #[test]
    fn the_reserve_counts_each_export_and_the_agent_bridge() {
        let readahead = u64::try_from(super::super::server::READAHEAD_DESCRIPTORS).unwrap();
        let bridge = u64::try_from(
            crate::devices::virtio::vsock::MAX_HOST_CONNECTIONS
                * crate::devices::virtio::vsock::DESCRIPTORS_PER_CONNECTION,
        )
        .unwrap();
        assert_eq!(reserve(0, false), RESERVED_FOR_THE_VMM);
        assert_eq!(reserve(2, false), RESERVED_FOR_THE_VMM + 2 * readahead);
        assert_eq!(reserve(1, true), RESERVED_FOR_THE_VMM + readahead + bridge);
    }

    // The budget is what the process can hold less the reserve. A limit too
    // small to leave a guest a shell after the reserve still gives it one.
    #[test]
    fn the_budget_is_the_usable_limit_less_the_reserve() {
        assert_eq!(budget_within(16_384, 456), 16_384 - 456);
        assert_eq!(budget_within(256, 456), MIN_BUDGET);
        assert_eq!(budget_within(456 + MIN_BUDGET as u64, 456), MIN_BUDGET);
    }
}

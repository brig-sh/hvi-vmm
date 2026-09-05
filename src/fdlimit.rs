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

//! Raising the open-file limit hvi runs under.
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

/// Descriptors held back for everything in the VMM that is not virtio-fs.
///
/// The descriptor table belongs to the process, not to one device: the block
/// device, the event ledger, the control socket, the vsock bridge and stdio
/// all draw on it. A guest that spends the last descriptor therefore breaks
/// parts of the VMM it never talks to, and only virtio-fs translates the
/// failure into an errno the guest can understand -- everything else fails
/// with no clear cause (#34).
///
/// So the guest never gets the last of them. This is the reserve.
const RESERVED_FOR_THE_VMM: u64 = 128;

/// How many host descriptors a virtio-fs export may pin for guest handles.
///
/// Derived from the limit actually in force rather than written down, which
/// is the point: a fixed number is either so low that it breaks a real build
/// -- the measured working set of one is ~2134 descriptors, see above -- or
/// so high that it is not a limit. This one is whatever the process was
/// granted, less the reserve, so raising `RLIMIT_NOFILE` raises it too.
///
/// The guest sees ENFILE on the request that would have crossed it, which is
/// the errno for "the host is out", and the VMM keeps working.
///
/// One caveat, written down rather than hidden: this is a per-export budget
/// and the table is per-process, so two exports can each stay inside it and
/// still exhaust the process together. hvi runs a handful of shares at most
/// and the reserve absorbs that, but a shared budget is the honest fix if the
/// share count ever grows.
#[must_use]
pub fn guest_handle_budget() -> usize {
    let soft = current_open_file_limit().unwrap_or(256);
    usize::try_from(soft.saturating_sub(RESERVED_FOR_THE_VMM))
        .unwrap_or(usize::MAX)
        .max(64)
}

/// The soft `RLIMIT_NOFILE` in force right now.
fn current_open_file_limit() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into a struct we own and fully initialised.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
            return None;
        }
        Some(lim.rlim_cur)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Raises the soft open-file limit to the hard limit, and reports what was
/// obtained.
///
/// Returns the soft limit now in force, whether or not it was raised, so the
/// caller can log it. A failure to raise is not fatal: hvi still works, it
/// simply cannot serve as many open files at once, and saying so is more useful
/// than refusing to start.
pub fn raise_open_file_limit() -> Result<u64, String> {
    #[cfg(unix)]
    {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into a struct we own and fully initialised.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
            return Err(format!(
                "could not read the open-file limit: {}",
                std::io::Error::last_os_error()
            ));
        }
        let current: u64 = lim.rlim_cur;
        let wanted = desired_limit(lim.rlim_max);
        if current >= wanted {
            return Ok(current);
        }

        let mut next = lim;
        next.rlim_cur = wanted;
        // SAFETY: setrlimit reads a struct we own and fully initialised.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &next) } == 0 {
            return Ok(wanted);
        }
        // Raising to the hard limit can still be refused. Try the largest value
        // that is accepted rather than giving up on the first refusal: a
        // partial raise is worth having, and on macOS the hard limit is
        // reported as unlimited while the kernel enforces kern.maxfilesperproc.
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
            Ok(best)
        } else {
            Err(format!(
                "could not raise the open-file limit above {current}: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(not(unix))]
    {
        Ok(0)
    }
}

/// The limit to ask for.
///
/// `RLIM_INFINITY` is not a number of descriptors, and asking for it on macOS
/// is refused: the kernel caps a process at `kern.maxfilesperproc` regardless
/// of what the hard limit claims. Clamp to something large but real, and let
/// the halving loop above find the ceiling if even that is refused.
#[cfg(unix)]
fn desired_limit(hard: u64) -> u64 {
    const CEILING: u64 = 65_536;
    if hard == u64::MAX || hard == libc::RLIM_INFINITY {
        return CEILING;
    }
    hard.min(CEILING)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

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
        match raise_open_file_limit() {
            Ok(now) => assert!(now >= before, "the limit went down: {before} -> {now}"),
            Err(e) => panic!("could not raise the open-file limit: {e}"),
        }
    }
}

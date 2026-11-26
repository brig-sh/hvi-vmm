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

//! The seccomp allowlists, one per kind of thread.
//!
//! A list is the calls its threads make once setup is over. The comment above
//! an entry says why the call is there. One that starts with "Safety net" marks
//! a call no trace of hvi showed, kept for a path a single trace does not
//! reach.
//!
//! A thread's filter allows [`BASE`], the calls every thread makes, and the
//! list of its own kind of thread. The base and each list serve both
//! architectures, with the entries only one of them has behind a `cfg`, and
//! both x86-64 irqchip modes.

use super::Thread;

/// A call an allowlist allows.
pub(super) struct Rule {
    /// The syscall's number on the architecture hvi is built for.
    pub(super) number: i64,
    /// What the rule requires of the call's request, when the call is an
    /// `ioctl`.
    pub(super) request: Request,
}

/// What a rule requires of the request of an `ioctl`, the call's second
/// argument.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Request {
    /// Nothing, so the rule allows the syscall whatever its arguments.
    Any,
    /// The request is this one.
    Is(libc::Ioctl),
    /// The request is none of these.
    IsNot(&'static [libc::Ioctl]),
}

impl Rule {
    /// Returns the rule that allows the syscall `number` whatever its
    /// arguments.
    const fn syscall(number: libc::c_long) -> Self {
        Self {
            number,
            request: Request::Any,
        }
    }

    /// Returns the rule that allows `ioctl` for `request`.
    const fn ioctl(request: libc::Ioctl) -> Self {
        Self {
            number: libc::SYS_ioctl,
            request: Request::Is(request),
        }
    }

    /// Returns the rule that allows `ioctl` for every request but `refused`.
    const fn ioctl_except(refused: &'static [libc::Ioctl]) -> Self {
        Self {
            number: libc::SYS_ioctl,
            request: Request::IsNot(refused),
        }
    }
}

/// The requests that push bytes into a terminal's input, which `vmm` and `vcpu`
/// refuse on any descriptor.
///
/// `TIOCSTI` pushes a byte into a terminal's input queue, and the paste
/// subcommand of `TIOCLINUX` pushes the selection into a virtual console's
/// input.
const TERMINAL_INPUT: &[libc::Ioctl] = &[libc::TIOCSTI, libc::TIOCLINUX];

/// The request that sets the level of an interrupt line of the in-kernel
/// irqchip.
///
/// Neither libc nor the kernel's bindings have a constant for it, so it is
/// built as the header builds it.
#[cfg(target_arch = "x86_64")]
pub(super) const KVM_IRQ_LINE: libc::Ioctl =
    libc::_IOW::<kvm_bindings::kvm_irq_level>(kvm_bindings::KVMIO, 0x61);

impl Thread {
    /// Every kind of thread that has an allowlist.
    pub(super) const ALL: [Thread; 3] = [Thread::Vmm, Thread::Vcpu, Thread::Block];

    /// Returns the rules of the allowlist a thread of this kind installs, the
    /// base's and then its own.
    pub(super) fn rules(self) -> impl Iterator<Item = &'static Rule> {
        let own = match self {
            Thread::Vmm => VMM,
            Thread::Vcpu => VCPU,
            Thread::Block => BLOCK,
        };
        BASE.iter().chain(own)
    }
}

/// The calls a thread makes for a reason that does not depend on what it
/// serves: those of the Rust runtime and the allocator, of the locks, of the
/// signal handlers and of the panic hook.
///
/// Every filter allows them, so a call here is granted to the vCPU threads and
/// to every worker. `read`, `close` and `ioctl` are in every list and not here.
/// A thread reads and closes what it serves, so each list gives its own reason,
/// and each list states which `ioctl` requests it allows.
const BASE: &[Rule] = &[
    // The panic hook's report, the ledger's stderr line about a full buffer, a
    // plugin's on_batch_end wake, and the irqfd write that raises an interrupt,
    // which x86-64 makes with the split irqchip only.
    Rule::syscall(libc::SYS_write),
    // Safety net: glibc's fatal-error message (heap corruption, fortify) before
    // it aborts; musl's C stdio output.
    Rule::syscall(libc::SYS_writev),
    // The stop-signal handler's wake, a send with MSG_DONTWAIT on whichever
    // thread takes the signal.
    Rule::syscall(libc::SYS_sendto),
    // Every Mutex, Condvar and thread join.
    Rule::syscall(libc::SYS_futex),
    // Allocator growth.
    Rule::syscall(libc::SYS_mmap),
    // Thread teardown and allocator release.
    Rule::syscall(libc::SYS_munmap),
    // The allocator.
    Rule::syscall(libc::SYS_mprotect),
    // Safety net: realloc of a large buffer.
    Rule::syscall(libc::SYS_mremap),
    // Allocator returning pages; glibc releasing a thread's stack as it exits.
    Rule::syscall(libc::SYS_madvise),
    // glibc malloc for small allocations.
    Rule::syscall(libc::SYS_brk),
    // The panic hook's waits for the lock on the current run and for the vCPUs
    // to exit, and the waits each list states.
    #[cfg(target_arch = "x86_64")]
    Rule::syscall(libc::SYS_poll),
    // Every wait on aarch64, which has no poll, for the reasons poll has on
    // x86-64. On x86-64 it is a safety net, as glibc may lower poll() to ppoll.
    Rule::syscall(libc::SYS_ppoll),
    // Safety net: event timestamps if vDSO is bypassed.
    Rule::syscall(libc::SYS_clock_gettime),
    // Safety net: the contention path of a lock.
    Rule::syscall(libc::SYS_sched_yield),
    // std thread startup.
    Rule::syscall(libc::SYS_sched_getaffinity),
    // The tgkill kick of the vCPUs, which the panic hook makes on any thread;
    // the fatal-signal handler raising its signal again.
    Rule::syscall(libc::SYS_getpid),
    // std thread startup.
    Rule::syscall(libc::SYS_gettid),
    // The panic hook kicking the vCPUs to stop, on any thread; the fatal-signal
    // handler raising its signal again.
    Rule::syscall(libc::SYS_tgkill),
    // The abort path; musl's raise in the fatal-signal handler.
    Rule::syscall(libc::SYS_tkill),
    // glibc restartable sequences, per thread.
    Rule::syscall(libc::SYS_rseq),
    // glibc thread startup.
    Rule::syscall(libc::SYS_set_robust_list),
    // std thread startup and teardown.
    Rule::syscall(libc::SYS_sigaltstack),
    // std signal setup; the fatal-signal handler setting the default action it
    // raises with.
    Rule::syscall(libc::SYS_rt_sigaction),
    // std thread startup and exit; musl's raise in the fatal-signal handler.
    Rule::syscall(libc::SYS_rt_sigprocmask),
    // Returning from the stop-signal handler, which runs on whichever thread
    // takes the signal.
    Rule::syscall(libc::SYS_rt_sigreturn),
    // Safety net: a call a signal interrupted.
    Rule::syscall(libc::SYS_restart_syscall),
    // Thread exit.
    Rule::syscall(libc::SYS_exit),
    // Process exit.
    Rule::syscall(libc::SYS_exit_group),
];

/// The calls of the thread that calls `boot` and of the host-side I/O threads,
/// beside [`BASE`].
///
/// Beyond the reasons the base gives, these threads make:
///
/// - `write` for the guest console to stdout, the wake of a stop request and
///   the ledger's other stderr lines. A plugin's on_batch_end wake comes from
///   the tap and gateway readers. The irqfd write comes from the tap, gateway
///   and agent bridge readers, and on x86-64 from the console reader too.
/// - `sendto` for the vsock bridge writer's `UnixStream::write`, which std
///   makes a send.
/// - `poll` for the plugin waker, the readers, any timer thread and the stop
///   loop's wake.
/// - `mmap` and `mprotect` for the stack and the guard pages of a thread one of
///   them starts.
/// - `getpid` and `tgkill` to kick a vCPU out of `KVM_RUN`, or the console
///   reader out of its read, and `rt_sigreturn` to return from that kick.
/// - `getpid`, `tgkill`, `rt_sigaction` and `rt_sigprocmask`, and `tkill` on
///   musl, to raise a stop or fatal signal with its default action, which ends
///   the process.
/// - `rt_sigaction` for std's signal setup on the reader threads, and for the
///   stop-signal handlers `stop_on_signals` registers when called once a run
///   has started.
/// - `rt_sigprocmask` for the stop-signal thread unblocking the stop signals.
/// - `restart_syscall`, a safety net, for a read the kick interrupted.
const VMM: &[Rule] = &[
    // Console stdin, tap and gateway readers; the stop loop draining its wake.
    Rule::syscall(libc::SYS_read),
    // The ledger writer.
    Rule::syscall(libc::SYS_pwrite64),
    // Safety net: std may vector a buffered read.
    Rule::syscall(libc::SYS_readv),
    // No thread under this filter calls it; a disk's worker makes its flush
    // with it (File::sync_data), and block allows nothing the vmm filter does
    // not, apart from preadv and pwritev.
    Rule::syscall(libc::SYS_fdatasync),
    // Safety net: sync_all, if a disk's flush ever needs metadata; here for the
    // same reason as fdatasync.
    Rule::syscall(libc::SYS_fsync),
    // Accepted connections, dropped descriptors.
    Rule::syscall(libc::SYS_close),
    // virtio-vsock shutting down a session's host end; the stop request; the
    // gateway relay ending; the virtio-fs daemon connections at a stop.
    Rule::syscall(libc::SYS_shutdown),
    // set_nonblocking on accepted sockets.
    Rule::syscall(libc::SYS_fcntl),
    // KVM_RUN and friends; TUNSETIFF is pre-filter; the terminal restore's
    // TCFLSH and TCSETS.
    Rule::ioctl_except(TERMINAL_INPUT),
    // Control socket and the agent bridge.
    Rule::syscall(libc::SYS_accept4),
    // Agent bridge reads; the gateway relay's non-blocking receive; the
    // stop-signal thread's read of its wake.
    Rule::syscall(libc::SYS_recvfrom),
    // Safety net: the control protocol's receive side.
    Rule::syscall(libc::SYS_recvmsg),
    // SCM_RIGHTS: guest-RAM fd to a plugin consumer.
    Rule::syscall(libc::SYS_sendmsg),
    // KVM irqfd/ioeventfd wiring.
    Rule::syscall(libc::SYS_eventfd2),
    // A reader thread per accepted vsock connection.
    Rule::syscall(libc::SYS_clone),
    // Same, on a glibc new enough to use it.
    Rule::syscall(libc::SYS_clone3),
    // A plugin thread that wakes on a timer; the ledger writer's wait before it
    // tries a failed write again.
    Rule::syscall(libc::SYS_clock_nanosleep),
    // HashMap seeding on first use.
    Rule::syscall(libc::SYS_getrandom),
];

/// The calls of a vCPU thread, beside [`BASE`].
///
/// Beyond the reasons the base gives, these threads make:
///
/// - `write` for the guest console's bytes, the I/O trace's buffer, the report
///   of an MMIO access no device claims, and the wake a vCPU thread writes as
///   it starts and as it exits. With the split irqchip, the irqfd write also
///   sends the edge an IOAPIC input held while masked.
/// - `sendto` for gateway and vsock TX from the device on an MMIO exit.
/// - `futex` for the device and ledger locks, and the waits for the ledger's
///   writer.
/// - `mmap` for a device's allocations, and `mremap`, a safety net, for the
///   realloc of a frame buffer.
/// - `poll` for a plugin's own wait at the safe point on vcpu0, and for the
///   vsock device's check for a host hangup, which does not wait.
/// - `clock_gettime`, a safety net as in the base, for the PL031 data-register
///   read on an arm64 vCPU.
/// - `sched_yield`, a safety net, for a lock a reader holds.
/// - `getpid` and `tgkill` for vcpu0 kicking the other vCPUs to quiesce.
/// - `rt_sigreturn` to return from the kick.
/// - `restart_syscall`, a safety net, for an `ioctl` the kick interrupted.
/// - `exit_group` for the process exit on a guest power-off.
const VCPU: &[Rule] = &[
    // KVM_RUN, KVM_IRQ_LINE and the register reads; on x86-64 also
    // KVM_KVMCLOCK_CTRL, and KVM_SET_GSI_ROUTING when the guest moves an input
    // of the split irqchip's IOAPIC; the terminal restore of the fatal-signal
    // handler and of the panic hook.
    Rule::ioctl_except(TERMINAL_INPUT),
    // A plugin draining its doorbell eventfd at the safe point.
    Rule::syscall(libc::SYS_read),
    // HashMap seeding inside a device.
    Rule::syscall(libc::SYS_getrandom),
    // Safety net: a device dropping a descriptor.
    Rule::syscall(libc::SYS_close),
    // virtio-vsock shutting down a session's host end; vhost-user: the
    // virtio-fs daemon connection a failed handover or reset breaks.
    Rule::syscall(libc::SYS_shutdown),
    // vhost-user: the guest's DRIVER_OK write hands the virtio-fs rings to the
    // daemon from this thread, and its reset takes them back.
    Rule::syscall(libc::SYS_sendmsg),
    // vhost-user: what the daemon answers during the handover and the reset.
    Rule::syscall(libc::SYS_recvmsg),
];

/// The calls of a disk's worker thread, beside [`BASE`].
///
/// Beyond the reasons the base gives, these threads make:
///
/// - `write` for the `HVI_BLK_TRACE` lines, the I/O trace's buffer and the stop
///   request of a worker that panics. The irqfd write raises the disk's
///   interrupt.
/// - `sendto` and `rt_sigreturn` when a worker takes the stop signal, since the
///   I/O threads block none.
/// - `futex` for the lock and the condition variable the worker shares with the
///   device, the interrupt's lock, the ledger's lock and the wake of its
///   writer.
/// - `mmap` for a request's list of buffers and a pass's records.
/// - `poll` for the wait on the wake eventfd beside the stop token.
/// - `clock_gettime`, a safety net as in the base, for the clock of the queue
///   poll.
/// - `sched_yield`, a safety net, for a lock a vCPU holds.
/// - `exit_group`, a safety net, for the process exit on the abort path.
const BLOCK: &[Rule] = &[
    // virtio-blk reads from the backing file straight into the request's
    // buffers in guest RAM (memory::read_vectored_at_volatile).
    Rule::syscall(libc::SYS_preadv),
    // virtio-blk writes to the backing file straight from the request's buffers
    // in guest RAM (memory::write_vectored_at_volatile).
    Rule::syscall(libc::SYS_pwritev),
    // virtio-blk flush: what File::sync_data calls.
    Rule::syscall(libc::SYS_fdatasync),
    // Safety net: sync_all, if a flush ever needs metadata.
    Rule::syscall(libc::SYS_fsync),
    // The worker clearing its wake eventfd.
    Rule::syscall(libc::SYS_read),
    // Raising the disk's interrupt with the in-kernel irqchip, on its IOAPIC
    // pin.
    #[cfg(target_arch = "x86_64")]
    Rule::ioctl(KVM_IRQ_LINE),
    // The terminal restore of the fatal-signal handler and of the panic hook:
    // glibc's tcsetattr reads the settings around its write.
    Rule::ioctl(libc::TCGETS),
    // The terminal restore of the fatal-signal handler and of the panic hook:
    // tcsetattr.
    Rule::ioctl(libc::TCSETS),
    // The terminal restore of the fatal-signal handler and of the panic hook:
    // tcgetattr and tcsetattr of a glibc that uses the termios2 requests.
    Rule::ioctl(libc::TCGETS2),
    // The terminal restore of the fatal-signal handler and of the panic hook:
    // tcsetattr of a glibc that uses the termios2 requests.
    Rule::ioctl(libc::TCSETS2),
    // The terminal restore of the fatal-signal handler and of the panic hook:
    // tcflush.
    Rule::ioctl(libc::TCFLSH),
    // The worker dropping the backing file and its wake as it exits.
    Rule::syscall(libc::SYS_close),
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// Pairs each syscall's number with the name libc has for it, for a test's
    /// messages.
    macro_rules! named {
        ($($(#[$cfg:meta])? $syscall:ident),* $(,)?) => {
            [$($(#[$cfg])? (stringify!($syscall), libc::$syscall)),*]
        };
    }

    /// Returns the numbers of the syscalls the filter of `thread` allows.
    fn numbers(thread: Thread) -> BTreeSet<i64> {
        thread.rules().map(|rule| rule.number).collect()
    }

    // A filter allows a syscall when one of its rules matches, and a rule with
    // no request compiles to no condition. Beside a rule with a request it
    // would read as allowing every call while the filter still allowed the
    // requests alone.
    #[test]
    fn lists_state_a_syscall_once_or_once_per_request() {
        for thread in Thread::ALL {
            let mut stated = BTreeSet::new();
            for rule in thread.rules() {
                assert!(
                    stated.insert((rule.number, rule.request)),
                    "{thread:?} states syscall {} twice",
                    rule.number
                );
            }
            for &(number, request) in &stated {
                let rules = stated.iter().filter(|(other, _)| *other == number);
                assert!(
                    matches!(request, Request::Is(_)) || rules.count() == 1,
                    "{thread:?} states syscall {number} more than once, and not per request"
                );
            }
        }
    }

    // The request is built in this file, so the number the header gives is
    // spelled out here.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn kvm_irq_line_is_the_headers_request() {
        assert_eq!(KVM_IRQ_LINE, 0x4008_ae61);
    }

    // `arm` compiles the filter of each kind in `ALL`, and the tests here check
    // each. The match has no wildcard, so a new variant does not compile until
    // the match lists it, which puts the count beside it, and `ALL` has to hold
    // as many kinds as the count.
    #[test]
    fn all_holds_every_kind_of_thread() {
        let kinds = match Thread::Vmm {
            Thread::Vmm | Thread::Vcpu | Thread::Block => 3,
        };
        assert_eq!(Thread::ALL.len(), kinds);
        for (index, thread) in Thread::ALL.iter().enumerate() {
            assert!(!Thread::ALL[..index].contains(thread), "{thread:?} twice");
        }
    }

    // The vCPU threads serve guest MMIO inline, so their list is the one that
    // matters most. A syscall in `vcpu` alone was added with no look at the
    // list of the threads around it.
    #[test]
    fn vcpu_is_a_subset_of_vmm() {
        let vmm = numbers(Thread::Vmm);
        let vcpu = numbers(Thread::Vcpu);
        let extra: Vec<_> = vcpu.difference(&vmm).collect();
        assert!(
            extra.is_empty(),
            "vcpu allows syscalls vmm does not: {extra:?}"
        );
        assert!(vcpu.len() < vmm.len(), "vcpu should be the tighter filter");
    }

    // A disk's requests run on its worker, so a vCPU thread reads and writes no
    // file at an offset, seeks none and syncs none.
    #[test]
    fn vcpu_filter_has_no_positioned_io_seek_or_sync() {
        let vcpu = numbers(Thread::Vcpu);
        for (name, number) in named![
            SYS_pread64,
            SYS_pwrite64,
            SYS_preadv,
            SYS_pwritev,
            SYS_preadv2,
            SYS_pwritev2,
            SYS_lseek,
            SYS_fsync,
            SYS_fdatasync,
            SYS_sync_file_range,
        ] {
            assert!(!vcpu.contains(&number), "vcpu allows {name}");
        }
    }

    // A disk's worker parses guest descriptors too, so its list follows the
    // same rule, apart from the two calls that move a request's data between
    // the backing file and guest RAM. No other thread makes them, so `vmm` does
    // not allow them.
    #[test]
    fn block_adds_only_the_vectored_file_calls_to_vmm() {
        let vmm = numbers(Thread::Vmm);
        let block = numbers(Thread::Block);
        let extra: BTreeSet<_> = block.difference(&vmm).copied().collect();
        assert_eq!(
            extra,
            BTreeSet::from([libc::SYS_preadv, libc::SYS_pwritev]),
            "block allows what vmm does not"
        );
        assert!(
            block.len() < vmm.len(),
            "block should be the tighter filter"
        );
    }

    // A worker takes no connection, starts no thread, makes no eventfd and
    // sends no descriptor.
    #[test]
    fn block_filter_has_no_socket_thread_or_descriptor_calls() {
        let block = numbers(Thread::Block);
        for (name, number) in named![
            SYS_accept4,
            SYS_recvfrom,
            SYS_recvmsg,
            SYS_sendmsg,
            SYS_eventfd2,
            SYS_clone,
            SYS_clone3,
            SYS_fcntl,
            SYS_shutdown,
        ] {
            assert!(!block.contains(&number), "block allows {name}");
        }
    }

    // The filters go in after setup so that the process can no longer reach the
    // filesystem or make a socket. Any of these syscalls in a list would undo
    // that.
    #[test]
    fn no_filter_can_open_or_connect() {
        let forbidden = named![
            #[cfg(target_arch = "x86_64")]
            SYS_open,
            SYS_openat,
            SYS_openat2,
            #[cfg(target_arch = "x86_64")]
            SYS_creat,
            SYS_socket,
            SYS_connect,
            SYS_execve,
            SYS_execveat,
            SYS_ptrace,
            SYS_process_vm_readv,
            SYS_process_vm_writev,
            SYS_memfd_create,
            SYS_seccomp,
            SYS_prctl,
        ];
        for thread in Thread::ALL {
            let allowed = numbers(thread);
            for (name, number) in forbidden {
                assert!(
                    !allowed.contains(&number),
                    "{thread:?} allows {name}, which defeats installing the filter after setup"
                );
            }
        }
    }
}

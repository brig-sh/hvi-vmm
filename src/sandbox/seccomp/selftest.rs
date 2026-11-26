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

//! The selftest of the seccomp filters, which `hvi seccomp-selftest` runs.

use std::io;

#[cfg(target_arch = "x86_64")]
use super::allowlists::KVM_IRQ_LINE;
use super::{allowed_count, install, kvm_run, log_mode, Thread, LOG_ENV};

/// A probe of one syscall, the filter installed before it, and the outcome that
/// filter is meant to give it.
struct Probe {
    what: &'static str,
    thread: Thread,
    /// The outcome the filter is meant to give the syscall.
    expected: Outcome,
    /// The code that makes the syscall in the child, after the filter is in. It
    /// returns when the syscall is allowed. A probe that expects a refusal ends
    /// the child with [`EXIT_REFUSED`] when its syscall fails with `EPERM`.
    run: fn(),
}

/// The outcome an open has under the filters, a refusal in a glibc build and a
/// trap in a musl build.
const OPEN_OUTCOME: Outcome = if cfg!(target_env = "gnu") {
    Outcome::Refused
} else {
    Outcome::Trapped
};

/// The probes. Denials first, so a filter that is accidentally permissive reads
/// as a wall of failures rather than one buried line.
fn probes() -> Vec<Probe> {
    vec![
        Probe {
            what: "open a file (vcpu)",
            thread: Thread::Vcpu,
            expected: OPEN_OUTCOME,
            run: open_each_way,
        },
        Probe {
            what: "open a file (vmm)",
            thread: Thread::Vmm,
            expected: OPEN_OUTCOME,
            run: open_each_way,
        },
        Probe {
            what: "open a file (block)",
            thread: Thread::Block,
            expected: OPEN_OUTCOME,
            run: open_each_way,
        },
        Probe {
            what: "create a socket (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Trapped,
            // SAFETY: socket(2) with constant arguments.
            run: || {
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            },
        },
        Probe {
            what: "create a socket (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Trapped,
            // The vmm filter allows accept4 on a listener bound beforehand but
            // never socket(2): it cannot make a new one.
            // SAFETY: socket(2) with constant arguments.
            run: || {
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            },
        },
        Probe {
            what: "create a socket (block)",
            thread: Thread::Block,
            expected: Outcome::Trapped,
            // SAFETY: socket(2) with constant arguments.
            run: || {
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            },
        },
        Probe {
            what: "execute another program (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Trapped,
            run: || {
                let p = c"/bin/true";
                let argv = [p.as_ptr(), std::ptr::null()];
                // SAFETY: valid NUL-terminated path and a NULL-terminated argv.
                unsafe { libc::execv(p.as_ptr(), argv.as_ptr()) };
            },
        },
        Probe {
            what: "spawn a thread (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Trapped,
            // clone is a vmm right (the agent bridge needs one per connection);
            // a vCPU thread servicing guest MMIO has no business making threads.
            run: || {
                let _ = std::thread::spawn(|| 0u8).join();
            },
        },
        Probe {
            what: "spawn a thread (block)",
            thread: Thread::Block,
            expected: Outcome::Trapped,
            // A disk's worker is queued before the filters go in and starts no
            // thread of its own.
            run: || {
                let _ = std::thread::spawn(|| 0u8).join();
            },
        },
        Probe {
            what: "make an ioctl outside its requests (block)",
            thread: Thread::Block,
            expected: Outcome::Trapped,
            // The rule matches the request number, whatever the descriptor.
            // SAFETY: an ioctl on a descriptor that is not open, which the
            // kernel refuses with EBADF once the filter has passed it.
            run: || {
                unsafe { libc::ioctl(-1, libc::FIONREAD, std::ptr::null_mut::<libc::c_int>()) };
            },
        },
        Probe {
            what: "unlink a file (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Trapped,
            run: || {
                let p = c"/tmp/hvi-seccomp-selftest-should-not-exist";
                // SAFETY: a valid NUL-terminated path.
                unsafe { libc::unlink(p.as_ptr()) };
            },
        },
        Probe {
            what: "change file mode (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Trapped,
            run: || {
                let p = c"/tmp";
                // SAFETY: a valid NUL-terminated path.
                unsafe { libc::chmod(p.as_ptr(), 0o777) };
            },
        },
        Probe {
            what: "send a signal to another process (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Trapped,
            // kill(2) is absent; tgkill is allowed, and only reaches our own
            // threads because the filter cannot constrain the target beyond
            // what the caller passes.
            // SAFETY: kill(2) with constant arguments.
            run: || {
                unsafe { libc::kill(1, 0) };
            },
        },
        // The ioctl rule's conditions. `vmm` and `vcpu` each state the rule, so
        // each gets its own probes.
        Probe {
            what: "push a byte into terminal input, TIOCSTI (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Trapped,
            run: || ioctl_on_no_descriptor(libc::TIOCSTI as libc::c_ulong),
        },
        Probe {
            what: "push a byte into terminal input, TIOCSTI (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Trapped,
            run: || ioctl_on_no_descriptor(libc::TIOCSTI as libc::c_ulong),
        },
        // The kernel drops bits 32-63 of the request, so these still reach it
        // as TIOCSTI.
        Probe {
            what: "push a byte into terminal input, TIOCSTI | 0xffffffff << 32 (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Trapped,
            run: || ioctl_on_no_descriptor(0xffff_ffff_0000_0000 | libc::TIOCSTI as libc::c_ulong),
        },
        Probe {
            what: "push a byte into terminal input, TIOCSTI | 0xffffffff << 32 (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Trapped,
            run: || ioctl_on_no_descriptor(0xffff_ffff_0000_0000 | libc::TIOCSTI as libc::c_ulong),
        },
        Probe {
            what: "paste a console selection, TIOCLINUX (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Trapped,
            run: || ioctl_on_no_descriptor(libc::TIOCLINUX as libc::c_ulong),
        },
        Probe {
            what: "paste a console selection, TIOCLINUX (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Trapped,
            run: || ioctl_on_no_descriptor(libc::TIOCLINUX as libc::c_ulong),
        },
        // A disk's requests run on its worker, so a vCPU thread reads and writes
        // no file at an offset and flushes none. The read and the write each
        // take one empty buffer, so a call the filter passes moves nothing.
        Probe {
            what: "read at an offset (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Trapped,
            run: || {
                let _ = std::os::unix::fs::FileExt::read_at(&*inherited(0), &mut [], 0);
            },
        },
        Probe {
            what: "write at an offset (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Trapped,
            run: || {
                let _ = std::os::unix::fs::FileExt::write_at(&*inherited(1), &[], 0);
            },
        },
        Probe {
            what: "flush an inherited descriptor (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Trapped,
            run: || {
                // SAFETY: fdatasync on fd 1, which we inherited.
                unsafe { libc::fdatasync(1) };
            },
        },
        Probe {
            what: "read at an offset (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Trapped,
            run: || {
                let _ = std::os::unix::fs::FileExt::read_at(&*inherited(0), &mut [], 0);
            },
        },
        // The other half: what a filtered thread must still be able to do.
        //
        // A disk's flush calls `File::sync_data`, which is `fdatasync`, not
        // `fsync`, so the probe makes the call the worker makes.
        Probe {
            what: "flush an inherited descriptor (block)",
            thread: Thread::Block,
            expected: Outcome::Allowed,
            run: || {
                // SAFETY: fdatasync on fd 1, which we inherited.
                unsafe { libc::fdatasync(1) };
            },
        },
        Probe {
            what: "write at an offset (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Allowed,
            // The ledger writer writes the file at an offset. The probe writes
            // one empty buffer to fd 1, which we inherited, so the call is made
            // and writes nothing.
            run: || {
                let _ = std::os::unix::fs::FileExt::write_at(&*inherited(1), &[], 0);
            },
        },
        // The probe calls the functions the worker calls for a virtio-blk read
        // or write, so it makes whichever syscall the libc lowers them to.
        Probe {
            what: "read at an offset into buffers (block)",
            thread: Thread::Block,
            expected: Outcome::Allowed,
            run: || {
                let mut empty = [0u8; 0];
                let buffers = [vm_memory::VolatileSlice::from(&mut empty[..])];
                // It reads one empty buffer from fd 0, which we inherited, so
                // the call is made and reads nothing.
                let _ = crate::memory::read_vectored_at_volatile(&inherited(0), &buffers, 0);
            },
        },
        Probe {
            what: "write at an offset from buffers (block)",
            thread: Thread::Block,
            expected: Outcome::Allowed,
            run: || {
                let mut empty = [0u8; 0];
                let buffers = [vm_memory::VolatileSlice::from(&mut empty[..])];
                // It writes one empty buffer to fd 1, which we inherited, so
                // the call is made and writes nothing.
                let _ = crate::memory::write_vectored_at_volatile(&inherited(1), &buffers, 0);
            },
        },
        Probe {
            what: "poll an inherited descriptor (block)",
            thread: Thread::Block,
            expected: Outcome::Allowed,
            // The worker waits in `poll` on its wake beside the stop token.
            run: || {
                let mut fds = [libc::pollfd {
                    fd: 1,
                    events: libc::POLLOUT,
                    revents: 0,
                }];
                // SAFETY: one pollfd for fd 1, which we inherited, and a zero
                // timeout, so the call returns at once.
                unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) };
            },
        },
        Probe {
            what: "restore the terminal (block)",
            thread: Thread::Block,
            expected: Outcome::Allowed,
            run: restore_terminal,
        },
        #[cfg(target_arch = "x86_64")]
        Probe {
            what: "raise an interrupt line (block)",
            thread: Thread::Block,
            expected: Outcome::Allowed,
            // With the in-kernel irqchip, a worker raises its disk's IOAPIC pin
            // with KVM_IRQ_LINE.
            run: || {
                let level = kvm_bindings::kvm_irq_level::default();
                // SAFETY: KVM_IRQ_LINE on a descriptor that is not open, which
                // the kernel refuses with EBADF once the filter has passed it.
                unsafe { libc::ioctl(-1, KVM_IRQ_LINE, &level) };
            },
        },
        Probe {
            what: "write to an inherited descriptor (block)",
            thread: Thread::Block,
            expected: Outcome::Allowed,
            // A worker raises its disk's interrupt with a write to an irqfd on
            // arm64, and on x86-64 with the split irqchip.
            run: || {
                let msg = b"";
                // SAFETY: writing zero bytes to fd 1, which we inherited.
                unsafe { libc::write(1, msg.as_ptr().cast(), 0) };
            },
        },
        Probe {
            what: "write to an inherited descriptor (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Allowed,
            run: || {
                let msg = b"";
                // SAFETY: writing zero bytes to fd 1, which we inherited.
                unsafe { libc::write(1, msg.as_ptr().cast(), 0) };
            },
        },
        // A plugin that parks the vCPUs and then drains an fd-based doorbell
        // does that read on *this* thread, under the tight filter. The first
        // lists omitted `read` here, and the symptom was a VMM that died only
        // when something was actually watching the guest.
        Probe {
            what: "read from an inherited descriptor (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Allowed,
            run: || {
                let mut b = [0u8; 1];
                // SAFETY: reading zero bytes from fd 0, which we inherited.
                unsafe { libc::read(0, b.as_mut_ptr().cast(), 0) };
            },
        },
        Probe {
            what: "allocate host memory (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Allowed,
            run: || {
                let v: Vec<u8> = vec![7u8; 4 << 20];
                std::hint::black_box(&v);
            },
        },
        Probe {
            what: "allocate host memory (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Allowed,
            run: || {
                let v: Vec<u8> = vec![7u8; 4 << 20];
                std::hint::black_box(&v);
            },
        },
        // A new thread gets an arena of its own, and freeing 800 KiB from it
        // shrinks that arena's heap. glibc reads `overcommit_memory` the first
        // time that happens in a process. The child inherits glibc's answer
        // across the fork, so the probe reaches the read only while the
        // selftest's own process has never shrunk a thread's arena. With
        // `GLIBC_TUNABLES` that cap the arenas or move the trim or mmap
        // threshold, the heap may not shrink, and the probe passes without
        // reaching the read.
        Probe {
            what: "free a thread's heap memory (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Allowed,
            run: || {
                let _ = std::thread::spawn(|| {
                    let blocks: Vec<Vec<u8>> = (0..8).map(|_| vec![7u8; 100 << 10]).collect();
                    drop(std::hint::black_box(blocks));
                })
                .join();
            },
        },
        Probe {
            what: "poll an inherited descriptor (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Allowed,
            // Every helper thread waits in `poll` beside its stop token. If
            // glibc lowers the call to a syscall the allowlist does not carry,
            // every sandboxed run ends at the first wakeup.
            run: || {
                let mut fds = [libc::pollfd {
                    fd: 1,
                    events: libc::POLLOUT,
                    revents: 0,
                }];
                // SAFETY: one pollfd for fd 1, which we inherited, and a zero
                // timeout, so the call returns at once.
                unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) };
            },
        },
        Probe {
            what: "receive without blocking on an inherited descriptor (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Allowed,
            // The gateway relay drains its socket with `recv(MSG_DONTWAIT)`.
            run: || {
                // SAFETY: a zero-length receive on fd 1, which we inherited,
                // so a stream socket loses nothing. The filter has passed the
                // call before the kernel looks at the length.
                unsafe { libc::recv(1, std::ptr::null_mut(), 0, libc::MSG_DONTWAIT) };
            },
        },
        Probe {
            what: "signal a thread of this process (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Allowed,
            // `IoThreads::stop` ends the console reader's blocking read with
            // the kick signal, sent from the thread that calls `boot` under
            // this filter.
            run: || {
                use crate::signal::{install_kick_handler, kick_signal};
                install_kick_handler();
                // SAFETY: the kick signal, which now has a no-op handler in
                // this child, sent to the calling thread itself.
                unsafe { libc::pthread_kill(libc::pthread_self(), kick_signal()) };
            },
        },
        Probe {
            what: "spawn a thread (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Allowed,
            // The agent bridge spawns a reader per accepted connection, after
            // the filter is in.
            run: || {
                let _ = std::thread::spawn(|| 0u8).join();
            },
        },
        // The ledger writer sleeps under the vmm filter before it tries a
        // failed write again. Which syscall a sleep reaches depends on std and
        // the libc.
        Probe {
            what: "sleep (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Allowed,
            run: || {
                std::thread::sleep(std::time::Duration::from_millis(1));
            },
        },
        // The ioctl rule refuses two requests and passes every other one.
        Probe {
            what: "run a vCPU, KVM_RUN (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Allowed,
            run: || ioctl_on_no_descriptor(kvm_run() as libc::c_ulong),
        },
        Probe {
            what: "restore the terminal (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Allowed,
            run: restore_terminal,
        },
        Probe {
            what: "restore the terminal (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Allowed,
            run: restore_terminal,
        },
        // std seeds the first `HashMap` a thread makes with `getrandom`, and a
        // sink may make one on a disk's worker. The syscall is made directly,
        // since a libc may serve `getrandom` without one.
        Probe {
            what: "read random bytes (block)",
            thread: Thread::Block,
            expected: Outcome::Allowed,
            run: || {
                let mut seed = [0u8; 16];
                // SAFETY: the syscall writes at most `seed.len()` bytes into
                // `seed`.
                unsafe {
                    libc::syscall(
                        libc::SYS_getrandom,
                        seed.as_mut_ptr(),
                        seed.len(),
                        libc::GRND_NONBLOCK,
                    )
                };
            },
        },
    ]
}

/// Makes the terminal calls and requests of the terminal restore.
///
/// `boot` restores the terminal on the main thread, after that thread has
/// filtered itself. The fatal-signal handler and the panic hook restore it from
/// whichever thread they run on. Each request is made directly too, since a
/// libc call may give up before its last request on a descriptor that is not
/// open.
fn restore_terminal() {
    // SAFETY: the terminal calls and requests on a descriptor that is not open,
    // which the kernel refuses with EBADF once the filter has passed them.
    // `termios` is plain data, so zeroes are valid.
    unsafe {
        let mut settings: libc::termios = std::mem::zeroed();
        libc::ioctl(-1, libc::TCGETS, &mut settings);
        libc::ioctl(-1, libc::TCSETS, &settings);
        libc::ioctl(-1, libc::TCGETS2, &mut settings);
        libc::ioctl(-1, libc::TCSETS2, &settings);
        libc::ioctl(-1, libc::TCFLSH, libc::TCIFLUSH);
        libc::tcflush(-1, libc::TCIFLUSH);
        libc::tcgetattr(-1, &mut settings);
        libc::tcsetattr(-1, libc::TCSANOW, &settings);
    }
}

/// Returns the inherited descriptor `fd` as a `File` that never closes it.
fn inherited(fd: std::os::fd::RawFd) -> std::mem::ManuallyDrop<std::fs::File> {
    use std::os::fd::FromRawFd;
    // SAFETY: the `File` is never dropped, so it never closes `fd`, which the
    // probe child inherited and owns no other handle to.
    std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Exit status of a probe child whose syscall failed with `EPERM`.
const EXIT_REFUSED: i32 = 98;

/// Opens a file through each open syscall of this architecture.
///
/// It makes the syscalls itself, since the libc picks which one `open` makes.
/// It ends the child with [`EXIT_REFUSED`] if every one fails with `EPERM`, and
/// returns at the first one that is not refused. In a musl build the first,
/// `openat`, traps.
fn open_each_way() {
    let path = c"/etc/hosts";
    let refused = |result: libc::c_long| {
        result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    };
    // SAFETY: openat(2) on a valid NUL-terminated path. A descriptor it returns
    // is left open, since the child exits next.
    let openat = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_RDONLY,
        )
    };
    if !refused(openat) {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: as above, for open(2).
        let open = unsafe { libc::syscall(libc::SYS_open, path.as_ptr(), libc::O_RDONLY) };
        if !refused(open) {
            return;
        }
    }
    // `struct open_how`: flags, mode and resolve. libc's is non-exhaustive, so
    // a struct expression cannot build it.
    let how: [u64; 3] = [libc::O_RDONLY as u64, 0, 0];
    // SAFETY: as above, for openat2(2), with an `open_how` and its size.
    let openat2 = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            std::mem::size_of_val(&how),
        )
    };
    if refused(openat2) {
        // SAFETY: terminating the child without running destructors.
        unsafe { libc::_exit(EXIT_REFUSED) };
    }
}

/// Calls `ioctl(-1, request, NULL)` through `syscall(2)`.
///
/// `syscall(2)` passes the request as a full 64-bit argument, which
/// `libc::ioctl` cannot do on musl. The kernel refuses descriptor -1 with
/// `EBADF` before it reads the request, so a call the filter passes reaches no
/// terminal.
fn ioctl_on_no_descriptor(request: libc::c_ulong) {
    // SAFETY: an invalid descriptor and a null argument, which the kernel
    // rejects without dereferencing anything.
    unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            -1 as libc::c_long,
            request,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
}

/// What a filter did with a probe's syscall, or is meant to do with it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The child ran the syscall and exited normally.
    Allowed,
    /// The child was killed by `SIGSYS`, i.e. the filter trapped the syscall.
    Trapped,
    /// The child's syscall failed with `EPERM`.
    Refused,
}

impl Outcome {
    /// Returns the selftest's label for this outcome as the expected one.
    fn expected_label(self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Trapped => "trapped",
            Outcome::Refused => "refused",
        }
    }

    /// Returns the selftest's label for this outcome as the one seen.
    fn seen_label(self) -> &'static str {
        match self {
            Outcome::Allowed => "ran",
            Outcome::Trapped => "killed by SIGSYS",
            Outcome::Refused => "refused with EPERM",
        }
    }
}

/// Returns the outcome of one probe, run in a forked child.
///
/// It returns `Err` with the raw wait status when the child ended any other
/// way.
///
/// A child per probe is not incidental. The mismatch action is `trap`, so a
/// denied syscall kills the thread that made it -- an in-process probe like the
/// macOS selftest's would end the selftest at the first denial and could not
/// report anything. The parent stays unfiltered so it can fork the next one.
fn run_probe(probe: &Probe) -> io::Result<Result<Outcome, i32>> {
    // SAFETY: fork in a process that has not yet installed a filter. The child
    // touches nothing that needs the parent's locks: it installs the filters,
    // runs one closure and _exits without unwinding or flushing.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            // Child. Any failure here is reported as a distinctive exit code
            // rather than a panic, since panicking would itself need syscalls
            // the filter may not allow.
            if let Err(e) = install(probe.thread) {
                // Worth printing rather than swallowing: the usual cause is an
                // outer sandbox that refuses `seccomp(2)` itself (Docker's
                // default profile gates it behind CAP_SYS_ADMIN), and that is
                // not something the exit code alone would ever explain.
                eprintln!("  (child could not install the filter: {e})");
                // SAFETY: terminating the child without running destructors.
                unsafe { libc::_exit(97) };
            }
            (probe.run)();
            // SAFETY: as above. Reaching here means the syscall was allowed.
            unsafe { libc::_exit(0) };
        }
        _ => {
            let mut status: libc::c_int = 0;
            // SAFETY: reaping the child we just forked.
            if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(if libc::WIFEXITED(status) {
                match libc::WEXITSTATUS(status) {
                    0 => Ok(Outcome::Allowed),
                    EXIT_REFUSED => Ok(Outcome::Refused),
                    _ => Err(status),
                }
            } else if libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS {
                Ok(Outcome::Trapped)
            } else {
                Err(status)
            })
        }
    }
}

/// Proves the filters, with no hypervisor and no privileges: installs the
/// production allowlists in child processes and reports which syscalls
/// survived.
///
/// This is the negative test for the confinement. It checks the filters that
/// ship, compiled from the same lists the VMM compiles, rather than a
/// restatement of them, and it runs anywhere Linux does, even on a host that
/// cannot boot a guest.
///
/// Returns the number of probes that did not behave as the filters say they
/// should.
pub fn selftest() -> io::Result<usize> {
    if log_mode() {
        return Err(io::Error::other(format!(
            "{LOG_ENV}=log turns every denial into a log line, so the selftest would \
             prove nothing; unset it"
        )));
    }
    println!(
        "hvi seccomp selftest: vmm allows {vmm} syscalls, vcpu allows {vcpu}, block allows {block}",
        vmm = allowed_count(Thread::Vmm),
        vcpu = allowed_count(Thread::Vcpu),
        block = allowed_count(Thread::Block),
    );
    println!("hvi seccomp selftest: each probe runs in a child that installs the real filter\n");

    let mut bad = 0usize;
    for probe in probes() {
        let outcome = run_probe(&probe)?;
        // A child that died for any other reason -- above all one that could
        // not install the filter at all -- must never read as a successful
        // denial. Without this, running the selftest somewhere `seccomp(2)` is
        // itself refused (inside Docker's default profile, say) would report
        // every negative probe as passing while proving nothing.
        let good = outcome == Ok(probe.expected);
        if !good {
            bad += 1;
        }
        let verdict = if good { "ok  " } else { "FAIL" };
        let actual = match outcome {
            Ok(seen) => seen.seen_label().to_string(),
            Err(status) => format!("unexpected wait status {status:#x}"),
        };
        println!(
            "  [{verdict}] want {}  {:<38} {actual}",
            probe.expected.expected_label(),
            probe.what
        );
    }
    Ok(bad)
}

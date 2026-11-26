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

//! seccomp-bpf confinement for the Linux backends.
//!
//! Same argument as the macOS half (`sandbox::seatbelt`): the virtio backends
//! parse guest-controlled data and they run in the same process as the vCPU
//! threads, so a bug in one of them is a bug in something holding the host's
//! full syscall surface. Whatever container boundary a caller wraps hvi in is
//! real, but it is outside the process and says nothing about what the process
//! itself may ask the kernel for.
//!
//! # What is reused, and what is not
//!
//! The mechanism is [`seccompiler`], the rust-vmm crate extracted from
//! Firecracker: it compiles an allowlist to BPF and installs it. We write no
//! BPF and no syscall-number tables. The lists are constants in the
//! `allowlists` module, where an entry takes its syscall number from libc's
//! constant, and an `ioctl` request from libc's constant or the header's
//! definition, under a comment that says why the call is there.
//!
//! What is deliberately *not* reused is the content of Firecracker's filters,
//! and that is worth writing down because it is the opposite of what you would
//! expect. Firecracker ships `x86_64-unknown-linux-musl.json` and
//! `aarch64-unknown-linux-musl.json`, musl only, and drives its devices with
//! epoll and io_uring. hvi's lists were measured on a glibc build, and hvi
//! uses blocking reads on dedicated threads. Their lists therefore carry
//! `io_uring_*` and `epoll_*`, and on x86-64 `open` and `stat`, which we never
//! call, and omit `statx`, `rseq`, `set_robust_list`, `sched_getaffinity` and
//! `clone3`, without which a glibc Rust binary dies before it reaches `main`.
//! Vendoring them would have been simultaneously too loose and fatally too
//! tight. So the lists are measured from hvi under `strace -f`, and the entries
//! that our trace did *not* show are marked in the lists as safety nets taken
//! from their production experience, which is the part of Firecracker's work
//! that transfers. The musl build shares the lists. musl can reach a different
//! syscall than glibc for the same library call, so `hvi seccomp-selftest` run
//! on the musl binary is the check for that.
//!
//! Firecracker's *jailer* is a different question and the answer is no. It is a
//! launcher binary -- chroot, cgroups, netns, uid drop -- not a library, so
//! "reusing" it would mean shipping and exec'ing a second binary and adopting
//! its directory layout. A container runtime already provides that outer
//! boundary wherever hvi runs under one. The gap this module closes is the
//! VMM's own syscall surface, and that is seccomp.
//!
//! # Where the filters go in
//!
//! Three filters, because the threads are not alike. `vcpu` is the tight one
//! for the vCPU threads. A vCPU thread serves its MMIO and port exits, so the
//! virtio-mmio transport, the net and vsock device models, the vhost-user
//! handover and the legacy devices run there, and the device models parse guest
//! descriptors. A disk's requests run on the disk's worker, so `vcpu` allows no
//! read or write at an offset, no seek and no file sync. `block` covers each
//! disk's worker thread, which parses the disk's descriptors and runs its
//! requests against the backing file. It alone allows `preadv` and `pwritev`,
//! which move a request's data between the backing file and guest RAM. `vmm`
//! covers the thread that calls `boot`, the boot thread below, the other
//! host-side I/O threads (the console reader, the agent bridge and its
//! per-connection readers, the tap and gateway readers, and the debug watchdog
//! when it is enabled), the threads a plugin starts with `VmHandle::spawn`, the
//! thread that receives the stop signals and the ledger writer. The ledger
//! writer starts with the ledger, before the filters are armed, and installs
//! `vmm` before its first write after the filters are armed. Each queued I/O
//! thread names its filter when it is queued.
//!
//! Ordering is the interesting part, and it is chosen so that **no filter has
//! to allow `seccomp` itself**:
//!
//! ```text
//! boot: acquire everything, spawn the I/O threads ─┐
//!                     each I/O thread installs its filter at its start
//! boot: spawn the vCPU threads ────────────────────┤
//!                     each vCPU thread installs `vcpu` at its start
//! boot: install `vmm` on itself, then join ────────┘
//! ```
//!
//! Nothing is ever spawned *underneath* a filter except the per-connection
//! vsock readers, which the agent bridge creates and which correctly inherit
//! `vmm`. Had the boot thread instead installed its filter first and relied on
//! inheritance, every thread wanting a filter of its own would have needed
//! `seccomp` allowed, which hands a compromised backend the ability to install
//! filters. The order above costs nothing and avoids that.
//!
//! Everything acquired during setup is finished by the time any filter is in,
//! so `openat`, `memfd_create`, `ftruncate` and the glibc startup calls are
//! absent from every list. A compromised virtio backend cannot open a file.
//!
//! # The files glibc opens by itself
//!
//! glibc's malloc opens two files on its own, from whichever thread is
//! allocating or freeing at the time: `/proc/sys/vm/overcommit_memory` the
//! first time the heap of a thread's arena shrinks, and
//! `/sys/devices/system/cpu/online`, falling back to `/proc/stat`, when a
//! thread needs a new arena while more than eight exist. It copes with each
//! open failing. So a glibc build installs, on every thread and before the
//! allowlist, a second filter that fails the open syscalls (`openat`,
//! `openat2`, and on x86-64 `open`) with `EPERM`, and adds them to the
//! allowlist it compiles. The kernel takes the strictest answer of a thread's
//! filters, so an open is refused rather than trapped, and a backend still
//! opens nothing. musl's malloc opens no file, so a musl build installs the
//! allowlist alone.
//!
//! # The default action, and diagnosing it
//!
//! A syscall outside the list traps: `SIGSYS`, a dead process, a core file.
//! That is Firecracker's choice too and it is the right one for a security
//! boundary -- `errno` would let a filtered VMM limp on doing something subtly
//! wrong. The open refusal above is the one exception, since the opens it
//! refuses come from glibc's malloc, which works without the file. The cost is
//! that a list which is too tight on some distro is a crash rather than a
//! warning, so there are two ways out: `--no-sandbox` skips the filter
//! entirely, and `HVI_SECCOMP=log` installs the same filters with the mismatch
//! action changed to `log`, which lets the kernel record what would have been
//! killed (`dmesg`, or `auditctl`) while the VMM keeps running. The open
//! refusal stays in under it, unrecorded.
//!
//! # Argument conditions
//!
//! A rule may match an argument as well as the syscall. Only the `ioctl` rules
//! do, on the request number. `block` allows `ioctl` only for the requests its
//! thread makes, so a worker cannot reach the rest of KVM's ioctls, or another
//! descriptor's. The `ioctl` rule of `vmm` and `vcpu` refuses `TIOCSTI` and
//! `TIOCLINUX` on any descriptor and allows every other request. A refused
//! request traps like an off-list syscall.
//!
//! The process shares the operator's terminal. Each request can push bytes
//! into a terminal's input, and the operator's shell reads them as typed input
//! once hvi exits. The kernel's own checks depend on the host. On the caller's
//! controlling terminal it refuses `TIOCSTI` only under
//! `dev.tty.legacy_tiocsti = 0`, and it refuses neither request to a caller
//! with `CAP_SYS_ADMIN`.
//!
//! Each condition compares the low 32 bits of the request, because the kernel
//! reads the request as an `unsigned int`. A 64-bit comparison would pass
//! `TIOCSTI` with a bit set above bit 31, and the kernel would still run it as
//! `TIOCSTI`.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

pub use super::Thread;
use crate::LOG_PREFIX;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

mod allowlists;
mod selftest;

pub use selftest::selftest;

use allowlists::Request;

impl Thread {
    /// Returns the name the filter has in a message.
    fn name(self) -> &'static str {
        match self {
            Thread::Vmm => "vmm",
            Thread::Vcpu => "vcpu",
            Thread::Block => "block",
        }
    }
}

/// The architecture seccompiler compiles a filter for.
///
/// It comes from `cfg`, as the syscall numbers in the lists do, so a filter
/// checks for the architecture its numbers belong to.
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
/// The architecture seccompiler compiles a filter for.
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;

/// The open syscalls of this architecture, which a glibc build refuses with
/// [`open_refusal_program`].
#[cfg(target_env = "gnu")]
const OPEN_SYSCALLS: &[i64] = &[
    #[cfg(target_arch = "x86_64")]
    libc::SYS_open,
    libc::SYS_openat,
    libc::SYS_openat2,
];

/// Environment variable that swaps the mismatch action for `log`, so a syscall
/// outside the allowlist is recorded by the kernel instead of killing the
/// process. For diagnosing a too-tight list on a distro we have not measured;
/// it is not a supported way to run, and the backend says so.
pub const LOG_ENV: &str = "HVI_SECCOMP";

/// True when [`LOG_ENV`] asks for log-instead-of-trap.
pub fn log_mode() -> bool {
    std::env::var(LOG_ENV).is_ok_and(|v| v == "log")
}

/// Returns the allowlist for `thread`, compiled from its rules.
///
/// With `log` set, a syscall outside the list is logged rather than trapped. A
/// glibc build adds the open syscalls to the list, which is safe only behind
/// the filter that refuses them, so the allowlist is compiled through
/// [`programs`] alone.
fn allowlist(thread: Thread, log: bool) -> io::Result<BpfProgram> {
    let failed = |e: seccompiler::BackendError| {
        io::Error::other(format!("compiling the {} filter: {e}", thread.name()))
    };
    // A condition on the request of an `ioctl`, compared in its low 32 bits,
    // whatever the libc's type for a request.
    let condition = |op, request: libc::Ioctl| {
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, op, u64::from(request as u32))
            .map_err(failed)
    };
    // A syscall with no condition is allowed whatever its arguments.
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for rule in thread.rules() {
        let allowed = rules.entry(rule.number).or_default();
        let conditions = match rule.request {
            Request::Any => continue,
            Request::Is(request) => vec![condition(SeccompCmpOp::Eq, request)?],
            Request::IsNot(requests) => requests
                .iter()
                .map(|&request| condition(SeccompCmpOp::Ne, request))
                .collect::<io::Result<_>>()?,
        };
        allowed.push(SeccompRule::new(conditions).map_err(failed)?);
    }
    #[cfg(target_env = "gnu")]
    for &number in OPEN_SYSCALLS {
        rules.entry(number).or_default();
    }
    let mismatch = if log {
        SeccompAction::Log
    } else {
        SeccompAction::Trap
    };
    SeccompFilter::new(rules, mismatch, SeccompAction::Allow, ARCH)
        .and_then(BpfProgram::try_from)
        .map_err(failed)
}

/// Compiles the filter a glibc build installs before each allowlist.
///
/// It fails [`OPEN_SYSCALLS`] with `EPERM` and allows every other syscall, so
/// the allowlist decides those. It returns `EPERM` rather than `ENOENT`, so an
/// open the sandbox refused does not read as a missing file.
#[cfg(target_env = "gnu")]
fn open_refusal_program() -> io::Result<BpfProgram> {
    let rules = OPEN_SYSCALLS
        .iter()
        .map(|&number| (number, Vec::new()))
        .collect();
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM.unsigned_abs()),
        ARCH,
    )
    .and_then(BpfProgram::try_from)
    .map_err(|e| io::Error::other(format!("compiling the open refusal filter: {e}")))
}

/// Compiles the filters `thread` installs, in the order it installs them, each
/// with a name for its errors.
///
/// A glibc build puts the filter that refuses an open first, since no allowlist
/// allows `seccomp` and nothing can go in after one. `log` is whether the
/// allowlist logs a syscall outside it rather than trapping.
fn programs(thread: Thread, log: bool) -> io::Result<Vec<(&'static str, BpfProgram)>> {
    Ok(vec![
        #[cfg(target_env = "gnu")]
        ("open refusal", open_refusal_program()?),
        (thread.name(), allowlist(thread, log)?),
    ])
}

/// Installs `thread`'s filters on the calling thread.
///
/// The thread counts as filtered once its first filter is in. A filter cannot
/// be removed, so the thread keeps that one even when a later one fails to
/// install.
///
/// Irreversible, and inherited by anything this thread spawns afterwards. Fails
/// closed: the caller refuses to boot rather than run unfiltered, because a
/// filter that will not compile or install is one nobody has tested.
pub fn install(thread: Thread) -> io::Result<()> {
    for (name, program) in programs(thread, log_mode())? {
        seccompiler::apply_filter(&program)
            .map_err(|e| io::Error::other(format!("installing the {name} filter: {e}")))?;
        INSTALLED.set(true);
    }
    Ok(())
}

/// Whether [`arm`] has run in this process.
///
/// It is set before a run spawns its threads and read by every thread that
/// filters itself, a flag rather than a parameter passed to each of those
/// threads. The threads that read it start after it is set, apart from two. The
/// stop-signal thread outlives the run that started it, and a ledger's writer
/// can start before [`arm`]. It is never cleared, since a filter cannot be
/// removed from a thread.
static ARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

thread_local! {
    /// Whether this thread installed a filter with [`install`].
    ///
    /// A thread that inherited a filter from the thread that started it reads
    /// `false`. See [`install_thread`] for why asking twice has to be harmless.
    static INSTALLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Returns whether [`arm`] has run in this process.
pub(crate) fn is_entered() -> bool {
    ARMED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Returns whether a syscall outside the allowlists ends the process.
///
/// It does once [`arm`] has run, outside log mode, since every thread a run
/// spawns from then on is filtered, and so is the thread that called `boot`. A
/// thread the caller started itself stays unfiltered, and there it returns
/// `true` while no filter applies.
pub(crate) fn is_trapping() -> bool {
    is_entered() && !log_mode()
}

/// Returns whether the calling thread installed a filter.
pub(crate) fn is_thread_filtered() -> bool {
    INSTALLED.get()
}

/// Turns filtering on for the threads spawned after this call.
///
/// It compiles every filter first, so a list seccompiler refuses is a boot
/// error on the thread that calls `boot`, where it can be reported, and no
/// thread aborts later because its filter does not compile.
pub fn arm() -> io::Result<()> {
    for thread in Thread::ALL {
        programs(thread, log_mode())?;
    }
    ARMED.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

/// Installs `thread`'s filters if [`arm`] was called.
///
/// Called at the top of each thread hvi spawns *before* the thread that calls
/// `boot` filters itself, and before each pass of a thread that can start
/// before [`arm`]: the stop-signal thread and a ledger's writer. Not called by
/// the per-connection vsock readers: those are spawned by an already-filtered
/// thread and correctly inherit its filter. Calling `seccomp` from under a
/// filter that does not allow it would trap.
///
/// It aborts if it cannot, rather than returning an error. There is no
/// meaningful recovery inside a worker thread: continuing would run a
/// guest-facing loop unfiltered, and returning would silently drop a device.
/// [`arm`] has already proved the filters compile, so reaching this means the
/// kernel refused the install.
pub fn install_thread(thread: Thread) {
    if !is_entered() {
        return;
    }
    // "Make sure this thread is filtered", not "add a filter". Asking twice is
    // a no-op rather than a kill, because the second `prctl` would be judged by
    // the filter the first one installed and neither list allows `prctl`. That
    // is not hypothetical: the first version of this change called it inside
    // the interval thread's loop, and the guest died three seconds in. The call
    // sites are correct now, and this makes getting one wrong later cheap.
    if INSTALLED.with(|done| done.replace(true)) {
        return;
    }
    if let Err(e) = install(thread) {
        stderrln!(
            "{LOG_PREFIX} FATAL: cannot filter the {} thread: {e}",
            thread.name()
        );
        std::process::abort();
    }
}

/// Returns the number of syscalls the filter of `thread` allows.
///
/// A syscall with a rule per argument value counts once.
pub fn allowed_count(thread: Thread) -> usize {
    thread
        .rules()
        .iter()
        .map(|rule| rule.number)
        .collect::<BTreeSet<_>>()
        .len()
}

/// Returns the `KVM_RUN` request, which `vmm` and `vcpu` allow.
const fn kvm_run() -> libc::Ioctl {
    libc::_IO(kvm_bindings::KVMIO, 0x80)
}

/// The seccomp filters of a run, compiled before its I/O and vCPU threads
/// start.
///
/// Each thread installs its own filters as it starts, with [`install_thread`].
/// [`Filters::install`] installs those of the thread that calls `boot`, last.
pub(crate) struct Filters {
    /// Whether the sandbox is on.
    armed: bool,
}

impl Filters {
    /// Arms the seccomp filters when `sandbox` is set.
    ///
    /// This compiles every filter, so a list that does not compile fails the
    /// boot here. Nothing is filtered yet: each thread installs its own as it
    /// starts.
    ///
    /// # Errors
    ///
    /// Errors if a filter does not compile.
    pub(crate) fn arm(sandbox: bool) -> io::Result<Self> {
        if !sandbox {
            return Ok(Self { armed: false });
        }
        arm()?;
        Ok(Self { armed: true })
    }

    /// Returns whether the filters are armed.
    pub(crate) fn is_armed(&self) -> bool {
        self.armed
    }

    /// Filters the calling thread, the one that called `boot`, and reports the
    /// confinement on stderr.
    ///
    /// It must run once every thread that thread spawns exists. That order lets
    /// every allowlist refuse `seccomp` itself, since nothing is created under
    /// a filter except the per-connection vsock threads, which inherit it.
    ///
    /// # Errors
    ///
    /// Errors if the filter cannot be installed.
    pub(crate) fn install(self) -> io::Result<()> {
        if !self.armed {
            stderrln!(
                "{LOG_PREFIX} seccomp: OFF (--no-sandbox); the VMM keeps the full host syscall surface"
            );
            return Ok(());
        }
        install(Thread::Vmm)?;
        let opens = if cfg!(target_env = "gnu") {
            "; open is refused"
        } else {
            ""
        };
        if log_mode() {
            stderrln!(
                "{LOG_PREFIX} seccomp: LOGGING ONLY ({LOG_ENV}=log); denials are recorded, not enforced{opens}"
            );
        } else {
            stderrln!(
                "{LOG_PREFIX} seccomp: on (vmm {vmm} syscalls, vcpu {vcpu}, block {block}, trap on mismatch{opens})",
                vmm = allowed_count(Thread::Vmm),
                vcpu = allowed_count(Thread::Vcpu),
                block = allowed_count(Thread::Block),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A list seccompiler refuses is a startup failure in production. Here it is
    // a test failure on any Linux host.
    #[test]
    fn filters_compile_for_this_arch() {
        for thread in Thread::ALL {
            for (_, p) in programs(thread, false).expect("filter should compile") {
                assert!(!p.is_empty(), "{:?} compiled to an empty program", thread);
            }
        }
    }

    /// The audit architecture the kernel puts in `seccomp_data`.
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    /// The audit architecture the kernel puts in `seccomp_data`.
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;

    /// Returns the action `program` takes for a syscall `number` with the
    /// arguments `args`.
    ///
    /// It runs the program as the kernel's classic BPF interpreter would. It
    /// knows the instructions seccompiler emits and panics on any other.
    fn run_program(program: &[seccompiler::sock_filter], number: i64, args: [u64; 6]) -> u32 {
        // `seccomp_data`: the syscall number, the audit architecture, the
        // instruction pointer and six arguments.
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&u32::try_from(number).unwrap().to_ne_bytes());
        data[4..8].copy_from_slice(&AUDIT_ARCH.to_ne_bytes());
        for (index, arg) in args.iter().enumerate() {
            data[16 + index * 8..24 + index * 8].copy_from_slice(&arg.to_ne_bytes());
        }
        let (mut pc, mut acc) = (0usize, 0u32);
        loop {
            let insn = &program[pc];
            pc += 1;
            let code = u32::from(insn.code);
            let jump = |taken: bool| usize::from(if taken { insn.jt } else { insn.jf });
            match code {
                c if c == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS => {
                    let at = insn.k as usize;
                    acc = u32::from_ne_bytes(data[at..at + 4].try_into().unwrap());
                }
                c if c == libc::BPF_ALU | libc::BPF_AND | libc::BPF_K => acc &= insn.k,
                c if c == libc::BPF_JMP | libc::BPF_JA => pc += insn.k as usize,
                c if c == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K => pc += jump(acc == insn.k),
                c if c == libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K => pc += jump(acc > insn.k),
                c if c == libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K => pc += jump(acc >= insn.k),
                c if c == libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K => {
                    pc += jump(acc & insn.k != 0)
                }
                c if c == libc::BPF_RET | libc::BPF_K => return insn.k,
                c => panic!("seccompiler emitted BPF opcode {c:#x}, which this test does not run"),
            }
        }
    }

    /// Returns the kernel's action for `number` with all-zero arguments under
    /// all of `programs`.
    fn verdict(programs: &[BpfProgram], number: i64) -> u32 {
        verdict_with(programs, number, [0; 6])
    }

    /// Returns the kernel's action for `number` with the arguments `args` under
    /// all of `programs`.
    ///
    /// That is the strictest of their actions, which is the lowest read as a
    /// signed number.
    fn verdict_with(programs: &[BpfProgram], number: i64, args: [u64; 6]) -> u32 {
        programs
            .iter()
            .map(|p| run_program(p, number, args))
            .min_by_key(|&action| (action & libc::SECCOMP_RET_ACTION_FULL) as i32)
            .unwrap()
    }

    /// Returns the filters `install` installs for `thread`.
    fn installed(thread: Thread) -> Vec<BpfProgram> {
        programs(thread, false)
            .unwrap()
            .into_iter()
            .map(|(_, program)| program)
            .collect()
    }

    // It runs the filters `install` installs, so it covers the open refusal
    // together with the allowlist that allows the opens. The syscall numbers
    // come from libc rather than from `OPEN_SYSCALLS`, so a wrong entry there
    // fails it.
    #[test]
    fn installed_filters_refuse_an_open_and_trap_a_socket() {
        let open = if cfg!(target_env = "gnu") {
            libc::SECCOMP_RET_ERRNO | libc::EPERM.unsigned_abs()
        } else {
            libc::SECCOMP_RET_TRAP
        };
        for thread in Thread::ALL {
            let filters = installed(thread);
            #[cfg(target_arch = "x86_64")]
            assert_eq!(verdict(&filters, libc::SYS_open), open, "open, {thread:?}");
            assert_eq!(
                verdict(&filters, libc::SYS_openat),
                open,
                "openat, {thread:?}"
            );
            assert_eq!(
                verdict(&filters, libc::SYS_openat2),
                open,
                "openat2, {thread:?}"
            );
            assert_eq!(
                verdict(&filters, libc::SYS_socket),
                libc::SECCOMP_RET_TRAP,
                "socket, {thread:?}"
            );
            assert_eq!(
                verdict(&filters, libc::SYS_write),
                libc::SECCOMP_RET_ALLOW,
                "write, {thread:?}"
            );
        }
    }

    // Every filter must deny by default. A filter that allowed by default
    // would install, run, and confine nothing.
    #[test]
    fn filters_trap_on_mismatch() {
        for thread in Thread::ALL {
            for (log, action) in [
                (false, libc::SECCOMP_RET_TRAP),
                (true, libc::SECCOMP_RET_LOG),
            ] {
                let program = allowlist(thread, log).unwrap();
                assert_eq!(
                    run_program(&program, libc::SYS_socket, [0; 6]),
                    action,
                    "{thread:?} on a syscall outside its list, log {log}"
                );
            }
        }
    }

    // The compiled filter is asked about each request a worker makes and about
    // some it does not, so a request the list lacks or gains fails.
    #[test]
    fn block_filter_allows_only_its_ioctl_requests() {
        let filters = installed(Thread::Block);
        let ioctl = |request: libc::Ioctl| {
            // A request is a 32-bit value, whatever the libc's type for it.
            let request = u64::from(request as u32);
            verdict_with(&filters, libc::SYS_ioctl, [0, request, 0, 0, 0, 0])
        };
        let allowed = [
            libc::TCGETS,
            libc::TCSETS,
            libc::TCGETS2,
            libc::TCSETS2,
            libc::TCFLSH,
            #[cfg(target_arch = "x86_64")]
            allowlists::KVM_IRQ_LINE,
        ];
        for request in allowed {
            assert_eq!(
                ioctl(request),
                libc::SECCOMP_RET_ALLOW,
                "request {request:#x}"
            );
        }
        for request in [libc::FIONREAD, libc::TIOCSTI, kvm_run()] {
            assert_eq!(
                ioctl(request),
                libc::SECCOMP_RET_TRAP,
                "request {request:#x}"
            );
        }
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            ioctl(libc::_IOW::<kvm_bindings::kvm_irq_level>(
                kvm_bindings::KVMIO,
                0x61
            )),
            libc::SECCOMP_RET_TRAP,
            "an arm64 worker raises its interrupt with an eventfd write"
        );
    }

    // The filters of the architecture the test runs on. The kernel reads the
    // request as a 32-bit unsigned int, so every refused request is also tried
    // with bits 32-63 set.
    #[test]
    fn ioctl_traps_terminal_input_requests() {
        let high = 0xffff_ffff_0000_0000u64;
        for thread in [Thread::Vmm, Thread::Vcpu] {
            let filters = installed(thread);
            let ioctl =
                |request: u64| verdict_with(&filters, libc::SYS_ioctl, [0, request, 0, 0, 0, 0]);
            // A request is a 32-bit value, whatever the libc's type for it.
            for refused in [libc::TIOCSTI as u32, libc::TIOCLINUX as u32] {
                for request in [u64::from(refused), high | u64::from(refused)] {
                    assert_eq!(
                        ioctl(request),
                        libc::SECCOMP_RET_TRAP,
                        "{} passes ioctl request {request:#x}",
                        thread.name()
                    );
                }
            }
            // KVM_RUN, TCSETS, and TIOCGWINSZ one above TIOCSTI.
            for request in [
                kvm_run() as u32,
                libc::TCSETS as u32,
                libc::TIOCGWINSZ as u32,
            ] {
                assert_eq!(
                    ioctl(u64::from(request)),
                    libc::SECCOMP_RET_ALLOW,
                    "{} refuses ioctl request {request:#x}",
                    thread.name()
                );
            }
        }
    }
}

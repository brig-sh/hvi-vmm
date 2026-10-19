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
//! Firecracker: it compiles a declarative allowlist to BPF and installs it. We
//! write no BPF and no syscall-number tables. The filter files in
//! `resources/seccomp/` are in seccompiler's JSON schema, which is
//! Firecracker's schema, so they are reviewable the same way theirs are.
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
//! that our trace did *not* show are marked in the JSON as safety nets taken
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
//! Two filters, because the threads are not alike. `vcpu` is the tight one and
//! it matters most: MMIO exits are serviced inline on the vCPU thread, so the
//! virtio device models -- the code that parses guest descriptors -- run there.
//! `vmm` covers the thread that calls `boot`, the boot thread below, the
//! host-side I/O threads (the console reader, the agent bridge and its
//! per-connection readers, the tap and gateway readers, and the debug watchdog
//! when it is enabled), the threads a plugin starts with `VmHandle::spawn`, the
//! thread that receives the stop signals and the ledger writer. The ledger
//! writer starts with the ledger, before the filters are armed, and installs
//! `vmm` before its first write after the filters are armed.
//!
//! Ordering is the interesting part, and it is chosen so that **no filter has
//! to allow `seccomp` itself**:
//!
//! ```text
//! boot: acquire everything, spawn the I/O threads ─┐
//!                     each I/O thread installs `vmm` at its start
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
//! absent from both lists. A compromised virtio backend cannot open a file.
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

use std::io;

use crate::LOG_PREFIX;
use seccompiler::{BpfProgram, TargetArch};

/// Which filter a thread installs on itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Thread {
    /// The thread that calls `boot` and the host-side I/O threads.
    Vmm,
    /// A vCPU thread: KVM plus the device models it services inline.
    Vcpu,
}

impl Thread {
    /// The key this filter has in the JSON.
    fn key(self) -> &'static str {
        match self {
            Thread::Vmm => "vmm",
            Thread::Vcpu => "vcpu",
        }
    }
}

/// The allowlists, per architecture. Compiled in, so the running binary carries
/// the filters it was reviewed with rather than reading them from a path an
/// attacker might control.
#[cfg(target_arch = "x86_64")]
pub const FILTERS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/seccomp/x86_64.json"
));
/// The allowlists, per architecture.
#[cfg(target_arch = "aarch64")]
pub const FILTERS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/seccomp/aarch64.json"
));

/// The architecture seccompiler compiles syscall names for. Getting this wrong
/// would compile a filter against the wrong syscall numbers, which is why it
/// comes from `cfg` rather than from anything at run time.
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
/// The architecture seccompiler compiles syscall names for.
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;

/// The open syscalls of this architecture, which a glibc build refuses with
/// [`open_refusal_program`].
#[cfg(target_env = "gnu")]
const OPEN_SYSCALLS: &[(&str, i64)] = &[
    #[cfg(target_arch = "x86_64")]
    ("open", libc::SYS_open),
    ("openat", libc::SYS_openat),
    ("openat2", libc::SYS_openat2),
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

/// Returns the allowlist for `thread`, compiled from [`FILTERS`].
///
/// The JSON is rewritten before compiling rather than kept as a second copy of
/// the lists that could drift from the real one. With `log` set,
/// `default_action`, the mismatch action in seccompiler's schema, becomes
/// `log`. A glibc build adds the open syscalls to each list, which is safe only
/// behind the filter that refuses them, so the allowlist is compiled through
/// [`programs`] alone.
fn allowlist(thread: Thread, log: bool) -> io::Result<BpfProgram> {
    let mut doc: serde_json::Value =
        serde_json::from_str(FILTERS).map_err(|e| io::Error::other(format!("filters: {e}")))?;
    let Some(map) = doc.as_object_mut() else {
        return Err(io::Error::other("filters: expected a JSON object"));
    };
    for (_name, filter) in map.iter_mut() {
        let Some(obj) = filter.as_object_mut() else {
            continue;
        };
        if log {
            obj.insert(
                "default_action".to_string(),
                serde_json::Value::String("log".to_string()),
            );
        }
        #[cfg(target_env = "gnu")]
        if let Some(list) = obj.get_mut("filter").and_then(|f| f.as_array_mut()) {
            list.extend(
                OPEN_SYSCALLS
                    .iter()
                    .map(|(name, _)| serde_json::json!({ "syscall": name })),
            );
        }
    }
    let json =
        serde_json::to_string(&doc).map_err(|e| io::Error::other(format!("filters: {e}")))?;

    let mut map = seccompiler::compile_from_json(json.as_bytes(), ARCH)
        .map_err(|e| io::Error::other(format!("compiling the {} filter: {e}", thread.key())))?;
    map.remove(thread.key())
        .ok_or_else(|| io::Error::other(format!("no {} filter in the allowlists", thread.key())))
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
        .map(|&(_, number)| (number, Vec::new()))
        .collect();
    seccompiler::SeccompFilter::new(
        rules,
        seccompiler::SeccompAction::Allow,
        seccompiler::SeccompAction::Errno(libc::EPERM.unsigned_abs()),
        ARCH,
    )
    .and_then(BpfProgram::try_from)
    .map_err(|e| io::Error::other(format!("compiling the open refusal filter: {e}")))
}

/// Compiles the filters `thread` installs, in the order it installs them, each
/// with a name for its errors.
///
/// A glibc build puts the filter that refuses an open first, since neither
/// allowlist allows `seccomp` and nothing can go in after one. `log` is whether
/// the allowlist logs a syscall outside it rather than trapping.
fn programs(thread: Thread, log: bool) -> io::Result<Vec<(&'static str, BpfProgram)>> {
    Ok(vec![
        #[cfg(target_env = "gnu")]
        ("open refusal", open_refusal_program()?),
        (thread.key(), allowlist(thread, log)?),
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
/// It compiles every filter first. That turns "this distro's kernel headers
/// spell a syscall differently" into a boot error on the thread that calls
/// `boot`, where it can be reported, instead of a `SIGSYS` inside a device
/// thread later on.
pub fn arm() -> io::Result<()> {
    for thread in [Thread::Vmm, Thread::Vcpu] {
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
            thread.key()
        );
        std::process::abort();
    }
}

/// Number of syscalls each filter allows, for the log line and the selftest.
pub fn allowed_counts() -> io::Result<(usize, usize)> {
    let doc: serde_json::Value =
        serde_json::from_str(FILTERS).map_err(|e| io::Error::other(format!("filters: {e}")))?;
    let count = |k: &str| -> usize {
        doc.get(k)
            .and_then(|f| f.get("filter"))
            .and_then(|f| f.as_array())
            .map_or(0, Vec::len)
    };
    Ok((count("vmm"), count("vcpu")))
}

/// The seccomp filters of a run, compiled before its I/O and vCPU threads
/// start.
///
/// Each thread installs its own filters as it starts, with [`install_thread`].
/// [`Filters::install`] installs those of the thread that calls `boot`, last.
pub(crate) struct Filters {
    /// The number of syscalls each filter allows, when the sandbox is on.
    counts: Option<(usize, usize)>,
}

impl Filters {
    /// Arms the seccomp filters when `sandbox` is set.
    ///
    /// This compiles every filter, so a bad list fails the boot here rather
    /// than as a `SIGSYS` inside a device thread later. Nothing is filtered
    /// yet: each thread installs its own as it starts.
    ///
    /// # Errors
    ///
    /// Errors if a filter does not compile.
    pub(crate) fn arm(sandbox: bool) -> io::Result<Self> {
        if !sandbox {
            return Ok(Self { counts: None });
        }
        arm()?;
        Ok(Self {
            counts: Some(allowed_counts()?),
        })
    }

    /// Returns whether the filters are armed.
    pub(crate) fn is_armed(&self) -> bool {
        self.counts.is_some()
    }

    /// Filters the calling thread, the one that called `boot`, and reports the
    /// confinement on stderr.
    ///
    /// It must run once every thread that thread spawns exists. That order lets
    /// both allowlists refuse `seccomp` itself, since nothing is created under
    /// a filter except the per-connection vsock threads, which inherit it.
    ///
    /// # Errors
    ///
    /// Errors if the filter cannot be installed.
    pub(crate) fn install(self) -> io::Result<()> {
        let Some((vmm, vcpu)) = self.counts else {
            stderrln!(
                "{LOG_PREFIX} seccomp: OFF (--no-sandbox); the VMM keeps the full host syscall surface"
            );
            return Ok(());
        };
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
                "{LOG_PREFIX} seccomp: on (vmm {vmm} syscalls, vcpu {vcpu}, trap on mismatch{opens})"
            );
        }
        Ok(())
    }
}

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
        // The other half: what a filtered thread must still be able to do.
        //
        // The flush pair earns its place: the lists first shipped allowing
        // `fsync` for "virtio-blk flush requests", but the device model calls
        // `File::sync_data`, which is `fdatasync`. Nothing caught it, because a
        // guest that only ever reads its disk never issues a flush -- it took a
        // container with a writable rootfs, and the VMM died of SIGSYS mid-run.
        // A probe per filter means the allowlist is checked against the syscall
        // the code actually makes.
        Probe {
            what: "flush an inherited descriptor (vcpu)",
            thread: Thread::Vcpu,
            expected: Outcome::Allowed,
            run: || {
                // SAFETY: fdatasync on fd 1, which we inherited. It is the
                // syscall `File::sync_data` makes on the virtio-blk flush path.
                unsafe { libc::fdatasync(1) };
            },
        },
        Probe {
            what: "flush an inherited descriptor (vmm)",
            thread: Thread::Vmm,
            expected: Outcome::Allowed,
            run: || {
                // SAFETY: as above.
                unsafe { libc::fdatasync(1) };
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
    ]
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
/// actually ship -- compiled from the same JSON the VMM compiles -- rather than
/// a restatement of them, and it runs anywhere Linux does, so a hosted runner
/// can prove the filter even where it cannot boot a guest.
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
    let (vmm, vcpu) = allowed_counts()?;
    println!("hvi seccomp selftest: vmm allows {vmm} syscalls, vcpu allows {vcpu}");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Both filters must compile for the architecture the binary is built for.
    /// A typo in a syscall name, or a name that does not exist on this arch
    /// (`poll` is the one that differs: x86-64 has both `poll` and `ppoll`,
    /// aarch64 has `ppoll` alone), is a startup failure in production; here it
    /// is a test failure on any Linux host.
    #[test]
    fn filters_compile_for_this_arch() {
        for thread in [Thread::Vmm, Thread::Vcpu] {
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

    /// Returns the action `program` takes for a syscall `number` with all-zero
    /// arguments.
    ///
    /// It runs the program as the kernel's classic BPF interpreter would. It
    /// knows the instructions seccompiler emits and panics on any other.
    fn run_program(program: &[seccompiler::sock_filter], number: i64) -> u32 {
        // `seccomp_data`: the syscall number, the audit architecture, the
        // instruction pointer and six arguments.
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&u32::try_from(number).unwrap().to_ne_bytes());
        data[4..8].copy_from_slice(&AUDIT_ARCH.to_ne_bytes());
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

    /// Returns the kernel's action for `number` under all of `programs`.
    ///
    /// That is the strictest of their actions, which is the lowest read as a
    /// signed number.
    fn verdict(programs: &[BpfProgram], number: i64) -> u32 {
        programs
            .iter()
            .map(|p| run_program(p, number))
            .min_by_key(|&action| (action & libc::SECCOMP_RET_ACTION_FULL) as i32)
            .unwrap()
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
        for thread in [Thread::Vmm, Thread::Vcpu] {
            let filters: Vec<BpfProgram> = programs(thread, false)
                .unwrap()
                .into_iter()
                .map(|(_, program)| program)
                .collect();
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

    // `programs` compiles the lists through `serde_json::Value`, which keeps
    // the last of two duplicate keys. Compiling the raw JSON fails on one.
    #[test]
    fn raw_filters_compile() {
        seccompiler::compile_from_json(FILTERS.as_bytes(), ARCH)
            .expect("the raw allowlists should compile");
    }

    /// Both filters must deny by default. A filter that allowed by default
    /// would install, run, and confine nothing.
    #[test]
    fn filters_trap_on_mismatch() {
        let doc: serde_json::Value = serde_json::from_str(FILTERS).unwrap();
        for key in ["vmm", "vcpu"] {
            assert_eq!(
                doc[key]["default_action"], "trap",
                "{key} must trap on a syscall outside its list"
            );
            assert_eq!(doc[key]["filter_action"], "allow");
        }
    }

    /// The vCPU threads service guest MMIO inline, so their list is the one
    /// that matters most and it must stay a strict subset of the VMM's --
    /// if a syscall is added to `vcpu` alone, it was added without anyone
    /// thinking about the thread that actually parses guest data.
    #[test]
    fn vcpu_is_a_subset_of_vmm() {
        let doc: serde_json::Value = serde_json::from_str(FILTERS).unwrap();
        let names = |k: &str| -> std::collections::BTreeSet<String> {
            doc[k]["filter"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["syscall"].as_str().unwrap().to_string())
                .collect()
        };
        let vmm = names("vmm");
        let vcpu = names("vcpu");
        let extra: Vec<_> = vcpu.difference(&vmm).collect();
        assert!(extra.is_empty(), "vcpu allows what vmm does not: {extra:?}");
        assert!(vcpu.len() < vmm.len(), "vcpu should be the tighter filter");
    }

    /// The point of installing after setup is that the process can no longer
    /// reach the filesystem or make a socket. These are the syscalls whose
    /// presence would quietly undo that, so name them rather than trust the
    /// lists to stay short.
    #[test]
    fn neither_filter_can_open_or_connect() {
        let doc: serde_json::Value = serde_json::from_str(FILTERS).unwrap();
        let forbidden = [
            "open",
            "openat",
            "openat2",
            "creat",
            "socket",
            "connect",
            "execve",
            "execveat",
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "memfd_create",
            "seccomp",
            "prctl",
        ];
        for key in ["vmm", "vcpu"] {
            for rule in doc[key]["filter"].as_array().unwrap() {
                let name = rule["syscall"].as_str().unwrap();
                assert!(
                    !forbidden.contains(&name),
                    "{key} allows {name}, which defeats installing the filter after setup"
                );
            }
        }
    }
}

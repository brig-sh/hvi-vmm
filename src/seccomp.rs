//! seccomp-bpf confinement for the Linux backends.
//!
//! Same argument as the macOS half (the `sandbox` module): the virtio backends
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
//! `aarch64-unknown-linux-musl.json` -- musl only -- and drives its devices
//! with epoll and io_uring. hvi is glibc and uses blocking reads on dedicated
//! threads. Their lists therefore carry `open`, `stat`, `io_uring_*` and
//! `epoll_*`, which we never call, and omit `openat`, `statx`, `rseq`,
//! `set_robust_list`, `sched_getaffinity` and `clone3`, without which a glibc
//! Rust binary dies before it reaches `main`. Vendoring them would have been
//! simultaneously too loose and fatally too tight. So the lists are measured
//! from hvi under `strace -f`, and the entries that our trace did *not* show
//! are marked in the JSON as safety nets taken from their production experience
//! -- which is the part of Firecracker's work that actually transfers.
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
//! `vmm` covers the main thread and the host-side I/O threads (the console
//! reader, the agent bridge and its per-connection readers, the tap and
//! gateway readers, and the debug watchdog when it is enabled).
//!
//! Ordering is the interesting part, and it is chosen so that **no filter has
//! to allow `seccomp` itself**:
//!
//! ```text
//! main: acquire everything, spawn the I/O threads ─┐
//!                     each I/O thread installs `vmm` at its start
//! main: spawn the vCPU threads ────────────────────┤
//!                     each vCPU thread installs `vcpu` at its start
//! main: install `vmm` on itself, then join ────────┘
//! ```
//!
//! Nothing is ever spawned *underneath* a filter except the per-connection
//! vsock readers, which the agent bridge creates and which correctly inherit
//! `vmm`. Had the main thread instead installed its filter first and relied on
//! inheritance, every thread wanting a filter of its own would have needed
//! `seccomp` allowed, which hands a compromised backend the ability to install
//! filters. The order above costs nothing and avoids that.
//!
//! Everything acquired during setup is finished by the time any filter is in,
//! so `openat`, `memfd_create`, `ftruncate` and the glibc startup calls are
//! absent from both lists. A compromised virtio backend cannot open a file.
//!
//! # The default action, and diagnosing it
//!
//! A syscall outside the list traps: `SIGSYS`, a dead process, a core file.
//! That is Firecracker's choice too and it is the right one for a security
//! boundary -- `errno` would let a filtered VMM limp on doing something subtly
//! wrong. The cost is that a list which is too tight on some distro is a crash
//! rather than a warning, so there are two ways out: `--no-sandbox` skips the
//! filter entirely, and `HVI_SECCOMP=log` installs the same filters with the
//! mismatch action changed to `log`, which lets the kernel record what would
//! have been killed (`dmesg`, or `auditctl`) while the VMM keeps running.

use std::io;

use seccompiler::{BpfProgram, TargetArch};

/// Which filter a thread installs on itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Thread {
    /// The main thread and the host-side I/O threads.
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
pub const FILTERS: &str = include_str!("../resources/seccomp/x86_64.json");
/// The allowlists, per architecture.
#[cfg(target_arch = "aarch64")]
pub const FILTERS: &str = include_str!("../resources/seccomp/aarch64.json");

/// The architecture seccompiler compiles syscall names for. Getting this wrong
/// would compile a filter against the wrong syscall numbers, which is why it
/// comes from `cfg` rather than from anything at run time.
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
/// The architecture seccompiler compiles syscall names for.
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;

/// Environment variable that swaps the mismatch action for `log`, so a syscall
/// outside the allowlist is recorded by the kernel instead of killing the
/// process. For diagnosing a too-tight list on a distro we have not measured;
/// it is not a supported way to run, and the backend says so.
pub const LOG_ENV: &str = "HVI_SECCOMP";

/// True when [`LOG_ENV`] asks for log-instead-of-trap.
pub fn log_mode() -> bool {
    std::env::var(LOG_ENV).is_ok_and(|v| v == "log")
}

/// Compiles [`FILTERS`] and returns the BPF program for `thread`.
///
/// In log mode the JSON is rewritten before compiling -- `default_action` is
/// the mismatch action in seccompiler's schema -- rather than kept as a second
/// copy of the lists that could drift from the real one.
fn program(thread: Thread) -> io::Result<BpfProgram> {
    let json = if log_mode() {
        let mut doc: serde_json::Value =
            serde_json::from_str(FILTERS).map_err(|e| io::Error::other(format!("filters: {e}")))?;
        let Some(map) = doc.as_object_mut() else {
            return Err(io::Error::other("filters: expected a JSON object"));
        };
        for (_name, filter) in map.iter_mut() {
            if let Some(obj) = filter.as_object_mut() {
                obj.insert(
                    "default_action".to_string(),
                    serde_json::Value::String("log".to_string()),
                );
            }
        }
        serde_json::to_string(&doc).map_err(|e| io::Error::other(format!("filters: {e}")))?
    } else {
        FILTERS.to_string()
    };

    let mut map = seccompiler::compile_from_json(json.as_bytes(), ARCH)
        .map_err(|e| io::Error::other(format!("compiling the {} filter: {e}", thread.key())))?;
    map.remove(thread.key())
        .ok_or_else(|| io::Error::other(format!("no {} filter in the allowlists", thread.key())))
}

/// Installs `thread`'s filter on the calling thread.
///
/// Irreversible, and inherited by anything this thread spawns afterwards. Fails
/// closed: the caller refuses to boot rather than run unfiltered, because a
/// filter that will not compile or install is one nobody has tested.
pub fn install(thread: Thread) -> io::Result<()> {
    let program = program(thread)?;
    seccompiler::apply_filter(&program)
        .map_err(|e| io::Error::other(format!("installing the {} filter: {e}", thread.key())))
}

/// Set once by [`arm`] before any thread is spawned, read by every thread that
/// filters itself. A flag rather than a parameter threaded through seven spawn
/// sites, and it is only ever written once, before the threads that read it
/// exist.
static ARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

thread_local! {
    /// Whether [`install_thread`] has already filtered this thread. See there
    /// for why asking twice has to be harmless.
    static INSTALLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Turns filtering on for the threads spawned after this call, and proves both
/// filters compile first.
///
/// Compiling here is the point: it turns "this distro's kernel headers spell a
/// syscall differently" into a boot error on the main thread, where it can be
/// reported, instead of a `SIGSYS` inside a device thread later on.
pub fn arm() -> io::Result<()> {
    for thread in [Thread::Vmm, Thread::Vcpu] {
        program(thread)?;
    }
    ARMED.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

/// Installs `thread`'s filter if [`arm`] was called, and aborts if it cannot.
///
/// Called at the top of each thread hvi spawns *before* the main thread filters
/// itself. Not called by the per-connection vsock readers: those are spawned by
/// an already-filtered thread and correctly inherit its filter -- calling
/// `seccomp` from under a filter that does not allow it would trap.
///
/// Aborting rather than returning an error is deliberate. There is no
/// meaningful recovery inside a worker thread: continuing would run a
/// guest-facing loop unfiltered, and returning would silently drop a device.
/// [`arm`] has already proved the filter compiles, so reaching this is a kernel
/// refusing the install, which is worth a loud death.
pub fn install_thread(thread: Thread) {
    if !ARMED.load(std::sync::atomic::Ordering::SeqCst) {
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
        eprintln!(
            "[hvi] FATAL: cannot install the {} seccomp filter: {e}",
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

/// One probe: a syscall, which filter to install first, and whether the
/// filtered thread is supposed to survive making it.
struct Probe {
    what: &'static str,
    thread: Thread,
    /// True if the filter is meant to allow this, false if it must trap.
    expect_ok: bool,
    /// Run in the child, *after* the filter is installed. Returning normally
    /// means the syscall was allowed.
    run: fn(),
}

/// The probes. Denials first, so a filter that is accidentally permissive reads
/// as a wall of failures rather than one buried line.
fn probes() -> Vec<Probe> {
    vec![
        Probe {
            what: "open a file (vcpu)",
            thread: Thread::Vcpu,
            expect_ok: false,
            run: || {
                let p = c"/etc/hosts";
                // SAFETY: a valid NUL-terminated path; the result is unused
                // because reaching this line at all is the finding.
                unsafe { libc::open(p.as_ptr(), libc::O_RDONLY) };
            },
        },
        Probe {
            what: "open a file (vmm)",
            thread: Thread::Vmm,
            expect_ok: false,
            run: || {
                let p = c"/etc/hosts";
                // SAFETY: as above.
                unsafe { libc::open(p.as_ptr(), libc::O_RDONLY) };
            },
        },
        Probe {
            what: "create a socket (vcpu)",
            thread: Thread::Vcpu,
            expect_ok: false,
            // SAFETY: socket(2) with constant arguments.
            run: || {
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            },
        },
        Probe {
            what: "create a socket (vmm)",
            thread: Thread::Vmm,
            expect_ok: false,
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
            expect_ok: false,
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
            expect_ok: false,
            // clone is a vmm right (the agent bridge needs one per connection);
            // a vCPU thread servicing guest MMIO has no business making threads.
            run: || {
                let _ = std::thread::spawn(|| 0u8).join();
            },
        },
        Probe {
            what: "unlink a file (vmm)",
            thread: Thread::Vmm,
            expect_ok: false,
            run: || {
                let p = c"/tmp/hvi-seccomp-selftest-should-not-exist";
                // SAFETY: a valid NUL-terminated path.
                unsafe { libc::unlink(p.as_ptr()) };
            },
        },
        Probe {
            what: "change file mode (vmm)",
            thread: Thread::Vmm,
            expect_ok: false,
            run: || {
                let p = c"/tmp";
                // SAFETY: a valid NUL-terminated path.
                unsafe { libc::chmod(p.as_ptr(), 0o777) };
            },
        },
        Probe {
            what: "send a signal to another process (vmm)",
            thread: Thread::Vmm,
            expect_ok: false,
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
            expect_ok: true,
            run: || {
                // SAFETY: fdatasync on fd 1, which we inherited. It is the
                // syscall `File::sync_data` makes on the virtio-blk flush path.
                unsafe { libc::fdatasync(1) };
            },
        },
        Probe {
            what: "flush an inherited descriptor (vmm)",
            thread: Thread::Vmm,
            expect_ok: true,
            run: || {
                // SAFETY: as above.
                unsafe { libc::fdatasync(1) };
            },
        },
        Probe {
            what: "write to an inherited descriptor (vcpu)",
            thread: Thread::Vcpu,
            expect_ok: true,
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
            expect_ok: true,
            run: || {
                let mut b = [0u8; 1];
                // SAFETY: reading zero bytes from fd 0, which we inherited.
                unsafe { libc::read(0, b.as_mut_ptr().cast(), 0) };
            },
        },
        Probe {
            what: "allocate host memory (vcpu)",
            thread: Thread::Vcpu,
            expect_ok: true,
            run: || {
                let v: Vec<u8> = vec![7u8; 4 << 20];
                std::hint::black_box(&v);
            },
        },
        Probe {
            what: "allocate host memory (vmm)",
            thread: Thread::Vmm,
            expect_ok: true,
            run: || {
                let v: Vec<u8> = vec![7u8; 4 << 20];
                std::hint::black_box(&v);
            },
        },
        Probe {
            what: "spawn a thread (vmm)",
            thread: Thread::Vmm,
            expect_ok: true,
            // The agent bridge spawns a reader per accepted connection, after
            // the filter is in.
            run: || {
                let _ = std::thread::spawn(|| 0u8).join();
            },
        },
    ]
}

/// Result of running one probe in a child process.
enum Outcome {
    /// The child ran the syscall and exited normally.
    Allowed,
    /// The child was killed by `SIGSYS`, i.e. the filter trapped the syscall.
    Trapped,
    /// Anything else, with the raw wait status.
    Other(i32),
}

/// Runs one probe in a forked child and reports what happened to it.
///
/// A child per probe is not incidental. The mismatch action is `trap`, so a
/// denied syscall kills the thread that made it -- an in-process probe like the
/// macOS selftest's would end the selftest at the first denial and could not
/// report anything. The parent stays unfiltered so it can fork the next one.
fn run_probe(probe: &Probe) -> io::Result<Outcome> {
    // SAFETY: fork in a process that has not yet installed a filter. The child
    // touches nothing that needs the parent's locks: it installs a filter, runs
    // one closure and _exits without unwinding or flushing.
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
            // WIFSIGNALED / WTERMSIG, spelled out because libc does not export
            // the macros.
            let termsig = status & 0x7f;
            let exited = termsig == 0;
            let exit_code = (status >> 8) & 0xff;
            Ok(if exited && exit_code == 0 {
                Outcome::Allowed
            } else if !exited && termsig == libc::SIGSYS {
                Outcome::Trapped
            } else {
                Outcome::Other(status)
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
        let good = match outcome {
            Outcome::Allowed => probe.expect_ok,
            Outcome::Trapped => !probe.expect_ok,
            Outcome::Other(_) => false,
        };
        if !good {
            bad += 1;
        }
        let verdict = if good { "ok  " } else { "FAIL" };
        let expectation = if probe.expect_ok {
            "allowed"
        } else {
            "trapped"
        };
        let actual = match outcome {
            Outcome::Allowed => "ran".to_string(),
            Outcome::Trapped => "killed by SIGSYS".to_string(),
            Outcome::Other(s) => format!("unexpected wait status {s:#x}"),
        };
        println!(
            "  [{verdict}] want {expectation}  {:<38} {actual}",
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
    /// (`poll` is x86-only, aarch64 spells it `ppoll`), is a startup failure in
    /// production; here it is a test failure on any Linux host.
    #[test]
    fn filters_compile_for_this_arch() {
        for thread in [Thread::Vmm, Thread::Vcpu] {
            let p = program(thread).expect("filter should compile");
            assert!(!p.is_empty(), "{:?} compiled to an empty program", thread);
        }
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

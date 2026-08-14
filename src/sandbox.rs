//! Seatbelt confinement for the macOS backend (NOFireAI/hvi#67).
//!
//! The virtio backends are guest-facing and they run in the same process as the
//! vCPU threads, so a bug in one of them is a bug in something holding the
//! host's full ambient authority. On Linux the answer is a seccomp filter
//! (#65); on macOS there is no equivalent in rust-vmm, so this is ours.
//!
//! What this is *not*: Seatbelt is not a syscall filter. It is a policy engine
//! over named operations on resources -- opening files, creating sockets,
//! looking up Mach services, exec'ing -- evaluated in the kernel by the
//! Sandbox kext. A syscall that touches no policed resource is not filtered by
//! it at all. So this is the macOS counterpart to #65's *goal* (confine the
//! VMM's authority over the host) rather than to its mechanism.
//!
//! # Why a deny-default profile can be this small
//!
//! Everything the VMM normally needs from the host is acquired before the
//! guest runs and is held as a descriptor afterwards:
//!
//! - guest RAM is a POSIX shared-memory object that [`crate::sharedmem`]
//!   unlinks the moment it is mapped, so it is reachable only through the fd;
//! - `hv_vm_create` / `hv_vm_map` have already happened;
//! - the block backing file, the event ledger, the gateway socket, the control
//!   and agent listeners, and stdio are all open by then.
//!
//! Seatbelt polices the acts of *acquiring* those resources, not I/O on
//! descriptors already held, so the profile does not need to name any of them.
//! That is the whole reason [`enter`](crate::sandbox::enter) is called where it
//! is: one line later and the profile would have to grant filesystem and socket
//! rights it can now refuse outright. The one exception is virtio-fs: directory
//! entries and files are opened lazily as the guest requests them. When
//! shares are configured, [`enter_with_shares`] appends one narrow subpath rule
//! for every already-canonical export root. Read-only exports receive
//! `file-read*`; writable exports also receive `file-write*`. The path is
//! required to be UTF-8/control-free and SBPL-escaped before interpolation;
//! every path outside those subtrees remains denied.
//!
//! The vCPU threads are created *after* this point and that is fine:
//! `hv_vcpu_create` and `hv_vcpu_run` on a fresh thread work under a bare
//! `(deny default)` profile. That was measured, not assumed (see the PR for
//! #67); it is also what [`selftest`](crate::sandbox::selftest) re-proves on every CI
//! run.
//!
//! # The deprecation caveat
//!
//! `sandbox_init(3)` has carried a deprecation warning since OS X 10.8. It has
//! nonetheless remained the mechanism essentially everything uses -- Chrome's
//! renderer sandbox, and `sandbox-exec(1)`, which still ships with the OS -- so
//! "deprecated" here means "unsupported but load-bearing" rather than "removed
//! next release". Apple's supported path is App Sandbox entitlements, which is
//! a larger question for hvi because it has to coexist with
//! `com.apple.security.hypervisor`; #67 leaves that as a spike, not this
//! change. The practical consequence of the deprecation is that this profile
//! has to be re-proven per OS release, which is what the CI selftest is for.

use std::ffi::{CStr, CString};
use std::io;
use std::path::{Path, PathBuf};

/// The Seatbelt profile, in SBPL.
///
/// Deny-default with exactly one exception, [documented in the profile
/// text](#the-tty-exception). Each `(allow)` here is a right a compromised
/// virtio backend gets to use, so the bar for adding one is a failing
/// [`selftest`] probe -- something the VMM demonstrably needs after entry --
/// not a suspicion that something might.
///
/// `(version 1)` is the only dialect `sandbox_init` accepts for a literal
/// profile string.
///
/// # The tty exception
///
/// The VMM puts the user's terminal into raw mode for the guest console and
/// restores it on the way out, which happens *after* entry. Seatbelt polices
/// the restoring `tcsetattr` (a write ioctl) though not the `tcgetattr` that
/// reads the settings back, so without this rule every interactive run would
/// exit leaving the user's shell in raw mode -- and the fix people would reach
/// for is `--no-sandbox`, which is a far worse outcome than the rule.
///
/// What the rule costs, measured rather than assumed:
///
/// - it grants nothing new to *reach*. `deny default` still refuses to open
///   `/dev/tty`, so the only descriptors the filter can apply to are the ones
///   the process already inherited.
/// - `TIOCSTI`, the ioctl that would let a confined process inject characters
///   into the terminal's input queue and so run a command in the user's shell,
///   is refused by macOS itself, sandbox or no sandbox. It was checked both
///   ways on macOS 26 while writing this.
///
/// What is left is window sizes, process groups and line discipline on a
/// terminal the process is already sharing -- which it could disturb with
/// escape sequences on stdout regardless.
pub const PROFILE: &str = r#"(version 1)
;; hvi VMM confinement -- see src/sandbox.rs for the reasoning behind each line.
;;
;; Installed after the machine is built and every host resource is already
;; open, and before any guest I/O is serviced. Seatbelt polices acquiring
;; resources rather than using descriptors already held, so the VMM keeps
;; working on what it has and can obtain nothing new.
;;
;; sandbox_init(3) is formally deprecated (10.8) and still the mechanism in
;; practice (Chrome, sandbox-exec). Re-prove this profile per OS release:
;; `hvi sandbox-selftest`.
(deny default)

;; Restoring the user's terminal on exit runs after this point. Opening a tty
;; stays denied, so this only ever applies to a descriptor already inherited,
;; and macOS refuses TIOCSTI on its own account.
(allow file-ioctl (regex #"^/dev/tty"))
"#;

// sandbox_init(3) and its error-buffer companion. Deprecated since 10.8, still
// exported by libSystem; see the module docs.
extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// Installs [`PROFILE`] on the calling process. Irreversible, and inherited by
/// every thread -- including the vCPU threads spawned afterwards.
///
/// Fails closed: the caller is expected to refuse to boot on an error rather
/// than run unconfined, because a profile that will not compile is a profile
/// nobody has tested, and continuing would silently return the process to full
/// ambient authority.
pub fn enter() -> io::Result<()> {
    enter_with_readonly_shares(&[])
}

/// Backwards-compatible single-export entry point.
pub fn enter_with_readonly_share(root: Option<&Path>) -> io::Result<()> {
    enter_with_paths(root.into_iter().map(|path| (path, false)))
}

/// Installs the production profile, granting read-only access to each
/// canonical virtio-fs export. Devices open files lazily as the guest requests
/// them, unlike virtio-blk's already-open descriptor, so one narrow subtree
/// grant per export is required after confinement.
pub fn enter_with_readonly_shares(roots: &[PathBuf]) -> io::Result<()> {
    enter_with_paths(roots.iter().map(|root| (root.as_path(), false)))
}

/// Installs the production profile with independently read-only or writable
/// virtio-fs exports. The boolean is true only for a writable share.
pub fn enter_with_shares(shares: &[(PathBuf, bool)]) -> io::Result<()> {
    enter_with_paths(
        shares
            .iter()
            .map(|(root, writable)| (root.as_path(), *writable)),
    )
}

fn enter_with_paths<'a>(roots: impl IntoIterator<Item = (&'a Path, bool)>) -> io::Result<()> {
    let mut policy = PROFILE.to_owned();
    for (root, writable) in roots {
        let root = root.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "virtio-fs export path is not valid UTF-8 for Seatbelt",
            )
        })?;
        if root.chars().any(char::is_control) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "virtio-fs export path contains a control character",
            ));
        }
        // SBPL strings use the conventional backslash escapes. Escaping both
        // special characters keeps a caller-controlled path data, not policy.
        let escaped = root.replace('\\', "\\\\").replace('"', "\\\"");
        if writable {
            policy.push_str(&format!(
                "\n;; virtio-fs may read and mutate only below this canonical writable export.\n\
                 (allow file-read* file-write* (subpath \"{escaped}\"))\n"
            ));
        } else {
            policy.push_str(&format!(
                "\n;; virtio-fs may acquire files only below this canonical read-only export.\n\
                 (allow file-read* (subpath \"{escaped}\"))\n"
            ));
        }
    }
    let profile =
        CString::new(policy).map_err(|_| io::Error::other("sandbox profile has a NUL"))?;
    let mut err: *mut libc::c_char = std::ptr::null_mut();
    // SAFETY: `profile` is a live NUL-terminated string; `err` is a valid
    // out-pointer that libsandbox fills only on failure, and which we free
    // through its own allocator below.
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut err) };
    if rc == 0 {
        return Ok(());
    }
    let detail = if err.is_null() {
        format!("sandbox_init returned {rc}")
    } else {
        // SAFETY: non-NULL error buffer owned by libsandbox; copied out before
        // it is handed back.
        let msg = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: freeing the buffer sandbox_init allocated, exactly once.
        unsafe { sandbox_free_error(err) };
        msg
    };
    Err(io::Error::other(format!("sandbox_init failed: {detail}")))
}

/// One probe in the [`selftest`]: an operation, and whether the confined
/// process is supposed to still be able to do it.
struct Probe {
    what: &'static str,
    /// True if the profile is meant to *allow* this (a right we still need),
    /// false if it is meant to deny it.
    expect_ok: bool,
    run: fn(&SelftestFixtures) -> io::Result<()>,
}

/// Host resources opened *before* the sandbox goes up, so the selftest can
/// check the other half of the claim: that descriptors acquired in advance keep
/// working afterwards. Without these the test would only prove the process was
/// crippled, not that it was confined.
pub struct SelftestFixtures {
    /// A file opened for writing before entry (stands in for the event ledger
    /// and the block backing file).
    pre_opened: std::fs::File,
    /// A Unix listener bound before entry (stands in for the control socket and
    /// the agent bridge).
    pre_bound: std::os::unix::net::UnixListener,
    /// A shared-memory mapping made before entry (stands in for guest RAM).
    pre_mapped: crate::sharedmem::SharedRam,
    /// A pty opened before entry, standing in for the guest console. The VMM
    /// puts the user's terminal into raw mode before entry and restores it on
    /// the way out, i.e. *after* entry -- so if Seatbelt policed `tcsetattr` on
    /// an already-open descriptor, every sandboxed run would leave the user's
    /// shell in raw mode. A pty rather than fd 0 so the probe is the same under
    /// CI's redirected stdin as it is interactively.
    pre_tty: libc::c_int,
    /// Directory holding the two path-backed fixtures; also the directory the
    /// "create a file" probe aims at, so a failure to deny is unambiguous.
    dir: std::path::PathBuf,
}

/// The probe list. Ordered denials-first so a profile that is accidentally
/// permissive reads as a wall of failures rather than one buried line.
fn probes() -> Vec<Probe> {
    vec![
        Probe {
            what: "open a file for reading (/etc/hosts)",
            expect_ok: false,
            run: |_| std::fs::read(std::path::Path::new("/etc/hosts")).map(|_| ()),
        },
        Probe {
            what: "read our own executable",
            expect_ok: false,
            run: |_| {
                let exe = std::env::current_exe()?;
                std::fs::File::open(exe).map(|_| ())
            },
        },
        Probe {
            what: "create a file next to the fixtures",
            expect_ok: false,
            run: |f| std::fs::write(f.dir.join("escaped"), b"x"),
        },
        Probe {
            what: "list a directory",
            expect_ok: false,
            run: |f| {
                std::fs::read_dir(&f.dir).and_then(|d| {
                    // read_dir itself can succeed lazily; force the open.
                    for e in d {
                        e?;
                    }
                    Ok(())
                })
            },
        },
        Probe {
            what: "open a new POSIX shared-memory object",
            expect_ok: false,
            run: |_| crate::sharedmem::SharedRam::new(0x4000).map(|_| ()),
        },
        Probe {
            // The companion to the profile's one allow rule: the tty ioctl is
            // only defensible while the process cannot get hold of a tty it was
            // not already given. If this probe ever passes, the rule stops
            // being scoped to inherited descriptors.
            what: "open a terminal by path (/dev/tty)",
            expect_ok: false,
            run: |_| {
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/tty")
                    .map(|_| ())
            },
        },
        Probe {
            what: "inject input into a tty opened before entry (TIOCSTI)",
            expect_ok: false,
            run: |f| {
                // Denied by macOS itself rather than by the profile, but it is
                // the escape the tty ioctl rule would otherwise hand over, so
                // it is worth failing loudly on the OS release where that
                // changes.
                let c: libc::c_char = b'x' as libc::c_char;
                // SAFETY: `pre_tty` is a live descriptor; TIOCSTI takes a
                // pointer to a single character.
                let rc = unsafe { libc::ioctl(f.pre_tty, libc::TIOCSTI, &c) };
                if rc == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            },
        },
        Probe {
            what: "connect a Unix socket",
            expect_ok: false,
            run: |f| {
                std::os::unix::net::UnixStream::connect(f.dir.join("nothing-here")).map(|_| ())
            },
        },
        Probe {
            what: "open an outbound TCP socket",
            expect_ok: false,
            run: |_| {
                // Bind, not connect: a connect could fail on the network rather
                // than on the policy and read as a pass for the wrong reason.
                std::net::TcpListener::bind("127.0.0.1:0").map(|_| ())
            },
        },
        Probe {
            what: "execute another program",
            expect_ok: false,
            run: |_| {
                std::process::Command::new("/usr/bin/true")
                    .status()
                    .map(|_| ())
            },
        },
        Probe {
            what: "fork a child",
            expect_ok: false,
            run: |_| {
                // SAFETY: fork in a test binary; the child exits immediately.
                let pid = unsafe { libc::fork() };
                match pid {
                    0 => unsafe { libc::_exit(0) },
                    -1 => Err(io::Error::last_os_error()),
                    _ => {
                        let mut status = 0;
                        // SAFETY: reaping a child we just created.
                        unsafe { libc::waitpid(pid, &mut status, 0) };
                        Ok(())
                    }
                }
            },
        },
        // The other half: rights the VMM still needs, held as descriptors.
        Probe {
            what: "write to a file opened before entry",
            expect_ok: true,
            run: |f| {
                use std::io::Write;
                (&f.pre_opened).write_all(b"still writable\n")
            },
        },
        Probe {
            what: "accept on a listener bound before entry",
            expect_ok: true,
            run: |f| {
                // Prove the listener is live without needing a peer that could
                // itself be blocked: a non-blocking accept on an idle listener
                // returns WouldBlock, which only happens if the socket works.
                f.pre_bound.set_nonblocking(true)?;
                match f.pre_bound.accept() {
                    Ok(_) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
                    Err(e) => Err(e),
                }
            },
        },
        Probe {
            // The vsock bridge clones every connection it accepts, so this
            // runs once per `exec`-style session -- after entry, on a
            // descriptor obtained after entry. Deriving a descriptor from one
            // we already hold has to keep working for that to be true.
            what: "duplicate a descriptor opened before entry",
            expect_ok: true,
            run: |f| f.pre_opened.try_clone().map(|_| ()),
        },
        Probe {
            what: "read and write guest RAM mapped before entry",
            expect_ok: true,
            run: |f| {
                // SAFETY: the mapping is live for `len` bytes and owned by the
                // fixture; nothing else touches it during the selftest.
                unsafe {
                    let p = f.pre_mapped.as_ptr();
                    std::ptr::write_volatile(p, 0xa5);
                    if std::ptr::read_volatile(p) != 0xa5 {
                        return Err(io::Error::other("guest RAM readback mismatch"));
                    }
                }
                Ok(())
            },
        },
        Probe {
            what: "restore terminal settings on a tty opened before entry",
            expect_ok: true,
            run: |f| {
                // SAFETY: `pre_tty` is a live pty descriptor owned by the
                // fixture; `termios` is POD and both calls are checked.
                unsafe {
                    let mut t: libc::termios = std::mem::zeroed();
                    if libc::tcgetattr(f.pre_tty, &mut t) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    let mut raw = t;
                    libc::cfmakeraw(&mut raw);
                    if libc::tcsetattr(f.pre_tty, libc::TCSANOW, &raw) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // The restore is the operation that matters: it is what
                    // runs after entry when the VMM drops its `RawTerm`.
                    if libc::tcsetattr(f.pre_tty, libc::TCSANOW, &t) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            },
        },
        Probe {
            what: "allocate host memory",
            expect_ok: true,
            run: |_| {
                // The virtio paths allocate per request; a profile that broke
                // this would break the VMM in a way no denial log would explain.
                let v: Vec<u8> = vec![0u8; 4 << 20];
                if v.len() != 4 << 20 {
                    return Err(io::Error::other("allocation short"));
                }
                Ok(())
            },
        },
        Probe {
            what: "spawn a thread",
            expect_ok: true,
            run: |_| {
                std::thread::spawn(|| 0u8)
                    .join()
                    .map(|_| ())
                    .map_err(|_| io::Error::other("thread join failed"))
            },
        },
    ]
}

/// Opens a pty and returns the slave descriptor, for the terminal probe. The
/// master is deliberately leaked: it has to stay open for the slave to remain a
/// live terminal, and the selftest process is about to exit anyway.
fn open_pty() -> io::Result<libc::c_int> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: both out-params are valid; the three optional arguments are NULL,
    // which openpty documents as "use the defaults".
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(slave)
}

/// Enters the sandbox and proves the profile, in-process, with no hypervisor
/// involved: every operation the VMM must keep and every one it must lose.
///
/// This is the negative test for the confinement. It has to run in a process
/// that has *actually installed the production profile* -- checking the string
/// would only prove the string -- and it has to run on every macOS version we
/// claim to support, because Seatbelt's implicit behaviour is not contractual
/// across releases. Hence a subcommand rather than a `#[test]`: `cargo test`
/// runs test cases in threads of one process, and entry is irreversible and
/// process-wide, so a sandboxing test would confine every other test with it.
///
/// Returns the number of probes that did not behave as the profile says they
/// should.
pub fn selftest() -> io::Result<usize> {
    // A directory under TMPDIR, created *before* entry -- afterwards we could
    // not make one.
    let dir = std::env::temp_dir().join(format!("hvi-sandbox-selftest-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let fixtures = SelftestFixtures {
        pre_opened: std::fs::File::create(dir.join("ledger"))?,
        pre_bound: {
            let path = dir.join("control.sock");
            let _ = std::fs::remove_file(&path);
            std::os::unix::net::UnixListener::bind(&path)?
        },
        pre_mapped: crate::sharedmem::SharedRam::new(0x4000)?,
        pre_tty: open_pty()?,
        dir: dir.clone(),
    };

    println!("hvi sandbox selftest: installing the production profile");
    enter()?;
    println!("hvi sandbox selftest: sandbox is up\n");

    let mut bad = 0usize;
    for probe in probes() {
        let outcome = (probe.run)(&fixtures);
        let got_ok = outcome.is_ok();
        let good = got_ok == probe.expect_ok;
        if !good {
            bad += 1;
        }
        let verdict = if good { "ok  " } else { "FAIL" };
        let expectation = if probe.expect_ok {
            "allowed"
        } else {
            "denied "
        };
        let actual = match &outcome {
            Ok(()) => "succeeded".to_string(),
            Err(e) => format!("refused ({})", e.kind()),
        };
        println!(
            "  [{verdict}] want {expectation}  {:<48} {actual}",
            probe.what
        );
    }

    // Cleanup is the caller's problem: we can no longer unlink anything. The
    // fixtures live under TMPDIR and are a socket and two small files.
    println!(
        "\nfixtures left in {} (the sandbox forbids removing them)",
        dir.display()
    );
    Ok(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The profile must stay deny-default. A regression that dropped this line
    /// would leave a profile that compiles, installs, and confines nothing.
    /// The selftest would catch it too, but only where a sandbox can actually
    /// be installed; this is the cheap check that runs under plain `cargo
    /// test` on any macOS host.
    #[test]
    fn profile_is_deny_default() {
        assert!(PROFILE.starts_with("(version 1)"));
        assert!(
            PROFILE.lines().any(|l| l.trim() == "(deny default)"),
            "the profile must deny by default"
        );
    }

    /// Nothing is interpolated into the profile, so no caller-controlled string
    /// can reach the policy language. If an `(allow)` is ever added it must
    /// still be a literal: this pins that the profile has no format holes and
    /// no unbalanced parens for one to hide in.
    #[test]
    fn profile_is_static_and_balanced() {
        assert!(
            !PROFILE.contains('{'),
            "the profile must not be a format string"
        );
        let mut depth = 0i32;
        let mut in_comment = false;
        for c in PROFILE.chars() {
            match c {
                ';' => in_comment = true,
                '\n' => in_comment = false,
                '(' if !in_comment => depth += 1,
                ')' if !in_comment => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "unbalanced ')' in the profile");
        }
        assert_eq!(depth, 0, "unbalanced '(' in the profile");
    }

    /// Every allow rule is a standing grant to a guest-facing process, so the
    /// set is pinned exactly: adding one has to be an edit here as well, which
    /// is the point at which somebody has to justify it in review.
    #[test]
    fn profile_grants_only_the_tty_ioctl() {
        let allows: Vec<&str> = PROFILE
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with(';'))
            .filter(|l| l.contains("(allow"))
            .collect();
        assert_eq!(
            allows,
            vec![r##"(allow file-ioctl (regex #"^/dev/tty"))"##],
            "the profile's allow set changed; see the tty exception in src/sandbox.rs"
        );
    }

    /// The tty rule is only defensible because the process cannot open a tty in
    /// the first place -- it applies to inherited descriptors and nothing else.
    /// A `file-read*`/`file-write*` rule for a tty path landing here later
    /// would quietly turn it into something much broader, so refuse the
    /// combination in the cheap test rather than in a post-mortem.
    #[test]
    fn profile_never_grants_opening_a_tty() {
        for line in PROFILE.lines().map(str::trim) {
            if line.starts_with(';') || !line.contains("(allow") {
                continue;
            }
            assert!(
                !(line.contains("file-read") || line.contains("file-write")),
                "the profile grants filesystem access ({line}); the tty ioctl rule assumes it \
                 cannot open anything"
            );
        }
    }
}

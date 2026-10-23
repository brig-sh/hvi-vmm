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

//! A guest run under the `hvi` binary.
//!
//! Each run writes its files to a directory of its own inside the test's
//! directory under [`Suite::artifacts`]: the command line, the console, hvi's
//! stderr and the event ledger. The test's directory is emptied the first time
//! the test uses it, so it holds only the files of that attempt.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hvi_e2e_protocol::{Request, Response};

use crate::agent::{Agent, GuestOutput};
use crate::daemon::signal_process;
use crate::export::FsExport;
use crate::ledger::Ledger;
use crate::net::Gateway;
use crate::sockets::SocketDir;
use crate::stream::{tail, Stream};
use crate::suite::Suite;

/// The name of the agent socket in a run's socket directory.
const AGENT_SOCKET: &str = "agent.sock";

/// How long a guest may take to boot until its agent answers.
const BOOT_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a run has to end once its guest is asked to stop.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the agent of a booted guest may take to answer a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a script run with [`Vm::sh`] may take.
const SH_TIMEOUT: Duration = Duration::from_secs(60);

/// How many lines of each stream a failure message quotes.
const TAIL_LINES: usize = 30;

/// The kernel command line every guest boots with.
///
/// hvi adds the ttyS0 console itself.
#[cfg(target_arch = "x86_64")]
const CMDLINE: &str = "panic=-1";
/// The kernel command line every guest boots with.
#[cfg(target_arch = "aarch64")]
const CMDLINE: &str = "earlycon console=ttyAMA0 panic=-1";

/// How a run is expected to stop, for [`RunOutput::assert_stopped`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// A power-off by the guest.
    SystemOff,
    /// A reset by the guest.
    SystemReset,
    /// A stop hvi made on receiving this signal.
    Requested(libc::c_int),
    /// A failure after the run started, with an error that contains this text.
    Failed(&'static str),
}

/// The options a run starts with.
#[derive(Debug)]
#[must_use]
pub struct VmBuilder {
    /// The number of vCPUs.
    cpus: u32,
    /// The guest's RAM in MiB.
    mem_mib: u32,
    /// Arguments appended to the kernel command line.
    cmdline: Vec<String>,
    /// Arguments appended to the `hvi boot` command line.
    args: Vec<OsString>,
    /// Variables set in hvi's environment.
    envs: Vec<(OsString, OsString)>,
    /// Whether hvi runs confined, as it does by default.
    confined: bool,
    /// The kernel, when not the suite's.
    kernel: Option<PathBuf>,
    /// The initramfs, when not the suite's.
    initramfs: Option<PathBuf>,
    /// Whether hvi's stdout is left unread.
    console_unread: bool,
}

impl VmBuilder {
    /// Leaves hvi's stdout, which carries the console, unread.
    pub fn console_unread(mut self) -> Self {
        self.console_unread = true;
        self
    }

    /// Boots `kernel` instead of the suite's kernel.
    pub fn kernel(mut self, kernel: impl Into<PathBuf>) -> Self {
        self.kernel = Some(kernel.into());
        self
    }

    /// Boots with `initramfs` instead of the suite's initramfs.
    pub fn initramfs(mut self, initramfs: impl Into<PathBuf>) -> Self {
        self.initramfs = Some(initramfs.into());
        self
    }

    /// Attaches the network through hvi's built-in stub stack.
    pub fn net_stub(self) -> Self {
        self.arg("--net-stub")
    }

    /// Attaches the network through `gateway`.
    pub fn net_gateway(self, gateway: &Gateway) -> Self {
        self.arg("--net-gateway").arg(gateway.socket())
    }

    /// Attaches the network to the tap device `tap`.
    pub fn net_tap(self, tap: &str) -> Self {
        self.arg("--net-tap").arg(tap)
    }

    /// Sets the MAC address of the guest's NIC.
    pub fn net_mac(self, mac: &str) -> Self {
        self.arg("--net-mac").arg(mac)
    }

    /// Attaches `export` to the guest.
    pub fn fs(mut self, export: &FsExport) -> Self {
        self.args.extend(export.args());
        self
    }

    /// Attaches a virtio-blk disk, given as `--disk` takes it: a path, or
    /// `path=<path>` with options.
    pub fn disk(mut self, spec: impl Into<OsString>) -> Self {
        self.args.push("--disk".into());
        self.args.push(spec.into());
        self
    }

    /// Sets the number of vCPUs, 1 by default.
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = cpus;
        self
    }

    /// Sets the guest's RAM in MiB, 512 by default.
    pub fn mem_mib(mut self, mem_mib: u32) -> Self {
        self.mem_mib = mem_mib;
        self
    }

    /// Appends `arg` to the kernel command line.
    pub fn cmdline_arg(mut self, arg: &str) -> Self {
        self.cmdline.push(arg.to_string());
        self
    }

    /// Appends `arg` to the `hvi boot` command line.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Sets the environment variable `key` to `value` for hvi.
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    /// Runs hvi with `--no-sandbox`.
    pub fn no_sandbox(mut self) -> Self {
        self.confined = false;
        self.args.push("--no-sandbox".into());
        self
    }

    /// Runs hvi with `HVI_SECCOMP=log`, so the run is not confined.
    #[cfg(target_os = "linux")]
    pub fn seccomp_log(mut self) -> Self {
        self.confined = false;
        self.envs.push(("HVI_SECCOMP".into(), "log".into()));
        self
    }

    /// Starts hvi and returns at once, without waiting for the guest.
    ///
    /// # Panics
    ///
    /// Panics if the run's directory or its files cannot be created, or hvi
    /// cannot be started.
    pub fn spawn(self) -> Vm {
        let suite = Suite::get();
        let dir = run_dir(suite);
        let sockets = SocketDir::new();
        let mut cmdline = CMDLINE.to_string();
        for arg in &self.cmdline {
            cmdline.push(' ');
            cmdline.push_str(arg);
        }
        let mut command = Command::new(&suite.hvi);
        // An `HVI_SECCOMP` set on the host would change the confinement every
        // run reports, so only `seccomp_log` sets it.
        command
            .env_remove("HVI_SECCOMP")
            .arg("boot")
            .arg("--kernel")
            .arg(self.kernel.as_ref().unwrap_or(&suite.kernel))
            .arg("--initramfs")
            .arg(self.initramfs.as_ref().unwrap_or(&suite.initramfs))
            .arg("--mem-mib")
            .arg(self.mem_mib.to_string())
            .arg("--cpus")
            .arg(self.cpus.to_string())
            .arg("--cmdline")
            .arg(&cmdline)
            .arg("--events")
            .arg(dir.join("ledger.ndjson"))
            .arg("--agent-sock")
            .arg(sockets.path().join(AGENT_SOCKET))
            .args(&self.args)
            .envs(self.envs.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // hvi does not stop on a signal it starts out ignoring. It can inherit
        // SIGHUP ignored from `nohup` and SIGINT ignored from a shell's
        // background job, so each stop signal gets its default action back.
        // SAFETY: the closure runs in the child between fork and exec, and
        // signal(2) is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
                    if libc::signal(signal, libc::SIG_DFL) == libc::SIG_ERR {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let line = format!("{command:?}\n");
        let command_file = dir.join("command.txt");
        std::fs::write(&command_file, line)
            .unwrap_or_else(|e| panic!("writing {}: {e}", command_file.display()));
        let mut child = command
            .spawn()
            .unwrap_or_else(|e| panic!("starting {}: {e}", suite.hvi.display()));
        let stdout = child.stdout.take().expect("stdout should be piped");
        let (console, unread) = if self.console_unread {
            let empty = Stream::drain(std::io::empty(), &dir.join("console.log"));
            (empty, Some(stdout))
        } else {
            (Stream::drain(stdout, &dir.join("console.log")), None)
        };
        let stderr = Stream::drain(
            child.stderr.take().expect("stderr should be piped"),
            &dir.join("stderr.log"),
        );
        Vm {
            stdin: child.stdin.take(),
            child: Some(child),
            console,
            unread,
            stderr,
            dir,
            sockets,
            confined: self.confined,
        }
    }

    /// Starts hvi and waits until the guest's agent answers.
    ///
    /// # Panics
    ///
    /// Panics if hvi exits first, or, after killing hvi, if the agent does not
    /// answer within the boot timeout.
    pub fn boot(self) -> Vm {
        let mut vm = self.spawn();
        vm.wait_for_guest();
        vm
    }
}

/// A running guest.
///
/// A `Vm` must be ended with [`Vm::power_off`], [`Vm::reset`], [`Vm::wait`] or
/// [`Vm::kill`]. Dropping one that is still running kills hvi, and panics
/// unless the thread is already panicking, since nothing checked how that run
/// ended.
pub struct Vm {
    /// The hvi process, until the run ends.
    child: Option<Child>,
    /// hvi's stdin.
    stdin: Option<ChildStdin>,
    /// hvi's stdout, which carries the guest's console, or an empty stream when
    /// the run leaves the console unread.
    console: Stream,
    /// hvi's stdout, held open and never read, when the run leaves the console
    /// unread.
    unread: Option<ChildStdout>,
    /// hvi's stderr, which carries hvi's own lines.
    stderr: Stream,
    /// The directory the run writes its files to.
    dir: PathBuf,
    /// The directory holding the run's Unix sockets.
    sockets: SocketDir,
    /// Whether hvi runs confined.
    confined: bool,
}

impl Vm {
    /// Returns a builder for a run with one vCPU and 512 MiB.
    pub fn builder() -> VmBuilder {
        VmBuilder {
            cpus: 1,
            mem_mib: 512,
            cmdline: Vec::new(),
            args: Vec::new(),
            envs: Vec::new(),
            confined: true,
            kernel: None,
            initramfs: None,
            console_unread: false,
        }
    }

    /// Returns the path of the agent socket.
    pub fn agent_socket(&self) -> PathBuf {
        self.sockets.path().join(AGENT_SOCKET)
    }

    /// Returns hvi's process id.
    fn pid(&self) -> u32 {
        self.child
            .as_ref()
            .expect("the run should not have ended")
            .id()
    }

    /// Returns a new connection to the guest's agent.
    ///
    /// # Panics
    ///
    /// Panics if the agent does not answer.
    pub fn connect_agent(&self) -> Agent {
        let timeout = Suite::get().timeout(CONNECT_TIMEOUT);
        Agent::connect(&self.agent_socket(), timeout)
            .unwrap_or_else(|e| panic!("connecting to the agent: {e}"))
    }

    /// Runs `script` with the guest's `sh -c` and returns how it ended.
    ///
    /// # Panics
    ///
    /// Panics if the agent cannot run it.
    pub fn sh(&self, script: &str) -> GuestOutput {
        let timeout = Suite::get().timeout(SH_TIMEOUT);
        self.connect_agent()
            .run("sh", &["-c", script], timeout)
            .unwrap_or_else(|e| panic!("running {script:?} in the guest: {e}"))
    }

    /// Returns the line `sha256sum` prints for the guest file `path`, once it
    /// is `len` bytes long.
    ///
    /// A file that does not reach `len` bytes within ten seconds, scaled for
    /// this host, is hashed as it is then.
    ///
    /// # Panics
    ///
    /// Panics if the agent cannot run the check or `sha256sum` fails.
    pub fn file_sha256(&self, path: &str, len: usize) -> String {
        let tries = Suite::get().timeout(Duration::from_secs(10)).as_millis() / 100;
        let script = format!(
            "for i in $(seq {tries}); do \
               [ \"$(stat -c %s {path} 2>/dev/null)\" = {len} ] && break; sleep 0.1; \
             done; sha256sum {path}"
        );
        self.sh(&script).assert_success().stdout
    }

    /// Returns the guest's console output so far.
    pub fn console(&self) -> String {
        self.console.text()
    }

    /// Waits until the console shows `needle`.
    ///
    /// # Panics
    ///
    /// Panics if it does not within `timeout`, scaled for this host.
    #[track_caller]
    pub fn wait_for_console(&self, needle: &str, timeout: Duration) {
        let timeout = Suite::get().timeout(timeout);
        assert!(
            self.console.wait_for(needle, timeout),
            "the console did not show {needle:?} within {timeout:?}\nrun files: {}\nconsole:\n{}",
            self.dir.display(),
            tail(&self.console.text(), TAIL_LINES)
        );
    }

    /// Returns whether hvi's stderr shows `needle` within `timeout`, scaled for
    /// this host, or `false` once hvi closes it without showing `needle`.
    pub fn stderr_shows(&self, needle: &str, timeout: Duration) -> bool {
        self.stderr.wait_for(needle, Suite::get().timeout(timeout))
    }

    /// Waits until the guest's agent answers, for a run started with
    /// [`VmBuilder::spawn`].
    ///
    /// # Panics
    ///
    /// Panics if hvi exits first, or, after killing hvi, if the agent does not
    /// answer within the boot timeout.
    pub fn wait_for_guest(&mut self) {
        let timeout = Suite::get().timeout(BOOT_TIMEOUT);
        let deadline = Instant::now() + timeout;
        // Each attempt is short, so a run that has already ended is reported at
        // once rather than after the whole timeout.
        loop {
            let child = self.child.as_mut().expect("the run should not have ended");
            if let Ok(Some(status)) = child.try_wait() {
                let ended = self.ended(status);
                panic!("hvi exited before the guest answered\n{}", ended.context());
            }
            let err = match Agent::connect(&self.agent_socket(), Duration::from_secs(1)) {
                Ok(_) => return,
                Err(e) => e,
            };
            if Instant::now() >= deadline {
                let ended = self.kill_now();
                panic!(
                    "the guest did not answer within {timeout:?}: {err}\n{}",
                    ended.context()
                );
            }
        }
    }

    /// Writes `bytes` to hvi's stdin, which hvi forwards to the console.
    ///
    /// # Panics
    ///
    /// Panics if the write fails.
    pub fn write_console(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin should be open");
        stdin
            .write_all(bytes)
            .and_then(|()| stdin.flush())
            .unwrap_or_else(|e| panic!("writing to hvi's stdin: {e}"));
    }

    /// Sends `signal` to hvi.
    ///
    /// # Panics
    ///
    /// Panics if the signal cannot be sent.
    pub fn signal(&self, signal: libc::c_int) {
        signal_process(self.pid(), signal, "hvi");
    }

    /// Powers the guest off through its agent and returns the ended run,
    /// checked by [`RunOutput::assert_stopped`] for [`Stop::SystemOff`].
    ///
    /// # Panics
    ///
    /// Panics with the run's files if the run did not end as a power-off.
    #[track_caller]
    pub fn power_off(self) -> RunOutput {
        let ended = self.stop_with(&Request::PowerOff);
        ended.assert_stopped(Stop::SystemOff);
        ended
    }

    /// Resets the guest through its agent and returns the ended run, checked by
    /// [`RunOutput::assert_stopped`] for [`Stop::SystemReset`].
    ///
    /// # Panics
    ///
    /// Panics with the run's files if the run did not end as a reset.
    #[track_caller]
    pub fn reset(self) -> RunOutput {
        let ended = self.stop_with(&Request::Reset);
        ended.assert_stopped(Stop::SystemReset);
        ended
    }

    /// Sends `request` to the agent and waits for the run to end.
    ///
    /// A guest that already stopped takes no connection, and one may stop
    /// before the response reaches the host. Neither is an error here, since
    /// the wait reports how the run ended.
    fn stop_with(self, request: &Request) -> RunOutput {
        let timeout = Suite::get().timeout(CONNECT_TIMEOUT);
        let sent = Agent::connect(&self.agent_socket(), timeout)
            .and_then(|mut agent| agent.request(request));
        if let Ok(response) = sent {
            assert_eq!(
                response,
                Response::Accepted,
                "the agent refused {request:?}"
            );
        }
        self.wait(STOP_TIMEOUT)
    }

    /// Waits for the run to end on its own.
    ///
    /// # Panics
    ///
    /// Panics, after killing hvi, if the run does not end within `timeout`,
    /// scaled for this host.
    pub fn wait(mut self, timeout: Duration) -> RunOutput {
        let timeout = Suite::get().timeout(timeout);
        let deadline = Instant::now() + timeout;
        let child = self.child.as_mut().expect("the run should not have ended");
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return self.ended(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let ended = self.kill_now();
                    panic!(
                        "the run did not end within {timeout:?}\n{}",
                        ended.context()
                    );
                }
                Err(e) => panic!("waiting for hvi: {e}"),
            }
        }
    }

    /// Kills hvi with `SIGKILL` and returns the ended run.
    pub fn kill(mut self) -> RunOutput {
        self.kill_now()
    }

    /// Kills hvi and collects what the run left.
    fn kill_now(&mut self) -> RunOutput {
        let child = self.child.as_mut().expect("the run should not have ended");
        let _ = child.kill();
        let status = child
            .wait()
            .unwrap_or_else(|e| panic!("waiting for hvi: {e}"));
        self.ended(status)
    }

    /// Collects what the run left, once hvi has exited with `status`.
    fn ended(&mut self, status: ExitStatus) -> RunOutput {
        self.child = None;
        self.stdin = None;
        self.unread = None;
        self.console.join();
        self.stderr.join();
        RunOutput {
            status,
            console: self.console.text(),
            stderr: self.stderr.text(),
            ledger: Ledger::read(&self.dir.join("ledger.ndjson")),
            dir: self.dir.clone(),
            confined: self.confined,
        }
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        if self.child.is_none() {
            return;
        }
        let ended = self.kill_now();
        if !std::thread::panicking() {
            panic!(
                "a Vm was dropped while hvi was running; end it with power_off, reset, \
                 wait or kill\n{}",
                ended.context()
            );
        }
    }
}

/// A run that has ended, with everything it left.
#[derive(Debug)]
pub struct RunOutput {
    /// How hvi exited.
    pub status: ExitStatus,
    /// The guest's console output.
    pub console: String,
    /// hvi's stderr.
    pub stderr: String,
    /// The event ledger.
    pub ledger: Ledger,
    /// The directory the run wrote its files to.
    dir: PathBuf,
    /// Whether hvi ran confined.
    confined: bool,
}

impl RunOutput {
    /// Checks that the run stopped as `stop` describes.
    ///
    /// hvi must exit with the status `stop` gives and not panic. A stop prints
    /// its `guest stopped:` line, and a failure prints its error instead. The
    /// ledger's `vmm.start` must report the confinement hvi was started with,
    /// its `vmm.stop` must give the reason and any signal or error that `stop`
    /// names, and no record may be dropped.
    ///
    /// # Panics
    ///
    /// Panics with the run's files when any of those does not hold.
    #[track_caller]
    pub fn assert_stopped(&self, stop: Stop) -> &RunOutput {
        let (exited_as_expected, line, reason) = match stop {
            Stop::SystemOff => (self.status.code() == Some(0), "SystemOff", "system_off"),
            Stop::SystemReset => (self.status.code() == Some(0), "SystemReset", "system_reset"),
            Stop::Requested(signal) => (
                self.status.signal() == Some(signal),
                "Requested",
                "requested",
            ),
            Stop::Failed(_) => (self.status.code() == Some(1), "", "failed"),
        };
        let context = self.context();
        assert!(
            exited_as_expected,
            "hvi ended with {}, not as {stop:?}\n{context}",
            self.status
        );
        if let Stop::Failed(error) = stop {
            assert!(
                self.stderr.contains(error) && !self.stderr.contains("guest stopped:"),
                "hvi did not fail with {error:?}\n{context}"
            );
        } else {
            assert!(
                self.stderr.contains(&format!("guest stopped: {line}")),
                "hvi did not report `guest stopped: {line}`\n{context}"
            );
        }
        assert!(!self.stderr.contains("panicked"), "hvi panicked\n{context}");
        let start = self
            .ledger
            .start_record()
            .unwrap_or_else(|| panic!("the ledger has no vmm.start\n{context}"));
        assert_eq!(
            start["confined"], self.confined,
            "vmm.start says confined is {}\n{context}",
            start["confined"]
        );
        let stopped = self
            .ledger
            .stop_record()
            .unwrap_or_else(|| panic!("the ledger has no vmm.stop\n{context}"));
        assert_eq!(
            stopped["reason"], reason,
            "vmm.stop gives the wrong reason\n{context}"
        );
        if let Stop::Requested(signal) = stop {
            assert_eq!(
                stopped["signal"],
                signal_name(signal),
                "vmm.stop names the wrong signal\n{context}"
            );
        }
        if let Stop::Failed(error) = stop {
            assert!(
                stopped["error"]
                    .as_str()
                    .is_some_and(|text| text.contains(error)),
                "vmm.stop gives the wrong error\n{context}"
            );
        }
        let dropped = self.ledger.records_from("vmm.dropped").count();
        assert!(
            dropped == 0 && stopped.get("dropped").is_none(),
            "the ledger dropped records\n{context}"
        );
        self
    }

    /// Checks that hvi refused the run before any vCPU started, with exit
    /// status 1 and a line on stderr containing `message`.
    ///
    /// A guest that crashes also ends the run with status 1 and an `hvi:` line,
    /// so the ledger must have no `vmm.start` for the run to count as refused.
    ///
    /// # Panics
    ///
    /// Panics with the run's files when it did not.
    #[track_caller]
    pub fn assert_refused(&self, message: &str) -> &RunOutput {
        let context = self.context();
        assert_eq!(
            self.status.code(),
            Some(1),
            "hvi ended with {}, not 1\n{context}",
            self.status
        );
        assert!(
            self.stderr.contains(message),
            "hvi's stderr does not contain {message:?}\n{context}"
        );
        assert!(!self.stderr.contains("panicked"), "hvi panicked\n{context}");
        assert!(
            self.ledger.start_record().is_none(),
            "the run started before it failed\n{context}"
        );
        self
    }

    /// Returns where the run's files are and the end of each stream, for a
    /// failure message.
    pub fn context(&self) -> String {
        format!(
            "run files: {}\nstderr:\n{}\nconsole:\n{}",
            self.dir.display(),
            tail(&self.stderr, TAIL_LINES),
            tail(&self.console, TAIL_LINES)
        )
    }
}

/// Returns the name hvi's ledger gives `signal`, or a placeholder for a signal
/// hvi does not stop on.
fn signal_name(signal: libc::c_int) -> &'static str {
    match signal {
        libc::SIGTERM => "SIGTERM",
        libc::SIGINT => "SIGINT",
        libc::SIGHUP => "SIGHUP",
        _ => "an unexpected signal",
    }
}

/// Returns the calling test's directory, emptied on the test's first call.
///
/// The path is the test's nextest binary and name under the artifacts
/// directory, with `.attempt<N>` after the name for a retry, so one directory
/// holds every test's files. Outside nextest, the name of the calling thread
/// names the test, since cargo test runs each test on a thread named after it.
fn test_dir(suite: &Suite) -> PathBuf {
    static DIRS: Mutex<BTreeMap<String, PathBuf>> = Mutex::new(BTreeMap::new());
    let test = std::env::var("NEXTEST_TEST_NAME")
        .ok()
        .or_else(|| std::thread::current().name().map(String::from))
        .unwrap_or_else(|| "unnamed".into());
    let mut dirs = DIRS.lock().unwrap_or_else(|e| e.into_inner());
    dirs.entry(test)
        .or_insert_with_key(|test| {
            let binary = std::env::var("NEXTEST_BINARY_ID").unwrap_or_else(|_| "cargo-test".into());
            // A retry writes beside the attempt that failed, which keeps its
            // files.
            let attempt = match std::env::var("NEXTEST_ATTEMPT").as_deref() {
                Ok("1") | Err(_) => String::new(),
                Ok(n) => format!(".attempt{n}"),
            };
            let dir = suite
                .artifacts
                .join("tests")
                .join(binary.replace("::", "/"))
                .join(test.replace("::", "/") + &attempt);
            let _ = std::fs::remove_dir_all(&dir);
            dir
        })
        .clone()
}

/// Returns a new, empty directory for the next run of the calling test.
fn run_dir(suite: &Suite) -> PathBuf {
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let run = RUNS.fetch_add(1, Ordering::Relaxed);
    let dir = test_dir(suite).join(format!("vm{run}"));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
    dir
}

/// Returns a directory for the files the calling test makes for its runs, such
/// as disk images, beside the runs' own directories.
///
/// # Panics
///
/// Panics if the directory cannot be created.
pub fn scratch_dir() -> PathBuf {
    let dir = test_dir(Suite::get()).join("files");
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
    dir
}

/// Returns the path of a new sparse file of `len` bytes named `name` in
/// [`scratch_dir`].
///
/// # Panics
///
/// Panics if the file cannot be created.
pub fn sparse_file(name: &str, len: u64) -> PathBuf {
    let path = scratch_dir().join(name);
    std::fs::File::create(&path)
        .and_then(|file| file.set_len(len))
        .unwrap_or_else(|e| panic!("creating {}: {e}", path.display()));
    path
}

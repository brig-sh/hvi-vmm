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

//! The control socket's thread: it serves [`control`](super::control)
//! requests against the running VM.
//!
//! The thread is one of the I/O threads. It polls its listener and its one
//! connection beside the stop token, so the stop ends it like the others, and
//! it never passes the pause gate itself, since it is the one that closes it.
//! It serves one connection at a time, in order. A client that disconnects
//! while the VM is paused leaves it paused: the next client resumes it, or
//! stops it.
//!
//! `pause` closes the I/O gate first and parks the vCPUs second, so no host
//! thread writes guest RAM once the vCPUs are still. Either step that misses
//! its deadline undoes the first and the VM runs on, since a pause that left
//! some thread running would be no pause. `resume` releases them in the other
//! order, so a released I/O thread never meets a parked guest that cannot
//! take its interrupt.
//!
//! `checkpoint` pauses the same way, or finds the VM paused already, then
//! asks every vCPU to export its state on its own thread and waits for all of
//! them within the same deadline. With everything still it writes the
//! bundle (see [`capture`]) and seals it. A failure at any
//! step before the seal leaves the VM as the request found it: running, or
//! paused if a client had paused it. After the seal, `then: "continue"`
//! does the same, and `then: "fence"` leaves the VM paused for good: `status`
//! says `fenced`, `resume` is refused, and only `stop` ends it.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::checkpoint::bundle::{resolve_in_root, BundleWriter};
use crate::checkpoint::capture::{self, Capture, Console};
use crate::checkpoint::control::{
    format_response, parse_request, CheckpointStats, Error, ErrorCode, Request, Response, Then,
    VmState, MAX_LINE,
};
use crate::checkpoint::cpu::{Output, VcpuState};
use crate::checkpoint::platform::PlatformState;
use crate::checkpoint::profile::{MachineProfile, ProfileCell};
use crate::config::MachineProfileKind;
use crate::devices::virtio::vsock::retry_read;
use crate::hypervisor::guest::Guest;
use crate::hypervisor::vcpus::{Kick, PauseError, Vcpus, WorkResult};
use crate::teardown::{PauseGate, StopToken};
use crate::LOG_PREFIX;

/// How long a pause waits for the I/O threads and the vCPUs together, and how
/// long `profile` waits for the profile to be complete. No request waits
/// longer, so a client that allows a little more than this for a reply never
/// gives up on a pause that later succeeds.
pub(crate) const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

/// How often a wait for the profile looks at whether the VM still runs.
const PROFILE_POLL: Duration = Duration::from_millis(50);

/// A bound control socket and the profile it reports.
pub(crate) struct ControlSocket {
    /// The socket, non-blocking.
    listener: UnixListener,
    /// The profile `profile` answers with.
    profile: Arc<ProfileCell>,
    /// The directory a `checkpoint` may write under, when the run has one.
    checkpoint_root: Option<CheckpointRoot>,
    /// What only the backend knows of a capture, once it has said.
    parts: Option<CaptureParts>,
    /// The state the VM starts in: running after a boot, restored-paused
    /// after a restore.
    initial: VmState,
}

/// The checkpoint root, resolved, and as the operator spelled it.
#[derive(Clone)]
struct CheckpointRoot {
    /// The resolved path, which confinement grants and every bundle is
    /// written below.
    resolved: std::path::PathBuf,
    /// The path as given, made absolute. A caller that names the root one
    /// way at boot names its bundles the same way, and on macOS `/tmp` and
    /// `/var` are links to `/private`.
    given: std::path::PathBuf,
}

impl CheckpointRoot {
    /// Returns the bundle directory `dir` names, below the resolved root.
    ///
    /// A `dir` spelled from the root as given is first respelled from the
    /// resolved root, so the writes land in the tree the confinement grants
    /// and a later change to a link on the given path cannot move them.
    fn bundle_dir(&self, dir: &str) -> std::io::Result<std::path::PathBuf> {
        let respelled = std::path::Path::new(dir)
            .strip_prefix(&self.given)
            .ok()
            .filter(|_| self.given != self.resolved)
            .map(|rest| self.resolved.join(rest).to_string_lossy().into_owned());
        resolve_in_root(&self.resolved, respelled.as_deref().unwrap_or(dir))
    }
}

/// What only the backend knows of a capture, beside what [`Guest`] holds.
struct CaptureParts {
    /// `hvf` or `kvm`.
    backend: &'static str,
    /// The path the disk was opened at.
    disk_path: Option<String>,
    /// The console devices.
    console: Console,
}

impl ControlSocket {
    /// Binds the control socket at `path`, first removing a stale socket a
    /// previous run left, and resolves `checkpoint_root`, the directory a
    /// `checkpoint` may write under.
    ///
    /// Only a socket is removed. Anything else at the path is an error, so a
    /// mistyped path such as `--control-sock disk.img` cannot delete a file.
    /// It must be bound before confinement, which allows accepting on a
    /// listener already held but not creating one. The root is resolved here
    /// for the same reason: confinement names it by its resolved path.
    ///
    /// # Errors
    ///
    /// Errors if something other than a socket is at `path`, the socket
    /// cannot be bound, or the root is not a directory.
    // The host-path ban in clippy.toml is aimed at the virtio-fs device. This
    // path is the operator's.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn bind(
        path: &str,
        profile: Arc<ProfileCell>,
        checkpoint_root: Option<&str>,
    ) -> std::io::Result<Self> {
        let checkpoint_root = checkpoint_root
            .map(|root| {
                let resolved = std::fs::canonicalize(root).map_err(|e| {
                    std::io::Error::new(e.kind(), format!("--checkpoint-root {root}: {e}"))
                })?;
                if !std::fs::metadata(&resolved)?.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("--checkpoint-root {root}: not a directory"),
                    ));
                }
                let given = std::env::current_dir()?.join(root).components().collect();
                Ok(CheckpointRoot { resolved, given })
            })
            .transpose()?;
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("cannot bind control socket {path}: it exists and is not a socket"),
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("cannot bind control socket {path}: {e}"),
                ))
            }
        }
        let listener = UnixListener::bind(path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("cannot bind control socket {path}: {e}"))
        })?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            profile,
            checkpoint_root,
            parts: None,
            initial: VmState::Running,
        })
    }

    /// Gives the socket what it needs to capture the guest beside what the
    /// guest holds: the backend's name, the disk's path and the console.
    #[must_use]
    pub(crate) fn capturing(
        mut self,
        backend: &'static str,
        disk_path: Option<String>,
        console: Console,
    ) -> Self {
        self.parts = Some(CaptureParts {
            backend,
            disk_path,
            console,
        });
        self
    }

    /// Starts the VM as `hvi restore` hands it over: restored-paused, with the
    /// I/O threads held and the control socket holding the vCPUs parked.
    #[must_use]
    // Only the HVF restore calls it so far.
    #[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
    pub(crate) fn restored(mut self) -> Self {
        self.initial = VmState::RestoredPaused;
        self
    }

    /// Returns what a `checkpoint` captures of `guest`, when the run has a
    /// checkpoint root and the backend said how.
    pub(crate) fn capture_of<K>(&self, guest: &Guest<K>) -> Option<Capture> {
        self.checkpoint_root.as_ref()?;
        let parts = self.parts.as_ref()?;
        Some(Capture {
            arch: guest.arch,
            backend: parts.backend,
            sandbox_id: guest.sandbox_id.clone(),
            ram: Arc::clone(&guest.ram),
            block: guest
                .block
                .as_ref()
                .map(|dev| (Arc::clone(dev), parts.disk_path.clone().unwrap_or_default())),
            net: guest.net.clone(),
            vsock: guest.vsock.clone(),
            console: parts.console.clone(),
            #[cfg(test)]
            after_component: None,
        })
    }

    /// Returns the resolved checkpoint root, when the run has one.
    pub(crate) fn checkpoint_root(&self) -> Option<&std::path::Path> {
        self.checkpoint_root
            .as_ref()
            .map(|root| root.resolved.as_path())
    }

    /// Serves connections until `stop` is requested.
    ///
    /// `gate` is the I/O threads' pause gate and `vcpus` the VM's vCPUs.
    /// `capture` is what a `checkpoint` writes, from
    /// [`capture_of`](Self::capture_of); without it every `checkpoint` is
    /// refused.
    pub(crate) fn run<K: Kick>(
        self,
        stop: &StopToken,
        gate: &PauseGate,
        vcpus: &Vcpus<K>,
        capture: Option<Capture>,
    ) {
        self.run_with(stop, gate, vcpus, capture, CONTROL_TIMEOUT);
    }

    /// [`run`](Self::run), with `timeout` for each wait.
    fn run_with<K: Kick>(
        self,
        stop: &StopToken,
        gate: &PauseGate,
        vcpus: &Vcpus<K>,
        capture: Option<Capture>,
        timeout: Duration,
    ) {
        let mut machine = Machine {
            state: self.initial,
            gate,
            vcpus,
            profile: &self.profile,
            capture: capture.zip(self.checkpoint_root.clone()),
            timeout,
        };
        loop {
            match stop.wait(self.listener.as_fd()) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    eprintln!("{LOG_PREFIX} control socket: {e}; no longer accepting");
                    break;
                }
            }
            let Ok((conn, _)) = self.listener.accept() else {
                continue;
            };
            if let Err(e) = serve(conn, stop, &mut machine) {
                eprintln!("{LOG_PREFIX} control socket: {e}; connection closed");
            }
        }
    }
}

/// Serves requests on `conn` until the client closes it, a line is too long,
/// or `stop` is requested.
fn serve<K: Kick>(
    mut conn: UnixStream,
    stop: &StopToken,
    machine: &mut Machine<'_, K>,
) -> std::io::Result<()> {
    // A macOS accept hands back a socket that inherits the listener's
    // non-blocking flag and a Linux one does not. Set it either way: the reads
    // and writes below wait on the stop token, not in the kernel.
    conn.set_nonblocking(true)?;
    let mut pending = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if !stop.wait(conn.as_fd())? {
            return Ok(());
        }
        let n = match conn.read(&mut chunk) {
            // A client that half-closes after its last request without a
            // newline still means it.
            Ok(0) => return answer(&mut conn, stop, machine, &pending),
            Ok(n) => n,
            Err(e) if retry_read(&e) => continue,
            Err(e) => return Err(e),
        };
        pending.extend_from_slice(&chunk[..n]);
        while let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            answer(&mut conn, stop, machine, &line[..end])?;
        }
        if pending.len() > MAX_LINE {
            let e = Error::new(
                ErrorCode::TooLong,
                format!("a request line is at most {MAX_LINE} bytes"),
            );
            send(&mut conn, stop, &Response::Error(e))?;
            return Ok(());
        }
    }
}

/// Serves the request `line`, without its newline, and replies on `conn`.
/// A blank line is skipped.
///
/// The request's follow-up runs whether or not the reply could be sent. Its
/// state change is already made, so a `stop` whose client hung up before the
/// reply would otherwise leave the VM running while every later `stop` is
/// answered `stopping` and does nothing.
fn answer<K: Kick>(
    conn: &mut UnixStream,
    stop: &StopToken,
    machine: &mut Machine<'_, K>,
    line: &[u8],
) -> std::io::Result<()> {
    let line = String::from_utf8_lossy(line);
    if line.trim().is_empty() {
        return Ok(());
    }
    let (response, then) = match parse_request(&line) {
        Ok(request) => machine.handle(request),
        Err(e) => (Response::Error(e), None),
    };
    let sent = send(conn, stop, &response);
    if let Some(after) = then {
        after.run(machine.vcpus);
    }
    sent
}

/// Writes `response` and its newline to `conn`, waiting for room beside the
/// stop token.
fn send(conn: &mut UnixStream, stop: &StopToken, response: &Response) -> std::io::Result<()> {
    let line = format_response(response) + "\n";
    let mut rest = line.as_bytes();
    while !rest.is_empty() {
        match conn.write(rest) {
            Ok(n) => rest = &rest[n..],
            Err(e) if retry_read(&e) => {
                if !stop.wait_writable(conn.as_fd())? {
                    return Ok(());
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// What a request does once its reply is on its way.
enum After {
    /// End the run.
    Stop,
}

impl After {
    fn run<K: Kick>(self, vcpus: &Vcpus<K>) {
        match self {
            Self::Stop => {
                // The loop that owns the run's stop wakes on the request, and
                // the run ends as `Stop::Requested`. The VM stops here at once
                // as well, so a pause this socket holds ends with the reply.
                vcpus.stop_handle().request_stop();
                vcpus.stop();
            }
        }
    }
}

/// The VM as the control socket drives it.
struct Machine<'a, K> {
    /// Where the socket has taken the VM.
    state: VmState,
    /// The I/O threads' pause gate.
    gate: &'a PauseGate,
    /// The vCPUs.
    vcpus: &'a Vcpus<K>,
    /// The profile `profile` reports.
    profile: &'a ProfileCell,
    /// What a `checkpoint` captures, and the root it writes under.
    capture: Option<(Capture, CheckpointRoot)>,
    /// The deadline of each wait, [`CONTROL_TIMEOUT`] outside the tests.
    timeout: Duration,
}

impl<K: Kick> Machine<'_, K> {
    /// Returns the reply to `request` and what to do once it is sent.
    fn handle(&mut self, request: Request) -> (Response, Option<After>) {
        if !self.vcpus.is_running() {
            self.state = VmState::Stopping;
        }
        let response = match request {
            Request::Profile => self.profile(),
            Request::Status => Response::Status {
                state: self.state,
                vcpus: self.vcpus.started(),
                vcpus_parked: self.vcpus.parked(),
            },
            Request::Pause => self.pause(),
            Request::Resume => self.resume(),
            Request::Stop => {
                if self.state == VmState::Stopping {
                    return (Response::State(VmState::Stopping), None);
                }
                self.state = VmState::Stopping;
                return (Response::State(VmState::Stopping), Some(After::Stop));
            }
            Request::Checkpoint {
                dir,
                then,
                txid,
                epoch,
            } => self.checkpoint(&dir, then, txid.as_deref(), epoch),
        };
        (response, None)
    }

    /// Returns the profile once it is complete, or the refusal to send.
    fn complete_profile(&self) -> Result<MachineProfile, Response> {
        match self.profile() {
            Response::Profile(profile) => Ok(*profile),
            other => Err(other),
        }
    }

    /// Captures the VM into the bundle directory `dir`, then continues it or
    /// fences it.
    ///
    /// Everything that can be refused without pausing is checked first: the
    /// state, the checkpoint root, the directory, the profile and its shares.
    /// The pause and the vCPU export then share one deadline. A failure from
    /// there to the seal returns the VM to the state the request found it in.
    fn checkpoint(&mut self, dir: &str, then: Then, txid: Option<&str>, epoch: u64) -> Response {
        match self.state {
            VmState::Fenced => {
                return refuse(ErrorCode::Fenced, "the VM was fenced after a checkpoint")
            }
            VmState::Stopping => return refuse(ErrorCode::Stopped, "the run is ending"),
            VmState::Running | VmState::Paused | VmState::RestoredPaused => {}
        }
        let Some((_, root)) = &self.capture else {
            return refuse(
                ErrorCode::Refused,
                "this run has no checkpoint root; boot it with --checkpoint-root",
            );
        };
        let dir = match root.bundle_dir(dir) {
            Ok(dir) => dir,
            Err(e) => return refuse(ErrorCode::Refused, e.to_string()),
        };
        let profile = match self.complete_profile() {
            Ok(profile) => profile,
            Err(refusal) => return refusal,
        };
        if profile.fs_shares > 0 {
            return refuse(
                ErrorCode::Refused,
                format!(
                    "the guest has {} virtio-fs share(s), whose state is host files that do \
                     not move",
                    profile.fs_shares
                ),
            );
        }
        if profile.profile != MachineProfileKind::Native.name() {
            return refuse(
                ErrorCode::Refused,
                format!(
                    "the guest has the {} machine profile, which no backend checkpoints yet",
                    profile.profile
                ),
            );
        }
        let writer = match BundleWriter::create(&dir) {
            Ok(writer) => writer,
            Err(e) => return refuse(ErrorCode::Refused, e.to_string()),
        };

        let started = Instant::now();
        let found = self.state;
        if found == VmState::Running {
            if let Response::Error(e) = self.pause() {
                return Response::Error(e);
            }
        }
        let exported = match self.export(started + self.timeout) {
            Ok(exported) => exported,
            Err(e) => {
                self.back_to(found);
                return Response::Error(e);
            }
        };
        let pause_ms = started.elapsed().as_millis() as u64;

        let captured_at = Instant::now();
        let request = capture::Request { then, txid, epoch };
        let sealed = match &self.capture {
            Some((capture, _)) => {
                let vcpus_of = self.vcpus;
                capture.write(writer, &profile, exported, &request, &|| {
                    !vcpus_of.is_running()
                })
            }
            None => Err(std::io::Error::other("no capture")),
        };
        let capture_ms = captured_at.elapsed().as_millis() as u64;
        let sealed = match sealed {
            Ok(sealed) => sealed,
            Err(e) => {
                if !self.vcpus.is_running() {
                    self.state = VmState::Stopping;
                    return refuse(ErrorCode::Stopped, format!("the run is ending: {e}"));
                }
                self.back_to(found);
                return refuse(
                    ErrorCode::CaptureFailed,
                    format!("{e}; nothing was kept, and the VM is as it was"),
                );
            }
        };
        match then {
            Then::Continue => self.back_to(found),
            Then::Fence => {
                self.state = VmState::Fenced;
                if let Some((capture, _)) = &self.capture {
                    capture.release_disk();
                }
            }
        }
        Response::Checkpoint {
            state: self.state,
            dir: dir.display().to_string(),
            manifest_sha256: sealed.manifest_sha256,
            stats: CheckpointStats {
                pause_ms,
                capture_ms,
                ram_present_bytes: sealed.ram_present_bytes,
                ram_total_bytes: sealed.ram_total_bytes,
                bundle_bytes: sealed.bundle_bytes,
            },
        }
    }

    /// Asks every parked vCPU for its state, then vCPU 0 for the platform,
    /// and returns the states by index with the platform they make up.
    ///
    /// A vCPU the guest never started is powered off, or waits for the
    /// `CPU_ON` the guest sent it. The platform is read in a request of its
    /// own, after every vCPU's export, so the interrupt controller vCPU 0
    /// reads is the one the others left; the wait between the two requests
    /// is the barrier. A backend that does not read the platform leaves it
    /// marked as not captured.
    fn export(&mut self, deadline: Instant) -> Result<capture::Exported, Error> {
        let Some((capture, _)) = &self.capture else {
            return Err(Error::new(ErrorCode::Refused, "no capture"));
        };
        let (arch, backend) = (capture.arch, capture.backend);
        let failed = |why: String| Error::new(ErrorCode::CaptureFailed, why);
        let results = self.work(deadline, "exported their state", Vcpus::request_export)?;
        let mut vcpus = Vec::with_capacity(results.len());
        let mut irq_cpus = Vec::new();
        let mut exported = 0;
        for (cpu, result) in (0u32..).zip(results) {
            match result {
                WorkResult::Done(Some(out)) => match *out {
                    Output::Vcpu { state, irq } if state.id() == cpu => {
                        exported += 1;
                        vcpus.push(state);
                        irq_cpus.extend(irq);
                    }
                    _ => return Err(failed(format!("vCPU {cpu} exported no state of its own"))),
                },
                WorkResult::Done(None) => {
                    return Err(failed(format!("vCPU {cpu} exported no state of its own")))
                }
                WorkResult::Failed(why) => {
                    return Err(failed(format!(
                        "vCPU {cpu} could not export its state: {why}"
                    )))
                }
                WorkResult::NotStarted => {
                    vcpus.push(match self.vcpus.kicker().pending_start(cpu) {
                        Some((entry, ctx)) => VcpuState::pending_on(arch, backend, cpu, entry, ctx),
                        None => VcpuState::powered_off(arch, backend, cpu),
                    });
                }
            }
        }
        // A vCPU that started after the wait ended has no export and is no
        // longer off. Writing it as either would lose it.
        if self.vcpus.started() != exported {
            return Err(failed(format!(
                "a vCPU started during the capture ({} started, {exported} exported); \
                 try again",
                self.vcpus.started()
            )));
        }
        let results = self.work(deadline, "read the platform", Vcpus::request_platform)?;
        let mut platform = None;
        for (cpu, result) in results.into_iter().enumerate() {
            match result {
                WorkResult::Done(None) | WorkResult::NotStarted => {}
                WorkResult::Done(Some(out)) => match *out {
                    Output::Platform {
                        platform: read,
                        capabilities,
                    } if cpu == 0 => platform = Some((read, capabilities)),
                    _ => return Err(failed(format!("vCPU {cpu} handed back no platform"))),
                },
                WorkResult::Failed(why) => {
                    return Err(failed(format!(
                        "vCPU {cpu} could not read the platform: {why}"
                    )))
                }
            }
        }
        let (mut platform, capabilities) =
            platform.unwrap_or_else(|| (PlatformState::not_captured(arch, backend), Vec::new()));
        platform.add_cpus(irq_cpus).map_err(failed)?;
        Ok(capture::Exported {
            vcpus,
            platform,
            capabilities,
        })
    }

    /// Posts work to the vCPUs with `post`, waits for every started one by
    /// `deadline`, and returns what each one handed back.
    fn work(
        &mut self,
        deadline: Instant,
        what: &str,
        post: impl FnOnce(&Vcpus<K>),
    ) -> Result<Vec<WorkResult>, Error> {
        post(self.vcpus);
        let waited = self
            .vcpus
            .wait_work(deadline.saturating_duration_since(Instant::now()));
        let results = self.vcpus.end_work();
        match waited {
            Ok(()) => Ok(results),
            Err(PauseError::Stopped) => {
                self.state = VmState::Stopping;
                Err(Error::new(ErrorCode::Stopped, "the run is ending"))
            }
            Err(PauseError::Timeout { parked, expected }) => Err(Error::new(
                ErrorCode::Timeout,
                format!("{parked} of {expected} vCPUs {what} in time"),
            )),
            Err(other) => Err(Error::new(ErrorCode::CaptureFailed, other.to_string())),
        }
    }

    /// Returns the VM to where a checkpoint found it, `found`: paused as it
    /// was, or running.
    fn back_to(&mut self, found: VmState) {
        if found == VmState::Running {
            let _ = self.vcpus.resume_from_control();
            self.gate.unpause();
        }
        self.state = found;
    }

    /// Returns the profile once it is complete.
    ///
    /// The wait ends with the stop as well as at its deadline. The stop cannot
    /// wake the profile's condition variable, so the wait is cut into short
    /// ones, or a `profile` asked before the boot vCPU starts would keep this
    /// thread past the deadline the join of the I/O threads has.
    fn profile(&self) -> Response {
        let deadline = Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if let Some(profile) = self.profile.get(left.min(PROFILE_POLL)) {
                return Response::Profile(Box::new(profile));
            }
            if !self.vcpus.is_running() {
                return refuse(ErrorCode::Stopped, "the run is ending");
            }
            if left.is_zero() {
                return refuse(ErrorCode::NotReady, "the boot vCPU has not started yet");
            }
        }
    }

    /// Holds the I/O threads, then parks the vCPUs, within one deadline for
    /// both. Pausing a paused VM succeeds and changes nothing.
    fn pause(&mut self) -> Response {
        match self.state {
            VmState::Paused | VmState::RestoredPaused | VmState::Fenced => {
                return Response::State(self.state)
            }
            VmState::Stopping => return refuse(ErrorCode::Stopped, "the run is ending"),
            VmState::Running => {}
        }
        let deadline = Instant::now() + self.timeout;
        if let Err(inside) = self.gate.pause(self.timeout) {
            // The gate gives up on the stop as well as at its deadline.
            if !self.vcpus.is_running() {
                self.state = VmState::Stopping;
                return refuse(ErrorCode::Stopped, "the run is ending");
            }
            return refuse(
                ErrorCode::Timeout,
                format!(
                    "{inside} I/O thread(s) still busy after {:?}; the VM runs on",
                    self.timeout
                ),
            );
        }
        // The vCPUs get what the gate left of the deadline, so the reply comes
        // within the one deadline the client is told about.
        let left = deadline.saturating_duration_since(Instant::now());
        match self.vcpus.pause_from_control(left) {
            Ok(_) => {
                self.state = VmState::Paused;
                Response::State(VmState::Paused)
            }
            Err(e) => {
                self.gate.unpause();
                let code = match e {
                    PauseError::Stopped => {
                        self.state = VmState::Stopping;
                        ErrorCode::Stopped
                    }
                    PauseError::Busy => ErrorCode::Busy,
                    PauseError::Timeout { .. } | PauseError::NotPaused => ErrorCode::Timeout,
                };
                refuse(code, format!("{e}; the VM runs on"))
            }
        }
    }

    /// Releases the vCPUs, then the I/O threads. Resuming a running VM
    /// succeeds and changes nothing.
    fn resume(&mut self) -> Response {
        match self.state {
            VmState::Running => Response::State(VmState::Running),
            VmState::Fenced => refuse(ErrorCode::Fenced, "the VM was fenced after a checkpoint"),
            VmState::Stopping => refuse(ErrorCode::Stopped, "the run is ending"),
            VmState::Paused | VmState::RestoredPaused => {
                // The only error is a quiesce the socket no longer holds, which
                // the stop's own release explains; the gate opens either way.
                let _ = self.vcpus.resume_from_control();
                self.gate.unpause();
                self.state = VmState::Running;
                Response::State(VmState::Running)
            }
        }
    }
}

/// Returns a refusal with `code` and `message`.
fn refuse(code: ErrorCode, message: impl Into<String>) -> Response {
    Response::Error(Error::new(code, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::bundle::Component;
    use crate::checkpoint::cpu::Work;
    use crate::config::Stop;
    use crate::hypervisor::vcpus::Outcome;
    use crate::memory::GuestRam;
    use crate::plugin::{GuestArch, RegsView};
    use crate::run::StopHandle;
    use crate::teardown::StopSource;
    use std::io::BufRead;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::JoinHandle;
    use std::time::Instant;

    /// A kicker that reaches no thread; the fake vCPUs below poll instead.
    ///
    /// It reports `pending` as the `CPU_ON` waiting for a vCPU that has not
    /// started, as an HVF secondary's mailbox would.
    #[derive(Default)]
    struct NoKick {
        pending: Option<(u32, u64, u64)>,
    }

    impl Kick for NoKick {
        fn kick(&self, _cpu: u32) {}
        fn kick_all(&self) {}
        fn pending_start(&self, cpu: u32) -> Option<(u64, u64)> {
            self.pending
                .filter(|(at, _, _)| *at == cpu)
                .map(|(_, entry, ctx)| (entry, ctx))
        }
    }

    /// What a [`Fixture`] serves.
    #[derive(Default)]
    struct Spec {
        /// vCPUs that park at their checkpoints and export their state.
        parking: u32,
        /// Started vCPUs that never reach a checkpoint.
        stuck: u32,
        /// vCPUs the guest never starts, as an HVF secondary before CPU_ON.
        unstarted: u32,
        /// A `CPU_ON` waiting for one of those, as (vCPU, entry, context).
        pending: Option<(u32, u64, u64)>,
        /// Whether the VM is handed over as `hvi restore` hands it: the
        /// `parking` vCPUs import a plan of their states first, and the
        /// socket starts restored-paused.
        restore: bool,
        /// Whether the run has a checkpoint root and what to capture.
        capture: bool,
        /// A virtio-net device the capture holds.
        net: Option<Arc<std::sync::Mutex<crate::devices::virtio::net::VirtioNet>>>,
        /// The profile's virtio-fs share count.
        fs_shares: u32,
        /// The profile's machine profile, when not native.
        machine: Option<&'static str>,
        /// The component after which the capture fails.
        fail_after: Option<Component>,
        /// The component after which the run is stopped.
        stop_after: Option<Component>,
        /// The disk image of a virtio-blk device the capture holds.
        disk: Option<String>,
    }

    /// Where the fixture's guest RAM starts, 1 MiB of it.
    const GPA: u64 = 0x4000_0000;

    /// A served control socket over fake vCPUs, with a client connected.
    struct Fixture {
        source: StopSource,
        vcpus: Arc<Vcpus<NoKick>>,
        cell: Arc<ProfileCell>,
        server: Option<JoinHandle<()>>,
        fake_vcpus: Vec<JoinHandle<()>>,
        client: UnixStream,
        replies: std::io::BufReader<UnixStream>,
        path: std::path::PathBuf,
        /// The checkpoint root, resolved, removed with the fixture.
        root: std::path::PathBuf,
        /// The checkpoint root as the fixture named it at bind, unresolved.
        given_root: std::path::PathBuf,
        /// The import steps the vCPUs carried out, when restored.
        log: crate::checkpoint::restore::tests::Log,
    }

    impl Fixture {
        /// Serves a VM of `parking` vCPUs that park at their checkpoints and
        /// `stuck` started ones that never do.
        fn new(name: &str, parking: u32, stuck: u32) -> Self {
            Self::with(
                name,
                Spec {
                    parking,
                    stuck,
                    ..Spec::default()
                },
            )
        }

        /// Serves the VM `spec` describes.
        #[allow(clippy::disallowed_methods)]
        fn with(name: &str, spec: Spec) -> Self {
            let path =
                std::env::temp_dir().join(format!("hvi-ctl-{}-{name}.sock", std::process::id()));
            let root =
                std::env::temp_dir().join(format!("hvi-ctl-{}-{name}.root", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir(&root).unwrap();
            let source = StopSource::new().unwrap();
            let count = spec.parking + spec.stuck + spec.unstarted;
            let vcpus = Arc::new(Vcpus::new(
                count,
                NoKick {
                    pending: spec.pending,
                },
                StopHandle::new_pair().unwrap().0,
            ));
            let log = crate::checkpoint::restore::tests::Log::default();
            if spec.restore {
                vcpus.pause_from_control(Duration::ZERO).unwrap();
                source.gate().pause(Duration::ZERO).unwrap();
            }
            let fake_vcpus = (0..spec.parking)
                .filter(|_| !spec.restore)
                .map(|cpu| {
                    vcpus.mark_started(vcpus.started());
                    let vcpus = Arc::clone(&vcpus);
                    std::thread::spawn(move || {
                        while vcpus.is_running() {
                            let _ = vcpus.checkpoint_with(cpu, |work| match work {
                                Work::Export => Ok(Some(Output::Vcpu {
                                    state: VcpuState::from_regs_view(
                                        GuestArch::Aarch64,
                                        "hvf",
                                        cpu,
                                        &RegsView::default(),
                                    ),
                                    irq: None,
                                })),
                                Work::ExportPlatform | Work::Import(..) => Ok(None),
                            });
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    })
                })
                .collect();
            let fake_vcpus: Vec<JoinHandle<()>> = if spec.restore {
                let fakes = (0..spec.parking)
                    .map(|cpu| {
                        crate::checkpoint::restore::tests::importing_vcpu(&vcpus, cpu, &log, None)
                    })
                    .collect();
                let plan = crate::checkpoint::restore::tests::plan(spec.parking, spec.unstarted);
                crate::checkpoint::restore::import(&vcpus, &plan, Duration::from_secs(5), || {
                    spec.parking + spec.unstarted
                })
                .unwrap();
                fakes
            } else {
                fake_vcpus
            };
            for _ in 0..spec.stuck {
                vcpus.mark_started(vcpus.started());
            }
            let cell = Arc::new(
                ProfileCell::new(MachineProfile::for_this_host("aarch64", "hvf"), None).unwrap(),
            );
            let ram = Arc::new(GuestRam::from_ranges(&[(GPA, 1 << 20)]));
            ram.write(GPA + 0x3000, b"guest data").unwrap();
            if spec.capture {
                let regions = ram.regions();
                cell.complete(|p| {
                    p.cpu.ident = Some("0x61".into());
                    p.vcpus = count;
                    p.fs_shares = spec.fs_shares;
                    if let Some(machine) = spec.machine {
                        p.profile = machine.to_string();
                    }
                    p.ram_regions = regions.into_iter().map(Into::into).collect();
                })
                .unwrap();
            }
            let root_arg = spec.capture.then(|| root.to_str().unwrap().to_string());
            let mut socket = ControlSocket::bind(
                path.to_str().unwrap(),
                Arc::clone(&cell),
                root_arg.as_deref(),
            )
            .unwrap();
            if spec.restore {
                socket = socket.restored();
            }
            let capture = spec.capture.then(|| Capture {
                arch: GuestArch::Aarch64,
                backend: "hvf",
                sandbox_id: "fixture".into(),
                ram,
                block: spec.disk.as_ref().map(|path| {
                    let dev = crate::devices::virtio::block::VirtioBlk::open(path).unwrap();
                    (Arc::new(std::sync::Mutex::new(dev)), path.clone())
                }),
                net: spec.net.clone(),
                vsock: None,
                console: Console::None,
                after_component: Some({
                    let (fail, stop, vcpus) =
                        (spec.fail_after, spec.stop_after, Arc::clone(&vcpus));
                    Arc::new(move |component| {
                        if stop == Some(component) {
                            vcpus.stop();
                        }
                        if fail == Some(component) {
                            return Err(std::io::Error::other(format!(
                                "a test failed the write after {}",
                                component.file()
                            )));
                        }
                        Ok(())
                    })
                }),
            });
            let server = {
                let (stop, gate, vcpus) = (
                    source.token(),
                    Arc::clone(source.gate()),
                    Arc::clone(&vcpus),
                );
                // A short deadline, so a test of a timeout is quick.
                std::thread::spawn(move || {
                    socket.run_with(&stop, &gate, &vcpus, capture, Duration::from_millis(200));
                })
            };
            let client = UnixStream::connect(&path).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let replies = std::io::BufReader::new(client.try_clone().unwrap());
            Self {
                source,
                vcpus,
                cell,
                server: Some(server),
                fake_vcpus,
                client,
                replies,
                path,
                given_root: root.clone(),
                root: std::fs::canonicalize(&root).unwrap(),
                log,
            }
        }

        /// Sends `line` and returns the reply line, without its newline.
        fn ask(&mut self, line: &str) -> String {
            self.client.write_all(line.as_bytes()).unwrap();
            self.client.write_all(b"\n").unwrap();
            let mut reply = String::new();
            self.replies.read_line(&mut reply).unwrap();
            reply.trim_end().to_string()
        }

        /// Asks for a checkpoint into `name` below the root, then `then`.
        fn checkpoint(&mut self, name: &str, then: &str) -> String {
            let dir = self.root.join(name);
            self.ask(&format!(
                r#"{{"v":1,"op":"checkpoint","dir":"{}","then":"{then}","txid":"t-{name}","epoch":2}}"#,
                dir.display()
            ))
        }

        /// Waits up to 5 s for no vCPU to be parked.
        fn assert_running(&self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.vcpus.parked() != 0 {
                assert!(Instant::now() < deadline, "a vCPU stayed parked");
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(!self.source.gate().is_paused(), "the gate stayed closed");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.vcpus.stop();
            self.source.request_stop();
            if let Some(server) = self.server.take() {
                let _ = server.join();
            }
            for fake in self.fake_vcpus.drain(..) {
                let _ = fake.join();
            }
            #[allow(clippy::disallowed_methods)]
            let _ = std::fs::remove_file(&self.path);
            #[allow(clippy::disallowed_methods)]
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn pause_status_resume_status() {
        let mut f = Fixture::new("cycle", 2, 0);
        assert_eq!(
            f.ask(r#"{"v":1,"op":"status"}"#),
            r#"{"v":1,"ok":true,"state":"running","vcpus":2,"vcpus_parked":0}"#
        );
        assert_eq!(
            f.ask(r#"{"v":1,"op":"pause"}"#),
            r#"{"v":1,"ok":true,"state":"paused"}"#
        );
        assert!(f.source.gate().is_paused());
        assert_eq!(
            f.ask(r#"{"v":1,"op":"status"}"#),
            r#"{"v":1,"ok":true,"state":"paused","vcpus":2,"vcpus_parked":2}"#
        );
        // A second pause is a no-op, for a client that retries.
        assert_eq!(
            f.ask(r#"{"v":1,"op":"pause"}"#),
            r#"{"v":1,"ok":true,"state":"paused"}"#
        );
        assert_eq!(
            f.ask(r#"{"v":1,"op":"resume"}"#),
            r#"{"v":1,"ok":true,"state":"running"}"#
        );
        assert!(!f.source.gate().is_paused());
        let deadline = Instant::now() + Duration::from_secs(5);
        while f.vcpus.parked() != 0 {
            assert!(Instant::now() < deadline, "the resume left a vCPU parked");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            f.ask(r#"{"v":1,"op":"resume"}"#),
            r#"{"v":1,"ok":true,"state":"running"}"#
        );
    }

    // The pause must hold the I/O threads as well as the vCPUs, and the
    // resume release them.
    #[test]
    fn pause_holds_the_io_threads_until_resume() {
        let mut f = Fixture::new("io", 1, 0);
        f.ask(r#"{"v":1,"op":"pause"}"#);
        let token = f.source.token();
        let passed = Arc::new(AtomicBool::new(false));
        let io = {
            let passed = Arc::clone(&passed);
            std::thread::spawn(move || {
                let _in = token.enter();
                passed.store(true, Ordering::SeqCst);
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !passed.load(Ordering::SeqCst),
            "an I/O thread ran under the pause"
        );
        f.ask(r#"{"v":1,"op":"resume"}"#);
        io.join().unwrap();
        assert!(passed.load(Ordering::SeqCst));
    }

    // A vCPU that never parks fails the pause, and the VM must be left
    // running, I/O threads included.
    #[test]
    fn a_pause_that_times_out_leaves_the_vm_running() {
        let mut f = Fixture::new("timeout", 1, 1);
        let reply = f.ask(r#"{"v":1,"op":"pause"}"#);
        assert!(
            reply.starts_with(r#"{"v":1,"ok":false,"code":"timeout","error":"1 of 2 vCPUs parked"#),
            "{reply}"
        );
        assert!(!f.source.gate().is_paused(), "the gate stayed closed");
        assert_eq!(
            f.ask(r#"{"v":1,"op":"status"}"#),
            r#"{"v":1,"ok":true,"state":"running","vcpus":2,"vcpus_parked":0}"#
        );
    }

    #[test]
    fn refusals_keep_the_connection_open() {
        let mut f = Fixture::new("refusals", 1, 0);
        assert_eq!(
            f.ask(r#"{"v":1,"op":"checkpoint","dir":"/tmp/ck"}"#),
            r#"{"v":1,"ok":false,"code":"refused","error":"this run has no checkpoint root; boot it with --checkpoint-root"}"#
        );
        assert!(f
            .ask("nonsense")
            .starts_with(r#"{"v":1,"ok":false,"code":"bad_request""#));
        assert!(f
            .ask(r#"{"v":1,"op":"reboot"}"#)
            .starts_with(r#"{"v":1,"ok":false,"code":"unknown_op""#));
        assert!(f
            .ask(r#"{"v":1,"op":"status"}"#)
            .starts_with(r#"{"v":1,"ok":true"#));
    }

    #[test]
    fn a_line_past_the_limit_is_refused_and_closed() {
        let mut f = Fixture::new("long", 1, 0);
        // The server may close before it has read everything, which fails the
        // rest of the write; only the reply matters.
        let mut writer = f.client.try_clone().unwrap();
        std::thread::spawn(move || {
            let _ = writer.write_all("x".repeat(MAX_LINE + 4096).as_bytes());
        });
        let mut reply = String::new();
        f.replies.read_line(&mut reply).unwrap();
        assert!(
            reply.starts_with(r#"{"v":1,"ok":false,"code":"too_long""#),
            "{reply}"
        );
        reply.clear();
        assert_eq!(
            f.replies.read_line(&mut reply).unwrap(),
            0,
            "the server closed"
        );
    }

    #[test]
    fn profile_waits_for_the_boot_vcpu() {
        let mut f = Fixture::new("profile", 1, 0);
        assert!(f
            .ask(r#"{"v":1,"op":"profile"}"#)
            .starts_with(r#"{"v":1,"ok":false,"code":"not_ready""#));
        f.cell
            .complete(|p| p.cpu.ident = Some("0x61".into()))
            .unwrap();
        let reply = f.ask(r#"{"v":1,"op":"profile"}"#);
        assert!(
            reply.starts_with(r#"{"v":1,"ok":true,"profile":{"profile_version":1,"#),
            "{reply}"
        );
        assert!(reply.contains(r#""ident":"0x61""#), "{reply}");
    }

    // The stop must end the run even when the VM is paused, and say so.
    #[test]
    fn stop_ends_a_paused_run() {
        let mut f = Fixture::new("stop", 2, 0);
        f.ask(r#"{"v":1,"op":"pause"}"#);
        assert_eq!(
            f.ask(r#"{"v":1,"op":"stop"}"#),
            r#"{"v":1,"ok":true,"state":"stopping"}"#
        );
        assert!(!f.vcpus.is_running());
        assert!(matches!(
            f.vcpus.outcome(),
            Outcome::Stopped(Stop::Requested)
        ));
        for fake in f.fake_vcpus.drain(..) {
            fake.join().unwrap();
        }
        assert!(f
            .ask(r#"{"v":1,"op":"resume"}"#)
            .starts_with(r#"{"v":1,"ok":false,"code":"stopped""#));
    }

    // A client that hangs up while the VM is paused leaves it paused, and the
    // next client finds it so.
    #[test]
    fn a_pause_outlives_its_connection() {
        let mut f = Fixture::new("reconnect", 1, 0);
        f.ask(r#"{"v":1,"op":"pause"}"#);
        f.client.shutdown(std::net::Shutdown::Both).unwrap();
        let mut client = UnixStream::connect(&f.path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(b"{\"v\":1,\"op\":\"status\"}\n").unwrap();
        let mut reply = String::new();
        std::io::BufReader::new(client)
            .read_line(&mut reply)
            .unwrap();
        assert!(reply.contains(r#""state":"paused""#), "{reply}");
    }

    /// Waits up to 5 s for the VM to stop, failing with `why` if it does not.
    /// The Fixture stops the vCPUs itself when dropped, so a test asks before.
    fn assert_stops(vcpus: &Vcpus<NoKick>, why: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while vcpus.is_running() {
            assert!(Instant::now() < deadline, "{why}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // A fire-and-forget client writes stop and hangs up before the reply. The
    // stop is already recorded by then, so if it were not carried out every
    // later stop would be answered `stopping` and do nothing.
    #[test]
    fn a_stop_whose_client_hung_up_still_stops() {
        let f = Fixture::new("hangup", 1, 0);
        // The server serves one connection at a time.
        f.client.shutdown(std::net::Shutdown::Both).unwrap();
        let mut c = UnixStream::connect(&f.path).unwrap();
        c.write_all(b"{\"v\":1,\"op\":\"stop\"}\n").unwrap();
        c.shutdown(std::net::Shutdown::Both).unwrap();
        drop(c);
        assert_stops(&f.vcpus, "a stop whose client hung up never stopped the VM");
        assert!(matches!(
            f.vcpus.outcome(),
            Outcome::Stopped(Stop::Requested)
        ));
    }

    // A last request without its newline, before the client half-closes, is
    // served like any other.
    #[test]
    fn an_unterminated_last_line_is_served() {
        let mut f = Fixture::new("eof", 1, 0);
        f.client.write_all(br#"{"v":1,"op":"stop"}"#).unwrap();
        f.client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        f.replies.read_line(&mut reply).unwrap();
        assert_eq!(reply, "{\"v\":1,\"ok\":true,\"state\":\"stopping\"}\n");
        assert_stops(&f.vcpus, "the unterminated stop was dropped");
    }

    // An I/O thread that stays inside the gate fails the pause before any
    // vCPU is asked to park, and the gate opens again.
    #[test]
    fn a_busy_io_thread_times_the_pause_out_with_the_vcpus_running() {
        let mut f = Fixture::new("gate", 1, 0);
        let token = f.source.token();
        let inside = token.enter();
        let reply = f.ask(r#"{"v":1,"op":"pause"}"#);
        assert!(
            reply.starts_with(
                r#"{"v":1,"ok":false,"code":"timeout","error":"1 I/O thread(s) still busy"#
            ),
            "{reply}"
        );
        assert!(!f.source.gate().is_paused(), "the gate stayed closed");
        assert_eq!(f.vcpus.parked(), 0);
        drop(inside);
        assert_eq!(
            f.ask(r#"{"v":1,"op":"status"}"#),
            r#"{"v":1,"ok":true,"state":"running","vcpus":1,"vcpus_parked":0}"#
        );
    }

    // A plugin's pause and the socket's are kept out of each other: the socket
    // refuses while a plugin holds the vCPUs and leaves the gate open.
    #[test]
    fn a_plugin_pause_makes_the_socket_busy() {
        let mut f = Fixture::new("busy", 2, 0);
        // As cpu0 would, it waits for every started vCPU but one.
        assert!(f.vcpus.pause(), "the plugin's pause");
        let reply = f.ask(r#"{"v":1,"op":"pause"}"#);
        assert!(
            reply.starts_with(r#"{"v":1,"ok":false,"code":"busy""#),
            "{reply}"
        );
        assert!(!f.source.gate().is_paused(), "the gate stayed closed");
        f.vcpus.resume();
        assert_eq!(
            f.ask(r#"{"v":1,"op":"pause"}"#),
            r#"{"v":1,"ok":true,"state":"paused"}"#
        );
    }

    // A profile asked before the boot vCPU starts must not hold the server
    // past the stop, whose join has a shorter deadline.
    #[test]
    fn a_wait_for_the_profile_ends_with_the_stop() {
        let mut f = Fixture::new("profile-stop", 1, 0);
        let vcpus = Arc::clone(&f.vcpus);
        let stopper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            vcpus.stop();
        });
        let reply = f.ask(r#"{"v":1,"op":"profile"}"#);
        stopper.join().unwrap();
        assert!(
            reply.starts_with(r#"{"v":1,"ok":false,"code":"stopped""#),
            "{reply}"
        );
    }

    // A stale socket from an earlier run is replaced; a file that happens to
    // be at a mistyped path is left alone.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn bind_replaces_only_a_socket() {
        let dir = std::env::temp_dir();
        let cell = || {
            Arc::new(
                ProfileCell::new(MachineProfile::for_this_host("aarch64", "hvf"), None).unwrap(),
            )
        };
        let stale = dir.join(format!("hvi-ctl-{}-stale.sock", std::process::id()));
        drop(UnixListener::bind(&stale).unwrap());
        drop(ControlSocket::bind(stale.to_str().unwrap(), cell(), None).expect("a stale socket"));
        let _ = std::fs::remove_file(&stale);

        let file = dir.join(format!("hvi-ctl-{}-disk.img", std::process::id()));
        std::fs::write(&file, b"guest disk").unwrap();
        let err = ControlSocket::bind(file.to_str().unwrap(), cell(), None)
            .err()
            .expect("a regular file");
        assert!(err.to_string().contains("is not a socket"), "{err}");
        assert_eq!(std::fs::read(&file).unwrap(), b"guest disk");
        let _ = std::fs::remove_file(&file);
    }

    /// Parses a reply line.
    fn reply(line: &str) -> serde_json::Value {
        serde_json::from_str(line).unwrap_or_else(|e| panic!("{line}: {e}"))
    }

    #[test]
    fn a_checkpoint_then_continue_resumes_the_vm() {
        let mut f = Fixture::with(
            "ck-continue",
            Spec {
                parking: 2,
                unstarted: 1,
                capture: true,
                ..Spec::default()
            },
        );
        let line = f.checkpoint("ck", "continue");
        let r = reply(&line);
        assert_eq!(r["ok"], true, "{line}");
        assert_eq!(r["state"], "running");
        let dir = f.root.join("ck");
        assert_eq!(r["dir"], dir.display().to_string());
        assert_eq!(r["stats"]["ram_total_bytes"], 1 << 20);
        assert_eq!(r["stats"]["ram_present_bytes"], 4096);
        assert!(r["stats"]["bundle_bytes"].as_u64().unwrap() > 4096);
        for key in ["pause_ms", "capture_ms"] {
            assert!(r["stats"][key].is_u64(), "{key}: {line}");
        }
        f.assert_running();
        assert_eq!(
            f.ask(r#"{"v":1,"op":"status"}"#),
            r#"{"v":1,"ok":true,"state":"running","vcpus":2,"vcpus_parked":0}"#
        );
        let verified = crate::checkpoint::bundle::verify(&dir).unwrap();
        assert_eq!(verified.manifest_sha256, r["manifest_sha256"]);
        let bundle = crate::checkpoint::bundle::Bundle::open(&dir).unwrap();
        let cpu = bundle.cpu().unwrap();
        assert_eq!(cpu.vcpus.len(), 3);
        // The secondary the guest never started is recorded as off.
        let off = serde_json::to_value(&cpu.vcpus[2]).unwrap();
        assert_eq!(off["power"], "off", "{off}");
        let session = bundle.session().unwrap();
        assert_eq!(
            (
                session.sandbox_id.as_str(),
                session.txid.as_deref(),
                session.epoch
            ),
            ("fixture", Some("t-ck"), 2)
        );
        // A second capture into the same directory is refused, VM untouched.
        let again = reply(&f.checkpoint("ck", "continue"));
        assert_eq!(again["code"], "refused", "{again}");
        f.assert_running();
    }

    // A secondary the guest asked to start, whose thread had not taken the
    // request, is neither off nor running: the restore must start it as the
    // request would have.
    #[test]
    fn a_secondary_waiting_for_its_start_is_written_pending_on() {
        let mut f = Fixture::with(
            "ck-pending",
            Spec {
                parking: 1,
                unstarted: 2,
                pending: Some((2, 0x4008_0000, 0x77)),
                capture: true,
                ..Spec::default()
            },
        );
        let line = f.checkpoint("ck", "fence");
        assert_eq!(reply(&line)["ok"], true, "{line}");
        let bundle = crate::checkpoint::bundle::Bundle::open(&f.root.join("ck")).unwrap();
        let cpu = serde_json::to_value(bundle.cpu().unwrap()).unwrap();
        assert_eq!(cpu["vcpus"][1]["power"], "off", "{cpu}");
        assert_eq!(
            cpu["vcpus"][2]["power"],
            serde_json::json!({"pending_on": {"entry": "0x40080000", "ctx": "0x77"}}),
            "{cpu}"
        );
        // The fixture's vCPUs read no platform, as the KVM backends do.
        let platform = bundle.platform().unwrap();
        assert!(platform.is_partial());
        assert!(bundle.manifest().capabilities.is_empty());
    }

    // `hvi restore` hands the socket a VM whose vCPUs imported their states
    // step by step and wait parked, and whose I/O threads are held. Nothing
    // runs until `resume`, and `stop` still ends it from there.
    #[test]
    fn a_restored_vm_waits_restored_paused_until_resume() {
        let mut f = Fixture::with(
            "restored",
            Spec {
                parking: 2,
                unstarted: 1,
                restore: true,
                capture: true,
                ..Spec::default()
            },
        );
        crate::checkpoint::restore::tests::assert_barriers(&f.log.lock().unwrap(), 2);
        assert_eq!(
            f.ask(r#"{"v":1,"op":"status"}"#),
            r#"{"v":1,"ok":true,"state":"restored-paused","vcpus":2,"vcpus_parked":2}"#
        );
        assert!(
            f.source.gate().is_paused(),
            "the I/O threads ran before resume"
        );
        assert_eq!(
            f.ask(r#"{"v":1,"op":"pause"}"#),
            r#"{"v":1,"ok":true,"state":"restored-paused"}"#
        );
        // A restored VM is a VM: it can be captured before it ever runs, and
        // the capture leaves it as it found it.
        let line = f.checkpoint("again", "continue");
        assert_eq!(reply(&line)["state"], "restored-paused", "{line}");
        assert_eq!(f.vcpus.parked(), 2);
        assert_eq!(
            f.ask(r#"{"v":1,"op":"resume"}"#),
            r#"{"v":1,"ok":true,"state":"running"}"#
        );
        f.assert_running();
        assert_eq!(
            f.ask(r#"{"v":1,"op":"stop"}"#),
            r#"{"v":1,"ok":true,"state":"stopping"}"#
        );
        assert_stops(&f.vcpus, "the restored VM did not stop");
    }

    #[test]
    fn a_restored_vm_stops_without_ever_running() {
        let mut f = Fixture::with(
            "restored-stop",
            Spec {
                parking: 1,
                restore: true,
                ..Spec::default()
            },
        );
        assert_eq!(
            f.ask(r#"{"v":1,"op":"stop"}"#),
            r#"{"v":1,"ok":true,"state":"stopping"}"#
        );
        assert_stops(&f.vcpus, "the restored VM did not stop");
        assert!(
            f.source.gate().is_paused(),
            "the stop released the I/O threads"
        );
    }

    // The source's half of a move: once captured it must never run again,
    // whatever a client asks, until it is stopped.
    #[test]
    fn a_checkpoint_then_fence_keeps_the_vm_parked_for_good() {
        let mut f = Fixture::with(
            "ck-fence",
            Spec {
                parking: 2,
                capture: true,
                ..Spec::default()
            },
        );
        let line = f.checkpoint("ck", "fence");
        assert_eq!(reply(&line)["state"], "fenced", "{line}");
        assert_eq!(
            f.ask(r#"{"v":1,"op":"status"}"#),
            r#"{"v":1,"ok":true,"state":"fenced","vcpus":2,"vcpus_parked":2}"#
        );
        assert!(f.source.gate().is_paused());
        assert_eq!(
            f.ask(r#"{"v":1,"op":"resume"}"#),
            r#"{"v":1,"ok":false,"code":"fenced","error":"the VM was fenced after a checkpoint"}"#
        );
        assert_eq!(reply(&f.checkpoint("ck2", "continue"))["code"], "fenced");
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(f.vcpus.parked(), 2, "a vCPU ran after the fence");
        assert_eq!(
            f.ask(r#"{"v":1,"op":"stop"}"#),
            r#"{"v":1,"ok":true,"state":"stopping"}"#
        );
        assert_stops(&f.vcpus, "the fenced VM did not stop");
        crate::checkpoint::bundle::verify(&f.root.join("ck")).unwrap();
    }

    // A move's restore opens the disk while the fenced source still runs,
    // and nothing else may open a disk whose guest can still write it.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn only_a_sealed_fence_releases_the_disk() {
        let disk =
            std::env::temp_dir().join(format!("hvi-ctl-{}-fenced-disk.img", std::process::id()));
        std::fs::write(&disk, [0u8; 4096]).unwrap();
        let path = disk.to_str().unwrap().to_string();
        let locked = || {
            crate::devices::virtio::block::VirtioBlk::open(&path)
                .map(drop)
                .err()
                .map(|e| e.kind())
                == Some(std::io::ErrorKind::WouldBlock)
        };
        {
            let mut f = Fixture::with(
                "ck-disk-fail",
                Spec {
                    parking: 2,
                    capture: true,
                    disk: Some(path.clone()),
                    fail_after: Some(Component::Cpu),
                    ..Spec::default()
                },
            );
            assert!(locked(), "a running guest's disk was not locked");
            assert_eq!(
                reply(&f.checkpoint("ck", "fence"))["code"],
                "capture_failed"
            );
            assert!(locked(), "a fence that failed released the disk");
        }
        assert!(!locked(), "the stopped source kept the disk");
        let mut f = Fixture::with(
            "ck-disk",
            Spec {
                parking: 2,
                capture: true,
                disk: Some(path.clone()),
                ..Spec::default()
            },
        );
        assert_eq!(reply(&f.checkpoint("ck", "continue"))["ok"], true);
        assert!(locked(), "a checkpoint that continues released the disk");
        assert_eq!(reply(&f.checkpoint("ck2", "fence"))["state"], "fenced");
        assert!(!locked(), "the fenced source kept the disk");
        drop(f);
        let _ = std::fs::remove_file(&disk);
    }

    // The temp dir is behind a link on macOS (/var is /private/var). A caller
    // that names its bundles the way it named the root at boot must not be
    // told they are outside it, and the bundle must land in the resolved
    // tree the confinement grants.
    #[test]
    fn a_bundle_named_from_the_root_as_given_is_written_below_it() {
        let mut f = Fixture::with(
            "ck-spelling",
            Spec {
                parking: 1,
                capture: true,
                ..Spec::default()
            },
        );
        let dir = f.given_root.join("ck");
        let line = f.ask(&format!(
            r#"{{"v":1,"op":"checkpoint","dir":"{}"}}"#,
            dir.display()
        ));
        let r = reply(&line);
        assert_eq!(r["ok"], true, "{line}");
        assert_eq!(r["dir"], f.root.join("ck").display().to_string());
        crate::checkpoint::bundle::verify(&f.root.join("ck")).unwrap();
    }

    // A client that paused first finds the VM still paused after a capture
    // with then=continue: the capture does not resume what it did not pause.
    #[test]
    fn a_checkpoint_of_a_paused_vm_leaves_it_paused() {
        let mut f = Fixture::with(
            "ck-paused",
            Spec {
                parking: 2,
                capture: true,
                ..Spec::default()
            },
        );
        f.ask(r#"{"v":1,"op":"pause"}"#);
        let line = f.checkpoint("ck", "continue");
        assert_eq!(reply(&line)["state"], "paused", "{line}");
        assert_eq!(
            f.ask(r#"{"v":1,"op":"status"}"#),
            r#"{"v":1,"ok":true,"state":"paused","vcpus":2,"vcpus_parked":2}"#
        );
        assert_eq!(
            f.ask(r#"{"v":1,"op":"resume"}"#),
            r#"{"v":1,"ok":true,"state":"running"}"#
        );
        f.assert_running();
        crate::checkpoint::bundle::verify(&f.root.join("ck")).unwrap();
    }

    // Each of these is refused before anything is paused, and leaves nothing
    // on disk.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn refused_checkpoints_never_pause_the_vm() {
        let mut f = Fixture::with(
            "ck-refused",
            Spec {
                parking: 1,
                capture: true,
                ..Spec::default()
            },
        );
        let refused = |f: &mut Fixture, line: &str, want: &str| {
            let r = reply(&f.ask(line));
            assert_eq!(r["code"], "refused", "{r}");
            assert!(r["error"].as_str().unwrap().contains(want), "{r}");
            assert_eq!(f.vcpus.parked(), 0);
            assert!(!f.source.gate().is_paused());
        };
        refused(
            &mut f,
            r#"{"v":1,"op":"checkpoint","dir":"/etc/ck"}"#,
            "not below the checkpoint root",
        );
        refused(
            &mut f,
            r#"{"v":1,"op":"checkpoint","dir":"ck"}"#,
            "absolute",
        );
        let busy = f.root.join("busy");
        std::fs::create_dir(&busy).unwrap();
        std::fs::write(busy.join("x"), b"x").unwrap();
        refused(
            &mut f,
            &format!(r#"{{"v":1,"op":"checkpoint","dir":"{}"}}"#, busy.display()),
            "not empty",
        );

        let mut shares = Fixture::with(
            "ck-shares",
            Spec {
                parking: 1,
                capture: true,
                fs_shares: 1,
                ..Spec::default()
            },
        );
        let dir = shares.root.join("ck");
        refused(
            &mut shares,
            &format!(r#"{{"v":1,"op":"checkpoint","dir":"{}"}}"#, dir.display()),
            "virtio-fs share",
        );
        assert!(
            std::fs::symlink_metadata(&dir).is_err(),
            "a refusal left a directory"
        );

        let mut portable = Fixture::with(
            "ck-portable",
            Spec {
                parking: 1,
                capture: true,
                machine: Some("portable-arm64-v1"),
                ..Spec::default()
            },
        );
        let dir = portable.root.join("ck");
        refused(
            &mut portable,
            &format!(r#"{{"v":1,"op":"checkpoint","dir":"{}"}}"#, dir.display()),
            "the portable-arm64-v1 machine profile, which no backend checkpoints yet",
        );
        assert!(
            std::fs::symlink_metadata(&dir).is_err(),
            "a refusal left a directory"
        );
    }

    // A vCPU that never parks fails the capture in time, and the VM runs on.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_checkpoint_that_times_out_leaves_the_vm_running() {
        let mut f = Fixture::with(
            "ck-timeout",
            Spec {
                parking: 1,
                stuck: 1,
                capture: true,
                ..Spec::default()
            },
        );
        let r = reply(&f.checkpoint("ck", "fence"));
        assert_eq!(r["code"], "timeout", "{r}");
        f.assert_running();
        assert!(
            std::fs::symlink_metadata(f.root.join("ck")).is_err(),
            "the failed capture left its directory"
        );
        assert!(f
            .ask(r#"{"v":1,"op":"status"}"#)
            .contains(r#""state":"running""#));
    }

    // A device state a restore would refuse must fail the capture while the
    // guest can still run on: here a net queue whose rings lie outside the
    // RAM the capture holds.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_device_state_a_restore_would_refuse_leaves_the_vm_running() {
        use crate::devices::virtio::mmio;
        use crate::devices::virtio::net::VirtioNet;
        let elsewhere = GuestRam::from_ranges(&[(0x8000_0000, 1 << 20)]);
        let mut net = VirtioNet::new();
        let base = 0x8000_0000u64;
        net.mmio(&elsewhere, mmio::QUEUE_SEL, true, 0);
        net.mmio(&elsewhere, mmio::QUEUE_NUM, true, 16);
        net.mmio(&elsewhere, mmio::QUEUE_DESC_LOW, true, base);
        net.mmio(&elsewhere, mmio::QUEUE_DRIVER_LOW, true, base + 0x1000);
        net.mmio(&elsewhere, mmio::QUEUE_DEVICE_LOW, true, base + 0x2000);
        net.mmio(&elsewhere, mmio::QUEUE_READY, true, 1);
        assert!(
            net.state().check(&elsewhere).is_ok(),
            "the state is good over the RAM its rings are in"
        );
        let mut f = Fixture::with(
            "ck-device",
            Spec {
                parking: 2,
                capture: true,
                net: Some(Arc::new(std::sync::Mutex::new(net))),
                ..Spec::default()
            },
        );
        let r = reply(&f.checkpoint("ck", "fence"));
        assert_eq!(r["code"], "capture_failed", "{r}");
        assert!(
            r["error"]
                .as_str()
                .unwrap()
                .contains("a restore would refuse the device state"),
            "{r}"
        );
        f.assert_running();
        assert!(f
            .ask(r#"{"v":1,"op":"status"}"#)
            .contains(r#""state":"running""#));
        assert!(
            std::fs::symlink_metadata(f.root.join("ck")).is_err(),
            "the refused capture left its directory"
        );
    }

    /// Lists what is in `dir`, or `None` when it is gone.
    #[allow(clippy::disallowed_methods)]
    fn listing(dir: &std::path::Path) -> Option<Vec<std::ffi::OsString>> {
        let entries = std::fs::read_dir(dir).ok()?;
        Some(entries.map(|e| e.unwrap().file_name()).collect())
    }

    // A write that fails part way, on a running VM, leaves it running and
    // leaves no file behind: the directory the capture created goes, and one
    // the caller made stays, empty.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_failed_write_leaves_the_vm_running_and_nothing_on_disk() {
        let mut f = Fixture::with(
            "ck-write",
            Spec {
                parking: 2,
                capture: true,
                fail_after: Some(Component::Cpu),
                ..Spec::default()
            },
        );
        let r = reply(&f.checkpoint("ck", "fence"));
        assert_eq!(r["code"], "capture_failed", "{r}");
        assert!(
            r["error"].as_str().unwrap().contains("after cpu.json"),
            "{r}"
        );
        f.assert_running();
        assert!(f
            .ask(r#"{"v":1,"op":"status"}"#)
            .contains(r#""state":"running""#));
        assert_eq!(listing(&f.root.join("ck")), None, "the directory stayed");

        std::fs::create_dir(f.root.join("made")).unwrap();
        let r = reply(&f.checkpoint("made", "continue"));
        assert_eq!(r["code"], "capture_failed", "{r}");
        f.assert_running();
        assert_eq!(listing(&f.root.join("made")), Some(Vec::new()));
    }

    // A capture that fails after a client paused the VM must leave it
    // paused, every vCPU parked, not resume what it did not pause.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_failed_capture_of_a_paused_vm_leaves_it_paused() {
        let mut f = Fixture::with(
            "ck-paused-fail",
            Spec {
                parking: 2,
                capture: true,
                fail_after: Some(Component::Devices),
                ..Spec::default()
            },
        );
        assert_eq!(
            f.ask(r#"{"v":1,"op":"pause"}"#),
            r#"{"v":1,"ok":true,"state":"paused"}"#
        );
        let r = reply(&f.checkpoint("ck", "continue"));
        assert_eq!(r["code"], "capture_failed", "{r}");
        assert_eq!(
            f.ask(r#"{"v":1,"op":"status"}"#),
            r#"{"v":1,"ok":true,"state":"paused","vcpus":2,"vcpus_parked":2}"#
        );
        assert!(f.source.gate().is_paused(), "the gate was opened");
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(f.vcpus.parked(), 2, "a vCPU ran after the failed capture");
        assert_eq!(listing(&f.root.join("ck")), None, "the directory stayed");
        assert_eq!(
            f.ask(r#"{"v":1,"op":"resume"}"#),
            r#"{"v":1,"ok":true,"state":"running"}"#
        );
        f.assert_running();
    }

    // A stop of the run during the capture ends it with `stopped`, and the
    // half-written bundle is removed.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_stop_during_the_capture_ends_it_and_removes_the_bundle() {
        let mut f = Fixture::with(
            "ck-stop",
            Spec {
                parking: 2,
                capture: true,
                stop_after: Some(Component::Profile),
                ..Spec::default()
            },
        );
        let r = reply(&f.checkpoint("ck", "continue"));
        assert_eq!(r["code"], "stopped", "{r}");
        assert!(
            r["error"].as_str().unwrap().contains("the run is stopping"),
            "{r}"
        );
        assert_eq!(listing(&f.root.join("ck")), None, "the directory stayed");
        assert_stops(&f.vcpus, "the run did not stop");
    }

    #[test]
    fn the_server_ends_with_the_stop() {
        let mut f = Fixture::new("end", 1, 0);
        f.source.request_stop();
        let server = f.server.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !server.is_finished() {
            assert!(Instant::now() < deadline, "the server ignored the stop");
            std::thread::sleep(Duration::from_millis(1));
        }
        server.join().unwrap();
    }
}

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
//!
//! `migrate` writes the same capture as a stream on the connection that
//! asked for it, with no file: the RAM rounds of [`migrate`] while the
//! guest runs, then the pause as for `checkpoint`, the final RAM round and
//! the documents with the guest still, and the manifest. Only this thread
//! writes, so a slow reader holds it up and never the guest; the pause
//! starts once the last round with the guest running has been written. A
//! failure before the manifest leaves the VM as the request found it, as a
//! `checkpoint`'s does, and the client reads the failure as a reply line
//! where a frame header was due. `then: "fence"` fences the VM once the
//! manifest is written to the connection, which is before the client has
//! read it. A fenced VM is never streamed again: the fence released its
//! disk, and the destination may already run it.
//!
//! `disk-dirty` and `disk-blocks` read the disk for a move, in any state but
//! stopping, and need a disk and the checkpoint root. `disk-blocks` streams
//! its batches on the connection before its reply, see
//! [`disk`].

use std::cell::Cell;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::checkpoint::bundle::{resolve_in_root, unix_ms, BundleWriter};
use crate::checkpoint::capture::{self, Capture, Console};
use crate::checkpoint::control::{
    format_response, parse_request, BlockSelection, CheckpointStats, DiskBlocksReply,
    DiskDirtyReply, Error, ErrorCode, Migrate, MigrateStats, Request, Response, Then, VmState,
    MAX_LINE,
};
use crate::checkpoint::cpu::{CpuState, Output, VcpuState};
use crate::checkpoint::disk;
use crate::checkpoint::migrate::{self, Policy, Tracker};
use crate::checkpoint::platform::{base64_encode, PlatformState};
use crate::checkpoint::profile::this_build;
use crate::checkpoint::profile::{MachineProfile, ProfileCell};
use crate::checkpoint::stream::StreamWriter;
use crate::config::Stop;
use crate::devices::virtio::block::{DirtySince, VirtioBlk, DIRTY_BLOCK_BYTES};
use crate::devices::virtio::vsock::retry_read;
use crate::hypervisor::guest::Guest;
use crate::hypervisor::vcpus::{Kick, PauseError, Vcpus, WorkResult};
use crate::sync::lock_or_recover;
use crate::teardown::{PauseGate, StopToken, Writable};
use crate::LOG_PREFIX;

/// How long a pause waits for the I/O threads and the vCPUs together, and how
/// long `profile` waits for the profile to be complete. No request waits
/// longer, so a client that allows a little more than this for a reply never
/// gives up on a pause that later succeeds.
pub(crate) const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a `migrate` waits for its reader to take a byte, with the guest
/// running or paused. A reader that has stopped reading without closing the
/// connection would otherwise hold the control thread, and a paused guest,
/// for as long as it stays stuck.
const STREAM_STALL: Duration = Duration::from_secs(30);

/// The least time a `migrate` gives the part of its stream written with the
/// guest paused, before it gives up and the guest runs on. See
/// [`StreamLimits::paused_budget`].
const STREAM_PAUSED_FLOOR: Duration = Duration::from_secs(10);

/// How long a `migrate` may wait on its reader.
#[derive(Clone, Copy, Debug)]
struct StreamLimits {
    /// The longest one write waits for the reader to take a byte.
    stall: Duration,
    /// The least time the paused part of the stream is given.
    paused_floor: Duration,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            stall: STREAM_STALL,
            paused_floor: STREAM_PAUSED_FLOOR,
        }
    }
}

impl StreamLimits {
    /// Returns how long the stream may take from the pause to the manifest,
    /// given how long the last round with the guest running took.
    ///
    /// The final round holds what the guest wrote during that round, so it
    /// is at most about as large, and the reader took that round at the rate
    /// it can. Twice that time, plus the floor for the pause, the documents
    /// and a reader's hiccup, bounds a healthy final round. A reader that
    /// stops taking the stream then costs the guest at most this pause.
    fn paused_budget(&self, last_round: Duration) -> Duration {
        self.paused_floor
            .saturating_add(last_round.saturating_mul(2))
    }
}

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
    // The x86-64 restore does not exist yet.
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    pub(crate) fn restored(mut self) -> Self {
        self.initial = VmState::RestoredPaused;
        self
    }

    /// Returns what a `checkpoint` or a `migrate` captures of `guest`, when
    /// the backend said how. A `checkpoint` needs a checkpoint root as well;
    /// a `migrate` writes no file.
    pub(crate) fn capture_of<K>(&self, guest: &Guest<K>) -> Option<Capture> {
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
            write_log: guest.write_log.clone(),
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
        self.run_with(
            stop,
            gate,
            vcpus,
            capture,
            CONTROL_TIMEOUT,
            StreamLimits::default(),
        );
    }

    /// [`run`](Self::run), with `timeout` for each wait and `stream` for a
    /// `migrate`'s waits on its reader.
    fn run_with<K: Kick>(
        self,
        stop: &StopToken,
        gate: &PauseGate,
        vcpus: &Vcpus<K>,
        capture: Option<Capture>,
        timeout: Duration,
        stream: StreamLimits,
    ) {
        let mut machine = Machine {
            state: self.initial,
            gate,
            vcpus,
            profile: &self.profile,
            capture,
            root: self.checkpoint_root.clone(),
            timeout,
            stream,
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
        // The stream goes on this connection, ahead of the reply. Its reader
        // may be the reason the stream failed, so the reply waits for it
        // only as long as a pause would, and the connection is closed if
        // the reply does not fit by then.
        Ok(Request::Migrate(request)) => {
            let response = machine.migrate(conn, stop, &request);
            let none = Cell::new(None);
            return SocketOut::new(conn, stop, machine.timeout, &none).send(&response);
        }
        Ok(Request::DiskBlocks(selection)) => return machine.disk_blocks(conn, stop, selection),
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
    write_all(conn, stop, line.as_bytes()).map(|_| ())
}

/// Writes `bytes` to `conn`, waiting for room beside the stop token.
/// Returns false when the stop came first.
fn write_all(conn: &mut UnixStream, stop: &StopToken, bytes: &[u8]) -> std::io::Result<bool> {
    let mut rest = bytes;
    while !rest.is_empty() {
        match conn.write(rest) {
            Ok(n) => rest = &rest[n..],
            Err(e) if retry_read(&e) => {
                if !stop.wait_writable(conn.as_fd())? {
                    return Ok(false);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// The control connection as a writer for a stream: it waits for room
/// beside the stop token, and gives up on a reader that takes nothing.
struct SocketOut<'a> {
    /// The connection, non-blocking.
    conn: &'a mut UnixStream,
    /// The stop, which ends a wait for room.
    stop: &'a StopToken,
    /// The longest one write waits for the reader to take a byte.
    stall: Duration,
    /// When every write fails, however the reader keeps up. The server sets
    /// it at the pause, while the stream holds this writer.
    deadline: &'a Cell<Option<Instant>>,
}

impl<'a> SocketOut<'a> {
    /// Wraps `conn`, with `stall` for each write and `deadline` for all.
    fn new(
        conn: &'a mut UnixStream,
        stop: &'a StopToken,
        stall: Duration,
        deadline: &'a Cell<Option<Instant>>,
    ) -> Self {
        Self {
            conn,
            stop,
            stall,
            deadline,
        }
    }

    /// Writes `response` and its newline.
    fn send(&mut self, response: &Response) -> std::io::Result<()> {
        self.write_all((format_response(response) + "\n").as_bytes())
    }
}

impl Write for SocketOut<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // The stall counts from this call, so the time the stream spends
        // reading and compressing RAM between writes is not the reader's.
        let stalled_at = Instant::now() + self.stall;
        let until = self
            .deadline
            .get()
            .map_or(stalled_at, |d| d.min(stalled_at));
        loop {
            match self.conn.write(buf) {
                Ok(n) => return Ok(n),
                Err(e) if retry_read(&e) => {
                    match self.stop.wait_writable_until(self.conn.as_fd(), until)? {
                        Writable::Ready => {}
                        // Not `Interrupted`, which `write_all` retries: the
                        // retry would find the stop again at once, and spin
                        // on it for as long as the reader stays stuck.
                        Writable::Stopped => {
                            return Err(std::io::Error::other("the run is stopping"))
                        }
                        Writable::TimedOut if until < stalled_at => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "the reader did not take the stream within the time the \
                                 guest may stay paused",
                            ))
                        }
                        Writable::TimedOut => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                format!(
                                    "the reader took nothing for {} ms",
                                    self.stall.as_millis()
                                ),
                            ))
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
                vcpus.set_stop_reason(Stop::Requested);
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
    /// What a `checkpoint` or a `migrate` captures.
    capture: Option<Capture>,
    /// The root a `checkpoint` writes under.
    root: Option<CheckpointRoot>,
    /// The deadline of each wait, [`CONTROL_TIMEOUT`] outside the tests.
    timeout: Duration,
    /// How long a `migrate` waits on its reader.
    stream: StreamLimits,
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
            Request::DiskDirty(since) => self.disk_dirty(since),
            // `answer` serves these, since they stream on the connection.
            Request::Migrate(_) => refuse(ErrorCode::BadRequest, "migrate needs its connection"),
            Request::DiskBlocks(_) => refuse(ErrorCode::BadRequest, "disk-blocks streams"),
        };
        (response, None)
    }

    /// Returns the guest's disk, or the refusal to send when there is none
    /// to read.
    fn disk(&self) -> Result<Arc<Mutex<VirtioBlk>>, Response> {
        if self.state == VmState::Stopping {
            return Err(refuse(ErrorCode::Stopped, "the run is ending"));
        }
        let (Some(capture), Some(_)) = (&self.capture, &self.root) else {
            return Err(refuse(
                ErrorCode::Refused,
                "this run has no checkpoint root; boot it with --checkpoint-root",
            ));
        };
        match &capture.block {
            Some((dev, _)) => Ok(Arc::clone(dev)),
            None => Err(refuse(ErrorCode::Refused, "the guest has no disk")),
        }
    }

    /// Reads the disk blocks written since boot or since the last read, and
    /// starts a round.
    ///
    /// With the guest still, the read is the last round of a move, so the
    /// disk is synced first, as a checkpoint syncs it.
    fn disk_dirty(&mut self, since: DirtySince) -> Response {
        let dev = match self.disk() {
            Ok(dev) => dev,
            Err(refusal) => return refusal,
        };
        let mut dev = lock_or_recover(&dev);
        if self.state != VmState::Running {
            if let Err(e) = dev.sync_data() {
                return refuse(ErrorCode::CaptureFailed, format!("syncing the disk: {e}"));
            }
        }
        let read = dev.read_dirty(since);
        drop(dev);
        match read {
            Ok(read) => Response::DiskDirty(DiskDirtyReply {
                since: match since {
                    DirtySince::Boot => "boot",
                    DirtySince::Round => "round",
                },
                round: read.round,
                block_size: DIRTY_BLOCK_BYTES,
                blocks: read.dirty.blocks(),
                dirty: read.dirty.count(),
                generation: read.generation,
                bitmap_sha256: read.bitmap_sha256,
                bitmap_b64: base64_encode(read.dirty.as_bytes()),
            }),
            Err(e) => refuse(ErrorCode::Refused, e.to_string()),
        }
    }

    /// Streams the disk blocks `selection` names on `conn`, then the reply.
    ///
    /// Every block is checked before the first byte goes out. A block that
    /// cannot be read ends the stream with a `capture_failed` reply; a
    /// connection that fails ends it with nothing more.
    fn disk_blocks(
        &mut self,
        conn: &mut UnixStream,
        stop: &StopToken,
        selection: BlockSelection,
    ) -> std::io::Result<()> {
        if !self.vcpus.is_running() {
            self.state = VmState::Stopping;
        }
        let dev = match self.disk() {
            Ok(dev) => dev,
            Err(refusal) => return send(conn, stop, &refusal),
        };
        let round = match selection {
            BlockSelection::Round(round) => Some(round),
            BlockSelection::Blocks(_) => None,
        };
        let blocks = {
            let dev = lock_or_recover(&dev);
            match selection {
                BlockSelection::Round(round) => match dev.last_round() {
                    Some((last, set)) if last == round => Ok(set.iter().collect()),
                    Some((last, _)) => Err(Error::new(
                        ErrorCode::Refused,
                        format!("round {round} is not the last round read, round {last} is"),
                    )),
                    None => Err(Error::new(
                        ErrorCode::Refused,
                        "no round has been read; ask disk-dirty first",
                    )),
                },
                BlockSelection::Blocks(blocks) => {
                    disk::check_blocks(&blocks, dev.dirty_since_boot().blocks())
                        .map(|()| blocks)
                        .map_err(|e| Error::new(ErrorCode::BadRequest, e))
                }
            }
        };
        let blocks: Vec<u64> = match blocks {
            Ok(blocks) => blocks,
            Err(e) => return send(conn, stop, &Response::Error(e)),
        };
        let mut lost: Option<std::io::Error> = None;
        let exported = disk::export(
            &dev,
            &blocks,
            &mut |bytes| match write_all(conn, stop, bytes) {
                Ok(true) => Ok(()),
                Ok(false) => {
                    let e =
                        std::io::Error::new(std::io::ErrorKind::Interrupted, "the run is ending");
                    lost = Some(std::io::Error::new(e.kind(), e.to_string()));
                    Err(e)
                }
                Err(e) => {
                    lost = Some(std::io::Error::new(e.kind(), e.to_string()));
                    Err(e)
                }
            },
        );
        if let Some(e) = lost {
            return if e.kind() == std::io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(e)
            };
        }
        let response = match exported {
            Ok(sent) => {
                // Every batch is on the connection: the round went out
                // whole, which disk.json records if it is captured later.
                let mut dev = lock_or_recover(&dev);
                if let Some(round) = round {
                    dev.record_sent(round, sent.sent_sha256.clone());
                }
                Response::DiskBlocks(DiskBlocksReply {
                    round,
                    blocks: sent.blocks,
                    bytes: sent.bytes,
                    batches: sent.batches,
                    generation: dev.generation(),
                    max_lock_us: sent.max_lock_us,
                    sent_sha256: sent.sent_sha256,
                })
            }
            Err(e) => refuse(ErrorCode::CaptureFailed, format!("reading the disk: {e}")),
        };
        send(conn, stop, &response)
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
        let (Some(_), Some(root)) = (&self.capture, &self.root) else {
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
            Some(capture) => {
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
                if let Some(capture) = &self.capture {
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

    /// Streams the VM on `conn`: the RAM rounds with the guest running, then
    /// the pause, the final round and the documents, then the manifest. It
    /// returns the reply that follows the manifest, or the refusal that
    /// takes the place of the next frame.
    ///
    /// Everything that can be refused without writing is checked first. A
    /// failure from the first frame to the manifest returns the VM to where
    /// the request found it, and stops the tracking of its writes.
    #[allow(clippy::too_many_lines)]
    fn migrate(&mut self, conn: &mut UnixStream, stop: &StopToken, request: &Migrate) -> Response {
        if !self.vcpus.is_running() {
            self.state = VmState::Stopping;
        }
        match self.state {
            // The fence released the disk, and the destination may run by
            // now. A second stream would hand out another copy that can
            // resume, so a fenced VM is refused here as `checkpoint` refuses
            // it.
            VmState::Fenced => {
                return refuse(ErrorCode::Fenced, "the VM was fenced after a checkpoint")
            }
            VmState::Stopping => return refuse(ErrorCode::Stopped, "the run is ending"),
            VmState::Running | VmState::Paused | VmState::RestoredPaused => {}
        }
        let Some(capture) = self.capture.clone() else {
            return refuse(ErrorCode::Refused, "this run cannot be captured");
        };
        let Some(write_log) = capture.write_log.clone() else {
            return refuse(
                ErrorCode::Refused,
                "this backend does not record the guest's writes to RAM",
            );
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
        let policy = Policy {
            max_rounds: request.max_rounds.unwrap_or(Policy::default().max_rounds),
            max_time: request
                .max_secs
                .map_or(Policy::default().max_time, Duration::from_secs),
            ..Policy::default()
        };
        let ram = Arc::clone(&capture.ram);
        let found = self.state;
        let paused_deadline = Cell::new(None);
        let mut out = SocketOut::new(conn, stop, self.stream.stall, &paused_deadline);
        let mut stream = StreamWriter::new(&mut out);
        if let Err(e) = stream.write_doc("profile.json", profile.to_json().as_bytes()) {
            return refuse(
                ErrorCode::CaptureFailed,
                format!("{e}; the VM is as it was"),
            );
        }
        let tracker = Tracker::new(&ram, &*write_log);
        let vcpus = self.vcpus;
        let stopping = || !vcpus.is_running();
        let started = Instant::now();
        let mut precopy = match migrate::precopy(&mut stream, &ram, &tracker, &policy, &stopping) {
            Ok(precopy) => precopy,
            Err(e) => {
                tracker.stop();
                if !self.vcpus.is_running() {
                    self.state = VmState::Stopping;
                    return refuse(ErrorCode::Stopped, format!("the run is ending: {e}"));
                }
                return refuse(
                    ErrorCode::CaptureFailed,
                    format!("{e}; the VM ran on and is as it was"),
                );
            }
        };
        let precopy_ms = started.elapsed().as_millis() as u64;
        let precopy_end_unix_ms = unix_ms();

        let paused_at = Instant::now();
        let last_round = precopy
            .rounds
            .last()
            .map_or(Duration::ZERO, |r| Duration::from_millis(r.ms));
        paused_deadline.set(Some(paused_at + self.stream.paused_budget(last_round)));
        if found == VmState::Running {
            if let Response::Error(e) = self.pause() {
                tracker.stop();
                return Response::Error(e);
            }
        }
        let exported = match self.export(paused_at + self.timeout) {
            Ok(exported) => exported,
            Err(e) => {
                tracker.stop();
                self.back_to(found);
                return Response::Error(e);
            }
        };
        let pause_ms = paused_at.elapsed().as_millis() as u64;
        let request_doc = capture::Request {
            then: request.then,
            txid: request.txid.as_deref(),
            epoch: request.epoch,
        };
        let sealed = (|| -> std::io::Result<_> {
            let devices = capture.device_states()?;
            let disk = capture.disk_state(&profile)?;
            let last = migrate::final_round(&mut stream, &ram, &tracker, &mut precopy, &stopping)?;
            stream.write_doc(
                "cpu.json",
                &json(&CpuState::new(capture.arch, exported.vcpus))?,
            )?;
            stream.write_doc("platform.json", &json(&exported.platform)?)?;
            stream.write_doc("devices.json", &devices.to_json()?)?;
            if let Some(disk) = &disk {
                stream.write_doc("disk.json", &json(disk)?)?;
            }
            stream.write_doc("session.json", &json(&capture.session(&request_doc))?)?;
            let sealed_at = unix_ms();
            let (_, manifest_sha256) = stream.seal(
                this_build(),
                migrate::regions_of(&ram),
                exported.capabilities,
                sealed_at,
            )?;
            Ok((last, manifest_sha256, sealed_at))
        })();
        // The destination may open the disk as soon as it has read the
        // manifest, so a fence releases the lock first of all.
        if sealed.is_ok() && request.then == Then::Fence {
            self.state = VmState::Fenced;
            capture.release_disk();
        }
        let faults = write_log.fault_stats();
        tracker.stop();
        let (last, manifest_sha256, sealed_at_unix_ms) = match sealed {
            Ok(sealed) => sealed,
            Err(e) => {
                if !self.vcpus.is_running() {
                    self.state = VmState::Stopping;
                    return refuse(ErrorCode::Stopped, format!("the run is ending: {e}"));
                }
                self.back_to(found);
                return refuse(
                    ErrorCode::CaptureFailed,
                    format!("{e}; the stream is not sealed, and the VM is as it was"),
                );
            }
        };
        let paused_ms = paused_at.elapsed().as_millis() as u64;
        if request.then == Then::Continue {
            self.back_to(found);
        }
        let mut rounds = precopy.rounds;
        rounds.push(last);
        let ram_raw_bytes = rounds.iter().map(migrate::RoundStats::raw_bytes).sum();
        let ram_stream_bytes = rounds.iter().map(|r| r.bytes).sum();
        Response::Migrate {
            state: self.state,
            manifest_sha256,
            stats: Box::new(MigrateStats {
                final_round_bytes: rounds.last().map_or(0, |r| r.bytes),
                rounds,
                stop_reason: precopy.reason,
                threshold_bytes: precopy.threshold_bytes,
                precopy_ms,
                pause_ms,
                paused_ms,
                ram_total_bytes: ram.regions().iter().map(|r| r.size).sum(),
                ram_present_bytes: precopy.present_bytes,
                ram_raw_bytes,
                ram_stream_bytes,
                stream_bytes: stream.written(),
                write_granule: write_log.granule(),
                write_faults: faults.map(|(n, _)| n),
                write_fault_ns: faults.map(|(n, ns)| ns / n.max(1)),
                precopy_end_unix_ms,
                sealed_at_unix_ms,
            }),
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
        let Some(capture) = &self.capture else {
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

/// Returns `doc` as JSON.
fn json<T: serde::Serialize>(doc: &T) -> std::io::Result<Vec<u8>> {
    serde_json::to_vec(doc).map_err(std::io::Error::other)
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
    use crate::memory::GuestRam;
    use crate::plugin::{GuestArch, RegsView};
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
        /// The record of the guest's writes a `migrate` reads.
        write_log: Option<Arc<dyn crate::memory::GuestWriteLog>>,
        /// MiB of pages that do not compress, added to guest RAM after its
        /// first MiB, so a stream of it outgrows a socket's buffer.
        noise_mib: u64,
        /// How long a `migrate` waits on its reader; the real limits when
        /// not set.
        stream: StreamLimits,
        /// A virtio-blk device the capture holds, and its path, in place of
        /// `disk`, so the test can write it as the guest would.
        blk: Option<(Arc<Mutex<VirtioBlk>>, String)>,
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
            ));
            let log = crate::checkpoint::restore::tests::Log::default();
            if spec.restore {
                vcpus.pause_from_control(Duration::ZERO).unwrap();
                source.gate().pause(Duration::ZERO).unwrap();
            }
            let fake_vcpus = (0..spec.parking)
                .filter(|_| !spec.restore)
                .map(|cpu| {
                    vcpus.mark_started();
                    let vcpus = Arc::clone(&vcpus);
                    std::thread::spawn(move || {
                        while vcpus.is_running() {
                            vcpus.checkpoint_with(cpu, |work| match work {
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
                vcpus.mark_started();
            }
            let cell = Arc::new(
                ProfileCell::new(MachineProfile::for_this_host("aarch64", "hvf"), None).unwrap(),
            );
            let ram = Arc::new(GuestRam::from_ranges(&[(
                GPA,
                ((1 + spec.noise_mib) << 20) as usize,
            )]));
            ram.write(GPA + 0x3000, b"guest data").unwrap();
            let mut x = 0x9e37_79b9_7f4a_7c15u64;
            let mut noise = vec![0u8; (spec.noise_mib << 20) as usize];
            for word in noise.chunks_exact_mut(8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                word.copy_from_slice(&x.to_le_bytes());
            }
            ram.write(GPA + (1 << 20), &noise).unwrap();
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
                block: spec.blk.clone().or_else(|| {
                    spec.disk.as_ref().map(|path| {
                        let dev = crate::devices::virtio::block::VirtioBlk::open(path).unwrap();
                        (Arc::new(std::sync::Mutex::new(dev)), path.clone())
                    })
                }),
                net: spec.net.clone(),
                vsock: None,
                console: Console::None,
                write_log: spec.write_log.clone(),
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
                let (stop, gate, vcpus, stream) = (
                    source.token(),
                    Arc::clone(source.gate()),
                    Arc::clone(&vcpus),
                    spec.stream,
                );
                // A short deadline, so a test of a timeout is quick.
                std::thread::spawn(move || {
                    socket.run_with(
                        &stop,
                        &gate,
                        &vcpus,
                        capture,
                        Duration::from_millis(200),
                        stream,
                    );
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
        // The vCPU that parked leaves its park on its own thread after the
        // release, so the count reaches 0 a moment after the reply.
        let running = r#"{"v":1,"ok":true,"state":"running","vcpus":2,"vcpus_parked":0}"#;
        let end = Instant::now() + Duration::from_secs(5);
        let mut status = f.ask(r#"{"v":1,"op":"status"}"#);
        while status != running && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
            status = f.ask(r#"{"v":1,"op":"status"}"#);
        }
        assert_eq!(status, running);
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
        assert!(matches!(f.vcpus.stop_reason(), Stop::Requested));
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
        assert!(matches!(f.vcpus.stop_reason(), Stop::Requested));
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
    }

    // The portable machine is captured as the native one is: its profile is
    // no reason to refuse.
    #[test]
    fn a_portable_guest_is_captured() {
        let mut portable = Fixture::with(
            "ck-portable",
            Spec {
                parking: 1,
                capture: true,
                machine: Some("portable-arm64-v1"),
                ..Spec::default()
            },
        );
        let r = reply(&portable.checkpoint("ck", "continue"));
        assert_eq!(r["ok"], true, "{r}");
        portable.assert_running();
        let bundle = crate::checkpoint::bundle::Bundle::open(&portable.root.join("ck")).unwrap();
        assert_eq!(bundle.profile().profile, "portable-arm64-v1");
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

    /// A record of the guest's writes that holds none, and counts its
    /// starts and stops.
    #[derive(Default)]
    struct QuietLog {
        starts: std::sync::atomic::AtomicU32,
        stops: std::sync::atomic::AtomicU32,
    }

    impl crate::memory::GuestWriteLog for QuietLog {
        fn start(&self) -> std::io::Result<()> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn collect(&self, _into: &mut crate::memory::DirtyPages) -> std::io::Result<()> {
            Ok(())
        }
        fn stop(&self) {
            self.stops.fetch_add(1, Ordering::SeqCst);
        }
        fn granule(&self) -> u64 {
            4096
        }
    }

    /// A record of the guest's writes that reports every page written in
    /// every round, as a guest that never stops writing would.
    #[derive(Default)]
    struct BusyLog {
        stops: std::sync::atomic::AtomicU32,
    }

    impl crate::memory::GuestWriteLog for BusyLog {
        fn start(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn collect(&self, into: &mut crate::memory::DirtyPages) -> std::io::Result<()> {
            for index in 0..into.region_count() {
                let (_, pages) = into.region(index).unwrap();
                into.set_range(index, 0, pages);
            }
            Ok(())
        }
        fn stop(&self) {
            self.stops.fetch_add(1, Ordering::SeqCst);
        }
        fn granule(&self) -> u64 {
            4096
        }
    }

    impl Fixture {
        /// Sends `line` and reads frames until the header of `component`,
        /// without its bytes. Returns the headers read, `component`'s last.
        fn read_stream_until(&mut self, line: &str, component: &str) -> Vec<serde_json::Value> {
            self.client.write_all(line.as_bytes()).unwrap();
            self.client.write_all(b"\n").unwrap();
            let mut headers = Vec::new();
            loop {
                let mut header = String::new();
                self.replies.read_line(&mut header).unwrap();
                let value: serde_json::Value = serde_json::from_str(header.trim_end())
                    .unwrap_or_else(|e| panic!("{e}: {header}"));
                let name = value["component"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{header}"));
                let (done, size) = (name == component, value["size"].as_u64().unwrap());
                headers.push(value);
                if done {
                    return headers;
                }
                let mut body = vec![0u8; usize::try_from(size).unwrap()];
                self.replies.read_exact(&mut body).unwrap();
            }
        }

        /// Asks a new connection for the status, as a client would while
        /// this one is stuck.
        fn status_elsewhere(&self) -> serde_json::Value {
            let mut next = UnixStream::connect(&self.path).unwrap();
            next.set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            next.write_all(b"{\"v\":1,\"op\":\"status\"}\n").unwrap();
            let mut line = String::new();
            std::io::BufReader::new(next).read_line(&mut line).unwrap();
            reply(line.trim_end())
        }

        /// Asks for a migrate and reads the stream into fresh guest RAM,
        /// then the reply line after it. Returns what was read, or the
        /// reader's error, and the reply.
        fn migrate(
            &mut self,
            line: &str,
        ) -> (
            std::io::Result<(crate::checkpoint::stream::Received, Arc<GuestRam>)>,
            serde_json::Value,
        ) {
            use crate::checkpoint::stream::{receive, PageSpace, StreamReader};
            self.client.write_all(line.as_bytes()).unwrap();
            self.client.write_all(b"\n").unwrap();
            let ram = Arc::new(GuestRam::from_ranges(&[(GPA, 1 << 20)]));
            let target = Arc::clone(&ram);
            let mut reader = StreamReader::new(&mut self.replies);
            let got = receive(
                &mut reader,
                |_| Ok((PageSpace::new(&migrate::regions_of(&target))?, target)),
                None,
            );
            let reply_line = match &got {
                // A refusal is the line where the next frame header was due,
                // and the reader read it.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {
                    return (
                        Err(std::io::Error::other(e.to_string())),
                        serde_json::Value::Null,
                    )
                }
                _ => {
                    let mut line = String::new();
                    self.replies.read_line(&mut line).unwrap();
                    line
                }
            };
            (got.map(|r| (r, ram)), reply(reply_line.trim_end()))
        }
    }

    #[test]
    fn a_migrate_streams_the_vm_then_fences_it() {
        let log = Arc::new(QuietLog::default());
        let mut f = Fixture::with(
            "mig-fence",
            Spec {
                parking: 2,
                capture: true,
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                ..Spec::default()
            },
        );
        let (got, r) = f.migrate(r#"{"v":1,"op":"migrate","then":"fence","txid":"m1","epoch":4}"#);
        let (received, ram) = got.expect("the stream reads whole");
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["state"], "fenced", "{r}");
        assert_eq!(r["manifest_sha256"], received.manifest_sha256.as_str());
        let mut data = [0u8; 10];
        ram.read(GPA + 0x3000, &mut data).unwrap();
        assert_eq!(&data, b"guest data", "the page came over");
        let stats = &r["stats"];
        assert_eq!(stats["stop_reason"], "converged", "{r}");
        assert_eq!(stats["rounds"].as_array().unwrap().len(), 2, "{r}");
        assert_eq!(stats["rounds"][1]["in_pause"], true, "{r}");
        assert_eq!(stats["ram_present_bytes"], 4096, "{r}");
        assert_eq!(stats["stream_bytes"], received.stream_bytes, "{r}");
        let session: serde_json::Value =
            serde_json::from_slice(received.doc("session.json").unwrap()).unwrap();
        assert_eq!(session["txid"], "m1");
        assert_eq!(session["then"], "fence");
        assert_eq!(log.starts.load(Ordering::SeqCst), 1);
        assert_eq!(log.stops.load(Ordering::SeqCst), 1, "the tracking stopped");
        let status = reply(&f.ask(r#"{"v":1,"op":"status"}"#));
        assert_eq!(status["state"], "fenced");
        assert_eq!(status["vcpus_parked"], 2);
        assert_eq!(reply(&f.ask(r#"{"v":1,"op":"resume"}"#))["code"], "fenced");
    }

    #[test]
    fn a_migrate_then_continue_leaves_the_vm_running() {
        let mut f = Fixture::with(
            "mig-cont",
            Spec {
                parking: 2,
                capture: true,
                write_log: Some(Arc::new(QuietLog::default())),
                ..Spec::default()
            },
        );
        let (got, r) = f.migrate(r#"{"v":1,"op":"migrate","then":"continue","max_rounds":1}"#);
        got.expect("the stream reads whole");
        assert_eq!(r["state"], "running", "{r}");
        f.assert_running();
    }

    // Refused before the first frame: the reply is the only line, and the VM
    // was never paused.
    #[test]
    fn a_migrate_without_a_record_of_writes_is_refused_before_it_starts() {
        let mut f = Fixture::with(
            "mig-nolog",
            Spec {
                parking: 2,
                capture: true,
                ..Spec::default()
            },
        );
        let r = reply(&f.ask(r#"{"v":1,"op":"migrate","then":"fence"}"#));
        assert_eq!(r["code"], "refused", "{r}");
        assert!(
            r["error"].as_str().unwrap().contains("does not record"),
            "{r}"
        );
        f.assert_running();
    }

    // A failure after the pause takes the place of the next frame, the VM
    // runs on, and the tracking of its writes is stopped.
    #[test]
    fn a_migrate_that_fails_in_the_pause_leaves_the_vm_running() {
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
        let log = Arc::new(QuietLog::default());
        let mut f = Fixture::with(
            "mig-fail",
            Spec {
                parking: 2,
                capture: true,
                net: Some(Arc::new(std::sync::Mutex::new(net))),
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                ..Spec::default()
            },
        );
        let (got, _) = f.migrate(r#"{"v":1,"op":"migrate","then":"fence"}"#);
        let err = got.err().expect("the stream ended early").to_string();
        assert!(
            err.contains("capture_failed") && err.contains("a restore would refuse"),
            "{err}"
        );
        f.assert_running();
        assert_eq!(log.stops.load(Ordering::SeqCst), 1);
        assert!(f
            .ask(r#"{"v":1,"op":"status"}"#)
            .contains(r#""state":"running""#));
    }

    // A client that goes away part way through leaves the VM running: the
    // stream, 8 MiB of pages that do not compress, cannot fit the socket's
    // buffer, so a write fails before the seal, and the tracking stops.
    #[test]
    fn a_migrate_whose_reader_hangs_up_leaves_the_vm_running() {
        let log = Arc::new(QuietLog::default());
        let mut f = Fixture::with(
            "mig-hangup",
            Spec {
                parking: 2,
                capture: true,
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                noise_mib: 8,
                ..Spec::default()
            },
        );
        // Past the profile and into round 0, so the tracking has started: a
        // client that hung up after the profile's header alone could fail
        // its body's write, which comes before the tracking.
        f.read_stream_until(r#"{"v":1,"op":"migrate","then":"fence"}"#, "ram-round-0");
        assert_eq!(log.starts.load(Ordering::SeqCst), 1);
        // Closed, not shut down: a macOS socket whose peer only shut its
        // reading side down takes the writes and drops them.
        let (spare, other) = UnixStream::pair().unwrap();
        drop(std::mem::replace(&mut f.client, spare));
        drop(std::mem::replace(
            &mut f.replies,
            std::io::BufReader::new(other),
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while log.stops.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "the migrate did not end");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(log.stops.load(Ordering::SeqCst), 1);
        f.assert_running();
        // The server serves the next client, and the VM was never fenced.
        let mut next = UnixStream::connect(&f.path).unwrap();
        next.write_all(b"{\"v\":1,\"op\":\"status\"}\n").unwrap();
        let mut line = String::new();
        std::io::BufReader::new(next).read_line(&mut line).unwrap();
        assert_eq!(reply(line.trim_end())["state"], "running", "{line}");
    }

    // A reader that stops reading while the guest runs, without closing the
    // connection, holds the stream only as long as the stall limit: the
    // rounds fail, the tracking stops, the guest never paused, and the
    // control socket serves the next client.
    #[test]
    fn a_migrate_whose_reader_stalls_while_the_guest_runs_gives_up() {
        let log = Arc::new(QuietLog::default());
        let mut f = Fixture::with(
            "mig-stall-run",
            Spec {
                parking: 2,
                capture: true,
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                noise_mib: 8,
                stream: StreamLimits {
                    stall: Duration::from_millis(300),
                    paused_floor: Duration::from_secs(60),
                },
                ..Spec::default()
            },
        );
        let stalled_at = Instant::now();
        f.read_stream_until(r#"{"v":1,"op":"migrate","then":"fence"}"#, "ram-round-0");
        let deadline = Instant::now() + Duration::from_secs(10);
        while log.stops.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "the stalled migrate did not end");
            assert_eq!(f.vcpus.parked(), 0, "the guest paused");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(stalled_at.elapsed() >= Duration::from_millis(300));
        f.assert_running();
        let status = f.status_elsewhere();
        assert_eq!(status["state"], "running", "{status}");
    }

    // A reader that stops reading during the final round, with the guest
    // paused, keeps it paused only for the paused budget: the stream fails,
    // the guest runs on unfenced, and the control socket serves the next
    // client. Every page is written in every round, so the final round is
    // 9 MiB, far more than the socket holds.
    #[test]
    fn a_migrate_whose_reader_stalls_while_the_guest_is_paused_resumes_it() {
        let log = Arc::new(BusyLog::default());
        let mut f = Fixture::with(
            "mig-stall-paused",
            Spec {
                parking: 2,
                capture: true,
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                noise_mib: 8,
                stream: StreamLimits {
                    stall: Duration::from_secs(60),
                    paused_floor: Duration::from_millis(300),
                },
                ..Spec::default()
            },
        );
        let headers = f.read_stream_until(
            r#"{"v":1,"op":"migrate","then":"fence","max_rounds":1}"#,
            "ram-round-1",
        );
        assert!(headers.len() > 2, "round 0 came first: {headers:?}");
        let stalled_at = Instant::now();
        assert_eq!(
            f.vcpus.parked(),
            2,
            "the final round began with the guest running"
        );
        assert!(
            f.source.gate().is_paused(),
            "the final round began with the gate open"
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while log.stops.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "the stalled migrate did not end");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(stalled_at.elapsed() >= Duration::from_millis(100));
        f.assert_running();
        let status = f.status_elsewhere();
        assert_eq!(status["state"], "running", "{status}");
    }

    // The stop ends a migrate stuck on a reader that takes nothing, at once
    // and not at the stall limit, and the server with it.
    #[test]
    fn the_stop_ends_a_migrate_stuck_on_its_reader() {
        let log = Arc::new(QuietLog::default());
        let mut f = Fixture::with(
            "mig-stall-stop",
            Spec {
                parking: 2,
                capture: true,
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                noise_mib: 8,
                stream: StreamLimits {
                    stall: Duration::from_secs(600),
                    paused_floor: Duration::from_secs(600),
                },
                ..Spec::default()
            },
        );
        f.read_stream_until(r#"{"v":1,"op":"migrate","then":"fence"}"#, "ram-round-0");
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            log.stops.load(Ordering::SeqCst),
            0,
            "the stream ended early"
        );
        f.source.request_stop();
        let server = f.server.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !server.is_finished() {
            assert!(
                Instant::now() < deadline,
                "the stuck migrate ignored the stop"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        server.join().unwrap();
        assert_eq!(log.stops.load(Ordering::SeqCst), 1);
    }

    // A fenced VM is not streamed again, whatever the second request asks:
    // the first destination may run it already.
    #[test]
    fn a_fenced_vm_refuses_a_second_stream() {
        let mut f = Fixture::with(
            "mig-again",
            Spec {
                parking: 2,
                capture: true,
                write_log: Some(Arc::new(QuietLog::default())),
                ..Spec::default()
            },
        );
        let (first, r) = f.migrate(r#"{"v":1,"op":"migrate","then":"fence"}"#);
        assert_eq!(r["state"], "fenced", "{r}");
        assert!(first.is_ok(), "the first stream was sealed");
        for then in ["fence", "continue"] {
            let (again, _) = f.migrate(&format!(
                r#"{{"v":1,"op":"migrate","then":"{then}","txid":"other","epoch":9}}"#
            ));
            let err = again.err().expect("a second stream was sent").to_string();
            assert!(
                err.contains("the source ended the stream: fenced:"),
                "{err}"
            );
        }
        let status = reply(&f.ask(r#"{"v":1,"op":"status"}"#));
        assert_eq!(status["state"], "fenced", "{status}");
        assert_eq!(reply(&f.ask(r#"{"v":1,"op":"resume"}"#))["code"], "fenced");
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

    /// A disk of `blocks` 64 KiB blocks and one sector, every 8-byte word
    /// its own offset, as a device the guest writes; removed on drop.
    struct TestDisk {
        path: std::path::PathBuf,
        dev: Arc<Mutex<VirtioBlk>>,
    }

    impl TestDisk {
        #[allow(clippy::disallowed_methods)]
        fn new(name: &str, blocks: u64) -> Self {
            let path =
                std::env::temp_dir().join(format!("hvi-ctl-{}-{name}.img", std::process::id()));
            let size = blocks * DIRTY_BLOCK_BYTES + 512;
            let bytes: Vec<u8> = (0..size / 8).flat_map(|w| (w * 8).to_le_bytes()).collect();
            std::fs::write(&path, bytes).unwrap();
            let dev = VirtioBlk::open(path.to_str().unwrap()).unwrap();
            Self {
                path,
                dev: Arc::new(Mutex::new(dev)),
            }
        }

        fn spec(&self) -> Option<(Arc<Mutex<VirtioBlk>>, String)> {
            Some((Arc::clone(&self.dev), self.path.display().to_string()))
        }

        /// Writes 64 bytes into block `block` as the guest would.
        fn write(&self, block: u64, byte: u8) {
            lock_or_recover(&self.dev).write_for_test(block * DIRTY_BLOCK_BYTES + 128, &[byte; 64]);
        }

        #[allow(clippy::disallowed_methods)]
        fn bytes(&self) -> Vec<u8> {
            std::fs::read(&self.path).unwrap()
        }
    }

    impl Drop for TestDisk {
        fn drop(&mut self) {
            #[allow(clippy::disallowed_methods)]
            let _ = std::fs::remove_file(&self.path);
        }
    }

    impl Fixture {
        /// Asks for `line`, reads the batches it streams into `image` at
        /// their offsets, checking each digest, and returns the reply after
        /// them with the batch headers.
        fn stream(
            &mut self,
            line: &str,
            image: &mut [u8],
        ) -> (serde_json::Value, Vec<disk::BatchHeader>) {
            use crate::checkpoint::bundle::hex;
            use sha2::{Digest, Sha256};
            use std::io::Read;
            self.client.write_all(line.as_bytes()).unwrap();
            self.client.write_all(b"\n").unwrap();
            let mut headers = Vec::new();
            loop {
                let mut text = String::new();
                self.replies.read_line(&mut text).unwrap();
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                if value.get("v").is_some() {
                    if value["ok"] == true {
                        // The reply's digest is the batches' digests, in
                        // order, as the reader saw them.
                        let chain: String = headers
                            .iter()
                            .map(|h: &disk::BatchHeader| h.sha256.as_str())
                            .collect();
                        let want = hex(&Sha256::digest(chain.as_bytes()));
                        assert_eq!(value["sent_sha256"], want.as_str(), "{value}");
                    }
                    return (value, headers);
                }
                let header: disk::BatchHeader = serde_json::from_value(value).unwrap();
                let mut bytes = vec![0u8; header.size as usize];
                self.replies.read_exact(&mut bytes).unwrap();
                assert_eq!(hex(&Sha256::digest(&bytes)), header.sha256);
                let at = header.offset as usize;
                image[at..at + bytes.len()].copy_from_slice(&bytes);
                headers.push(header);
            }
        }
    }

    fn bitmap(reply: &serde_json::Value) -> Vec<u64> {
        let bits =
            crate::checkpoint::platform::base64_decode(reply["bitmap_b64"].as_str().unwrap())
                .unwrap();
        (0..bits.len() as u64 * 8)
            .filter(|i| bits[(*i / 8) as usize] & (1 << (i % 8)) != 0)
            .collect()
    }

    #[test]
    fn the_disk_ops_need_a_root_and_a_disk() {
        let mut f = Fixture::new("disk-noroot", 1, 0);
        let r = reply(&f.ask(r#"{"v":1,"op":"disk-dirty","since":"boot"}"#));
        assert_eq!(r["code"], "refused", "{r}");
        assert!(r["error"].as_str().unwrap().contains("no checkpoint root"));
        let r = reply(&f.ask(r#"{"v":1,"op":"disk-blocks","round":0}"#));
        assert_eq!(r["code"], "refused", "{r}");
        drop(f);
        let mut f = Fixture::with(
            "disk-nodisk",
            Spec {
                parking: 1,
                capture: true,
                ..Spec::default()
            },
        );
        let r = reply(&f.ask(r#"{"v":1,"op":"disk-dirty","since":"boot"}"#));
        assert_eq!(r["error"], "the guest has no disk", "{r}");
        assert_eq!(
            reply(&f.ask(r#"{"v":1,"op":"status"}"#))["state"],
            "running"
        );
    }

    // The rounds of a move as hull drives them: round 0 while the guest
    // runs, a pause, the final round, then the fence. The blocks applied to
    // a copy of the base image make the disk the guest left.
    #[test]
    fn a_move_streams_its_rounds_onto_the_base_and_ends_with_the_disk() {
        let disk = TestDisk::new("disk-move", 40);
        let mut image = disk.bytes();
        let mut f = Fixture::with(
            "disk-move",
            Spec {
                parking: 2,
                capture: true,
                blk: disk.spec(),
                ..Spec::default()
            },
        );
        let r = reply(&f.ask(r#"{"v":1,"op":"disk-dirty","since":"round"}"#));
        assert_eq!(r["code"], "refused", "{r}");
        assert!(r["error"].as_str().unwrap().contains("no round 0"), "{r}");

        for block in [1, 2, 3, 40] {
            disk.write(block, 0xa1);
        }
        let r0 = reply(&f.ask(r#"{"v":1,"op":"disk-dirty","since":"boot"}"#));
        assert_eq!(
            (
                &r0["since"],
                &r0["round"],
                &r0["blocks"],
                &r0["dirty"],
                &r0["generation"]
            ),
            (&"boot".into(), &0.into(), &41.into(), &4.into(), &4.into()),
            "{r0}"
        );
        assert_eq!(r0["block_size"], 65536);
        assert_eq!(bitmap(&r0), [1, 2, 3, 40]);
        // Written after the read: round 1.
        disk.write(7, 0xb2);
        let (done, headers) = f.stream(r#"{"v":1,"op":"disk-blocks","round":0}"#, &mut image);
        assert_eq!(done["ok"], true, "{done}");
        assert_eq!(done["round"], 0, "{done}");
        let round0_sent = done["sent_sha256"].as_str().unwrap().to_string();
        assert_eq!(
            headers
                .iter()
                .map(|h| (h.first, h.count))
                .collect::<Vec<_>>(),
            [(1, 3), (40, 1)]
        );
        assert_eq!((&done["blocks"], &done["batches"]), (&4.into(), &2.into()));
        assert_eq!(done["bytes"], 3 * 65536 + 512);
        assert_eq!(done["generation"], 5);

        assert_eq!(reply(&f.ask(r#"{"v":1,"op":"pause"}"#))["state"], "paused");
        let r1 = reply(&f.ask(r#"{"v":1,"op":"disk-dirty","since":"round"}"#));
        assert_eq!(
            (&r1["round"], &r1["generation"]),
            (&1.into(), &5.into()),
            "{r1}"
        );
        assert_eq!(bitmap(&r1), [7]);
        let r = reply(&f.ask(r#"{"v":1,"op":"disk-blocks","round":0}"#));
        assert_eq!(r["code"], "refused", "{r}");
        assert!(r["error"].as_str().unwrap().contains("round 1 is"), "{r}");
        // Named by number: a block past the disk is refused before a byte
        // goes out, so the next line is the refusal.
        let (r, headers) = f.stream(r#"{"v":1,"op":"disk-blocks","blocks":[7,41]}"#, &mut image);
        assert_eq!(r["code"], "bad_request", "{r}");
        assert!(headers.is_empty());
        let (done, _) = f.stream(r#"{"v":1,"op":"disk-blocks","blocks":[7]}"#, &mut image);
        assert_eq!(done["blocks"], 1, "{done}");
        assert!(
            image == disk.bytes(),
            "the base and the rounds are not the disk"
        );

        assert_eq!(reply(&f.checkpoint("ck", "fence"))["state"], "fenced");
        // The bundle records the rounds, the last read inside the pause at
        // the disk's generation, and every block written since boot.
        let disk_json = crate::checkpoint::bundle::Bundle::open(&f.root.join("ck"))
            .unwrap()
            .disk()
            .unwrap()
            .unwrap();
        assert_eq!(disk_json.generation, 5);
        assert_eq!(disk_json.base_sha256, None);
        let rounds: Vec<(u32, u64, u64)> = disk_json
            .rounds
            .iter()
            .map(|r| (r.round, r.generation, r.blocks))
            .collect();
        assert_eq!(rounds, [(0, 4, 4), (1, 5, 1)]);
        // Round 0 went out by its number and is recorded sent, with the
        // digest its reply gave; round 1 went out as a list, which records
        // nothing. Each records its bitmap's digest, as disk-dirty gave it.
        assert_eq!(disk_json.rounds[0].sent_sha256, Some(round0_sent));
        assert_eq!(disk_json.rounds[1].sent_sha256, None);
        assert_eq!(
            disk_json.rounds[0].bitmap_sha256.as_deref(),
            r0["bitmap_sha256"].as_str()
        );
        assert_eq!(
            disk_json.rounds[1].bitmap_sha256.as_deref(),
            r1["bitmap_sha256"].as_str()
        );
        let since_boot = disk_json.dirty_since_boot().unwrap().unwrap();
        assert_eq!(since_boot.iter().collect::<Vec<_>>(), [1, 2, 3, 7, 40]);
        let r2 = reply(&f.ask(r#"{"v":1,"op":"disk-dirty","since":"round"}"#));
        assert_eq!((&r2["round"], &r2["dirty"]), (&2.into(), &0.into()), "{r2}");
    }

    // hull's order: the pre-copy rounds while the guest runs, the fence,
    // then the final round on a new connection. disk.json was written
    // before that read, so it cannot list it; the read is at the captured
    // generation, since a fenced guest writes nothing more, and that is
    // what a restore with --disk-generation checks.
    #[test]
    fn a_final_round_read_after_the_fence_ends_with_the_disk() {
        let disk = TestDisk::new("disk-fence-final", 20);
        let mut image = disk.bytes();
        let mut f = Fixture::with(
            "disk-fence-final",
            Spec {
                parking: 2,
                capture: true,
                blk: disk.spec(),
                ..Spec::default()
            },
        );
        disk.write(2, 0xa1);
        let r0 = reply(&f.ask(r#"{"v":1,"op":"disk-dirty","since":"boot"}"#));
        assert_eq!(bitmap(&r0), [2], "{r0}");
        let (done, _) = f.stream(r#"{"v":1,"op":"disk-blocks","round":0}"#, &mut image);
        assert_eq!(done["blocks"], 1, "{done}");
        disk.write(5, 0xb2);
        let r1 = reply(&f.ask(r#"{"v":1,"op":"disk-dirty","since":"round"}"#));
        assert_eq!(bitmap(&r1), [5], "{r1}");
        // Written after round 1 was read, before the fence.
        disk.write(9, 0xc3);
        disk.write(20, 0xc3);
        let (done, _) = f.stream(r#"{"v":1,"op":"disk-blocks","round":1}"#, &mut image);
        assert_eq!(done["blocks"], 1, "{done}");
        assert!(
            image != disk.bytes(),
            "the pre-copy rounds miss the last writes"
        );

        assert_eq!(reply(&f.checkpoint("ck", "fence"))["state"], "fenced");
        let disk_json = crate::checkpoint::bundle::Bundle::open(&f.root.join("ck"))
            .unwrap()
            .disk()
            .unwrap()
            .unwrap();
        let rounds: Vec<(u32, u64)> = disk_json
            .rounds
            .iter()
            .map(|r| (r.round, r.generation))
            .collect();
        assert_eq!(rounds, [(0, 1), (1, 2)]);
        assert_eq!(disk_json.generation, 4);

        let r2 = reply(&f.ask(r#"{"v":1,"op":"disk-dirty","since":"round"}"#));
        assert_eq!(
            (&r2["round"], &r2["generation"]),
            (&2.into(), &4.into()),
            "{r2}"
        );
        assert_eq!(bitmap(&r2), [9, 20]);
        let (done, headers) = f.stream(r#"{"v":1,"op":"disk-blocks","round":2}"#, &mut image);
        assert_eq!(done["ok"], true, "{done}");
        assert_eq!(headers.len(), 2);
        assert!(
            image == disk.bytes(),
            "the base and the rounds are not the disk"
        );
        assert_eq!(r2["generation"].as_u64(), Some(disk_json.generation));
    }
}

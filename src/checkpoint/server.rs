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
//! `checkpoint`'s does. The client reads the failure as a reply line where
//! a frame header was due, if the socket had room for it, and then the end
//! of the connection, which a failed stream always closes: an end before
//! the manifest means the VM was not fenced. `then: "fence"` fences the VM once
//! the manifest is written to the connection, which is before the client has
//! read it. The fence released its disk, and the destination may already
//! run it, so a fenced VM is streamed again only for the move that fenced
//! it, by its txid and epoch, and stays fenced: the mover that lost the
//! stream after the seal recovers it so. Any other `migrate` of a fenced
//! VM is refused with `fenced`.
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

/// How long a `migrate` waits for the I/O threads and the vCPUs to stop,
/// and then again for the vCPUs' state.
///
/// A vCPU parks only between guest entries, and an exit it is serving runs
/// to its end first: a virtio-blk flush is an `fdatasync` on the vCPU's
/// thread, which took seconds on a loaded Raspberry Pi. The 2 s of
/// [`CONTROL_TIMEOUT`] failed the pause of a move there again and again,
/// and the move with it, while the guest ran on. A move has already spent
/// its rounds, and its client waits for the stream with no fixed timeout,
/// so it waits longer for the park than a `pause` does.
const MIGRATE_PARK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a `migrate` may wait on its reader.
#[derive(Clone, Copy, Debug)]
struct StreamLimits {
    /// The longest one write waits for the reader to take a byte.
    stall: Duration,
    /// The least time the paused part of the stream is given.
    paused_floor: Duration,
    /// How long the pause waits for the vCPUs to park, and then for their
    /// state.
    park: Duration,
    /// Whether the stream's writes fail once the guest is paused.
    #[cfg(test)]
    fail_in_pause: bool,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            stall: STREAM_STALL,
            paused_floor: STREAM_PAUSED_FLOOR,
            park: MIGRATE_PARK_TIMEOUT,
            #[cfg(test)]
            fail_in_pause: false,
        }
    }
}

impl StreamLimits {
    /// Returns how long the stream may take from the pause to the manifest,
    /// given how long the last round with the guest running took, its disk
    /// round included.
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
            fenced_by: None,
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
            Ok(0) => return answer(&mut conn, stop, machine, &pending).map(|_| ()),
            Ok(n) => n,
            Err(e) if retry_read(&e) => continue,
            Err(e) => return Err(e),
        };
        pending.extend_from_slice(&chunk[..n]);
        while let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            // Whatever the client sent after a stream that failed is not
            // read: the connection is shut down.
            if answer(&mut conn, stop, machine, &line[..end])? == Served::Closed {
                return Ok(());
            }
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

/// Whether a connection stays open after a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Served {
    /// The connection takes the next request.
    Open,
    /// The connection was shut down, after a stream that failed.
    Closed,
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
) -> std::io::Result<Served> {
    let line = String::from_utf8_lossy(line);
    if line.trim().is_empty() {
        return Ok(Served::Open);
    }
    let (response, then) = match parse_request(&line) {
        Ok(Request::Migrate(request)) => return stream_and_reply(conn, stop, machine, &request),
        Ok(Request::DiskBlocks(selection)) => {
            return machine
                .disk_blocks(conn, stop, selection)
                .map(|()| Served::Open)
        }
        Ok(request) => machine.handle(request),
        Err(e) => (Response::Error(e), None),
    };
    let sent = send(conn, stop, &response);
    if let Some(after) = then {
        after.run(machine.vcpus);
    }
    sent.map(|()| Served::Open)
}

/// Serves a `migrate` on `conn`: the stream, then its reply.
///
/// The reply to a stream that ends with its manifest waits for the reader
/// only as long as a pause would, and the connection is closed if it does
/// not fit by then. A refusal before the first byte of the stream is a
/// reply like any other, and the connection stays open.
///
/// A stream that failed once it had begun is cut off: the refusal is
/// written only if the socket has room for it at once, and the connection
/// is shut down both ways. The reader may be why the stream failed, and a
/// failure part way through a frame leaves the refusal inside that frame's
/// bytes, where no reader can take it for a reply. So the reader learns of
/// the failure from the end of the stream, which it sees as soon as it has
/// taken what is buffered, rather than from a reply it may wait for until
/// its own timeout. An end before the manifest means the VM was not fenced.
fn stream_and_reply<K: Kick>(
    conn: &mut UnixStream,
    stop: &StopToken,
    machine: &mut Machine<'_, K>,
    request: &Migrate,
) -> std::io::Result<Served> {
    let deadline = Cell::new(None);
    let mut out = SocketOut::new(conn, stop, machine.stream.stall, &deadline);
    #[cfg(test)]
    {
        out.fail_in_pause = machine.stream.fail_in_pause;
    }
    let response = machine.migrate(&mut out, request);
    if out.written == 0 || !matches!(response, Response::Error(_)) {
        out.stall = machine.timeout;
        deadline.set(None);
        return out.send(&response).map(|()| Served::Open);
    }
    let line = format_response(&response) + "\n";
    match out.conn.write(line.as_bytes()) {
        Ok(_) => {}
        Err(e) if retry_read(&e) => {}
        Err(e) => eprintln!("{LOG_PREFIX} control socket: the refusal after a stream: {e}"),
    }
    // The connection closes when it is dropped; the shutdown says so to
    // the reader even if another handle on the socket outlives it.
    let _ = out.conn.shutdown(std::net::Shutdown::Both);
    Ok(Served::Closed)
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
    /// The bytes the reader was given.
    written: u64,
    /// Whether a write once the pause's deadline is set fails, as a test's
    /// write error.
    #[cfg(test)]
    fail_in_pause: bool,
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
            written: 0,
            #[cfg(test)]
            fail_in_pause: false,
        }
    }

    /// Writes `response` and its newline.
    fn send(&mut self, response: &Response) -> std::io::Result<()> {
        self.write_all((format_response(response) + "\n").as_bytes())
    }
}

impl Write for SocketOut<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(test)]
        if self.fail_in_pause && self.deadline.get().is_some() {
            return Err(std::io::Error::other(
                "a test failed the write in the pause",
            ));
        }
        // The stall counts from this call, so the time the stream spends
        // reading and compressing RAM between writes is not the reader's.
        let stalled_at = Instant::now() + self.stall;
        let until = self
            .deadline
            .get()
            .map_or(stalled_at, |d| d.min(stalled_at));
        loop {
            match self.conn.write(buf) {
                Ok(n) => {
                    self.written += n as u64;
                    return Ok(n);
                }
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

/// How long a pause took to stop each part of the VM.
#[derive(Clone, Copy, Debug, Default)]
struct PauseTimes {
    /// The I/O threads, in milliseconds.
    gate_ms: u64,
    /// The vCPUs, after the I/O threads.
    park_ms: u64,
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
    /// What a `checkpoint` or a `migrate` captures.
    capture: Option<Capture>,
    /// The root a `checkpoint` writes under.
    root: Option<CheckpointRoot>,
    /// The deadline of each wait, [`CONTROL_TIMEOUT`] outside the tests.
    timeout: Duration,
    /// How long a `migrate` waits on its reader.
    stream: StreamLimits,
    /// What the `migrate` that fenced the VM sent, when it gave a txid and
    /// an epoch.
    fenced_by: Option<FenceRecord>,
}

/// What a `migrate` that fenced the VM sent, kept so that the move that
/// fenced it, and only that one, can have the sealed state streamed again:
/// hull's recovery when it died between hvi's seal and its own.
struct FenceRecord {
    /// The txid of the request that fenced the VM.
    txid: String,
    /// Its epoch.
    epoch: u64,
    /// The profile it sent.
    profile: MachineProfile,
    /// `profile.json` as it sent it.
    profile_json: Vec<u8>,
    /// The documents after RAM as it sent them, but disk.json when the
    /// stream had disk rounds, which a stream sent again rewrites.
    docs: Vec<(&'static str, Vec<u8>)>,
    /// Whether the stream had disk rounds.
    disk_rounds: bool,
    /// The capabilities its manifest listed.
    capabilities: Vec<String>,
    /// Its manifest's SHA-256.
    manifest_sha256: String,
    /// Every component its manifest listed.
    components: Vec<crate::checkpoint::stream::StreamComponent>,
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
    fn migrate(&mut self, out: &mut SocketOut<'_>, request: &Migrate) -> Response {
        if !self.vcpus.is_running() {
            self.state = VmState::Stopping;
        }
        match self.state {
            // The fence released the disk, and the destination may run by
            // now. A second stream would hand out another copy that can
            // resume, so only the move that fenced the VM may have it again.
            VmState::Fenced => return self.restream(out, request),
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
        let paused_deadline = out.deadline;
        let mut stream = StreamWriter::new(out);
        let profile_json = profile.to_json().into_bytes();
        if let Err(e) = stream.write_doc("profile.json", &profile_json) {
            return refuse(
                ErrorCode::CaptureFailed,
                format!("{e}; the VM is as it was"),
            );
        }
        let tracker = Tracker::new(&ram, &*write_log);
        let vcpus = self.vcpus;
        let stopping = || !vcpus.is_running();
        // The disk moves in the rounds when the destination holds its base
        // image; otherwise the stream has no disk rounds, and the mover
        // copies the disk whole.
        let block = capture.block.as_ref().map(|(dev, _)| Arc::clone(dev));
        let disk_rounds = block
            .as_deref()
            .filter(|_| profile.disk_base_sha256.is_some());
        let started = Instant::now();
        let precopy =
            migrate::precopy(&mut stream, &ram, &tracker, disk_rounds, &policy, &stopping);
        let rounds_end_unix_ms = unix_ms();
        // The disk is synced here, with the guest still running and
        // without the device's lock, so the sync in the pause has only the
        // writes since left; that one took seconds on a busy host.
        let disk_synced_at = Instant::now();
        let precopy = precopy.and_then(|precopy| {
            if let Some(dev) = &block {
                let file = lock_or_recover(dev).data_file();
                file.sync_data()
                    .map_err(|e| std::io::Error::new(e.kind(), format!("syncing the disk: {e}")))?;
            }
            Ok(precopy)
        });
        let disk_sync_ms = disk_synced_at.elapsed().as_millis() as u64;
        let mut precopy = match precopy {
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
        let last_round = precopy.last_round_time();
        let times = if found == VmState::Running {
            match self.pause_within(self.stream.park) {
                Ok(times) => times,
                Err(refusal) => {
                    tracker.stop();
                    return refusal;
                }
            }
        } else {
            PauseTimes::default()
        };
        let exported = match self.export(Instant::now() + self.stream.park) {
            Ok(exported) => exported,
            Err(e) => {
                tracker.stop();
                self.back_to(found);
                return Response::Error(e);
            }
        };
        let pause_ms = paused_at.elapsed().as_millis() as u64;
        // The budget for the paused part of the stream starts once the
        // vCPUs are still and their state is in hand, since nothing was
        // written before: a park that took long under load does not eat
        // into what the final round may take.
        paused_deadline.set(Some(Instant::now() + self.stream.paused_budget(last_round)));
        let request_doc = capture::Request {
            then: request.then,
            txid: request.txid.as_deref(),
            epoch: request.epoch.unwrap_or(0),
        };
        let sealed = (|| -> std::io::Result<_> {
            let devices = capture.device_states()?;
            let last = migrate::final_round(
                &mut stream,
                &ram,
                &tracker,
                disk_rounds,
                &mut precopy,
                &stopping,
            )?;
            // After the final disk round, so disk.json lists it with its
            // digest, and its generation is the disk's. With disk rounds
            // the destination holds every block and syncs them itself, so
            // the source's disk is not synced again with the guest paused:
            // that sync took seconds on a busy host. Without them the mover
            // copies this disk, which must then be durable. The sync has
            // only what the guest wrote since the one before the pause, and
            // is timed on its own, since the guest waits for it.
            let (disk, pause_sync) = capture.disk_state_timed(&profile, disk_rounds.is_none())?;
            let mut docs = vec![
                (
                    "cpu.json",
                    json(&CpuState::new(capture.arch, exported.vcpus))?,
                ),
                ("platform.json", json(&exported.platform)?),
                ("devices.json", devices.to_json()?),
            ];
            if let Some(disk) = &disk {
                docs.push(("disk.json", json(disk)?));
            }
            docs.push(("session.json", json(&capture.session(&request_doc))?));
            for (name, bytes) in &docs {
                stream.write_doc(name, bytes)?;
            }
            let sealed_at = unix_ms();
            let (manifest, manifest_sha256) = stream.seal(
                this_build(),
                migrate::regions_of(&ram),
                exported.capabilities.clone(),
                sealed_at,
            )?;
            Ok((
                last,
                manifest_sha256,
                sealed_at,
                docs,
                manifest.components,
                exported.capabilities,
                pause_sync,
            ))
        })();
        // The destination may open the disk as soon as it has read the
        // manifest, so a fence releases the lock first of all.
        if sealed.is_ok() && request.then == Then::Fence {
            self.state = VmState::Fenced;
            capture.release_disk();
        }
        let faults = write_log.fault_stats();
        tracker.stop();
        let sealed = match sealed {
            Ok((
                last,
                manifest_sha256,
                sealed_at,
                mut docs,
                components,
                capabilities,
                pause_sync,
            )) => {
                // Only a move that names itself by both can be told from
                // another, so only it may have the state again.
                if let (Then::Fence, Some(txid), Some(epoch)) =
                    (request.then, &request.txid, request.epoch)
                {
                    if disk_rounds.is_some() {
                        docs.retain(|(name, _)| *name != "disk.json");
                    }
                    self.fenced_by = Some(FenceRecord {
                        txid: txid.clone(),
                        epoch,
                        profile: profile.clone(),
                        profile_json,
                        docs,
                        disk_rounds: disk_rounds.is_some(),
                        capabilities,
                        manifest_sha256: manifest_sha256.clone(),
                        components,
                    });
                }
                Ok((last, manifest_sha256, sealed_at, pause_sync))
            }
            Err(e) => Err(e),
        };
        let (last, manifest_sha256, sealed_at_unix_ms, pause_sync) = match sealed {
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
        // The vCPUs ran on while the gate waited for the I/O threads, the
        // virtio-blk worker's request in flight among them: the guest was
        // stopped from the park on.
        let paused_ms = (paused_at.elapsed().as_millis() as u64).saturating_sub(times.gate_ms);
        if request.then == Then::Continue {
            self.back_to(found);
        }
        let mut rounds = precopy.rounds;
        rounds.push(last);
        let ram_raw_bytes = rounds.iter().map(migrate::RoundStats::raw_bytes).sum();
        let ram_stream_bytes = rounds.iter().map(|r| r.bytes).sum();
        let disk_rounds = precopy.disk_rounds;
        Response::Migrate {
            state: self.state,
            manifest_sha256,
            stats: Box::new(MigrateStats {
                disk_raw_bytes: disk_rounds.iter().map(|r| r.raw_bytes).sum(),
                disk_stream_bytes: disk_rounds.iter().map(|r| r.bytes).sum(),
                disk_rounds,
                disk_sync_ms,
                pause_sync_ms: pause_sync.as_millis() as u64,
                gate_ms: times.gate_ms,
                park_ms: times.park_ms,
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
                rounds_end_unix_ms,
                precopy_end_unix_ms,
                sealed_at_unix_ms,
                first_manifest_sha256: None,
                same_as_first: None,
            }),
        }
    }

    /// Streams a fenced VM's sealed state again on `conn`, for the move
    /// that fenced it: the same txid and epoch, and `then: "fence"`. Any
    /// other request is refused with `fenced`, as is a VM a `checkpoint`
    /// fenced, and the VM stays fenced either way.
    ///
    /// The stream is the final round alone: with disk rounds, one disk
    /// round of every block written since boot, read from the disk; every
    /// page of RAM, which has not changed since the seal; and the
    /// documents as the first stream sent them, disk.json written again
    /// for its one round. So profile.json, the vCPU, platform, device and
    /// session documents, and disk.json without disk rounds, are the first
    /// stream's bytes, and the reply names them. The manifest is a new
    /// one, whose SHA-256 never equals the first's, since the rounds are
    /// not the first stream's: a mover compares those documents' digests.
    /// The pause is long over, so only the stall bound applies to the
    /// reader. The record is kept for as long as the run lives, so the
    /// mover may ask again; only it can know that the first destination
    /// never resumed.
    fn restream(&mut self, out: &mut SocketOut<'_>, request: &Migrate) -> Response {
        let Some(record) = &self.fenced_by else {
            return refuse(
                ErrorCode::Fenced,
                "the VM was fenced after a checkpoint, or by a move that gave no txid and \
                 epoch",
            );
        };
        if request.txid.as_deref() != Some(record.txid.as_str())
            || request.epoch != Some(record.epoch)
        {
            return refuse(
                ErrorCode::Fenced,
                "the VM is fenced; only the move that fenced it, by its txid and epoch, may \
                 have its state streamed again",
            );
        }
        if request.then != Then::Fence {
            return refuse(
                ErrorCode::Fenced,
                "the VM is fenced and stays fenced; ask with then: fence",
            );
        }
        let Some(capture) = self.capture.clone() else {
            return refuse(ErrorCode::Refused, "this run cannot be captured");
        };
        let ram = Arc::clone(&capture.ram);
        let vcpus = self.vcpus;
        let stopping = || !vcpus.is_running();
        let started = Instant::now();
        let mut stream = StreamWriter::new(out);
        let sent = (|| -> std::io::Result<_> {
            stream.write_doc("profile.json", &record.profile_json)?;
            let mut disk_rounds = Vec::new();
            let mut disk = None;
            if record.disk_rounds {
                if let Some((dev, _)) = &capture.block {
                    disk_rounds.push(migrate::send_disk(
                        &mut stream,
                        dev,
                        DirtySince::Boot,
                        true,
                        &stopping,
                    )?);
                    disk = capture.disk_state(&record.profile)?;
                }
            }
            let round = migrate::whole_round(&mut stream, &ram, &stopping)?;
            for (name, bytes) in &record.docs {
                if *name == "session.json" {
                    if let Some(disk) = &disk {
                        stream.write_doc("disk.json", &json(disk)?)?;
                    }
                }
                stream.write_doc(name, bytes)?;
            }
            let sealed_at = unix_ms();
            let (manifest, sha256) = stream.seal(
                this_build(),
                migrate::regions_of(&ram),
                record.capabilities.clone(),
                sealed_at,
            )?;
            Ok((round, disk_rounds, manifest, sha256, sealed_at))
        })();
        let (round, disk_rounds, manifest, manifest_sha256, sealed_at_unix_ms) = match sent {
            Ok(sent) => sent,
            Err(e) => {
                if !self.vcpus.is_running() {
                    self.state = VmState::Stopping;
                    return refuse(ErrorCode::Stopped, format!("the run is ending: {e}"));
                }
                return refuse(
                    ErrorCode::CaptureFailed,
                    format!("{e}; the stream is not sealed, and the VM stays fenced"),
                );
            }
        };
        let same_as_first = manifest
            .components
            .iter()
            .filter(|c| record.components.contains(c))
            .map(|c| c.name.clone())
            .collect();
        let paused_ms = started.elapsed().as_millis() as u64;
        Response::Migrate {
            state: self.state,
            manifest_sha256,
            stats: Box::new(MigrateStats {
                final_round_bytes: round.bytes,
                ram_present_bytes: round.data_pages * crate::checkpoint::ram::PAGE_SIZE,
                ram_raw_bytes: round.raw_bytes(),
                ram_stream_bytes: round.bytes,
                rounds: vec![round],
                stop_reason: migrate::StopReason::Fenced,
                threshold_bytes: 0,
                precopy_ms: 0,
                pause_ms: 0,
                paused_ms,
                ram_total_bytes: ram.regions().iter().map(|r| r.size).sum(),
                stream_bytes: stream.written(),
                disk_raw_bytes: disk_rounds.iter().map(|r| r.raw_bytes).sum(),
                disk_stream_bytes: disk_rounds.iter().map(|r| r.bytes).sum(),
                disk_rounds,
                disk_sync_ms: 0,
                pause_sync_ms: 0,
                gate_ms: 0,
                park_ms: 0,
                write_granule: capture.write_log.as_ref().map_or(0, |l| l.granule()),
                write_faults: None,
                write_fault_ns: None,
                rounds_end_unix_ms: sealed_at_unix_ms,
                precopy_end_unix_ms: sealed_at_unix_ms,
                sealed_at_unix_ms,
                first_manifest_sha256: Some(record.manifest_sha256.clone()),
                same_as_first: Some(same_as_first),
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
        match self.pause_within(self.timeout) {
            Ok(_) => Response::State(self.state),
            Err(refusal) => refusal,
        }
    }

    /// Holds the I/O threads, then parks the vCPUs, within `timeout` for
    /// both, and returns how long each took. Pausing a paused VM succeeds
    /// and changes nothing.
    ///
    /// # Errors
    ///
    /// Returns the refusal to send when the run is ending, another pause
    /// holds the vCPUs, or they did not all stop in time; the VM then runs
    /// on, and the refusal says how long the wait took and how much of it
    /// the I/O threads had.
    fn pause_within(&mut self, timeout: Duration) -> Result<PauseTimes, Response> {
        match self.state {
            VmState::Paused | VmState::RestoredPaused | VmState::Fenced => {
                return Ok(PauseTimes::default())
            }
            VmState::Stopping => return Err(refuse(ErrorCode::Stopped, "the run is ending")),
            VmState::Running => {}
        }
        let started = Instant::now();
        let deadline = started + timeout;
        if let Err(inside) = self.gate.pause(timeout) {
            // The gate gives up on the stop as well as at its deadline.
            if !self.vcpus.is_running() {
                self.state = VmState::Stopping;
                return Err(refuse(ErrorCode::Stopped, "the run is ending"));
            }
            return Err(refuse(
                ErrorCode::Timeout,
                format!("{inside} I/O thread(s) still busy after {timeout:?}; the VM runs on"),
            ));
        }
        let gate_ms = started.elapsed().as_millis() as u64;
        // The vCPUs get what the gate left of the deadline, so the reply comes
        // within the one deadline the client is told about.
        let left = deadline.saturating_duration_since(Instant::now());
        let parking = Instant::now();
        match self.vcpus.pause_from_control(left) {
            Ok(_) => {
                self.state = VmState::Paused;
                Ok(PauseTimes {
                    gate_ms,
                    park_ms: parking.elapsed().as_millis() as u64,
                })
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
                Err(refuse(
                    code,
                    format!(
                        "{e} ({} ms, after {gate_ms} ms for the I/O threads); the VM runs on",
                        parking.elapsed().as_millis()
                    ),
                ))
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
        /// The profile's `disk_base_sha256`.
        base: Option<String>,
        /// How long each parking vCPU stays in an exit after a pause is
        /// asked, before it reaches its checkpoint: a vCPU serving a slow
        /// disk flush.
        slow_exit: Option<Duration>,
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
        /// Guest RAM, which a test may write as the guest would.
        ram: Arc<GuestRam>,
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
                    let slow_exit = spec.slow_exit;
                    std::thread::spawn(move || {
                        let mut delayed = false;
                        while vcpus.is_running() {
                            if let Some(slow) = slow_exit {
                                if !vcpus.quiesce_requested() {
                                    delayed = false;
                                } else if !delayed {
                                    delayed = true;
                                    std::thread::sleep(slow);
                                }
                            }
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
                let base = spec.base.clone();
                cell.complete(|p| {
                    p.disk_base_sha256 = base;
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
            let guest_ram = Arc::clone(&ram);
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
                ram: guest_ram,
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
            self.migrate_into(line, None)
        }

        /// As [`migrate`](Self::migrate), writing the disk rounds into
        /// `disk`.
        fn migrate_into(
            &mut self,
            line: &str,
            disk: Option<&mut dyn crate::checkpoint::stream::DiskTarget>,
        ) -> (
            std::io::Result<(crate::checkpoint::stream::Received, Arc<GuestRam>)>,
            serde_json::Value,
        ) {
            use crate::checkpoint::stream::{receive, PageSpace, StreamReader};
            self.client.write_all(line.as_bytes()).unwrap();
            self.client.write_all(b"\n").unwrap();
            let mut made = None;
            let mut reader = StreamReader::new(&mut self.replies);
            let got = receive(
                &mut reader,
                |profile| {
                    // As large as the source's RAM, noise included.
                    let profile =
                        MachineProfile::from_json(std::str::from_utf8(profile).unwrap()).unwrap();
                    let ram = Arc::new(GuestRam::from_ranges(&[(
                        GPA,
                        profile.ram_regions[0].size as usize,
                    )]));
                    made = Some(Arc::clone(&ram));
                    Ok((PageSpace::new(&migrate::regions_of(&ram))?, ram))
                },
                disk,
            );
            let ram = made.unwrap_or_else(|| Arc::new(GuestRam::from_ranges(&[(GPA, 1 << 20)])));
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
    // runs on, the tracking of its writes is stopped, and the connection is
    // closed after the refusal.
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
        let mut rest = Vec::new();
        f.replies.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "the connection went on: {rest:?}");
        assert_eq!(f.status_elsewhere()["state"], "running");
    }

    impl Fixture {
        /// Reads what is left of the connection until it ends, within the
        /// client's 30 s read timeout, and returns it with when it ended.
        fn read_to_eof(&mut self) -> (Vec<u8>, Instant) {
            let mut rest = Vec::new();
            self.replies
                .read_to_end(&mut rest)
                .expect("the connection ended");
            (rest, Instant::now())
        }
    }

    /// Returns the refusal line at the end of `rest`, if the server had room
    /// to write it.
    fn trailing_refusal(rest: &[u8]) -> Option<serde_json::Value> {
        let text = String::from_utf8_lossy(rest);
        let at = text.rfind(r#"{"v":1,"ok":false"#)?;
        serde_json::from_str(text[at..].trim_end()).ok()
    }

    // A reader that stalls once it has the final disk round, in the pause,
    // is cut off at the paused budget: the stream ends there, and the
    // connection with it, rather than staying open for a reply the reader
    // could not tell from the frame it was reading. The VM runs on
    // unfenced, as an end before the manifest says.
    #[test]
    fn a_reader_stalled_after_the_final_disk_round_sees_the_end_at_the_budget() {
        let disk = TestDisk::new("mig-stall-eof", 4);
        disk.write(1, 0x21);
        let log = Arc::new(BusyLog::default());
        let budget = Duration::from_millis(300);
        let mut f = Fixture::with(
            "mig-stall-eof",
            Spec {
                parking: 2,
                capture: true,
                blk: disk.spec(),
                base: Some("ab".repeat(32)),
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                noise_mib: 8,
                stream: StreamLimits {
                    stall: Duration::from_secs(60),
                    paused_floor: budget,
                    ..StreamLimits::default()
                },
                ..Spec::default()
            },
        );
        let headers = f.read_stream_until(
            r#"{"v":1,"op":"migrate","then":"fence","txid":"s1","epoch":1,"max_rounds":1}"#,
            "disk-round-final",
        );
        let size = headers.last().unwrap()["size"].as_u64().unwrap();
        let mut body = vec![0u8; usize::try_from(size).unwrap()];
        f.replies.read_exact(&mut body).unwrap();
        let stalled_at = Instant::now();
        assert_eq!(f.vcpus.parked(), 2, "the final disk round came paused");
        let deadline = Instant::now() + Duration::from_secs(20);
        while log.stops.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "the stalled migrate did not end");
            std::thread::sleep(Duration::from_millis(5));
        }
        let failed_at = Instant::now();
        // The rounds took a few ms, so the budget is about the floor.
        assert!(
            failed_at - stalled_at < budget + Duration::from_secs(2),
            "the stream ended {:?} after the stall",
            failed_at - stalled_at
        );
        let (rest, ended_at) = f.read_to_eof();
        // What was buffered, then the end: no wait for a reply.
        assert!(
            ended_at - failed_at < Duration::from_secs(2),
            "the end came {:?} after the failure",
            ended_at - failed_at
        );
        assert!(!rest.is_empty(), "the final RAM round was under way");
        if let Some(r) = trailing_refusal(&rest) {
            assert!(r["error"].as_str().unwrap().contains("as it was"), "{r}");
        }
        f.assert_running();
        assert_eq!(f.status_elsewhere()["state"], "running");
    }

    // A write that fails in the pause ends the connection at once, after
    // the refusal where the next frame was due, and the VM runs on.
    #[test]
    fn a_write_error_in_the_pause_closes_the_connection_with_the_vm_running() {
        let disk = TestDisk::new("mig-werr", 4);
        disk.write(1, 0x31);
        let log = Arc::new(QuietLog::default());
        let mut f = Fixture::with(
            "mig-werr",
            Spec {
                parking: 2,
                capture: true,
                blk: disk.spec(),
                base: Some("ab".repeat(32)),
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                stream: StreamLimits {
                    fail_in_pause: true,
                    ..StreamLimits::default()
                },
                ..Spec::default()
            },
        );
        let asked = Instant::now();
        f.client
            .write_all(
                b"{\"v\":1,\"op\":\"migrate\",\"then\":\"fence\",\"txid\":\"w\",\"epoch\":1}\n",
            )
            .unwrap();
        // A request sent behind it is not served.
        f.client
            .write_all(b"{\"v\":1,\"op\":\"status\"}\n")
            .unwrap();
        let (rest, ended_at) = f.read_to_eof();
        assert!(
            ended_at - asked < Duration::from_secs(5),
            "the end came {:?} after the request",
            ended_at - asked
        );
        let text = String::from_utf8_lossy(&rest);
        assert!(text.contains("disk-round-0"), "the stream began");
        assert!(
            !text.contains("disk-round-final"),
            "a frame went in the pause"
        );
        let r = trailing_refusal(&rest).expect("the refusal fit");
        assert_eq!(r["code"], "capture_failed", "{r}");
        assert!(
            r["error"]
                .as_str()
                .unwrap()
                .contains("a test failed the write in the pause"),
            "{r}"
        );
        assert!(r["error"].as_str().unwrap().contains("as it was"), "{r}");
        assert!(!text.contains(r#""vcpus_parked""#), "the status was served");
        assert_eq!(log.stops.load(Ordering::SeqCst), 1);
        f.assert_running();
        assert_eq!(f.status_elsewhere()["state"], "running");
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
                    ..StreamLimits::default()
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
                    ..StreamLimits::default()
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
                    ..StreamLimits::default()
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

    /// A record of the guest's writes for a move with a disk: at each of
    /// its first collects it writes the next block of `writes` to `disk`,
    /// as the guest would, and reports every page written, so the rounds
    /// do not converge; after them it reports nothing. The collect the
    /// final round makes, paused, finds the list empty.
    struct DiskWritingLog {
        disk: Arc<Mutex<VirtioBlk>>,
        writes: Mutex<Vec<u64>>,
    }

    impl crate::memory::GuestWriteLog for DiskWritingLog {
        fn start(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn collect(&self, into: &mut crate::memory::DirtyPages) -> std::io::Result<()> {
            let Some(block) = self.writes.lock().unwrap().pop() else {
                return Ok(());
            };
            lock_or_recover(&self.disk)
                .write_for_test(block * DIRTY_BLOCK_BYTES + 100, &[0xd5; 64]);
            for index in 0..into.region_count() {
                let (_, pages) = into.region(index).unwrap();
                into.set_range(index, 0, pages);
            }
            Ok(())
        }
        fn stop(&self) {}
        fn granule(&self) -> u64 {
            4096
        }
    }

    /// A disk image in memory that a stream's disk rounds go into.
    struct Image(Vec<u8>);

    impl crate::checkpoint::stream::DiskTarget for Image {
        fn begin(&mut self) -> std::io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
            self.0[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
        fn round_end(&mut self, _in_pause: bool) -> std::io::Result<()> {
            Ok(())
        }
    }

    // A guest whose disk has a base moves it in the migrate stream: disk
    // round k before RAM round k, the final disk round paused, and the base
    // with the rounds applied is the disk the source left. disk.json lists
    // every round with the digests of what the stream carried, and its last
    // round's generation is the disk's.
    #[test]
    fn a_migrate_moves_the_disk_in_its_rounds() {
        let disk = TestDisk::new("mig-disk", 20);
        let base = disk.bytes();
        disk.write(2, 0xa1);
        disk.write(3, 0xa2);
        // Popped from the end: block 5 at the first collect, then 9, then
        // the disk's short last block 20.
        let log = Arc::new(DiskWritingLog {
            disk: Arc::clone(&disk.dev),
            writes: Mutex::new(vec![20, 9, 5]),
        });
        let mut f = Fixture::with(
            "mig-disk",
            Spec {
                parking: 2,
                capture: true,
                blk: disk.spec(),
                base: Some("ab".repeat(32)),
                noise_mib: 9,
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                ..Spec::default()
            },
        );
        let mut image = Image(base.clone());
        let (got, r) = f.migrate_into(
            r#"{"v":1,"op":"migrate","then":"fence","txid":"d1","epoch":2,"max_rounds":3}"#,
            Some(&mut image),
        );
        let (received, _) = got.expect("the stream reads whole");
        assert_eq!(r["state"], "fenced", "{r}");
        assert!(
            image.0 == disk.bytes(),
            "the base and the rounds are the disk"
        );
        let names: Vec<&str> = received.disk.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "disk-round-0",
                "disk-round-1",
                "disk-round-2",
                "disk-round-final"
            ]
        );
        let blocks: Vec<u64> = received.disk.iter().map(|d| d.blocks).collect();
        assert_eq!(blocks, [2, 1, 1, 1]);
        let stats = &r["stats"];
        assert_eq!(stats["disk_rounds"].as_array().unwrap().len(), 4, "{r}");
        assert_eq!(stats["disk_rounds"][3]["in_pause"], true, "{r}");
        assert_eq!(stats["rounds"].as_array().unwrap().len(), 4, "{r}");
        // Both syncs are timed, and the rounds end before the sync after
        // them does.
        assert!(
            stats["disk_sync_ms"].is_u64() && stats["pause_sync_ms"].is_u64(),
            "{r}"
        );
        let (end, synced) = (
            stats["rounds_end_unix_ms"].as_u64().unwrap(),
            stats["precopy_end_unix_ms"].as_u64().unwrap(),
        );
        assert!(
            end <= synced && synced <= stats["sealed_at_unix_ms"].as_u64().unwrap(),
            "{r}"
        );
        let disk_json =
            crate::checkpoint::bundle::parse_disk(received.doc("disk.json").unwrap()).unwrap();
        assert_eq!(disk_json.rounds.len(), 4);
        for (listed, got) in disk_json.rounds.iter().zip(&received.disk) {
            assert_eq!(listed.sent_sha256.as_deref(), Some(got.sha256.as_str()));
            assert_eq!(
                listed.bitmap_sha256.as_deref(),
                Some(got.bitmap_sha256.as_str())
            );
        }
        assert_eq!(disk_json.rounds[3].generation, disk_json.generation);
        assert_eq!(disk_json.generation, 5, "five writes");
        // The destination has the blocks, so the pause syncs nothing.
        assert!(!disk_json.synced, "the disk was synced in the pause");
        assert_eq!(stats["pause_sync_ms"], 0, "{r}");
    }

    // Without a base the stream has no disk rounds: the mover copies the
    // disk whole, as before.
    #[test]
    fn a_migrate_without_a_base_sends_no_disk_rounds() {
        let disk = TestDisk::new("mig-nobase", 4);
        disk.write(1, 0x11);
        let mut f = Fixture::with(
            "mig-nobase",
            Spec {
                parking: 2,
                capture: true,
                blk: disk.spec(),
                write_log: Some(Arc::new(QuietLog::default())),
                ..Spec::default()
            },
        );
        let (got, r) = f.migrate(r#"{"v":1,"op":"migrate","then":"continue"}"#);
        let (received, _) = got.expect("the stream reads whole");
        assert!(received.disk.is_empty() && received.manifest.disk.is_none());
        assert_eq!(r["stats"]["disk_rounds"], serde_json::json!([]), "{r}");
        // The mover copies this disk, so it is synced in the pause.
        let disk_json =
            crate::checkpoint::bundle::parse_disk(received.doc("disk.json").unwrap()).unwrap();
        assert!(disk_json.synced, "the disk was synced in the pause");
    }

    // hull's recovery after it died between hvi's seal and its own: the
    // move that fenced the VM, by its txid and epoch, has the sealed state
    // streamed again. The documents are the first stream's bytes, RAM is
    // what it was, and the VM stays fenced.
    #[test]
    fn the_fence_owner_has_the_sealed_state_streamed_again() {
        let mut f = Fixture::with(
            "mig-restream",
            Spec {
                parking: 2,
                capture: true,
                write_log: Some(Arc::new(QuietLog::default())),
                ..Spec::default()
            },
        );
        let line = r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-7","epoch":3}"#;
        let (first, r1) = f.migrate(line);
        let (first, _) = first.expect("the first stream reads whole");
        assert_eq!(r1["state"], "fenced", "{r1}");
        let (again, r2) = f.migrate(line);
        let (again, ram) = again.expect("the stream sent again reads whole");
        assert_eq!(r2["state"], "fenced", "{r2}");
        assert_eq!(r2["manifest_sha256"], again.manifest_sha256.as_str());
        let stats = &r2["stats"];
        assert_eq!(
            stats["first_manifest_sha256"], r1["manifest_sha256"],
            "{r2}"
        );
        assert_eq!(stats["stop_reason"], "fenced", "{r2}");
        assert_eq!(stats["rounds"].as_array().unwrap().len(), 1, "{r2}");
        // The guest wrote nothing during the move, so even RAM round 0 is
        // the first stream's: every page, the same chunks.
        assert_eq!(
            stats["same_as_first"],
            serde_json::json!([
                "profile.json",
                "ram-round-0",
                "cpu.json",
                "platform.json",
                "devices.json",
                "session.json"
            ]),
            "{r2}"
        );
        for name in ["cpu.json", "platform.json", "devices.json", "session.json"] {
            assert_eq!(first.doc(name), again.doc(name), "{name}");
        }
        let mut data = [0u8; 10];
        ram.read(GPA + 0x3000, &mut data).unwrap();
        assert_eq!(&data, b"guest data", "RAM came over again");
        // And again: the record is kept until the run ends.
        let (third, _) = f.migrate(line);
        assert!(third.is_ok());
        assert_eq!(reply(&f.ask(r#"{"v":1,"op":"status"}"#))["state"], "fenced");
        assert_eq!(reply(&f.ask(r#"{"v":1,"op":"resume"}"#))["code"], "fenced");
        assert_eq!(reply(&f.ask(r#"{"v":1,"op":"stop"}"#))["state"], "stopping");
    }

    #[test]
    fn only_the_fence_owner_may_have_the_state_again() {
        let mut f = Fixture::with(
            "mig-restream-other",
            Spec {
                parking: 2,
                capture: true,
                write_log: Some(Arc::new(QuietLog::default())),
                ..Spec::default()
            },
        );
        let (first, _) =
            f.migrate(r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-7","epoch":3}"#);
        assert!(first.is_ok());
        for line in [
            r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-8","epoch":3}"#,
            r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-7","epoch":4}"#,
            r#"{"v":1,"op":"migrate","then":"fence","epoch":3}"#,
            r#"{"v":1,"op":"migrate","then":"fence"}"#,
            r#"{"v":1,"op":"migrate","then":"continue","txid":"tx-7","epoch":3}"#,
        ] {
            let (again, _) = f.migrate(line);
            let err = again.err().expect("refused").to_string();
            assert!(
                err.contains("the source ended the stream: fenced:"),
                "{line}: {err}"
            );
        }
        assert_eq!(reply(&f.ask(r#"{"v":1,"op":"status"}"#))["state"], "fenced");
        // A VM a checkpoint fenced has no stream to send again.
        let mut f = Fixture::with(
            "mig-restream-ck",
            Spec {
                parking: 2,
                capture: true,
                write_log: Some(Arc::new(QuietLog::default())),
                ..Spec::default()
            },
        );
        assert_eq!(reply(&f.checkpoint("ck", "fence"))["state"], "fenced");
        let (again, _) = f.migrate(r#"{"v":1,"op":"migrate","then":"fence","txid":"x","epoch":0}"#);
        let err = again.err().expect("refused").to_string();
        assert!(err.contains("fenced after a checkpoint"), "{err}");
    }

    /// A record of the guest's writes for a move whose guest changes both
    /// RAM and its disk while the rounds run: at each of its first
    /// collects it writes the next block of `writes` to `disk` and a page
    /// of RAM with a value of its own, through the guest's side, and
    /// reports every page written; after them it reports nothing.
    struct MovingGuestLog {
        ram: std::sync::OnceLock<Arc<GuestRam>>,
        disk: Arc<Mutex<VirtioBlk>>,
        writes: Mutex<Vec<u64>>,
    }

    impl crate::memory::GuestWriteLog for MovingGuestLog {
        fn start(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn collect(&self, into: &mut crate::memory::DirtyPages) -> std::io::Result<()> {
            let Some(block) = self.writes.lock().unwrap().pop() else {
                return Ok(());
            };
            let byte = 0xc0 | block as u8;
            lock_or_recover(&self.disk)
                .write_for_test(block * DIRTY_BLOCK_BYTES + 200, &[byte; 64]);
            let ram = self.ram.get().expect("the test set the RAM");
            // Not through `GuestRam::write`, which would mark hvi's own log:
            // the guest's stores do not.
            let ptr = ram.host_ptr(GPA + 0x3000, 4096).unwrap();
            // SAFETY: host_ptr bounds-checked the page.
            unsafe { std::ptr::write_bytes(ptr, byte, 4096) };
            for index in 0..into.region_count() {
                let (_, pages) = into.region(index).unwrap();
                into.set_range(index, 0, pages);
            }
            Ok(())
        }
        fn stop(&self) {}
        fn granule(&self) -> u64 {
            4096
        }
    }

    // The fence owner's second stream is the machine the first one moved,
    // though the guest wrote RAM and its disk during the first one's
    // rounds: applied to fresh RAM and to another copy of the base, it
    // makes the same RAM and the same disk as the first stream does, which
    // are the source's at the fence. Its manifest is its own, and RAM
    // round 0 differs from the first stream's round 0, so a mover compares
    // the documents by their digests, not the manifests.
    #[test]
    fn a_stream_sent_again_is_the_machine_the_first_one_moved() {
        let disk = TestDisk::new("mig-again-same", 20);
        let base = disk.bytes();
        disk.write(2, 0xa1);
        let log = Arc::new(MovingGuestLog {
            ram: std::sync::OnceLock::new(),
            disk: Arc::clone(&disk.dev),
            writes: Mutex::new(vec![20, 9, 5]),
        });
        let mut f = Fixture::with(
            "mig-again-same",
            Spec {
                parking: 2,
                capture: true,
                blk: disk.spec(),
                base: Some("ab".repeat(32)),
                noise_mib: 9,
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                ..Spec::default()
            },
        );
        log.ram.set(Arc::clone(&f.ram)).ok().unwrap();
        let line =
            r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-9","epoch":4,"max_rounds":3}"#;
        let mut first_disk = Image(base.clone());
        let (first, r1) = f.migrate_into(line, Some(&mut first_disk));
        let (first, first_ram) = first.expect("the first stream reads whole");
        assert_eq!(r1["state"], "fenced", "{r1}");
        let mut again_disk = Image(base);
        let (again, r2) = f.migrate_into(line, Some(&mut again_disk));
        let (again, again_ram) = again.expect("the stream sent again reads whole");
        assert_eq!(r2["state"], "fenced", "{r2}");

        let whole = |ram: &GuestRam| {
            let mut bytes = vec![0u8; 10 << 20];
            ram.read(GPA, &mut bytes).unwrap();
            bytes
        };
        let source = whole(&f.ram);
        assert_eq!(source[0x3000], 0xc0 | 20, "the guest wrote during the move");
        assert!(whole(&first_ram) == source, "the first stream moved RAM");
        assert!(
            whole(&again_ram) == source,
            "the second stream moved the same RAM"
        );
        assert!(
            first_disk.0 == disk.bytes(),
            "the first stream moved the disk"
        );
        assert!(
            again_disk.0 == disk.bytes(),
            "the second moved the same disk"
        );

        assert_ne!(r2["manifest_sha256"], r1["manifest_sha256"], "{r2}");
        assert_eq!(r2["stats"]["first_manifest_sha256"], r1["manifest_sha256"]);
        assert_eq!(
            r2["stats"]["same_as_first"],
            serde_json::json!([
                "profile.json",
                "cpu.json",
                "platform.json",
                "devices.json",
                "session.json"
            ]),
            "{r2}"
        );
        for name in ["cpu.json", "platform.json", "devices.json", "session.json"] {
            assert_eq!(first.doc(name), again.doc(name), "{name}");
        }
        assert_eq!(first.profile, again.profile);
    }

    // A request without an epoch is not one with epoch 0: a fence made
    // with epoch 0 is streamed again only for epoch 0, and a fence made
    // with no epoch cannot be told from another move, so never is.
    #[test]
    fn an_epoch_left_out_is_not_epoch_0() {
        let spec = || Spec {
            parking: 2,
            capture: true,
            write_log: Some(Arc::new(QuietLog::default())),
            ..Spec::default()
        };
        let mut f = Fixture::with("mig-restream-e0", spec());
        let (first, _) =
            f.migrate(r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-0","epoch":0}"#);
        assert!(first.is_ok());
        let (again, _) = f.migrate(r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-0"}"#);
        let err = again.err().expect("refused").to_string();
        assert!(err.contains("only the move that fenced it"), "{err}");
        let (again, r) =
            f.migrate(r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-0","epoch":0}"#);
        assert!(again.is_ok(), "{r}");
        drop(f);
        let mut f = Fixture::with("mig-restream-enone", spec());
        let (first, _) = f.migrate(r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-0"}"#);
        assert!(first.is_ok());
        for line in [
            r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-0"}"#,
            r#"{"v":1,"op":"migrate","then":"fence","txid":"tx-0","epoch":0}"#,
        ] {
            let (again, _) = f.migrate(line);
            let err = again.err().expect("refused").to_string();
            assert!(err.contains("gave no txid and epoch"), "{line}: {err}");
        }
    }

    // With disk rounds, the stream sent again has one disk round, every
    // block written since boot, read from the disk the fence left; with
    // the base it makes the source's disk, and disk.json lists that round.
    #[test]
    fn a_stream_sent_again_carries_the_whole_disk_delta() {
        let disk = TestDisk::new("mig-restream-disk", 20);
        let base = disk.bytes();
        disk.write(2, 0xa1);
        let log = Arc::new(DiskWritingLog {
            disk: Arc::clone(&disk.dev),
            writes: Mutex::new(vec![20, 9, 5]),
        });
        let mut f = Fixture::with(
            "mig-restream-disk",
            Spec {
                parking: 2,
                capture: true,
                blk: disk.spec(),
                base: Some("ab".repeat(32)),
                noise_mib: 9,
                write_log: Some(Arc::clone(&log) as Arc<dyn crate::memory::GuestWriteLog>),
                ..Spec::default()
            },
        );
        let line = r#"{"v":1,"op":"migrate","then":"fence","txid":"d2","epoch":1,"max_rounds":3}"#;
        let mut image = Image(base.clone());
        let (first, _) = f.migrate_into(line, Some(&mut image));
        first.expect("the first stream reads whole");
        let mut image = Image(base);
        let (again, r) = f.migrate_into(line, Some(&mut image));
        let (again, _) = again.expect("the stream sent again reads whole");
        assert!(
            image.0 == disk.bytes(),
            "the base and the one round are the disk"
        );
        let names: Vec<&str> = again.disk.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["disk-round-final"]);
        assert_eq!(again.disk[0].blocks, 4);
        assert_eq!(r["stats"]["disk_rounds"][0]["round"], 0, "{r}");
        let disk_json =
            crate::checkpoint::bundle::parse_disk(again.doc("disk.json").unwrap()).unwrap();
        assert_eq!(disk_json.rounds.len(), 1);
        assert_eq!(
            disk_json.rounds[0].sent_sha256.as_deref(),
            Some(again.disk[0].sha256.as_str())
        );
        assert_eq!(disk_json.rounds[0].generation, disk_json.generation);
    }

    // A vCPU that is in a long exit when the pause comes parks late. A
    // `pause` gives up at the control timeout and the VM runs on; a
    // `migrate` waits its own, longer bound, and the move goes ahead. The
    // refusal says how long the wait took.
    #[test]
    fn a_migrate_waits_longer_than_a_pause_for_a_slow_vcpu() {
        let mut f = Fixture::with(
            "mig-slow-park",
            Spec {
                parking: 2,
                capture: true,
                slow_exit: Some(Duration::from_millis(700)),
                write_log: Some(Arc::new(QuietLog::default())),
                ..Spec::default()
            },
        );
        let r = reply(&f.ask(r#"{"v":1,"op":"pause"}"#));
        assert_eq!(r["code"], "timeout", "{r}");
        let why = r["error"].as_str().unwrap();
        assert!(
            why.contains("vCPUs parked in time (") && why.contains("ms for the I/O threads"),
            "{r}"
        );
        // Let the vCPUs leave the exit the failed pause found them in.
        std::thread::sleep(Duration::from_millis(800));
        f.assert_running();
        let (got, r) = f.migrate(r#"{"v":1,"op":"migrate","then":"continue","max_rounds":1}"#);
        got.expect("the stream reads whole");
        assert_eq!(r["state"], "running", "{r}");
        let park = r["stats"]["park_ms"].as_u64().unwrap();
        assert!((600..5000).contains(&park), "{r}");
        f.assert_running();
    }
}

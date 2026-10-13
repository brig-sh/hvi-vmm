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

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::checkpoint::control::{
    format_response, parse_request, Error, ErrorCode, Request, Response, VmState, MAX_LINE,
};
use crate::checkpoint::profile::ProfileCell;
use crate::devices::virtio::vsock::retry_read;
use crate::hypervisor::vcpus::{Kick, PauseError, Vcpus};
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
}

impl ControlSocket {
    /// Binds the control socket at `path`, first removing a stale socket a
    /// previous run left.
    ///
    /// Only a socket is removed. Anything else at the path is an error, so a
    /// mistyped path such as `--control-sock disk.img` cannot delete a file.
    /// It must be bound before confinement, which allows accepting on a
    /// listener already held but not creating one.
    ///
    /// # Errors
    ///
    /// Errors if something other than a socket is at `path`, or the socket
    /// cannot be bound.
    // The host-path ban in clippy.toml is aimed at the virtio-fs device. This
    // path is the operator's.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn bind(path: &str, profile: Arc<ProfileCell>) -> std::io::Result<Self> {
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
        Ok(Self { listener, profile })
    }

    /// Serves connections until `stop` is requested.
    ///
    /// `gate` is the I/O threads' pause gate and `vcpus` the VM's vCPUs.
    pub(crate) fn run<K: Kick>(self, stop: &StopToken, gate: &PauseGate, vcpus: &Vcpus<K>) {
        self.run_with(stop, gate, vcpus, CONTROL_TIMEOUT);
    }

    /// [`run`](Self::run), with `timeout` for each wait.
    fn run_with<K: Kick>(
        self,
        stop: &StopToken,
        gate: &PauseGate,
        vcpus: &Vcpus<K>,
        timeout: Duration,
    ) {
        let mut machine = Machine {
            state: VmState::Running,
            gate,
            vcpus,
            profile: &self.profile,
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
            Request::Checkpoint { .. } => refuse(
                ErrorCode::NotImplemented,
                "checkpoint is not implemented by this hvi",
            ),
        };
        (response, None)
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
            VmState::Paused | VmState::Fenced => return Response::State(self.state),
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
            VmState::Paused => {
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
    use crate::checkpoint::profile::MachineProfile;
    use crate::config::Stop;
    use crate::hypervisor::vcpus::Outcome;
    use crate::run::StopHandle;
    use crate::teardown::StopSource;
    use std::io::BufRead;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::JoinHandle;
    use std::time::Instant;

    /// A kicker that reaches no thread; the fake vCPUs below poll instead.
    struct NoKick;

    impl Kick for NoKick {
        fn kick(&self, _cpu: u32) {}
        fn kick_all(&self) {}
    }

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
    }

    impl Fixture {
        /// Serves a VM of `parking` vCPUs that park at their checkpoints and
        /// `stuck` started ones that never do.
        fn new(name: &str, parking: u32, stuck: u32) -> Self {
            let path =
                std::env::temp_dir().join(format!("hvi-ctl-{}-{name}.sock", std::process::id()));
            let source = StopSource::new().unwrap();
            let vcpus = Arc::new(Vcpus::new(
                parking + stuck,
                NoKick,
                StopHandle::new_pair().unwrap().0,
            ));
            let fake_vcpus = (0..parking)
                .map(|_| {
                    vcpus.mark_started(vcpus.started());
                    let vcpus = Arc::clone(&vcpus);
                    std::thread::spawn(move || {
                        while vcpus.is_running() {
                            let _ = vcpus.checkpoint();
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    })
                })
                .collect();
            for _ in 0..stuck {
                vcpus.mark_started(vcpus.started());
            }
            let cell = Arc::new(
                ProfileCell::new(MachineProfile::for_this_host("aarch64", "hvf"), None).unwrap(),
            );
            let socket = ControlSocket::bind(path.to_str().unwrap(), Arc::clone(&cell)).unwrap();
            let server = {
                let (stop, gate, vcpus) = (
                    source.token(),
                    Arc::clone(source.gate()),
                    Arc::clone(&vcpus),
                );
                // A short deadline, so a test of a timeout is quick.
                std::thread::spawn(move || {
                    socket.run_with(&stop, &gate, &vcpus, Duration::from_millis(200));
                })
            };
            let client = UnixStream::connect(&path).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
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
            r#"{"v":1,"ok":false,"code":"not_implemented","error":"checkpoint is not implemented by this hvi"}"#
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
        drop(ControlSocket::bind(stale.to_str().unwrap(), cell()).expect("a stale socket"));
        let _ = std::fs::remove_file(&stale);

        let file = dir.join(format!("hvi-ctl-{}-disk.img", std::process::id()));
        std::fs::write(&file, b"guest disk").unwrap();
        let err = ControlSocket::bind(file.to_str().unwrap(), cell())
            .err()
            .expect("a regular file");
        assert!(err.to_string().contains("is not a socket"), "{err}");
        assert_eq!(std::fs::read(&file).unwrap(), b"guest disk");
        let _ = std::fs::remove_file(&file);
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

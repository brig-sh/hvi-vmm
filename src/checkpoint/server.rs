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
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

use crate::checkpoint::control::{
    format_response, parse_request, Error, ErrorCode, Request, Response, VmState, MAX_LINE,
};
use crate::checkpoint::profile::ProfileCell;
use crate::config::Stop;
use crate::devices::virtio::vsock::retry_read;
use crate::hypervisor::vcpus::{Kick, PauseError, Vcpus};
use crate::teardown::{PauseGate, StopToken};
use crate::LOG_PREFIX;

/// How long a pause waits for the I/O threads, and then for the vCPUs, and
/// how long `profile` waits for the profile to be complete.
pub(crate) const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// It must be bound before confinement, which allows accepting on a
    /// listener already held but not creating one.
    ///
    /// # Errors
    ///
    /// Errors if the socket cannot be bound.
    // The host-path ban in clippy.toml is aimed at the virtio-fs device. This
    // path is the operator's.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn bind(path: &str, profile: Arc<ProfileCell>) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(path);
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
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if retry_read(&e) => continue,
            Err(e) => return Err(e),
        };
        pending.extend_from_slice(&chunk[..n]);
        while let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line[..end]);
            if line.trim().is_empty() {
                continue;
            }
            let (response, then) = match parse_request(&line) {
                Ok(request) => machine.handle(request),
                Err(e) => (Response::Error(e), None),
            };
            send(&mut conn, stop, &response)?;
            if let Some(after) = then {
                after.run(machine.vcpus);
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
            Request::Profile => match self.profile.get(self.timeout) {
                Some(profile) => Response::Profile(Box::new(profile)),
                None => refuse(ErrorCode::NotReady, "the boot vCPU has not started yet"),
            },
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

    /// Holds the I/O threads, then parks the vCPUs. Pausing a paused VM
    /// succeeds and changes nothing.
    fn pause(&mut self) -> Response {
        match self.state {
            VmState::Paused | VmState::Fenced => return Response::State(self.state),
            VmState::Stopping => return refuse(ErrorCode::Stopped, "the run is ending"),
            VmState::Running => {}
        }
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
        match self.vcpus.pause_from_control(self.timeout) {
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
            let vcpus = Arc::new(Vcpus::new(parking + stuck, NoKick));
            let fake_vcpus = (0..parking)
                .map(|_| {
                    vcpus.mark_started();
                    let vcpus = Arc::clone(&vcpus);
                    std::thread::spawn(move || {
                        while vcpus.is_running() {
                            vcpus.checkpoint();
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    })
                })
                .collect();
            for _ in 0..stuck {
                vcpus.mark_started();
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

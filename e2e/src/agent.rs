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

//! A connection to the guest agent, through hvi's agent socket.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use hvi_e2e_protocol::{read_frame, write_frame, Request, Response};

/// How long a request may wait for its response beyond the time the request
/// itself allows.
const RESPONSE_MARGIN: Duration = Duration::from_secs(10);

/// One connection to the guest agent.
pub struct Agent {
    /// The connection to hvi's agent socket, which hvi bridges to the guest.
    stream: UnixStream,
}

impl Agent {
    /// Connects to the agent behind the agent socket at `socket`, retrying
    /// until it answers a [`Request::Ping`] or `timeout` passes.
    ///
    /// hvi accepts a connection before the guest listens, and ends it when the
    /// guest refuses it. A connection counts only once the agent has answered
    /// on it.
    ///
    /// # Errors
    ///
    /// Returns the last error when no attempt succeeds within `timeout`.
    pub fn connect(socket: &Path, timeout: Duration) -> io::Result<Agent> {
        let deadline = Instant::now() + timeout;
        loop {
            let err = match Agent::ping(socket) {
                Ok(agent) => return Ok(agent),
                Err(e) => e,
            };
            if Instant::now() >= deadline {
                return Err(err);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Connects once and checks that the agent answers.
    fn ping(socket: &Path) -> io::Result<Agent> {
        let stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut agent = Agent { stream };
        match agent.request(&Request::Ping)? {
            Response::Pong => Ok(agent),
            other => Err(io::Error::other(format!("expected Pong, got {other:?}"))),
        }
    }

    /// Sends `request` and returns the response.
    ///
    /// # Errors
    ///
    /// Errors if the request cannot be written or no response arrives.
    pub fn request(&mut self, request: &Request) -> io::Result<Response> {
        write_frame(&mut self.stream, request)?;
        read_frame(&mut self.stream)
    }

    /// Runs `program` with `args` in the guest and returns how it ended.
    ///
    /// The agent kills the program after `timeout`. Its response arrives by
    /// then, even if a background job the program started still holds the
    /// program's output open.
    ///
    /// # Errors
    ///
    /// Errors if the request fails or the agent cannot start the program.
    pub fn run(
        &mut self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> io::Result<GuestOutput> {
        self.stream
            .set_read_timeout(Some(timeout + RESPONSE_MARGIN))?;
        let request = Request::Run {
            program: program.into(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
            timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        };
        match self.request(&request)? {
            Response::Exited {
                code,
                signal,
                stdout,
                stderr,
                timed_out,
            } => Ok(GuestOutput {
                code,
                signal,
                stdout,
                stderr,
                timed_out,
            }),
            Response::Failed { message } => Err(io::Error::other(message)),
            other => Err(io::Error::other(format!("expected Exited, got {other:?}"))),
        }
    }

    /// Returns the underlying connection.
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }
}

/// How a program the agent ran ended.
#[derive(Clone, Debug)]
pub struct GuestOutput {
    /// The exit code, or `None` when a signal ended the program.
    pub code: Option<i32>,
    /// The signal that ended the program, or `None` when it exited.
    pub signal: Option<i32>,
    /// What the program wrote to stdout.
    pub stdout: String,
    /// What the program wrote to stderr.
    pub stderr: String,
    /// Whether the agent killed the program at its timeout.
    pub timed_out: bool,
}

impl GuestOutput {
    /// Returns whether the program exited with status 0.
    pub fn is_success(&self) -> bool {
        self.code == Some(0)
    }

    /// Returns the output, after checking that the program exited with status
    /// 0.
    ///
    /// # Panics
    ///
    /// Panics with the program's output if it did not.
    #[track_caller]
    pub fn assert_success(self) -> GuestOutput {
        assert!(
            self.is_success(),
            "the guest program failed: code {:?}, signal {:?}, timed out {}\n\
             stdout:\n{}\nstderr:\n{}",
            self.code,
            self.signal,
            self.timed_out,
            self.stdout,
            self.stderr
        );
        self
    }
}

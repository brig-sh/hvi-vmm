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

//! The messages the e2e harness and the guest agent exchange.
//!
//! The harness reaches the agent through hvi's agent socket, which hvi bridges
//! to the guest over vsock. Each message is one frame, a 4-byte big-endian
//! length followed by that many bytes of JSON. A connection carries one
//! [`Request`] and one [`Response`] at a time, in that order.
//!
//! Four requests change what follows their response. After [`Request::Echo`]
//! and [`Request::Sink`] the connection carries raw bytes, and after
//! [`Request::PowerOff`] and [`Request::Reset`] the guest stops.

use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The vsock port the agent listens on, which is the port hvi bridges its agent
/// socket to.
pub const VSOCK_PORT: u32 = 1024;

/// The largest frame either side accepts.
pub const MAX_FRAME_LEN: u32 = 16 << 20;

/// A request from the harness to the agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// A liveness check, answered by [`Response::Pong`].
    Ping,
    /// A program to run and wait for, answered by [`Response::Exited`].
    Run {
        /// The program, found on the guest's `PATH`.
        program: String,
        /// The program's arguments.
        args: Vec<String>,
        /// How long the program may run before the agent kills it.
        timeout_ms: u64,
    },
    /// A request to send back the next `len` bytes the harness sends, answered
    /// by [`Response::Ready`] before the first byte.
    ///
    /// The connection then returns to requests.
    Echo {
        /// How many bytes the agent echoes.
        len: u64,
    },
    /// A request to write every byte the harness sends to `path` until it
    /// closes the connection, answered by [`Response::Ready`] before the first
    /// byte.
    Sink {
        /// The guest file the bytes go to, created or truncated.
        path: String,
    },
    /// A request to sync the guest's filesystems and power it off, answered by
    /// [`Response::Accepted`] first.
    PowerOff,
    /// A request to sync the guest's filesystems and reset it, answered by
    /// [`Response::Accepted`] first.
    Reset,
}

/// The agent's answer to a [`Request`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// The answer to [`Request::Ping`].
    Pong,
    /// How a program from [`Request::Run`] ended.
    Exited {
        /// The exit code, or `None` when a signal ended the program.
        code: Option<i32>,
        /// The signal that ended the program, or `None` when it exited.
        signal: Option<i32>,
        /// What the program wrote to stdout, with invalid UTF-8 replaced.
        stdout: String,
        /// What the program wrote to stderr, with invalid UTF-8 replaced.
        stderr: String,
        /// Whether the agent killed the program at its timeout.
        timed_out: bool,
    },
    /// A notice that the connection is about to carry raw bytes, as the request
    /// asked.
    Ready,
    /// A notice that the guest is about to stop, as the request asked.
    Accepted,
    /// A report that the request could not be carried out.
    Failed {
        /// What went wrong.
        message: String,
    },
}

/// Writes `message` to `writer` as one frame.
///
/// # Errors
///
/// Errors if the message does not serialize, is larger than [`MAX_FRAME_LEN`],
/// or cannot be written.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, message: &T) -> io::Result<()> {
    let body = serde_json::to_vec(message).map_err(io::Error::other)?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|len| *len <= MAX_FRAME_LEN)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

/// Returns the message decoded from the next frame in `reader`.
///
/// # Errors
///
/// Errors with [`io::ErrorKind::UnexpectedEof`] if the connection ends before a
/// whole frame, and with [`io::ErrorKind::InvalidData`] if the frame is larger
/// than [`MAX_FRAME_LEN`] or does not decode.
pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> io::Result<T> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes is larger than {MAX_FRAME_LEN}"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_a_frame() {
        let request = Request::Run {
            program: "sh".into(),
            args: vec!["-c".into(), "true".into()],
            timeout_ms: 1000,
        };
        let mut wire = Vec::new();
        write_frame(&mut wire, &request).unwrap();
        assert_eq!(
            read_frame::<_, Request>(&mut wire.as_slice()).unwrap(),
            request
        );
    }

    #[test]
    fn oversized_length_is_refused_before_reading_the_body() {
        let wire = (MAX_FRAME_LEN + 1).to_be_bytes();
        let err = read_frame::<_, Request>(&mut wire.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_frame_is_an_eof() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &Request::Ping).unwrap();
        wire.pop();
        let err = read_frame::<_, Request>(&mut wire.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}

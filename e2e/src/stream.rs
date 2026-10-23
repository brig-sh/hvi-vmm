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

//! An output stream of the `hvi` process, drained as it arrives.
//!
//! hvi writes the guest's console to stdout from the vCPU thread, so a stdout
//! nobody reads stalls the guest. Each stream is read on a thread of its own
//! into a buffer the test can wait on. A second thread writes what was read to
//! a log file, so a slow disk does not hold up the reading.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The bytes a stream has carried so far, and whether it has ended.
#[derive(Default)]
struct Contents {
    /// Everything read so far.
    bytes: Vec<u8>,
    /// Whether the stream reached its end.
    ended: bool,
}

/// One output stream of a running process.
pub(crate) struct Stream {
    /// What the reader thread has read, shared with it.
    contents: Arc<(Mutex<Contents>, Condvar)>,
    /// The reader thread, until [`Stream::join`].
    reader: Option<JoinHandle<()>>,
    /// The thread that writes the log file, until [`Stream::join`].
    writer: Option<JoinHandle<()>>,
}

impl Stream {
    /// Starts draining `pipe` into the file at `log` and the buffer.
    ///
    /// # Panics
    ///
    /// Panics if the log file cannot be created.
    pub(crate) fn drain(pipe: impl Read + Send + 'static, log: &Path) -> Stream {
        let mut file =
            File::create(log).unwrap_or_else(|e| panic!("creating {}: {e}", log.display()));
        let (to_log, chunks) = mpsc::channel::<Vec<u8>>();
        let writer = std::thread::spawn(move || {
            for chunk in chunks {
                let _ = file.write_all(&chunk);
            }
        });
        let contents = Arc::new((Mutex::new(Contents::default()), Condvar::new()));
        let shared = Arc::clone(&contents);
        let reader = std::thread::spawn(move || {
            let mut pipe = pipe;
            let mut chunk = [0u8; 8192];
            loop {
                let n = match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let (lock, condvar) = &*shared;
                lock.lock().unwrap().bytes.extend_from_slice(&chunk[..n]);
                condvar.notify_all();
                let _ = to_log.send(chunk[..n].to_vec());
            }
            let (lock, condvar) = &*shared;
            lock.lock().unwrap().ended = true;
            condvar.notify_all();
        });
        Stream {
            contents,
            reader: Some(reader),
            writer: Some(writer),
        }
    }

    /// Returns what the stream has carried so far, with invalid UTF-8 replaced.
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.contents.0.lock().unwrap().bytes).into_owned()
    }

    /// Returns whether `needle` appears in the stream within `timeout`, or
    /// `false` once the stream ends without it.
    pub(crate) fn wait_for(&self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (lock, condvar) = &*self.contents;
        let mut contents = lock.lock().unwrap();
        loop {
            if String::from_utf8_lossy(&contents.bytes).contains(needle) {
                return true;
            }
            let now = Instant::now();
            if contents.ended || now >= deadline {
                return false;
            }
            contents = condvar.wait_timeout(contents, deadline - now).unwrap().0;
        }
    }

    /// Waits for the reader thread, once the process has exited and closed the
    /// stream, and then for the log file to be written.
    pub(crate) fn join(&mut self) {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        // The reader thread drops its sender when it ends, which ends the
        // writer's loop.
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

/// Returns the last `lines` lines of `text`, for a failure message.
pub(crate) fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

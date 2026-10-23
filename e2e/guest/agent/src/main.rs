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

//! The guest side of the e2e suite.
//!
//! The guest's init starts this program. It listens on vsock port
//! [`hvi_e2e_protocol::VSOCK_PORT`], serves each connection on a thread of its
//! own, and answers each [`hvi_e2e_protocol::Request`]. It is built for the
//! guest's musl target and linked statically, so it runs on any root
//! filesystem.
//!
//! Run as `hvi-e2e-agent devmem <address>`, it reads 32 bits at a physical
//! address instead, as busybox's `devmem` does, so a test can make the guest
//! touch a device's registers or an address that no device claims. On arm64,
//! `hvi-e2e-agent load-pair <address>` reads two words there with one `ldp`.

#[cfg(target_os = "linux")]
mod devmem;
#[cfg(target_os = "linux")]
mod vsock;

#[cfg(target_os = "linux")]
fn main() {
    use std::io::Write;

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("devmem") => read_once("devmem", args.next(), |address| {
            devmem::read_u32(address).map(|value| format!("{value:#010x}"))
        }),
        #[cfg(target_arch = "aarch64")]
        Some("load-pair") => read_once("load-pair", args.next(), |address| {
            devmem::load_pair(address)
                .map(|(first, second)| format!("{first:#010x} {second:#010x}"))
        }),
        _ => {}
    }

    let listener = match vsock::Listener::bind(hvi_e2e_protocol::VSOCK_PORT) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!(
                "hvi-e2e-agent: listening on vsock port {}: {e}",
                hvi_e2e_protocol::VSOCK_PORT
            );
            std::process::exit(1);
        }
    };
    println!(
        "hvi-e2e-agent: listening on vsock port {}",
        hvi_e2e_protocol::VSOCK_PORT
    );
    let _ = std::io::stdout().flush();
    loop {
        match listener.accept() {
            Ok(connection) => {
                std::thread::spawn(move || serve::connection(connection));
            }
            Err(e) => eprintln!("hvi-e2e-agent: accepting a connection: {e}"),
        }
    }
}

/// Reads at the hexadecimal address `arg` with `read`, prints the result, and
/// exits, for the one-shot mode `mode`.
#[cfg(target_os = "linux")]
fn read_once(
    mode: &str,
    arg: Option<String>,
    read: impl FnOnce(u64) -> std::io::Result<String>,
) -> ! {
    let address =
        arg.and_then(|arg| u64::from_str_radix(arg.strip_prefix("0x").unwrap_or(&arg), 16).ok());
    let Some(address) = address else {
        eprintln!("hvi-e2e-agent: {mode} needs a hexadecimal address");
        std::process::exit(2);
    };
    match read(address) {
        Ok(text) => {
            println!("{text}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("hvi-e2e-agent: reading {address:#x}: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("hvi-e2e-agent runs in a Linux guest");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod serve {
    //! Serving one connection.

    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use hvi_e2e_protocol::{read_frame, write_frame, Request, Response};

    /// Answers requests on `connection` until the harness closes it.
    pub(crate) fn connection(mut connection: File) {
        loop {
            let request: Request = match read_frame(&mut connection) {
                Ok(request) => request,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return,
                Err(e) => {
                    eprintln!("hvi-e2e-agent: reading a request: {e}");
                    return;
                }
            };
            if let Err(e) = answer(&mut connection, request) {
                eprintln!("hvi-e2e-agent: answering a request: {e}");
                return;
            }
        }
    }

    /// Answers `request` on `connection`.
    fn answer(connection: &mut File, request: Request) -> io::Result<()> {
        match request {
            Request::Ping => write_frame(connection, &Response::Pong),
            Request::Run {
                program,
                args,
                timeout_ms,
            } => {
                let response = run(&program, &args, Duration::from_millis(timeout_ms))
                    .unwrap_or_else(|e| Response::Failed {
                        message: format!("running {program}: {e}"),
                    });
                // A response over the frame limit is refused before any of it
                // is written, so a short one can still say why.
                match write_frame(connection, &response) {
                    Err(e) if e.kind() == io::ErrorKind::InvalidInput => write_frame(
                        connection,
                        &Response::Failed {
                            message: format!("running {program}: its output is too large"),
                        },
                    ),
                    written => written,
                }
            }
            Request::Echo { len } => {
                write_frame(connection, &Response::Ready)?;
                echo(connection, len)
            }
            Request::Sink { path } => {
                let mut file = match File::create(&path) {
                    Ok(file) => file,
                    Err(e) => {
                        let message = format!("creating {path}: {e}");
                        return write_frame(connection, &Response::Failed { message });
                    }
                };
                write_frame(connection, &Response::Ready)?;
                io::copy(connection, &mut file)?;
                file.sync_all()
            }
            Request::PowerOff => stop(connection, libc::RB_POWER_OFF),
            Request::Reset => stop(connection, libc::RB_AUTOBOOT),
        }
    }

    /// Runs `program` with `args`, killing it once `timeout` has passed.
    ///
    /// The program leads a process group of its own, and the timeout kills the
    /// whole group, so its children that are still running die with it. A
    /// background job that outlives the program keeps running. If it holds the
    /// program's stdout or stderr, the pipes are read only until the timeout.
    fn run(program: &str, args: &[String], timeout: Duration) -> io::Result<Response> {
        let mut child = Command::new(program)
            .args(args)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let group = libc::pid_t::try_from(child.id()).expect("a pid should fit pid_t");
        // Each pipe gets a thread, so a program that fills one pipe while
        // waiting on another cannot stall.
        let stdout = Drain::start(child.stdout.take().expect("stdout should be piped"));
        let stderr = Drain::start(child.stderr.take().expect("stderr should be piped"));
        let deadline = Instant::now() + timeout;
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                // SAFETY: kill takes plain values; a negative pid names the
                // program's process group.
                unsafe { libc::kill(-group, libc::SIGKILL) };
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        // The pipes are read until the deadline, and a moment longer for what a
        // killed program had already written.
        let end = deadline.max(Instant::now() + Duration::from_millis(100));
        while !(stdout.is_finished() && stderr.is_finished()) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(Response::Exited {
            code: status.code(),
            signal: status.signal(),
            stdout: stdout.text(),
            stderr: stderr.text(),
            timed_out,
        })
    }

    /// A pipe read to its end on a thread of its own, into a buffer that can be
    /// read before the end.
    struct Drain {
        /// What has been read so far.
        bytes: Arc<Mutex<Vec<u8>>>,
        /// The reading thread.
        thread: std::thread::JoinHandle<()>,
    }

    impl Drain {
        /// Starts reading `pipe`.
        fn start(mut pipe: impl Read + Send + 'static) -> Drain {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&bytes);
            let thread = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n @ 1..) = pipe.read(&mut buf) {
                    sink.lock()
                        .expect("the buffer lock should not be poisoned")
                        .extend_from_slice(&buf[..n]);
                }
            });
            Drain { bytes, thread }
        }

        /// Returns whether the pipe has been read to its end.
        fn is_finished(&self) -> bool {
            self.thread.is_finished()
        }

        /// Returns what has been read so far, as text.
        fn text(&self) -> String {
            String::from_utf8_lossy(
                &self
                    .bytes
                    .lock()
                    .expect("the buffer lock should not be poisoned"),
            )
            .into_owned()
        }
    }

    /// Sends back the next `len` bytes read from `connection`.
    fn echo(connection: &mut File, mut len: u64) -> io::Result<()> {
        let mut buf = vec![0u8; 64 << 10];
        while len > 0 {
            let want = buf.len().min(usize::try_from(len).unwrap_or(usize::MAX));
            let n = connection.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            connection.write_all(&buf[..n])?;
            len -= n as u64;
        }
        Ok(())
    }

    /// Stops the guest with the `reboot(2)` command `command`, after answering
    /// [`Response::Accepted`] and syncing.
    fn stop(connection: &mut File, command: libc::c_int) -> io::Result<()> {
        write_frame(connection, &Response::Accepted)?;
        // SAFETY: sync takes no arguments and cannot fail.
        unsafe { libc::sync() };
        // SAFETY: reboot takes a plain command value; on success it does not
        // return.
        if unsafe { libc::reboot(command) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

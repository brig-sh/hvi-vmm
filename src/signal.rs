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

//! The signals hvi handles: the stop signals a binary can turn into a stop
//! request, and the signal hvi kicks its own threads with.
//!
//! [`stop_on_signals`] makes `SIGTERM`, `SIGINT` and `SIGHUP` request a stop on
//! a [`StopHandle`], and a binary that wants that calls it before `boot`. The
//! next `boot` installs the handlers and starts a thread of their own that
//! receives the signals, so what a signal does runs as ordinary code rather
//! than in a signal handler. A second one that arrives [`STOP_TIMEOUT`] or more
//! after the first ends the process at once. Once `boot` has returned, the
//! binary calls [`exit_by_signal`] with the handle's
//! [`signal`](StopHandle::signal), so the process ends the way the signal would
//! have ended it.
//!
//! A kick ends a blocking call on the thread it is sent to: `KVM_RUN` on a KVM
//! vCPU thread, and the console reader's read of stdin on every backend.

use std::io;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use signal_hook::iterator::{Handle, Signals};

use crate::stop::StopHandle;
use crate::sync::lock_or_recover;
use crate::teardown::STOP_TIMEOUT;

/// The signals [`stop_on_signals`] turns into a stop request.
pub const STOP_SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

/// The state [`stop_on_signals`] and `boot` share with the thread that receives
/// the stop signals, set by the first call.
static STOP_SIGNAL_STATE: OnceLock<Mutex<StopSignals>> = OnceLock::new();

/// What the thread that receives the stop signals acts on.
struct StopSignals {
    /// The stop the signals request, from the latest [`stop_on_signals`].
    target: StopHandle,
    /// When the first stop signal for `target` arrived.
    first: Option<Instant>,
    /// The handle that adds a signal to the set the thread receives, once
    /// `boot` has started the thread.
    signals: Option<Handle>,
    /// The stop signals registered so far, whose action is signal-hook's
    /// handler.
    registered: Vec<libc::c_int>,
}

impl StopSignals {
    /// Registers each stop signal not registered yet, apart from those the
    /// process ignores, once the thread has started.
    ///
    /// # Errors
    ///
    /// Errors if a signal's action cannot be read or its handler installed.
    fn register(&mut self) -> io::Result<()> {
        let Some(signals) = &self.signals else {
            return Ok(());
        };
        for signal in STOP_SIGNALS {
            if self.registered.contains(&signal) || action(signal)?.sa_sigaction == libc::SIG_IGN {
                continue;
            }
            signals.add_signal(signal)?;
            self.registered.push(signal);
        }
        Ok(())
    }
}

/// Makes [`STOP_SIGNALS`] request a stop on `handle`.
///
/// The signals keep their actions until the next `boot` starts its run: on
/// Linux once it arms its filters, on macOS before it enters the sandbox. Until
/// then a stop signal ends the process, unless the binary changed its action.
/// That `boot` installs signal-hook's handlers for them, which it does not
/// remove, and starts the thread that receives them, which runs for the life of
/// the process.
///
/// A signal the process ignores when the run starts stays ignored, as `nohup`
/// leaves `SIGHUP` and a shell leaves `SIGINT` for a background job. A binary
/// that wants the stop on such a signal sets it to its default action first.
/// Once a run has started, the next call registers it at once. A binary makes
/// no other change to these signals' actions once a run has started, since a
/// registered signal is not installed again. A handler a signal already has
/// still runs, before the stop request.
///
/// A second stop signal that arrives [`STOP_TIMEOUT`] or more after the first
/// ends the process with the signal's default action, so a stop that does not
/// complete can still be ended. One that arrives sooner has no effect, so a
/// copy that a wrapper forwards does not cut the stop short. A later call moves
/// the signals to another handle and releases the one before.
///
/// A first stop signal that arrives once the run of `handle` has ended asks a
/// finished run to stop and has no effect. Only another one, [`STOP_TIMEOUT`]
/// or more later, ends the process. A binary that keeps running after `boot`
/// returns checks [`StopHandle::signal`] once it is done, as hvi's binary does
/// at once.
///
/// # Errors
///
/// Errors if, in a call made after a run has started, a signal's action cannot
/// be read or its handler installed.
pub fn stop_on_signals(handle: &StopHandle) -> io::Result<()> {
    let state = STOP_SIGNAL_STATE.get_or_init(|| {
        Mutex::new(StopSignals {
            target: handle.clone(),
            first: None,
            signals: None,
            registered: Vec::new(),
        })
    });
    let mut state = lock_or_recover(state);
    state.target = handle.clone();
    state.first = None;
    state.register()
}

/// Installs the handlers for the stop signals and starts the thread that
/// receives them, when [`stop_on_signals`] has been called.
///
/// `boot` calls it as the run starts: on Linux once its filters are armed, so
/// the thread installs the `vmm` filter as its first act, and on macOS before
/// it enters the sandbox. A thread a run already started serves the later ones,
/// and a signal no longer ignored joins its set. A thread that cannot be
/// started leaves the handlers uninstalled, and the next `boot` tries again.
///
/// # Errors
///
/// Errors if the thread cannot be started, or a signal's action cannot be read
/// or its handler installed.
pub(crate) fn start_stop_signal_thread() -> io::Result<()> {
    let Some(state) = STOP_SIGNAL_STATE.get() else {
        return Ok(());
    };
    let mut stop_signals = lock_or_recover(state);
    if stop_signals.signals.is_none() {
        let signals = Signals::new(std::iter::empty::<libc::c_int>())?;
        let handle = signals.handle();
        std::thread::Builder::new()
            .name("stop signals".to_string())
            .spawn(move || receive_stop_signals(state, signals))?;
        stop_signals.signals = Some(handle);
    }
    stop_signals.register()
}

/// Receives the stop signals and acts on each, for the life of the process.
///
/// The first signal for a target requests its stop. A later one ends the
/// process, unless it arrives within [`STOP_TIMEOUT`] of the first.
fn receive_stop_signals(state: &Mutex<StopSignals>, mut signals: Signals) {
    crate::sandbox::confine_io_thread();
    // The thread inherits the mask of the one that started it, and a stop
    // signal blocked here would only pend when it is raised to end the process.
    unblock(&STOP_SIGNALS);
    for signal in signals.forever() {
        // A run with the sandbox off starts the thread unfiltered, so each wake
        // confines it under the filters a later run armed.
        crate::sandbox::confine_io_thread();
        let escalate = {
            let mut state = lock_or_recover(state);
            match state.first {
                None => {
                    state.first = Some(Instant::now());
                    state.target.request_stop_by(signal);
                    false
                }
                Some(first) => first.elapsed() >= STOP_TIMEOUT,
            }
        };
        if escalate {
            raise_with_default_action(signal);
        }
    }
}

/// Unblocks `signals` on the calling thread.
fn unblock(signals: &[libc::c_int]) {
    // SAFETY: `sigset_t` is plain data, so a zeroed one is valid, and the calls
    // only write the set and the calling thread's mask.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &signal in signals {
            libc::sigaddset(&mut set, signal);
        }
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    }
}

/// Ends the process by `signal`, with the signal's default action.
///
/// It resets `signal` to its default action and raises it on the calling
/// thread, so the parent sees the process end by that signal. The signal is
/// then unblocked on that thread, since a blocked one stays pending. If the
/// action does not end the process, it exits with status `128 + signal`.
pub fn exit_by_signal(signal: libc::c_int) -> ! {
    raise_with_default_action(signal);
    unblock(&[signal]);
    std::process::exit(128 + signal)
}

/// Returns the signal that kicks a thread out of a blocking call.
///
/// Linux uses the first real-time signal, so `SIGUSR1` stays free for a program
/// that embeds hvi. macOS has no real-time signals and uses `SIGUSR1`.
pub(crate) fn kick_signal() -> libc::c_int {
    #[cfg(target_os = "linux")]
    let signal = libc::SIGRTMIN();
    #[cfg(target_os = "macos")]
    let signal = libc::SIGUSR1;
    signal
}

/// Returns the action of `signal`.
///
/// It is one `sigaction` call, so a signal handler can call it.
///
/// # Errors
///
/// Errors if `signal` is not a valid signal.
pub(crate) fn action(signal: libc::c_int) -> io::Result<libc::sigaction> {
    // SAFETY: `sigaction` is plain data, so a zeroed one is valid, and the call
    // only writes it.
    unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(signal, std::ptr::null(), &mut current) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(current)
    }
}

/// Sets the action of `signal` to `handler`, with `flags` and an empty mask.
///
/// It is one `sigaction` call, so a signal handler can call it.
///
/// # Errors
///
/// Errors if the action cannot be set.
///
/// # Safety
///
/// `handler` is `SIG_DFL`, `SIG_IGN`, or the address of a handler function that
/// takes the arguments `flags` says it takes and makes only calls that are safe
/// in a signal handler.
pub(crate) unsafe fn set_action(
    signal: libc::c_int,
    handler: libc::sighandler_t,
    flags: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `sigaction` is plain data, so a zeroed one is valid, and the call
    // only reads it.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = flags;
        if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Raises `signal` on the calling thread with its default action.
///
/// It resets the action and calls `raise`, so a signal handler can call it.
/// Inside a handler for `signal`, the signal stays blocked until the handler
/// returns.
pub(crate) fn raise_with_default_action(signal: libc::c_int) {
    // SAFETY: the default action runs no handler, and `raise` sends the signal
    // to the calling thread.
    unsafe {
        let _ = set_action(signal, libc::SIG_DFL, 0);
        libc::raise(signal);
    }
}

/// Installs a no-op handler for the [kick signal](kick_signal).
///
/// The handler is installed without `SA_RESTART`, so a blocking call the signal
/// interrupts returns `EINTR` instead of resuming.
pub(crate) fn install_kick_handler() {
    extern "C" fn noop(_: libc::c_int) {}
    // SAFETY: the handler takes the signal number alone and does nothing.
    let _ = unsafe { set_action(kick_signal(), noop as *const () as usize, 0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// The variable that names the case [`stop_signal_child`] runs.
    const CHILD: &str = "HVI_STOP_SIGNAL_CHILD";

    /// Sets `signal` to its default action when the process ignores it, as a
    /// test run under `nohup` ignores `SIGHUP`.
    fn unignore(signal: libc::c_int) {
        if action(signal).unwrap().sa_sigaction == libc::SIG_IGN {
            // SAFETY: the default action runs no handler.
            unsafe { set_action(signal, libc::SIG_DFL, 0) }.unwrap();
        }
    }

    /// Makes the stop signals request a stop on `handle`, then installs the
    /// handlers and starts the thread, as `boot` would.
    fn stop_on_signals_now(handle: &StopHandle) {
        stop_on_signals(handle).unwrap();
        start_stop_signal_thread().unwrap();
    }

    /// Raises `signal` on the calling thread, which reaches the handler on this
    /// thread.
    fn raise(signal: libc::c_int) {
        // SAFETY: raising a signal on the calling thread.
        assert_eq!(unsafe { libc::raise(signal) }, 0);
    }

    /// Runs [`stop_signal_child`] for `case` in a process of its own, so no
    /// other test has touched the signals' actions, and returns how it ended
    /// and what it wrote to stdout.
    ///
    /// A child that hangs fails the test rather than holding it up.
    fn run_child(case: &str) -> (ExitStatus, String) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "signal::tests::stop_signal_child"])
            .env(CHILD, case)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the child for {case} did not end");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        (status, out)
    }

    /// Whether the handler a test installs before [`stop_on_signals`] ran.
    static EARLIER_HANDLER_RAN: AtomicBool = AtomicBool::new(false);

    // The child half of the tests below. Each case that passes exits with a
    // status of its own, which the parent checks, so a child that ran no test
    // does not pass. It returns at once in a normal run.
    #[test]
    fn stop_signal_child() {
        let Ok(case) = std::env::var(CHILD) else {
            return;
        };
        let (handle, _registration) = StopHandle::new_pair().unwrap();
        match case.as_str() {
            "request" => {
                unignore(libc::SIGHUP);
                stop_on_signals_now(&handle);
                raise(libc::SIGHUP);
                assert!(handle.wait_for_request(Duration::from_secs(5)));
                assert_eq!(handle.signal(), Some(libc::SIGHUP));
                std::process::exit(10);
            }
            "repeat" => {
                unignore(libc::SIGHUP);
                stop_on_signals_now(&handle);
                raise(libc::SIGHUP);
                // The second raise waits for the first to be acted on, so the
                // two are not taken as one.
                assert!(handle.wait_for_request(Duration::from_secs(5)));
                raise(libc::SIGHUP);
                std::thread::sleep(Duration::from_millis(100));
                assert_eq!(handle.signal(), Some(libc::SIGHUP));
                std::process::exit(11);
            }
            "ignored" => {
                // SAFETY: an ignored signal runs no handler.
                unsafe { set_action(libc::SIGINT, libc::SIG_IGN, 0) }.unwrap();
                stop_on_signals_now(&handle);
                assert_eq!(action(libc::SIGINT).unwrap().sa_sigaction, libc::SIG_IGN);
                std::process::exit(12);
            }
            "earlier" => {
                extern "C" fn note(_: libc::c_int) {
                    EARLIER_HANDLER_RAN.store(true, Ordering::SeqCst);
                }
                // SAFETY: the handler takes the signal number alone and only
                // stores an atomic.
                unsafe { set_action(libc::SIGTERM, note as *const () as usize, 0) }.unwrap();
                stop_on_signals_now(&handle);
                raise(libc::SIGTERM);
                assert!(handle.wait_for_request(Duration::from_secs(5)));
                assert!(EARLIER_HANDLER_RAN.load(Ordering::SeqCst));
                std::process::exit(13);
            }
            "unignored-later" => {
                // SAFETY: an ignored signal runs no handler.
                unsafe { set_action(libc::SIGHUP, libc::SIG_IGN, 0) }.unwrap();
                stop_on_signals_now(&handle);
                // SAFETY: the default action runs no handler.
                unsafe { set_action(libc::SIGHUP, libc::SIG_DFL, 0) }.unwrap();
                let (later, _later_registration) = StopHandle::new_pair().unwrap();
                stop_on_signals(&later).unwrap();
                raise(libc::SIGHUP);
                assert!(later.wait_for_request(Duration::from_secs(5)));
                std::process::exit(14);
            }
            "before-boot" => {
                unignore(libc::SIGTERM);
                stop_on_signals(&handle).unwrap();
                raise(libc::SIGTERM);
                unreachable!("the signal kept its default action and did not end the process");
            }
            "second" => {
                unignore(libc::SIGTERM);
                // The thread inherits this mask, and has to unblock the signal
                // for the second one to end the process.
                block(&[libc::SIGTERM]);
                stop_on_signals_now(&handle);
                unblock(&[libc::SIGTERM]);
                raise(libc::SIGTERM);
                assert!(handle.wait_for_request(Duration::from_secs(5)));
                std::thread::sleep(STOP_TIMEOUT + Duration::from_millis(100));
                // The parent sees this, so it was the second signal, not the
                // first, that ended the process. It goes to stdout directly,
                // since the test harness captures `println!`.
                std::io::stdout().write_all(b"requested\n").unwrap();
                std::io::stdout().flush().unwrap();
                raise(libc::SIGTERM);
                // The stop-signal thread ends the process while this sleeps.
                std::thread::sleep(Duration::from_secs(5));
                unreachable!("the second signal did not end the process");
            }
            "exit-blocked" => {
                unignore(libc::SIGTERM);
                block(&[libc::SIGTERM]);
                exit_by_signal(libc::SIGTERM);
            }
            other => unreachable!("unknown case {other}"),
        }
    }

    /// Blocks `signals` on the calling thread.
    fn block(signals: &[libc::c_int]) {
        // SAFETY: as in `unblock`.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for &signal in signals {
                libc::sigaddset(&mut set, signal);
            }
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
    }

    #[test]
    fn stop_signal_requests_a_stop_and_names_the_signal() {
        let (status, _) = run_child("request");
        assert_eq!(status.code(), Some(10), "child ended with {status:?}");
    }

    // A copy of the first stop signal, such as a wrapper forwards, arrives
    // within the window and has no effect.
    #[test]
    fn stop_signal_repeated_within_the_window_has_no_effect() {
        let (status, _) = run_child("repeat");
        assert_eq!(status.code(), Some(11), "child ended with {status:?}");
    }

    #[test]
    fn ignored_stop_signal_stays_ignored() {
        let (status, _) = run_child("ignored");
        assert_eq!(status.code(), Some(12), "child ended with {status:?}");
    }

    // A signal the process ignored when the run started, and set to its default
    // action after, is registered by the next call.
    #[test]
    fn stop_signal_no_longer_ignored_joins_after_a_run() {
        let (status, _) = run_child("unignored-later");
        assert_eq!(status.code(), Some(14), "child ended with {status:?}");
    }

    #[test]
    fn earlier_stop_signal_handler_still_runs() {
        let (status, _) = run_child("earlier");
        assert_eq!(status.code(), Some(13), "child ended with {status:?}");
    }

    #[test]
    fn exit_by_signal_ends_the_process_by_a_blocked_signal() {
        let (status, _) = run_child("exit-blocked");
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "child ended with {status:?}"
        );
    }

    // Until `boot` installs the handlers, a stop signal keeps the action it
    // had, so it can still end a process that never reaches a run.
    #[test]
    fn stop_signal_before_boot_keeps_its_action() {
        let (status, _) = run_child("before-boot");
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "child ended with {status:?}"
        );
    }

    #[test]
    fn second_stop_signal_ends_the_process() {
        let (status, out) = run_child("second");
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "child ended with {status:?}"
        );
        assert!(
            out.contains("requested\n"),
            "the first signal ended the child"
        );
    }

    // Each call releases the handle of the call before, with the pipe it owns,
    // so an embedder that calls it once per run does not leak descriptors. No
    // handler is installed, since no run starts here.
    #[test]
    fn stop_on_signals_releases_the_previous_handle() {
        let (first, _first_registration) = StopHandle::new_pair().unwrap();
        stop_on_signals(&first).unwrap();
        let held = first.holders();
        let (second, _second_registration) = StopHandle::new_pair().unwrap();
        stop_on_signals(&second).unwrap();
        assert_eq!(first.holders(), held - 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kick_handler_leaves_sigusr1_to_the_embedder() {
        install_kick_handler();
        assert_eq!(kick_signal(), libc::SIGRTMIN());
        assert_ne!(action(kick_signal()).unwrap().sa_sigaction, libc::SIG_DFL);
        assert_eq!(action(libc::SIGUSR1).unwrap().sa_sigaction, libc::SIG_DFL);
    }
}

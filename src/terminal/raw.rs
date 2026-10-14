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

//! The raw mode of the operator's terminal for the length of a run.
//!
//! [`RawTerm`] puts stdin in raw mode and restores the settings it found when
//! it is dropped. A drop does not run when a signal ends the process, so
//! `RawTerm` also publishes the settings, and [`RawTerm::restore_saved`]
//! restores them from any thread, a signal handler included.
//! [`restore_on_fatal_signals`] installs a handler that calls it before a fatal
//! signal takes its default action.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::OnceLock;

/// Stdin in raw mode for the guest console, restored on drop.
pub(crate) struct RawTerm {
    /// The settings stdin had before, restored on drop.
    orig: libc::termios,
}

impl RawTerm {
    /// Puts stdin in raw mode, or returns `None` when stdin is not a terminal
    /// or its settings cannot be changed.
    pub(crate) fn enable() -> Option<RawTerm> {
        // SAFETY: `termios` is plain data, so a zeroed one is valid, and the
        // calls on fd 0 only read or write it. Each result is checked.
        unsafe {
            if libc::isatty(0) == 0 {
                return None;
            }
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut orig) != 0 {
                return None;
            }
            let mut raw = orig;
            libc::cfmakeraw(&mut raw);
            // The settings are published before raw mode is set, so a signal at
            // any later point finds them. The copy is never freed, since a
            // handler on another thread may hold it.
            SAVED.store(Box::into_raw(Box::new(orig)), Ordering::SeqCst);
            if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
                SAVED.store(std::ptr::null_mut(), Ordering::SeqCst);
                return None;
            }
            Some(RawTerm { orig })
        }
    }

    /// Restores the terminal settings a [`RawTerm`] in effect replaced, if any.
    ///
    /// A signal handler can call it. See [`restore`].
    pub(crate) fn restore_saved() {
        let saved = SAVED.load(Ordering::SeqCst);
        if !saved.is_null() {
            // SAFETY: `saved` came from `Box::into_raw` in `RawTerm::enable`
            // and is never freed.
            unsafe { restore(saved) };
        }
    }
}

impl Drop for RawTerm {
    fn drop(&mut self) {
        // SAFETY: `self.orig` is the settings `enable` read from fd 0.
        unsafe { restore(&self.orig) };
        // The settings stay published through the restore, so a signal during
        // it still restores them. They are withdrawn before the drop returns,
        // so a later signal does not overwrite a change the caller makes after
        // it.
        SAVED.store(std::ptr::null_mut(), Ordering::SeqCst);
    }
}

/// Discards the input stdin holds and applies `settings` to it at once.
///
/// The input the guest did not read, keystrokes and terminal answers, never
/// reaches the shell. The settings apply with `TCSANOW`. `TCSAFLUSH` would also
/// wait for the terminal's queued output to drain, which never happens once the
/// terminal has stopped reading, and the process would hang. The flush comes
/// first: on macOS, input still queued when the settings turn signal keys back
/// on is read again under them, so a Ctrl-C the guest never read would raise
/// `SIGINT`. It is two calls, `tcflush` and `tcsetattr`, so a signal handler
/// can make it.
///
/// # Safety
///
/// `settings` points to a live `termios`.
unsafe fn restore(settings: *const libc::termios) {
    // SAFETY: the calls only read `settings` and act on fd 0.
    unsafe {
        libc::tcflush(0, libc::TCIFLUSH);
        libc::tcsetattr(0, libc::TCSANOW, settings);
    }
}

/// The settings stdin had before raw mode, or null when no [`RawTerm`] is in
/// effect.
static SAVED: AtomicPtr<libc::termios> = AtomicPtr::new(std::ptr::null_mut());

/// Returns the signals [`restore_on_fatal_signals`] restores the terminal on.
///
/// They are the signals whose default action ends the process, except `SIGKILL`
/// (which cannot be handled), the [`STOP_SIGNALS`](crate::signal::STOP_SIGNALS)
/// (which stop the run instead) and the signal hvi kicks its threads with.
#[must_use]
pub fn fatal_signals() -> Vec<libc::c_int> {
    let mut signals = vec![
        libc::SIGQUIT,
        libc::SIGILL,
        libc::SIGTRAP,
        libc::SIGABRT,
        libc::SIGBUS,
        libc::SIGFPE,
        libc::SIGSEGV,
        libc::SIGSYS,
        libc::SIGXCPU,
        libc::SIGXFSZ,
        libc::SIGALRM,
        libc::SIGPIPE,
        libc::SIGPROF,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGVTALRM,
    ];
    #[cfg(target_os = "linux")]
    {
        signals.extend([libc::SIGIO, libc::SIGPWR, libc::SIGSTKFLT]);
        signals.extend(libc::SIGRTMIN()..=libc::SIGRTMAX());
    }
    #[cfg(target_os = "macos")]
    signals.push(libc::SIGEMT);
    signals.retain(|&signal| signal != crate::signal::kick_signal());
    signals
}

/// The `SIGSEGV` handler [`restore_on_fatal_signals`] replaced, which
/// [`on_fatal_signal`] calls before it decides on the restore.
static PREVIOUS_SEGV: OnceLock<libc::sigaction> = OnceLock::new();
/// The `SIGBUS` handler [`restore_on_fatal_signals`] replaced, which
/// [`on_fatal_signal`] calls before it decides on the restore.
static PREVIOUS_BUS: OnceLock<libc::sigaction> = OnceLock::new();
/// Whether [`PREVIOUS_SEGV`] ran once and was installed to run once.
static PREVIOUS_SEGV_USED: AtomicBool = AtomicBool::new(false);
/// Whether [`PREVIOUS_BUS`] ran once and was installed to run once.
static PREVIOUS_BUS_USED: AtomicBool = AtomicBool::new(false);

/// The handler for [`fatal_signals`].
///
/// It restores the terminal and raises the signal again with its default
/// action. The signal is blocked while the handler runs, so the raised signal
/// is delivered once the handler returns.
///
/// A `SIGSEGV` or `SIGBUS` first goes to the handler the signal had before, if
/// it had one. When that handler returns and has not set the default action, it
/// recovered, and this returns and leaves the terminal as it is. Std's handler
/// sets the default action for a fault outside a stack guard page. A fault on
/// Linux is not raised again: once the terminal is restored, this sets the
/// default action and returns, so the faulting instruction runs again and the
/// fault ends the process with its own `siginfo_t`. A handler installed with
/// `SA_RESETHAND` runs once, as the system would run it, and a later fault
/// takes the default action. Linux reports that flag back; macOS does not, so
/// there such a handler runs on every fault.
extern "C" fn on_fatal_signal(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    let (previous, used) = match signal {
        libc::SIGSEGV => (PREVIOUS_SEGV.get(), Some(&PREVIOUS_SEGV_USED)),
        libc::SIGBUS => (PREVIOUS_BUS.get(), Some(&PREVIOUS_BUS_USED)),
        _ => (None, None),
    };
    let handler = previous.map_or(libc::SIG_DFL, |previous| previous.sa_sigaction);
    let spent = used.is_some_and(|used| used.load(Ordering::SeqCst));
    if let Some(previous) =
        previous.filter(|_| handler != libc::SIG_DFL && handler != libc::SIG_IGN && !spent)
    {
        if previous.sa_flags & libc::SA_RESETHAND != 0 {
            if let Some(used) = used {
                used.store(true, Ordering::SeqCst);
            }
        }
        // SAFETY: `handler` is the handler the process had for `signal`, called
        // with the arguments its flags say it takes.
        unsafe {
            if previous.sa_flags & libc::SA_SIGINFO != 0 {
                let handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
                    std::mem::transmute(handler);
                handler(signal, info, context);
            } else {
                let handler: extern "C" fn(libc::c_int) = std::mem::transmute(handler);
                handler(signal);
            }
        }
        let recovered =
            crate::signal::action(signal).is_ok_and(|action| action.sa_sigaction != libc::SIG_DFL);
        if recovered {
            return;
        }
    }
    RawTerm::restore_saved();
    // SAFETY: the system passes a valid `siginfo_t` to a handler installed with
    // `SA_SIGINFO`.
    if previous.is_some() && is_fault(unsafe { &*info }) {
        // SAFETY: the default action runs no handler.
        let _ = unsafe { crate::signal::set_action(signal, libc::SIG_DFL, 0) };
        return;
    }
    crate::signal::raise_with_default_action(signal);
}

/// Returns whether `info` reports a fault of the calling thread, rather than a
/// signal that `kill`, `raise` or the like sent.
///
/// Linux numbers the codes of a sent signal from 0 down. macOS fills the
/// `siginfo_t` of a `SIGSEGV` that `raise` sent as it fills a fault's, with
/// code `SEGV_ACCERR` and no sender, so there no signal counts as a fault.
fn is_fault(info: &libc::siginfo_t) -> bool {
    cfg!(target_os = "linux") && info.si_code > 0
}

/// Makes each of [`fatal_signals`] restore the terminal before it ends the
/// process.
///
/// Each handler restores the terminal settings that `boot` replaced with raw
/// mode, then raises the signal again with its default action, so the process
/// still ends by the signal, with a core dump where that action makes one. A
/// signal that already has a handler, or is ignored, keeps that. `SIGSEGV` and
/// `SIGBUS` are the exception: their handlers are replaced, and a fault goes to
/// the replaced handler first. The terminal is then restored only when the
/// fault still ends the process. `SIGKILL` cannot be handled, and leaves the
/// terminal in raw mode. With these handlers, a stack overflow on x86-64 Linux
/// ends the process by `SIGSEGV` rather than by the `SIGABRT` std's handler
/// raises, with the terminal restored either way. macOS does not report
/// `SA_RESETHAND` back, so there a replaced handler installed with it that
/// returns without setting the default action makes the process spin on the
/// fault at full CPU.
///
/// It replaces the process's handlers for those signals and does not restore
/// them, so a binary calls it once, before `boot`.
///
/// # Errors
///
/// Errors if a handler cannot be read or installed.
pub fn restore_on_fatal_signals() -> io::Result<()> {
    let handler = on_fatal_signal as *const () as usize;
    for signal in fatal_signals() {
        let previous = crate::signal::action(signal)?;
        match signal {
            libc::SIGSEGV => {
                let _ = PREVIOUS_SEGV.set(previous);
            }
            libc::SIGBUS => {
                let _ = PREVIOUS_BUS.set(previous);
            }
            _ if previous.sa_sigaction != libc::SIG_DFL => continue,
            _ => {}
        }
        // With `SA_ONSTACK` the handler runs on the thread's alternate signal
        // stack, so it also runs after a stack overflow.
        // SAFETY: the handler takes the `siginfo_t` that `SA_SIGINFO` passes.
        // It calls the handler it replaced, restores the terminal, and sets and
        // raises the signal's action.
        unsafe {
            crate::signal::set_action(signal, handler, libc::SA_SIGINFO | libc::SA_ONSTACK)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::atomic::AtomicUsize;

    /// The variable that tells [`fatal_signal_child`] what to do: a signal
    /// number to raise, `fault`, `recovered-fault`, `second-stop-signal`,
    /// `stalled-signal` or `stalled-return`.
    const CHILD_CASE: &str = "HVI_FATAL_SIGNAL_CHILD";

    /// The signal a write to a page with no access raises.
    #[cfg(target_os = "linux")]
    const FAULT_SIGNAL: libc::c_int = libc::SIGSEGV;
    /// The signal a write to a page with no access raises.
    #[cfg(target_os = "macos")]
    const FAULT_SIGNAL: libc::c_int = libc::SIGBUS;

    /// The page [`page_with_no_access`] mapped.
    static PAGE: AtomicPtr<libc::c_void> = AtomicPtr::new(std::ptr::null_mut());
    /// The length of [`PAGE`].
    static PAGE_LEN: AtomicUsize = AtomicUsize::new(0);

    /// Maps a page with no access and returns it.
    fn page_with_no_access() -> *mut u8 {
        // SAFETY: `sysconf` only reads a value, and `mmap` maps a new private
        // page. The result is checked.
        let page = unsafe {
            let len = usize::try_from(libc::sysconf(libc::_SC_PAGESIZE)).unwrap();
            PAGE_LEN.store(len, Ordering::SeqCst);
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        PAGE.store(page, Ordering::SeqCst);
        page.cast()
    }

    /// Gives [`PAGE`] write access, so the write that faulted succeeds when it
    /// runs again.
    extern "C" fn make_page_writable(_: libc::c_int) {
        let (page, len) = (PAGE.load(Ordering::SeqCst), PAGE_LEN.load(Ordering::SeqCst));
        // SAFETY: the page is a mapping of this process `len` bytes long.
        unsafe { libc::mprotect(page, len, libc::PROT_READ | libc::PROT_WRITE) };
    }

    // The child half of the tests below: with the pty it was given as stdin in
    // raw mode, it does what `CHILD_CASE` says. It returns at once in a normal
    // run.
    #[test]
    fn fatal_signal_child() {
        let Ok(case) = std::env::var(CHILD_CASE) else {
            return;
        };
        let _raw = RawTerm::enable().expect("stdin is a terminal");
        match case.as_str() {
            "second-stop-signal" => {
                let (handle, _registration) = crate::run::StopHandle::new_pair().unwrap();
                // SAFETY: the default action runs no handler.
                unsafe { crate::signal::set_action(libc::SIGTERM, libc::SIG_DFL, 0) }.unwrap();
                crate::signal::stop_on_signals(&handle).unwrap();
                crate::signal::start_stop_signal_thread().unwrap();
                // SAFETY: raising a signal on the calling thread.
                unsafe { libc::raise(libc::SIGTERM) };
                // The stop-signal thread acts on the first signal. The sleep
                // below waits out the window in which a second one has no
                // effect.
                assert!(handle.wait_for_request(std::time::Duration::from_secs(5)));
                std::thread::sleep(
                    crate::teardown::STOP_TIMEOUT + std::time::Duration::from_millis(100),
                );
                // SAFETY: raising a signal on the calling thread.
                unsafe { libc::raise(libc::SIGTERM) };
                // The stop-signal thread ends the process while this sleeps.
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            "fault"
            | "recovered-fault"
            | "reset-handler-fault"
            | "recovered-reset-handler-fault" => {
                let page = page_with_no_access();
                if case == "recovered-fault" {
                    let handler = make_page_writable as *const () as usize;
                    // SAFETY: the handler takes the signal number alone and
                    // only calls `mprotect`.
                    unsafe { crate::signal::set_action(FAULT_SIGNAL, handler, 0) }.unwrap();
                }
                if case == "recovered-reset-handler-fault" {
                    let handler = make_page_writable as *const () as usize;
                    // SAFETY: the handler takes the signal number alone and
                    // only calls `mprotect`.
                    unsafe { crate::signal::set_action(FAULT_SIGNAL, handler, libc::SA_RESETHAND) }
                        .unwrap();
                }
                if case == "reset-handler-fault" {
                    extern "C" fn returns(_: libc::c_int) {}
                    let handler = returns as *const () as usize;
                    // SAFETY: the handler takes the signal number alone and
                    // does nothing.
                    unsafe { crate::signal::set_action(FAULT_SIGNAL, handler, libc::SA_RESETHAND) }
                        .unwrap();
                }
                restore_on_fatal_signals().unwrap();
                // SAFETY: the page is mapped, so the write either faults or
                // writes a page only this test uses.
                unsafe { page.write_volatile(1) };
                if case == "recovered-fault" {
                    std::process::exit(20);
                }
                if case == "recovered-reset-handler-fault" {
                    std::process::exit(22);
                }
            }
            "stalled-signal" | "stalled-return" => {
                // A thread writes to the pty, whose controller nobody reads,
                // until the write blocks with output queued.
                std::thread::spawn(|| {
                    // SAFETY: `dup` returns a new descriptor for the pty, which
                    // the file then owns.
                    let mut terminal = unsafe { File::from_raw_fd(libc::dup(0)) };
                    loop {
                        let _ = std::io::Write::write(&mut terminal, &[b'x'; 4096]);
                    }
                });
                std::thread::sleep(std::time::Duration::from_millis(200));
                if case == "stalled-return" {
                    drop(_raw);
                    std::process::exit(21);
                }
                restore_on_fatal_signals().unwrap();
                // SAFETY: raising a signal on the calling thread.
                unsafe { libc::raise(libc::SIGQUIT) };
            }
            signal => {
                restore_on_fatal_signals().unwrap();
                // SAFETY: raising a signal on the calling thread.
                unsafe { libc::raise(signal.parse().unwrap()) };
            }
        }
        unreachable!("the process did not end");
    }

    #[test]
    fn fatal_signals_leave_out_the_ones_handled_otherwise() {
        let signals = fatal_signals();
        assert!(signals.contains(&libc::SIGUSR2));
        for other in crate::signal::STOP_SIGNALS.into_iter().chain([
            libc::SIGKILL,
            libc::SIGCHLD,
            crate::signal::kick_signal(),
        ]) {
            assert!(!signals.contains(&other), "signal {other}");
        }
    }

    /// Returns the flags of the terminal behind `fd`, apart from `PENDIN`.
    ///
    /// `PENDIN` is the kernel's note to reprint pending input, not a setting.
    /// On macOS the kernel sets it when settings that turn canonical mode back
    /// on apply with no flush after them, as the restore's do.
    fn flags(
        fd: libc::c_int,
    ) -> (
        libc::tcflag_t,
        libc::tcflag_t,
        libc::tcflag_t,
        libc::tcflag_t,
    ) {
        // SAFETY: `termios` is plain data, and the call only writes it.
        let mut settings: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(fd, &mut settings) }, 0);
        (
            settings.c_iflag,
            settings.c_oflag,
            settings.c_cflag,
            settings.c_lflag & !libc::PENDIN,
        )
    }

    /// Runs [`fatal_signal_child`] for `case`, with a new pty as its stdin,
    /// which the child puts in raw mode.
    ///
    /// Input the guest never reads is queued on the pty before the child
    /// starts. Returns how the child ended, whether the pty has the settings it
    /// had before the child started, and how many bytes of that input are left.
    fn run_child(case: &str) -> (ExitStatus, bool, libc::c_int) {
        let (mut controller, mut terminal) = (0, 0);
        // SAFETY: both descriptors are written by the call, which opens a new
        // pty pair.
        let opened = unsafe {
            libc::openpty(
                &mut controller,
                &mut terminal,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(opened, 0);
        // SAFETY: the pty pair is this test's own, and each end is owned once.
        let (_controller, stdin) =
            unsafe { (File::from_raw_fd(controller), File::from_raw_fd(terminal)) };
        let before = flags(stdin.as_raw_fd());
        // Input the guest never reads, which the restore discards.
        // SAFETY: the buffer is live for the call, and `controller` is open.
        let typed = unsafe { libc::write(controller, b"typed\n".as_ptr().cast(), 6) };
        assert_eq!(typed, 6);
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "terminal::raw::tests::fatal_signal_child"])
            .env(CHILD_CASE, case)
            .stdin(stdin.try_clone().unwrap())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // The limit keeps the child's crash from writing a core file.
        // SAFETY: `setrlimit` is safe to call between `fork` and `exec`.
        unsafe {
            child.pre_exec(|| {
                let none = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                match libc::setrlimit(libc::RLIMIT_CORE, &none) {
                    0 => Ok(()),
                    _ => Err(io::Error::last_os_error()),
                }
            });
        }
        // A child that hangs fails the test rather than holding it up.
        let mut child = child.spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the child for {case} did not end");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let mut unread: libc::c_int = 0;
        // SAFETY: `FIONREAD` writes the count of queued input bytes to
        // `unread`.
        assert_eq!(
            unsafe { libc::ioctl(stdin.as_raw_fd(), libc::FIONREAD, &mut unread) },
            0
        );
        (status, flags(stdin.as_raw_fd()) == before, unread)
    }

    // Each signal ends a child that had its pty in raw mode. The child dies by
    // that signal, and the pty has the settings it had before. `SIGQUIT` stands
    // for the signals a key raises, `SIGUSR2` for those only `kill` sends. A
    // raised `SIGSEGV` goes to std's handler first, which sets the default
    // action.
    #[test]
    fn terminal_is_restored_when_a_fatal_signal_ends_the_process() {
        #[cfg(target_os = "linux")]
        let signals = [
            libc::SIGQUIT,
            libc::SIGSEGV,
            libc::SIGUSR2,
            libc::SIGRTMAX(),
        ];
        #[cfg(target_os = "macos")]
        let signals = [libc::SIGQUIT, libc::SIGSEGV, libc::SIGUSR2];
        for signal in signals {
            let (status, restored, unread) = run_child(&signal.to_string());
            assert_eq!(status.signal(), Some(signal), "child ended with {status:?}");
            assert!(restored, "signal {signal}");
            assert_eq!(unread, 0, "unread input reached the shell");
        }
    }

    // The fault goes to std's handler first, which sets the default action, and
    // the write that runs again then ends the child.
    #[test]
    fn terminal_is_restored_when_a_fault_ends_the_process() {
        let (status, restored, unread) = run_child("fault");
        assert_eq!(
            status.signal(),
            Some(FAULT_SIGNAL),
            "child ended with {status:?}"
        );
        assert!(restored);
        assert_eq!(unread, 0, "unread input reached the shell");
    }

    // The earlier handler was installed with `SA_RESETHAND`, so it returns
    // expecting the default action back, and the write that runs again ends the
    // child. macOS does not report the flag back, so it cannot be honored
    // there.
    #[cfg(target_os = "linux")]
    #[test]
    fn fault_after_a_reset_handler_ends_the_process() {
        let (status, restored, unread) = run_child("reset-handler-fault");
        assert_eq!(
            status.signal(),
            Some(FAULT_SIGNAL),
            "child ended with {status:?}"
        );
        assert!(restored);
        assert_eq!(unread, 0, "unread input reached the shell");
    }

    // A handler installed with `SA_RESETHAND` that fixes the fault leaves the
    // process running, as one that stays installed does.
    #[cfg(target_os = "linux")]
    #[test]
    fn fault_a_reset_handler_recovers_from_leaves_the_process_running() {
        let (status, restored, _) = run_child("recovered-reset-handler-fault");
        assert_eq!(status.code(), Some(22), "child ended with {status:?}");
        assert!(!restored, "the terminal was restored for a recovered fault");
    }

    #[test]
    fn recovered_fault_leaves_the_process_running() {
        let (status, restored, _) = run_child("recovered-fault");
        assert_eq!(status.code(), Some(20), "child ended with {status:?}");
        // The process went on, so the terminal stayed as the child left it.
        assert!(!restored, "the terminal was restored for a recovered fault");
    }

    // The restore must not wait for output a terminal that stopped reading
    // never drains, on a fatal signal or when `boot` returns.
    #[test]
    fn terminal_is_restored_while_its_output_is_stalled() {
        let (status, restored, unread) = run_child("stalled-signal");
        assert_eq!(
            status.signal(),
            Some(libc::SIGQUIT),
            "child ended with {status:?}"
        );
        assert!(restored);
        assert_eq!(unread, 0, "unread input reached the shell");
        let (status, restored, unread) = run_child("stalled-return");
        assert_eq!(status.code(), Some(21), "child ended with {status:?}");
        assert!(restored);
        assert_eq!(unread, 0, "unread input reached the shell");
    }

    #[test]
    fn second_stop_signal_restores_the_terminal() {
        let (status, restored, unread) = run_child("second-stop-signal");
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "child ended with {status:?}"
        );
        assert!(restored);
        assert_eq!(unread, 0, "unread input reached the shell");
    }
}

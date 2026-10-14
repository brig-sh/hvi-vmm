# Embedding hvi

hvi is a library as well as a command. The `hvi` binary is a thin CLI over it:
it parses flags, reads the kernel, and hands a `BootConfig` to the active
backend. Everything of substance is in the library.

This page is the path from running the CLI to linking the VMM. For attaching a
tool once you are here, read [plugins.md](plugins.md).

## Depend on it

```toml
[dependencies]
hvi = { git = "https://github.com/brig-sh/hvi-vmm", rev = "<commit>" }
```

There is no published crate, no release and no tag, so pin a commit. The API
is not stable, and there is no compatibility promise between commits.

hull, the first consumer, does the same thing a level up: it vendors hvi as a
git submodule pinned to a commit and builds it with `cargo build --release`
before signing it. Pinning a commit is the supported way to depend on hvi.

## The entry point

`hvi::boot` boots on the backend for the host target, so a caller writes one
line whatever the host:

```rust
pub fn boot(cfg: BootConfig) -> Result<Stop, BootError>;
```

`BootError` implements `Error`, `Send` and `Sync`, so `?` turns it into a
`Box<dyn Error>`, and it can be returned from another thread. Its message is
that of the error that failed the run, and it names any thread the run left
running. `BootError::get_ref` returns that error, which a caller can downcast to
tell one failure from another, and `BootError::into_inner` hands it over.

`Stop` says how the run ended. `SystemOff` and `SystemReset` mean the guest
powered off or reset. `Requested` means the host asked the run to stop (see
[Stopping a run from the host](#stopping-a-run-from-the-host)), or that the
control socket's `stop` ended it. It is `#[non_exhaustive]`, so a `match` on it
needs a wildcard arm. When a vCPU fails, `boot` returns an error that names the
vCPU and says how it failed.

CAUTION: `boot` returns `Stop::SystemReset` and stops. It does not reboot the
guest, and nothing in hvi restarts one. If your integration wants a reboot,
start a new run yourself, through `spawn` after a sandboxed run on Linux (see
[Stopping a run from the host](#stopping-a-run-from-the-host)). On macOS no run
can follow one that entered the sandbox in the same process, so a reboot there
takes a new process.

The call blocks until the guest stops, a vCPU fails, or a stop is requested. It
reads the process's stdin for the whole run, one byte at a time, as the guest
console; nothing else in the process should read stdin while `boot` runs. It
also takes over the kick signal, `SIGRTMIN` on Linux and `SIGUSR1` on macOS: it
installs a no-op handler for it and does not restore the one it replaced. It
sends that signal to its own threads to interrupt them, so nothing else in the
process should use it.

Before it returns, the ledger is closed, the agent listener, the control socket
and every accepted connection are closed, and every thread it started itself has
exited, with three exceptions. A thread still running at its deadline is left
running and `boot` returns an error naming the first such thread, a vCPU thread
before a helper thread. The thread that receives the stop signals runs for the
life of the process (see [Stopping a run from the
host](#stopping-a-run-from-the-host)). The ledger's writer thread is not
joined. `boot` waits up to one second for the
vCPU threads, then up to one second for the helper threads, and then up to one
second for the writer to write the `vmm.stop` record, so it returns at most
three seconds after the stop, with no error for a writer still in a write. The
writer finishes the ledger if the process keeps running. A write that blocks, as
on a hung network file system, holds the file and its lock until it returns, so
a later run needs another ledger path (see [When a record reaches the
file](observability.md#when-a-record-reaches-the-file)). The waits `boot` cannot
interrupt are a plugin blocking in `request`, in `safepoint` or on a thread it
started with `VmHandle::spawn`, and a virtio-fs worker waiting on a host file
lock. On macOS such a lock wait can also stall a vCPU (see [Known
limits](limitations.md#virtio-fs-resource-limits)).

A plugin that keeps the `Arc<dyn VmHandle>` it was given keeps guest RAM and the
block, net and vsock devices until it drops the handle. It also keeps the VM,
through the vCPU kicker on macOS and through the interrupt line of each block,
net or vsock device on Linux. The ledger's writer closes the ledger file once it
has written the `vmm.stop` record, whether or not a plugin keeps the handle. The
vCPUs have exited or been left running, so a kick reaches only a vCPU left
running. The tap under `--net-tap` keeps its carrier up. The disks stay open.
The gateway connection under `--net-gateway` stays on the handle, but the relay
shut it down as it ended, so it carries nothing. A thread the plugin started
with `VmHandle::spawn` is joined with the I/O threads. One it started any other
way is not joined, and holds the handle for as long as it runs. On macOS a
second `boot` fails while such a handle exists, because Hypervisor.framework
allows one VM per process. On either host the handle also holds the disks' image
locks, so a second `boot` on the same writable image fails with "the image is
open elsewhere" while it lives.

On macOS the crate root also exports `hvi::restore`, which resumes a
checkpoint bundle instead of booting a kernel:

```rust
pub fn restore(cfg: RestoreConfig) -> Result<Stop, Box<dyn std::error::Error>>;
```

`RestoreConfig` names the bundle, the control socket the guest waits on for
`resume`, and the host resources the guest's devices need. It returns as
`boot` does, and the same rules apply to stdin, the kick signal and the
threads. A restore is a run like a boot: it takes the process's one run, a
panic during it writes its `vmm.stop` record as [Panics](#panics) says, and
the sandbox rules that refuse a later `boot` refuse a later restore too. See [checkpoint.md](checkpoint.md#restoring-a-bundle). On arm64
KVM it restores the portable profile only; there is no x86-64 restore yet.

## A minimal caller

```rust
use hvi::config::{BootConfig, MachineProfileKind};

let cfg = BootConfig {
    kernel: std::fs::read("Image")?,
    initramfs: Some(std::fs::read("initramfs.cpio")?),
    mem_bytes: 1024 << 20,
    cmdline: String::from("earlycon console=ttyAMA0 panic=-1"),
    disks: Vec::new(),
    fs_shares: Vec::new(),
    fs: Vec::new(),
    net: true,
    net_gateway: None,
    net_tap: None,
    net_mac: None,
    events: None,
    sandbox_id: String::from("my-sandbox"),
    vcpus: 2,
    agent_sock: None,
    profile_out: None,
    control_sock: None,
    checkpoint_root: None,
    plugin: None,
    sandbox: true,
    profile: MachineProfileKind::Native,
    arch_timer_irq: None,
    stop: None,
};

let stop = hvi::boot(cfg)?;
eprintln!("guest stopped: {stop:?}");
```

`BootConfig` has no `Default` and no builder. Every field is public and
required, which means a new field is a compile error in your code rather than
a silent behaviour change.

The compile-checked version of this, with a plugin attached, is
[`examples/watch_guest.rs`](../examples/watch_guest.rs):

```sh
cargo build --release --example watch_guest
```

## The fields

| Field | Type | Notes |
| --- | --- | --- |
| `kernel` | `Vec<u8>` | The image bytes. arm64 `Image`, x86-64 `bzImage` or uncompressed `vmlinux`, matching the target. |
| `initramfs` | `Option<Vec<u8>>` | Bytes, not a path. |
| `mem_bytes` | `u64` | Guest RAM. |
| `cmdline` | `String` | The backend appends what its own devices need. |
| `disks` | `Vec<DiskConfig>` | virtio-blk disks, at most `MAX_DISKS` (4), in guest order. `DiskConfig::rw(path)`, `DiskConfig::ro(path)` or `DiskConfig::parse(spec)`. A disk without a `serial` answers `disk<N>` for its index `N`. More than one **fails the boot** under `PortableArm64V1`, and a checkpoint or a move takes a guest of exactly one writable disk. |
| `fs_shares` | `Vec<FsShare>` | virtio-fs exports served in-process. macOS only. A non-empty vector **fails the boot** under `PortableArm64V1`. |
| `fs` | `Vec<FsConfig>` | virtio-fs exports served by vhost-user daemons the caller runs. Linux only. A non-empty vector **fails the boot** under `PortableArm64V1`. |
| `net` | `bool` | The built-in stub stack. |
| `net_gateway` | `Option<String>` | A gvisor-tap socket path. Takes precedence over `net`. |
| `net_tap` | `Option<String>` | An existing tap. Linux only. Takes precedence over both. |
| `net_mac` | `Option<[u8; 6]>` | Guest MAC, applied on every backend and mode. |
| `events` | `Option<String>` | The ledger path. `boot` refuses anything there other than a regular file, a file locked by this process or another, and a symbolic link as the last component of the path. |
| `sandbox_id` | `String` | Written into every ledger record. |
| `vcpus` | `u32` | 1 or more. Linux/arm64 refuses more than 8 on a GICv2 host and more than 507 on a GICv3 one, and x86-64 more than 254. |
| `agent_sock` | `Option<String>` | Host Unix socket bridged to the guest agent over vsock. |
| `profile_out` | `Option<String>` | Where the machine profile is written. Created before confinement. See [cli.md](cli.md#the-control-socket). |
| `control_sock` | `Option<String>` | The control socket's path. Bound before confinement. See [cli.md](cli.md#the-control-socket). |
| `checkpoint_root` | `Option<String>` | The directory a `checkpoint` may write bundles under; `None` refuses every checkpoint. Resolved before confinement. Seatbelt holds writes to it on macOS; on Linux only hvi's own path check does. One private root (mode 0700) per sandbox: bundles hold guest RAM in clear. Needs `control_sock`. See [checkpoint.md](checkpoint.md#confinement). |
| `plugin` | `Option<Arc<dyn Plugin>>` | See [plugins.md](plugins.md). The CLI sets it only for `--dump-memory` and `--trace-io`, chained into one. |
| `sandbox` | `bool` | Confinement. Leave it `true`. |
| `profile` | `MachineProfileKind` | `Native`, or `PortableArm64V1` for one machine on every host: macOS and arm64 KVM. See [portable-profile.md](portable-profile.md). |
| `arch_timer_irq` | `Option<bool>` | Leave it `None`, the profile's default: interrupts on the native profile, none on the portable one, whose clock is `hvi-time`. `Some(true)` is the `--arch-timer-irq` debugging aid, and only `PortableArm64V1` accepts a value. |
| `stop` | `Option<StopRegistration>` | Asks the run to stop from the host. See [Stopping a run from the host](#stopping-a-run-from-the-host). |

`FsShare` carries a `path`, a `tag`, a `ShareMode`, a `CachePolicy` and the
`uid` and `gid` the host user's files carry in the guest. `FsConfig` carries a
`tag`, the `socket` its daemon listens on, `num_queues` and `queue_size`.
`FsSpec::parse` reads one `--fs` into either. Each backend refuses the other's
list. See [storage-and-sharing.md](storage-and-sharing.md).

## Stopping a run from the host

Create a pair with `hvi::run::StopHandle::new_pair()` before `boot`, keep the
`StopHandle` and pass the `StopRegistration` in `BootConfig::stop`. `boot` takes
the registration by value, so it serves one run. `StopHandle::request_stop` from
any thread stops the run: the VM stops, the threads are joined and the ledger is
closed, and `boot` returns `Stop::Requested`. A failure a thread reports, or a
guest stop a vCPU reports, before `boot` reads how the run ended takes the place
of `Stop::Requested`. A plugin asks for the same stop with
`VmHandle::request_stop`.

`hvi::spawn` does this for a caller that runs the guest beside its own work. It
creates the pair, starts a thread that calls `boot` and returns a `Run` at once:

```rust
let run = hvi::spawn(cfg)?;
// ...
run.request_stop();
let stop = run.wait()?;
```

`Run::wait` returns what `boot` returned, and `Run::is_finished` says whether
the run has ended. A `BootConfig` whose `stop` is set keeps that stop, and
`Run::stop_handle` returns a handle on it. Dropping a `Run` leaves the guest
running until it stops on its own. A process that exits before the run ends
skips the terminal restore, and its ledger loses the `vmm.stop` record and the
records not written yet, so call `wait` before returning. On Linux, `boot`
installs its seccomp filter on the thread that calls it, which with `spawn` is
the `run` thread. On macOS the Seatbelt profile confines the whole process, the
thread that called `spawn` included, from the start of the run until the process
exits.

A process runs one guest at a time, since runs that overlap share stdin, the
terminal settings, the stop signals and the seccomp state. `boot` refuses a run
while another is in progress. It refuses every run after one that left a thread
running or whose `boot` unwound from a panic, since what that run left behind
still shares them.

A sandboxed run leaves its confinement in place for the life of the process. On
Linux the `vmm` seccomp filter stays on the thread that called `boot`, and every
thread that thread starts later inherits it. The filter refuses opening a file,
so `boot` and `spawn` refuse a later run from that thread. A run from a thread
the filtered thread started ends the process by `SIGSYS`. Start every sandboxed
run with `spawn`, so the thread that calls it stays unfiltered. `boot` refuses a
later run with `sandbox: false`. On macOS the Seatbelt profile stays on the
whole process once a run has entered it, and refuses what a later run sets up,
such as its guest RAM, so `boot` refuses every later run there. A sandboxed run
that fails before it enters the profile leaves later runs free. A run that
`boot` refuses for the sandbox needs a process of its own.

The library installs no handler for a stop signal. To stop the run on `SIGTERM`,
`SIGINT` and `SIGHUP`, as the `hvi` binary does, call
`hvi::signal::stop_on_signals(&handle)` before `boot`. The signals keep their
actions until the next `boot` starts its run, on Linux once it arms its filters
and on macOS before it enters the sandbox. Until then a stop signal ends the
process, unless you changed its action. That `boot` installs handlers for the
signals, which are not removed, and starts a thread that receives them for the
life of the process, outside the threads `boot` joins.

A signal the process ignores when the run starts stays ignored, as `SIGHUP` is
under `nohup`. To stop on it anyway, set it to `SIG_DFL` first. Once a run has
started, the next call registers it at once. Make no other change to these
signals' actions once a run has started, since a registered signal is not
installed again. A handler a signal already has still runs, before the stop
request.

Once a run has started, the process outlives a `SIGHUP`, and stderr can then be
a terminal that hung up. `eprintln!` panics on a failed write, so a line your
code or your plugin prints with it after a `SIGHUP` panics that thread. A panic
in a plugin hook, or in a thread the plugin started with `VmHandle::spawn`,
fails the run, as [Panics](#panics) says. The setup lines of a later `boot` in
the same process are printed with `eprintln!` too, so a binary that stopped on
`SIGHUP` should end rather than boot again.

Another stop signal, one second or more after the first, restores the terminal
and ends the process at once by that signal, and the ledger loses the records
not written yet. One that arrives sooner, such as a copy a wrapper forwards, has
no effect. A later call moves the signals to another handle.

Once `boot` has returned, `handle.signal()` names the first stop signal that
asked for the stop, if one did, even one that asked after another request, and
`hvi::signal::exit_by_signal(signal)` ends the process by it, so a parent sees
the same status it would have seen with no handler. A first stop signal that
arrives after the run has ended asks a finished run to stop, so a binary that
keeps running after `boot` returns checks `handle.signal()` once it is done.

`hvi::signal::StopOnSignals` does all of this for a binary that ends with its
run, as the `hvi` binary does:

```rust
let (signals, registration) = hvi::signal::StopOnSignals::new()?;
cfg.stop = Some(registration);
signals.finish(hvi::boot(cfg))
```

`finish` prints `guest stopped: <stop>` or `hvi: <error>` on stderr, ignoring a
failed write, and ends the process by the first stop signal that asked, even
after another request. With no such signal it exits with status 0 after a stop
and 1 after a failure. A write to a closed pipe fails only while `SIGPIPE` is
ignored, as the Rust runtime sets it before `main`. Under its default action the
write ends the process. With `spawn`, pass the registration the same way and
call `signals.finish(run.wait())` once the caller is done with the run.

`boot` restores the terminal it put in raw mode when it returns. A signal that
ends the process skips that restore. `hvi::terminal::restore_on_fatal_signals()`
installs a handler for each signal in `hvi::terminal::fatal_signals()` that has
no handler and is not ignored. The handler restores the terminal, and the signal
then ends the process with its default action. `SIGSEGV` and `SIGBUS` get the
handler even when they have one. A fault goes to their earlier handler first,
and the terminal is restored only when the fault still ends the process. It does
not restore the handlers it replaces, so call it once, before `boot`, if you
want it.

## Panics

The panic strategy belongs to the binary. hvi's own binary is built with
`panic = "abort"` and calls `hvi::run::set_panic_hook()` before `boot`. Its
panic hook stops the vCPUs and writes the run's `vmm.stop` record before the
process aborts. The record has reason `failed` and a report that names the
thread, the message and where the panic happened. On a vCPU thread the report
adds the vCPU's program counter and, once the vCPU has run, its last exit.

A binary built the same way calls `set_panic_hook` too, or
`hvi::run::record_panic` from a hook of its own, since the abort skips the stop
that writes the record. Such a hook prints its own report before it calls
`record_panic`, since a panic on another thread can abort the process once the
record is written. The terminal is still in raw mode while such a hook prints,
so it ends its lines with `\r\n`. `record_panic` does not restore the terminal,
so the binary also calls `hvi::terminal::restore_on_fatal_signals()`, whose
handler restores it when the abort raises `SIGABRT`. Once either hook has
started, `boot` does not return, so the abort ends the process. A binary that
can end the process another way while `boot` runs, by `exit` from another thread
for example, calls `hvi::run::wait_for_panic_abort()` first, so the process
still ends by the abort, with its status and core file.

In a binary that unwinds, a panic on a vCPU thread, an I/O thread or a thread a
plugin started with `VmHandle::spawn` stops the run. The VM stops, the threads
are joined, the `vmm.stop` record is written, and `boot` returns an error that
names the thread that panicked. hvi takes a blocking lock with
`.lock().unwrap()`, so the next thread to take a lock that the panic poisoned
panics in turn. A panic makes `boot` refuse later runs in the process only when
a thread was left running or the panic unwound out of `boot` itself. Without
hvi's hook, the default hook resolves a backtrace when `RUST_BACKTRACE` is set.
Resolving it opens the binary, which the Linux seccomp filters refuse, so under
the sandbox the process ends by `SIGSYS`.

## Configuration outside `BootConfig`

One thing a caller sets is not in the struct.

**Environment variables.** `HVI_SECCOMP`, `HVI_BLK_TRACE` and `HVI_X86_TRACE`
are read from the process environment, not from `BootConfig`. An embedder that
wants them off must make sure they are unset in the process it runs in. See
[cli.md](cli.md#environment-variables).

## What the guest agent must provide

With `agent_sock` set, hvi stands up a host `UnixListener` at that path. Each
accepted connection opens a vsock stream to the guest and relays bytes both
ways. When either side closes, the other reads EOF: a host client that closes
ends the guest stream, and a guest that closes, or a guest driver that resets
the device, ends the host connection.

hvi sends host bytes only as fast as the guest reads them, and guest bytes only
as fast as the host client reads them. While one side is behind, the other
side's writes block. A host client that writes without reading can therefore
stall its own connection, but not the guest. A host client that streams both
ways should read the connection while it writes to it.

Each side sees the other's close after the last byte written before it. Once
the host client has gone, the guest's writes fail with EPIPE and its reads go
on. The guest's connection is reset once it has every host byte.

The contract the guest side must satisfy:

- Listen on **port 1024**, with the guest at **CID 3** and the host at
  **CID 2**.
- Speak whatever protocol your host side speaks. hvi relays bytes and does not
  interpret them.
- Be listening before a connection arrives, or the connect fails.

hvi provides the transport. It provides no agent, no protocol and no
handshake.

## The vsock, gateway and tap contracts

| Thing | Who creates it | What hvi does |
| --- | --- | --- |
| Agent socket | hvi creates the host listener | Relays bytes to guest CID 3 port 1024. |
| Gateway socket | an external gvisor-tap process | Connects as a client. Warns and falls back to the built-in stub stack if it cannot. |
| Tap device | whoever owns the network namespace | Opens it. Never creates, configures or brings one up. Fails the boot if it cannot open it. |

## Platform gating

hvi builds for its three backend targets only: aarch64 macOS, aarch64 Linux and
x86-64 Linux. On any other target the build stops with a compile error. A crate
that also builds for other targets depends on hvi only for these three, and
gates its call the same way:

```toml
[target.'cfg(any(all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")), all(target_arch = "x86_64", target_os = "linux")))'.dependencies]
hvi = { git = "https://github.com/brig-sh/hvi-vmm", rev = "<commit>" }
```

```rust
#[cfg(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
))]
```

`hvi::CORE_VERSION` reports the VMM core a binary was built against. More than
one binary is built from this crate, and two reporting the same core ran the
same VMM.

## macOS

A binary that links hvi needs the same entitlement the `hvi` command does, on
the binary that actually runs:

```sh
codesign --sign - --entitlements hvi.entitlements --force \
         --options runtime target/release/my-binary
```

An ad-hoc signature is enough, with SIP enabled and with no terminal session.
Re-sign after every build. See
[first-boot.md](first-boot.md#2-sign-on-macos-only).

A core file of a process that links hvi holds all of guest RAM, since macOS
cannot leave a mapping out of one. AMFI writes no core file for a binary without
`com.apple.security.get-task-allow`, so make sure the signed binary does not
carry it. Xcode adds it to a Debug build, and
`codesign -d --entitlements - <binary>` lists what a binary carries. With it,
the sandbox refuses the write only once a run has entered the sandbox, and never
under `sandbox: false`.

## See also

- [plugins.md](plugins.md) for the extension seam.
- [cli.md](cli.md) for what each field does, seen from the command line.
- [architecture.md](architecture.md) for what happens inside `boot`.

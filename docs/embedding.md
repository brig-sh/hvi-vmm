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
[Stopping a run from the host](#stopping-a-run-from-the-host)). It is
`#[non_exhaustive]`, so a `match` on it needs a wildcard arm. When a vCPU fails,
`boot` returns an error that names the vCPU and says how it failed.

CAUTION: `boot` returns `Stop::SystemReset` and stops. It does not reboot the
guest, and nothing in hvi restarts one. If your integration wants a reboot,
call `boot` again yourself.

The call blocks until the guest stops, a vCPU fails, or a stop is requested. It
reads the process's stdin for the whole run, one byte at a time, as the guest
console; nothing else in the process should read stdin while `boot` runs. It
also takes over the kick signal, `SIGRTMIN` on Linux and `SIGUSR1` on macOS: it
installs a no-op handler for it and does not restore the one it replaced. It
sends that signal to its own threads to interrupt them, so nothing else in the
process should use it. Before it returns, the ledger is flushed, the agent
listener and every accepted agent connection are closed, and every thread it
started itself has exited, with two exceptions. A thread still running at its
deadline is left running and `boot` returns an error naming the first such
thread, a vCPU thread before a helper thread. The thread that receives the stop
signals runs for the life of the process (see [Stopping a run from the
host](#stopping-a-run-from-the-host)). `boot` waits up to one second for the
vCPU threads, then up to one second for the helper threads, and then up to one
second for the ledger, which a thread left running can hold; it does not write
the tail of a ledger still held. It returns at most three seconds after the
stop. The waits it cannot interrupt are a plugin blocking in `request`, in
`safepoint` or on a thread it started with `VmHandle::spawn`, and a virtio-fs
worker waiting on a host file lock. On macOS such a lock wait can also stall a
vCPU (see [Known limits](limitations.md#virtio-fs-resource-limits)). A plugin
that keeps the `Arc<dyn VmHandle>` it was given keeps guest RAM, the ledger file
and the block, net and vsock devices until it drops the handle. It also keeps
the VM, through the vCPU kicker on macOS and through the interrupt line of each
block, net or vsock device on Linux. The vCPUs have exited or been left running,
so a kick reaches only a vCPU left running. The tap under `--net-tap` keeps its
carrier up. The disk stays open. The gateway connection under `--net-gateway`
stays on the handle, but the relay shut it down as it ended, so it carries
nothing. A thread the plugin started with `VmHandle::spawn` is joined with the
I/O threads. One it started any other way is not joined, and holds the handle
for as long as it runs. On macOS a second `boot` fails while such a handle
exists, because Hypervisor.framework allows one VM per process.

## A minimal caller

```rust
use hvi::config::BootConfig;

let cfg = BootConfig {
    kernel: std::fs::read("Image")?,
    initramfs: Some(std::fs::read("initramfs.cpio")?),
    mem_bytes: 1024 << 20,
    cmdline: String::from("earlycon console=ttyAMA0 panic=-1"),
    disk: None,
    fs_shares: Vec::new(),
    net: true,
    net_gateway: None,
    net_tap: None,
    net_mac: None,
    events: None,
    sandbox_id: String::from("my-sandbox"),
    vcpus: 2,
    agent_sock: None,
    plugin: None,
    sandbox: true,
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
| `disk` | `Option<String>` | One virtio-blk backing file. |
| `fs_shares` | `Vec<FsShare>` | virtio-fs exports. macOS only: a non-empty vector **fails the boot** on either Linux backend. |
| `net` | `bool` | The built-in stub stack. |
| `net_gateway` | `Option<String>` | A gvisor-tap socket path. Takes precedence over `net`. |
| `net_tap` | `Option<String>` | An existing tap. Linux only. Takes precedence over both. |
| `net_mac` | `Option<[u8; 6]>` | Guest MAC, applied on every backend and mode. |
| `events` | `Option<String>` | The ledger path. |
| `sandbox_id` | `String` | Written into every ledger record. |
| `vcpus` | `u32` | 1 or more. Linux/arm64 refuses more than 8 on a GICv2 host and more than 507 on a GICv3 one, and x86-64 more than 254. |
| `agent_sock` | `Option<String>` | Host Unix socket bridged to the guest agent over vsock. |
| `plugin` | `Option<Arc<dyn Plugin>>` | See [plugins.md](plugins.md). The CLI sets it only for `--dump-memory` and `--trace-io`, chained into one. |
| `sandbox` | `bool` | Confinement. Leave it `true`. |
| `stop` | `Option<StopRegistration>` | Asks the run to stop from the host. See [Stopping a run from the host](#stopping-a-run-from-the-host). |

`FsShare` carries a `path`, a `tag`, a `ShareMode` and a `CachePolicy`. See
[storage-and-sharing.md](storage-and-sharing.md).

## Stopping a run from the host

Create a pair with `hvi::stop::StopHandle::new_pair()` before `boot`, keep the
`StopHandle` and pass the `StopRegistration` in `BootConfig::stop`. `boot` takes
the registration by value, so it serves one run. `StopHandle::request_stop` from
any thread stops the run: the VM stops, the threads are joined and the ledger is
flushed, and `boot` returns `Stop::Requested`. A failure a thread reports, or a
guest stop a vCPU reports, before `boot` reads how the run ended takes the place
of `Stop::Requested`. A plugin asks for the same stop with
`VmHandle::request_stop`.

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
fails the run. The setup lines of a later `boot` in the same process are printed
with `eprintln!` too, so a binary that stopped on `SIGHUP` should end rather
than boot again.

Another stop signal, one second or more after the first, restores the terminal
and ends the process at once by that signal, and the ledger loses its tail. One
that arrives sooner, such as a copy a wrapper forwards, has no effect. A later
call moves the signals to another handle.

Once `boot` has returned, `handle.signal()` names the first stop signal that
asked for the stop, if one did, even one that asked after another request, and
`hvi::signal::exit_by_signal(signal)` ends the process by it, so a parent sees
the same status it would have seen with no handler. A first stop signal that
arrives after the run has ended asks a finished run to stop, so a binary that
keeps running after `boot` returns checks `handle.signal()` once it is done.

`boot` restores the terminal it put in raw mode when it returns. A signal that
ends the process skips that restore. `hvi::terminal::restore_on_fatal_signals()`
installs a handler for each signal in `hvi::terminal::fatal_signals()` that has
no handler and is not ignored. The handler restores the terminal, and the signal
then ends the process with its default action. `SIGSEGV` and `SIGBUS` get the
handler even when they have one. A fault goes to their earlier handler first,
and the terminal is restored only when the fault still ends the process. It does
not restore the handlers it replaces, so call it once, before `boot`, if you
want it.

## Configuration outside `BootConfig`

Two things a caller sets are not in the struct. Both matter.

**Guest file ownership.** `--fs-uid` and `--fs-gid` become two process-global
atomics through `devices::virtio::fs::set_guest_ids(uid, gid)`, because every
share reads the same pair. Call it before `boot`, on macOS only:

```rust
#[cfg(target_os = "macos")]
hvi::devices::virtio::fs::set_guest_ids(0, 0);
```

Setting it after a share is already answering hands the guest a home it cannot
write.

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

## See also

- [plugins.md](plugins.md) for the extension seam.
- [cli.md](cli.md) for what each field does, seen from the command line.
- [architecture.md](architecture.md) for what happens inside `boot`.

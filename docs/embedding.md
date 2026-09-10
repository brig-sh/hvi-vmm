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

Every backend exposes the same function. `lib.rs` aliases the right one to
`hvi::machine` by target triple, so a caller writes one line whatever the
host:

```rust
pub fn boot(cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error>>;
```

`Stop` is `SystemOff` or `SystemReset`: how the guest asked to halt.

CAUTION: `boot` returns `Stop::SystemReset` and stops. It does not reboot the
guest, and nothing in hvi restarts one. If your integration wants a reboot,
call `boot` again yourself.

The call blocks until the guest stops. One process runs one guest.

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
};

let stop = hvi::machine::boot(cfg)?;
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
| `kernel` | `Vec<u8>` | The image bytes. arm64 `Image` or x86-64 `bzImage`, matching the target. |
| `initramfs` | `Option<Vec<u8>>` | Bytes, not a path. |
| `mem_bytes` | `u64` | Guest RAM. |
| `cmdline` | `String` | The backend appends what its own devices need. |
| `disk` | `Option<String>` | One virtio-blk backing file. |
| `fs_shares` | `Vec<FsShare>` | virtio-fs exports. macOS only: a non-empty vector **fails the boot** on either Linux backend. |
| `net` | `bool` | The built-in stack. |
| `net_gateway` | `Option<String>` | A gvisor-tap socket path. Takes precedence over `net`. |
| `net_tap` | `Option<String>` | An existing tap. Linux only. Takes precedence over both. |
| `net_mac` | `Option<String>` | Read only in the tap branch. Ignored everywhere else. |
| `events` | `Option<String>` | The ledger path. |
| `sandbox_id` | `String` | Written into every ledger record. |
| `vcpus` | `u32` | 1 or more. A GICv2 arm64 host refuses more than 8. |
| `agent_sock` | `Option<String>` | Host Unix socket bridged to the guest agent over vsock. |
| `plugin` | `Option<Arc<dyn Plugin>>` | See [plugins.md](plugins.md). The CLI sets it only for `--dump-memory` and `--trace-io`, chained into one. |
| `sandbox` | `bool` | Confinement. Leave it `true`. |

`FsShare` carries a `path`, a `tag`, a `ShareMode` and a `CachePolicy`. See
[storage-and-sharing.md](storage-and-sharing.md).

## Configuration outside `BootConfig`

Two things a caller sets are not in the struct. Both matter.

**Guest file ownership.** `--fs-uid` and `--fs-gid` become two process-global
atomics through `virtio_fs::set_guest_ids(uid, gid)`, because every share
reads the same pair. Call it before `boot`, on macOS only:

```rust
#[cfg(target_os = "macos")]
hvi::virtio_fs::set_guest_ids(0, 0);
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
ways.

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
| Gateway socket | an external gvisor-tap process | Connects as a client. Warns and falls back to the built-in stack if it cannot. |
| Tap device | whoever owns the network namespace | Opens it. Never creates, configures or brings one up. Fails the boot if it cannot open it. |

## Platform gating

Only the backend for your host target compiles. On any other host the crate
builds without one, so the shared code and its unit tests still compile, but
`hvi::machine` does not exist. Gate your call:

```rust
#[cfg(any(
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "linux")
))]
```

`hvi::HAS_BACKEND` is the same predicate as a `const bool`, for a runtime
check or a clear error message.

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

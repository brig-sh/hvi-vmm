# Security model

To report a vulnerability, read [SECURITY.md](../SECURITY.md). This page
describes what hvi defends, how, and what it leaves open.

## The boundary

hvi assumes the guest is hostile. The boundary it is built to hold is the one
around the guest: keep it inside its own VM, away from the host, and away from
every other sandbox on the same machine.

Two mechanisms hold that boundary, and they are not the same thing.

**VM isolation** is the hypervisor's. The guest runs at EL1 or in VMX
non-root, reaches only the memory hvi mapped for it, and every device access
leaves the guest.

**Process confinement** is hvi's own. The VMM confines itself before it
services guest I/O, so a bug in a device backend does not start with the
host's full syscall surface behind it. This is defence in depth. It narrows
the consequences of a bug in hvi. It does not prevent one.

## What the guest can reach

Everything a hostile guest can touch, it touches through hvi:

| Surface | Exposure |
| --- | --- |
| virtio device registers | Parsed on the vCPU thread, from guest-controlled memory. |
| Descriptor chains and buffers | Guest-controlled indices and lengths, bounds-checked against guest RAM. |
| virtio-blk backing file | Whatever `--disk` names. |
| virtio-fs shares | The exported tree, read-only or read-write. |
| Network frames | Parsed by the built-in stack, or relayed without the guest's virtio-net header. |
| vsock | Bytes relayed to whatever listens on `--agent-sock`. |
| Serial console | Bytes written to hvi's stdout, often the operator's terminal. |

A writable share and the agent socket are the two that hand the guest reach
into host state on purpose. Choose both deliberately.

The console reaches the operator's terminal, and a terminal acts on escape
sequences. Some of them write the clipboard, draw hyperlinks or set the window
title. Others make the terminal answer on its input side, which hvi forwards to
the guest, and an answer still queued at exit would reach the operator's shell.
hvi writes console output through a filter that passes text and an allowlist of
escape sequences for the display, and drops the rest. When it restores the
terminal at exit, it discards the input the guest did not read. The allowlist
is in [cli.md](cli.md#console-output).

## Confinement

On by default. `--no-sandbox` turns it off, for debugging a run the profile or
the filters break. Once a run turns it on, it stays on for the life of the
process, since a Seatbelt profile cannot be left and a seccomp filter cannot be
removed from a thread. A process that embeds hvi and runs a sandboxed guest
cannot run a later one with the sandbox off: `boot` refuses that run. On macOS
the profile also refuses what a later sandboxed run sets up, so `boot` refuses
every later run there.

Each backend prints what it installed, so a host where confinement did not
happen says so:

```text
[hvi] seatbelt sandbox: on (deny default)
[hvi] seatbelt sandbox: OFF (--no-sandbox) - the VMM keeps full host authority
```

### macOS: Seatbelt

One process-wide profile, entered once every host resource is open and before
the first I/O thread or vCPU starts. It is deny-default, with one static allow
rule for `file-ioctl` on `/dev/tty`, plus one rule per virtio-fs export by
resolved root path: `file-read*` for a read-only share, `file-read* file-write*`
for a writable one.

A writable export adds one more: `system-fsctl` for the single command
`FSIOC_SYNC_VOLUME`, which is how SYNCFS writes out the export's volume
(`fsync_volume_np(3)` on the export root's descriptor). It is a command
filter, not a path filter, so the process can ask any mounted volume to write
out what it already holds, whatever its file grants. Seatbelt checks this
fsctl per mount, so a path filter on the rule denies every call. The process
can issue no other fsctl, and the grant is absent when every export is
read-only.

Because it is process-wide and goes up before any vCPU exists, no thread
touches guest data unconfined.

### Linux: seccomp-bpf

Two allowlists per architecture, in `resources/seccomp/`, installed by each
thread for itself:

| Filter | Covers | aarch64 | x86-64 |
| --- | --- | --- | --- |
| `vcpu` | the vCPU threads, where guest descriptors are parsed | 37 syscalls | 38 syscalls |
| `vmm` | the thread that calls `boot`, the host-side I/O threads, the threads a plugin starts with `VmHandle::spawn`, the stop-signal thread and the ledger writer | 47 syscalls | 48 syscalls |

The stop-signal thread starts in the first run after a call to
`hvi::signal::stop_on_signals`, once that run's filters are armed, and installs
the `vmm` filter as its first act. It outlives the run and stays filtered. When
that first run has the sandbox off, the thread starts unfiltered, and installs
the filter the first time a stop signal wakes it in a later run with the sandbox
on.

The ledger writer starts when `boot` opens the `--events` file, before the
filters are armed. Before each write it checks whether they are armed, and
installs the `vmm` filter once they are, so only a write under way as they are
armed runs unfiltered. The `vmm.start` record wakes it before any vCPU thread
starts.

`vcpu` is a strict subset of `vmm`, checked by a test. Both use a default
action of `trap`, so an off-list syscall raises `SIGSYS` and kills the
process.

Neither list carries an open syscall (`openat`, `openat2`, and on x86-64
`open`). A glibc build also installs, on every filtered thread and before the
allowlist, a filter that fails those with `EPERM`, and adds them to the
allowlist it compiles. glibc's malloc opens `/proc/sys/vm/overcommit_memory`,
`/sys/devices/system/cpu/online` and `/proc/stat` on its own, from whichever
thread is allocating or freeing, and copes with each open failing. The open is
refused rather than trapped, and the process still opens nothing. A musl build,
whose malloc opens no file, installs the allowlist alone.

The two architecture files are not generated from one source. `poll` is the
only name that differs: x86-64 has both `poll` and `ppoll`, and aarch64 has
`ppoll` alone, because aarch64 has no `poll` syscall.

Failure behaviour differs by install site, and all three fail closed:

- A list that will not compile refuses the boot, before any thread is spawned.
- A worker thread that cannot install its filter prints `[hvi] FATAL` and
  aborts the process.
- The thread that calls `boot` installs its own filter after the vCPUs are
  running, so a failure there stops the guest, waits for every thread and
  returns the error from `boot`.

### `HVI_SECCOMP=log` turns enforcement off

The variable rewrites every filter's mismatch action to `log`. The kernel then
**permits** the off-list syscall and records it. This is not a softer
enforcement mode. It is no enforcement, with logging. A glibc build still
refuses an open under it, without a record.

Use it to find a syscall a distribution needs, by reading `dmesg` or the audit
log while the VMM keeps running. Never run a workload with it set. The
seccomp selftest refuses to run under it, because every denial would become a
log line and the test would prove nothing.

`--no-sandbox` and `HVI_SECCOMP=log` are both out of scope for a
vulnerability report.

## The selftests

```sh
hvi sandbox-selftest    # macOS: 23 probes, 14 expect denial, 9 expect success
hvi seccomp-selftest    # Linux: 21 probes, 9 expect denial, 12 expect success
```

On Linux a glibc build expects 2 of the 9 denials, the two opens, to fail with
`EPERM`, and a musl build expects all 9 to raise `SIGSYS`.

Both install the profile or the filters that actually ship and check both
directions: what a confined thread must keep, and what it must lose. Neither
needs a hypervisor or privileges, so a runner that cannot boot a guest can
still fail a bad list.

```text
  [ok  ] want denied   open an outbound TCP socket    refused (permission denied)
  [ok  ] want allowed  write to a file opened before entry    succeeded
sandbox selftest: every probe matched the profile
```

These are checks of specific allowed and denied actions. A passing selftest
says those probes behaved as the profile says. It is not proof that the
sandbox is secure.

## What confinement does not do

- **It does not drop privilege.** There is no uid, gid or capability change
  anywhere in hvi. The process keeps the identity it was started with.
  Confinement narrows what it may ask the kernel for, nothing else.
- **It does not cover a thread a plugin starts outside `VmHandle::spawn`.** Such
  a thread starts in `on_attach`, before the Linux filters are armed, and stays
  unfiltered. A thread started with `VmHandle::spawn` installs the `vmm` filter
  as it begins, as the memory-dump plugin's `--dump-after` timer does.
- **It does not constrain syscall arguments.** No rule in either architecture
  file carries an argument condition, so `ioctl` and `sendmsg` are
  unconstrained over every descriptor the process already holds.
- **It does not remove the risk of an escape.** It reduces what an escape
  reaches first.

## Out of scope

- A guest that wastes or hangs **its own VM**. The guest owns what it was
  given.
- Host resource exhaustion that follows from limits the operator chose, such
  as running many VMs with no bound on memory.
- Anything under `--no-sandbox` or `HVI_SECCOMP=log`.
- A local user who can open the `--events` file. The ledger's lock is advisory,
  so such a user can hold it and refuse the next run at that path, and can read
  what the guest did. Keep the file where only trusted readers can open it, as
  [observability.md](observability.md#the-event-ledger) says.
- Side channels that come from sharing microarchitecture, such as speculative
  execution and cache timing. They are real, and they are the platform's to
  mitigate.

## Maturity

hvi has had no external security audit, and no part of it has been through
formal verification. CI boots every backend on real hardware and runs the
confinement selftests on both hosts. That is testing, not assurance.

Weigh that before you put something valuable behind it.

## See also

- [limitations.md](limitations.md) for the known limits, including the ones
  with security consequences.
- [storage-and-sharing.md](storage-and-sharing.md) before exporting a writable
  directory.
- [../resources/seccomp/README.md](../resources/seccomp/README.md) to change
  an allowlist.

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
| Network frames | Parsed by the built-in stack, or relayed. |
| vsock | Bytes relayed to whatever listens on `--agent-sock`. |

A writable share and the agent socket are the two that hand the guest reach
into host state on purpose. Choose both deliberately.

## Confinement

On by default. `--no-sandbox` turns it off, for debugging a run the profile or
the filters break.

Each backend prints what it installed, so a host where confinement did not
happen says so:

```text
[hvi] seatbelt sandbox: on (deny default)
[hvi] seatbelt sandbox: OFF (--no-sandbox) - the VMM keeps full host authority
```

### macOS: Seatbelt

One process-wide profile, entered as the last step before the first vCPU
starts. It is deny-default, with one static allow rule for `file-ioctl` on
`/dev/tty`, plus one rule per virtio-fs export by resolved root path:
`file-read*` for a read-only share, `file-read* file-write*` for a writable
one.

Because it is process-wide and goes up before any vCPU exists, no thread
touches guest data unconfined.

### Linux: seccomp-bpf

Two allowlists per architecture, in `resources/seccomp/`, installed per
thread as that thread's first act:

| Filter | Covers | aarch64 | x86-64 |
| --- | --- | --- | --- |
| `vcpu` | the vCPU threads, where guest descriptors are parsed | 36 syscalls | 37 syscalls |
| `vmm` | the main thread and the host-side I/O threads | 46 syscalls | 47 syscalls |

`vcpu` is a strict subset of `vmm`, checked by a test. Both use a default
action of `trap`, so an off-list syscall raises `SIGSYS` and kills the
process.

The two architecture files are not generated from one source. `poll` is the
only name that differs: x86-64 has both `poll` and `ppoll`, and aarch64 has
`ppoll` alone, because aarch64 has no `poll` syscall.

Failure behaviour differs by install site, and all three fail closed:

- A list that will not compile refuses the boot, before any thread is spawned.
- A worker thread that cannot install its filter prints `[hvi] FATAL` and
  aborts the process.
- The main thread installs its own filter after the vCPUs are running, so a
  failure there exits the process with an error.

### `HVI_SECCOMP=log` turns enforcement off

The variable rewrites every filter's mismatch action to `log`. The kernel then
**permits** the off-list syscall and records it. This is not a softer
enforcement mode. It is no enforcement, with logging.

Use it to find a syscall a distribution needs, by reading `dmesg` or the audit
log while the VMM keeps running. Never run a workload with it set. The
seccomp selftest refuses to run under it, because every denial would become a
log line and the test would prove nothing.

`--no-sandbox` and `HVI_SECCOMP=log` are both out of scope for a
vulnerability report.

## The selftests

```sh
hvi sandbox-selftest    # macOS: 23 probes, 14 expect denial, 9 expect success
hvi seccomp-selftest    # Linux: 16 probes, 9 expect a SIGSYS trap, 7 expect success
```

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
- **It does not cover every thread.** With `--dump-after`, the memory-dump
  plugin starts its timer thread before the Linux filters are armed, and that
  thread runs unfiltered for the life of the VM.
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

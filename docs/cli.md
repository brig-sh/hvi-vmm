# Command reference

There is no `--help`. `hvi` with no argument prints one usage line to stderr
and exits 0. `hvi boot --help` is an error, because `--help` is not a flag:

```text
hvi: unknown boot arg "--help"
```

This page is the reference instead.

## Subcommands

Every subcommand is compiled on every supported host. A subcommand that does
not apply returns a named error rather than "unknown subcommand".

| Subcommand | Where it works | What it does |
| --- | --- | --- |
| `boot` | all three backends | Boot a Linux guest. |
| `dump-fdt` | aarch64 only | Build the arm64 devicetree and print the layout. No hypervisor needed. |
| `smoke` | macOS, Apple silicon | The M0 Hypervisor.framework test. `--shm` runs it over shared guest RAM. |
| `smoke-shm-verify <name> <hex>` | macOS, Apple silicon | The child half of `smoke --shm`. Not for direct use. |
| `sandbox-selftest` | macOS | Install the Seatbelt profile and probe it. |
| `seccomp-selftest` | Linux x86-64 and aarch64 | Install the seccomp filters in child processes and probe them. |
| `version`, `--version`, `-V` | everywhere | Print the version and the VMM core. |

```text
$ hvi version
hvi 0.1.0 (core 0.1.0)
```

`smoke` dispatches on an exact match for `--shm`. Any other third argument,
including a typo, silently runs the plain test.

## `boot`

`--kernel` is the only required flag.

### Flag reference

| Flag | Default | Effect |
| --- | --- | --- |
| `--kernel <path>` | required | arm64 `Image` or x86-64 `bzImage`, read whole into memory. |
| `--initramfs <path>` | none | Read whole into memory. |
| `--mem-mib <N>` | 512 | Guest RAM. On x86-64 it is split around the MMIO hole. |
| `--cpus <N>` | 1 | vCPUs. `0` becomes 1 silently. |
| `--cmdline <string>` | `earlycon console=ttyAMA0 panic=-1` | Kernel command line. The default is arm64-flavoured on every backend. |
| `--disk <path>` | none | One virtio-blk backing file. A failure to open fails the boot. |
| `--share-ro <dir> <tag> [cache=…]` | none | Read-only virtio-fs share. Repeatable. macOS only. |
| `--share-rw <dir> <tag> [cache=…]` | none | Read-write virtio-fs share. Repeatable. macOS only. |
| `--fs-uid <N>` | 0 | Guest uid the host's files belong to. macOS only. |
| `--fs-gid <N>` | 0 | Guest gid the host's files belong to. macOS only. |
| `--net` | off | The built-in user-space stack. |
| `--net-gateway <socket>` | none | Relay to an external gvisor-tap process. |
| `--net-tap <dev>` | none | Attach to an existing tap. Linux only. |
| `--net-mac <mac>` | none | Guest MAC. Read only under `--net-tap`. |
| `--agent-sock <path>` | none | Host Unix socket bridged to the guest agent over vsock. |
| `--events <path>` | none | Write the `RawEvent` NDJSON ledger here. |
| `--sandbox-id <string>` | `hvi` | Written into every ledger record. |
| `--dump-memory <path>` | none | Attach the memory dumper. |
| `--dump-after <secs>` | none | Dump automatically after this long. Needs `--dump-memory`. `0` becomes 1. |
| `--trace-io <path>` | none | Attach the I/O tracer. |
| `--no-sandbox` | off | Boot unconfined. For debugging the profile or the filters. |

### Parsing behaviour

Three things about the parser are worth knowing, because none of them warns.

**Repeating a flag is last-wins.** Only `--share-ro` and `--share-rw`
accumulate. A second `--disk` replaces the first.

**A value-taking flag at the end of the line silently takes none.** These
flags accept a missing value as "not set" rather than erroring: `--initramfs`,
`--disk`, `--net-gateway`, `--net-tap`, `--net-mac`, `--events`,
`--agent-sock`, `--dump-memory`, `--trace-io`. So `hvi boot --kernel Image
--disk` boots with no disk.

The rest do error: `--mem-mib`, `--cmdline`, `--fs-uid`, `--fs-gid`,
`--share-ro`, `--share-rw`, `--sandbox-id`, `--cpus`, `--dump-after`.

**A bad number reports the raw parse error, without the flag name.**

```text
hvi: invalid digit found in string
```

### Ignored, refused, or acted on

Which flags a platform honours is the most common source of surprise. There
are three behaviours, not two.

| Flag | macOS | Linux arm64 | Linux x86-64 |
| --- | --- | --- | --- |
| `--share-ro`, `--share-rw` | acted on | **refused**, boot fails | **refused**, boot fails |
| `--fs-uid`, `--fs-gid` | acted on | **ignored silently** | **ignored silently** |
| `--net-tap` | **refused**, boot fails | acted on | acted on |
| `--net-mac` | **ignored silently** | only under `--net-tap` | only under `--net-tap` |
| `--dump-memory` | acted on, but see below | acted on | acted on |
| everything else | acted on | acted on | acted on |

Two of those errors appear **after** `booting <kernel> with <N> MiB ...` has
printed, because they are raised inside the backend rather than at parse time:
`--net-tap` on macOS, and the shares on either Linux backend.

```text
booting Image with 512 MiB ...
hvi: --net-tap tap0: no /dev/net/tun on macOS; use --net-gateway
```

Unknown flags are the one class caught before anything prints.

### Networking precedence

`--net-tap`, then `--net-gateway`, then `--net`. The first that matches wins
and the rest are ignored with no message. See
[networking.md](networking.md).

An unreachable `--net-gateway` warns and falls back to the built-in stack. An
unopenable `--net-tap` fails the boot.

### Parse-time validation

```text
hvi: boot needs --kernel <Image>
hvi: virtio-fs tag must be 1..=36 bytes and contain no NUL
hvi: duplicate virtio-fs tag "dup"
hvi: virtio-fs export is not a directory: /path/to/file
hvi: unknown cache policy "bogus"; expected auto, always or none
hvi: --dump-after needs --dump-memory <path>
hvi: unknown boot arg "--nope"
```

`--net-mac` is **not** validated at parse time. A malformed value only warns
inside the tap branch that reads it.

## `dump-fdt`

Runs the whole arm64 pre-boot pipeline with no hypervisor, no entitlement and
no `/dev/kvm`.

```sh
hvi dump-fdt --kernel Image --mem-mib 1024 --out fdt.dtb
```

| Flag | Default |
| --- | --- |
| `--kernel <Image>` | required |
| `--initramfs <cpio>` | none, only its length is used |
| `--mem-mib <N>` | 512 |
| `--cmdline <string>` | `earlycon console=ttyAMA0 panic=-1` |
| `--out <file>` | none, print only |

It always builds a **one-vCPU devicetree with no virtio devices**, using the
fixed QEMU virt GIC layout rather than whatever a host would negotiate. It has
no `--cpus`, `--disk` or `--net`. Use it to check the kernel header, the guest
layout and the placement arithmetic. It cannot show you the device set a real
boot would describe.

## Environment variables

| Variable | Read by | Effect |
| --- | --- | --- |
| `HVI_SECCOMP=log` | Linux | Install the same allowlists, but let an off-list syscall run and be recorded instead of killing the process. **This turns enforcement off.** |
| `HVI_X86_TRACE` | x86-64 | Any value. Log the first 80 I/O and MMIO exits of each vCPU, dump registers on shutdown, and kick cpu0 four times at two-second intervals so a stuck guest still dumps its registers. |
| `HVI_BLK_TRACE` | all | Any value. Log every virtio-blk request to stderr. Off by default: one synchronous write per request. |

There are no others at run time. `HVI_BLOCK_DEV` appears only inside a test
module and is not read by the VMM.

An embedder inherits these from the process environment. They are not part of
`BootConfig`.

## Stopping a guest

| Path | Result |
| --- | --- |
| The guest powers off | `guest stopped: SystemOff`, exit 0. |
| The guest resets | `guest stopped: SystemReset`, exit 0. |
| The guest halts on x86-64 | Reported as `SystemOff`, because a halt records no reason. |

**hvi never reboots a guest.** `SystemReset` ends the process exactly as
`SystemOff` does. Nothing loops around `machine::boot`. An integration that
wants a reboot calls it again.

### Signals and the terminal

There is no `SIGINT`, `SIGTERM` or `SIGHUP` handler. `SIGUSR1` is used
internally to break a vCPU out of `KVM_RUN` on the Linux backends and is not a
control interface.

hvi puts the terminal into raw mode when stdin is a TTY and restores it when
the boot returns normally. That restore is a destructor, and a destructor does
not run when a signal kills the process.

CAUTION: If you kill hvi with Ctrl-C or `kill`, the terminal is left in raw
mode. Run `stty sane` or `reset` to recover it. Stop a guest from inside it
where you can.

### Ctrl-]

`Ctrl-]` (0x1d) is the plugin request key, and it is intercepted **only when a
plugin is attached**. With no plugin it is sent to the guest as an ordinary
byte.

Only `--dump-memory` acts on it. With `--trace-io` alone the key is
intercepted and nothing happens, because `IoTrace` does not implement the
request hook.

## Startup output

Every backend logs what it set up on stderr before the guest runs. On macOS:

```text
booting Image with 1024 MiB ...
[hvi] 2 vCPU(s)  GICD 0x8000000+0x10000  GICR 0x80a0000+0x2000000  UART 0x1000000
[hvi] virtio-blk: /path/to/disk.img
[hvi] virtio-net: user-space (guest 10.0.2.15, gw 10.0.2.2, DHCP)
[hvi] open-file limit: 1048576
[hvi] virtio-fs[0]: /path/to/share as "code" (read-only)
[hvi] event ledger: /path/to/ledger.ndjson
[hvi] seatbelt sandbox: on (deny default)
```

The Linux backends use `[hvi/kvm]` and `[hvi/x86]` for device lines and plain
`[hvi]` for the confinement line.

`[hvi] open-file limit:` appears only on macOS, and only when at least one
share is configured, because the limit is raised while the first share is set
up.

On a clean stop, macOS reports each share's peak handle count:

```text
[hvi] virtio-fs[0]: peak 1 of 1048448 guest handles
guest stopped: SystemOff
```

## vCPU limits

The only cap inside hvi is the vGICv2 one on Linux/arm64:

```text
this host offers only vGICv2, which supports at most 8 vCPUs (asked for 16)
```

macOS and x86-64 have no hvi-side cap. An over-large `--cpus` on macOS spawns
that many threads and then fails per vCPU with `[hvi] cpuN: vcpu_create
failed`. The absence of a cap is not unlimited capacity.

## See also

- [first-boot.md](first-boot.md) for the sequence.
- [storage-and-sharing.md](storage-and-sharing.md), [networking.md](networking.md),
  [observability.md](observability.md) for what each group of flags does.
- [embedding.md](embedding.md) for the same surface as a `BootConfig`.

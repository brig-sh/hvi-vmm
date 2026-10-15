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
| `restore` | macOS, Apple silicon; arm64 Linux with KVM | Resume a checkpoint bundle, or the stream of a live move, in this process. See [`restore`](#restore). On KVM it restores the portable profile only. On x86-64 Linux it returns an error: that restore is not built yet. |
| `checkpoint-verify <dir>` | everywhere | Check a checkpoint bundle whole and print what it holds. Exits 1, naming the file, on the first mismatch. See [checkpoint.md](checkpoint.md#checking-a-bundle). |
| `dump-fdt` | aarch64 only | Build the arm64 devicetree and print the layout. No hypervisor needed. |
| `smoke` | macOS, Apple silicon | The Hypervisor.framework smoke test. `--shm` runs it over shared guest RAM. |
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
| `--kernel <path>` | required | arm64 `Image`, x86-64 `bzImage` or uncompressed `vmlinux`, read whole into memory. |
| `--initramfs <path>` | none | Read whole into memory. |
| `--mem-mib <N>` | 512 | Guest RAM. On x86-64 it is split around the MMIO hole. |
| `--cpus <N>` | 1 | vCPUs. `0` becomes 1 silently. |
| `--cmdline <string>` | `earlycon console=ttyAMA0 panic=-1` | Kernel command line. The default is arm64-flavoured on every backend. |
| `--disk <path>` | none | One virtio-blk backing file. A failure to open fails the boot, and so does a disk another process holds locked: hvi holds an exclusive `flock` on its disk (see [checkpoint.md](checkpoint.md#the-disk-lock)). |
| `--disk-base-sha256 <hex>` | none | The SHA-256 of `--disk` as this boot opens it, before this hvi writes it, 64 lowercase hex digits. hvi tracks only the writes it serves from this boot on, so a disk that an earlier boot wrote needs a new digest, or no flag. hvi does not hash the disk: the caller did, and keeps a copy of that image. The machine profile records it as `disk_base_sha256`, and a move can then send only the blocks the guest wrote (see [checkpoint.md](checkpoint.md#moving-the-disk-by-its-blocks)). Needs `--disk`. The boot refuses a disk over 4 TiB with it, when it opens the disk. With `--disk-written`, it is the digest of the base image `--disk` was made from instead. |
| `--disk-written <file>` | none | The blocks where `--disk` already differs from the base image `--disk-base-sha256` names, as a bitmap file: bit `i` of byte `i / 8` for 64 KiB block `i`, exactly as long as the disk's bitmap (`ceil(blocks / 8)` bytes). A launcher that writes files into its copy of the base before the boot names the blocks it changed, and they start the blocks written since boot, so a move by blocks sends them too. hvi reads the file at the boot and does not check it against the disk. Needs `--disk-base-sha256`; the boot refuses a file of the wrong length or with a bit past the disk. |
| `--fs tag=<tag>,path=<dir>[,readonly=on\|off][,cache=auto\|always\|none][,uid=<n>][,gid=<n>]` | none | virtio-fs export of `<dir>`, which hvi serves itself. Writable unless `readonly=on`; `cache` defaults to `auto`; `uid` and `gid` are the guest owner of the host user's files, 0 by default. Repeatable. macOS only. |
| `--fs tag=<tag>,socket=<socket>[,num_queues=<n>][,queue_size=<size>]` | none | virtio-fs export served by the vhost-user daemon listening on `<socket>`, which the caller runs. Cloud Hypervisor's syntax and defaults: one request queue, at most one per vCPU, and a queue size of 1024, a power of two up to 32768. hvi waits up to 60 s for the socket to accept. Repeatable. Linux only. |
| `--share-ro <dir> <tag> [cache=…]`, `--share-rw <dir> <tag> [cache=…]` | none | Deprecated: `--fs tag=<tag>,path=<dir>` with `readonly=on` or off. Each prints a note. macOS only. |
| `--fs-uid <N>`, `--fs-gid <N>` | 0 | Deprecated: `uid=` and `gid=` on every `--share-ro`/`--share-rw` export. An `--fs` export keeps its own. Each prints a note. No effect on Linux. |
| `--net-stub` | off | The built-in stub stack: answers ARP, ICMP, DNS and DHCP, forwards nothing in either direction. `--net` is a deprecated alias. |
| `--net-gateway <socket>` | none | Relay to an external gvisor-tap process. |
| `--net-tap <dev>` | none | Attach to an existing tap. Linux only. |
| `--net-mac <mac>` | none | Guest MAC. Honoured on every backend and mode. |
| `--agent-sock <path>` | none | Host Unix socket bridged to the guest agent over vsock. |
| `--control-sock <path>` | none | Host Unix socket that pauses, resumes, reports and stops the VM. See [The control socket](#the-control-socket). |
| `--profile-out <path>` | none | Write the machine profile here, as one line of JSON. See [The control socket](#the-control-socket). |
| `--checkpoint-root <dir>` | none | The directory a `checkpoint` may write bundles below. It must exist, and should be private to this sandbox (mode 0700): bundles hold guest RAM in clear. Needs `--control-sock`. Without it every `checkpoint` is refused. See [checkpoint.md](checkpoint.md). |
| `--events <path>` | none | Write the `RawEvent` NDJSON ledger here. |
| `--sandbox-id <string>` | `hvi` | Written into every ledger record. |
| `--dump-memory <path>` | none | Attach the memory dumper. |
| `--dump-after <secs>` | none | Dump automatically after this long. Needs `--dump-memory`. `0` becomes 1. |
| `--trace-io <path>` | none | Attach the I/O tracer. |
| `--no-sandbox` | off | Boot unconfined. For debugging the profile or the filters. |
| `--profile <name>` | `native` | The machine the guest gets: `native` or `portable-arm64-v1`. See [portable-profile.md](portable-profile.md). |
| `--arch-timer-irq` | off | A debugging aid for `--profile portable-arm64-v1`, whose `/timer` otherwise has a fixed `clock-frequency` of 54 MHz and no interrupts. Gives `/timer` its four PPIs back, so a kernel without the `hvi-time` driver still ticks. It changes the devicetree and the profile's `dtb_sha256`. |

### Parsing behaviour

Three things about the parser are worth knowing, because none of them warns.

**Repeating a flag is last-wins.** Only `--fs`, `--share-ro` and `--share-rw`
accumulate. A second `--disk` replaces the first.

**A value-taking flag at the end of the line silently takes none.** These
flags accept a missing value as "not set" rather than erroring: `--kernel`,
`--initramfs`, `--disk`, `--net-gateway`, `--net-tap`, `--events`,
`--agent-sock`, `--dump-memory`, `--trace-io`. So `hvi boot --kernel Image
--disk` boots with no disk. `--net-mac` is not among them: it is parsed where
it is read, so a missing or malformed value fails the boot.

`--kernel` is the one where that matters, because it is required. It is not
caught by the parser. A trailing `hvi boot --kernel` parses to "not set" and
then fails the later required check, with the same message as omitting the
flag altogether:

```text
hvi: boot needs --kernel <Image>
```

The rest do error at parse time: `--mem-mib`, `--cmdline`, `--fs-uid`,
`--fs-gid`, `--share-ro`, `--share-rw`, `--fs`, `--sandbox-id`, `--cpus`,
`--dump-after`, `--control-sock`, `--profile-out`, `--checkpoint-root`,
`--disk-base-sha256`, `--disk-written`.

**A bad number reports the raw parse error, without the flag name.**

```text
hvi: invalid digit found in string
```

### Ignored, refused, or acted on

Which flags a platform honours is the most common source of surprise. There
are three behaviours, not two.

| Flag | macOS | Linux arm64 | Linux x86-64 |
| --- | --- | --- | --- |
| `--fs path=`, `--share-ro`, `--share-rw` | acted on | **refused**, boot fails | **refused**, boot fails |
| `--fs socket=` | **refused**, boot fails | acted on | acted on |
| `--fs-uid`, `--fs-gid` | acted on | **ignored**, with a note | **ignored**, with a note |
| `--net-tap` | **refused**, boot fails | acted on | acted on |
| `--dump-memory` | acted on, but see below | acted on | acted on |
| `--profile portable-arm64-v1`, `--arch-timer-irq` | acted on | acted on, on a host that can present the profile | **refused**, boot fails |
| `--fs`, `--share-ro`, `--share-rw` with `--profile portable-arm64-v1` | **refused**, boot fails | **refused**, boot fails | **refused**, boot fails |
| `--arch-timer-irq` without `--profile portable-arm64-v1` | **refused**, boot fails | **refused**, boot fails | **refused**, boot fails |
| everything else | acted on | acted on | acted on |

Every refusal in that table appears **after** `booting <kernel> with <N> MiB
...` has printed, because it is raised inside the backend rather than at parse
time. The last two are checked by every backend, so a program that embeds hvi
gets them too:

```text
booting Image with 512 MiB ...
hvi: --net-tap tap0: no /dev/net/tun on macOS; use --net-gateway
```

```text
booting Image with 512 MiB ...
hvi: --fs/--share-ro/--share-rw are not part of --profile portable-arm64-v1: a portable guest keeps its storage on virtio-blk
```

```text
booting Image with 512 MiB ...
hvi: --arch-timer-irq needs --profile portable-arm64-v1
```

On Linux/arm64 the portable profile also needs a host that can present it:
a vGICv2, a Cortex-A76 r4p1 `MIDR_EL1`, ID register fields KVM can lower to
the baseline, a 40-bit guest address space, `KVM_CAP_READONLY_MEM`, and 4 KiB
or 16 KiB pages. Otherwise the boot fails, naming each problem, as in
`this host cannot present --profile portable-arm64-v1: …`.

`--no-arch-timer-irq` no longer exists: no interrupts on `/timer` is the
portable profile's default. It is now an unknown flag.

Unknown flags are the one class caught before anything prints.

### Networking precedence

`--net-tap`, then `--net-gateway`, then `--net-stub`. The first that matches
wins and the rest are ignored with no message. See
[networking.md](networking.md).

An unreachable `--net-gateway` warns and falls back to the built-in stub stack.
An unopenable `--net-tap` fails the boot.

### Parse-time validation

```text
hvi: boot needs --kernel <Image>
hvi: virtio-fs tag must be 1..=36 bytes and contain no NUL
hvi: duplicate virtio-fs tag "dup"
hvi: virtio-fs export /path/to/missing: No such file or directory (os error 2)
hvi: virtio-fs export is not a directory: /path/to/file
hvi: unknown cache policy "bogus"; expected auto, always or none
hvi: --dump-after needs --dump-memory <path>
hvi: --disk-base-sha256 must be 64 lowercase hex digits, not "ABC"
hvi: --disk-base-sha256 needs --disk, the disk it describes
hvi: --disk-written needs --disk-base-sha256, the base it differs from
hvi: unknown machine profile "portable"; expected native or portable-arm64-v1
hvi: unknown boot arg "--nope"
```

### The control socket

`--control-sock` binds a Unix socket before confinement, as `--agent-sock` does,
and serves one connection at a time. A socket left at the path by an earlier run
is replaced. Anything else there is an error, and is left alone. Each request is one JSON object on a line,
and each reply is one line:

```text
{"v":1,"op":"pause"}   ->  {"v":1,"ok":true,"state":"paused"}
{"v":1,"op":"status"}  ->  {"v":1,"ok":true,"state":"paused","vcpus":2,"vcpus_parked":2}
{"v":1,"op":"resume"}  ->  {"v":1,"ok":true,"state":"running"}
```

| `op` | Effect |
| --- | --- |
| `profile` | Replies with the machine profile under `profile`, waiting up to 2 s for it on macOS, where the boot vCPU completes it. |
| `pause` | Holds the host I/O threads, waiting up to 10 s for them as `migrate` does, then parks every started vCPU, waiting up to 2 s. If either wait runs out, the pause is undone and the reply is `timeout`. The vCPUs run on while the I/O threads are waited for: the wait is for the virtio-blk worker's request in flight, a flush that took over 2 s on a busy disk among them. |
| `resume` | Releases the vCPUs, then the I/O threads. |
| `status` | Replies with `state` (`running`, `paused`, `restored-paused`, `fenced` or `stopping`), `vcpus` started and `vcpus_parked`. `restored-paused` is a guest `hvi restore` loaded that has not run yet; `resume` runs it, as from `paused`. |
| `stop` | Ends the run, paused or not. `boot` returns `Requested`. |
| `checkpoint` | Captures the VM into a new bundle directory below `--checkpoint-root`, then resumes it or fences it. See [checkpoint.md](checkpoint.md#taking-a-checkpoint). |
| `migrate` | Streams the VM on this connection: its RAM in rounds while the guest runs, with the disk's written blocks in rounds of their own when the disk has a base, then the last rounds and its state paused, then resumes it or fences it. Takes `then`, `txid` and `epoch` as `checkpoint` does, and optionally `max_rounds` (1 to 16, default 5) and `max_secs` (0 to 3600, default 60). Needs no `--checkpoint-root`. Its pause waits up to 10 s for the I/O threads and the vCPUs together, where a `pause` gives the vCPUs 2 s of their own. On a fenced VM it streams the sealed state again only for the same `txid` and `epoch`, both given, with `then: "fence"`, and is `fenced` otherwise. See [checkpoint.md](checkpoint.md#live-moves). |
| `disk-dirty` | `{"since":"boot"}` or `{"since":"round"}`. Replies with the disk's 64 KiB blocks the guest wrote since it booted, or since the last `disk-dirty`, as a base64 bitmap under `bitmap_b64`, with `round`, `block_size`, `blocks` (of the disk), `dirty` (set in the bitmap), `generation` and `bitmap_sha256` (the SHA-256 of the bitmap). Each read starts a round: `boot` is round 0 and clears what `round` would return. With the guest paused it syncs the disk first. See [checkpoint.md](checkpoint.md#moving-the-disk-by-its-blocks). |
| `disk-blocks` | `{"blocks":[3,4,9]}` (ascending, at most 4096) or `{"round":k}` (the round the last `disk-dirty` read). Streams the blocks' bytes on the connection in batches, each a header line and its bytes, then replies with `round` (for a round), `blocks`, `bytes`, `batches`, `generation`, `max_lock_us` and `sent_sha256` (the SHA-256 of the batches' digests in order). See [checkpoint.md](checkpoint.md#the-block-stream). |

`disk-dirty` and `disk-blocks` need `--checkpoint-root` and a disk, as a move
does, and work in every state but `stopping`; without either they are
`refused`. A `disk-blocks` whose list names a block past the disk, or out of
order, is `bad_request`, and one for a round that is not the last read is
`refused`; neither sends a byte first. A block that cannot be read ends the
stream with `capture_failed`. A line with a `v` key is always the reply; a
batch header has none.

`pause` and `resume` are idempotent. A pause outlives the connection that asked
for it. A `pause` replies within about 12 s, the I/O threads' 10 s and the
vCPUs' 2 s, so give its client a reply timeout of at least 13 s. Apart from
`pause`, `checkpoint`, `migrate` and `disk-blocks`, no reply takes longer than
about 2 s, so give a client a reply timeout of at least 3 s. A `checkpoint`
pauses as `pause` does, then waits up to 2 s for the vCPUs' state, and replies
once its bundle is written, which takes longer the more
guest RAM is in use, and a `disk-blocks` once its last batch is out, which
takes as long as the client takes to read them. A `migrate` writes its stream
before its reply, as fast as the client reads it: rounds with the guest
running until one ends past `max_secs` (the cap is checked as each round
ends, so a round under way, round 0 included, runs to its end however long it
takes), then the paused part. So its client reads the frames and waits for
the reply with no fixed timeout. hvi gives up on a client that takes nothing
for 30 s, or that does not take the paused part within its budget, and the VM
runs on (see [checkpoint.md](checkpoint.md#the-rounds)). A client that gives
up on a `pause` before its reply cannot
tell whether the VM paused: it should reconnect and ask `status`, or send
`resume`, which is harmless on a running VM. A refusal is `{"v":1,"ok":false,"code":...,"error":...}`. Branch on
`code`; `error` is for a person. The codes are listed in
`src/checkpoint/control.rs`. The socket has no authentication: anyone who can
connect to it can pause or stop the VM, and read its disk with `disk-blocks`
once it has a checkpoint root, so put it in a directory only its owner can
reach.

`--profile-out` writes the machine profile: what the guest was built against,
such as the CPU's ID registers, the counter frequency, the interrupt
controller, RAM, devices and the hvi commit. Two hosts compare profiles before
a guest moves between them. A profile matches no other when a value in it could
not be read, or when its hvi does not know its commit or was built with
uncommitted changes. The file is created before confinement. On Linux it
is written before the guest starts. On macOS the boot vCPU writes it just
before the guest's first instruction, since only that thread can read
`MIDR_EL1`, so a reader that finds it empty waits or asks the socket.

## `restore`

`restore --from <dir> --control-sock <path> --checkpoint-root <dir> [flags]`
resumes the checkpoint bundle in `<dir>` in this process, and
`restore --from-stream <socket>|- [--stream-keep <dir>] --control-sock <path> --checkpoint-root <dir> [flags]`
resumes the streamed bundle a `migrate` writes, on a host whose
machine profile matches the bundle's. It refuses with every reason it finds
before it creates anything, and otherwise brings the guest up
`restored-paused` on the control socket. The guest runs once a client sends
`resume`. See [checkpoint.md](checkpoint.md#restoring-a-bundle).

| Flag | Default | Effect |
| --- | --- | --- |
| `--from <dir>` | one of the two | The bundle directory. |
| `--from-stream <socket>\|-` | one of the two | The streamed bundle: `-` reads it from stdin, anything else is a Unix socket hvi connects to before confinement and reads it from. RAM is applied as it arrives and never reaches disk; the stream's disk rounds, if it has them, are written into `--disk` as they arrive; the documents and the disk rounds are checked once the manifest is in, before anything runs. Stdin that carried a stream is replaced with `/dev/null` afterwards, so the console reads nothing that followed it. See [checkpoint.md](checkpoint.md#restoring-a-stream). |
| `--stream-keep <dir>` | none | With `--from-stream`: a new directory the stream's documents and manifest are written to as they came, without RAM, as the record of what was restored. They are not synced. |
| `--control-sock <path>` | required | The control socket, as for `boot`. The guest waits on it for `resume`, so a restore without one could never run. |
| `--checkpoint-root <dir>` | required | The directory a later `checkpoint` of the restored guest writes below, as for `boot`. |
| `--disk <path>` | none | The disk to reopen for the guest's virtio-blk. Required when the guest had a disk, refused when it had none. It must be the size the guest was given, and no other process may hold it locked: a second restore onto the disk of a running guest fails (see [checkpoint.md](checkpoint.md#the-disk-lock)). For a stream with disk rounds it is the destination's own copy of the guest's base image, which the rounds turn into the guest's disk; a disk another hvi holds is then refused at once. |
| `--disk-generation <g>` | none | With `--from` only: says `--disk` is the guest's base image with every round of `disk-blocks` applied, the last of them started by a `disk-dirty` reply whose `generation` was `g`. The restore then refuses a `disk.json` with no base, or captured at another generation: the guest wrote after that round. Needs `--disk`. A stream checks its disk rounds this way itself, and refuses the flag. See [checkpoint.md](checkpoint.md#restoring-onto-the-base). |
| `--disk-base-sha256 <hex>` | none | With `--from-stream` and `--disk` only: says `--disk` is a copy of the base image with this SHA-256, as the source's `boot --disk-base-sha256` named it. The restore then refuses, at `profile.json` and before a block is written, a stream whose source named another base or none, and refuses a stream that carried no disk rounds. Without it such a stream would restore onto the bare base, a disk without the guest's writes. A mover that restores onto a base copy should always give it. |
| `--net-stub` | off | The built-in stack, for a guest that ran on it. |
| `--net-gateway <socket>` | none | The gateway, for a guest that ran on one. Unlike `boot`, a gateway that cannot be reached is an error, not a fallback to the stub. |
| `--net-mac <mac>` | none | Optional: the bundle holds the MAC. One given here must be that MAC. |
| `--agent-sock <path>` | none | The agent socket. Required when the guest had a vsock device, refused when it had none. The guest's earlier connections are reset. |
| `--sandbox-id <string>` | the bundle's | Written into every ledger record. |
| `--events <path>` | none | The `RawEvent` ledger, as for `boot`. |
| `--profile-out <path>` | none | This machine's profile, as for `boot`. |
| `--no-sandbox` | off | Run unconfined. |

Each flag needs exactly what the guest had: the network mode and the
devices are part of the machine it was built against. `--net-tap` is not
taken. The kernel, initramfs, command line, vCPU count and RAM size come
from the bundle, and so does the machine profile: a bundle of a
`--profile portable-arm64-v1` guest restores as one, on HVF or on arm64
KVM, from either backend. On KVM only the portable profile restores; a
native KVM bundle is refused, since its vGICv3 is not captured. See
[checkpoint.md](checkpoint.md#the-portable-restore).

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

The blob it writes carries a fresh random `rng-seed` and `kaslr-seed`, as a
boot's would. Neither is printed, and no boot uses them.

It always builds a **one-vCPU devicetree with no virtio devices**, using the
fixed QEMU virt GIC layout rather than whatever a host would negotiate. It has
no `--cpus`, `--disk` or `--net-stub`. Use it to check the kernel header, the
guest layout and the placement arithmetic. It cannot show you the device set
a real boot would describe.

## Environment variables

| Variable | Read by | Effect |
| --- | --- | --- |
| `HVI_SECCOMP=log` | Linux | Install the same allowlists, but let an off-list syscall run and be recorded instead of killing the process. **This turns enforcement off.** |
| `HVI_X86_TRACE` | x86-64 | Any value. Print the guest's CPUID leaf 1 and `0x4000_0001` at boot, log the first 80 I/O and MMIO exits of each vCPU, dump registers on shutdown, and kick vcpu0 four times at two-second intervals so a stuck guest still dumps its registers. |
| `HVI_BLK_TRACE` | all | Any value. Log every virtio-blk request to stderr. Off by default: one synchronous write per request. |

There are no others at run time. `HVI_BLOCK_DEV` appears only inside a test
module and is not read by the VMM.

An embedder inherits these from the process environment. They are not part of
`BootConfig`.

## Stopping a guest

| Path | Result |
| --- | --- |
| The guest powers off | `guest stopped: SystemOff`, exit 0. |
| The control socket's `stop` | `guest stopped: Requested`, exit 0. |
| The guest resets | `guest stopped: SystemReset`, exit 0. |
| A vCPU fails | `hvi: <what failed>`, exit 1. |
| `SIGTERM`, `SIGINT` or `SIGHUP` | `guest stopped: Requested`, or `hvi: <what failed>` if the run failed, and then the process ends by that signal. |
| An x86-64 guest halts, or powers off without ACPI | The run does not end. |

A vCPU fails on an exit hvi does not service, on an error from the hypervisor,
or on a panic in hvi. On macOS, an access to an address no device answers is
such an exit. The line names the vCPU and the failure. A panic in one of hvi's
I/O threads, such as the console reader or a network relay, fails the run the
same way, and the line names the thread.

An x86-64 guest powers off through ACPI, so a kernel without ACPI cannot power
off; see [guest-images.md](guest-images.md). `reboot -f` ends the run either
way, as `SystemReset`.

**hvi never reboots a guest.** `SystemReset` ends the process exactly as
`SystemOff` does. Nothing loops around `hvi::boot`. An integration that wants a
reboot calls it again.

### Signals and the terminal

`SIGTERM`, `SIGINT` and `SIGHUP` stop the run. hvi stops the vCPUs, joins its
threads, flushes the ledger and restores the terminal, and then ends by the
signal it received, so a shell reports status 128 plus the signal number and a
service manager sees the process end by that signal. The guest is not asked to
shut down first. If the stop does not complete, another of these signals, one
second or more after the first, restores the terminal and ends hvi at once by
that signal, and the ledger loses its tail. One that arrives sooner, such as a
copy a wrapper script forwards, has no effect. A signal hvi starts with ignored,
such as `SIGHUP` under `nohup`, stays ignored.

In raw mode the terminal sends Ctrl-C to the guest as a byte, so `SIGINT`
reaches hvi only from `kill` or when stdin is not a TTY.

hvi uses one signal internally, `SIGRTMIN` on Linux and `SIGUSR1` on macOS. It
breaks a vCPU out of `KVM_RUN` on the Linux backends and ends the console
reader's read of stdin when the run stops. It is not a control interface.

hvi puts the terminal into raw mode when stdin is a TTY and restores it when the
boot returns. The restore discards input the guest did not read. hvi also
restores the terminal when any other signal ends the process, such as a crash,
an abort, a syscall the seccomp filter refuses or `SIGQUIT`. The process then
ends by that signal, with a core dump where that signal's default makes one.

CAUTION: `SIGKILL` cannot be handled. If hvi is killed with it, the terminal is
left in raw mode. Run `stty sane` or `reset` to recover it.

### Console output

The guest's console output reaches stdout through a filter. It passes text and
the C0 controls a console uses, except ENQ. Of the escape sequences, it passes:

- cursor movement and position, saving and restoring the cursor, and the
  cursor's style;
- erasing, inserting and deleting characters and lines, scrolling, the scrolling
  region, moving by tab stops, repeat and insert mode;
- colors and attributes (SGR);
- the G0 to G3 character sets (ASCII, UK and DEC line drawing) and the keypad
  mode;
- the DEC private modes for cursor keys, reverse video, origin, autowrap, cursor
  blink and visibility, the alternate screen and bracketed paste;
- the soft reset (DECSTR).

`csi_allowed` and `DEC_MODES` in `src/terminal/filter.rs` are the full
definition. The filter drops every other escape sequence, every OSC, DCS, APC,
PM and SOS string, every C1 control, and ENQ. That includes the hard reset
(RIS), erasing the scrollback (`CSI 3 J`) and setting or clearing tab stops
(HTS, TBC), which would change the terminal after hvi exits. Bytes that are not
valid UTF-8 are shown as U+FFFD.

A guest therefore cannot set the window title, write the clipboard, draw a
hyperlink or enable mouse reporting. A guest program that asks the terminal a
question, such as a cursor position report or its device attributes, gets no
answer. When hvi restores the terminal at exit, it discards the input the guest
did not read.

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
[hvi] 2 vCPU(s)  GICD 0x8000000+0x10000  GICR 0x80a0000+0x2000000  UART 0xc000000
[hvi] virtio-blk: /path/to/disk.img
[hvi] virtio-net: built-in stub stack (guest 10.0.2.15, gw 10.0.2.2, DHCP; no egress, no inbound)
[hvi] open-file limit: 1048576
[hvi] virtio-fs[0]: /path/to/share as "code" (read-only)
[hvi] event ledger: /path/to/ledger.ndjson
[hvi] seatbelt sandbox: on (deny default)
```

Under `--profile portable-arm64-v1` the GIC line names the software GICv2,
`hvi-time` reports its windows and its timer thread, and the boot vCPU logs
the CPU baseline it gave every vCPU:

```text
[hvi] 1 vCPU(s)  profile portable-arm64-v1  software GICv2: GICD 0x8000000+0x10000  GICC 0x8010000+0x10000  UART 0xc000000
[hvi] hvi-time: page 0xd100000+0x10000 (read-only), timers 0xd110000+0x10000, PPI 4 (INTID 20), counter 24000000 Hz
[hvi] seatbelt sandbox: on (deny default)
[hvi] hvi-time: timer thread on time-constraint policy
[hvi] portable-arm64-v1 CPU baseline: MIDR_EL1=0x414fd0b1 ID_AA64PFR0_EL1=0x1100000010110011 ... (host CTR_EL0=0x99444c004 DCZID_EL0=0x4, not settable)
```

On Linux/arm64 the same profile logs the baseline it wrote, the counter
offset and its check, and the read-only memory slot:

```text
[hvi] 1 vCPU(s)  V2  GICD 0x8000000+0x10000  GICC 0x8010000+0x10000  profile portable-arm64-v1
[hvi] portable-arm64-v1 CPU baseline: MIDR_EL1=0x414fd0b1 ... ID_AA64ISAR2_EL1=0x0 (host CTR_EL0=0x9444c004 DCZID_EL0=0x4, not lowered); firmware bitmaps 0, PSCI 1.1
[hvi] hvi-time: guest counter set with KVM_ARM_SET_COUNTER_OFFSET; check: KVM_REG_ARM_TIMER_CNT 115 within hvi's [81, 125]: yes
[hvi] hvi-time: page 0xd100000+0x10000 (read-only slot), timers 0xd110000+0x10000, PPI 4 (INTID 20), counter 54000000 Hz, counter offset 0x…
[hvi] seccomp: on (vmm 47 syscalls, vcpu 37, trap on mismatch)
[hvi] hvi-time: timer thread on timer slack 1 ns
```

`HVI_TIME_TRACE=1` in the environment adds one line a second with the exits
hvi handled and how late the timers fired, for measuring the profile's cost:

```text
[hvi] hvi-time trace: exits/s 1750 (gic 750, hvi-time 750, kicked 250) fires/s 250 late avg 8 us max 18 us
```

`HVI_TIME_TEST_RESTORE=<at>,<downtime>` is a test hook, not a feature: it
captures and restores `hvi-time` in the same process while the vCPUs are
paused. See [portable-profile.md](portable-profile.md#restore).
`HVI_TIME_TEST_SLEEP=<at>,<secs>` is one too: it moves the host clocks
`hvi-time` reads `<secs>` ahead at `<at>`, as a host sleep would, and logs
`hvi-time test sleep: …` at the start. `tools/sleep-e2e.py` uses it. See
[portable-profile.md](portable-profile.md#host-sleep).

`[hvi] open-file limit:` appears only on macOS, and only when at least one
share is configured, because the limit is raised while the first share is set
up.

On a clean stop, macOS reports each share's peak handle count:

```text
[hvi] virtio-fs[0]: peak 1 of 1048448 guest handles
guest stopped: SystemOff
```

## vCPU limits

hvi has three caps. The GICv2 one takes at most 8 vCPUs: on Linux/arm64 when the
host offers only a vGICv2 or the boot asks for `--profile portable-arm64-v1`,
and on macOS under that profile, whose software GICv2 addresses at most 8 CPUs:

```text
this host offers only vGICv2, which supports at most 8 vCPUs (asked for 16)
```

A vGICv3 host takes at most 507, since each vCPU adds a redistributor frame from
a fixed base and the frames must end below the UART:

```text
512 vCPUs would push the GIC redistributors into the UART at 0xc000000; at most 507 fit
```

An x86-64 guest takes at most 254, since the MP table and the ACPI tables give
each vCPU a one-byte APIC id and the IOAPIC the next one:

```text
x86-64 supports at most 254 vCPUs (asked for 300)
```

macOS has no hvi-side cap. An over-large `--cpus` there spawns that many
threads, and the run then fails with exit 1 and `hvi: vcpuN: vcpu_create
failed`. The absence of a cap is not unlimited capacity.

## See also

- [first-boot.md](first-boot.md) for the sequence.
- [storage-and-sharing.md](storage-and-sharing.md), [networking.md](networking.md),
  [observability.md](observability.md) for what each group of flags does.
- [embedding.md](embedding.md) for the same surface as a `BootConfig`.

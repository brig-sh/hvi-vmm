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
| `--disk <path>` | none | A writable virtio-blk disk. Repeatable, up to 4 disks. A failure to open, or a lock another hvi holds on the image, fails the boot. |
| `--disk path=<path>[,readonly=on\|off][,serial=<id>]` | none | The same disk with options, in Cloud Hypervisor's form. `readonly=on` opens the image `O_RDONLY` and advertises `VIRTIO_BLK_F_RO`. `serial` is what the guest reads from `/sys/block/vdX/serial`, 1 to 20 printable ASCII bytes, `disk<N>` by default with `N` the disk's position. Two disks may not share one. |
| `--fs tag=<tag>,path=<dir>[,readonly=on\|off][,cache=auto\|always\|none][,uid=<n>][,gid=<n>]` | none | virtio-fs export of `<dir>`, which hvi serves itself. Writable unless `readonly=on`; `cache` defaults to `auto`; `uid` and `gid` are the guest owner of the host user's files, 0 by default. Repeatable. macOS only. |
| `--fs tag=<tag>,socket=<socket>[,num_queues=<n>][,queue_size=<size>]` | none | virtio-fs export served by the vhost-user daemon listening on `<socket>`, which the caller runs. Cloud Hypervisor's syntax and defaults: one request queue, at most one per vCPU, and a queue size of 1024, a power of two up to 32768. hvi waits up to 60 s for the socket to accept. Repeatable, up to 11 exports on x86-64. Linux only. |
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
| `--events <path>` | none | Write the `RawEvent` NDJSON ledger to this file. hvi refuses anything that is not a regular file, such as `/dev/null` or a FIFO. It also refuses a locked file, such as another run's ledger or disk, and a symbolic link as the last component of the path, such as `/dev/fd/N` on Linux. |
| `--sandbox-id <string>` | `hvi` | Written into every ledger record. |
| `--dump-memory <path>` | none | Attach the memory dumper. |
| `--dump-after <secs>` | none | Dump automatically after this long. Needs `--dump-memory`. `0` becomes 1. |
| `--trace-io <path>` | none | Attach the I/O tracer. |
| `--no-sandbox` | off | Boot unconfined. For debugging the profile or the filters. |

### Parsing behaviour

Three things about the parser are worth knowing, because none of them warns.

**Repeating a flag is last-wins.** Only `--fs`, `--share-ro`, `--share-rw` and
`--disk` accumulate. Each `--disk` adds a disk, in command-line order, and a
fifth fails the boot. Before hvi had more than one disk slot, a second `--disk`
replaced the first without a word; a caller that relied on that now gets two
disks.

**A value-taking flag at the end of the line silently takes none.** These
flags accept a missing value as "not set" rather than erroring: `--kernel`,
`--initramfs`, `--net-gateway`, `--net-tap`, `--events`, `--agent-sock`,
`--dump-memory`, `--trace-io`. So `hvi boot --kernel Image --events` boots with
no ledger. `--net-mac` and `--disk` are not among them: a missing or malformed
value fails the boot.

`--kernel` is the one where that matters, because it is required. It is not
caught by the parser. A trailing `hvi boot --kernel` parses to "not set" and
then fails the later required check, with the same message as omitting the
flag altogether:

```text
hvi: boot needs --kernel <Image>
```

The rest do error at parse time: `--mem-mib`, `--cmdline`, `--fs-uid`,
`--fs-gid`, `--share-ro`, `--share-rw`, `--fs`, `--sandbox-id`, `--cpus`,
`--dump-after`, `--control-sock`, `--profile-out`, `--checkpoint-root`.

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
| everything else | acted on | acted on | acted on |

Two of those errors appear **after** `booting <kernel> with <N> MiB ...` has
printed, because they are raised inside the backend rather than at parse time:
`--net-tap` and `--fs socket=` on macOS, and `--fs path=`, `--share-ro` and
`--share-rw` on either Linux backend.

```text
booting Image with 512 MiB ...
hvi: --net-tap tap0: no /dev/net/tun on macOS; use --net-gateway
```

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
| `pause` | Holds the host I/O threads, then parks every started vCPU. If both have not happened within 2 s in all, the pause is undone and the reply is `timeout`. |
| `resume` | Releases the vCPUs, then the I/O threads. |
| `status` | Replies with `state` (`running`, `paused`, `fenced` or `stopping`), `vcpus` started and `vcpus_parked`. |
| `stop` | Ends the run, paused or not. `boot` returns `Requested`. |
| `checkpoint` | Captures the VM into a new bundle directory below `--checkpoint-root`, then resumes it or fences it. See [checkpoint.md](checkpoint.md#taking-a-checkpoint). |

`pause` and `resume` are idempotent. A pause outlives the connection that asked
for it. Apart from `checkpoint`, no reply takes longer than about 2 s, so give a
client a reply timeout of at least 3 s. A `checkpoint` replies once its bundle
is written, which takes longer the more guest RAM is in use. A client that gives up on a `pause` before its reply cannot
tell whether the VM paused: it should reconnect and ask `status`, or send
`resume`, which is harmless on a running VM. A refusal is `{"v":1,"ok":false,"code":...,"error":...}`. Branch on
`code`; `error` is for a person. The codes are listed in
`src/checkpoint/control.rs`. The socket has no authentication: anyone who can
connect to it can pause or stop the VM, so put it in a directory only its owner
can reach.

`--profile-out` writes the machine profile: what the guest was built against,
such as the CPU's ID registers, the counter frequency, the interrupt
controller, RAM, devices and the hvi commit. Two hosts compare profiles before
a guest moves between them. A profile matches no other when a value in it could
not be read, or when its hvi does not know its commit or was built with
uncommitted changes. The file is created before confinement. On Linux it
is written before the guest starts. On macOS the boot vCPU writes it just
before the guest's first instruction, since only that thread can read
`MIDR_EL1`, so a reader that finds it empty waits or asks the socket.

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
| `RUST_BACKTRACE` | all | A value other than `0` prints a backtrace after a panic's line, and `full` prints every frame. Under the seccomp sandbox on Linux hvi prints none. |

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
| hvi panics | `[hvi] <thread>: panicked (<message>) at <file:line:column>`, and the process ends by `SIGABRT`. |
| `SIGTERM`, `SIGINT` or `SIGHUP` | `guest stopped: Requested`, or `hvi: <what failed>` if the run failed, and then the process ends by that signal. |
| An x86-64 guest halts, or powers off without ACPI | The run does not end. |

A vCPU fails on an exit hvi does not service or on an error from the hypervisor.
On macOS, an access to an address no device answers is such an exit. The line
names the vCPU and the failure.

A panic anywhere in hvi ends the process by `SIGABRT`, which a shell reports as
status 134, with a core dump where the system writes one. Before the abort, hvi
stops the vCPUs and writes a `vmm.stop` record to the ledger, with reason
`failed` and the line's text. It waits at most one second in all for the vCPUs
to exit and for the record to be written. On a vCPU thread the line adds the
vCPU's program counter and, once the vCPU has run, its last exit. A backtrace
follows the line when `RUST_BACKTRACE` asks for one (see [Environment
variables](#environment-variables)). Under the seccomp sandbox on Linux hvi
prints none, since resolving one opens the binary and the filters refuse that.
Under the macOS sandbox the frames stay unresolved for the same reason.

An x86-64 guest powers off through ACPI, so a kernel without ACPI cannot power
off; see [guest-images.md](guest-images.md). `reboot -f` ends the run either
way, as `SystemReset`.

**hvi never reboots a guest.** `SystemReset` ends the process exactly as
`SystemOff` does. Nothing loops around `hvi::boot`. An integration that wants a
reboot calls it again, within the limits the sandbox sets, which
[embedding.md](embedding.md#stopping-a-run-from-the-host) describes.

### Signals and the terminal

`SIGTERM`, `SIGINT` and `SIGHUP` stop the run. hvi stops the vCPUs, joins its
threads, closes the ledger and restores the terminal, and then ends by the
signal it received, so a shell reports status 128 plus the signal number and a
service manager sees the process end by that signal. The guest is not asked to
shut down first. If the stop does not complete, another of these signals, one
second or more after the first, restores the terminal and ends hvi at once by
that signal, and the ledger loses the records not written yet. One that arrives
sooner, such as a copy a wrapper script forwards, has no effect. A signal hvi
starts with ignored, such as `SIGHUP` under `nohup`, stays ignored.

In raw mode the terminal sends Ctrl-C to the guest as a byte, so `SIGINT`
reaches hvi only from `kill` or when stdin is not a TTY.

hvi uses one signal internally, `SIGRTMIN` on Linux and `SIGUSR1` on macOS. It
breaks a vCPU out of `KVM_RUN` on the Linux backends and ends the console
reader's read of stdin when the run stops. It is not a control interface.

hvi puts the terminal into raw mode when stdin is a TTY and restores it when the
boot returns. The restore discards input the guest did not read. hvi also
restores the terminal when any other signal ends the process, such as a crash,
an abort, a syscall the seccomp filter refuses or `SIGQUIT`. The process then
ends by that signal, with a core dump where that signal's default makes one and
the core size limit (`ulimit -c`) allows it.

On Linux the core dump leaves out guest RAM. It can still hold data a device
copied out of guest RAM into hvi's own buffers, such as disk blocks and network
frames. On macOS a binary signed without `get-task-allow` writes no core dump,
and `hvi.entitlements` does not grant that entitlement. A build that carries it
writes a core dump holding all of guest RAM when it runs with `--no-sandbox` or
crashes before it enters the sandbox. Once hvi has entered the sandbox, the
sandbox refuses the write. A crash still leaves a report with each thread's
stack in `~/Library/Logs/DiagnosticReports`, or in
`/Library/Logs/DiagnosticReports` for hvi run as root.

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
[hvi] virtio-blk[0]: /path/to/disk.img (rw, serial disk0)
[hvi] virtio-net: built-in stub stack (guest 10.0.2.15, gw 10.0.2.2, DHCP; no egress, no inbound)
[hvi] open-file limit: 1048576
[hvi] virtio-fs[0]: /path/to/share as "code" (read-only)
[hvi] event ledger: /path/to/ledger.ndjson
[hvi] seatbelt sandbox: on (deny default)
```

`[hvi] open-file limit:` appears only on macOS, and only when at least one
share is configured, because the limit is raised while the first share is set
up.

On a clean stop, macOS reports each share's peak handle count:

```text
[hvi] virtio-fs[0]: peak 1 of 1048448 guest handles
guest stopped: SystemOff
```

## vCPU limits

hvi has three caps. On Linux/arm64 a vGICv2 host takes at most 8 vCPUs:

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

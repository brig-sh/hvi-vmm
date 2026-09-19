# Observing a guest

hvi is the other end of every virtio request a guest makes, so it can record
what a guest does without anything inside the guest cooperating. Three
artefacts come out of that position, and they answer different questions.

| Artefact | Flag | What it is |
| --- | --- | --- |
| Event ledger | `--events <path>` | Structured NDJSON records of device activity and the run's lifecycle. |
| I/O trace | `--trace-io <path>` | One raw line per block request and per network frame. |
| Memory dump | `--dump-memory <path>` | Guest RAM, written with the VM parked. |

CAUTION: All three contain the guest's workload data. A memory dump contains
whatever was in guest RAM, which includes keys, tokens and plaintext. Treat
these files with the same care as the workload itself. Write them somewhere
only you can read, and delete them when the investigation ends.

## The event ledger

```sh
hvi boot --kernel <Image> --disk disk.img --net-stub --events ledger.ndjson
```

One compact JSON object per line:

```json
{"sandbox_id":"hvi","ts":1788992154877294000,"provenance":"boundary","source":"block","payload":{"disk":"disk0","lba":0,"len":4096,"rw":"r"}}
{"sandbox_id":"hvi","ts":1788992154919811000,"provenance":"boundary","source":"net","payload":{"five_tuple":{"proto":17,"src_ip":"10.0.2.15","src_port":43098,"dst_ip":"10.0.2.3","dst_port":53},"direction":"egress","guest_initiated":true,"bytes":37,"dns":"example.com"}}
```

The envelope is `sandbox_id`, `ts`, `provenance`, `source`, `payload`. Its
wire shape is pinned by tests. `--sandbox-id` sets the first field.

The VMM also records the run's lifecycle, with `provenance` `vmm`:

| `source` | When | `payload` |
| --- | --- | --- |
| `vmm.start` | The vCPU threads are about to start. | `arch`, `vcpus`, `mem_bytes`, `confined`, `core_version` |
| `vmm.vcpu_started` | A vCPU entered its run loop. | `vcpu` |
| `vmm.dropped` | `block` or `net` records were dropped just before it, because the ledger's buffer was full. | `records` |
| `vmm.stop` | The run has stopped. | `reason`, `signal`, `error`, `dropped` |

`confined` says whether the confinement is on, and `vcpu` is the vCPU id.
`reason` is `system_off`, `system_reset`, `requested` or `failed`. `signal`
names the stop signal, `SIGTERM`, `SIGINT` or `SIGHUP`, when it asked first and
the run stopped on its request, and `error` is the error `boot` returns when the
run failed. `records` counts the `block` and `net` records dropped since the
previous `vmm.dropped` record. `dropped` counts every `block` and `net` record
the run left out because the ledger's buffer was full, and appears only when
there were any. A boot that fails before it writes `vmm.start` writes no
`vmm.stop` either. A record's `ts` is when the VMM added it to the ledger's
buffer, so a `vmm.vcpu_started` record can follow records the vCPU caused after
it entered its run loop.

Under hvi's own binary, a panic stops the vCPUs and writes `vmm.stop` before the
process aborts, with reason `failed` and the panic's report as `error`. Every
`block` and `net` record comes from a vCPU thread, and the VMM waits up to half
a second for the vCPUs to exit before it writes the record. So the record
follows every record the vCPUs caused, unless a vCPU has not exited by then,
such as one a plugin's pause holds. The VMM writes a `vmm.vcpu_started` record a
moment after the vCPU starts, so a vCPU that starts just before a panic can have
none.

On KVM every vCPU enters its run loop at the start, and one the guest has not
brought up yet waits inside the hypervisor. On macOS a secondary vCPU enters its
run loop when the guest brings it up.

```json
{"sandbox_id":"hvi","ts":1791672885321504305,"provenance":"vmm","source":"vmm.start","payload":{"arch":"x86_64","vcpus":2,"mem_bytes":268435456,"confined":true,"core_version":"0.1.0+15.gabc1234"}}
{"sandbox_id":"hvi","ts":1791672885321619047,"provenance":"vmm","source":"vmm.vcpu_started","payload":{"vcpu":0}}
{"sandbox_id":"hvi","ts":1791672885321654412,"provenance":"vmm","source":"vmm.vcpu_started","payload":{"vcpu":1}}
{"sandbox_id":"hvi","ts":1791672887494077791,"provenance":"vmm","source":"vmm.stop","payload":{"reason":"system_reset"}}
```

What the ledger is not:

- **Not lossless.** A VMM that is killed, crashes or panics can lose the records
  not written yet, and a write that stalls can make the ledger drop `block` and
  `net` records. [When a record reaches the
  file](#when-a-record-reaches-the-file) says what each case loses.
- **Not tamper-proof.** It is an ordinary file written by the VMM process.
  Nothing signs, chains or seals it.
- **Not private, and its lock is advisory.** The file is created under the
  process's umask, which often lets every local user read it. It records what
  the guest did: block offsets, packet addresses and the names the guest
  resolves. hvi locks the file while it writes it, so a second ledger at the
  path is refused. Any process that can open the file can hold that lock too,
  and so refuse the next run at that path. Keep the ledger where only its
  trusted readers can open it, such as a directory of mode 0750 with a group for
  them.
- **Not monotonic.** `ts` is host wall-clock nanoseconds. It can move
  backwards when the host clock does.
- **Not aggregated.** `net` records are per packet, and egress only. See
  [networking.md](networking.md#what-the-ledger-records).

A boot with no block device and no network traffic produces the lifecycle
records alone.

### When a record reaches the file

A thread of hvi's own writes the file. The call that adds `vmm.start`,
`vmm.stop` or a plugin's record waits for that thread and returns once the
record has reached the kernel, so the record survives the death of the process.
It waits up to one second, or 100 ms for a plugin's record, and then returns
with the record still buffered. The `block`, `net` and `vmm.vcpu_started`
records do not wait. The writer takes them at once when it is idle. After each
write it waits 1 ms for more records before it goes idle, so the records of a
burst are written together, within about 1 ms. A write in progress delays them
until it ends.

A run loses nothing when the guest stops it, a vCPU fails, or a stop is
requested, by `SIGTERM` for example. The exceptions are a write at the stop that
stalls for one second or more, and a vCPU left running at the stop, whose later
records are discarded. A VMM ended by `SIGKILL`, a crash or a syscall the
seccomp filter refuses loses the records not written yet. Under hvi's own
binary, a panic loses the records not written within one second of it. A panic
before `vmm.start` loses every record not written yet. A repeated stop signal
that arrives one second or more after the first ends the process at once and
loses the records not written yet. One that arrives sooner has no effect.

Once a stalled write lets the buffer fill to 4 MiB, the ledger drops later
`block` and `net` records. A `vmm.dropped` record after each run of drops says
how many, and `dropped` in `vmm.stop` counts them all. The VMM prints a line on
stderr when it starts to drop them. It prints the number dropped once a `block`
or `net` record fits after one second with no drop, or at the stop.

A write that fails is tried again every 100 ms, and the records after it wait
for it. While writes fail, a call that adds `vmm.start` or a plugin's record
returns at once instead of waiting. Once the ledger is closed, the writer tries
for one more second and then drops what it holds. A process that ends while a
write still fails can leave a partial last line, which is the part the failed
write put in the file. A write the writer gives up can leave one too. A write
that blocks, as on a hung network file system, holds the writer and the file's
lock until it returns.

## The I/O trace

```sh
hvi boot --kernel <Image> --disk disk.img --net-stub --trace-io io.trace
```

```text
blk r disk=0x12704793 sector=0 len=4096
blk w disk=0x12704793 sector=0 len=4096
net tx len=42
net rx len=42
```

This is the raw counterpart to the ledger. It carries every layer-2 frame in
both directions, unparsed, where the ledger's `net` records cover only IPv4
TCP, UDP and ICMP leaving the guest.

The trace buffers on the device path and flushes at a vCPU safe point, so a VMM
that is killed, or that panics, loses only what had not reached the last safe
point. After a panic, that can include the request that panicked.

## Memory dumps

```sh
hvi boot --kernel <Image> --dump-memory guest.ram --dump-after 30
```

The dump is triggered by `--dump-after <secs>`, or by pressing **Ctrl-]** on
the console. That key is intercepted only when a plugin is attached, and only
`--dump-memory` acts on it: with `--trace-io` alone it is swallowed and
nothing happens. hvi parks every vCPU, writes the image, and resumes:

```text
[hvi] dumped 536870912 bytes of guest RAM to guest.ram
```

The guest is stopped for the whole write. That is deliberate. A dump taken
while the guest runs is torn, and a torn image is worse than a slow one
because nothing about it says so.

### The dump needs somewhere it is allowed to write

The dump file is created **at dump time**, after the VMM has confined itself.
The default confinement denies it:

```text
[hvi] dump to /tmp/guest.ram failed: Operation not permitted (os error 1)
```

On macOS two destinations work:

- A path inside a writable `--fs path=` directory, which the Seatbelt profile grants.
- Anywhere, with `--no-sandbox`.

```sh
# Keeps confinement on.
hvi boot --kernel <Image> --fs tag=out,path=./dumps \
         --dump-memory ./dumps/guest.ram --dump-after 30
```

On Linux the seccomp filters refuse every open after confinement, whatever the
path, so only `--no-sandbox` works. A glibc build reports the error above, and a
musl build ends the process by `SIGSYS`.

`--events` and `--trace-io` do not have this problem. Their files are opened
before confinement.

`--dump-after` also needs the guest to still be running when the timer fires.
A guest that powers off after five seconds produces no dump from
`--dump-after 30`, and no error.

### What a dump is

Raw guest-physical memory, region after region, in ascending address order.
Nothing else is written: no register state, no device state, no virtqueue
state.

It is an image you can inspect. **It is not a checkpoint.** Nothing can
restore a VM from it.

Guest RAM is not always one span. On arm64 it is one region. On x86-64 it is
one region up to 3328 MiB of guest RAM and two above that, because RAM stops
at the MMIO hole and resumes at 4 GiB. A tool that assumes one region reads
nothing above the hole and looks like it found an empty guest.

## Tracing environment variables

| Variable | Effect |
| --- | --- |
| `HVI_BLK_TRACE=1` | Log every virtio-blk request to stderr. Off by default: one synchronous write per request. |
| `HVI_X86_TRACE=1` | x86 backend: print the guest's CPUID leaf 1 and `0x4000_0001` at boot, log the first 80 I/O and MMIO exits of each vCPU, dump registers on shutdown, and kick vcpu0 four times at two-second intervals so a stuck guest still dumps its registers. |
| `HVI_SECCOMP=log` | Linux: install the allowlists but let an off-list syscall run and be recorded. This turns enforcement off. See [security.md](security.md). |

## Writing your own tool

Everything above attaches through the same seam another crate can use. A tool
can read guest RAM, read the boot vCPU's registers, park the VM, subscribe to
device I/O, and put its own records in the same ledger.

Start at [plugins.md](plugins.md), and read
[`examples/watch_guest.rs`](../examples/watch_guest.rs), which is a complete
extension in one file.

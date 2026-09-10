# Observing a guest

hvi is the other end of every virtio request a guest makes, so it can record
what a guest does without anything inside the guest cooperating. Three
artefacts come out of that position, and they answer different questions.

| Artefact | Flag | What it is |
| --- | --- | --- |
| Event ledger | `--events <path>` | Structured NDJSON records of device activity. |
| I/O trace | `--trace-io <path>` | One raw line per block request and per network frame. |
| Memory dump | `--dump-memory <path>` | Guest RAM, written with the VM parked. |

CAUTION: All three contain the guest's workload data. A memory dump contains
whatever was in guest RAM, which includes keys, tokens and plaintext. Treat
these files with the same care as the workload itself. Write them somewhere
only you can read, and delete them when the investigation ends.

## The event ledger

```sh
hvi boot --kernel <Image> --disk disk.img --net --events ledger.ndjson
```

One compact JSON object per line:

```json
{"sandbox_id":"hvi","ts":1788992154877294000,"provenance":"boundary","source":"block","payload":{"lba":0,"len":4096,"rw":"r"}}
{"sandbox_id":"hvi","ts":1788992154919811000,"provenance":"boundary","source":"net","payload":{"five_tuple":{"proto":17,"src_ip":"10.0.2.15","src_port":43098,"dst_ip":"10.0.2.3","dst_port":53},"direction":"egress","guest_initiated":true,"bytes":37,"dns":"example.com"}}
```

The envelope is `sandbox_id`, `ts`, `provenance`, `source`, `payload`. Its
wire shape is pinned by tests. `--sandbox-id` sets the first field.

What the ledger is not:

- **Not lossless.** Records are buffered and drained when a new event arrives
  more than 100 ms after the last drain. That is a cadence of continued
  traffic, not of wall time. Events emitted just before a guest goes quiet
  stay in the buffer until something else is emitted or the emitter is
  dropped. A killed VMM loses the tail.
- **Not tamper-proof.** It is an ordinary file written by the VMM process.
  Nothing signs, chains or seals it.
- **Not monotonic.** `ts` is host wall-clock nanoseconds. It can move
  backwards when the host clock does.
- **Not aggregated.** `net` records are per packet, and egress only. See
  [networking.md](networking.md#what-the-ledger-records).

A boot with no block device and no network traffic produces an empty file.
That is the normal result, not a failure.

## The I/O trace

```sh
hvi boot --kernel <Image> --disk disk.img --net --trace-io io.trace
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

The trace buffers on the device path and flushes at a vCPU safe point, so a
killed VMM loses only what had not reached the last safe point.

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

Two destinations work:

- A path inside a `--share-rw` directory, which the Seatbelt profile grants.
- Anywhere, with `--no-sandbox`.

```sh
# Keeps confinement on.
hvi boot --kernel <Image> --share-rw ./dumps out \
         --dump-memory ./dumps/guest.ram --dump-after 30
```

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
| `HVI_X86_TRACE=1` | x86 backend: log the first 80 I/O and MMIO exits of each vCPU, dump registers on shutdown, and kick cpu0 four times at two-second intervals so a stuck guest still dumps its registers. |
| `HVI_SECCOMP=log` | Linux: install the allowlists but let an off-list syscall run and be recorded. This turns enforcement off. See [security.md](security.md). |

## Writing your own tool

Everything above attaches through the same seam another crate can use. A tool
can read guest RAM, read the boot vCPU's registers, park the VM, subscribe to
device I/O, and put its own records in the same ledger.

Start at [plugins.md](plugins.md), and read
[`examples/watch_guest.rs`](../examples/watch_guest.rs), which is a complete
extension in one file.

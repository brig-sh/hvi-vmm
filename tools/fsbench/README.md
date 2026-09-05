# fsbench -- virtio-fs benchmarks in a real guest

The unit tests in `src/virtio_fs.rs` drive the FUSE handlers directly: no
guest, no virtqueue, no VM exits. That is the right shape for correctness, and
it is blind to everything that decides how fast the filesystem actually feels.
A change that made small writes 2.6x slower passed every one of them.

This boots a guest, mounts one share, runs a workload, and prints how long each
phase took.

## Running

Needs a static aarch64 busybox for the guest. hull's `container-initrd` carries
one:

```sh
mkdir -p /tmp/ci && (cd /tmp/ci && cpio -idm < /path/to/container-initrd)
```

Then, from the repo root:

```sh
cargo build --release
codesign --sign - --entitlements hvi.entitlements --force \
         --options runtime target/release/hvi

tools/fsbench/run.sh \
    --hvi target/release/hvi \
    --kernel /path/to/Image \
    --busybox /tmp/ci/busybox \
    --tree /path/to/a/copy/of/some/tree \
    --workload walk
```

**A rebuild invalidates the code signature**, and an unsigned binary cannot
create a VM. Re-sign after every `cargo build`.

**`--tree` is shared read-write and is written to.** Point it at a copy.

## Workloads

| `--workload` | what it measures |
| --- | --- |
| `walk` | metadata: `find`, `ls -lR`, a repeat walk, `stat` of every file, small-file create and unlink |
| `write` | writes at 4k / 64k / 1M block sizes, then a sequential read |
| `concurrent` | the same walk split across 4 and 8 processes, plus 4 concurrent read streams |

Run `walk` and `concurrent` together, never one instead of the other: a
single-threaded walk cannot exercise queue depth, so it cannot tell you whether
a dispatch change helped or hurt. The `write` sweep is equally load-bearing --
per-request cost only shows up at a small block size, and the data path only at
a large one.

`--cache auto|always|none` selects the share's cache policy. `none` is the
useful one when attributing a change: it stops the guest's own caching from
hiding what the device is doing.

## Comparing two builds

Run each twice, alternating, so host cache warmth does not favour whichever
went second:

```sh
for i in 1 2; do
    tools/fsbench/run.sh --hvi ./hvi-before ... --workload walk
    tools/fsbench/run.sh --hvi ./hvi-after  ... --workload walk
done
```

Numbers move by 10-20% run to run; anything smaller than that is not a result.

`write_bs_4k` is worse than noisy, it is **bimodal**: it lands either around
0.85s or around 2.1s, with nothing in between, and a run of three identical
results says nothing about the fourth. This predates the inline-budget work
(the pre-worker build does it too, 1.54 / 0.88 / 0.88 / 0.89), so it is a
property of the workload rather than of the dispatch path, and its cause is
still open. Take at least five samples of that line and compare the *fast*
mode, or you will attribute a mode flip to whatever you happened to change --
a sweep of FS_INLINE_BUDGET over 1, 4 and 8 looked like a clear win for 4
until the sixth sample of 4 came back at 2.03s.

## Interpreting

Host-side cost is usually not the limit. Measured on an M-series host over
APFS, a 4 KiB write costs ~7us of host time inside a ~23us request, so most of
it is the VM exit and the dispatch around it. Two consequences worth keeping in
mind before optimising:

- Making each request cheaper moves the guest very little. Making the guest
  send *fewer* requests -- attribute and entry timeouts, page-cache retention
  -- moves it enormously.
- A read-only share already had long timeouts before the cache policy existed,
  so it will not show a change that only affects writable shares. Benchmark
  `--share-rw`, which is what a development workload uses.

# Measuring virtio-fs

The unit tests in `src/virtio_fs.rs` drive the FUSE handlers directly: no
guest, no virtqueue, no VM exits. That is the right shape for correctness, and
it is blind to everything that decides how fast the filesystem feels. A change
that made small writes 2.6 times slower passed every one of them.

Two things close that gap, and they measure different quantities.

| | What it measures | Where |
| --- | --- | --- |
| [`tools/fsbench`](../tools/fsbench/README.md) | End-to-end time in a real guest. | Your machine, macOS. |
| `tools/perf-gate.sh` | Host operations per round, and wall time, against the merge base. | CI, and your machine. |

Host-side work is usually not the limit. Measured on an M-series host over
APFS, a 4 KiB write cost about 7 microseconds of host time inside a request of
about 23 microseconds, so most of it was the VM exit and the dispatch around
it. Two consequences follow, and both are about the guest rather than the
host:

- Making each request cheaper moves the guest very little.
- Making the guest send **fewer** requests, through attribute and entry
  timeouts and page-cache retention, moves it a great deal.

Those figures are a historical measurement on one host and one filesystem.
They are not a general performance claim.

## fsbench

It boots a guest, mounts one share, runs a workload, and prints how long each
phase took.

### What you need

- A static aarch64 busybox for the guest. hull's `container-initrd` carries
  one:

  ```sh
  mkdir -p /tmp/ci && (cd /tmp/ci && cpio -idm < /path/to/container-initrd)
  ```

- A kernel `Image`. See [first-boot.md](first-boot.md#3-get-a-kernel).
- A directory tree to work on.

### Running it

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

CAUTION: `--tree` is shared **read-write** and the workloads write to it.
Point it at a copy you can afford to lose, never at a working tree or
anything you have not backed up.

Re-sign after every `cargo build`. A rebuilt binary is unsigned and cannot
create a VM.

`--mem-mib` and `--cpus` size the guest, 2048 MiB and 2 vCPUs by default.
`--timeout <secs>` (default 300) kills the VM if the workload has not
finished, which counts as a failed run. `--cache auto|always|none` selects the
share's cache policy.

### Workloads

| `--workload` | What it measures |
| --- | --- |
| `walk` | Metadata: `find`, `ls -lR`, a repeat walk, `stat` of every file, small-file create and unlink. |
| `write` | Writes at 4k, 64k and 1M block sizes, then a sequential read. |
| `concurrent` | The same walk split across 4 and 8 processes, plus 4 concurrent read streams. |

Run `walk` and `concurrent` together, never one instead of the other. A
single-threaded walk cannot exercise queue depth, so it cannot tell you
whether a dispatch change helped or hurt. The `write` sweep matters the same
way: per-request cost only shows at a small block size, and the data path only
at a large one.

`cache=none` is the useful policy when attributing a change, because it stops
the guest's own caching from hiding what the device is doing.

Benchmark `--share-rw`. A read-only share already had long timeouts before the
cache policy existed, so it will not show a change that only affects writable
shares.

## Comparing two builds

Run each twice, alternating, so host cache warmth does not favour whichever
went second:

```sh
for i in 1 2; do
    tools/fsbench/run.sh --hvi ./hvi-before ... --workload walk
    tools/fsbench/run.sh --hvi ./hvi-after  ... --workload walk
done
```

Numbers move by 10 to 20 percent run to run. Anything smaller is not a result.

### `write_bs_4k` is bimodal

It is worse than noisy. It lands either around 0.85 s or around 2.1 s, with
nothing in between, and a run of three identical results says nothing about
the fourth.

This predates the inline-budget work. The pre-worker build does it too
(1.54 / 0.88 / 0.88 / 0.89), so it is a property of the workload rather than
of the dispatch path. Its cause is still open.

Take at least five samples of that line and compare the **fast** mode, or you
will attribute a mode flip to whatever you happened to change. A sweep of
`FS_INLINE_BUDGET`, the per-notify inline drain budget and a constant in
`src/machine_macos.rs`, over 1, 4 and 8 looked like a clear win for 4 until
the sixth sample of 4 came back at 2.03 s.

That record is why this page does not compare two numbers and call it a
result.

## The host-operation count

```sh
cargo test --release -- --ignored --nocapture bench_metadata_workload
```

This reports host-side microseconds and host operations per request, with no
guest at all. A unit test pins the count exactly: 2 host operations per file
and 36 per listing.

An operation count is a different quantity from end-to-end guest latency.
It is deterministic and it is not a time, so it catches a change that adds
work even when the clock does not notice. It cannot tell you the guest got
faster.

## The performance gate

`tools/perf-gate.sh` builds the branch and its merge base in a throwaway git
worktree on the same machine in the same run, then compares:

- **Host operations per round.** It fails when the count goes **up**. A
  decrease is reported and passes.
- **Wall time.** It fails when the branch is more than 1.5 times slower.

Overrides: `--base <ref>`, `--samples <n>`, `--limit <ratio>`, or
`PERF_GATE_BASE`, `PERF_GATE_SAMPLES`, `PERF_GATE_LIMIT`. The defaults are
`origin/main`, five samples per side and 1.5.

CI runs it on the Apple-silicon runner for same-repo pull requests only, with
`fetch-depth: 0`, because a shallow clone has no merge base. Locally:

```sh
tools/gates.sh --with-perf
```

It builds the merge base as well as the branch, so it costs more than every
other check together.

## Reporting a result

State the host, the filesystem, the workload, the cache policy, the number of
samples and the spread. A single sample is not a measurement, and two numbers
next to each other are not a cause.

## See also

- [storage-and-sharing.md](storage-and-sharing.md) for what the cache
  policies do.
- [testing.md](testing.md) for the rest of CI.

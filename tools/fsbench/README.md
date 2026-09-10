# fsbench

Boots a guest, mounts one virtio-fs share, runs a workload, and prints how
long each phase took. macOS only, because that is where the device compiles.

The unit tests in `src/virtio_fs.rs` drive the FUSE handlers directly, with no
guest and no virtqueue. That is right for correctness and blind to speed: a
change that made small writes 2.6 times slower passed every one of them. This
is what sees that.

**[docs/benchmarking.md](../../docs/benchmarking.md) is the guide**: what to
measure, how to compare two builds, the known bimodal result, and the CI
performance gate. Read it before drawing a conclusion from a number here.

## Running it

Needs a static aarch64 busybox. hull's `container-initrd` carries one:

```sh
mkdir -p /tmp/ci && (cd /tmp/ci && cpio -idm < /path/to/container-initrd)
```

Then, from the repository root:

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

CAUTION: `--tree` is shared read-write and the workloads write to it. Point it
at a copy.

A rebuild leaves the binary unsigned, and an unsigned binary cannot create a
VM. Re-sign after every `cargo build`.

## Flags

| Flag | Default | Effect |
| --- | --- | --- |
| `--hvi <path>` | required | The binary to measure. |
| `--kernel <Image>` | required | arm64 kernel. |
| `--busybox <path>` | required | Static aarch64 busybox for the guest. |
| `--tree <dir>` | required | The tree to work on. Written to. |
| `--workload <name>` | required | `walk`, `write` or `concurrent`. |
| `--cache <policy>` | `auto` | `auto`, `always` or `none`. |
| `--mem-mib <N>` | 2048 | Guest RAM. |
| `--cpus <N>` | 2 | vCPUs. |
| `--timeout <secs>` | 300 | Kills the VM if the workload has not finished, which counts as a failed run. |

| Workload | What it measures |
| --- | --- |
| `walk` | Metadata: `find`, `ls -lR`, a repeat walk, `stat` of every file, small-file create and unlink. |
| `write` | Writes at 4k, 64k and 1M block sizes, then a sequential read. |
| `concurrent` | The same walk across 4 and 8 processes, plus 4 concurrent read streams. |

Run `walk` and `concurrent` together. A single-threaded walk cannot exercise
queue depth, so on its own it cannot tell you whether a dispatch change helped.

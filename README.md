# hvi

[![CI](https://github.com/brig-sh/hvi-vmm/actions/workflows/main-build-and-verify.yml/badge.svg)](https://github.com/brig-sh/hvi-vmm/actions/workflows/main-build-and-verify.yml)
[![Coverage](https://codecov.io/gh/brig-sh/hvi-vmm/graph/badge.svg)](https://codecov.io/gh/brig-sh/hvi-vmm)
[![Rust](https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrig-sh%2Fhvi-vmm%2Fmain%2Frust-toolchain.toml&query=%24.toolchain.channel&label=rust&color=orange)](rust-toolchain.toml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A small microVMM for **Linux guests** (arm64 and x86-64), and the substrate
brig runs its sandboxes on, with three host backends behind one CLI:

| Guest | Host | Backend | Status |
| --- | --- | --- | --- |
| aarch64 | macOS / Apple silicon | Apple **Hypervisor.framework** (`applevisor`) | boots + benchmarked; virtio-fs shares; live in CI |
| aarch64 | Linux | **KVM** (`kvm-ioctls`) | boots to userspace + SMP (vGICv3 or vGICv2) + tap networking; live in CI |
| x86-64 | Linux | **KVM** | boots to userspace + virtio-blk/net + SMP; live in CI on a KVM host |

See [`docs/architecture.md`](docs/architecture.md) for how the pieces fit
together (backends, boot protocols, device model, the extension seam).

hvi owns guest RAM and the vCPUs, and it is its own virtio backend, so a
sandbox gets the same device model on macOS and on Linux. That is what lets
brig run the same workload on either host without the guest noticing.

## Layout

```
src/
  main.rs                     CLI (boot | dump-fdt | smoke | sandbox-selftest | seccomp-selftest | version)
  config.rs                   BootConfig / Stop / FsShare / CachePolicy (shared by all backends)
  machine_macos.rs            Hypervisor.framework backend (macOS + aarch64)
  machine_linux.rs            KVM backend (Linux + aarch64)
  machine_x86.rs              KVM backend (Linux + x86-64)
  boot.rs layout.rs fdt.rs    arm64 Image parse, guest RAM layout, devicetree
  boot_x86.rs layout_x86.rs   x86 bzImage + boot_params + e820, guest memory map
  mptable.rs                  x86 Intel MP table
  uart16550.rs rtc_cmos.rs    x86 COM1 (vm-superio Serial, level-triggered) and MC146818 CMOS RTC
  pl011.rs esr.rs             PL011 UART and ESR_EL2 decode (arm64)
  guestmem.rs sharedmem.rs    Send+Sync guest-RAM accessor; memfd / POSIX-shm backing for it
  virtio.rs                   virtio-mmio transport, Queue, virtio-blk
  virtio_net.rs tap.rs        virtio-net: user-space stack, gvisor-tap gateway relay, Linux tap
  virtio_vsock.rs             virtio-vsock agent bridge
  virtio_fs.rs                virtio-fs directory shares (macOS)
  fdlimit.rs                  raise RLIMIT_NOFILE at startup (aarch64, both hosts; virtio-fs spends it)
  sandbox.rs seccomp.rs       Seatbelt profile (macOS) and seccomp-bpf filters (Linux), with selftests
  quiesce.rs sync.rs          vCPU park/resume; taking a lock whose holder panicked
  plugin.rs                   the extension seam (Plugin / VmHandle / CpuHandle / IoSink)
  plugins.rs                  tools built on it: memory dump, I/O trace
  events.rs                   the event log written by `--events`
  smoke.rs                    M0 hvf smoke test (macOS only), plus `--shm` and its child `smoke-shm-verify`
  used_ring_litmus.rs         concurrency litmus for the used-ring publish (#[ignore], weekly in CI)
resources/seccomp/            one seccompiler JSON allowlist per architecture, plus a README
docs/                         architecture + writing a tool
tools/
  tidy.sh                     fmt, comment reflow (pinned nightly), clippy, rustdoc
  gates.sh                    the CI checks a developer machine can run, in one command
  perf-gate.sh                virtio-fs performance gate: branch against its merge base
  fsbench/                    virtio-fs benchmarks in a real guest (walk / write / concurrent)
  mk-initramfs.py             Alpine arm64 initramfs for a boot test, no root or cpio needed
pins.env                      the nightly rustfmt the comment reflow runs on
deny.toml                     cargo-deny policy (advisories, licences, duplicates, sources)
LICENSE NOTICE                Apache-2.0; credit for the Firecracker-derived parts
SECURITY.md CODE_OF_CONDUCT.md AI_POLICY.md CONTRIBUTING.md
```

The three backends share every module except `machine_*`/`smoke`; the split is
what makes each port small (the virtio devices and the ledger are hypervisor-
and arch-neutral: they need only a guest-RAM accessor). The arch-specific
surface is the boot protocol (`boot*`/`layout*`/`fdt`/`mptable`).

Feature bits, device ids, the virtio-mmio register map and the
`virtio_net_hdr_v1` layout come from `virtio-bindings` (bindgen output from
the kernel headers). The vsock op codes, packet header and CIDs are still
hvi's own; that crate has no vsock module. The x86 COM1 is `vm-superio`'s
16550 behind a level-triggered wrapper; PL011 and the CMOS RTC are hvi's. The
Linux backends are on `kvm-ioctls` 0.25 and `kvm-bindings` 0.14.

## Build

```sh
# macOS / Apple silicon (needs Xcode CLT):
cargo build --release
codesign --sign - --entitlements hvi.entitlements --force --options runtime target/release/hvi
#   or: ./run.sh --release boot --kernel <Image> ...   (builds, signs, runs)

# Linux (needs /dev/kvm to run), arm64 or x86-64, native:
cargo build --release

# Cross compile-check the arm64 Linux backend from an x86 host:
rustup target add aarch64-unknown-linux-gnu
cargo check --target aarch64-unknown-linux-gnu
```

## Run

```sh
hvi boot --kernel <arm64 Image | x86-64 bzImage> \
  [--initramfs <cpio>] [--disk <raw.img>] [--mem-mib N] [--cpus N] [--cmdline <str>] \
  [--share-ro <host-directory> <mount-tag> [cache=auto|always|none]]... \
  [--share-rw <host-directory> <mount-tag> [cache=auto|always|none]]... \
  [--fs-uid <uid>] [--fs-gid <gid>] \
  [--net | --net-gateway <gvisor-tap .qemu socket> | --net-tap <dev>] [--net-mac <aa:bb:..>] \
  [--agent-sock <unix socket>] \
  [--events <ledger.ndjson>] [--sandbox-id <id>] [--no-sandbox] \
  [--dump-memory <path> [--dump-after <secs>]] [--trace-io <path>]

hvi dump-fdt --kernel <Image> [--initramfs <cpio>] [--mem-mib N] [--cmdline <str>] [--out fdt.dtb]
                                                 # pre-boot pipeline, no hypervisor (arm64); the
                                                 # extra flags change the layout the DTB describes
hvi smoke [--shm]                                # macOS-only M0 hvf test; --shm over shared guest RAM
hvi smoke-shm-verify <shm-name> <hex>            # child half of `smoke --shm`; not for direct use
hvi sandbox-selftest                             # macOS: prove the Seatbelt profile
hvi seccomp-selftest                             # Linux: prove the seccomp filters
hvi version                                      # also --version, -V: the crate version and the VMM core
```

`smoke --shm` spawns `smoke-shm-verify` itself, as a second process that
never touched the hypervisor, to read the shared guest RAM back by name; the
subcommand exists so that child has something to run.

Environment variables the binary reads:

| Variable | Effect |
| --- | --- |
| `HVI_SECCOMP=log` | Linux: keep the seccomp allowlists but log a mismatch instead of killing the process (see [Confinement](#confinement)) |
| `HVI_X86_TRACE=1` | x86 backend: log the first 80 I/O and MMIO exits of each vCPU, dump registers on a shutdown, and kick cpu0 four times at two-second intervals so a stuck guest still dumps its registers |
| `HVI_BLK_TRACE=1` | log every virtio-blk request on stderr as `[virtio-blk]` lines. Off by default: it is a synchronous write per request. The ledger records every request either way |
| `HVI_BLOCK_DEV=<dev>` | test-only: points the virtio-blk sizing test at a real block device; the CI boot-x86 job sets it to a loop device. Not read by the VMM |

Every backend logs what it set up on stderr with a `[hvi]` prefix: the vCPU
count and GIC layout, each device, the open-file limit it obtained, the
confinement it installed, and on a clean stop the peak guest handle count of
each virtio-fs export.

### Confinement

The VMM confines itself before it services any guest I/O, and it is **on by
default**: a Seatbelt profile on macOS, seccomp-bpf allowlists on Linux
(`resources/seccomp/*.json`, one per architecture). The reason is that the
virtio backends parse guest-controlled data on the same threads that run the
vCPUs, so a bug in one of them is a bug in a process that would otherwise hold
the host's full syscall surface. Two Linux filters, because the threads differ:
`vcpu` is the tight one, `vmm` covers the main thread and the host-side I/O
threads.

Each backend prints what it installed, so a host where confinement did not
happen says so. `--no-sandbox` boots unconfined, for debugging a run the
profile or the filters break; on Linux, `HVI_SECCOMP=log` keeps the same
allowlists but has the kernel record a mismatch instead of killing the
process, which is how you find a syscall a distro needs and these lists do not
have.

The selftests are the negative test: they install the filters that ship and
check both directions, what a confined thread must keep and what it must lose.
Neither needs a hypervisor or privileges, and CI runs both: the seccomp one on
the hosted x86 job, the Seatbelt one on the hosted `macos-15` job after the
signing step.

### Directory shares (virtio-fs, macOS)

Repeat `--share-ro <path> <tag>` or `--share-rw <path> <tag>` to export
unpacked host directories through independent virtio-fs devices, one mount tag
each, without block images or host FUSE mounts. The device answers the guest's
FUSE requests itself over a hiprio and a request queue; there is no DAX window
and no indirect descriptors. Tags must be unique and at most 36 bytes. The
Linux backends do not carry the device.

What a writable share supports: file and directory handles, hard links, the
atomic rename variants, timestamps, xattrs, advisory locks (OFD locks on the
host), allocation,
zero and punch, seek and copy_file_range, statx and statfs, FIFOs, tmpfiles,
and Unix sockets. A read-only share answers `EROFS` to every mutation.

How host paths are reached. Every operation resolves through the parent
directory's descriptor with `O_NOFOLLOW` on each component (`openat`,
`fstatat`, `mkdirat`, `unlinkat`, `linkat`, `renameat`, `readlinkat`,
`faccessat`, `fsetxattr` on an `O_SYMLINK` descriptor for the link's own
attributes). Containment is a property of how a descriptor was obtained, so
the device asks no path-string question afterwards, and clippy's
`disallowed-methods` refuses `fs::canonicalize` and `Path::canonicalize`
inside it. A symlink stored in a share names something in the guest's
namespace: an absolute target restarts at the export root, a relative one
continues from where it was found, a target that climbs is clamped at the
root, and a pair of links naming each other ends as `ELOOP`. Descriptors are
cached per relative path with LRU eviction and the root pinned; removals and
renames drop the cache for the path and everything beneath it, and
`cache=none` bypasses the descriptor cache entirely.

Cache policy. A trailing `cache=auto|always|none` on a share selects how much
the guest may cache. `auto` (the default) keeps attributes and entries for a
second and retains the page cache across opens, with `FUSE_AUTO_INVAL_DATA`
negotiated so a size or mtime change still drops cached pages. `none`
revalidates everything against the host, for a tree the host mutates
concurrently. `always` adds the writeback cache, which hands mtime, ctime and
size to the guest and is correct only when the guest is the sole writer.
`FUSE_PARALLEL_DIROPS` is negotiated on every share.

Ownership. Linux mode, uid, gid and device numbers are kept in a private host
xattr under `com.nofire.hvi.`, and the host inode keeps enough owner access for
the unprivileged VMM, so a mode-000 file or an arbitrary guest owner survives a
backend restart without being imposed on the host. The guest cannot read or
forge that attribute; its own xattrs are namespaced away from it. `--fs-uid`
and `--fs-gid` say which guest identity the host user's files belong to, in
both directions. The default is 0, so a workload running as root sees its
files as root; a guest running as an unprivileged user needs its own uid here
or the guest kernel refuses every write before it reaches the device.

Unix sockets. `MKNOD` with `S_IFSOCK` is served from the device: the socket
inode lives in hvi, by path, with a real creation time that `SETATTR` and
`touch` update, and never reaches the host filesystem. The guest kernel's own
socket table carries the traffic. Device nodes are still refused.

Host resources. At startup hvi raises the soft `RLIMIT_NOFILE` to the hard
limit and logs the result, because every open guest file and directory handle
is a host descriptor and macOS starts a non-terminal process at 256. An export
refuses an `OPEN` past its budget with `ENFILE`; the budget is the process
limit less a reserve of 128 for the rest of the VMM, so the guest cannot take
the descriptors the block device, ledger, control socket and vsock bridge
need. Each export prints its peak handle count on a clean stop. A node keeps at
most sixteen host paths for one inode (hard links), evicting a name that no
longer resolves before a live one. `FORGET` and `BATCH_FORGET`, which carry no
reply, are served, so the node table shrinks when the guest drops entries.
Errnos the host returns are named to the guest (`EMFILE`, `ENFILE`,
`ETXTBSY`, `ENAMETOOLONG`, `EBUSY`, `ENOMEM`, `EMLINK`, `ENOLCK`, `EOVERFLOW`,
`ESTALE`, `EDQUOT`) instead of collapsing to `EIO`.

Dispatch and data path. Each device has a worker thread. A `QUEUE_NOTIFY`
drains up to an inline budget of chains on the vCPU thread and wakes the
worker only for what is left, so a syscall's worth of requests pays no
handoff while a deeply queued guest is serviced off the vCPU. `READ` and
`WRITE` go through `preadv`/`pwritev` over iovecs pointing straight into
guest RAM when the chain's declared size matches what the descriptors carry;
any other shape falls back to the buffered handler, which re-validates. The
used-ring publish carries a release fence per drain pass (`dmb` on arm64) so
a guest on another core never observes a bumped index before the element.
`OPEN` refuses anything that is not a regular file, because opening a FIFO
under the device mutex blocked the VM; a guest kernel never sends `OPEN` for a
FIFO, socket or device node anyway.

Measuring it. `tools/fsbench` boots a guest against one share and times three
workloads (`walk`, `write`, `concurrent`); its README records that the 4k
write result is bimodal and how to compare two builds. `cargo test --release
-- --ignored --nocapture bench_metadata_workload` reports host-side
microseconds and host operations per request with no guest. A unit test pins
the host-operation count of the metadata workload exactly, and
`tools/perf-gate.sh` runs in CI on every same-repo pull request: it builds the
branch and its merge base on the same runner, requires the host-operation
count to be equal, and fails a branch that is more than 1.5x slower.
`--base <ref>`, `--samples <n>` and `--limit <ratio>` (or `PERF_GATE_BASE`,
`PERF_GATE_SAMPLES`, `PERF_GATE_LIMIT`) override the merge base, the five
samples per side and the 1.5x ceiling.

Protect a shared OCI cache with `--share-ro`, or give `--share-rw` an
instance-owned APFS clone.

### Networking

- `--net` on its own answers ARP, ICMP, DNS and DHCP from a user-space stack
  inside the VMM (guest `10.0.2.15`, gateway `10.0.2.2`, DNS `10.0.2.3`); TCP is
  seen but not forwarded.
- `--net-gateway <socket>` relays frames to a gvisor-tap process over a Unix
  socket (guest `10.87.0.2`, gateway and DNS `10.87.0.1`). If the socket cannot
  be reached, hvi logs a warning and falls back to the built-in stack.
- `--net-tap <dev>` attaches to an existing tap with `IFF_VNET_HDR` and no
  offloads. Linux only; macOS refuses the flag and names `--net-gateway`. A
  tap that cannot be opened fails the boot with the interface named in the
  error.
- `--net-mac <aa:bb:cc:dd:ee:ff>` sets the guest MAC, and only under
  `--net-tap`: the redirect hands hvi the veth's frames unchanged, so the
  guest has to answer to the veth's MAC. The Linux backends read it there and
  nowhere else (`src/machine_linux.rs`, `src/machine_x86.rs`); the macOS
  backend, `--net` and `--net-gateway` ignore it, and a value that does not
  parse logs a warning and keeps the default.

Every mode parses TLS SNI out of the ClientHello and emits a `net` record per
flow into the ledger. Transmit chains are bounded to a maximum frame, and a
DNS question that ends before its type and class is refused.

### Tools

`--dump-memory <path>` writes guest RAM to a file with the VM parked, on the
console's interrupt key (**Ctrl-]**) or automatically with `--dump-after
<secs>`. The image is raw guest-physical memory; on x86 that is two regions,
because of the MMIO hole.

`--trace-io <path>` logs every virtio-blk request and virtio-net frame as the
device sees it, one line each: the unaggregated counterpart to the ledger's
per-flow `net` records.

Both attach through the seam in [`src/plugin.rs`](src/plugin.rs), which is
also what another crate would use to attach a tool of its own: a debugger, a
profiler, a snapshotter. See [`docs/plugins.md`](docs/plugins.md); the two
in [`src/plugins.rs`](src/plugins.rs) are short enough to read as the worked
examples, and between them they use every part of it. Guest RAM is allocated
from a memfd (Linux) or a POSIX shared-memory object (macOS), unlinked once
mapped, so an out-of-process tool handed the descriptor can map it read-only.

- **macOS** needs the `com.apple.security.hypervisor` entitlement and an
  interactive host (AMFI). Device events land in `--events <path>` as
  `RawEvent` NDJSON.
- **Linux** needs `/dev/kvm`. On arm64 the guest GIC version follows the host's:
  a GICv3 host gets vGICv3, a GIC-400 host gets vGICv2 (capped at 8 vCPUs, a
  GICv2 architectural limit).

### Failure behaviour

On the macOS backend every path that ends the run loop goes through one stop
routine, whichever vCPU hit it: an unhandled MMIO or exception, an unknown
exit reason, a failed `vcpu_create` or `vcpu.run()`, and a panic in a plugin
hook or a device. The vCPU loop runs under `catch_unwind`; a panic is reported
with the vCPU, its last exit reason and its program counter, the quiesce is
released so no vCPU stays parked, and the process exits. Device and ledger
mutexes recover from poisoning instead of cascading a second panic into every
thread that locks next. The Linux and x86 backends still use
`.lock().unwrap()` on their device mutexes.

## CI

A pull request runs `.github/workflows/pr-build-and-verify.yml`, a push to
`main`
runs `main-build-and-verify.yml`. Both call the same reusable workflows:

- **validate-commits** (pull requests only): commit-message conventions and
  spelling, over the tree and over the messages the pull request adds.
- **validate-code**: `tools/tidy.sh --check` (fmt, comment reflow on the
  nightly pinned in `pins.env`, clippy, rustdoc) on x86 Linux; clippy and
  rustdoc for the arm64/KVM backend cross-checked from the same runner and for
  the hvf backend on `macos-15`; actionlint plus shellcheck over the workflows;
  `cargo deny check` over the lockfile.
- **build-and-test**: unit tests on x86 Linux (on a push to `main` the
  suite runs once under `cargo llvm-cov` instead, and the profile goes to
  Codecov, which is what the coverage badge reads); the seccomp selftest on
  x86 Linux; build, test, entitlement sign and the Seatbelt selftest on
  `macos-15`; then the live boots.
- **boot-x86**: a real Linux kernel under the x86/KVM backend to the
  userspace/VFS gate with `--cpus 2`, on a self-hosted runner with `/dev/kvm`
  (label `kvm`). The job skips itself with a warning if the runner has no KVM.
- **boot-arm64-hvf**: `hvi smoke`, `hvi smoke --shm` and a live boot on a
  self-hosted Apple-silicon runner.
- **boot-arm64-kvm**: a two-way matrix, vGICv2 on a GIC-400 host (`nbfc`) and
  vGICv3 (`gicv3`), each running the aarch64 seccomp selftest, a live boot, a
  boot on a real tap when the runner can create one, and a check that an
  unusable tap refuses to boot and names the interface.
- **perf-virtiofs**: `tools/perf-gate.sh` on the Apple-silicon runner, for
  same-repo pull requests.

The self-hosted lanes (the three boots and the perf gate) are withheld from
pull requests opened from a fork; a fork still gets the hosted jobs. No
GitHub-hosted runner exposes `/dev/kvm` for arm64, and a live macOS boot needs
the entitlement on an interactive host, so the live boots run on runners the
project owns.

Three scheduled workflows report through a tracking issue and leave `main`
green: the weekly dependency audit (`cargo deny check` on Mondays), the weekly
used-ring litmus on arm64, and a monthly check that the pinned reflow nightly
still agrees with the latest one.

Every job carries a `timeout-minutes` cap, and the boot jobs upload their logs
and the event ledger as artifacts on failure. Run `tools/gates.sh` before you
push; it mirrors the checks a developer machine can run and names every check
it had to skip. Add `--with-perf` on a Mac to include the virtio-fs gate. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the commit conventions and the full job
list.

## Status and limits

hvi is small by design. It boots and runs Linux guests on all three backends
with virtio-blk, virtio-net and virtio-vsock, virtio-fs on macOS, and each
backend is booted in CI on real hardware.

The limits worth knowing before you build on it:

- **No egress from the built-in network stack.** `--net` answers ARP, ICMP,
  DNS and DHCP inside the VMM; TCP is seen but not forwarded. Real egress means
  `--net-gateway <socket>` or, on Linux, `--net-tap <dev>`.
- **8 vCPUs on a GICv2 arm64 host.** The guest's interrupt controller follows
  the host's, and GICv2 caps there architecturally. A GICv3 host has no such
  limit.
- **macOS needs the hypervisor entitlement and an interactive session.** The
  signature has to be applied to the binary that runs: copying a signed
  Mach-O invalidates it, so `codesign` after every build, not once.
- **One disk and one NIC.** `--disk` and `--net` take a single device each;
  there is no hotplug, and no PCI at all.
- **virtio-fs is macOS-only.** The Linux backends do not carry the device.
  Each share has one request queue and no DAX window.
- **The virtio-fs node table has no cap.** `FORGET` is what shrinks it; a
  guest that never sends one grows it for the life of the VM.
- **`SETLKW` blocks under the device mutex.** A guest waiting on a lock it
  holds through another handle stalls that device until the lock is released.
- **The 4k write benchmark is bimodal** (near 0.85s or near 2.1s on the same
  build). The cause is open; compare several samples per side.
- **x86 vCPUs share one CPUID blob**, so the APIC id the guest reports for a
  secondary CPU varies run to run. Filed separately.
- **arm64-Linux unit tests run nowhere.** `cargo test` runs on x86 Linux and
  on macOS; the arm64/KVM jobs build and boot without a test step.

## Security

The boundary hvi is built to hold is the one around the guest. We assume the
guest is hostile, and the VMM's job is to keep it inside its own VM: away from
the host, and away from any other sandbox on the same machine. The VMM itself
runs confined, so a bug in a device backend is not automatically a bug with the
host's full authority behind it. [Confinement](#confinement) describes what that
looks like and how to see what was installed.

What we do not claim to defend against: a guest that wastes or hangs the VM it
was given, and side channels that come from sharing a CPU with something else,
such as speculative execution and cache timing. Those are the platform's to
mitigate.

hvi has had no external security audit. CI boots every backend on real
hardware, and the confinement selftests check both directions of the profile
and the filters, but testing is not assurance. Weigh that before you put
something valuable behind it.

If you think you have found a way past that boundary, please report it
privately: [SECURITY.md](SECURITY.md) explains how, and what happens next.

## Licence and provenance

Apache-2.0, copyright NOFire AI; every source file carries the header.
[NOTICE](NOTICE) names the modules that follow Firecracker
(`boot_x86`, `layout_x86`, `machine_x86`, `mptable`, `virtio`, `sandbox`) and
records that the Linux seccomp filters are written for seccompiler but are
hvi's own. `cargo deny` checks the licences of everything else against
`deny.toml`. Maintainers are listed in `.github/CODEOWNERS`; the
[code of conduct](CODE_OF_CONDUCT.md) and the [AI policy](AI_POLICY.md) apply
to every contribution.

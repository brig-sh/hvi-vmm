# hvi

A small microVMM for **Linux guests** (arm64 and x86-64), and the substrate
brig runs its sandboxes on, with three host backends behind one CLI:

| Guest | Host | Backend | Status |
| --- | --- | --- | --- |
| aarch64 | macOS / Apple silicon | Apple **Hypervisor.framework** (`applevisor`) | boots + benchmarked |
| aarch64 | Linux | **KVM** (`kvm-ioctls`) | boots to userspace + SMP (vGICv3 or vGICv2) |
| x86-64 | Linux | **KVM** | boots to userspace + virtio-blk/net + SMP (live in CI) |

See [`docs/architecture.md`](docs/architecture.md) for how the pieces fit
together (backends, boot protocols, device model, the extension seam).

hvi owns guest RAM and the vCPUs, and it is its own virtio backend, so a
sandbox gets the same device model on macOS and on Linux. That is what lets
brig run the same workload on either host without the guest noticing.

## Layout

```
src/
  main.rs                     CLI (boot | dump-fdt | smoke); selects the backend by target
  config.rs                   BootConfig / Stop (shared by all backends)
  machine_macos.rs            Hypervisor.framework backend (macOS + aarch64)
  machine_linux.rs            KVM backend (Linux + aarch64)
  machine_x86.rs              KVM backend (Linux + x86-64)
  boot.rs layout.rs fdt.rs    arm64 Image parse, guest RAM layout, devicetree
  boot_x86.rs layout_x86.rs   x86 bzImage + boot_params + e820, guest memory map
  mptable.rs uart16550.rs     x86 Intel MP table, 16550 COM1 serial
  guestmem.rs                 Send+Sync guest-RAM accessor over the host mapping
  virtio*.rs                  virtio-mmio blk / net / vsock / virtio-fs
  pl011.rs                    PL011 UART (arm64)
  plugin.rs                  the extension seam (Plugin / VmHandle / CpuHandle / IoSink)
  plugins.rs                tools built on it: memory dump, I/O trace
  events.rs                   the event log written by `--events`
  smoke.rs                    M0 hvf smoke test (macOS only)
docs/                         architecture + writing a tool
tools/mk-initramfs.py
```

The three backends share every module except `machine_*`/`smoke`; the split is
what makes each port small (the virtio devices and the ledger are hypervisor-
and arch-neutral — they need only a guest-RAM accessor). The arch-specific
surface is the boot protocol (`boot*`/`layout*`/`fdt`/`mptable`).

## Build

```sh
# macOS / Apple silicon (needs Xcode CLT):
cargo build --release
codesign --sign - --entitlements hvi.entitlements --force --options runtime target/release/hvi
#   or: ./run.sh --release boot --kernel <Image> ...   (builds, signs, runs)

# Linux (needs /dev/kvm to run) — arm64 or x86-64, native:
cargo build --release

# Cross compile-check the arm64 Linux backend from an x86 host:
rustup target add aarch64-unknown-linux-gnu
cargo check --target aarch64-unknown-linux-gnu
```

## Run

```sh
hvi boot --kernel <arm64 Image | x86-64 bzImage> \
  [--initramfs <cpio>] [--disk <raw.img>] [--mem-mib N] [--cpus N] \
  [--share-ro <host-directory> <mount-tag>]... \
  [--share-rw <host-directory> <mount-tag>]... \
  [--net | --net-gateway <gvisor-tap .qemu socket>] \
  [--agent-sock <unix socket>] \
  [--events <ledger.ndjson>] [--sandbox-id <id>] [--no-sandbox]

hvi dump-fdt --kernel <Image> [--out fdt.dtb]   # pre-boot pipeline, no hypervisor
hvi smoke                                        # macOS-only M0 hvf test
hvi sandbox-selftest                             # macOS: prove the Seatbelt profile
hvi seccomp-selftest                             # Linux: prove the seccomp filters
hvi --version
```

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
happen says so rather than implying it. `--no-sandbox` boots unconfined, for
debugging a run the profile or the filters break; on Linux, `HVI_SECCOMP=log`
keeps the same allowlists but has the kernel record a mismatch instead of
killing the process, which is how you find a syscall a distro needs and these
lists do not have.

The selftests are the negative test: they install the filters that actually
ship and check both directions — what a confined thread must keep, and what it
must lose. Neither needs a hypervisor or privileges.

### Tools

`--dump-memory <path>` writes guest RAM to a file with the VM parked, on the
console's interrupt key (**Ctrl-]**) or automatically with `--dump-after
<secs>`. The image is raw guest-physical memory; on x86 that is two regions,
because of the MMIO hole.

`--trace-io <path>` logs every virtio-blk request and virtio-net frame as the
device sees it, one line each — the unaggregated counterpart to the ledger's
per-flow `net` records.

Both attach through the seam in [`src/plugin.rs`](src/plugin.rs), which is
also what another crate would use to attach a tool of its own: a debugger, a
profiler, a snapshotter. See [`docs/plugins.md`](docs/plugins.md); the two
in [`src/plugins.rs`](src/plugins.rs) are short enough to read as the worked
examples, and between them they use every part of it.

- **macOS** needs the `com.apple.security.hypervisor` entitlement and an
  interactive host (AMFI). Device events land in `--events <path>` as
  `RawEvent` NDJSON.
- **Linux** needs `/dev/kvm`. On arm64 the guest GIC version follows the host's:
  a GICv3 host gets vGICv3, a GIC-400 host gets vGICv2 (capped at 8 vCPUs, a
  GICv2 architectural limit).

## CI

A pull request runs `.github/workflows/pr-build-and-verify.yml`, a push to `main`
runs `main-build-and-verify.yml`. Both call the same reusable workflows:

- **validate-commits** (pull requests only) -- commit-message conventions and
  spelling, over the tree and over the messages the pull request adds.
- **validate-code** -- `tools/tidy.sh --check` (fmt, comment reflow, clippy,
  rustdoc) on x86 Linux, plus clippy and rustdoc for the arm64/KVM backend
  cross-checked from the same runner and for the hvf backend on `macos-15`.
- **build-and-test** -- unit tests on x86 Linux; build, test and entitlement
  sign on `macos-15`; then a live boot on each backend.
- **boot-x86** -- live boot of a real Linux kernel under the x86/KVM backend to
  the userspace/VFS gate, with `--cpus 2` asserting SMP AP bringup.
- **boot-arm64-hvf** / **boot-arm64-kvm** -- the same for the two arm64
  backends, on self-hosted runners.

The GitHub-hosted x86 `ubuntu-latest` runners expose `/dev/kvm`, so the x86 live
boot actually runs in CI. GitHub-hosted arm64 runners do **not** expose KVM, so
both arm64 backends are compile-checked in CI and boot-tested on self-hosted
runners.

Run `tools/tidy.sh` before you push. See [CONTRIBUTING.md](CONTRIBUTING.md) for
the commit conventions and the full job list.

## Status and limits

hvi is young, and deliberately small. It boots and runs Linux guests on all
three backends with virtio-blk, virtio-net and virtio-vsock, and each backend
is exercised in CI.

The limits worth knowing before you build on it:

- **No egress from the built-in network stack.** `--net` on its own answers ARP,
  ICMP, DNS and DHCP from a user-space stack inside the VMM; TCP is seen but not
  forwarded. Real egress means `--net-gateway <socket>` or, on Linux,
  `--net-tap <dev>`.
- **8 vCPUs on a GICv2 arm64 host.** The guest's interrupt controller follows
  the host's, and GICv2 caps there architecturally. A GICv3 host has no such
  limit.
- **macOS needs the hypervisor entitlement and an interactive session.** The
  signature has to be applied to the binary that actually runs: copying a signed
  Mach-O invalidates it, so `codesign` after every build, not once.
- **One disk and one NIC.** `--disk` and `--net` take a single device each;
  there is no hotplug, and no PCI at all.
- **Directory shares on macOS.** Repeat `--share-ro <path> <tag>` or
  `--share-rw <path> <tag>` to export unpacked directories through independent
  virtio-fs devices, without block images or host FUSE mounts. Each has one
  request queue and no DAX window; tags must be unique, and the Linux backends
  are not wired yet. Writable shares support development workloads: file and
  directory handles, hard links, atomic rename variants, timestamps, xattrs,
  locks, allocation/zero/punch, seek/copy, statx/statfs, FIFOs and tmpfiles.
  A trailing `cache=auto|always|none` on a share selects how much the guest
  may cache: `auto` (the default) keeps attributes for a second and retains
  page cache across opens, `none` revalidates everything against the host for
  a tree the host mutates concurrently, and `always` adds the writeback cache,
  which is only correct when the guest is the sole writer. On macOS, Linux
  mode/uid/gid values are persisted in a private host xattr while the host
  inode retains enough owner access for the unprivileged VMM; restrictive
  modes and arbitrary guest owners therefore survive a backend restart.
  Protect a shared OCI cache with `--share-ro`, or give `--share-rw` an
  instance-owned APFS clone.

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
mitigate, and a small VMM cannot honestly promise otherwise.

hvi is young and has had no external security audit. CI exercises every backend
on real hardware, and the confinement selftests check both directions of the
profile and the filters, but testing is not assurance. Weigh that before you put
something valuable behind it.

If you think you have found a way past that boundary, please report it
privately: [SECURITY.md](SECURITY.md) explains how, and what happens next.

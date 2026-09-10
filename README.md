# hvi

[![CI](https://github.com/brig-sh/hvi-vmm/actions/workflows/main-build-and-verify.yml/badge.svg)](https://github.com/brig-sh/hvi-vmm/actions/workflows/main-build-and-verify.yml)
[![Coverage](https://codecov.io/gh/brig-sh/hvi-vmm/graph/badge.svg)](https://codecov.io/gh/brig-sh/hvi-vmm)
[![Rust](https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrig-sh%2Fhvi-vmm%2Fmain%2Frust-toolchain.toml&query=%24.toolchain.channel&label=rust&color=orange)](rust-toolchain.toml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A small microVMM for Linux guests, and the substrate brig runs its sandboxes
on. hvi owns guest RAM and the vCPUs, and it is its own virtio backend, so a
guest gets the same device model on macOS and on Linux.

It is a command and a Rust library. Use the command to boot a guest. Link the
library to embed the VMM, or to attach a tool to a running guest through
[`src/plugin.rs`](src/plugin.rs).

## Platforms

The backend is chosen by target triple at compile time. There is no runtime
flag to select one.

| Guest | Host | Backend | Shares | Networking |
| --- | --- | --- | --- | --- |
| aarch64 | macOS, Apple silicon | Hypervisor.framework (`applevisor`) | virtio-fs | `--net`, `--net-gateway` |
| aarch64 | Linux | KVM | none | `--net`, `--net-gateway`, `--net-tap` |
| x86-64 | Linux | KVM | none | `--net`, `--net-gateway`, `--net-tap` |

All three carry virtio-blk, virtio-net and virtio-vsock. virtio-fs is macOS
only. CI boots each backend on real hardware: the two arm64 lanes reach
userspace, and the x86 lane reaches the userspace or root-filesystem gate.
No boot job attaches a disk or a vsock agent, so those devices are covered by
unit tests rather than by a live boot. On any other host the crate builds
without a backend, so the shared code and its unit tests still compile. That
stub is not a runnable backend.

## Build

There is no published crate and no downloadable release. Build from source.
The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml).

```sh
cargo build --release
```

On macOS you need macOS 15 or newer, because the backend uses the `hv_gic_*`
in-kernel interrupt controller calls introduced there. Hypervisor.framework
also refuses to start without the `com.apple.security.hypervisor` entitlement,
so sign the binary after every build:

```sh
codesign --sign - --entitlements hvi.entitlements --force \
         --options runtime target/release/hvi
```

An ad-hoc signature is enough. It works with SIP enabled and needs no
Developer ID and no terminal session. Each build writes a new unsigned binary,
which is why you sign after every build. Copying a signed binary keeps its
signature.

On Linux you need read and write access to `/dev/kvm`. No signing applies.

## First boot

This boots an arm64 guest to an Alpine shell. It runs on macOS/Apple silicon
and on Linux/arm64. For x86-64, and for the full explanation, read
[docs/first-boot.md](docs/first-boot.md).

```sh
# The arm64 kernel Image that CI boots, published as an OCI artifact.
# Needs oras; docs/first-boot.md has a curl fallback that needs nothing.
oras pull ghcr.io/nofireai/urunc-kernel:minimal -o target

# An Alpine initramfs. Needs no root and no cpio.
tools/mk-initramfs.py --out target/initramfs.cpio

./target/release/hvi boot \
  --kernel target/Image \
  --initramfs target/initramfs.cpio \
  --mem-mib 1024 --cpus 2
```

The guest reaches a shell on the console:

```text
booting target/Image with 1024 MiB ...
[hvi] 2 vCPU(s)  GICD 0x8000000+0x10000  GICR 0x80a0000+0x2000000  UART 0x1000000
[hvi] seatbelt sandbox: on (deny default)
[    0.000000] Linux version 6.12.95 ...
[    0.094332] Run /init as init process

  ARM64 guest on hvi / hvf  --  interactive
```

Type `poweroff -f` to stop the guest. hvi prints `guest stopped: SystemOff`
and exits.

## More commands

```sh
hvi boot --kernel <Image> --disk disk.img --net           # block device and a NIC
hvi boot --kernel <Image> --share-ro ./src code           # a read-only share (macOS)
hvi boot --kernel <Image> --events ledger.ndjson          # record device I/O
hvi dump-fdt --kernel <Image>                             # arm64 devicetree, no hypervisor
hvi sandbox-selftest                                      # macOS: probe the Seatbelt profile
hvi seccomp-selftest                                      # Linux: probe the seccomp filters
hvi smoke [--shm]                                         # macOS: the Hypervisor.framework test
hvi version                                               # also --version, -V
```

There is no `--help`. [docs/cli.md](docs/cli.md) is the flag reference.

## Design

<img src="docs/img/guest-memory-arm64.svg" alt="arm64 guest physical address space: devices low, RAM at 1 GiB" width="720">

Every backend speaks virtio-mmio, which avoids a PCI host bridge and lets one
set of device models serve all three. The `machine_*` modules hold the
hypervisor differences. The boot protocol differs too, and by more: arm64 uses
an `Image` header, a devicetree and PSCI, while x86-64 uses a `bzImage`,
`boot_params`, an e820 map and an MP table.

[docs/architecture.md](docs/architecture.md) describes the whole design.

## Status and limits

hvi is young. Read these before you build on it.

- **No egress from the built-in network stack.** `--net` answers ARP for the
  gateway and DNS addresses, ICMP echo requests, and DHCP, all inside the VMM.
  TCP is seen but not forwarded. Real egress needs `--net-gateway`, or
  `--net-tap` on Linux.
- **The built-in stack cannot resolve DNS while confined.** It records the
  queried name, then asks the host to resolve it. The default sandbox denies
  the socket that needs, so the guest gets a reply with no addresses in it.
  Only `--no-sandbox` resolves.
- **One disk and one NIC.** No hotplug, and no PCI at all.
- **virtio-fs is macOS only**, one request queue per share, no DAX window.
- **8 vCPUs on a GICv2 arm64 host.** The guest interrupt controller follows
  the host, and GICv2 caps there.
- **The event ledger is per packet and egress only.** It is not aggregated per
  flow, and it is not a tamper-proof record.
- **The arm64/KVM backend has no unit tests.** `src/machine_linux.rs` carries
  none, and no job would run a suite on arm64 Linux if it did. That backend is
  cross-linted and booted, not unit-tested.

[docs/limitations.md](docs/limitations.md) has the full list with the
consequences.

## Security

hvi assumes the guest is hostile. Its job is to keep that guest inside its own
VM, away from the host and from every other sandbox on the machine. The VMM
also confines itself before it runs a guest, with a Seatbelt profile on macOS
and seccomp-bpf filters on Linux, so a bug in a device backend does not start
with the host's full syscall surface behind it.

hvi has had no external security audit. Confinement narrows what the process
can ask the kernel for. It does not drop privilege, and it does not remove the
risk of an escape. [docs/security.md](docs/security.md) gives the threat model
and the residual risks. [SECURITY.md](SECURITY.md) explains how to report a
vulnerability.

## Documentation

[docs/README.md](docs/README.md) is the index. It covers first boot, guest
images, the CLI, storage and sharing, networking, observability, security,
architecture, embedding, benchmarking, and contributor testing.

## Licence and provenance

Apache-2.0, copyright NOFire AI. [NOTICE](NOTICE) names the modules that
follow Firecracker and records that the Linux seccomp filters are hvi's own.
Maintainers are in [`.github/CODEOWNERS`](.github/CODEOWNERS). The
[code of conduct](CODE_OF_CONDUCT.md), the [AI policy](AI_POLICY.md) and
[CONTRIBUTING.md](CONTRIBUTING.md) apply to every contribution.

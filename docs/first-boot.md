# Your first guest

This page takes you from a fresh checkout to a Linux shell inside a guest.

The tutorial in full is the macOS/Apple silicon path, because that is the one
with an extra step. Linux follows the same shape without the signing, and the
differences are listed at the end.

## Before you start

You need:

- A host with a backend. See the platform table in the
  [README](../README.md#platforms). No other host can run a guest.
- The Rust toolchain pinned in [`rust-toolchain.toml`](../rust-toolchain.toml).
  `rustup` installs it from the file.
- On macOS: the Xcode command line tools, for the linker, and **macOS 15 or
  newer**. The backend drives Apple's in-kernel interrupt controller through
  the `hv_gic_*` calls, which arrived in macOS 15, so an older host has no
  such symbols. hvi does not check the version itself and fails when it first
  reaches the framework rather than with a clear message.
- On Linux: read and write access to `/dev/kvm`. Add yourself to the `kvm`
  group. A group you join does not reach a running shell, so start a new one.
- `python3`, for the initramfs builder.
- `oras`, to pull the kernel below. Optional: step 3 has a `curl` fallback
  that needs only `curl` and `python3`.

There is no published crate and no downloadable release, so you build from
source.

## 1. Build

```sh
cargo build --release
```

## 2. Sign, on macOS only

Hypervisor.framework refuses to start without the
`com.apple.security.hypervisor` entitlement.

```sh
codesign --sign - --entitlements hvi.entitlements --force \
         --options runtime target/release/hvi
```

Make sure the entitlement is on the binary:

```sh
codesign -d --entitlements - target/release/hvi
```

```text
[Dict]
	[Key] com.apple.security.hypervisor
	[Value]
		[Bool] true
```

Three things about this signature are often stated wrongly:

- An ad-hoc signature (`--sign -`) is enough. It works with SIP enabled.
- No terminal session is needed. A background process can boot a guest.
- Copying the signed binary keeps the signature and the entitlement. What
  invalidates it is a rebuild, because `cargo build` writes a new unsigned
  binary over the old one. Sign after every build.

An unsigned binary fails at the first hypervisor call:

```text
hvi: operation not allowed by the system (error 0xfae94007)
```

Distributing a binary to other people is a different problem. That needs a
Developer ID certificate and notarization, which this page does not cover.

## 3. Get a kernel

hvi boots an uncompressed arm64 `Image`. CI uses a published OCI artifact, and
so can you:

```sh
oras pull ghcr.io/nofireai/urunc-kernel:minimal -o target
```

That writes `target/Image`, a 6.12.95 kernel. If you have no `oras`, the same
blob comes down with `curl`, because the registry allows anonymous pulls:

```sh
TOKEN=$(curl -s "https://ghcr.io/token?scope=repository:nofireai/urunc-kernel:pull&service=ghcr.io" \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
DIGEST=$(curl -s -H "Authorization: Bearer $TOKEN" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        "https://ghcr.io/v2/nofireai/urunc-kernel/manifests/minimal" \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["layers"][0]["digest"])')
curl -sL -H "Authorization: Bearer $TOKEN" \
     "https://ghcr.io/v2/nofireai/urunc-kernel/blobs/$DIGEST" -o target/Image
```

To build your own kernel instead, read [guest-images.md](guest-images.md).

## 4. Build an initramfs

`tools/mk-initramfs.py` turns an Alpine root filesystem into a cpio archive,
with an `/init` that mounts the pseudo-filesystems and starts a shell. It
needs no root and no `cpio` command. It downloads the Alpine tarball once and
caches it beside the output.

```sh
tools/mk-initramfs.py --out target/initramfs.cpio
```

## 5. Boot

```sh
./target/release/hvi boot \
  --kernel target/Image \
  --initramfs target/initramfs.cpio \
  --mem-mib 1024 --cpus 2
```

hvi prints what it set up, then hands the console to the guest:

```text
booting target/Image with 1024 MiB ...
[hvi] 2 vCPU(s)  GICD 0x8000000+0x10000  GICR 0x80a0000+0x2000000  UART 0x1000000
[hvi] seatbelt sandbox: on (deny default)
[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x610f0000]
[    0.000000] Linux version 6.12.95 ...
[    0.094332] Run /init as init process

===================================================
  ARM64 guest on hvi / hvf  --  interactive
Linux (none) 6.12.95 #1 SMP PREEMPT aarch64 Linux
  alpine 3.20.10, type 'poweroff -f' or 'exit' to stop
===================================================
/ #
```

The `/ #` prompt is the guest. Your keystrokes go to its console.

## 6. Stop it

Type `poweroff -f`, or `exit` to leave the shell, which powers off too. The
guest asks PSCI to shut down, and hvi reports how the run ended:

```text
[   12.106892] reboot: Power down
guest stopped: SystemOff
```

`Ctrl-]` is not an exit key. With a plugin attached hvi intercepts it and asks
that plugin for an observation. With no plugin it goes to the guest as an
ordinary byte. Only `--dump-memory` acts on it. See
[observability.md](observability.md).

## Platform differences

### Linux, arm64

Identical, minus step 2. Nothing is signed. The guest interrupt controller
follows the host: a GICv3 host gives the guest vGICv3, and a GIC-400 host
gives it vGICv2, which caps the guest at 8 vCPUs.

### Linux, x86-64

The kernel format and the console differ. hvi boots a `bzImage` or an
uncompressed `vmlinux`, not an `Image`, and the console is a 16550 at port
`0x3f8` rather than a PL011. A distribution kernel works:

```sh
sudo apt-get install -y --no-install-recommends linux-image-virtual

./target/release/hvi boot \
  --kernel /boot/vmlinuz-$(uname -r) \
  --mem-mib 1024 --cpus 2 \
  --cmdline "console=ttyS0 panic=-1"
```

hvi appends `console=ttyS0` and the `virtio_mmio.device=` arguments its own
devices need, so an x86-64 guest has a console even with the default
`--cmdline`. Pass `console=ttyS0` anyway: the default names `ttyAMA0`, which
is the arm64 console and does nothing here.

`tools/mk-initramfs.py` builds an **arm64** initramfs only. For an x86-64
guest, supply your own, or boot without one and let the kernel stop at the
root-filesystem gate.

### No hypervisor at all

`hvi dump-fdt` runs the whole arm64 pre-boot pipeline, parsing the kernel
header, computing the guest layout and building the devicetree, without
touching a hypervisor. It needs no entitlement and no `/dev/kvm`, so it works
where a boot cannot:

```sh
hvi dump-fdt --kernel target/Image --mem-mib 1024 --out target/fdt.dtb
```

```text
kernel target/Image: kernel@0x40000000 reserved_size=0x33c0000 (file 53412352 bytes)
RAM   0x40000000 + 1024 MiB
kernel@0x40000000 dtb@0x43400000 (+0x503) initrd@0x43401000 (+0x0)  top=0x43401000
cmdline: earlycon console=ttyAMA0 panic=-1
wrote 1283 byte DTB to target/fdt.dtb
```

This is a check of the pre-boot pipeline. It is not a boot, and a successful
`dump-fdt` says nothing about whether the guest runs.

## If it does not work

| Symptom | Cause |
| --- | --- |
| `operation not allowed by the system (error 0xfae94007)` | macOS: the binary is unsigned, or you rebuilt after signing. Sign it again. |
| `Permission denied` opening `/dev/kvm` | Linux: you are not in the `kvm` group, or the shell predates the change. |
| The console stops after `Run /init as init process` | The initramfs has no working `/init`, or it is built for the wrong architecture. |
| The kernel panics at `Unable to mount root fs` | No initramfs and no `--disk`. Expected without a root filesystem. |
| `--net-stub` gives the guest an address but no name resolution | Expected while confined. See [networking.md](networking.md#dns). |

## Next

- [cli.md](cli.md) for every flag.
- [storage-and-sharing.md](storage-and-sharing.md) to give the guest a disk or
  a host directory.
- [networking.md](networking.md) for real egress.

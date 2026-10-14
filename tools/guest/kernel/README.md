# Portable guest kernel

The portable profile (`--profile portable-arm64-v1`, see
[portable-profile.md](../../../docs/portable-profile.md)) needs a guest
kernel with the `hvi,time-v1` driver. This directory holds what that kernel
is built from: Linux 6.12.95 plus the four patches in `patches/`, with the
published guest config and one fragment.

**Licence.** The patches change the Linux kernel and are GPL-2.0, like the
kernel itself (`drivers/clocksource/hvi-time.c` carries
`SPDX-License-Identifier: GPL-2.0`). They are kept here as input to a
separate build and are not part of hvi, which stays Apache-2.0.

| File | What |
| --- | --- |
| `patches/0001-arm64-Let-a-clock-driver-supply-trapped-EL0-counter-.patch` | `arm64_set_el0_counter()`: trapped EL0 reads of `CNTVCT_EL0`, `CNTVCTSS_EL0` and `CNTFRQ_EL0` use a counter a clock driver registers, and `update_cntkctl_el1()` keeps EL0 counter access off while one is registered. |
| `patches/0002-clocksource-Add-the-hvi-time-paravirtual-clock-and-t.patch` | `drivers/clocksource/hvi-time.c`: the clocksource, `sched_clock`, per-CPU clock event and 54 MHz EL0 counter on the pvclock page, and the restore work. `HVI_TIME` in Kconfig. |
| `patches/0003-clocksource-hvi-time-Handle-each-page-generation-onc.patch` | The restore work handles each page generation once. Without it a guest with more than one vCPU can log and count one move two or more times. |
| `patches/0004-clocksource-hvi-time-Count-host-sleep-publishes-apar.patch` | The driver tells host-sleep publishes from restores by the page's `host_sleeps`, and counts them in `host_sleeps` instead of `migrations`. |
| `guest.config` | The config of the published `ghcr.io/nofireai/urunc-kernel:minimal` 6.12.95 Image: the image's config layer, sha256 `93b8fef02034fa1c4805e90c3964d9cfdc41af1d74963a1f08a274fa6c9296e7`. |
| `hvi-time.config` | The fragment merged over it: `CONFIG_HVI_TIME=y`. |

The series is out of tree: there is no devicetree binding document for
`hvi,time-v1`. The binding is summarised in the header of `hvi-time.c` and in
[portable-profile.md](../../../docs/portable-profile.md#devicetree).

## Build

On an arm64 Debian 12 host (the Images below were built on a Raspberry Pi 5,
gcc 12.2.0):

```sh
sudo apt-get install -y --no-install-recommends bc bison flex libssl-dev \
    libelf-dev dwarves cpio xz-utils kmod python3
git clone --depth 1 --branch v6.12.95 https://github.com/gregkh/linux
cd linux        # HEAD 296aabce4594, "Linux 6.12.95"
git am /path/to/hvi-vmm/tools/guest/kernel/patches/*.patch
git rev-parse HEAD^{tree}    # 9821a1668ca7ed109cf35d4ece22cc4e2da4371a
cp /path/to/hvi-vmm/tools/guest/kernel/guest.config .config
./scripts/kconfig/merge_config.sh -m .config \
    /path/to/hvi-vmm/tools/guest/kernel/hvi-time.config
make RUSTC=false olddefconfig
./scripts/diffconfig /path/to/hvi-vmm/tools/guest/kernel/guest.config .config
                             # prints only "+HVI_TIME y"
make RUSTC=false -j3 Image   # arch/arm64/boot/Image
```

Pass `RUSTC=false` when a `rustc` is on `PATH`: without it Kconfig records
the Rust version and the config drifts from the published one.

`git am` makes new commit hashes, so the `uname -r` suffix
(`-00004-g<hash>`, from `LOCALVERSION_AUTO`) and the Image's sha256 differ
from the ones below; the tree is the same. The Image also embeds the build's
time, user and host.

## Images

The Image the docs and tests name, built from the four patches:

- sha256 `e85e4338feeb361c5329b4105fa3bda5cd72a235c9ae16c3c4ff94728b12aa1f`,
  53412352 bytes;
- `Linux version 6.12.95-00004-gc61d393fb996`, tree `9821a1668ca7`.

Earlier Images, for the records in the docs that name them:

| sha256 | `uname -r` | Patches |
| --- | --- | --- |
| `4b2e8c5ce382a2635efe1b1b198e35b081d2f0cd4d39d9689b026fbc7d8f21b7` | `6.12.95-00003-g51cdb81da818` | 0001 to 0003 |
| `32725b9b4327a8833d833e2a017f510310504309a8ed1d1030ef0118d018a152` | `6.12.95-00002-g4cfd86639cc9` | 0001 and 0002 |

The Image is not published to a registry yet.

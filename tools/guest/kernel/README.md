# Portable guest kernel

The portable profile (`--profile portable-arm64-v1`, see
[portable-profile.md](../../../docs/portable-profile.md)) needs a guest
kernel with the `hvi,time-v1` driver. This directory holds what that kernel
is built from: Linux 6.12.95 plus the five patches in `patches/`, with the
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
| `patches/0005-clocksource-hvi-time-Tell-user-space-about-each-migr.patch` | After it counts a restore, the restore work sends a `KOBJ_CHANGE` uevent on the node's platform device with `HVI_TIME_EVENT=migrated` and `MIGRATIONS=<count>`. A host-sleep publish sends none. The count is also in `/sys/kernel/hvi_time/migrations`; the other files are unchanged. |
| `guest.config` | The config of the published `ghcr.io/nofireai/urunc-kernel:minimal` 6.12.95 Image: the image's config layer, sha256 `93b8fef02034fa1c4805e90c3964d9cfdc41af1d74963a1f08a274fa6c9296e7`. |
| `hvi-time.config` | The fragment merged over it: `CONFIG_HVI_TIME=y` and `CONFIG_INET_DIAG_DESTROY=y`. |

`CONFIG_INET_DIAG_DESTROY` lets a process with `CAP_NET_ADMIN` close
another process's socket over inet_diag (`SOCK_DESTROY`, the call behind
`ss -K`). The guest agent uses it after a move. A TCP connection the guest
only reads from, such as an API response stream, sends nothing after the
guest resumes on another host, so no gateway resets it, and it waits about
a minute for its keepalive timer. On the patch 0005 uevent the agent
destroys each TCP connection whose peer is off the guest, and its client
connects again at once. The agent is `urunit-agent`, from urunc's
`cmd/urunit-agent`, which the boot bundle's initrd carries. The version
that acts on the uevent is on urunc's branch
`feat/agent-migration-tcp-reset` and in no published bundle yet; with the
bundle's agent this Image keeps such a connection open as the four-patch
one did.

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
git rev-parse HEAD^{tree}    # d8b5845ff315584bde1561d14d11c54823be1493
cp /path/to/hvi-vmm/tools/guest/kernel/guest.config .config
./scripts/kconfig/merge_config.sh -m .config \
    /path/to/hvi-vmm/tools/guest/kernel/hvi-time.config
make RUSTC=false olddefconfig
./scripts/diffconfig /path/to/hvi-vmm/tools/guest/kernel/guest.config .config
                             # prints only " INET_DIAG_DESTROY n -> y"
                             # and "+HVI_TIME y"
make RUSTC=false -j3 Image   # arch/arm64/boot/Image
```

Pass `RUSTC=false` when a `rustc` is on `PATH`: without it Kconfig records
the Rust version and the config drifts from the published one.

`git am` makes new commit hashes, so the `uname -r` suffix
(`-00005-g<hash>`, from `LOCALVERSION_AUTO`) and the Image's sha256 differ
from the ones below; the tree is the same. The Image also embeds the build's
time, user and host.

## Images

The Image the docs and tests name, built from the five patches on
2026-10-16 on a Raspberry Pi 5 (`make -j3 Image`, 32 min):

- sha256 `778700360da1641466b5b9791a0fe231a52a20c4fb221e1b0e2cdf42730ed295`,
  53412352 bytes;
- `Linux version 6.12.95-00005-g3fd3cba0e98a`, tree `d8b5845ff315`.

Earlier Images, for the records in the docs that name them:

| sha256 | `uname -r` | Patches |
| --- | --- | --- |
| `e85e4338feeb361c5329b4105fa3bda5cd72a235c9ae16c3c4ff94728b12aa1f` | `6.12.95-00004-gc61d393fb996`, tree `9821a1668ca7` | 0001 to 0004 |
| `4b2e8c5ce382a2635efe1b1b198e35b081d2f0cd4d39d9689b026fbc7d8f21b7` | `6.12.95-00003-g51cdb81da818` | 0001 to 0003 |
| `32725b9b4327a8833d833e2a017f510310504309a8ed1d1030ef0118d018a152` | `6.12.95-00002-g4cfd86639cc9` | 0001 and 0002 |

The Image is not published to a registry yet.

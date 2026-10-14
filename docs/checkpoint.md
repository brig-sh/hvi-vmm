# Checkpoints

A checkpoint captures a running guest into a bundle: a directory that holds
its RAM, its vCPUs, its devices and the machine it was built against. The
plan is that another hvi restores the bundle on a compatible host, and the
guest runs on there without rebooting.

That plan is not finished. This page says what works today and what does
not.

- **Works:** the bundle format, the capture on the control socket on all
  three backends, the fence that keeps a source from running again, and
  `hvi checkpoint-verify`.
- **Does not work yet:** a bundle cannot be restored. Each vCPU's state is
  partial, and the interrupt controller and the guest counter are not
  captured. [What is captured](#what-is-captured) has the details.

## Taking a checkpoint

Boot with a control socket and a checkpoint root:

```sh
hvi boot --kernel Image --initramfs initramfs.cpio --disk root.img \
    --control-sock /run/sb1/ctl.sock --checkpoint-root /var/lib/sb1/checkpoints
```

`--checkpoint-root` names the only directory a checkpoint may write below.
The directory must exist. hvi resolves its path at boot, before the process
is confined, and refuses a bundle directory that is not below it. On macOS
the kernel enforces that too. On Linux only hvi's own check does: see
[Confinement](#confinement). Without `--checkpoint-root`, every `checkpoint`
is refused.

Give each sandbox a root of its own, owned by the user hvi runs as, with mode
0700, and never share one root between sandboxes. A bundle holds the guest's
RAM in clear, with any keys and credentials the guest had in memory. The hvi
process can read and write everything below its root, so a VMM that a guest
took over could read or change another sandbox's bundles in a shared root.

Then ask the socket:

```text
{"v":1,"op":"checkpoint","dir":"/var/lib/sb1/checkpoints/tx-42","then":"continue","txid":"tx-42","epoch":3}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `dir` | yes | The bundle directory. It must be absolute and below the checkpoint root, spelled as given at boot or resolved; the bundle is written below the resolved root either way. It must not exist, or be an empty directory. Its parent must exist. No directory on the way may be a link. |
| `then` | no, default `continue` | `continue`: the VM goes back to the state it was in. `fence`: the VM stays paused for good. |
| `txid` | no | The caller's transaction id, at most 256 bytes. Recorded in `session.json`. |
| `epoch` | no, default 0 | The caller's epoch for the sandbox. Recorded in `session.json`. |

A capture that sealed its bundle replies:

```text
{"v":1,"ok":true,"state":"running","dir":"/var/lib/sb1/checkpoints/tx-42",
 "manifest_sha256":"fb9f…36d4",
 "stats":{"pause_ms":0,"capture_ms":264,"ram_present_bytes":93126656,
          "ram_total_bytes":536870912,"bundle_bytes":93147151}}
```

The reply is one line; it is wrapped here to fit the page.

| Stat | Meaning |
| --- | --- |
| `pause_ms` | From the request to every vCPU parked with its state exported. |
| `capture_ms` | From then to the sealed bundle: device states, the disk sync, RAM and the files. |
| `ram_present_bytes` | The bytes of guest RAM in the bundle. Pages that are all zero are not stored. |
| `ram_total_bytes` | The size of guest RAM. |
| `bundle_bytes` | The size of every file in the bundle, the manifest included. |

The guest does not run from the request to the reply. Its downtime is
`pause_ms + capture_ms`, and `capture_ms` grows with `ram_present_bytes`. A
client must allow for that in its reply timeout: the 3 s that suits `pause` is
not enough here. These figures were measured with 2 vCPUs, no disk and no
network:

| Host | Guest RAM | Present | `capture_ms` | Bundle |
| --- | --- | --- | --- | --- |
| Apple M5 Pro, HVF | 512 MiB | 89 MiB | 250 to 264 | 89 MiB |
| Apple M5 Pro, HVF | 1024 MiB | 98 MiB | 320 to 347 | 98 MiB |
| Apple M5 Pro, HVF | 1024 MiB, 256 MiB written by the guest | 345 MiB | 793 to 946 | 345 MiB |
| Raspberry Pi 5, KVM | 512 MiB | 89 MiB | 795 to 1194 | 89 MiB |
| Raspberry Pi 5, KVM | 1024 MiB | 98 MiB | 1023 to 1174 | 98 MiB |
| Raspberry Pi 5, KVM | 1024 MiB, 256 MiB written by the guest | 347 MiB | 2869 to 3143 | 347 MiB |

`pause_ms` was 0 in every run: the vCPUs park and export in under a
millisecond.

The capture syncs every file it writes, so its time also depends on how busy
the host's storage is. rp1 is shared with other builds. While a cargo build
ran there, 512 MiB captures took from 0.8 s to 14 s, with or without a disk,
an agent socket or a network. `strace` showed where the time went: the
`fsync` of `ram.bin` took 8.3 s in a slow capture and 0.2 s in a fast one. The
rows above were measured while the Pi was quiet.

### Refusals

A refusal is `{"v":1,"ok":false,"code":...,"error":...}`.

| `code` | When | The VM afterwards |
| --- | --- | --- |
| `refused` | No checkpoint root, a `dir` outside it, a `dir` that is not empty or goes through a link, a guest with virtio-fs shares, or a guest with a second disk or a read-only one. | Untouched: nothing was paused. |
| `not_ready` | The machine profile is not complete yet. | Untouched. |
| `timeout` | The I/O threads or the vCPUs did not park, or the vCPUs did not export their state, within 2 s. | As the request found it. |
| `capture_failed` | Anything after the pause: a device state that a restore would refuse, a failed disk sync, a failed write or sync, a bundle the reader would refuse. | As the request found it. Every file the capture wrote is removed, the manifest included, and the directory too when the capture created it. |
| `fenced` | The VM was fenced by an earlier checkpoint. | Still fenced. |
| `stopped` | The run is ending. | Ending. |

"As the request found it" means running if it was running, and paused if a
client had paused it. A checkpoint never resumes a VM that a client paused.

### The fence

`then: "fence"` is the source's half of a move. Once the destination runs the
guest, the source must never run it again. After a fenced capture:

- `status` reports `fenced`, with every vCPU parked.
- `resume` is refused with `fenced`, on this connection and on any later one.
- `pause` answers `fenced` and changes nothing.
- A second `checkpoint` is refused with `fenced`.
- `stop` ends the run as usual.

The fence holds only while this hvi process lives. It is not written
anywhere. A caller that must survive a crash of the source records the fence
itself.

## Checking a bundle

```sh
hvi checkpoint-verify /var/lib/sb1/checkpoints/tx-42
```

It reads the manifest within its limits, checks every component's size and
SHA-256, parses every document and checks them against the profile and
against each other. It prints what the bundle holds and exits 0, or it prints
the first problem, naming the file, and exits 1:

```text
bundle ok: manifest sha256 fb9fbc73425d49e4dd02374b61b591f0dfc6a19891791d46bccf6ee6823036d4
written by hvi 0.1.0 (aa0bd9ed8f21dd49792f25f86e4fa686b17e200b), aarch64 on hvf
  profile.json             1208 bytes
  ram.bin              93126656 bytes
  ram.map                 16400 bytes
  cpu.json                  659 bytes
  platform.json             258 bytes
  devices.json              177 bytes
  session.json              115 bytes
  manifest.json            1678 bytes
RAM: 93126656 of 536870912 bytes present; 2 vCPU(s)
partial: vCPU registers, interrupt controller and timer not captured, so no restore can resume this bundle
```

```text
hvi: /var/lib/sb1/checkpoints/tx-42: ram.bin: SHA-256 does not match the manifest
```

## The bundle format

`checkpoint_format` 1. Every document is JSON with fields by name and a
`version`. No file holds a native struct layout, so a bundle does not depend
on the byte layout of the build that wrote it.

| File | Holds |
| --- | --- |
| `profile.json` | The source's machine profile. See [cli.md](cli.md#the-control-socket). |
| `ram.bin` | The pages of guest RAM that are not all zero, region by region, in address order, with nothing between them. |
| `ram.map` | A 16-byte header (`HVIRAM01`, a little-endian `u32` page size of 4096, a little-endian `u32` region count), then one bitmap per region. Bit `i` is bit `i % 8` of byte `i / 8`. 1 means page `i` is the next page in `ram.bin`, and 0 means the page is all zero. |
| `cpu.json` | `{"version":1,"arch":"aarch64"\|"x86_64","vcpus":[...]}`. Registers by architectural name, values as `"0x..."` strings. Each vCPU says whether it is `partial`. |
| `platform.json` | The interrupt controller (`irq`) and the guest counter (`timer`), and an optional backend blob. Both sections are `{"kind":"not-captured","reason":...}` today. |
| `devices.json` | Every device's state, with a `null` for a device the guest does not have, and `irq_levels`: the level of each device's interrupt line at the capture, so a restore can drive the lines again. The virtio-blk state is version 2: version 1 had no `serial` and `read_only`, which it now records, so the restored disk answers `GET_ID` with the serial the guest read from `/sys/block/vdX/serial` at boot. A restore refuses version 1. |
| `disk.json` | Only when the guest has a disk: the path it was opened at, its size, `generation` (the writes and flushes since boot), `synced: true`, and `sha256_sparse: null`, which whoever moves the disk fills in. |
| `session.json` | The sandbox id, `epoch`, `txid`, the capture time and `then`. |
| `manifest.json` | Every other file's name, size and SHA-256, the RAM regions with their present page counts, the SHA-256 of `profile.json`, the hvi build, `capabilities` (empty today) and the seal time. |

The writer syncs the parent of a bundle directory it creates, so the
directory itself survives a host crash. It syncs each component to stable
storage. It writes the manifest last, under a temporary name, syncs it,
renames it into place and syncs the directory. The bundle is sealed only once
that last sync returns. So a directory without `manifest.json` is not a
bundle, whatever else is in it. A capture that fails before the seal removes
what it wrote, including a manifest already renamed into place.

The writer refuses what the reader below would refuse. A component larger
than the reader's limit for it, or a manifest that fails the reader's checks,
fails the capture with `capture_failed` before the seal, while the VM can
still run on. Without this, a fenced source could seal a bundle that no
restore opens, and the session would be lost. The vsock device can reach
such a size: `devices.json` writes every byte it holds as a JSON number.

The reader trusts nothing in the directory:

- It reads the manifest only up to 1 MiB.
- It checks every count, name and size against fixed limits before it
  allocates anything by them. A manifest lists at most 16 components, and
  each name must be a known component at its own file name. `ram.bin` may be
  at most 64 GiB. There are 1 to 8 RAM regions, and no region may have more
  present pages than pages.
- It checks that the manifest agrees with itself and with the profile: the
  present bytes add up, `ram.bin` and `ram.map` have the sizes the regions
  need, `profile_sha256` is the profile's hash, and the regions are the
  profile's regions.
- It opens every component without following a link, and refuses anything
  that is not a regular file.
- It hashes every component before it returns, and again when it reads the
  component for use.

Any mismatch is refused with the name of the file. Nothing is truncated,
skipped or repaired.

## How the capture works

1. The control thread refuses what it can without pausing: the state, the
   root, the directory, the profile and its shares. It then creates the
   bundle directory.
2. It closes the I/O pause gate, so no host thread is inside a device or
   writing guest RAM. Then it parks every vCPU.
3. It asks every vCPU to export its state. Only a vCPU's own thread can read
   its registers on HVF and on KVM. So each vCPU does the export at its
   park point, out of the guest, and stays parked. A vCPU that was already
   parked by an earlier `pause` is woken to do it.
4. With everything still, it locks every device mutex and collects the device
   states. Then it checks them as a restore would. A state that a restore
   would refuse fails the capture here, before any file is written, while the
   guest can still run on. The vsock device is the one that can reach such a
   state, with more connections or waiting packets than a restore takes.
5. It syncs the disk image with `fdatasync`.
6. It writes the profile, RAM, the vCPUs, the platform, the devices, the disk
   and the session, then seals the manifest.
7. It replies, then resumes the VM, or keeps it parked for `fence`.

Steps 2 and 3 share one 2 s deadline. A stop of the run during the capture
ends it between components and between reads of RAM.

### Confinement

The control thread writes the bundle after the process is confined:

- **macOS.** The Seatbelt profile gets one more subtree rule, `file-read*
  file-write*` below the resolved checkpoint root. The kernel enforces it: no
  thread can write outside the root and the writable shares. The rule covers
  the whole process, so every thread, the vCPU threads included, can read and
  write every bundle below the root.
- **Linux.** The control thread installs its own seccomp filter, `control`.
  It is `vmm` plus the file calls a bundle needs: `openat`, `mkdirat`,
  `renameat`, `unlinkat`, the `stat` family, `getdents64` and `readlinkat`
  (x86-64 also has the older names). Only a run with `--checkpoint-root` gives
  the thread that filter. Every thread that parses guest data still cannot
  open a file. seccomp cannot filter the path a call names, so the filter
  does not hold the control thread to the root. That thread can read, create,
  rename and remove files anywhere the user hvi runs as can. The rule that a
  bundle goes below the root is hvi's own path check, which a compromised
  control thread would skip. Holding the thread to the root in the kernel
  needs Landlock, which hvi does not use yet; the Raspberry Pi 5 kernel it was
  tested on does not enable it.

Both selftests write and verify a real bundle under the production
confinement. They also check that a bundle outside the root (macOS), or one
written from a `vmm` thread (Linux), is refused.

## What is captured

| Part | Today | Next |
| --- | --- | --- |
| Guest RAM | Whole, without zero pages. | Dirty tracking for pre-copy rounds. |
| Device state | Whole: virtio-blk, virtio-net and virtio-vsock queues and registers, the PL011, or the 16550 and the CMOS RTC. | |
| Disk | Synced, with its size and generation. The image itself is not in the bundle; whoever moves the sandbox moves the disk. | A dirty-sector bitmap. |
| vCPU registers | **Partial.** On arm64: PC, PSTATE, SP_EL0, SP_EL1, SCTLR_EL1, TCR_EL1, TTBR0_EL1 and TTBR1_EL1. On x86-64: RIP and CR3. A register the backend could not read is 0. | HVF and KVM exports of every register, under the same names. |
| A secondary arm64 vCPU the guest never started | `"power":"off"`. | A pending `CPU_ON` recorded as `pending_on`. |
| Interrupt controller | **Not captured.** | The GICv3 state on HVF, the vGIC state on KVM arm64, the irqchip and PIT on KVM x86-64. |
| Guest counter | **Not captured.** | The counter value at the capture, so the guest's counter continues from it. |

A restore must refuse a vCPU marked `partial` and a `not-captured` section.
`hvi checkpoint-verify` reports both.

### What a capture can lose

The pause gate holds every host thread out of the devices. A capture holds
everything the guest was given, with two exceptions:

- **One console keystroke.** The console reader reads stdin outside the gate.
  stdin is a shared terminal that hvi does not make non-blocking. So a capture
  can find one byte read from the terminal and not yet in the UART.
- **The start of one gateway frame.** The gateway relay receives inside the
  gate. It can still hold the first part of a frame whose rest had not
  arrived. To the guest this is one lost frame, which its TCP sends again.

Pause and resume on one host lose neither. What is outside the VM is not in
the bundle either: bytes still in a host socket, the gateway's own
connections, and the host ends of vsock connections. A restore resets the
vsock connections, so the guest sees each one shut down.

## Clock policy

The guest's counters (CNTVCT on arm64, the TSC and kvmclock on x86-64)
continue from the captured value. Downtime is invisible to the guest's
monotonic clock. A timer whose deadline passed during the downtime fires on
the first entry after the restore. The guest's wall clock is behind by the
downtime until the guest's own time sync corrects it. hull's `/urunc-epoch`
only sets the boot time. QEMU behaves the same way by default, when it is run
without `-rtc clock=host` for the monotonic counter.

Today's capture does not record the counter, so this is the policy a restore
will follow, not one in effect yet. A `pause` alone does not stop guest time:
the counter runs on through it.

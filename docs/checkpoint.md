# Checkpoints

A checkpoint captures a running guest into a bundle: a directory that holds
its RAM, its vCPUs, its devices and the machine it was built against.
`hvi restore` resumes the bundle in another hvi process on a compatible host,
and the guest runs on there without rebooting.

This page says what works today and what does not.

- **Works:** the bundle format, the capture on the control socket on all
  three backends, the fence that keeps a source from running again,
  `hvi checkpoint-verify`, and on HVF (macOS) the whole capture and
  `hvi restore`: a guest moves from one hvi process to another on the same
  Mac and goes on where it was.
- **Does not work yet:** a KVM bundle cannot be restored. On KVM each vCPU's
  state is partial, and the interrupt controller and the guest counter are
  not captured. A bundle moves only between hosts on the same macOS build,
  CPU and hvi commit. [What is captured](#what-is-captured) has the details.

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
written by hvi 0.1.0 (4ea836ffa0bca2049ae80d3b601a50a19909e6ef), aarch64 on hvf
  profile.json             1478 bytes
  ram.bin              94359552 bytes
  ram.map                 16400 bytes
  cpu.json                 8597 bytes
  platform.json          180878 bytes
  devices.json             1180 bytes
  disk.json                 228 bytes
  session.json              108 bytes
  manifest.json            1873 bytes
RAM: 94359552 of 536870912 bytes present; 2 vCPU(s)
complete: every part a restore needs is captured
```

A bundle from a KVM host ends with `partial: vCPU registers, interrupt
controller and timer not captured, so no restore can resume this bundle`
instead.

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
| `cpu.json` | `{"version":1,"arch":"aarch64"\|"x86_64","vcpus":[...]}`. Registers by architectural name, values as `"0x..."` strings. Each vCPU says whether it is `partial`. See [The vCPU state](#the-vcpu-state). |
| `platform.json` | The interrupt controller (`irq`) and the guest counter (`timer`), each tagged with its `kind`, and an optional backend blob. See [The platform state](#the-platform-state). |
| `devices.json` | Every device's state, with a `null` for a device the guest does not have, and `irq_levels`: the level of each device's interrupt line at the capture, so a restore can drive the lines again. The virtio-blk state is version 2: version 1 had no `serial` and `read_only`, which it now records, so the restored disk answers `GET_ID` with the serial the guest read from `/sys/block/vdX/serial` at boot. A restore refuses version 1. |
| `disk.json` | Only when the guest has a disk: the path it was opened at, its size, `generation` (the writes and flushes since boot, which a restore carries on, so it only grows across moves), `synced: true`, and `sha256_sparse: null`, which whoever moves the disk fills in. |
| `session.json` | The sandbox id, `epoch`, `txid`, the capture time and `then`. |
| `manifest.json` | Every other file's name, size and SHA-256, the RAM regions with their present page counts, the SHA-256 of `profile.json`, the hvi build, `capabilities` (what a restore must be able to load: `hvf-gic-state-v1` on HVF, empty on KVM) and the seal time. |

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

### The vCPU state

An arm64 vCPU that ran is written whole on HVF:

```text
{"id":0,"power":"on",
 "regs":{"x0":"0x..",..,"x30":"0x..","sp_el0":"0x..","sp_el1":"0x..","pc":"0x..",
         "pstate":"0x3c5","fpcr":"0x0","fpsr":"0x0"},
 "simd":["<32 hex digits>", ... 32 of them, q0 first],
 "sysregs":{"SCTLR_EL1":"0x..",...,"MPIDR_EL1":"0x80000000"},
 "timer":{"vtimer_masked":false},
 "backend":"hvf","partial":false}
```

`sysregs` holds the EL1 and EL0 registers of `AARCH64_SYSREGS` in
`src/checkpoint/cpu.rs`: the MMU and exception registers, the thread
pointers, `CNTKCTL_EL1`, `CNTV_CTL_EL0` and `CNTV_CVAL_EL0`, the
pointer-authentication keys, `MDSCR_EL1`, `MDCCINT_EL1`, the 16 breakpoint
and 16 watchpoint register pairs, `ACTLR_EL1` and `MPIDR_EL1`. A register
the export fails to read fails the capture. Five are optional, because only
some hosts have them (SME, or new in macOS 15.2): `SCXTNUM_EL0`,
`SCXTNUM_EL1`, `TPIDR2_EL0`, `SMCR_EL1` and `SMPRI_EL1`. One the host
lacks is listed under `unavailable` instead. A vCPU in SME streaming mode or
with ZA storage on fails the capture: its Z, P and ZA registers have no place
in the schema.

A secondary the guest never started is `"power":"off"` with no registers.
One the guest sent a `CPU_ON` that its thread had not taken yet is
`{"pending_on":{"entry":"0x..","ctx":"0x.."}}`, and a restore starts it from
there. The KVM backends still write `"partial": true` with PC, PSTATE, SP_EL0,
SP_EL1, SCTLR_EL1, TCR_EL1, TTBR0_EL1 and TTBR1_EL1 on arm64, and RIP and
CR3 on x86-64.

### The platform state

| Section | `kind` | Written by | Holds |
| --- | --- | --- | --- |
| `irq` | `hv-gic-v3` | HVF | The GICv3 in canonical form: `dist` (`GICD_CTLR`, then `igroupr`, `isenabler`, `ispendr`, `isactiver`, `ipriorityr`, `icfgr` by register number from 0, and `irouter` by interrupt ID), `redist` and `icc` for each vCPU that ran, and `spi_count`. |
| `timer` | `arch-timer` | HVF | `counter_freq_hz`, `counter_at_capture` (the guest's `CNTVCT_EL0` as vCPU 0 saw it) and `host_monotonic_at_capture_ns`. |
| either | `not-captured` | KVM | `reason`. A restore refuses it. |

`backend_adjunct` carries HVF's own GIC state, the `hv_gic_state` blob,
as `{"kind":"hvf_gic_state","data_b64":...,"sha256":...}`. A restore on
HVF loads the blob, not the canonical registers, and only the same macOS build
is sure to load it. The canonical part is for a later import on another
backend. `GICR_CTLR` is not in `redist`: Hypervisor.framework has no call
that reads it. The portable profile adds the kinds `gicv2` and `hvi-time`.

## How the capture works

1. The control thread refuses what it can without pausing: the state, the
   root, the directory, the profile and its shares. It then creates the
   bundle directory.
2. It closes the I/O pause gate, so no host thread is inside a device or
   writing guest RAM. Then it parks every vCPU.
3. It asks every vCPU to export its state. Only a vCPU's own thread can read
   its registers on HVF and on KVM. So each vCPU does the export at its
   park point, out of the guest, and stays parked. A vCPU that was already
   parked by an earlier `pause` is woken to do it. On HVF the export also
   reads the vCPU's GIC redistributor and CPU interface, which only its own
   thread may read.
4. Once every vCPU has exported, it asks vCPU 0 for the platform, in a
   request of its own. The wait between the two requests is the barrier:
   the framework gives the `hv_gic_state` blob only while every vCPU is
   stopped, and vCPU 0 reads it, the distributor and the counter after all
   the others are done. A KVM vCPU 0 hands back nothing, and the platform
   is written as `not-captured`.
5. With everything still, it locks every device mutex and collects the device
   states. Then it checks them as a restore would. A state that a restore
   would refuse fails the capture here, before any file is written, while the
   guest can still run on. The vsock device is the one that can reach such a
   state, with more connections or waiting packets than a restore takes.
6. It syncs the disk image with `fdatasync`.
7. It writes the profile, RAM, the vCPUs, the platform, the devices, the disk
   and the session, then seals the manifest.
8. It replies, then resumes the VM, or keeps it parked for `fence`.

Steps 2 to 4 share one 2 s deadline. A vCPU that starts during the capture,
after the wait for the exports ended, fails it with `capture_failed`, since it
is neither off nor exported; the caller can try again. A stop of the run during the capture
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

| Part | HVF (macOS) | KVM (Linux) |
| --- | --- | --- |
| Guest RAM | Whole, without zero pages. | The same. |
| Device state | Whole: virtio-blk, virtio-net and virtio-vsock queues and registers, and the PL011. | The same, with the 16550 and the CMOS RTC on x86-64. |
| Disk | Synced, with its size and generation. The image itself is not in the bundle; whoever moves the sandbox moves the disk. | The same. |
| vCPU registers | Whole. See [The vCPU state](#the-vcpu-state). | **Partial**: the plugin register view. A register the backend could not read is 0. |
| A secondary the guest never started | `off`, or `pending_on` with the entry and context of the `CPU_ON` it had not taken. | Every KVM vCPU starts at once. |
| Interrupt controller | The `hv_gic_state` blob, and the GICv3 registers in canonical form. | **Not captured.** |
| Guest counter | The counter at the capture. | **Not captured.** |

A restore refuses a vCPU marked `partial` and a `not-captured` section.
`hvi checkpoint-verify` reports both. Dirty tracking for pre-copy rounds and
a dirty-sector bitmap for the disk come later.

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

## Restoring a bundle

```sh
hvi restore --from /var/lib/sb1/checkpoints/tx-42 \
    --control-sock /run/sb1/ctl-2.sock --checkpoint-root /var/lib/sb1/checkpoints \
    --disk root.img --net-stub --agent-sock /run/sb1/agent-2.sock
```

The flags are in [cli.md](cli.md#restore). The machine comes from the bundle.
The flags name what it needs from this host, and must match what the guest
had: `--disk` when it had a disk, the network mode it ran on, and
`--agent-sock` when it had a vsock device. The restored guest comes up
paused. `status` reports `restored-paused`, and the guest runs once a client
sends `resume`. `stop` ends it without it ever running. A checkpoint of a
restored guest works as of any other, so a guest can move again.

A restore runs these steps, in this order:

1. **Refuse or go on.** It opens the bundle and checks it as
   `checkpoint-verify` does. It then lists every reason this host cannot
   resume it, and stops with all of them before it creates anything:
   - a vCPU state that is partial or not whole;
   - an interrupt controller or counter `kind` this backend has no import
     for, or a missing GIC blob or capability;
   - more vCPUs than the host's VMs take, or RAM that is not one region at
     `0x40000000` in whole host pages;
   - flags that do not match the devices: a disk missing, extra or of
     another size, another network mode or MAC, an agent socket missing or
     extra;
   - every difference between the bundle's machine profile and this host's,
     which it builds as a boot does. RAM, the vCPU count and the devicetree
     digest come from the bundle, since the restore loads no kernel and
     builds no devicetree: guest RAM holds both. `MIDR_EL1` is readable only
     on a vCPU's thread, so vCPU 0 compares it as soon as it exists, before
     anything is loaded.
2. **The machine.** It creates the VM and its GIC as a boot does, maps RAM of
   the bundle's size and copies the image in.
3. **The devices.** It rebuilds virtio-blk over the reopened disk,
   virtio-net over the network the flags give, virtio-vsock and the PL011,
   each from its state. Each device's line level must be the one
   `devices.json` recorded. It then ends the vsock connections, whose host
   end stayed on the source: the guest sees each one reset. The agent
   bridge, the control socket and the profile file are bound or created
   before Seatbelt, as at boot. A `--net-gateway` that cannot be reached is
   an error. A boot falls back to the stub stack instead, but the restored
   guest already holds an address on the gateway's network.
4. **Confinement.** Seatbelt goes on with the same rules as at boot. Every
   file the restore reads is read before this, so a restore needs no allow a
   boot does not have.
5. **The vCPUs.** The I/O threads are held at the pause gate, and the vCPUs
   by the control socket, before any thread starts. The vCPU threads create
   their vCPUs in index order, as at boot: the framework numbers vCPUs as
   they are created, and the GIC blob may hold per-vCPU state by that
   number. Each one that ran parks at its first checkpoint. A secondary that
   was off waits for its `CPU_ON`, and one that was `pending_on` starts from
   a refilled mailbox. The control thread waits until every vCPU exists,
   the ones that were off as well, and every one that ran or was
   `pending_on` is parked. It then posts three import steps, and waits for
   every vCPU between them:
   - **A.** Each vCPU loads its registers, SIMD registers, system
     registers and vtimer mask.
   - **B.** vCPU 0 loads the GIC from the blob with `hv_gic_set_state`. All
     vCPUs exist by now and none has run, as the framework requires.
   - **C.** Each vCPU loads its ICC registers, which the blob does not hold.
6. **The lines.** `hv_gic_set_state` sets the GIC's view of every line, so
   each device line is driven again, to the device's level.
7. **Restored-paused.** The I/O threads start, held at the gate, and the
   control socket reports `restored-paused`. `resume` releases the vCPUs
   and then the I/O threads.

A failure after step 1 stops everything that started and exits 1 with the
reason. Nothing is written to the bundle or the disk before the guest runs.

### Timings

Measured with `tools/checkpoint-e2e.sh` on an Apple M5 Pro running macOS
26.7, with an ext4 disk, the stub network and an agent socket. Four runs of
each, the range given. Each stat is defined in the script:

| Guest | `pause_ms` | `capture_ms` | Bundle | Restore to restored-paused | Checkpoint request to resume reply |
| --- | --- | --- | --- | --- | --- |
| 2 vCPUs, 512 MiB | 2 to 3 | 251 to 341 | 92 to 95 MB | 347 to 393 ms | 606 to 743 ms |
| 1 vCPU, 1024 MiB | 3 to 5 | 378 to 586 | 104 MB | 388 to 413 ms | 776 to 989 ms |

The fence reply to the resume reply is the restore's time plus well under a
millisecond: the script starts `hvi restore` as soon as the fence replies.

The restore's time is mostly reading the bundle twice: `Bundle::open` hashes
every component, and the copy of RAM hashes `ram.bin` again as it reads it.
`resume` replies in under a millisecond.

## Clock policy

The guest's counter continues from the captured value. On HVF, the capture
records `CNTVCT_EL0` as vCPU 0 sees it, `mach_absolute_time()` less its
vtimer offset. A restore fixes one vtimer offset for every vCPU when the
first vCPU is about to enter the guest after `resume`, so that `CNTVCT_EL0`
goes on from `counter_at_capture`. Neither the time the guest was away nor
the time it waited restored-paused shows on its counter. A secondary the
guest brings up later gets the same offset. The policy is:

- **The monotonic clock continues.** `CLOCK_MONOTONIC` and the uptime go on
  from the capture.
- **Deadlines that passed fire.** A timer whose deadline passed while the
  guest was away fires on the first entry after the restore.
- **The wall clock is not corrected.** `CLOCK_REALTIME` goes on from the
  captured time too, so the guest's clock is behind the host's by the time
  it was away. Nothing corrects it until the guest's own time sync does:
  hvi has no guest agent to set it, and hull's `/urunc-epoch` only sets the
  boot time.

QEMU behaves the same way by default, when it is run without `-rtc
clock=host` for the monotonic counter. A `pause` alone does not stop guest
time: the counter runs on through it. The KVM backends do not capture the
counter yet.

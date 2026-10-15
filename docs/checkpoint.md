# Checkpoints

A checkpoint captures a running guest into a bundle: a directory that holds
its RAM, its vCPUs, its devices and the machine it was built against.
`hvi restore` resumes the bundle in another hvi process on a compatible host,
and the guest runs on there without rebooting.

This page says what works today and what does not.

- **Works:** the bundle format, the capture on the control socket on all
  three backends, the fence that keeps a source from running again,
  `hvi checkpoint-verify`, live moves (the `migrate` op streams a guest
  while it runs, see [Live moves](#live-moves)), and `hvi restore`:
  - on HVF (macOS), a native guest moves from one hvi process to another on
    the same Mac and goes on where it was;
  - a guest of the portable profile (`--profile portable-arm64-v1`, see
    [portable-profile.md](portable-profile.md)) does the same on the Mac and
    on arm64 KVM (a Raspberry Pi 5), and its bundle is the same on both, so
    `hvi restore` takes a bundle of either backend on either. See
    [Moving between hosts](#moving-between-hosts);
  - the disk's written blocks can be read and streamed while the guest
    runs, and applied onto a copy of the image it booted from. See
    [Moving the disk by its blocks](#moving-the-disk-by-its-blocks).
- **Does not work yet:** a native KVM bundle cannot be restored: its vCPUs
  are whole, but the vGICv3 and the counter are not captured. A native HVF
  bundle moves only between hosts on the same macOS build, CPU and hvi
  commit. x86-64 vCPUs are still partial. [What is captured](#what-is-captured)
  has the details.

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
| `refused` | No checkpoint root, a `dir` outside it, a `dir` that is not empty or goes through a link, or a guest with virtio-fs shares. | Untouched: nothing was paused. |
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
- A second `checkpoint`, or a `migrate`, is refused with `fenced`.
- `stop` ends the run as usual.

The fence holds only while this hvi process lives. It is not written
anywhere. A caller that must survive a crash of the source records the fence
itself.

A fenced source also releases the lock it holds on its disk (see
[The disk lock](#the-disk-lock)). Its guest never runs again, so it never
writes the disk again, and the restore can open the disk before the source
is stopped.

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

A native bundle from an arm64 KVM host ends with `partial: interrupt
controller and timer not captured, so no restore can resume this bundle`
instead, and one from x86-64 with `partial: vCPU registers, interrupt
controller and timer not captured, ...`.

```text
hvi: /var/lib/sb1/checkpoints/tx-42: ram.bin: SHA-256 does not match the manifest
```

## The bundle format

The bundle directory is `checkpoint_format` 1; the stream of a live move
is format 2, or 3 when it carries the disk's rounds (see [The stream
format](#the-stream-format)), with the same documents. A profile gives the
newest format its hvi writes, now 3, so a mover can tell an hvi whose
stream carries the disk and whose fenced source streams again for its
fence owner; a directory may hold a profile of any of them. Every document is JSON with fields by name and a
`version`. No file holds a native struct layout, so a bundle does not depend
on the byte layout of the build that wrote it.

| File | Holds |
| --- | --- |
| `profile.json` | The source's machine profile. See [cli.md](cli.md#the-control-socket). |
| `ram.bin` | The pages of guest RAM that are not all zero, region by region, in address order, with nothing between them. |
| `ram.map` | A 16-byte header (`HVIRAM01`, a little-endian `u32` page size of 4096, a little-endian `u32` region count), then one bitmap per region. Bit `i` is bit `i % 8` of byte `i / 8`. 1 means page `i` is the next page in `ram.bin`, and 0 means the page is all zero. |
| `cpu.json` | `{"version":1,"arch":"aarch64"\|"x86_64","vcpus":[...]}`. Registers by architectural name, values as `"0x..."` strings. Each vCPU says whether it is `partial`. See [The vCPU state](#the-vcpu-state). |
| `platform.json` | The interrupt controller (`irq`) and the guest counter (`timer`), each tagged with its `kind`, and an optional backend blob. See [The platform state](#the-platform-state). |
| `devices.json` | Every device's state, with a `null` for a device the guest does not have, and `irq_levels`: the level of each device's interrupt line at the capture, so a restore can drive the lines again. |
| `disk.json` | Only when the guest has a disk: the path it was opened at, its size, `generation` (the writes and flushes since boot, which a restore carries on, so it only grows across moves), `synced: true`, `sha256_sparse: null`, which whoever moves the disk fills in, and for a move by blocks `base_sha256`, `block_size`, `dirty_since_boot_b64` and `rounds`. See [Moving the disk by its blocks](#moving-the-disk-by-its-blocks). |
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
there. The pointer-authentication keys are optional too: a KVM vCPU has
them only with PAuth, which hvi does not give it.

On arm64 KVM each vCPU writes the same document, by the same names. KVM
names a register by a `KVM_GET_REG_LIST` id, and
[The KVM registers](#the-kvm-registers) says what each id becomes. Beside the
registers, a KVM vCPU records:

```text
 "mp_state":"runnable",
 "firmware":{"PSCI_VERSION":"0x10001","SMCCC_ARCH_WORKAROUND_1":"0x2",...},
 "fixed":{"OSLSR_EL1":"0x8","DISR_EL1":"0x0","CNTP_CTL_EL0":"0x4","CNTP_CVAL_EL0":"0x0"},
 "events":{"serror_pending":false,...},   (only when one is pending)
 "unavailable":["APIAKEYLO_EL1",...,"SMPRI_EL1"],
 "timer":{"vtimer_masked":false},
 "backend":"kvm"
```

A stopped KVM vCPU (`KVM_MP_STATE_STOPPED`) is written `"power":"off"`, as
on HVF. A register KVM lists that hvi has no rule for fails the capture.
The x86-64 backend still writes `"partial": true` with RIP and CR3.

### The KVM registers

Every id a Raspberry Pi 5's KVM lists (Linux 6.12.25, 259 ids, the same for
a native and a portable vCPU; the fixture is
`src/checkpoint/testdata/kvm-reg-list-rp2.txt`) is in one of four classes,
which `src/checkpoint/kvm_regs.rs` encodes. An id outside every rule is
refused, and a test checks that no id of the fixture is.

| Class | Ids | In `cpu.json` | On import |
| --- | --- | --- | --- |
| shared (160) | core `x0`..`x30`, `sp` (`sp_el0`), `pc`, `pstate`, `sp_el1`, `elr_el1` and `spsr[0]` (`ELR_EL1`, `SPSR_EL1`), `vregs` (128-bit, `q0`..`q31`), `fpsr`, `fpcr`; system registers by encoding: `SCTLR`, `ACTLR`, `CPACR`, `TTBR0/1`, `TCR`, `AFSR0/1`, `ESR`, `FAR`, `PAR`, `MAIR`, `AMAIR`, `VBAR`, `CONTEXTIDR`, `TPIDR_EL1`, `CNTKCTL`, `CSSELR`, `TPIDR_EL0`, `TPIDRRO_EL0`, `MDSCR`, `MDCCINT`, `DBGBVR/BCR/WVR/WCR0..15`, `MPIDR_EL1`; the timer's `TIMER_CTL` (`CNTV_CTL_EL0`) and `TIMER_CVAL` (`CNTV_CVAL_EL0`, under the encoding of `CNTVCT_EL0`, which the UAPI swapped) | `regs`, `simd`, `sysregs` by name | Written by name. `MPIDR_EL1` is compared: KVM sets it from the vCPU index. |
| set-by-baseline (88) | the ID registers `(3,0,0,*,*)`, `MIDR_EL1`, `REVIDR_EL1`, `AIDR_EL1`, `CLIDR_EL1`, `CTR_EL0`, the 14 `CCSIDR_EL1` demux ids; `TIMER_CNT` and `CNTPCT_EL0` (the counter); `TCR2_EL1`, `PIRE0_EL1`, `PIR_EL1` (features `ID_AA64MMFR3_EL1` hides); the AArch32 state `spsr[1..4]`, `DACR32_EL2`, `IFSR32_EL2`, `FPEXC32_EL2`, `DBGVCR32_EL2` (the baseline offers AArch64 only) | Not written | Not written: the portable baseline, the profile check or the counter offset gives them. |
| checked-equal-on-import (11) | the firmware registers `PSCI_VERSION`, `SMCCC_ARCH_WORKAROUND_1/2/3`, `STD_BMAP`, `STD_HYP_BMAP`, `VENDOR_HYP_BMAP`; `OSLSR_EL1`, `DISR_EL1`, `CNTP_CTL_EL0` (ENABLE and IMASK), `CNTP_CVAL_EL0` | `firmware`, `fixed` | The destination's value must equal the recorded one, or, for a state from HVF, the value a guest there sees. Workaround 2 reads 0 natively and 3 (not required) once the baseline hides SSBS; hvi on the Mac answers as the latter. |
| refused (0 on the Pi) | anything else, such as SVE or PMU registers | | The capture fails; a restore on a host that lists one refuses. |

The other direction: `AARCH64_SYSREGS` names 15 registers a portable KVM
vCPU does not have, the 10 pointer-authentication keys, `SCXTNUM_EL0/1`,
`TPIDR2_EL0`, `SMCR_EL1` and `SMPRI_EL1`. A KVM export lists them under
`unavailable`, and an HVF import leaves them at their reset value. A KVM
import of an HVF state drops them only when they hold 0, as each does for a
portable guest on HVF (measured on an M5 Pro), since the baseline hides
their features; one that holds anything else is refused. A firmware
answer, a fixed register or a pending SError from KVM that an HVF guest
could not have is refused by the HVF import.

### The platform state

| Section | `kind` | Written by | Holds |
| --- | --- | --- | --- |
| `irq` | `hv-gic-v3` | HVF | The GICv3 in canonical form: `dist` (`GICD_CTLR`, then `igroupr`, `isenabler`, `ispendr`, `isactiver`, `ipriorityr`, `icfgr` by register number from 0, and `irouter` by interrupt ID), `redist` and `icc` for each vCPU that ran, and `spi_count`. |
| `timer` | `arch-timer` | HVF | `counter_freq_hz`, `counter_at_capture` (the guest's `CNTVCT_EL0` as vCPU 0 saw it) and `host_monotonic_at_capture_ns`. |
| either | `not-captured` | KVM, native | `reason`. A restore refuses it. |
| `irq` | `gicv2` | HVF and KVM, portable | The portable profile's GICv2 in canonical form (`Gicv2State`, see [portable-profile.md](portable-profile.md#2-interrupt-controller)): on HVF the software model's state, on KVM the vGICv2's with the line levels hvi's devices hold. |
| `timer` | `hvi-time` | HVF and KVM, portable | The portable profile's `hvi-time` state (`HviTimeState`, see [portable-profile.md](portable-profile.md#restore)), with `counter_at_capture`, the guest's raw counter at the capture. |

`backend_adjunct` carries HVF's own GIC state, the `hv_gic_state` blob,
as `{"kind":"hvf_gic_state","data_b64":...,"sha256":...}`. A restore on
HVF loads the blob, not the canonical registers, and only the same macOS build
is sure to load it. The canonical part is for a later import on another
backend. `GICR_CTLR` is not in `redist`: Hypervisor.framework has no call
that reads it.

For a portable guest vCPU 0 reads `hvi-time` frozen, so no timer fires
between its state and the GIC's. A guest that goes on after the capture
(`then: "continue"`, or a failed capture) thaws it: a deadline that came due
meanwhile fires then, and nothing is published.

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
   the others are done. On the portable profile vCPU 0 reads the GICv2
   (the software model on HVF, the vGICv2 on KVM) and `hvi-time`. On native
   KVM vCPU 0 hands back nothing, and the platform is written as
   `not-captured`.
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
| Disk | Synced, with its size, generation, base digest, the blocks written since boot and the rounds read. The image itself is not in the bundle; whoever moves the sandbox moves the disk, whole or by its blocks. | The same. |
| vCPU registers | Whole. See [The vCPU state](#the-vcpu-state). | arm64: whole, by the same names, with the firmware and fixed registers and `mp_state`. x86-64: **partial**, the plugin register view. |
| A secondary the guest never started | `off`, or `pending_on` with the entry and context of the `CPU_ON` it had not taken. | `off` when KVM reports it stopped. PSCI is KVM's: a vCPU whose `CPU_ON` KVM has not served yet still holds its initialisation registers (pc 0), and the capture fails until the guest has run again. One turned off and being turned on again is not seen (`portable-profile.md`, Limits). |
| Interrupt controller | Native: the `hv_gic_state` blob, and the GICv3 registers in canonical form. Portable: the software GICv2's state. | Portable: the vGICv2 in canonical form. Native: **not captured**. |
| Guest counter | Native: the counter at the capture. Portable: `hvi-time`'s state and the raw counter. | Portable: the same. Native: **not captured**. |

A restore refuses a vCPU marked `partial` and a `not-captured` section.
`hvi checkpoint-verify` reports both. Dirty tracking for pre-copy rounds of
guest RAM comes later; the disk's written blocks are tracked, see
[Moving the disk by its blocks](#moving-the-disk-by-its-blocks).

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

hvi does not consume a bundle. It restores a sealed bundle as often as it
is asked to, a `then: "continue"` snapshot as well as a fenced one, and it
records nothing in the bundle. The caller makes sure a guest runs in one
place only: it restores a bundle once, and only once the source is fenced or
stopped.

### The disk lock

Two guests that write one disk image corrupt its filesystem. Each hvi holds
an exclusive `flock` on its `--disk` while its guest may write it, from the
open at boot or restore until the process exits, or until a fenced
checkpoint releases it. A boot or restore whose disk another process holds
locked fails with `virtio-blk: PATH is locked by another process`. So a
second restore of one bundle onto the disk a restored guest runs on fails,
and so does a restore of a `then: "continue"` snapshot while its source
still runs.

The lock is advisory. It keeps out another hvi, not a program that writes
the image without taking it. A regular file or a block device is locked; a
filesystem that has no `flock` leaves the disk unlocked, and hvi says so on
stderr. The lock is held on a second open of the disk, so the fence releases
it by closing that open, which needs no call the sandbox would have to allow.

### The steps

The steps below are the native HVF restore's. The portable profile's
differ where its machine does, on HVF and on KVM: see
[The portable restore](#the-portable-restore). A restore runs these steps,
in this order:

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

### The portable restore

A bundle of the portable profile restores on HVF and on arm64 KVM, from
either. The refusals of step 1 are the same, and for a profile check
`compatible_with` compares what the portable machine fixes instead of the
host: the profile name, the hvi commit, the CPU baseline, the GICv2 and
`hvi-time` (not the counter rate), the RAM, the vCPU count, the device map,
the PSCI version, the devicetree digest and the agent socket. A restore
loads no kernel, so its devicetree digest is the bundle's: equal digests
across hosts are a check of the two boots, which give the same devicetree
for the same inputs (`portable-profile.md`). Each backend then runs the host
check of a portable boot: on HVF that the host can back the baseline,
before any vCPU exists; on KVM `kvm_host_problems` (a vGICv2, 4 or 16 KiB
pages, 40-bit IPA, the baseline within what KVM can lower), once the VM and
its vCPUs exist and before any runs. A native bundle of the other backend
is refused for its backend.

- **HVF.** No `hv_gic`: the VM gets the software GICv2, `hvi-time`'s page
  mapped read-only, and the baseline on every vCPU, as a portable boot does.
  The guest's counter offset is fixed before the vCPUs are created (see
  [Clock policy](#clock-policy)). Steps A to C run as above, but vCPU 0
  loads the software GICv2 from the canonical state in step B, and step C
  has nothing to load.
- **KVM.** The VM and the vGICv2; every vCPU created and initialised in
  index order, one that was off powered off; the host check and the
  baseline and firmware registers, as at boot, before guest RAM is copied
  and the disk opened; then RAM and the devices as above; the counter
  offset and `hvi-time`'s read-only memory slot; the vGIC's `NR_IRQS` and
  init. Before any vCPU thread starts, each vCPU loads its state with
  `KVM_SET_ONE_REG` by name, its `mp_state` and any pending SError, and the
  vGIC loads the canonical state, every register read back
  (`kvm_state::load_portable`). KVM has no rule that a vCPU's own thread
  load it, so the main thread does, before the seccomp filters go on.

Then, on both, each device's line is driven to the device's level, and the
device's record of its line with it: loading the interrupt controller sets
every line behind the devices' backs. The vCPUs and the I/O threads are held
before they start, and the control socket reports `restored-paused`. The
first vCPU to enter the guest after `resume` publishes `hvi-time`'s page,
and every other vCPU waits for it before its own first entry. A checkpoint
of the guest before that writes the state waiting to be published, which is
the guest's, since it has not run.

### Moving between hosts

The portable profile is the one that moves between hosts: the Mac and a
Pi present the same machine, and the bundle holds only canonical state.
Copy the bundle and the disk to the destination and run `hvi restore`
there with the same flags. What carries over:

- **The vCPUs**, by register name, with the classes of
  [The KVM registers](#the-kvm-registers): what one backend has and the
  other lacks is either set by the machine, compared, dropped at 0 under
  the baseline, or refused.
- **The interrupt controller**, through the canonical GICv2 state. Two
  things are lost on the way through KVM's register view: a level interrupt
  whose latch and line are both set comes out with the line only, and the
  vGICv2's SGI active source is not carried.
- **The clock**, through `hvi-time`: guest `CLOCK_MONOTONIC` goes on from
  the capture at the destination's counter rate, and the wall clock moves to
  the host's. The guest's raw counter is not continuous across rates, but
  the destination's starts no lower than the capture's, scaled to its rate.

The bundle's hvi commit must equal the destination's, so build both hosts
from one commit, with no uncommitted changes: a build with them is refused
on either side, as for the native machine.

Run so far: a portable bundle restored on the host that took it, on the
Mac and on a Pi 5 (`tools/checkpoint-e2e.sh --portable`), and moves each
way between an Apple M5 Pro and a Pi 5 by hand: a 1-vCPU, 512 MiB guest
with an ext4 disk and the stub network, fenced, copied with `rsync --sparse`
(the bundle is 95 MB) and restored with the same flags, under Seatbelt and
seccomp.

The first pair of moves ran before a fix to the restore on the Mac, which
loaded every SIMD register with whatever the host's `v0` held (fixed in
`0c178e0`). The Pi to Mac move of that pair lost the guest's live SIMD
registers. Its checks did not show it: the `awk` sum stayed exact, because
the guest kept the sum in memory.

Each move was run again on `9880f4d`. Before the resume, the restored guest
was checkpointed again while restored-paused, and that state was compared
with the bundle's. The general, SIMD and system registers were equal,
including the non-zero `q` registers (`q0`-`q3` and `q9` from the Mac,
`q1`-`q3` from the Pi). The 15 registers only HVF has read 0 on the Mac in
both directions, and are not carried. The GICv2 and `hvi-time` state was equal too. After the
resume, in both directions:

- the guest's count went on by one, and no boot banner appeared;
- a 6 s timerfd armed before the capture fired 6.00009 s (to the Pi) and
  6.00007 s (to the Mac) of guest time after it was armed;
- `el0check` passed, the clocksource stayed `hvi-time`, and the driver
  logged generation 4 at the destination's rate (24 MHz to 54 MHz and back)
  with `migrations=1`;
- the file held open after its unlink stayed readable, the file written
  before the move was on the disk, and a write after it worked.

The downtime was mostly the copy: 174 s from the Mac to the Pi over the
tailnet, and 19 s back.

`tools/migrate-e2e.sh` now runs these moves and their checks, each way and
on one host, with the guest's clocks read against each host's, its
interrupts and `Features` line compared, a 10-minute drift window and the
refusals. On one LAN a move took 4.6 s from the fence request to the
resume reply each way, 3.2 to 3.4 s of it the copy. See
[portable-profile.md](portable-profile.md#measured-results) for the figures
and [testing.md](testing.md#the-migration-end-to-end-test) for the script.

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

Those figures were taken while the restore still read the bundle twice:
`Bundle::open` hashed every component, and the copy of RAM hashed
`ram.bin` again as it read it. A restore now opens the bundle with
`Bundle::open_for_restore`, which checks only the size of `ram.bin`, and
the copy is its one read and its hash check; a changed byte is refused
there, before any device, disk or socket exists, with the same
`SHA-256 does not match the manifest`. `hvi bundle verify` still hashes
everything. On the same Mac, 2 vCPUs and 512 MiB, one run each: restore to
restored-paused 196.0 ms native and 199.6 ms portable, against 525.7 and
538.9 ms before the change. `resume` replies in under a millisecond.

## Live moves

A checkpoint stops the guest for as long as it takes to write all of its
RAM. A live move stops it only for what it wrote last: the source sends its
RAM in rounds while the guest runs, then pauses it for the final round and
its state. When the guest's disk has a base image the destination holds
(`--disk-base-sha256`, see [Moving the disk by its
blocks](#moving-the-disk-by-its-blocks)), the disk's written blocks travel
in the same rounds. The control socket's `migrate` op does it, on the
connection that asked, since a confined hvi may write to a socket it
accepted but cannot open a new one:

```text
{"v":1,"op":"migrate","then":"fence","txid":"tx-43","epoch":8}
```

hvi then writes the stream (see [The stream format](#the-stream-format))
on that connection and, after its manifest, the reply line:

```json
{"v":1,"ok":true,"state":"fenced","manifest_sha256":"...","stats":{
 "rounds":[{"round":0,"in_pause":false,"pages":25920,"data_pages":24022,"bytes":35800360,"ms":165,"dirty_pages_per_s":0},
           {"round":1,"in_pause":true,"pages":844,"data_pages":635,"bytes":408967,"ms":2,"dirty_pages_per_s":4948}],
 "stop_reason":"converged","threshold_bytes":8388608,"precopy_ms":170,
 "pause_ms":0,"gate_ms":0,"park_ms":0,"paused_ms":6,
 "final_round_bytes":408967,"ram_total_bytes":536870912,"ram_present_bytes":98394112,
 "ram_raw_bytes":100995072,"ram_stream_bytes":36209327,"stream_bytes":36237937,
 "disk_rounds":[{"name":"disk-round-0","round":0,"in_pause":false,"blocks":5,"raw_bytes":327680,"bytes":5955,"ms":0,"generation":22,"max_lock_us":5},
                {"name":"disk-round-final","round":1,"in_pause":true,"blocks":0,"raw_bytes":0,"bytes":0,"ms":0,"generation":22,"max_lock_us":0}],
 "disk_raw_bytes":327680,"disk_stream_bytes":5955,"disk_sync_ms":4,"pause_sync_ms":1,
 "write_granule":16384,"write_faults":257,"write_fault_ns":2481,
 "rounds_end_unix_ms":1792036700119,"precopy_end_unix_ms":1792036700123,
 "sealed_at_unix_ms":1792036700129}}
```

`pause_ms` is the time from the pause to every vCPU parked with its state
exported; `gate_ms` and `park_ms` are its first two parts, the I/O threads
held and the vCPUs parked. `paused_ms` is the time from the pause to the
manifest written: the source's part of the downtime. The rest is the
transport and the destination's restore. `rounds_end_unix_ms` is when the
last round with the guest running ended. `disk_sync_ms` is the sync of the
disk after it and just before the pause, with the guest still running,
and `precopy_end_unix_ms` is taken after that sync, at the pause; it
included the sync from the build that added the sync on, so a consumer
that took it as the end of the rounds now reads the end of the sync.
`pause_sync_ms` is the second sync, in the pause before disk.json, and
is part of `paused_ms`. A `migrate` needs no
`--checkpoint-root`, since it writes no file. It refuses, before the first
frame and with the VM untouched, what a `checkpoint` refuses, and a backend
that keeps no record of the guest's writes.

### The rounds

Round 0 sends every page that is not zero, with the guest running; a run
of 64 zero pages is left out, since fresh RAM on the destination is zero.
Each later round sends the pages written during the round before, from two
records, ORed into one set of 4 KiB pages:

- **The guest's own stores.** On KVM, every RAM slot is registered again
  with `KVM_MEM_LOG_DIRTY_PAGES` when the move starts (a flags-only change,
  which KVM takes while the vCPUs run), and each round reads
  `KVM_GET_DIRTY_LOG`, which returns and clears the log and write-protects
  the pages again. On Hypervisor.framework, which keeps no dirty log, hvi
  write-protects guest RAM with `hv_vm_protect`; a store to a protected
  granule exits to the vCPU's thread as a data abort, and hvi records the
  granule, makes it writable and lets the store run again. Each round
  protects again the granules recorded. The record and the protection
  change under one lock, so no granule is writable without being recorded.
  Both count in their own unit, the host page on KVM (16 KiB on a
  Raspberry Pi 5's kernel) and the IPA granule on HVF (16 KiB on Apple
  silicon), and each one written adds all its 4 KiB pages.
- **hvi's own writes.** A virtio device fills guest buffers and used rings
  from host threads, which no hypervisor sees. Guest RAM keeps a log, one
  atomic bit per 4 KiB page, that every write accessor marks after it
  writes, so a round that takes the mark reads the written bytes.

The rounds with the guest running stop when the pages written during the
last one come to at most 8 MiB or 2% of the RAM round 0 found present,
whichever is larger (`converged`), after 5 rounds (`round_cap`), or when a
round ends 60 s or more after the start (`time_cap`); `max_rounds` and
`max_secs` on the request change those two. The time cap is checked only
as each round ends, so a round under way runs to its end: a large round 0
behind a slow reader can take longer than `max_secs` on its own. A guest
that writes faster than the rounds copy never converges: the round cap
ends it, and its final round is as large as what it writes in one round,
so the pause lasts as long as that takes to send. The final round is
always taken paused.

With a disk base, each round `k` taken with the guest running sends disk
round `k` before RAM round `k`: round 0 the blocks written since boot,
which are every block that differs from the base, each later round the
blocks written since the disk round before. The blocks are read through
the device's lock one block at a time, so the guest's disk waits for one
64 KiB read at most (`max_lock_us`), and a block the guest writes while it
is read is in the next round either way. Whether the rounds converge is
judged by RAM alone.

### The pause

When the rounds with the guest running end, the source:

1. Syncs the disk with `fdatasync` on a second handle to the device's
   file, without the device's lock, while the guest still runs. The sync in
   the pause then has only the writes since; with it inside the pause, a
   busy Pi spent up to 4.9 s of downtime on it.
2. Holds the I/O threads and parks the vCPUs, waiting up to 10 s for both,
   and then up to 10 s for the vCPUs' state. A `pause` op waits 2 s; a
   move waits longer because a vCPU parks only between guest entries, and
   one serving a virtio-blk flush is in an `fdatasync` on its own thread
   until the flush ends (see [limitations.md](limitations.md)). A move
   that still misses the bound fails, and the VM runs on.
3. Sends the final disk round, the blocks written since the last one, then
   the final RAM round, the pages left and every page written since, then
   the documents, with nothing running. `disk.json` is captured after the
   final disk round, so it lists every disk round with the digests of what
   the stream carried, and its last round's generation is the disk's.

Only the control thread writes the stream. A slow reader holds it up, and
the guest runs on meanwhile; the pause starts once the last round with the
guest running is written. A reader that stops taking the stream without
closing the connection is not waited for without end, since it would hold
the control socket and, in the final round, a paused guest:

- Any write that waits 30 s for the reader to take a byte fails the move.
- From the moment the vCPUs are parked with their state in hand, the rest
  of the stream must be written within 10 s plus twice the time the last
  round with the guest running took, its disk round included. The final
  round holds what the guest wrote during that round, to RAM and to the
  disk, so a reader that kept up with it keeps up with this one. A slow park does not count against it, since nothing is
  written while the vCPUs park.

Either failure leaves the VM as the request found it, as any failure before
the manifest does: running, and not fenced. The reply then waits at most
2 s for room, and the connection is closed if it does not fit. A zero page in a later round is sent as a clear
bit, and the destination zeroes it where an earlier round wrote it.

### The fence of a live move

A failure before the manifest leaves the VM as the request found it, and
the client reads it as a reply line where the next frame header was due.
`then: "fence"` fences once the manifest is written to the connection,
which is before the client has read it, and releases the disk's lock at
once, since the destination may open the disk as soon as it has the
manifest. So a client that reads the end of the connection before the
manifest knows the source runs on, unfenced; one that has the manifest
knows it is fenced.

The destination may run the guest as soon as it has the manifest, so a
fenced VM is streamed again only for the move that fenced it. A `migrate`
on a fenced VM with the same `txid` and `epoch` as the one that fenced it,
and `then: "fence"`, streams the sealed state again: the mover that died
after hvi's manifest went out and before it had kept a whole copy
recovers it this way. The VM stays fenced. The stream is the final round
alone:

- with disk rounds, one disk round, `disk-round-final`, of every block
  written since boot, read from the disk the fence left;
- one RAM round, taken paused, of every page that is not zero, which is
  the RAM the first stream carried, since nothing has run since;
- `profile.json`, `cpu.json`, `platform.json`, `devices.json` and
  `session.json` as the first stream sent them, byte for byte, and
  `disk.json` written again for its one disk round (as first sent, when
  the stream has no disk rounds);
- a manifest of its own.

The stream sent again moves the same machine as the first: applied to
fresh RAM and another copy of the base, it gives the RAM and the disk
the first stream gives, which are the source's at the fence, though the
guest wrote both during the first stream's rounds. Its manifest is not
the first one's and its SHA-256 never equals the first's: the first
stream's RAM rounds and disk rounds are gone, so this one carries RAM
in one round and the disk in one round, and is sealed at another time.
A mover therefore does not compare whole manifests. It compares the
SHA-256 that each manifest lists for `profile.json`, `cpu.json`,
`platform.json`, `devices.json` and `session.json`, taken from the first
manifest it kept, with the ones the new manifest lists: they are always
equal. The reply carries `first_manifest_sha256`, the first stream's
manifest, and `same_as_first`, the components whose size and SHA-256
equal the first stream's: those five documents, and RAM round 0 too
when the guest wrote nothing during the first move. hvi computes
`same_as_first` itself, so it is a report, not a check a mover can rely
on.

hvi streams the state again as often as the fence owner asks, so a
mover may retry its recovery. It cannot know whether the first
destination resumed the guest: the mover must make sure the first
destination is gone, or never resumed, before it restores a stream
sent again, or two hosts run the guest.

Only the stall bound applies to the reader; the guest is not waiting.
Any other `txid` or `epoch`, a request that leaves out `txid` or `epoch`
(a missing epoch is not epoch 0), `then: "continue"`, a VM a
`checkpoint` fenced, or one a `migrate` fenced without both a `txid` and
an `epoch`, is refused with `fenced`. `resume` stays refused, and `stop`
ends the run.

### The stream format

`checkpoint_format` 3 when the stream carries disk rounds, 2 when it does
not, and the reader refuses a manifest that lists disk rounds under 2 or
none under 3. The number only tells tooling that reads manifests whether
to expect `disk`: an hvi from before the disk rounds does not restore
either kind, since profile.json says format 3 and a restore refuses a
profile of another format or from another hvi build. The stream is a
sequence of frames, each one line of JSON then exactly `size` bytes whose
SHA-256 is `sha256`:

```text
{"component":"ram-round-0","size":1049352,"sha256":"5c2e..."}\n<1049352 bytes>
```

| Component | Frames | Holds |
| --- | --- | --- |
| `profile.json` | 1 | The source's machine profile, first, so the destination can refuse it or build RAM for it before anything else arrives. |
| `disk-round-k`, then `ram-round-k`, for each round `k` taken with the guest running | 1 or more each | The disk's blocks written since the disk round before (round 0: since boot), then guest RAM, in chunks. |
| `disk-round-final`, then `ram-round-K` | 1 or more each | The same, taken paused. |
| `cpu.json`, `platform.json`, `devices.json` | 1 each | As in the bundle directory. |
| `disk.json` | 1, when the guest has a disk | As in the bundle directory. |
| `session.json` | 1 | As in the bundle directory. |
| `manifest.json` | 1 | Every other component with its size, its frame count and the SHA-256 of all its frames' bytes in order, the RAM regions and page size, each round's pages and bytes and whether it was taken paused, each disk round's blocks and bytes (`disk`, absent without disk rounds), the profile's hash, the capabilities a restore needs, and the seal time. |

A stream has a disk round before every RAM round, or none at all: the disk
rounds are there only when the guest's disk has a base. A fenced VM's
state sent again has only the paused pair.

A RAM round is cut into frames of about 1 MiB, so neither side holds a
whole round. A frame is a sequence of chunks, each a 24-byte header,
little-endian, then its payload:

| Bytes | Field |
| --- | --- |
| 0..8 | The first page, counted from page 0 of the first region across every region in order. A chunk lies in one region. |
| 8..16 | The present bitmap: bit `i` set means page `first + i` is in the payload, clear means it is all zero. |
| 16..18 | The page count, 1 to 64. |
| 18..20 | Flags: bit 0 set means the payload is the pages as they are; clear means one LZ4 block (`lz4_flex`). |
| 20..24 | The payload length. |

The payload is the present pages in order, compressed unless that would
make them larger.

A disk round is cut into frames the same way. Its chunks cover 1 to 16
adjacent 64 KiB blocks, in ascending order, each block at most once in a
round, and are a 24-byte header, little-endian, then the payload:

| Bytes | Field |
| --- | --- |
| 0..8 | The first block. |
| 8..12 | The block count, 1 to 16. |
| 12..16 | Flags: bit 0 set means the payload is the blocks as they are; clear means one LZ4 block. |
| 16..20 | The length of the blocks: whole blocks, but the disk's last when it is short. |
| 20..24 | The payload length. |

The reader checks each frame's header against its limits (a header line
of at most 1 KiB, a RAM or disk frame of at most 8 MiB, a document at most
the directory's limit for it, at most 64 rounds) before it reads the
bytes, and the hash before it uses them. It checks every chunk header in a
frame before the frame writes a page or a block, that each RAM payload is
exactly its present pages, and that each disk chunk lies on the
destination's disk, after the round's last block, and is exactly its
blocks. The components must come in the order above,
and the manifest must list exactly what was read: a frame dropped,
repeated, reordered or changed is refused, as is a stream that ends before
the manifest. A reply line where a frame header was due ends the stream
with the source's error.

### Restoring a stream

```sh
hvi restore --from-stream /run/sb1/stream.sock --stream-keep /var/lib/sb1/checkpoints/tx-43 \
    --control-sock /run/sb1/ctl-2.sock --checkpoint-root /var/lib/sb1/checkpoints \
    --disk root.img --disk-base-sha256 9f2c...e1 --net-stub --agent-sock /run/sb1/agent-2.sock
```

The restore connects to the socket (or reads stdin, with `-`) before it is
confined, and reads the stream whole before anything runs. Once
`profile.json` is in and its RAM regions are checked, it allocates guest
RAM and applies each round to it as it arrives, a later page over an
earlier one; no RAM reaches disk. After the manifest it parses the
documents, refuses with every reason as a directory restore does, and
otherwise builds the VM over the RAM it filled and waits restored-paused.

A stream with disk rounds writes them into `--disk`, which must then be
the destination's own copy of the guest's base image. The restore opens
it when the first disk round arrives, takes its lock and refuses a disk
another hvi holds, rather than wait: on one host that is the source's own
disk, and the blocks of the rounds sent while the guest ran would
overwrite its newer writes. Each round's blocks go in as they arrive, a
later round over an earlier one, and a sync of the disk starts as each
round ends, one at a time, and once more after the final round; the
restore waits for it, so the guest's first flush does not inherit the
writeback. Once the manifest checks, the disk rounds must be `disk.json`'s,
one for one: the bitmap of the blocks each round wrote hashes to the
round's `bitmap_sha256`, its component's SHA-256 is the round's
`sent_sha256`, the last one is the paused round, and it was read at the
generation `disk.json` was captured at. Otherwise the restore is refused
before anything runs. That is the check `--disk-generation` asks for of a
directory, so a stream restore refuses that flag. A stream without disk
rounds leaves `--disk` as it is: the mover copied the whole disk, or the
restore reopens the source's on the same host. Such a stream is refused
when its `disk.json` names a base image, since the guest's disk is then
that base plus disk rounds the stream does not have. A mover that passes
a copy of the base gives `--disk-base-sha256` with it: the restore then
refuses, at `profile.json` and before a block is written, a stream whose
source named another base or none, and at its end a stream that carried
no disk rounds, either of which would leave the bare base as the guest's
disk. A streaming source
releases the disk's lock as it fences, which can land just after the
restore read the manifest, so such a restore waits up to 2 s for the
lock. `--stream-keep` writes the documents and the
manifest, as they came and unsynced, as the record of what was restored.
A stream read from stdin leaves stdin as `/dev/null`, so the console never
reads what followed the stream.

### Live-move timings

Measured with `tools/stream-e2e.sh` (see
[testing.md](testing.md#the-live-move-end-to-end-test)): a portable guest
with 2 vCPUs, an ext4 disk, the stub network and an agent socket, moved
twice on the same host; the stream goes from the source's control
connection through a Python relay into the restore's socket. Downtime is
from the end of the last round with the guest running to the resume reply.
The busy guest runs `tools/guest/dirty.c`, which rewrites 256 MiB of
pseudo-random pages over and over (about 2.5 GiB/s on the Mac, 560 MiB/s
in the Pi's guest); its pages
do not compress, and it never converges.

| Host | Guest | Rounds | Round 0 | Each later round | Final round | Dirty rate | Downtime |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Apple M5 Pro, macOS 26.7 | idle, 512 MiB | 2 | 35.6 MB in 188 ms | | 0.41 MB, 2 ms | 4,150 pages/s | 21.7 ms |
| Apple M5 Pro | 256 MiB writer, 1024 MiB | 6 (round cap) | 306 MB in 737 ms | 269 MB in 521 to 545 ms | 269 MB, 441 ms | 90,000 to 126,000 pages/s | 460 ms |
| Raspberry Pi 5, KVM | idle, 512 MiB | 2 | 35.8 MB in 1528 ms | | 0.48 MB, 12 ms | 595 pages/s | 65 ms |
| Raspberry Pi 5 | 256 MiB writer, 1024 MiB | 6 (round cap) | 306 MB in 3616 to 4656 ms | 269 MB in 2385 to 3265 ms | 269 MB, 1614 to 1693 ms | 14,000 to 28,000 pages/s | 1675 to 3487 ms |

- The idle guest's RAM compresses 2.8 to 1 (100 MB of pages in 36 MB);
  the writer's 1.05 to 1. On the Pi the idle round 0 took 0.5 s on a quiet
  host and 1.5 s while another session's build ran.
- HVF write faults: 202 in the idle move, 83,400 per move with the writer,
  at 0.8 to 3.2 us of host time each in hvi's handler. The ignored test
  `a_protected_granule_faults_once_and_the_store_completes` puts one
  fault at about 6 us end to end, 1.2 us of it in hvi, on the M5 Pro.
- `paused_ms`, the source's part: 7 ms idle on the Mac, 12 to 43 ms on the
  Pi, and with the writer about 440 ms on the Mac and 1.6 to 3.5 s on the
  Pi, nearly all of it the final round. The disk's sync inside the pause
  took 3.9 s once on the Pi, on a disk with 64 MiB not yet synced while
  another build ran.
- The destination's part, manifest to restored-paused: 10 to 58 ms.
- A native HVF guest (2 vCPUs, 512 MiB) moved the same way, three runs:
  22 to 27 ms of downtime.
- Mac to Pi: an idle portable guest with 2 vCPUs, 512 MiB and no disk (the
  disk's transfer is the mover's), streamed from the M5 Pro into
  `hvi restore --from-stream -` on a Pi 5 through `ssh` (5 ms round trip),
  two runs: round 0 put 36 MB on the link in 755 to 779 ms (46 to 47 MB/s,
  about 128 MB/s of guest RAM), the paused round 0.42 MB, `paused_ms` 25 to
  29, the whole move 0.79 to 0.81 s, and at most 83 to 85 ms of downtime,
  read on the Mac as the resume reply arrived back over `ssh`. The guest
  counted on and printed no boot banner.

#### With the disk in the stream

Measured again on 2026-10-15 at `169e200`, with the disk moving in the
stream: the same guests and `tools/stream-e2e.sh`, the source booted with
`--disk-base-sha256` of its fresh 64 MiB ext4 image, and each restore
given a new copy of that base. The busy runs add `--disk-churn`, a guest
loop rewriting 1 MiB of random data on the disk with `fsync` every 0.1 s.
Downtime here is from the pause, after the sync before it, to the resume
reply, less the e2e's hash of both disks (about 50 ms on the Mac) that
sits between the restore and the resume.

| Host | Guest | RAM rounds | RAM on the stream | Disk rounds: blocks | Disk on the stream | `paused_ms` | Downtime |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Apple M5 Pro | idle, 512 MiB | 2 | 100 MB raw, 36.0 MB (2.8:1) | 68, 0 | 4.5 MB raw, 22 KB | 2 | 21.5 ms |
| Apple M5 Pro | 256 MiB writer and disk churn, 1024 MiB | 6 (round cap) | 1748 MB raw, 1659 MB (1.05:1) | 46, 75, then 34 or 35 a round, 35 paused | 17.0 MB raw, 11.6 MB | 432 | 448 ms |
| Apple M5 Pro | `--dirty-once 10` and disk churn | 4 (converged) | 469 MB raw, 391 MB | 22, 51, 27, 0 paused | 6.6 MB raw, 4.2 MB | 7 | 24 ms |
| Raspberry Pi 5 | idle, 512 MiB | 2 | 99 MB raw, 36.4 MB (2.7:1) | 68, 0 | 4.5 MB raw, 22 KB | 8 | 20 ms |
| Raspberry Pi 5 | 256 MiB writer and disk churn | 6 (round cap) | 1749 MB raw, 1660 MB | 85, then 34 or 35 a round, 35 paused | 17.0 MB raw, 11.6 MB | 848 | 861 ms |
| Raspberry Pi 5 | `--dirty-once 10` and disk churn | 6 (converged) | 635 MB raw, 550 MB | 85, 35, 34, 18, 18, 0 paused | 12.5 MB raw, 7.4 MB | 21 | 33 ms |

- Every restored disk hashed as the source's disk at its fence, on both
  hosts and in both moves of each run.
- A disk round of churn is 34 or 35 blocks of random data, which LZ4
  leaves as it is (2.1 MB on the stream); the blocks ext4 writes on its own
  compress 50 to 200 to 1. The final disk round of the busy runs was 2.1 MB
  and took 3 ms on the Mac and 6 ms on the Pi to read and send.
- The longest hold of the device's lock for one block was 59 us on the
  Mac and 223 us on the Pi (579 us in an earlier run).
- In the Pi's `--dirty-once` run, disk round 1 of the second move took
  29.9 s for 18 blocks: the guest's vCPU 0 was in a virtio-blk exit for
  about 21 s (its kernel logged an RCU stall in `vm_notify`, the same trace
  as below), holding the device's lock, which each block's read waits for.
  The move went on and every check passed. See [limitations.md](limitations.md).
- The sync before the pause (`disk_sync_ms`) took 0 to 4 ms on a quiet
  host; with an `O_DIRECT` writer beside it on the Pi, a median of 234 to
  293 ms and once 10.2 s, all of it with the guest running.
- The destination's part, manifest to restored-paused, includes the sync of
  the disk rounds it wrote: 13 to 16 ms on both hosts.
- Mac to Pi, through `ssh` (rp2, 43 MB/s for round 0), with the base copied
  to the Pi first (64 MiB in 1.9 s) and cloned there: idle, 2 RAM rounds
  (36.0 MB), disk rounds of 69 and 0 blocks (23 KB), `paused_ms` 27, the
  whole move 0.85 s, and at most 138 ms from the pause to the resume reply
  seen back on the Mac over `ssh`, 56 ms of it the Pi hashing the restored
  disk before the resume. With the 256 MiB writer and the disk churn: 6
  RAM rounds of 271 to 307 MB each over the link, so the final round alone
  took 6.1 s: `paused_ms` 6206 and 6.2 s of downtime; a guest that does
  not converge pays for its final round at the link's rate. The restored
  disk hashed as the source's in both, the count, the awk's sum and the
  `boot_id` went on, `/dirty` reported no lost page, and the guest's disk
  writes after the move were on the Pi's disk.

### The pause under load

On a Raspberry Pi 5 running the guest above with a disk writer in it
(`dd conv=fsync` in a loop), 4 host loops spinning on all cores and a host
`dd oflag=direct conv=fsync` loop on the same filesystem, 30 `migrate`s
with `then: "continue"` per pass:

| Build | Passes | Moves that failed to park | Park time of the others: median, 90th percentile, longest |
| --- | --- | --- | --- |
| `d43bd55`, before the disk rounds | 1 | 4 of 30 | 85, 1166, 1799 ms (`pause_ms`) |
| `9aae1a8`, the disk rounds, the 2 s bound | 3 | 19 of 90 | 305 to 424, 696 to 1746, 1452 to 1979 ms |
| `81da52d`, the 10 s bound | 3 | 0 of 90 | 3 to 5, 329 to 346, 754 to 1666 ms |
| `9aae1a8`, random gaps between moves | 2 | 4 of 60 | 4 to 5, 677 to 688, 1519 to 1982 ms |
| `169e200`, the 10 s bound, random gaps | 2 | 0 of 60 | 365 to 1492, 2168 to 2285, 2491 to 2545 ms; 13 moves parked in 2.0 to 2.5 s |

The first passes ran a move every 0.5 s and may have locked to the host
writer's cycle; the last two wait 0.3 to 2 s at random between moves.
Each failure was "0 of 2" or "1 of 2 vCPUs parked in time", or once "1 of
2 vCPUs exported their state in time", and the VM ran on. Sampling
`/proc/PID/task/*/syscall` and `wchan` every 10 ms during each pause put
the vCPU thread that had not parked in `fdatasync` (syscall 83) in
`jbd2_log_wait_commit` or `folio_wait_bit_common` for the whole wait: it
was serving the guest's flush, which the host's ext4 journal held up
behind the `O_DIRECT` writer, and a vCPU parks only between guest
entries. With the CPU loops alone, 30 of 30 parked within 321 ms.

## Moving the disk by its blocks

A move that copies the whole disk image copies 1.6 GB for the claude-code
guest, even when the destination already holds the image the guest booted
from and the guest changed a few MB of it. hvi tracks which blocks the guest
wrote, so a mover that keeps a copy of that base image can send only them,
and send most of them while the guest still runs.

A live move does this itself: `migrate` sends the disk rounds in its
stream, takes the final one in its pause, and the manifest covers their
bytes (see [Live moves](#live-moves)); the destination passes its copy of
the base as `--disk`, with its digest as `--disk-base-sha256`, to
`hvi restore --from-stream`. The `disk-dirty` and
`disk-blocks` ops below move the disk beside a bundle directory, and serve
to look at a guest's writes; a mover of a live move needs neither.

**The base.** Whoever starts hvi hashes the disk as this boot opens it,
before this hvi writes it, keeps a copy, and passes the digest with
`--disk-base-sha256`. hvi tracks only the writes it serves from this boot
on, so a disk that an earlier boot wrote needs a new digest, or no flag:
the earlier boot's writes are in no bitmap, and a move by blocks would
leave them out. hvi does not read the image to check it. The machine
profile records it as `disk_base_sha256`, no compatibility check reads it,
and a restore carries it to the restored guest's profile. A disk with a
base must be at most 4 TiB, whose bitmap (8 MiB, 11,184,812 characters of
base64) still fits `disk.json`'s 12 MiB limit; the boot refuses a larger
one. A disk over 4 TiB without a base is checkpointed without the bitmap.

A launcher that writes files into its copy of the base before the boot, as
hull writes an instance's own files, has a disk that differs from the base
before this hvi wrote anything. It passes the digest of the base image and,
with `--disk-written`, the bitmap of the blocks it changed; they start the
blocks written since boot, so round 0 sends them with the guest's own
writes, and the destination needs only the base.

**The bitmaps.** virtio-blk keeps two bitmaps of the disk's 64 KiB blocks
(a 16 GiB disk takes 32 KiB each): the blocks written since the guest
booted, and the blocks written since a mover last read them. A write marks
its blocks before it reaches the image, with the device's lock held, so a
write that fails part way is marked too. A read or a flush marks nothing.
The device offers neither discard nor write-zeroes, so a write is the only
request that changes the image. A reset, as a guest reboot makes, keeps
both bitmaps. A restore starts the first from `disk.json`, so the blocks
written since boot are counted over every move, as `generation` is. Bit
`i` is bit `i % 8` of byte `i / 8`, as in `ram.map`; the last block is
short when the disk is not a whole number of blocks.

### The rounds

`disk-dirty` on the control socket reads a bitmap and starts a round:

1. `{"since":"boot"}` returns the blocks written since boot. It is round 0,
   it starts the rounds over, and it clears the second bitmap, since round 0
   holds those writes already.
2. `{"since":"round"}` returns the blocks written since the last read and
   clears them: round 1, 2 and on. It is refused before a round 0, and
   after round 1024, so the list of rounds `disk.json` records stays
   small; reading since boot again starts over.

Each read records the device's generation, under the lock the guest's
writes take, so a write after a read is in the next round, and the
SHA-256 of the bitmap it returns, which the reply gives as
`bitmap_sha256`. Read with the
guest paused (`paused`, `restored-paused` or `fenced`), it first syncs the
disk with `fdatasync`, as a capture does.

A move beside a bundle directory then runs:

1. Boot with `--disk-base-sha256`, and keep the base image.
2. While the guest runs: `disk-dirty` since boot, and `disk-blocks` for
   round 0; then `disk-dirty` since the last round and `disk-blocks` for
   it, until a round is small. The destination applies each round into
   its copy of the base as it arrives.
3. The final round, read with the guest still, so no write comes after
   it. Either order works:
   - `pause`, then `disk-dirty` since the last round and its
     `disk-blocks`, then `checkpoint` with `then: "fence"`. Its
     `disk.json` lists the final round too.
   - `checkpoint` with `then: "fence"`, then `disk-dirty` since the last
     round and its `disk-blocks`. `disk.json` was written before that
     read and does not list it, but a fenced guest never writes again,
     so the read is at the generation `disk.json` records.
4. On the destination, `hvi restore --disk <the copy> --disk-generation G`,
   where `G` is the `generation` of the `disk-dirty` reply that started
   the final round.

`G` must come from the `disk-dirty` reply, not from the `disk-blocks`
reply. While the guest runs, a write can land between the read and the
end of its export: the `disk-blocks` reply's generation then counts a
write that only the next round holds. After a fence the two are equal.

A block applied twice is harmless: a later round carries the newer bytes.

### The block stream

`disk-blocks` names the blocks as a list, `{"blocks":[3,4,9]}`, ascending
and each once, at most 4096 per request, which fit a request line of
64 KiB, or as `{"round":k}`, the round the last `disk-dirty` read, which is
the way to ask for a whole round. A longer list is `bad_request`. Every
block number is checked before the first byte goes out. The blocks then
come on the connection in batches, then the op's reply:

```text
{"component":"disk-blocks","batch":0,"first":3,"count":2,"offset":196608,"size":131072,"sha256":"<hex>"}
<131072 bytes: blocks 3 and 4>
{"component":"disk-blocks","batch":1,"first":9,"count":1,"offset":589824,"size":65536,"sha256":"<hex>"}
<65536 bytes: block 9>
{"v":1,"ok":true,"blocks":3,"bytes":196608,"batches":2,"generation":41,"max_lock_us":38,"sent_sha256":"<hex>"}
```

| Header field | Meaning |
| --- | --- |
| `component` | Always `disk-blocks`. |
| `batch` | The batch's number in this stream, from 0. |
| `first`, `count` | The blocks: `count` adjacent blocks from `first`, at most 16 (1 MiB). |
| `offset` | The byte on the disk the first block starts at, `first * 65536`. |
| `size` | The bytes after the line: `count` blocks, less when the last is the disk's short last block. |
| `sha256` | The SHA-256 of those bytes, lowercase hex. |

A line with a `v` key is the reply and ends the stream; a header has none.
A block that cannot be read ends it with a `capture_failed` reply. Each
block is read with the device's lock held for that block only, so the
guest's I/O waits for one 64 KiB read at most; `max_lock_us` is the
longest hold. A block the guest writes while it is exported may go out
with or without the write, and is in the next round either way.

The reply's `sent_sha256` is the SHA-256 of the batches' `sha256` texts,
in order, with nothing between them. A reader that hashes the digests of
the batches it applied the same way, and compares `blocks`, `bytes` and
`batches` with what it applied, knows it applied the whole stream. For
`{"round":k}` the reply also carries `round`, and the device records the
digest against the round, so a `disk.json` captured later lists it as
the round's `sent_sha256`.

`tools/apply-blocks.py --image <copy> --sock <control socket> --round <k>`
applies a round as a destination would: it checks each header, that the
blocks are inside the image and at their own offset, and each digest,
never grows the image, and refuses a reply whose counts or `sent_sha256`
are not those of the batches it applied. `--stream FILE` reads a saved
stream instead.

### Restoring onto the base

`disk.json` records `base_sha256` (the profile's `disk_base_sha256`),
`block_size` (65536), `dirty_since_boot_b64` (the first bitmap as base64)
and `rounds`, each `{"round","generation","blocks","bitmap_sha256",
"sent_sha256"}`. `bitmap_sha256` is the digest of the round's bitmap, as
its `disk-dirty` reply gave it. `sent_sha256` is, for a round a live
move's stream carried, the SHA-256 of that disk round's frames, which the
stream's manifest lists too; for a round `disk-blocks` sent as
`{"round":k}`, the digest its reply gave; and `null` for a round not sent
either way before the capture. With them a destination can show it
applied each listed round's blocks, and that no round was read before the
one before it went out: such a round has no `sent_sha256`. A stream
restore compares them with what it applied (see [Restoring a
stream](#restoring-a-stream)); for a directory, hvi checks only their form
and comparing them is the mover's work. A final round read after a fence
is not in `disk.json`, so its digests are only in its replies. A
directory's manifest covers `disk.json`, and so the digests it lists, but
not the block bytes themselves; a stream's covers both.

A `disk.json` written before these fields existed still reads. The reader
refuses one whose base is not the profile's, whose rounds are out of order
or of a generation past the disk's, whose digests are not 64 lowercase hex
digits, or whose bitmap is not the bitmap of a disk this size; it checks
the bitmap's length before it decodes it.

Only the mover knows how it made the destination's disk, so it says so:
`hvi restore --disk-generation G` means `--disk` is the base with every
round applied, and the last round's `disk-dirty` read was at generation
`G`. The restore then refuses, with its other reasons and before it
creates anything, a `disk.json` with no base, or one captured at another
generation. A `G` below it means the guest wrote after that round and the
disk lacks the write, as when a mover skips the final round. Without the
flag nothing about rounds is checked, so rounds left over from a move that
was given up do not refuse a bundle whose disk was copied whole.

The restored device goes on from `dirty_since_boot_b64`, so a second move
from the destination against the same base still sends every block that
differs from it.

### Measured

On the Mac (Apple M5 Pro, HVF), a 2-vCPU, 512 MiB guest with a raw 1 GiB
disk (16384 blocks), driven by a scratch script around
`tools/apply-blocks.py`. The guest wrote 32 MiB at 8 MiB, one block at
block 5 and 6 bytes at byte 512000. `disk-dirty` since boot returned
exactly those 514 blocks (5, 7 and 128 to 639), in 0.1 ms. Then a guest
loop wrote random 64 KiB blocks with `conv=fsync` while the rounds ran:

| Round | Guest | Blocks | MiB | Batches | Applied in | Longest lock hold |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | after its pattern | 514 | 32.1 | 34 | 309 ms (104 MiB/s) | 397 µs |
| 1 | writing | 482 | 30.1 | 465 | 1039 ms (29 MiB/s) | 53 µs |
| 2 | writing | 690 | 43.1 | 652 | 1351 ms (32 MiB/s) | 51 µs |
| 3 (final) | paused | 320 | 20.0 | 316 | 135 ms (148 MiB/s) | 20 µs |

The base with the four rounds applied had the live disk's SHA-256. From
the `pause` request to the final round applied took 141 ms. The fenced
bundle verified, its `disk.json` (3.3 KB) listed the four rounds with the
last at the disk's generation, a restore from the copy came up
restored-paused, reported the source's 1923 blocks since boot, and its
guest answered after `resume`. The rates include the Python reader's
hashing; scattered single blocks cost one batch each.

The same check with the final round read after the fence, as hull does
it: rounds 0 to 2 while the guest wrote (514, 376 and 543 blocks), then
`checkpoint` with `then: "fence"`, then round 3 (252 blocks, 15.8 MiB,
applied in 81 ms). The base with rounds 0 to 3 had the live disk's
SHA-256. `disk.json` listed rounds 0 to 2 and generation 28357, the
generation of round 3's `disk-dirty` reply. A restore with
`--disk-generation 24022`, round 2's read, as a mover that skipped the
final round would pass, was refused; with `--disk-generation 28357` it
came up restored-paused and its guest answered after `resume`.

## Clock policy

### The native profile

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
time: the counter runs on through it. The native KVM backends do not capture
the counter yet.

### The portable profile

The guest's clock is `hvi-time`, and its restore republishes the page
([portable-profile.md](portable-profile.md#restore)):

- **The monotonic clock continues.** The page is published when the first
  vCPU enters the guest after `resume`, with guest nanoseconds going on from
  the capture, so neither the time away nor the time restored-paused shows
  on `CLOCK_MONOTONIC`. Deadlines that passed while away fire at once.
- **The wall clock is corrected.** The page carries the host's wall clock,
  and the guest driver moves `CLOCK_REALTIME` and `CLOCK_BOOTTIME` on by the
  downtime when it sees the new generation. `/proc/uptime` is
  `CLOCK_BOOTTIME`, so it moves on too.
- **The raw counter does not go back.** The destination's counter offset is
  set when its vCPUs are created (on KVM `KVM_ARM_SET_COUNTER_OFFSET` takes
  it only before a vCPU has run), so that `CNTVCT_EL0` starts no lower than
  `counter_at_capture` scaled to the destination's rate, rounded up. It runs
  on while the guest waits restored-paused. The guest reads it only through
  `hvi-time`, and EL0 reads trap to the synthetic counter.
- **The driver counts each publish once**, however many vCPUs take
  `GEN_CHANGED`, with the portable kernel's third patch: `migrations` is 1
  after a move on 2 or 4 vCPUs. hvi also publishes the page after a host
  sleep ([portable-profile.md](portable-profile.md#host-sleep)); with the
  fourth patch the driver counts those in `host_sleeps`, not in
  `migrations`. The series is in
  [tools/guest/kernel](../tools/guest/kernel/README.md).

Measured with `tools/checkpoint-e2e.sh --portable`, one run on each host,
1 vCPU, 512 MiB:

| Host | `capture_ms` | Restore to restored-paused | Checkpoint request to resume reply | A 6 s timerfd armed before the capture |
| --- | --- | --- | --- | --- |
| Apple M5 Pro, macOS 26.7 | 406 | 576 ms | 987 ms | fired 6.000061 s of guest time after it was armed |
| Raspberry Pi 5, Linux 6.12.25 | 914 | 881 ms | 1798 ms | fired 6.000051 s of guest time after it was armed |

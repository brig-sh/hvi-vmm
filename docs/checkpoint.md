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
    [Moving between hosts](#moving-between-hosts).
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
is format 2 (see [The stream format](#the-stream-format)), with the same
documents. A profile gives the newest format its hvi writes, now 2, and a
directory may hold a profile of either. Every document is JSON with fields by name and a
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
| Disk | Synced, with its size and generation. The image itself is not in the bundle; whoever moves the sandbox moves the disk. | The same. |
| vCPU registers | Whole. See [The vCPU state](#the-vcpu-state). | arm64: whole, by the same names, with the firmware and fixed registers and `mp_state`. x86-64: **partial**, the plugin register view. |
| A secondary the guest never started | `off`, or `pending_on` with the entry and context of the `CPU_ON` it had not taken. | `off` when KVM reports it stopped. PSCI is KVM's: a vCPU whose `CPU_ON` KVM has not served yet still holds its initialisation registers (pc 0), and the capture fails until the guest has run again. One turned off and being turned on again is not seen (`portable-profile.md`, Limits). |
| Interrupt controller | Native: the `hv_gic_state` blob, and the GICv3 registers in canonical form. Portable: the software GICv2's state. | Portable: the vGICv2 in canonical form. Native: **not captured**. |
| Guest counter | Native: the counter at the capture. Portable: `hvi-time`'s state and the raw counter. | Portable: the same. Native: **not captured**. |

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
its state. The control socket's `migrate` op does it, on the connection
that asked, since a confined hvi may write to a socket it accepted but
cannot open a new one:

```text
{"v":1,"op":"migrate","then":"fence","txid":"tx-43","epoch":8}
```

hvi then writes the stream (see [The stream format](#the-stream-format))
on that connection and, after its manifest, the reply line:

```json
{"v":1,"ok":true,"state":"fenced","manifest_sha256":"...","stats":{
 "rounds":[{"round":0,"in_pause":false,"pages":25664,"data_pages":23817,"bytes":35627331,"ms":188,"dirty_pages_per_s":0},
           {"round":1,"in_pause":true,"pages":804,"data_pages":604,"bytes":406935,"ms":2,"dirty_pages_per_s":4150}],
 "stop_reason":"converged","threshold_bytes":8388608,"precopy_ms":189,"pause_ms":0,"paused_ms":7,
 "final_round_bytes":406935,"ram_total_bytes":536870912,"ram_present_bytes":97251328,
 "ram_raw_bytes":100028416,"ram_stream_bytes":36024172,"stream_bytes":36045338,
 "write_granule":16384,"write_faults":202,"write_fault_ns":3219,
 "precopy_end_unix_ms":1792019500123,"sealed_at_unix_ms":1792019500131}}
```

`pause_ms` is the time to park the vCPUs, `paused_ms` the time from the
pause to the manifest written: the source's part of the downtime. The rest
is the transport and the destination's restore. A `migrate` needs no
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
whichever is larger (`converged`), after 5 rounds (`round_cap`), or 60 s
after the start (`time_cap`); `max_rounds` and `max_secs` on the request
lower or change those two. Then the guest is paused as for a checkpoint,
the disk is synced, and the final round sends the pages left and every page
written since, with nothing running. A guest that writes faster than the
rounds copy never converges: the round cap ends it, and its final round is
as large as what it writes in one round, so the pause lasts as long as
that takes to send. The final round is always taken paused.

Only the control thread writes the stream. A slow reader holds it up, and
the guest runs on meanwhile; the pause starts once the last round with the
guest running is written. A reader that stops taking the stream without
closing the connection is not waited for without end, since it would hold
the control socket and, in the final round, a paused guest:

- Any write that waits 30 s for the reader to take a byte fails the move.
- From the pause, the rest of the stream must be written within 10 s plus
  twice the time the last round with the guest running took. The final
  round holds what the guest wrote during that round, so a reader that kept
  up with it keeps up with this one.

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
manifest. A later `migrate` on the fenced VM is refused with `fenced`,
whatever its `then`, `txid` or `epoch`: the destination may run the guest
by then, and a second stream would be a second copy that can resume. A
caller that must be able to send the stream again keeps its own copy as it
reads it.

### The stream format

`checkpoint_format` 2: a sequence of frames, each one line of JSON then
exactly `size` bytes whose SHA-256 is `sha256`:

```text
{"component":"ram-round-0","size":1049352,"sha256":"5c2e..."}\n<1049352 bytes>
```

| Component | Frames | Holds |
| --- | --- | --- |
| `profile.json` | 1 | The source's machine profile, first, so the destination can refuse it or build RAM for it before anything else arrives. |
| `ram-round-0` .. `ram-round-K` | 1 or more each | Guest RAM, in chunks. The last round is the one taken paused. |
| `cpu.json`, `platform.json`, `devices.json` | 1 each | As in the bundle directory. |
| `disk.json` | 1, when the guest has a disk | As in the bundle directory. |
| `session.json` | 1 | As in the bundle directory. |
| `manifest.json` | 1 | Every other component with its size, its frame count and the SHA-256 of all its frames' bytes in order, the RAM regions and page size, each round's pages and bytes and whether it was taken paused, the profile's hash, the capabilities a restore needs, and the seal time. |

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
make them larger. The reader checks each frame's header against its limits
(a header line of at most 1 KiB, a RAM frame of at most 8 MiB, a document
at most the directory's limit for it, at most 64 rounds) before it reads
the bytes, and the hash before it uses them. It checks every chunk header
in a frame before the frame writes a page, and that each payload is
exactly its present pages. The components must come in the order above,
and the manifest must list exactly what was read: a frame dropped,
repeated, reordered or changed is refused, as is a stream that ends before
the manifest. A reply line where a frame header was due ends the stream
with the source's error.

### Restoring a stream

```sh
hvi restore --from-stream /run/sb1/stream.sock --stream-keep /var/lib/sb1/checkpoints/tx-43 \
    --control-sock /run/sb1/ctl-2.sock --checkpoint-root /var/lib/sb1/checkpoints \
    --disk root.img --net-stub --agent-sock /run/sb1/agent-2.sock
```

The restore connects to the socket (or reads stdin, with `-`) before it is
confined, and reads the stream whole before anything runs. Once
`profile.json` is in and its RAM regions are checked, it allocates guest
RAM and applies each round to it as it arrives, a later page over an
earlier one; no RAM reaches disk. After the manifest it parses the
documents, refuses with every reason as a directory restore does, and
otherwise builds the VM over the RAM it filled and waits restored-paused.
A streaming source releases the disk's lock as it fences, which can land
just after the restore read the manifest, so a restore from a stream waits
up to 2 s for the lock. `--stream-keep` writes the documents and the
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

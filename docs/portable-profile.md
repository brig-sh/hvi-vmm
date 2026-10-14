# The portable machine profile

`--profile portable-arm64-v1` gives an arm64 guest one machine on every host
that implements the profile, so that a checkpoint taken on one host can be
restored on another without a reboot. The hosts in view are a Mac with Apple
silicon (Hypervisor.framework) and a Raspberry Pi 5 (KVM).

Status: the macOS backend and the arm64 KVM backend both implement the CPU
baseline, the GICv2, the firmware and the `hvi-time` clock below, and give a
guest of the same configuration the same devicetree, byte for byte. A guest
kernel with the `hvi,time-v1` driver keeps time in nanoseconds on both hosts,
although the counter under it runs at 24 MHz on Apple silicon and at 54 MHz
on the Pi. Checkpoint and restore are not implemented yet, so a guest cannot
move between hosts in this increment; the device's state and its restore
are, and a test hook exercises the restore in one process (see
[Restore](#restore)). The x86-64 KVM backend refuses the profile.

The default, `--profile native`, is unchanged: the host's own CPU features and,
on macOS, Apple's in-kernel GICv3.

## Where the numbers come from

Every value here was measured on 2026-10-14:

- **Mac:** an Apple M5 Pro on macOS 26.7. Small Hypervisor.framework programs
  read the ID registers a guest sees with and without `hv_gic`, wrote them
  before the first run and read them back from the guest, and recorded how
  WFI, the virtual timer and interrupt injection behave without `hv_gic`.
- **Pi:** a Raspberry Pi 5 (Cortex-A76) on Linux 6.12.25 with KVM. Small KVM
  programs read the ID registers, their writable masks and the firmware
  registers, set up a vGICv2 and compared what userspace and a guest read
  from it. A small guest issued the version, feature, `MIGRATE_INFO_TYPE`,
  `AFFINITY_INFO` and workaround calls in the firmware table below.

## 1. CPU

### ID registers

Each vCPU is given these values before its first instruction. Before that,
hvi compares every field with what the host offers a guest and refuses the
boot, naming each field, if the baseline claims more than the host has.
Hypervisor.framework accepts a value above what the hardware has without
complaint and then reads it back, so only this comparison catches a raise.
KVM refuses a raise itself. Fields are compared as Linux reads them: FP,
AdvSIMD, TGran4, TGran64 and DoubleLock are signed (`0xf` means absent),
the rest unsigned. The only raises allowed are `ID_AA64MMFR1_EL1` VMIDBits
and VH, which the Pi fixes above the Mac's 0 and which describe EL2, which
the guest does not have. hvi also reads every register back after writing
it and refuses the boot if one differs.

| Register | Value | What the guest sees |
| --- | --- | --- |
| `MIDR_EL1` | `0x414fd0b1` | Cortex-A76 r4p1, the Pi's CPU. KVM cannot change it. |
| `MPIDR_EL1` | `0x80000000 \| cpu` | Affinity 0 is the vCPU index. |
| `ID_AA64PFR0_EL1` | `0x1100000010110011` | AArch64 only at EL0 and EL1, FP, AdvSIMD, RAS, CSV2, CSV3. No GIC system registers, no SVE, no DIT. |
| `ID_AA64PFR1_EL1` | `0` | No BTI, SSBS, MTE or SME. |
| `ID_AA64ZFR0_EL1`, `ID_AA64SMFR0_EL1` | `0` | |
| `ID_AA64ISAR0_EL1` | `0x0000100010211120` | AES with PMULL, SHA1, SHA256, CRC32, LSE atomics, RDM, DotProd. The Pi's value. |
| `ID_AA64ISAR1_EL1` | `0x0000000000100001` | DPB, LRCPC. No pointer authentication. The Pi's value. |
| `ID_AA64ISAR2_EL1` | `0` | Both hosts already read 0. Hypervisor.framework has no way to set it. |
| `ID_AA64MMFR0_EL1` | `0x000000000f100022` | 40-bit physical addresses, 16-bit ASIDs, 4K and 16K pages, no 64K pages (the Mac has none). |
| `ID_AA64MMFR1_EL1` | `0x0000000010212120` | PAN 2, no hardware access-flag update. VMIDBits and VH as the Pi fixes them. |
| `ID_AA64MMFR2_EL1` | `0x0000000000001011` | CnP, UAO, IESB. No LSE2, TTL or E0PD. |
| `ID_AA64DFR0_EL1` | `0x0000000010305006` | Debug v8.0, no PMU. |
| `ID_AA64DFR1_EL1` | `0` | |

A guest booted this way on the Mac reports the same `Features` line as the
Pi 5 host's `/proc/cpuinfo`:

```text
fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
```

Some registers cannot be set on one host or the other:

- `CTR_EL0`: not settable on the Mac. It reads `0x99444c004` there and
  `0x9444c004` on the Pi. They differ only in TminLine, which matters only
  with MTE, and MTE is hidden. The Pi must not lower its value.
- `DCZID_EL0`: settable on neither host, and `0x4` (64-byte `DC ZVA`) on
  both. hvi refuses the boot if the host reports another value.
- `CNTFRQ_EL0`: settable on neither host. It reads 24 MHz on the Mac and
  54 MHz on the Pi.

The profile also puts `arm64.nopauth arm64.nobti arm64.nosve arm64.nosme
arm64.nomte` at the front of the kernel command line, so the guest stays off
those features even if a register slipped through. They go in front because
Linux passes everything after a standalone `--` to init.

Because the guest sees a Cortex-A76 on the Mac too, Linux applies the A76's
errata workarounds there ("Broken broadcast TLBI completion", "SSBS not fully
self-synchronizing") and chooses the A76's Spectre-BHB loop mitigation.

### Firmware

PSCI is served over HVC. KVM answers PSCI and SMCCC calls in the kernel, so on
the Mac hvi answers them as KVM on the Pi does. The values below are what a
guest on the Pi read with the KVM firmware bitmaps `STD`, `STD_HYP` and
`VENDOR_HYP` lowered to 0, which is how the profile sets them on KVM.

| Call | Answer |
| --- | --- |
| `PSCI_VERSION` | `0x10001` (PSCI 1.1) |
| `SMCCC_VERSION` | `0x10001` (SMCCC 1.1) |
| `PSCI_FEATURES` of `PSCI_VERSION`, `CPU_SUSPEND` (32 and 64), `CPU_OFF`, `CPU_ON` (32 and 64), `AFFINITY_INFO` (32 and 64), `MIGRATE_INFO_TYPE`, `SYSTEM_OFF`, `SYSTEM_RESET`, `PSCI_FEATURES`, `SYSTEM_RESET2` (32 and 64), `SMCCC_VERSION` | `0` |
| `PSCI_FEATURES` of anything else, `SYSTEM_SUSPEND` included | `NOT_SUPPORTED` (-1) |
| `SMCCC_ARCH_FEATURES(ARCH_WORKAROUND_1)` | `1`: not required on this CPU |
| `SMCCC_ARCH_FEATURES(ARCH_WORKAROUND_2)` | `NOT_SUPPORTED` |
| `SMCCC_ARCH_FEATURES(ARCH_WORKAROUND_3)` | `0`: available |
| `SMCCC_ARCH_FEATURES` of anything else, `SMCCC_ARCH_SOC_ID` included | `NOT_SUPPORTED` |
| `ARCH_WORKAROUND_1`, `ARCH_WORKAROUND_3` | `0`, and nothing else happens |
| `MIGRATE_INFO_TYPE` | `2`: no Trusted OS to migrate |
| `TRNG_VERSION`, the vendor hypervisor UID, `PV_TIME_FEATURES` | `NOT_SUPPORTED` |

The rest of what the calls do follows KVM's source
(`arch/arm64/kvm/psci.c` in Linux 6.12) rather than a measurement:
`CPU_SUSPEND` waits as a WFI does and returns 0. `CPU_ON` answers
`ALREADY_ON` for a vCPU that is on and `INVALID_PARAMETERS` for an affinity
no vCPU has. `AFFINITY_INFO` reports a vCPU on from its `CPU_ON` (cpu0 from
the start), and `INVALID_PARAMETERS` for an affinity no vCPU has.
`SYSTEM_RESET2` resets for the warm reset type (0) or a vendor type
(`0x80000000` and up).

## 2. Interrupt controller

The guest gets a GICv2: `arm,cortex-a15-gic` in the devicetree, the
distributor at `0x0800_0000` and the CPU interface at `0x0801_0000`, 64 KiB
each. On the Pi it is KVM's vGICv2. On the Mac it is hvi's software model,
`devices/gicv2.rs`, which mirrors what a guest on the Pi reads:

- `GICD_TYPER` is `((ncpu - 1) << 5) | 7`: 256 interrupts. `GICD_IIDR` is
  `0x4b00343b` and `GICC_IIDR` is `0x0202143b`, as a guest on the Pi reads them
  (KVM's userspace view of `GICC_IIDR` differs).
- Priorities have five bits: a write keeps bits 7:3, so `GICC_PMR` reads
  `0xf8` after a write of `0xff`. `GICC_BPR` resets to 2 and never reads lower.
  `GICC_ABPR` resets to 3.
- SGIs 0-15 are enabled at reset and edge-triggered. `GICD_ICFGR0` reads
  `0xaaaaaaaa` and `GICD_ICFGR1` reads 0 (PPIs level), both read-only. SPIs
  reset to edge and their configuration is writable.
- `GICD_ITARGETSR0-7` are banked and read-only, with the reading CPU's bit in
  every byte. Enables, pending and active bits and priorities of interrupts
  0-31 are banked per CPU.
- `GICC_CTLR` keeps EnableGrp0, EnableGrp1, AckCtl, FIQEn, CBPR and
  EOImode: a guest on the Pi that writes `0xffffffff` reads `0x21f`. The
  bypass bits read as zero.
- With EOImode 0, `GICC_EOIR` drops the priority and deactivates the
  interrupt. With EOImode 1 it only drops the priority, and `GICC_DIR` at
  offset `0x1000` deactivates. The drop clears the highest active priority,
  whichever interrupt the write names, and only an active interrupt is
  deactivated. This is what a guest on the Pi sees.
- Interrupts reset to group 0 and are all signalled as IRQs. CBPR applies
  `GICC_BPR` to group 1. FIQEn and AckCtl are kept but change nothing: no
  interrupt becomes an FIQ, and `GICC_IAR` acknowledges either group. Linux
  sets neither.

The model keeps each interrupt's enable, line level, software latch and
active state apart. KVM's v2 userspace interface cannot report the line level
on its own (`ISPENDR` reads latch OR level, and the level-info attribute is
v3-only on the Pi), so a checkpoint in this form can be restored on either
host. A level interrupt's latch is cleared when the guest deactivates it,
which is when KVM's vGICv2 clears it.

The canonical checkpoint form is `Gicv2State` in `devices/gicv2.rs`: the
distributor's registers for all 256 interrupts (the slots of interrupts 0-31
are zero there) and, for each CPU, its interface and its banked state for
interrupts 0-31, with the source CPUs of each pending SGI.

### Delivery on Hypervisor.framework

Measured without `hv_gic`:

- `hv_vcpu_set_pending_interrupt` delivers an IRQ exception, but the pending
  state is cleared after every run, and only the vCPU's own thread may set
  it. So each vCPU thread sets its IRQ line from the GIC before every run.
- A guest WFI exits at once with the PC on the WFI. hvi steps past it and
  sleeps the vCPU's thread until the GIC has an interrupt for it, its virtual
  timer is due, a pause asks it to park, or the VM stops. WFE never exits.
- A thread that gives another vCPU an interrupt wakes it from that sleep, or
  ends its run with `hv_vcpus_exit`.
- `CNTPCT_EL0` and `CNTPCTSS_EL0` trap. hvi answers with the guest's virtual
  counter.

## 3. Clock and timers: `hvi-time`

The guest cannot keep time with the architected timer: its counter runs at
the host's rate, and a guest moved from a Mac to a Pi would see it change
from 24 MHz to 54 MHz. The profile gives it `hvi-time` instead
(`devices/hvitime.rs`), and the portable guest kernel's `hvi,time-v1` driver
(`drivers/clocksource/hvi-time.c`, Linux 6.12.95 plus two patches) builds the
kernel's clocksource, `sched_clock` and per-CPU clock event on it, all at
1 GHz.

### Devicetree

```text
timer {
        compatible = "arm,armv8-timer";
        clock-frequency = <54000000>;
};
hvi-time@d100000 {
        compatible = "hvi,time-v1";
        reg = <0x0 0x0d100000 0x0 0x10000>, <0x0 0x0d110000 0x0 0x10000>;
        interrupts = <1 4 0x104>;
};
```

- `/timer` has a fixed `clock-frequency` and no interrupts. Linux's
  arch-timer driver sets its rate from it and gives up ("No interrupt
  available, giving up") before it registers anything. Without any timer
  node the kernel panics in `time_init`.
- `interrupts` is PPI 4 (INTID 20), level high. The CPU mask in bits 15:8 is
  `(1 << N) - 1` for N vCPUs: `0x104` for one, `0x304` for two, `0xff04` for
  eight.
- The page is in `reg` and not under `/memory`, so the guest never allocates
  from it.

Both backends build the tree from one helper, `portable::devicetree`, and the
same loader, so one configuration gives one tree on both hosts. The two
1-vCPU boots below recorded the same `dtb_sha256`
(`d8975a56…bd09d0`).

`--arch-timer-irq` is a debugging aid. It gives `/timer` its four PPIs back,
so a kernel without the `hvi-time` driver still ticks on the profile: on the
Mac through the virtual timer path below, on the Pi through KVM's. It changes
the devicetree, and with it `dtb_sha256`. Without it, such a kernel reaches
`/init` and stops at its first timed sleep, because jiffies never advance.

### The pvclock page

64 KiB of memory hvi writes and the guest maps read-only: `hv_vm_map` with
read permission only on the Mac, a `KVM_MEM_READONLY` memory slot on the Pi.
The guest reads it without an exit. A guest write to it is dropped. Fields,
little-endian:

| Offset | Field | |
| --- | --- | --- |
| 0x00 | `u32 magic` | `0x4d545648`, "HVTM" |
| 0x04 | `u32 version` | 1 |
| 0x08 | `u32 generation` | Odd while hvi writes the page. |
| 0x0c | `u32 counter_freq_hz` | The host counter's rate. |
| 0x10 | `u64 base_counter` | The guest's `CNTVCT_EL0` at the publish. |
| 0x18 | `u64 base_ns` | Guest nanoseconds at the publish. |
| 0x20 | `u32 mult`, 0x24 `u32 shift` | `ns = base_ns + ((cnt - base_counter) * mult) >> shift`, 96-bit product. |
| 0x28 | `u64 wall_ns` | The host's `CLOCK_REALTIME` at the publish. |
| 0x30 | `u64 downtime_total_ns` | Time the guest spent stopped across restores. |
| 0x38 | `u64 flags` | 0. |

`shift` is 24 and `mult` the nearest integer to `(10^9 << 24) / freq`:
699050667 at 24 MHz, 310689185 at 54 MHz, which is what the guest kernel's
pvclock test pins. `mult` fits in 32 bits only for a counter faster than
3,906,250 Hz, so hvi refuses to boot a portable guest on a host whose
`CNTFRQ_EL0` is below 3,906,251 Hz, is 0, or does not fit in the 32-bit
field. hvi writes the generation odd, then the fields, then the
generation even, with release fences between. The guest reads under that
sequence count and retries.

hvi publishes the page at the boot vCPU's first entry (guest nanoseconds
start at 0 there) and at every restore, and never otherwise.

The counter the page maps is the guest's virtual counter, and hvi must know
it exactly:

- **Mac:** every vCPU is given one virtual timer offset, taken at boot, and
  reads it back. The guest's counter is `mach_absolute_time()` less that
  offset.
- **Pi:** hvi sets the VM's counter offset with `KVM_ARM_SET_COUNTER_OFFSET`
  (`KVM_CAP_COUNTER_OFFSET`). The guest's counter is the host's `CNTVCT_EL0`
  less that offset. The boot checks it once against `KVM_REG_ARM_TIMER_CNT`
  (`0x603000000013df1a`); measured: `TIMER_CNT 115 within hvi's [81, 125]`.
  On a kernel without the capability, hvi writes `TIMER_CNT` and measures the
  offset around a read of it.

### The timers

One 0x100-byte block per vCPU at `0x0d110000 + cpu * 0x100`, `cpu` being the
vCPU index, which is `MPIDR_EL1.Aff0`:

| Offset | Register | |
| --- | --- | --- |
| 0x00 | `DEADLINE_NS` | Read/write. A write arms a one-shot at that guest nanosecond; `u64::MAX` disarms. Reads the armed value, `u64::MAX` once it fired. |
| 0x08 | `NOW_NS` | Read-only. Guest nanoseconds now, as hvi computes them. |
| 0x10 | `STATUS` | Write 1 to clear. Bit 0 `EXPIRED`, bit 1 `GEN_CHANGED`. |
| 0x18 | `CTRL` | Read/write. Bit 0 `ENABLE`. |

64-bit accesses and 32-bit accesses to either half work. Anything else reads
as zero and ignores writes.

A vCPU's line, PPI 20, is high while its timer is enabled and `STATUS` is not
zero, so the guest's write that clears `STATUS` lowers it. With `ENABLE`
clear an armed deadline waits, and a status bit holds the line low until the
guest enables the timer again; the driver clears `ENABLE` when a CPU goes
offline.

One thread per VM sleeps until the earliest armed deadline, sets `EXPIRED`
and raises the line. It never fires early: after every wake it reads the
counter again and sleeps again for what is left. A deadline at or before now
fires at once, on the vCPU that wrote it. The sleep is a condition-variable
wait, so a deadline armed meanwhile ends it, which `mach_wait_until` and
`clock_nanosleep` cannot do. On Linux that wait is a futex on
`CLOCK_MONOTONIC` with an absolute timeout, the clock
`clock_nanosleep(TIMER_ABSTIME)` would use. On the Mac it is as punctual as
`mach_wait_until`. A 1 ms wait measured on this M5 Pro, 300 times each:

| Thread | `mach_wait_until`, late by | condition variable, late by |
| --- | --- | --- |
| Default | 496 µs average, 544 µs max | 486 µs average, 596 µs max |
| `THREAD_TIME_CONSTRAINT_POLICY` | 8.7 µs average, 36 µs max | 8.6 µs average, 54 µs max |

So the thread runs under `THREAD_TIME_CONSTRAINT_POLICY` on macOS (50 µs
computation, 1 ms constraint), and with a timer slack of 1 ns on Linux. On
Linux the thread sets its timer slack before it installs its seccomp filter,
because neither allowlist has `prctl`.

The thread raises the line through the backend:

- **Mac:** PPI 20 is set in the software GICv2, and the vCPU is woken from an
  emulated WFI or kicked out of its run with `hv_vcpus_exit`.
- **Pi:** `KVM_IRQ_LINE` with `(KVM_ARM_IRQ_TYPE_PPI << 24) | (cpu << 16) |
  20`. The vGIC wakes the vCPU itself.

On the Mac a vCPU in an emulated WFI still also wakes at its virtual timer's
deadline. The portable kernel never arms the virtual timer. A kernel booted
with `--arch-timer-irq` does: Hypervisor.framework reports the timer's
expiry as a `VTIMER_ACTIVATED` exit and masks the timer, hvi raises PPI 27,
and the timer stays masked until the guest ends that interrupt.

### Restore

The canonical checkpoint form (`HviTimeState`, `platform.json` `timer`, kind
`hvi-time`) is:

```text
{"page":{"generation","counter_freq_hz","base_counter","base_ns","mult","shift",
         "wall_ns","downtime_total_ns"},
 "guest_ns_at_capture",
 "cpus":[{"deadline_ns" (null when disarmed),"status","ctrl"}]}
```

`HviTime::restore` publishes the page again from the destination's counter:
`base_ns` is `guest_ns_at_capture`, `base_counter` the destination's counter
now, `mult` the destination's, `wall_ns` the destination's clock, and the
time since the capture is added to `downtime_total_ns`. The generation goes
up by 2, every vCPU's `STATUS` gains `GEN_CHANGED`, deadlines are armed
again (one already due fires at once) and each line follows its restored
state. The guest's driver then sets its delay loop for the new rate in the
interrupt handler, and its work item moves REALTIME and BOOTTIME on by the
downtime while MONOTONIC carries on from the capture.

Checkpoints do not exist yet. `HVI_TIME_TEST_RESTORE=<at>,<downtime>` runs
the restore in one process: at `<at>` seconds it pauses the vCPUs, freezes
and captures the device, holds the guest for `<downtime>` seconds, restores
and resumes. It shows everything a same-host restore shows. A change of
counter rate needs two hosts.

### Clock policy

- **MONOTONIC** runs on guest nanoseconds, which start at the boot vCPU's
  first entry. It does not advance while the guest is stopped across a
  restore.
- **REALTIME** follows the host's clock at boot (the driver sets it from
  `wall_ns` when the guest's clock still reads 1970) and after each restore.
  In between it runs on the host's counter, not on the host's disciplined
  clock, so it drifts from the host by the counter's error. Fitted over
  four 85 s boots against host timestamps with about 1 ms of jitter: -8 to
  -31 ppm on rp2, -2 to -5 ppm on this Mac.
- **BOOTTIME** moves on with REALTIME across a restore.
- **EL0 counter reads** (`CNTVCT_EL0`, `CNTFRQ_EL0`) trap to the guest
  kernel, which answers with a synthetic 54 MHz counter derived from guest
  nanoseconds, on both hosts. `test/el0check.c` checks this.
- **`clock_gettime`** of a high-resolution clock is a system call: the vDSO
  has no `hvi-time` mode. Coarse clocks stay in the vDSO.
- **`udelay`** is calibrated with the host's counter rate (`lpj` 96000 on the
  Mac, 216000 on the Pi at `HZ=250`), and set again for the new rate on a
  restore.

### Cost

`HVI_TIME_TRACE=1` counts every exit hvi handles by kind and prints the
rates once a second (`HVI_TIME_TRACE=<secs>` for another interval), with
how late each timer fired. KVM handles GIC accesses and WFI in the kernel, so
on the Pi the total comes from the VM's KVM debugfs counters
(`/sys/kernel/debug/kvm/<pid>-<fd>/`).

Measured with the portable kernel, 1 vCPU, `HZ=250`, `NO_HZ_IDLE`. "Idle"
is a guest in `sleep 10`. "Busy" is a guest running
`while :; do date >/dev/null; done` for 10 s. Rates are per second of host
time over 9 one-second reports, or 8 s of debugfs samples.

| | Mac (hvf), exits to hvi | Pi (KVM), exits to hvi | Pi (KVM), all exits (debugfs) |
| --- | --- | --- | --- |
| Idle | 32 to 71: GIC 12 to 27, `hvi-time` 16 to 35, WFI 4 to 9 | 16 to 36, all `hvi-time` | 43 (`mmio_exit_user` 29, `wfi_exit_stat` 7) |
| Busy | 1750: GIC 750, `hvi-time` 750, kicks 250 | 750, all `hvi-time` | 1516 (`mmio_exit_user` 750) |
| Timer fires | idle 4 to 9, busy 250 | idle 4 to 9, busy 250 | |
| Fire lateness, whole 85 s run | median of the per-second averages 9 µs, worst single fire 55 µs | median 8 µs, worst 3.5 ms (see below) | |

On the Pi, 3 of the 85 one-second reports of the 1-vCPU run hold a fire
more than 1 ms late (worst 3.5 ms), and 5 more than 100 µs. The timer
thread is an ordinary `SCHED_OTHER` thread there: hvi does not ask for a
real-time policy, which would need privileges. A late fire makes a guest
timer late, never early.

With 2 vCPUs the busy loop is dominated by the IPIs of `fork` and `exec`,
not by the clock: about 90,000 exits a second on the Mac (GIC 71,000, WFI
16,800, `hvi-time` 1,500) and 19,300 on the Pi (`mmio_exit_kernel` 8,100,
which is the in-kernel vGIC distributor an IPI writes, WFI 7,300, `hvi-time`
1,500).

Each guest tick costs three `hvi-time` exits on both hosts: the deadline
write, the `STATUS` read and its clearing write. On the Mac it also costs
three GIC exits (the acknowledge, the end of interrupt and the spurious
acknowledge that ends Linux's loop) and a kick, because the vCPU is in its
run when the timer thread fires. The guest ticks at 250 Hz when busy and
about 4 to 9 times a second when idle.

### Acceptance evidence

Portable kernel `out/Image` (sha256 `028090a2…`, Linux
`6.12.95-00002-gd37da45a76ee`), an Alpine initramfs from
`tools/mk-initramfs.py` with `el0check` run first and then a shell loop, hvi
at `b2c0648` (built on rp2 from a bundle of the branch), `--profile
portable-arm64-v1 --mem-mib 512`, 2026-10-14. The host times are the host
clock's stamps on each console line, to the millisecond.

| Check | Mac, 1 vCPU | Pi, 1 vCPU |
| --- | --- | --- |
| `hvi-time: counter … Hz` | `24000000 Hz, lpj 96000` | `54000000 Hz, lpj 216000` |
| Clocksource | `Switched to clocksource hvi-time` | same |
| Tick device in `/proc/timer_list` | `Clock Event Device: hvi-time`, `hvi_time_set_next_event`, `hrtimer_interrupt` | same |
| `el0check` | `EL0CHECK PASS` at boot and at the end | same |
| `sleep 5`, guest MONOTONIC | 5.001163 s (host 5.002 s) | 5.001635 s (host 5.002 s) |
| 60 s window, guest REALTIME against host | 60.021410 s against 60.022 s | 60.045355 s against 60.049 s |
| `NOW_NS` against the guest's own read (`snapshot`) | `mmio_now_ns` 0.5 to 1.7 µs later | 1.1 to 5.8 µs later |
| `hvi-time` interrupts (boot, after 65 s, after the busy loop) | 17, 526, 3065 | 45, 570, 3092 |
| `dtb_sha256` | `d8975a56…bd09d0` | the same |

Both hosts also booted with 2 vCPUs (`CPU1: Booted secondary processor`),
each CPU's `hvi-time` line ticking (Mac 2979 and 3030 at the end, Pi 3019
and 2871) and `EL0CHECK PASS`. `compatible_with` accepts the Mac's 1-vCPU
profile for the Pi's and the reverse, and the 2-vCPU pair, and refuses a
1-vCPU profile for a 2-vCPU one (vCPUs and devicetree digest).

The restore test (`HVI_TIME_TEST_RESTORE=27,5`) on each host, across the
5 s hold:

| | Mac | Pi |
| --- | --- | --- |
| Host time between two `CLOCKS` lines | 10.011 s | 10.004 s |
| Guest REALTIME, BOOTTIME | 10.013 s, 10.013 s | 10.005 s, 10.005 s |
| Guest MONOTONIC | 5.003 s | 5.004 s |
| Guest log | `hvi-time: generation 4: counter 24000000 Hz, lpj 96000, wall clock moved 5010679321 ns` | `generation 4: counter 54000000 Hz, lpj 216000, wall clock moved 5001383267 ns` |
| `snapshot` afterwards | `generation=4 … migrations=1` | same |

The stock 6.12.95 kernel with `--arch-timer-irq --cpus 2` boots and ticks
on both hosts: `TICK 19` at `date=57`, `sleep 5` from `uptime` 60.22 to
65.22.

## Limits

- macOS and arm64 Linux with KVM. The x86-64 backend refuses the profile.
- On KVM the host must offer a vGICv2 (a GICv3-only host is refused), a
  Cortex-A76 r4p1 `MIDR_EL1` (KVM cannot change it), ID register fields that
  can be lowered to the baseline, a 40-bit guest address space,
  `KVM_CAP_READONLY_MEM`, and 4 KiB or 16 KiB pages. hvi refuses the boot and
  names each problem.
- Checkpoint and restore are not implemented; `hvi-time`'s state and restore
  are, and are tested in one process only.
- At most 8 vCPUs, the GICv2 limit.
- No virtio-fs: `--share-ro` and `--share-rw` are refused, because a guest
  meant to move keeps its storage on virtio-blk, which every host offers.
- The guest needs the `hvi,time-v1` driver to keep time. A stock kernel
  stops at its first timed sleep unless booted with `--arch-timer-irq`, and
  then its clock runs at the host's counter rate.
- REALTIME runs on the host's counter between publishes, so it drifts from
  the host's NTP-disciplined clock by the counter's error (up to about
  30 ppm measured on rp2). Nothing resynchronises it until a restore.
- `clock_gettime` of a high-resolution clock is a system call in the guest.
- On KVM the vCPUs' MMIO exits for `hvi-time` are served in user space,
  three per guest tick.
- `CPU_OFF` returns success and the vCPU goes on running, as on the native
  machine.
- The model keeps one `GICD_IGROUPR0` for all CPUs. Linux never writes it.

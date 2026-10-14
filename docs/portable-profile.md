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
on the Pi. A portable guest is checkpointed and restored on both backends,
and its bundle is the same on both: the vCPUs by register name, the GICv2 in
its canonical form (the software model on the Mac, the vGICv2 on the Pi, see
[Capture and restore on KVM](#capture-and-restore-on-kvm)) and `hvi-time`'s
state ([Restore](#restore)). `hvi restore` takes a portable bundle of either
backend on either (see [checkpoint.md](checkpoint.md#the-portable-restore)).
A restore on the host that took the bundle has been run on both, and
`tools/migrate-e2e.sh` moves a running guest from the Mac to a Pi and from
a Pi to the Mac, stopped, and checks it on the way (see
[Measured results](#measured-results)). The x86-64 KVM backend refuses the
profile.

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
| `SMCCC_ARCH_FEATURES(ARCH_WORKAROUND_2)` | `NOT_REQUIRED` (-2), measured with `ID_AA64PFR1_EL1` at the baseline's 0 |
| `SMCCC_ARCH_FEATURES(ARCH_WORKAROUND_3)` | `0`: available |
| `SMCCC_ARCH_FEATURES` of anything else, `SMCCC_ARCH_SOC_ID` included | `NOT_SUPPORTED` |
| `ARCH_WORKAROUND_1`, `ARCH_WORKAROUND_3` | `0`, and nothing else happens |
| `MIGRATE_INFO_TYPE` | `2`: no Trusted OS to migrate |
| `TRNG_VERSION`, the vendor hypervisor UID, `PV_TIME_FEATURES` | `NOT_SUPPORTED` |

Workaround 2's answer follows SSBS. While a vCPU on the Pi sees SSBS, KVM
answers `NOT_SUPPORTED`. The baseline hides SSBS, and KVM then answers
`NOT_REQUIRED` and keeps the guest mitigated itself. A Linux guest takes
that answer to mean it is not affected by Spectre v4: it logs no
"Spectre-v4" CPU feature line, and
`/sys/devices/system/cpu/vulnerabilities/spec_store_bypass` reads "Not
affected". hvi answers the same on the Mac, so a guest reads the same
mitigation state wherever it boots. On the Mac nothing backs that answer.
The guest is unmitigated there either way: before, it read
`NOT_SUPPORTED` and reported itself "Vulnerable".

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

### Capture and restore on KVM

`arch/aarch64/vgicv2.rs` reads KVM's vGICv2 into `Gicv2State` and writes
one back, through the `KVM_DEV_ARM_VGIC_GRP_DIST_REGS` and
`KVM_DEV_ARM_VGIC_GRP_CPU_REGS` attributes. Every vCPU must be out of
`KVM_RUN` meanwhile; KVM answers `EBUSY` otherwise. What KVM's userspace
view (Linux 6.12, `arch/arm64/kvm/vgic/`) makes the conversion do:

- The import writes `GICD_IIDR` first, because KVM drops `GICD_IGROUPR`
  writes until it has seen one. It then writes group, configuration,
  priorities and targets, then clears each enable, active and pending set
  with all-ones before it sets the state's, so it is exact on a vGIC that
  has already run.
- A `GICD_ISPENDR` write to an SGI makes the writer its only source, so SGIs
  go through `GICD_SPENDSGIR` with their source CPUs.
- `GICD_ISPENDR` reads latch OR line for a level interrupt. The export
  takes the line levels from hvi's devices and leaves them out of the
  latch. A level interrupt whose latch and line are both set comes out with
  the line only: the one loss.
- After the registers, the import sets the lines hvi drives with
  `KVM_IRQ_LINE`: the level SPIs, and PPI 20 of each vCPU. KVM ignores a
  line it owns itself (its timers, the PMU), so a state with another PPI's
  line high is refused.
- `GICC_PMR` is its five priority bits, shifted right by 3. A GICv2 host has
  `GICC_APR0` only, so a state with `GICC_APR1-3` set is refused.
  `GICC_BPR` and `GICC_ABPR` read 0 from a fresh vCPU; the export gives the
  guest's view, 2 and 3.
- The import reads every register back and refuses the state, naming each
  register, when one differs.

An ignored test (`a_gicv2_state_round_trips_through_kvm`, run on rp2 with
`--ignored`) loads a busy state from the software model into a 2-vCPU
vGICv2: pending edge and level SPIs, a level line, SGIs from both CPUs, an
active interrupt and its `GICC_APR0` bit, and one CPU's `hvi-time` line.
231 registers read back as written and the export equals the state. On
KVM, `HVI_TIME_TEST_RESTORE` also exports the live guest's vGIC while the
vCPUs are held, imports it back and exports it again.

A checkpoint runs the export on vCPU 0's thread, once every vCPU has
exported its registers and the I/O threads are held, with `hvi-time`
frozen so the line levels it gives do not change. A restore runs the import
before any vCPU has run, then drives each device's line to the device's
level through the device, so the device's record of its line agrees with
the vGIC. On HVF the capture reads the software model under its lock, and
the restore replaces the model with the captured state in the platform step
of the import.

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
        always-on;
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
  node the kernel panics in `time_init`. It is marked `always-on` like the
  `/timer` of every hvi guest, which changes nothing for a timer the driver
  gives up on.
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
| 0x10 | `u64 base_counter` | The guest's `CNTVCT_EL0` at the boot publish or the last restore. A host-sleep publish keeps it. |
| 0x18 | `u64 base_ns` | Guest nanoseconds at `base_counter`. |
| 0x20 | `u32 mult`, 0x24 `u32 shift` | `ns = base_ns + ((cnt - base_counter) * mult) >> shift`, 96-bit product. |
| 0x28 | `u64 wall_ns` | The host's `CLOCK_REALTIME` at guest nanosecond `base_ns`. |
| 0x30 | `u64 downtime_total_ns` | Time the guest spent stopped across restores and host sleeps. |
| 0x38 | `u32 flags` | 0. |
| 0x3c | `u32 host_sleeps` | How many publishes so far followed a host sleep (see [Host sleep](#host-sleep)). A restore carries it on. |

`shift` is 24 and `mult` the nearest integer to `(10^9 << 24) / freq`:
699050667 at 24 MHz, 310689185 at 54 MHz, which is what the guest kernel's
pvclock test pins. `mult` fits in 32 bits only for a counter faster than
3,906,250 Hz, so hvi refuses to boot a portable guest on a host whose
`CNTFRQ_EL0` is below 3,906,251 Hz, is 0, or does not fit in the 32-bit
field. hvi writes the generation odd, then the fields, then the
generation even, with release fences between. The guest reads under that
sequence count and retries.

hvi publishes the page at the boot vCPU's first entry (guest nanoseconds
start at 0 there), at every restore and after a host sleep (see
[Host sleep](#host-sleep)), and never otherwise.

The counter the page maps is the guest's virtual counter, and hvi must know
it exactly:

- **Mac:** every vCPU is given one virtual timer offset, taken at boot, and
  reads it back. The guest's counter is `mach_absolute_time()` less that
  offset.
- **Pi:** hvi sets the VM's counter offset with `KVM_ARM_SET_COUNTER_OFFSET`
  (`KVM_CAP_COUNTER_OFFSET`). The guest's counter is the host's `CNTVCT_EL0`
  less that offset. The boot checks it once against `KVM_REG_ARM_TIMER_CNT`
  (`0x603000000013df1a`); measured: `TIMER_CNT 115 within hvi's [81, 125]`.
  A value more than 1 µs of ticks outside hvi's reads around it refuses the
  boot, naming both, because every deadline and `NOW_NS` would be wrong.
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
as zero and ignores writes. A 32-bit `DEADLINE_NS` write goes low half
first: hvi holds the low half and disarms the timer (the register reads
`u64::MAX`) until the high half arrives, then arms both halves together.
Merged into the deadline still armed, a low half alone could make a time
already past, and the timer would fire early. A high half written alone
keeps the deadline's low half. A checkpoint taken between the two writes
loses the held low half, and the high half then arms the last nanosecond
of its 2^32 ns window: late, never early. The guest driver writes the
deadline with one 64-bit store.

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
         "wall_ns","downtime_total_ns","host_sleeps"},
 "guest_ns_at_capture",
 "counter_at_capture",
 "cpus":[{"deadline_ns" (null when disarmed),"status","ctrl"}]}
```

`counter_at_capture` is the guest's raw counter at the same moment as
`guest_ns_at_capture`, at `page.counter_freq_hz`. A restore sets the
destination's counter offset so the guest's counter starts no lower than
that value scaled to the destination's rate, rounded up
(`HviTimeState::counter_target`). An older state without it reads as 0,
and so does one without `page.host_sleeps`.

`HviTime::restore` publishes the page again from the destination's counter:
`base_ns` is `guest_ns_at_capture`, `base_counter` the destination's counter
now, `mult` the destination's, `wall_ns` the destination's clock,
`host_sleeps` the captured count, and the time since the capture is added
to `downtime_total_ns`. The generation goes
up by 2, every vCPU's `STATUS` gains `GEN_CHANGED`, deadlines are armed
again (one already due fires at once) and each line follows its restored
state. The guest's driver then sets its delay loop for the new rate in the
interrupt handler, and its work item moves REALTIME and BOOTTIME on by the
downtime while MONOTONIC carries on from the capture.

A checkpoint reads the state with the device frozen, so no deadline fires
under it; a guest that goes on after the capture thaws it, and what came due
meanwhile fires then. `hvi restore` publishes the state once, when the first
vCPU enters the guest after `resume`, and every vCPU waits for that before
its first entry (`PendingPublish`), so the guest never reads an empty page
and the time it waited restored-paused does not show on MONOTONIC.

`HVI_TIME_TEST_RESTORE=<at>,<downtime>` runs
the restore in one process: at `<at>` seconds it pauses the vCPUs, freezes
and captures the device, holds the guest for `<downtime>` seconds, restores
and resumes. It shows everything a same-host restore shows. A change of
counter rate needs two hosts. On KVM it also round-trips the vGIC while the
guest is held, which logs `vGICv2 round trip while held: 231 registers read
back as written`.

Every vCPU takes `GEN_CHANGED` and schedules the driver's work item, which
can then run more than once for one publish. The driver handles each
generation once: it keeps the generation and the `host_sleeps` count it
last handled, starting from the boot page's, and splits the publishes since
into host sleeps (the growth of `host_sleeps`) and restores. It counts the
restores in `migrations` and the host sleeps in `host_sleeps`, which
`/sys/kernel/hvi_time/snapshot` prints just before `migrations`. An Image
before the fourth patch of the series counted a host-sleep publish in
`migrations`. An Image before the third patch of the series ran the work once per vCPU that took
the bit. `tools/checkpoint-e2e.sh --portable --cpus 4` on rp2, three runs
of each Image: the old one logged and counted the move 2, 3 and 3 times,
the current one once each time. On the Mac one run of each counted 1: the
recount is a race, and the Mac did not hit it.

### Host sleep

The guest's counter does not run while a Mac sleeps: it is
`mach_absolute_time()`, less an offset. Guest nanoseconds stop with it, and
so does the wall clock the guest derives from the page, which then trails
the host's by the sleep. hvi publishes the page again after a sleep:

- The timer thread wakes at least once a second and reads a clock that runs
  only while the host sleeps: on macOS `CLOCK_MONOTONIC_RAW` (continuous)
  less `CLOCK_UPTIME_RAW`, on Linux `CLOCK_BOOTTIME` less `CLOCK_MONOTONIC`.
  The two clocks of a pair share their rate and their adjustments, so the
  difference moves with nothing else.
- When it grew by 50 ms or more since the last publish, the page is
  published again on the same counter, rate and base: `base_counter` and
  `base_ns` stay, and `wall_ns` becomes the host's clock less the guest
  nanoseconds since `base_ns`, so the guest's wall clock reads the host's.
  The vCPUs run while the page is written, and a base moved to the
  current counter would round guest nanoseconds down by up to 1 ns
  between a read of the old page and one of the new.
  `downtime_total_ns` grows by how far the guest's wall clock was behind,
  and the generation goes up by 2. Every vCPU gets `GEN_CHANGED`; deadlines stay as they are,
  since guest nanoseconds did not jump. The driver then moves REALTIME and
  BOOTTIME on as after a restore, and MONOTONIC carries on. hvi logs
  `hvi-time: the host slept 30.000 s; published generation 4, the guest's
  wall clock was 30.000 s behind`.
- Nothing is published while a capture holds the device frozen, or before
  a restored VM's first publish; each publish reads the sleep clock again,
  so a sleep while restored-paused is not counted twice.
- A process stopped with `SIGSTOP` is not a sleep: the guest's counter runs
  on with the host's wall clock, so the guest's REALTIME stays right, the
  sleep clock does not move, and nothing is published.
- On a host whose counter runs through a sleep, as a Pi's might in a
  suspend, the same publish happens with the guest's wall clock 0 behind.
  No Pi was suspended to see which it is.

`HVI_TIME_TEST_SLEEP=<at>,<secs>` simulates a sleep without one: `<at>`
seconds after the device is made, the host wall clock and sleep clock as
hvi reads them move `<secs>` ahead. To hvi that is a sleep of `<secs>` with
the guest's counter stopped; the guest's REALTIME then moves `<secs>` ahead
of the real host's. It cannot stop the guest's counter, which a real sleep
does. Measured on 2026-10-14 with a scratch driver that boots the
portable guest with 2 vCPUs, 512 MiB and `/clk 50` (a `CLK` line every
50 ms), and stamps each console line with the host's wall clock on
receipt. `HVI_TIME_TEST_SLEEP=25,30` and, separately, a `SIGSTOP` of the
hvi process for 10 s:

| | Mac | Pi |
| --- | --- | --- |
| First `CLK` line within 100 ms of host + 30 s | 14.5 ms after the republish | 7.6 ms after |
| Guest REALTIME minus (host + 30 s), from then on | -0.40 to -0.18 ms | median -0.30 ms, 2 of 157 lines below -5 ms (worst -73.6 ms) |
| Driver | `generation 4: … wall clock moved 30000021115 ns`, `migrations=1` | `30000031493 ns`, `migrations=1` |
| `downtime_total_ns` | 30000058489 | 30000031586 |
| `SIGSTOP` 10 s: generation, REALTIME after | 2, unchanged; -2.29 to -0.15 ms | 2, unchanged; -0.3 ms once the console drained |

Every offset is negative: a line is stamped after the guest printed it.
The Pi's worst lines are the console's delay, not the clock's: right after
`SIGCONT`, `clk` printed the 200 lines it had missed at once, and they
reached the host up to 686 ms late; from 0.96 s after it, every line read
-0.3 ms.

### Clock policy

- **MONOTONIC** runs on guest nanoseconds, which start at the boot vCPU's
  first entry. It does not advance while the guest is stopped across a
  restore.
- **REALTIME** follows the host's clock at boot (the driver sets it from
  `wall_ns` when the guest's clock still reads 1970), after each restore
  and after each host sleep.
  The boot set is an `fs_initcall_sync`, after timekeeping has switched to
  `hvi-time`: set earlier, while timekeeping still reads the jiffies
  clocksource, the switch carries the time over in whole jiffies, and
  REALTIME started up to 4 ms off the host.
  In between it runs on the host's counter, not on the host's disciplined
  clock, so it drifts from the host by the counter's error. Fitted over
  four 85 s boots against host timestamps with about 1 ms of jitter: -8 to
  -31 ppm on rp2, -2 to -5 ppm on this Mac.
- **BOOTTIME** moves on with REALTIME across a restore.
- **EL0 counter reads** (`CNTVCT_EL0`, `CNTFRQ_EL0`) trap to the guest
  kernel, which answers with a synthetic 54 MHz counter derived from guest
  nanoseconds, on both hosts. `tools/guest/el0check.c` checks this.
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

The tables above are from the first portable Image. Its driver set the
wall clock before the clocksource switch, and the restore then moved the
clock by about 1 ms more than the downtime (5001383267 ns against
5000096767 ns on the Pi). The Image `32725b9b…` (Linux
`6.12.95-00002-g4cfd86639cc9`) sets it after the switch, and was booted
again on both hosts, with the console stamped to the microsecond, with hvi
built at the commit that adds the vGICv2 import:

| Check | Mac | Pi |
| --- | --- | --- |
| Boot order | `Switched to clocksource hvi-time` at 0.024 s, `hvi-time: wall clock` at 0.028 s | 0.047 s, then 0.057 s |
| Guest REALTIME minus host stamp, every `CLOCKS` and `EL0CHECK` line, 1 vCPU | -0.19 to -0.97 ms | -0.42 to -3.03 ms |
| The same, 2 vCPUs | -0.18 to -2.54 ms | -0.37 to -1.39 ms |
| Restore, 2 vCPUs: wall clock moved against the downtime | 5004273946 ns against 5004274196 ns | 5000800163 ns against 5000800219 ns |
| Restore: host, REALTIME, MONOTONIC across the hold | 10.006885, 10.006528, 5.002255 s | 10.004107, 10.003894, 5.003094 s |
| `dtb_sha256`, 1 and 2 vCPUs | `d8975a56…`, `ffe55778…` | the same |

No line has the guest ahead of the host. Each stamp is taken after the
guest printed its line, so a correct clock reads at or before it, and the
console path's latency makes the guest look further behind than it is.

The current Image adds a third patch, which handles each page generation
once (see [Restore](#restore)): sha256
`4b2e8c5ce382a2635efe1b1b198e35b081d2f0cd4d39d9689b026fbc7d8f21b7`, Linux
`6.12.95-00003-g51cdb81da818`. The runs in the next section used
`32725b9b…`, with 1 vCPU, where the recount does not happen.

## Measured results

`tools/migrate-e2e.sh` ([testing.md](testing.md#the-migration-end-to-end-test))
was run on 2026-10-14 between the Apple M5 Pro (macOS 26.7, build 25G229)
and rp2, a Raspberry Pi 5 (Linux 6.12.25, KVM with a vGICv2), each way, and
on each host to itself:

- hvi at `c580223`, built on each host from that commit with no
  uncommitted changes, and signed on the Mac;
- the portable `Image` (sha256 `32725b9b…`), and one initramfs on both
  hosts (sha256 `b2855e38…`) from `tools/mk-initramfs.py
  --checkpoint-workload --add el0check --add tfd --add clk`, with the
  helpers built static on rp2;
- 1 vCPU, 512 MiB, a 64 MiB ext4 disk, the stub network;
- Tailscale between the hosts, a direct path: over the internet (15 ms
  round trip) for the first Mac to Pi run, on one LAN (5 ms) for the rest.

The commands, with `$S` the Mac's work directory and the paths after
`--dst-hvi`, `--dst-dir` and on rp2 there:

```sh
# Mac to Pi
tools/migrate-e2e.sh --src local --dst rp2 \
    --src-hvi $S/bin/hvi-mac --dst-hvi /home/pmoust/p4c/hvi-pi \
    --kernel $S/Image --initramfs $S/initramfs-migrate.cpio \
    --src-dir $S/m2p/src --dst-dir /home/pmoust/p4c/m2p --out $S/m2p/out \
    --drift-secs 600
# Pi to Mac
tools/migrate-e2e.sh --src rp2 --dst local \
    --src-hvi /home/pmoust/p4c/hvi-pi --dst-hvi $S/bin/hvi-mac \
    --kernel /home/pmoust/p4c/Image --initramfs /home/pmoust/p4c/initramfs-migrate.cpio \
    --src-dir /home/pmoust/p4c/p2m --dst-dir $S/p2m/dst --out $S/p2m/out \
    --drift-secs 600
```

The same with `--src local --dst local` and `--src rp2 --dst rp2`
(`--drift-secs 60`) for the moves on one host. For the state comparison,
the two commands above with `--recapture --drift-secs 30` in place of
`--drift-secs 600`, and `m2p-recap` and `p2m-recap` in place of `m2p` and
`p2m` in every directory. The refusals, against the bundles the two runs above
left:

```sh
tools/migrate-e2e.sh --negative --src local --dst rp2 \
    --src-hvi $S/bin/hvi-mac --dst-hvi /home/pmoust/p4c/hvi-pi \
    --kernel $S/Image --initramfs $S/initramfs-migrate.cpio \
    --dst-kernel /home/pmoust/p4c/Image \
    --dst-initramfs /home/pmoust/p4c/initramfs-migrate.cpio \
    --src-dir $S/neg-m2p/src --dst-dir /home/pmoust/p4c/m2p --out $S/neg-m2p/out
tools/migrate-e2e.sh --negative --src rp2 --dst local \
    --src-hvi /home/pmoust/p4c/hvi-pi --dst-hvi $S/bin/hvi-mac \
    --kernel /home/pmoust/p4c/Image --initramfs /home/pmoust/p4c/initramfs-migrate.cpio \
    --dst-kernel $S/Image --dst-initramfs $S/initramfs-migrate.cpio \
    --src-dir /home/pmoust/p4c/neg-p2m --dst-dir $S/p2m/dst --out $S/neg-p2m/out
```

Every run in the table passed every check: 41, or 42 with `--recapture`. The internet
run used an earlier version of the script, which typed on an echoing
console and had no check that both timers were still pending at the
capture, so it ran 40. The other runs used the script before its last
changes, which touch only the refusals' boot, a copy on one remote host
and a marker's name; the committed script then ran each way again with
`--drift-secs 30` and passed all 41 checks, with a downtime of 5.9 s to
the Pi and 4.2 s back. The timings, from `summary.json`:

| | Mac to Pi, LAN | Pi to Mac, LAN | Mac to Pi, internet | Mac to Mac | Pi to Pi |
| --- | --- | --- | --- | --- | --- |
| `pause_ms`, `capture_ms` | 0, 375 | 0, 846 | 0, 377 | 0, 431 | 0, 844 |
| Source stopped after the fence reply | 19 ms | 32 ms | 21 ms | 19 ms | 32 ms |
| Bundle (present RAM) | 96.4 MB (96.4 MB) | 96.3 MB (96.2 MB) | 96.3 MB | 96.2 MB | 96.2 MB |
| Copied: bundle, disk, record | 163.5 MB | 163.4 MB | 163.4 MB | 163.3 MB | 163.3 MB |
| Copy time, rate | 3.36 s, 48.6 MB/s | 3.19 s, 51.3 MB/s | 168.1 s, 0.97 MB/s | 0.98 s | 0.52 s |
| `hvi restore` to `restored-paused` | 873 ms | 540 ms | 1013 ms | 546 ms | 881 ms |
| `resume` reply | 0.1 ms | 0.1 ms | 9.9 ms | 0.1 ms | 0.1 ms |
| Downtime, fence request to resume reply | 4.65 s | 4.62 s | 169.5 s | 1.99 s | 2.29 s |
| Wall clock moved by `hvi-time` | 4.750 s | 4.504 s | 169.554 s | 1.979 s | 2.284 s |

The copy is most of the downtime. rsync sends the 64 MiB disk whole, zeros
and all (`-S` only keeps the copy sparse: 380 KiB on rp2's disk), and the
bundle holds the present RAM pages, of which 96 MB were present. The first
Mac to Pi run is the same move over the Mac's uplink. The capture takes
more than twice as long on the Pi, and the restore 0.3 s longer.

`hvi-time` moves the guest's wall clock by the source's wall clock at the
capture against the destination's at the resume, so the two hosts' clock
difference is in it. During these runs the Mac's clock was 40 to 146 ms
behind rp2's (measured by the script over one ssh session, round trip
4 to 17 ms), and rp2's chrony had it within 0.2 ms of NTP. A move to the Pi
moved the guest's clock by about 0.1 s more than the measured downtime, a
move to the Mac by about 0.1 s less. Either way the guest ends on the destination's
clock.

The guest after the move, with "before" the source's values:

| | Mac to Pi, LAN | Pi to Mac, LAN |
| --- | --- | --- |
| Count, `awk` sums, boot banner | 15 then 16; FP 5000000 then 5500000, exact; none | 15 then 16; FP 1500000 then 2000000; none |
| Driver log | `generation 4: counter 54000000 Hz, lpj 216000`, `migrations=1` | `generation 4: counter 24000000 Hz, lpj 96000`, `migrations=1` |
| 6 s `timerfd` and `sleep` armed before the capture, guest time | 6.000039 s, 6.00 s | 6.003720 s, 6.01 s |
| `CLOCK_MONOTONIC` gap over the move (`clk` every 0.25 s) | 0.250038 s, while REALTIME moved 5.000 s | 0.250048 s, while REALTIME moved 4.754 s |
| `CLOCK_REALTIME` less the host's, first 10 s after the fix-up | median 0.27 ms, worst 0.34 ms | median 0.17 ms, worst 0.40 ms |
| The same after 611 s | 0.52 ms | -4.76 ms |
| `hvi-time`, PL011, virtio-blk interrupts: before, after, after the workload's request | 761, 2333, 3658; 2, 5, 7; 83, 87, 93 | 780, 2352, 3672; 2, 5, 7; 51, 55, 62 |
| `sleep 5` against the host | 5.002 s | 5.001 s |
| `Features` line, before and after | `fp asimd aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp` | the same |

The `Features` line lacks the `evtstrm` of the Pi host's: the guest does
not use the architected timer, so its event stream is not set up. fd 3,
the file written before the move, a write after it, `el0check`, the
clocksource, `e2fsck -fn` on the stopped image and the post-move file read
with `debugfs` passed on every run. The worst 10 s offset of the internet
run, 23.6 ms, is one `clk` line held back by the console while the workload
printed its answer; its median was 0.3 ms.

Against the destination host's wall clock the guest drifted -0.41 ppm on
the Pi (LAN run), -2.88 ppm on the Pi (internet run) and +8.20 ppm on the
Mac, over about 590 s, from the lines with the least console delay in the
first and last 10 s. On the Mac most of that is the host clock's own
movement: its wall clock ran 8.2 ppm slow against its monotonic clock,
which is the counter the guest runs on, while the guest's REALTIME kept
that counter's rate (+0.04 ppm). The log stamps host monotonic time to
the millisecond, so those two figures are good to about 1.7 ppm. On Linux
`CLOCK_MONOTONIC` is slewed with the wall clock, so the Pi's log cannot
split its figure the same way.

With `--recapture` the restored guest was checkpointed again before it
resumed, and its vCPU and platform state equalled the bundle's, each way:
the general, SIMD and system registers, the GICv2 and `hvi-time`. The 15
registers only HVF has were 0. That capture took 843 ms on the Pi and
386 ms on the Mac, inside the downtime.

The refusals (`--negative`), each with exit 1 before anything ran:

| Case | On the Pi | On the Mac |
| --- | --- | --- |
| The other host's native bundle | `profile.json: a native guest, which this hvi does not restore on kvm`; the interrupt controller `hv-gic-v3` and the counter `arch-timer` cannot be restored on kvm; `the bundle needs hvf-gic-state-v1`; `the KVM restore rebuilds the portable machine only` | `an aarch64 guest on kvm, and this hvi restores aarch64 guests from hvf on hvf (only the portable profile moves between backends)`; interrupt controller and counter `not-captured`; the blob missing; then every profile difference (backend, OS, 54 against 24 MHz, ID registers, GIC, PSCI 1.1 against 1.0) |
| `profile.json` with 2 vCPUs, sealed again | `checkpoint-verify`: `cpu.json: 1 aarch64 vCPU(s), the profile has 2 aarch64`; `restore`: `cpu.json: 1 vCPUs, the profile has 2` and `platform.json: irq: GICv2 state has 1 CPUs, this machine 2` | the same |
| `profile.json` with 1024 MiB, sealed again | `manifest.json: the RAM regions are not the profile's`, from both | the same |
| One byte of `ram.bin` changed | `ram.bin: SHA-256 does not match the manifest`, from both | the same |
| `cpu.json` cut to half | `cpu.json: is 2090 bytes, the manifest says 4180`, from both | the same, with its sizes |
| No `--disk` | `the guest had a disk; give it with --disk`, and the device map then differs | the same |
| KVM without a vGICv2 (shim) | restore: `the portable guest needs a vGICv2, and KVM offers none on this host (No such device (os error 19)): a GICv3-only host serves vGICv3 alone`; portable boot: `--profile portable-arm64-v1 needs a vGICv2, and KVM offers none on this host …` | not run: no KVM |

A restore takes its machine from the bundle, so it has no vCPU count or
RAM size of its own to compare. The two altered bundles check that hvi
does not trust a `profile.json` that disagrees with the rest of the
bundle; the digests were made to match, so the refusal is the machine
check's, not the digest's.

Each host also ran `tools/checkpoint-e2e.sh --portable --cpus 1 --mem 512`
on itself with the same assets: 41 checks passed on each; `capture_ms` 373
on the Mac and 849 on the Pi, checkpoint request to resume reply 917 ms and
1817 ms, the `timerfd` 6.000049 s and 6.000048 s.

**A Mac that sleeps stops the guest's clocks.** An earlier Pi to Mac run
went through a clamshell sleep and two maintenance sleeps of the Mac
during its 600 s window (`pmset -g log`: 149 s, then about 73 and 44
minutes). The guest's `CLOCK_MONOTONIC` and `CLOCK_REALTIME` kept pace
with the host's monotonic clock throughout, to within the console's
delay. That clock does not run in sleep either, so the guest fell behind
the host's wall clock by each sleep: 146.9 s after the first, 7158.6 s at
the end. No `clk` line was
lost and MONOTONIC never stepped back; the check of REALTIME at the end
failed, as it should. hvi then did not publish `hvi-time` again on
wake; it does now (see [Host sleep](#host-sleep)), but that was measured
with `HVI_TIME_TEST_SLEEP`, not a real sleep. The native profile's guest
counter is the same host clock and it has no `hvi-time`, so it should
fall behind the same way; that was not measured. The figures above are
from a run with the Mac kept awake.

## Limits

- macOS and arm64 Linux with KVM. The x86-64 backend refuses the profile.
- On KVM the host must offer a vGICv2 (a GICv3-only host is refused), a
  Cortex-A76 r4p1 `MIDR_EL1` (KVM cannot change it), ID register fields that
  can be lowered to the baseline, a 40-bit guest address space,
  `KVM_CAP_READONLY_MEM`, and 4 KiB or 16 KiB pages. hvi refuses the boot and
  names each problem.
- A move between a Mac and a Pi is run by hand with
  `tools/migrate-e2e.sh`; no CI job runs it. Only stopped moves exist: the
  guest is paused from the capture until the copy is done.
- A Mac that sleeps stops a guest's clocks with it. hvi publishes the
  page again after the sleep and the guest's REALTIME catches up (see
  [Host sleep](#host-sleep)); that path was tested with a simulated sleep,
  not a real one.
- A guest booted with `--arch-timer-irq` is checkpointed like any other,
  but its architected timer's line is not carried by the restore; that
  debugging flag is not tested with checkpoints.
- On KVM, a capture that finds a vCPU turned on by a `CPU_ON` that KVM has
  not served yet fails, and the guest stays paused: the vCPU still holds
  the registers of its initialisation, and KVM sets its start registers
  only when it next runs. Resume the guest and checkpoint again. A vCPU
  that was turned off and is being turned on again holds the registers
  it had when it went off, and the capture cannot tell that apart from a
  vCPU that is on; it would restore past its `CPU_OFF`. Linux turns
  vCPUs off and on only for CPU hotplug.
- At most 8 vCPUs, the GICv2 limit.
- No virtio-fs: `--fs`, `--share-ro` and `--share-rw` are refused, because
  a guest meant to move keeps its storage on virtio-blk, which every host
  offers.
- One disk: a second `--disk` is refused, because a move carries one
  writable disk. The devicetree and the software GICv2 still have the
  windows and lines of all four disk slots, as the native machine does.
- The guest needs the `hvi,time-v1` driver to keep time. A stock kernel
  stops at its first timed sleep unless booted with `--arch-timer-irq`, and
  then its clock runs at the host's counter rate.
- REALTIME runs on the host's counter between publishes, so it drifts from
  the host's NTP-disciplined clock by the counter's error (up to about
  30 ppm measured on rp2). Nothing resynchronises it until a restore or a
  host sleep.
- `clock_gettime` of a high-resolution clock is a system call in the guest.
- On KVM the vCPUs' MMIO exits for `hvi-time` are served in user space,
  three per guest tick.
- `CPU_OFF` returns success and the vCPU goes on running, as on the native
  machine.
- The model keeps one `GICD_IGROUPR0` for all CPUs. Linux never writes it.

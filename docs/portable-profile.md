# The portable machine profile

`--profile portable-arm64-v1` gives an arm64 guest one machine on every host
that implements the profile, so that a checkpoint taken on one host can be
restored on another without a reboot. The hosts in view are a Mac with Apple
silicon (Hypervisor.framework) and a Raspberry Pi 5 (KVM).

Status: the macOS backend implements the CPU baseline, the GICv2 and the
firmware below. The KVM backends refuse the profile for now. The guest's
clock is still the architected timer, whose rate differs between the hosts
(24 MHz on Apple silicon, 54 MHz on the Pi), so a guest cannot yet move
between them. A paravirtual clock device (`hvi-time`) replaces it in a later
increment. Until then the profile is for testing the machine, not for moving
guests.

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

The profile also appends `arm64.nopauth arm64.nobti arm64.nosve arm64.nosme
arm64.nomte` to the kernel command line, so the guest stays off those
features even if a register slipped through.

Because the guest sees a Cortex-A76 on the Mac too, Linux applies the A76's
errata workarounds there ("Broken broadcast TLBI completion", "SSBS not fully
self-synchronizing") and chooses the A76's Spectre-BHB loop mitigation.

### Firmware

PSCI is served over HVC. KVM answers PSCI and SMCCC calls in the kernel, so on
the Mac hvi answers them as KVM on the Pi does. The values below are what a
guest on the Pi read with the KVM firmware bitmaps `STD`, `STD_HYP` and
`VENDOR_HYP` lowered to 0, which is how the profile will set them on KVM.

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

### The timer in this increment

The guest still uses the architected virtual timer, through the software GIC:
Hypervisor.framework reports its expiry as a `VTIMER_ACTIVATED` exit and masks
the timer. hvi raises PPI 27 and keeps the timer masked until the guest ends
that interrupt. If the timer still fires then, the line stays high; otherwise
it drops and the timer is unmasked.

`--no-arch-timer-irq` gives `/timer` a `clock-frequency` of 54 MHz and no
interrupts, the shape the profile takes once `hvi-time` exists. Linux then
logs `arch_timer: No interrupt available, giving up`, takes its delay-loop
rate from the property and has no clock event. A stock kernel reaches
`/init` and stops at its first timed sleep, because jiffies never advance.

## Limits

- macOS only for now. The KVM backends refuse the profile.
- At most 8 vCPUs, the GICv2 limit.
- The guest's counter runs at the host's rate, so the profile does not yet
  make a guest movable between a Mac and a Pi.
- `CPU_OFF` returns success and the vCPU goes on running, as on the native
  machine.
- The model keeps one `GICD_IGROUPR0` for all CPUs. Linux never writes it.

# Architecture

hvi runs an unmodified Linux kernel under one of three host backends behind a
single entry point, and it is itself the virtio backend, so a guest gets the
same device model wherever it runs.

This page describes the design. For attaching a tool, read
[plugins.md](plugins.md). For linking the library, read
[embedding.md](embedding.md).

## 1. Guests, hosts and backends

hvi separates the **guest architecture**, which decides the boot protocol,
from the **host backend**, which decides the hypervisor API. Three
combinations are built, selected at compile time by target triple.

| Guest | Host | Backend module | Hypervisor API |
| --- | --- | --- | --- |
| aarch64 | macOS, Apple silicon | `arch/aarch64/hvf.rs` | Hypervisor.framework (`applevisor`) |
| aarch64 | Linux | `arch/aarch64/kvm.rs` | KVM (`kvm-ioctls` 0.25) |
| x86-64 | Linux | `arch/x86_64/kvm.rs` | KVM (`kvm-ioctls` 0.25) |

Two kinds of difference cut across those three, and conflating them is the
usual mistake:

- **Host differences** live in the backend modules, and in `hypervisor/kvm.rs`
  for what the two KVM backends share: creating the VM, mapping guest RAM,
  entering the guest and serving its exits, and how a kick and an interrupt
  line reach the guest. Confinement is a host difference too, and lives in
  `sandbox/`.
- **Guest-architecture differences** live in the loader and layout modules
  under `arch/<arch>/`, and they are larger. An arm64 guest gets an `Image`, a
  devicetree and PSCI. An x86-64 guest gets a `bzImage` or an uncompressed
  `vmlinux` with a `boot_params` page, an e820 map, an MP table and ACPI tables
  for power-off and reset. Some devices are architecture-specific too: PL011
  against 16550, and a CMOS RTC and ACPI power-management registers that only
  x86 needs.

Porting to a new host backend means a new `arch/<arch>/<hypervisor>.rs` file
with a `Kick` and an `IrqLine` implementation and a `Guest` built from them, its
`mod` line in `arch/<arch>/mod.rs`, its `use ... as backend` line and its target
in the build guard, both in `lib.rs`, and its dependencies in `Cargo.toml`.
Porting to a new guest architecture is a much larger job.

On any other target the build stops with a compile error.

```mermaid
flowchart TB
    subgraph host["Host process (hvi)"]
        cli["main.rs — CLI<br/>parses flags → BootConfig"]
        subgraph backend["backend boot(BootConfig) → Stop  (one of three, cfg-selected, called by hvi::boot)"]
            direction LR
            m1["arch/aarch64/hvf.rs<br/>Hypervisor.framework"]
            m2["arch/aarch64/kvm.rs<br/>KVM / aarch64"]
            m3["arch/x86_64/kvm.rs<br/>KVM / x86-64"]
        end
        subgraph shared["Shared core"]
            direction LR
            arch_["arch/aarch64: loader / layout / fdt<br/>arch/x86_64: loader / layout / mptable / acpi"]
            dev["devices/virtio: queue / block / net / tap<br/>vsock / fs<br/>devices/legacy: pl011 / uart16550 / rtc_cmos / acpi_pm"]
            obs["plugin: the seam<br/>plugin::builtin · events ledger"]
            vm["hypervisor: vcpus / guest / kvm / quiesce"]
            rt["run: spawn / stop / supervisor<br/>io_threads · signal<br/>terminal: filter / raw / input"]
            conf["sandbox: seatbelt (macOS)<br/>seccomp (Linux, bpf)"]
            gm["memory: GuestRam over vm-memory<br/>SharedRam: memfd / POSIX shm"]
        end
        cli --> backend
        backend --> shared
        shared --> gm
    end
    guest["Guest: unmodified Linux kernel + initramfs/rootfs"]
    ledger["--events path: RawEvent NDJSON file"]
    backend -. "vCPU run loop, guest RAM" .-> guest
    obs -- "one JSON object per line" --> ledger
```

### The entry point

Every backend has the same signature:

```rust
pub(crate) fn boot(cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>>;
```

`hvi::boot` calls the one for the host target and returns its error as a
`BootError`, so the CLI and a linking crate use the same call. `hvi::spawn`
makes the same call on a thread of its own. `Stop` is `SystemOff`, `SystemReset`
or `Requested`, the last when the host asks the run to stop or the control socket
ends it.

`SystemReset` stops the process. hvi never reboots a guest.

One setting a caller supplies is not in `BootConfig`: the `HVI_*` environment
variables. See
[embedding.md](embedding.md#configuration-outside-bootconfig).

## 2. Guest memory

`GuestRam` (`memory/guest.rs`) is what makes the device models host-neutral: a
wrapper over a `vm-memory` `GuestMemoryMmap` whose regions are the guest's RAM.
Every device reads and writes guest memory only through it, and `memory()`
returns the collection for the rust-vmm crates that take guest memory. Its read
accessors live on `GuestRamView`, which it dereferences to; a tool that only
reads builds a `GuestRamView` of its own over the RAM descriptor, with
`PROT_READ` pages and no write accessor.

Every accessor that takes a guest address resolves it through the view's table
of the collection's regions and fails with an `io::Error` on a range the guest
does not own. A range that would cross from one region into the next is refused.
`scan()` takes no guest address: it walks each region's host mapping and maps
its hits back to guest addresses.

`host_ptr` is a bounds-checked raw pointer into one region for the iovec
paths. It is a raw pointer rather than a `&mut [u8]` because a guest can point
two descriptors at one address, which would alias the borrow.

The backing object comes from `memory/shared.rs`: a memfd on Linux or a POSIX
shared-memory object on macOS, unlinked from the namespace as soon as it is
created. A tool given the descriptor builds a `GuestRamView` over the same
pages, read-only; no other process can open them by name. Each region is a
`MAP_SHARED` mapping of that object at its file offset, and the hypervisor gets
it as a KVM memory slot or through `hv_vm_map`. A region's address, size and
file offset are multiples of 1 MiB, so they are page-aligned on any host.

### Guest memory maps

<img src="img/guest-memory-arm64.svg" alt="arm64 guest physical address space: GIC at 0x08000000, PL011 UART at 0x0c000000, virtio-mmio window from 0x0d000000, RAM at 0x40000000" width="720">

**aarch64** (`arch/aarch64/layout.rs`). Devices sit above the GIC, RAM at 1 GiB.

| Region | Address | Size | IRQ |
| --- | --- | --- | --- |
| GIC distributor | `0x0800_0000` | `0x1_0000` | |
| GIC CPU interface (v2) | `0x0801_0000` | `0x1_0000` shared | |
| GIC redistributor (v3) | `0x080A_0000` | `0x2_0000` per vCPU | |
| PL011 UART | `0x0c00_0000` | `0x1000` | SPI 1, INTID 33 |
| virtio-blk | `0x0d00_0000` | `0x200` | SPI 2, INTID 34 |
| virtio-net | `0x0d00_0200` | `0x200` | SPI 3, INTID 35 |
| virtio-vsock | `0x0d00_0400` | `0x200` | SPI 4, INTID 36 |
| virtio-fs share `i` | `0x0d00_0600 + i * 0x200` | `0x200` | SPI `5 + i`, INTID `37 + i` |
| RAM | `0x4000_0000` | `--mem-mib` | |

INTID is `32 + SPI` on both backends. Every device window sits inside
`DEVICE_WINDOW_BASE`..`DEVICE_WINDOW_END` (`0x0800_0000`..`0x4000_0000`),
because a guest whose boot page table is fixed at link time maps only that
range as device memory and cannot reach MMIO outside it. They sit above the
GIC rather than below because `hv_gic`'s redistributor region is far larger
than QEMU's and extends past QEMU virt's `0x0900_0000`.

Those GIC values are the constants in `arch/aarch64/layout.rs`, and the
Linux/KVM backend uses them through `GicLayout::for_vcpus`. **The macOS backend
does not.** It builds its own layout: always v3, bases aligned down to what
Hypervisor.framework requires, and both sizes taken from `hv_gic`'s own getters.
A macOS guest is told whatever the framework reported, which is why a running VM
logs a redistributor region that does not match the table:

```text
[hvi] 2 vCPU(s)  GICD 0x8000000+0x10000  GICR 0x80a0000+0x2000000  UART 0xc000000
```

<img src="img/guest-memory-x86.svg" alt="x86-64 guest memory: RAM from 0 to the MMIO hole at 0xd0000000, devices in the hole, RAM resuming at 4 GiB" width="720">

**x86-64** (`arch/x86_64/layout.rs`). RAM starts at 0 and has a hole.

| Region | Address |
| --- | --- |
| boot stack | `0x6ff0` |
| `boot_params` zero page | `0x7000` |
| PML4 / PDPT | `0x9000` / `0xa000` |
| boot GDT | `0xc000` |
| kernel command line | `0x2_0000` |
| MP table (EBDA) | `0x9_fc00` |
| ACPI tables: RSDP, DSDT, FACS, FADT, MADT, XSDT | `0xe_0000` |
| `bzImage` load / 64-bit entry | `0x10_0000` / `0x10_0200` (a `vmlinux` enters at its `e_entry`) |
| RAM, low half | `0x0` to `0xd000_0000` |
| virtio-blk / net / vsock | `0xd000_0000` / `0xd000_0200` / `0xd000_0400`, GSIs 5 / 6 / 7 |
| COM1 UART | PIO `0x3f8`, GSI 4 |
| CMOS RTC | PIO `0x70` / `0x71` |
| i8042 status and reset command | PIO `0x64` |
| ACPI PM1 event, PM1 control and reset registers | PIO `0x600` / `0x604` / `0x606`, SCI on GSI 23 |
| IOAPIC / LAPIC | `0xfec0_0000` / `0xfee0_0000` |
| RAM, high half | `0x1_0000_0000` upward |

Guest RAM cannot be one contiguous span from zero. Two fixed things live under
4 GiB, and RAM over either one breaks, in different ways:

- RAM over the **virtio-mmio window** shadows the device registers. KVM
  services the access from memory and never exits to hvi, so the guest
  registers the device, finds no virtio magic, and never probes it. A silent
  loss of the disk, which is the dangerous half.
- RAM over the **in-kernel LAPIC page** makes KVM refuse the memory region
  outright with `EEXIST`, and the VM does not start. A loud failure.

RAM stops at the device window, the lower of the two, and the remainder
resumes at 4 GiB as a second KVM slot into the same memfd, at file offset
`low_bytes`. The two host mappings are separate, so the high half's address
cannot be derived from the low half's.

A tool reading guest memory must therefore read `ram_regions()` rather than
assume a count. It returns one region on arm64, and on x86-64 one region up to
3328 MiB of guest RAM and two above that.

## 3. Boot protocols

### 3.1 aarch64: Image, devicetree, PSCI

```mermaid
flowchart TB
    A["Payload::load: linux-loader PE::load(kernel)<br/>magic check, kernel@RAM_BASE+text_offset<br/>image_size read from the header"] --> B
    B["LoadedKernel::plan: GuestLayout::new<br/>dtb@align2M(kernel+image_size)<br/>initrd@align4K(dtb_end)"] --> C
    C["fdt::build → DTB<br/>/chosen /memory /psci /cpus /timer<br/>/intc (GICv3 or v2) /apb-pclk /pl011<br/>virtio_mmio@… per device<br/>hvi-time@d100000 (portable profile)"] --> D
    D["linux-loader load_dtb writes the DTB (2 MiB cap), initrd copied<br/>x0=dtb_addr, pc=kernel_addr<br/>PSTATE=0x3c5 (EL1h, DAIF masked)"]
```

`arch/aarch64/fdt.rs` builds the devicetree the kernel reads at `x0`. It emits
PSCI with `method = "hvc"`, the interrupt controller the backend chose
(`arm,gic-v3`, or `arm,cortex-a15-gic` for the compatible QEMU virt advertises
for its vGICv2), the architected timer PPIs, an `/apb-pclk` fixed 24 MHz clock,
the PL011 console as `stdout-path`, and one `virtio_mmio@…` node per backed
device. The timer node is marked `always-on`, because the hypervisor keeps each
vCPU's timer while the vCPU is out of the guest. Under `--profile
portable-arm64-v1` both backends take the tree's inputs from
`portable::devicetree`: `/timer` has a fixed `clock-frequency` and no
interrupts, and an `hvi-time` node describes the clock device, so one
configuration gives the same tree on both hosts.

`/chosen` also carries a 64-byte `rng-seed`, fresh from the host's CSPRNG for
every boot. Under HVF it is the guest's only entropy source at boot, since the
guest has no RNDR and no SMCCC TRNG. Under KVM, KVM serves the TRNG call too.
Linux credits the seed and overwrites the property in its in-RAM blob.

An 8-byte `kaslr-seed` is drawn the same way. The arm64 kernel takes its KASLR
offset only from it or from RNDR, which an HVF guest does not have and a KVM
guest has only on a host with FEAT_RNG. Without it the kernel logs `KASLR
disabled due to lack of seed`. When KASLR is on, the kernel zeroes the property
once it has read it.

The `/apb-pclk` node is load-bearing rather than decorative: the PL011 node's
`clocks` property points at it twice, and the `amba-pl011` driver needs that
to bind.

Each cpu node's `reg` is the vCPU's MPIDR affinity, numbered the way KVM resets
it: the index's low four bits in Aff0 and the next eight in Aff1, so vCPU 16 is
`cpu@100`. The guest's PSCI `CPU_ON` names its target by that value. The KVM
backend checks at boot that KVM gave each vCPU that affinity, and the macOS
backend writes it into each vCPU's `MPIDR_EL1`. `enable-method = "psci"` is
emitted on the cpu nodes only when there is more than one vCPU.

The DTB's own length feeds initrd placement, so `LoadedKernel::plan` builds it
twice: once against a provisional `0x4000` slot, then again at the settled
layout. Both backends and `dump-fdt` call it.

No firmware and no bootloader. hvi drops the kernel straight into EL1.

On KVM each vCPU starts with PSCI 0.2, and with address and generic pointer
authentication when KVM supports both. KVM hides pointer authentication from a
guest whose vCPUs do not ask for it. Under HVF the guest gets the CPU features
Hypervisor.framework passes through, which on Apple silicon include pointer
authentication. A `--profile portable-arm64-v1` guest gets it on neither: the
profile's baseline ID registers show no pointer authentication, and its KVM
vCPUs do not ask for it.

The GIC version is not a choice. KVM offers the vGIC that matches the host, so
a GIC-400 host gets v2 and refuses more than 8 vCPUs, and a GICv3 host gets
v3. The macOS backend is v3, because Apple's `hv_gic` is one, unless the boot
asks for `--profile portable-arm64-v1`. That profile creates no `hv_gic` and
gives the guest hvi's software GICv2 at the v2 addresses. On KVM the same
profile asks for a vGICv2 alone and refuses a host without one (see
[portable-profile.md](portable-profile.md)).

A v3 guest on KVM takes at most 507 vCPUs, since each vCPU adds a redistributor
frame from a fixed base and the frames must end below the UART.

### 3.2 x86-64: the Linux 64-bit boot protocol

There is no devicetree. hvi fills the boot protocol's structures with
`linux-loader`'s loaders and `LinuxBootConfigurator`. A `bzImage` is entered at
`code32_start + 0x200` and its setup header is taken from the image. For an
uncompressed `vmlinux` ELF, the segments load at their physical addresses, the
entry is `e_entry`, and the setup header is synthesized. A `vmlinux` skips the
decompressor, so it boots without KASLR.

```mermaid
flowchart TB
    A["linux-loader BzImage::load: 0xAA55, 'HdrS', protocol ≥ 2.00, LOADED_HIGH<br/>kernel@code32_start (1 MiB), entry +0x200<br/>or Elf::load(vmlinux): PT_LOADs @p_paddr, entry e_entry"] --> B
    B["boot_params @0x7000 via LinuxBootConfigurator<br/>setup hdr from the image or synthesized; type_of_loader=0xff, cmd_line_ptr=0x20000<br/>e820 from the RAM regions + ramdisk image/size"] --> C
    C["mptable::build @0x9fc00<br/>_MP_ + PCMP: N CPUs, ISA bus,<br/>IOAPIC@0xfec00000, 16 ISA IRQs<br/>acpi::build @0xe0000<br/>RSDP, DSDT (_S5), FACS,<br/>FADT (PM1 @0x600), MADT, XSDT"] --> D
    D["long mode<br/>PML4@0x9000, PDPT 4 GiB identity map, 1 GiB pages<br/>GDT@0xc000<br/>CR0=0x80050033 CR4=PAE EFER=LME|LMA"] --> E
    E["KVM: set_tss_address(0xfffbd000)<br/>set_identity_map_address(0xfffbc000)<br/>irqchip + PIT2, CPUID +RDRAND +RDSEED<br/>+hypervisor +TSC-deadline"] --> F
    F["BSP: rip=entry, rsi=0x7000, rsp=0x6ff0<br/>APs wait for the guest's INIT-SIPI-SIPI"]
```

Three details are load-bearing and were each the difference between a boot and
a failure:

- `set_tss_address` and `set_identity_map_address` must be set on Intel VMX
  even for a long-mode entry. Without them the guest triple-faults.
- CPUID must advertise **RDRAND**, or KASLR stalls waiting for entropy. hvi
  also sets RDSEED.
- The CMOS RTC is not optional. An unimplemented PIO read returns `0xff`, so
  the update-in-progress bit would never clear and a guest polling it with
  interrupts disabled spins forever, before the console is up.

CPUID also sets the hypervisor bit and the TSC-deadline bit, which older KVMs,
such as Linux 6.8's, leave out of the CPUID they report. With the hypervisor bit
the guest reads KVM's leaves and uses every paravirtual feature they list, such
as kvm-clock, steal time and paravirtual EOI, IPIs and TLB flushes. It starts on
kvm-clock, and moves to the TSC when the host's TSC is invariant. A Linux guest
also runs its local APIC in x2APIC mode, which it allows without interrupt
remapping only under a hypervisor. With the TSC-deadline bit the guest runs its
APIC timer in that mode and skips calibrating it at boot.

With kvm-clock set up, a vCPU can tell the guest it was paused (section 5). A
vCPU that parked for a second or more, and the boot vCPU after a safe point
whose pauses add up to a second or more, call `KVM_KVMCLOCK_CTRL` before they
enter the guest again. Each call leaves a mark that resets the soft-lockup check
of its vCPU and the guest-wide RCU stall and hung-task checks, so the pause does
not look like a lockup. Shorter pauses are not marked, so frequent observations
leave those checks armed.

Only vCPU 0 is initialised. The APs are brought up by the guest itself, with
INIT-SIPI-SIPI serviced by the in-kernel LAPIC.

hvi appends `console=ttyS0` and one `virtio_mmio.device=` entry per attached
device to the command line, spliced in before the first standalone `--`, so
arguments meant for `init` are not read by the kernel.

## 4. Device model

hvi speaks **virtio-mmio** on every backend, x86 included, which avoids a PCI
host bridge and lets one set of device models serve all three.

```mermaid
sequenceDiagram
    participant G as Guest vCPU
    participant B as Backend run loop
    participant D as Device (blk/net/vsock/fs)
    participant M as GuestRam
    participant L as Event ledger
    G->>B: MMIO/PIO exit @ device window
    B->>D: mmio(off, is_write, value)
    D->>M: read/write descriptors + buffers
    D->>L: CapturedEvent (block / net / SNI)
    D->>G: set its IRQ line (GIC SPI / IOAPIC GSI)
    B->>G: resume
```

Each device sets its own interrupt line, from the methods that change its
interrupt level, so the line is set under the device's lock. A device sets the
line only when the level differs from the one the line last took, so it tries
again after a failure. How the line reaches the guest is the one device-facing
thing that differs by backend:

- **macOS/arm64**: `gic_set_spi(INTID, level)` on the in-kernel GICv3. A virtio
  line that rises on an I/O thread also kicks the vCPUs. The console UART's line
  never kicks.
- **macOS/arm64, portable profile**: the line is set in the software GICv2
  (`devices/gicv2.rs`), and every vCPU the GIC routes it to, other than the
  calling thread's own, is woken. See [The software GICv2](#the-software-gicv2).
- **Linux/arm64**: `vm.set_irq_line(spi_gsi(SPI), level)`, the same call for
  vGICv2 and vGICv3. The `hvi-time` timers raise a PPI instead, with the
  vCPU index in the line number.
- **x86**: `vm.set_irq_line(GSI, level)` on the in-kernel IOAPIC, GSIs 4 to 7.

### Devices

- **virtio-blk** (`devices/virtio/block.rs`, id 2) backs `--disk`. It advertises
  `VIRTIO_BLK_F_FLUSH` and honours a flush with a real sync. Its requests are
  served on a worker thread of its own (`block::serve`), not in the vCPU's
  exit: a notify only wakes the worker, which takes each chain, makes the disk
  call with no device lock held, and returns the chain, in order and one at a
  time. A write's data is copied out of guest RAM when the chain is taken,
  under the lock, so a driver that resets the device while the write is in
  flight cannot change what lands on the disk. A flush or a write that waits seconds on a busy host disk then stops
  no vCPU. The worker starts with the I/O threads, runs under the `vmm`
  seccomp filter and raises the line from its thread, as the network relay
  does.
- **virtio-net** (`devices/virtio/net.rs`, id 1) has three modes. See
  [networking.md](networking.md). It offers `VIRTIO_F_VERSION_1` and
  `VIRTIO_NET_F_MAC` and no offloads. Queue 0 is RX, queue 1 is TX.
- **virtio-vsock** (`devices/virtio/vsock.rs`, id 19) is the exec channel. Host
  CID 2, guest CID 3, port 1024.
- **virtio-fs** (`devices/virtio/fs/`, id 26) has one device per export, each
  with a hiprio and a request queue. On macOS (`fs/server.rs`) the VMM answers
  the guest's FUSE messages itself. On Linux (`fs/vhost_user.rs`) the device
  is a transport in front of a vhost-user daemon the caller runs, such as
  `virtiofsd`. The daemon is handed the rings and the memfd behind guest RAM
  and serves the requests in its own process. See
  [storage-and-sharing.md](storage-and-sharing.md).
- **hvi-time** (`devices/hvitime.rs`, portable profile only) is the guest's
  clock and timers: a read-only pvclock page at `0x0d100000` and one timer
  block per vCPU at `0x0d110000`, raising PPI 20. See
  [hvi-time](#hvi-time) below.

A write of 0 to a device's STATUS register resets it: every queue returns to
its unprogrammed state, the interrupt is withdrawn, and state the driver
created goes with them (vsock sessions, the virtio-fs FUSE session). A driver
that binds again after that starts from a device in its boot state.

The serial console is a **PL011** on arm64 and a **16550** on x86. The x86 one
wraps `vm-superio`'s `Serial`. The UART sets COM1's line whenever its level
changes, under its lock. The guest programs the pin as edge-triggered, so the
line is high exactly when an IIR read would report an interrupt. To keep it so,
the wrapper tracks THR-empty itself and answers IIR reads. Both write guest
output to stdout through `terminal::ConsoleFilter`, which drops the escape
sequences that change host state or make the terminal answer (see
[security.md](security.md#what-the-guest-can-reach)).

### The software GICv2

`devices/gicv2.rs` is a GICv2 distributor and CPU interface in software, for
the portable profile on Hypervisor.framework, which has no GIC without
`hv_gic`. It mirrors what a guest reads from KVM's vGICv2 on a Raspberry Pi 5:
the identification registers, five priority bits, fixed SGI and PPI
configuration, and banked read-only targets for interrupts 0-31. It keeps each
interrupt's enable, line level, software latch and active state apart, so a
checkpoint can carry all four (`Gicv2::state`, `Gicv2::restore`). On KVM,
`arch/aarch64/vgicv2.rs` reads and writes the in-kernel vGICv2 in the same
form, through the vGIC device's register attributes, with the line levels
from hvi's own devices (see
[portable-profile.md](portable-profile.md#capture-and-restore-on-kvm)). The
model knows nothing of the hypervisor:

- The backend routes guest accesses to `GICD` and the first 4 KiB of `GICC` to
  it. The rest of the `GICC` window reads as zero.
- Before every guest entry the vCPU thread sets the vCPU's IRQ line from
  `Gicv2::irq_pending`. Hypervisor.framework drops that line after each run,
  and only the vCPU's own thread can set it.
- A change that gives another vCPU an interrupt returns it to be woken: a
  notify for one asleep in an emulated WFI, and `hv_vcpus_exit` for one in a
  run.
- Without `hv_gic` a guest WFI exits at once, so the vCPU thread steps past it
  and sleeps until the GIC has an interrupt for it, the guest's virtual timer
  is due, a pause asks it to park, or the VM stops.
- The virtual timer reaches the guest only as a `VTIMER_ACTIVATED` exit. hvi
  raises PPI 27 and keeps the timer masked until the guest's `GICC_EOIR` for
  it. It then lowers the line and unmasks, unless the timer still fires.

### Used-ring ordering

`Queue::push_used` writes the used element and then the index. Completions
happen on worker threads while the guest runs on another core, so the publish
carries a release fence per drain pass: free on x86, `dmb` on arm64. Without
it an arm64 guest observed the bumped index before the element and broke its
virtqueue with `id 65 is not a head!`.

`ordering_tests` in `devices/virtio/queue.rs` drives the real `push_used`
against a consumer that behaves like the driver. It demonstrates the defect and
the fix, and it does not reliably catch a regression, so it is `#[ignore]`d and
run weekly.

Every descriptor-chain walker refuses an index outside the ring and caps the
walk at the ring size, so a cycle runs out of budget. Re-programming any queue
register clears `ready`.

### hvi-time

`devices/hvitime.rs` gives a portable guest a clock in nanoseconds, so that
it keeps time at one rate on hosts whose counters do not (24 MHz on Apple
silicon, 54 MHz on the Pi). It knows nothing of the hypervisor:

- The backend supplies the guest's counter (`GuestCounter`) and the timers'
  lines (`TimerLine`), maps the page read-only into the guest and routes the
  timer window to `HviTime::mmio_read` and `mmio_write`.
- hvi writes the page under a sequence count at boot, at every restore and
  after a host sleep. The guest reads it without an exit.
- One thread per VM, started with the I/O threads and ended before them,
  sleeps until the earliest armed deadline and raises the vCPU's line. It
  wakes at least once a second to look for a host sleep, and publishes the
  page again after one (`HostClock`, read from the host by `SystemClock`). On
  macOS it runs under `THREAD_TIME_CONSTRAINT_POLICY`, on Linux with a 1 ns
  timer slack and the `vmm` seccomp filter.
- Lock order: the device's lock, then the GIC's. Wakes of vCPUs happen after
  the device's lock is released.
- `HviTime::state` and `HviTime::restore` carry its canonical checkpoint
  state.

## 5. Concurrency and failure

`hypervisor/quiesce.rs` parks every vCPU at a safe point so an observation sees
a still guest. `CpuHandle::pause()` requests the quiesce, kicks the other vCPUs,
and waits up to 500 ms for every other vCPU that has started to park. A stop
ends the wait at once, and the pause fails. The calling vCPU never parks itself.
Every KVM vCPU counts as started once its thread runs, since one the guest has
not brought up waits inside `KVM_RUN`, where a kick reaches it. On macOS a
secondary the guest has not brought up waits for `CPU_ON` outside the hypervisor
and is not waited for.

The control socket (`checkpoint/server.rs`) is the other requester, and it is
not a vCPU. Its `pause` first closes the I/O threads' `PauseGate`
(`teardown.rs`): each of the console reader, the network relay, the agent
bridge and its connections, and the macOS virtio-fs workers passes the gate
around every call that takes a device mutex or writes guest RAM, so the pause
waits only for the work in progress, never for traffic. The virtio-blk worker
holds the gate from taking a chain to returning it, its disk call included,
so the pause waits for at most one request, with the vCPUs still running,
and finds no chain half-served. It then calls
`Vcpus::pause_from_control`, which waits for every started vCPU, since its
caller parks none. The two waits share one 2 s deadline, and a pause that misses
it is undone and the VM runs on. The agent bridge and the network relays read
their non-blocking sockets inside the gate, so what they have read is in a
device by the time a pause completes. Two pieces of input can still be off the
host and not yet in a device: the start of a gateway frame whose rest has not
arrived, and one console byte, since the console reader reads stdin, a shared
terminal, outside the gate. Pause and resume lose neither; a checkpoint taken
then drops them.

A `checkpoint` (`checkpoint/server.rs`, `checkpoint/capture.rs`) pauses the
same way, or finds the VM paused already. It then posts an export request to
the vCPUs through `Vcpus::request_export`. Only a vCPU's own thread may read its
registers, so each vCPU does the export at its checkpoint, through the closure
its backend passes to `Vcpus::checkpoint_with`, and stays parked. A vCPU parked
before the request is woken to do it. A second request, `Vcpus::request_platform`,
then has vCPU 0 read the interrupt controller and the counter; on HVF that is
the `hv_gic_state` blob, which the framework gives only with every vCPU
stopped (`arch/aarch64/hvf_state.rs`). With every vCPU parked and every helper
outside the gate, the control thread locks each device mutex, collects and
checks the device states, syncs the disk and writes the bundle
(`checkpoint/bundle.rs`, `checkpoint/ram.rs`), all before it resumes or fences
the VM. See [checkpoint.md](checkpoint.md).

`hvi restore` (`arch/aarch64/hvf.rs`, `checkpoint/restore.rs`) builds the same
machine from a bundle: the VM and GIC as a boot does, RAM copied from the
bundle, the devices from their state. It holds the gate and the quiesce before
any vCPU thread starts, then posts three import requests through
`Vcpus::request_import` and waits for every vCPU between them: each vCPU's
registers, the GIC blob on vCPU 0, each vCPU's GIC CPU interface. The control
socket then starts in `restored-paused`, and its `resume` is the first time
the guest runs on this host. The plugin and the control socket share one quiesce, and whichever
holds it keeps the other out, so neither can release the other's pause.

On every backend, the thread that called `boot` owns the stop. Once the vCPU
threads are spawned it waits in `run/supervisor.rs` on a pipe. A guard held by
each vCPU thread writes it when the thread exits, whatever ended the loop: a
guest-requested stop, a failed entry, an unhandled exit, a failed run, or a
panic. Each of these is reported to `Vcpus` as the run's outcome. A thread
`IoThreads` started, a plugin's among them, reports its panic there too and asks
for the stop. The vsock bridge starts its per-connection threads itself, outside
`IoThreads`. A stop request through a `StopHandle` or `VmHandle::request_stop`
writes the same pipe. `boot` returns the guest's `Stop`, or an error that names
the vCPU or thread and the failure. The first report is kept, except that a
failure replaces an earlier stop. A failure that is not kept is printed. With no
report, a request makes `boot` return `Stop::Requested`.

The loop then ends the VM through `Vcpus::stop` in `hypervisor/vcpus.rs`, which
clears the running flag, kicks the vCPUs out of the hypervisor, and then
releases the quiesce so no vCPU stays parked. It joins the vCPU threads and then
the I/O threads, each within one second, and leaves a thread still running at
its deadline and names it in the error. The kick is the backend's:
`hypervisor/kvm.rs` holds the one the two KVM backends share, and the macOS
backend kicks with `hv_vcpus_exit`. The vCPU threads are named `vcpu0`, `vcpu1`
and so on, so the panic hook's report says which vCPU panicked. A panic that
leaves the vCPU thread is caught where the thread starts, and its message goes
in the error. The macOS backend catches it at the loop instead, to add the
vCPU's last exit reason and its program counter. Under the seccomp sandbox the
report has to stay unsymbolized: with `RUST_BACKTRACE` set it opens the binary,
which the vCPU allowlist refuses, and the process dies of `SIGSYS` after the
message.

Device and ledger mutexes on the macOS backend and in the helper threads go
through `sync::lock_or_recover`, which takes a poisoned lock so the panic that
poisoned it is reported once, where it happened. The vCPU-side device locks on
the Linux and x86 backends use `.lock().unwrap()`.

## 6. The event ledger

What the VMM sees at its own device models lands in one NDJSON stream
(`events.rs`), one compact JSON object per line, whose shape is pinned by
exact-string tests.

Because hvi *is* the virtio backend, these are observed rather than reported:
the guest cannot decline to be seen at a device it has to use. What the stream
is and is not, including its buffering and loss behaviour, is in
[observability.md](observability.md).

## 7. The extension seam

A VMM holds the guest's memory, can park its vCPUs, and is the other end of
every virtio request. `plugin/api.rs` offers those three things to a tool, in
four traits. The whole seam is optional: with no plugin the hooks cost one null
check per guest entry.

The contract, the hook ordering and the rules that fail quietly are in
[plugins.md](plugins.md).

## 8. Source map

Kept separate from the diagrams above on purpose: this is where to look, not
how it works.

| Area | Files |
| --- | --- |
| Crate root and backend selection | `lib.rs`, `arch/<arch>/mod.rs` |
| CLI and configuration | `main.rs`, `config.rs` |
| Backends | `arch/aarch64/hvf.rs`, `arch/aarch64/kvm.rs`, `arch/x86_64/kvm.rs`, `arch/aarch64/smoke.rs` |
| arm64 guest support | `arch/aarch64/`: `loader.rs`, `layout.rs`, `fdt.rs`, `esr.rs`, `portable.rs`, `profile.rs` |
| x86-64 guest support | `arch/x86_64/`: `loader.rs`, `layout.rs`, `mptable.rs`, `acpi.rs` |
| Guest memory | `memory/`: `guest.rs`, `shared.rs`, `region.rs` |
| Devices | `devices/virtio/`: `queue.rs`, `mmio.rs`, `block.rs`, `net.rs`, `tap.rs`, `vsock.rs`, `fs/server.rs`, `fs/fdlimit.rs`, `fs/vhost_user.rs`; `devices/legacy/`: `pl011.rs`, `uart16550.rs`, `rtc_cmos.rs`, `acpi_pm.rs`; `devices/irq.rs`; `devices/gicv2.rs`, `devices/hvitime.rs` (portable profile) |
| Host terminal | `terminal/`: `filter.rs`, `raw.rs`, `input.rs` |
| Confinement | `sandbox/seatbelt.rs` (macOS), `sandbox/seccomp.rs` (Linux), `resources/seccomp/*.json` |
| Control socket, checkpoints and restore | `checkpoint/`: `control.rs`, `server.rs`, `profile.rs`, `capture.rs`, `bundle.rs`, `ram.rs`, `cpu.rs`, `platform.rs`, `restore.rs`; `arch/aarch64/hvf_state.rs` for HVF |
| Extension and observation | `plugin/mod.rs`, `plugin/api.rs`, `hypervisor/guest.rs`, `plugin/builtin.rs`, `events.rs`, `examples/watch_guest.rs` |
| Concurrency | `hypervisor/vcpus.rs`, `hypervisor/kvm.rs`, `run/supervisor.rs`, `run/stop.rs`, `run/spawn.rs`, `io_threads.rs`, `signal.rs`, `hypervisor/quiesce.rs`, `sync.rs`, `teardown.rs`, `devices/virtio/queue.rs` (`ordering_tests`) |

Feature bits, device ids, the virtio-mmio register map and the
`virtio_net_hdr_v1` layout come from `virtio-bindings`, which is bindgen
output from the kernel headers. The vsock op codes, packet header and CIDs are
hvi's own, because that crate has no vsock module.

## See also

- [testing.md](testing.md) for what CI runs and where.
- [limitations.md](limitations.md) for the known limits.
- [security.md](security.md) for the threat model.

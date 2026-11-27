# Known limits

Every limit in one place, with what it costs you. The last column separates
three things a reader should not have to guess between:

- **Design** is a deliberate choice. It is not going to change by itself.
- **Defect** is something that should work and does not.
- **Platform** is imposed from outside hvi.

## Platforms and features

| Limit | Consequence | Kind |
| --- | --- | --- |
| The backend is chosen at compile time by target triple. | There is no runtime flag to pick one. Cross-compiling checks a backend, it does not produce a runnable one for this host. | Design |
| virtio-fs is served in-process on macOS and by the caller's vhost-user daemon on Linux. | On Linux the caller starts a daemon, such as `virtiofsd`, per export and passes its socket. The directory, the mode and the daemon's sandbox are the daemon's options, which hvi cannot check. | Design |
| A Linux export produces no file-level events. | The daemon serves the guest in its own process, so the ledger sees none of it. The block and network boundaries are unaffected. | Design |
| Only three host targets are supported. | aarch64 macOS, aarch64 Linux and x86-64 Linux. On any other target the build stops with a compile error. | Design |
| The macOS backend needs macOS 15 or newer. | It calls `hv_gic_*`, which arrived in macOS 15. hvi runs no version check, so an older host fails when it first reaches the framework rather than with a clear message. | Platform |
| The KVM backends need kernel 4.11 or newer. | hvi stops a vCPU through `kvm_run.immediate_exit` and refuses to boot without `KVM_CAP_IMMEDIATE_EXIT`, which 4.11 added. | Platform |
| No published crate. | Build from source, or take a release binary; pin a commit or a release tag when you depend on it. | Design |
| The arm64/KVM backend is unit-tested on its stop path and its vGIC irqfd list only. | Its tests are the KVM tests in `src/hypervisor/kvm.rs`: the stop tests, of how a run stops (a vCPU thread that ends, a stop request, plugin threads, the lifecycle records, and a kick), and the queue notification test, which runs a few guest instructions in a bare VM. They need `/dev/kvm`. `src/arch/aarch64/kvm/gic.rs` also tests the vGIC's irqfd list, with and without `/dev/kvm`. The rest of that backend is cross-linted and booted. | Defect |

## Devices

| Limit | Consequence | Kind |
| --- | --- | --- |
| virtio-blk disks attach at boot only. | No hotplug, no PCI at all. | Design |
| A disk image is locked while a guest has it open. | A writable image takes an exclusive `flock` and a read-only one a shared `flock`, so a second hvi on a writable image, or an hvi writing an image another hvi reads, fails to boot with "the image is open elsewhere". Many guests can read one image. The lock holds against other hvi processes: a VMM that takes OFD locks takes a lock `flock` does not see, and a filesystem without a lock service, such as NFS without lockd, refuses the lock and so the boot. A writable block device is also opened `O_EXCL` on Linux, which holds against another device node for it and against a mount; a read-only open through another node is not held against a writer. | Design |
| A disk's requests run one at a time. | Each disk has one worker thread, so the host sees one request at a time whatever the guest queues, and a read waits behind a flush queued before it. | Design |
| A disk's worker uses host CPU while it polls. | After a request the worker polls its queue for up to 32 microseconds, or the disk's `poll-max-us`, while the guest's requests keep coming that closely. A guest that sends one small request after another keeps one host thread per such disk busy. `poll-max-us=0` turns the poll off for that disk. | Design |
| Busy disks share the host's cores with the vCPUs. | A request runs on the disk's worker while the vCPU that sent it waits. When a guest sends small requests to several disks at once, each request takes longer the more disks are busy. The cost is largest once the vCPUs and the busy workers outnumber the host's cores. On a Mac only the performance cores count. | Design |
| A disk whose backing file or plugin sink stops answering holds the vCPU that resets the disk. | The reset waits for the request in flight until the VMM's stop ends the wait. See [architecture.md](architecture.md#the-disk-worker). | Design |
| An MMIO access to an address no device claims reads 0, and a write there is dropped. | The run goes on. With `HVI_MMIO_TRACE` set, hvi writes a line to stderr with the address, the width and the program counter, at most 10 at once and then one every 500 ms. It is off by default, because the line is written on the vCPU, and a full stderr would stop it. On x86-64, the program counter of a write is the next instruction's, because KVM has finished the instruction by then. | Design |
| On arm64, an MMIO access with no instruction syndrome, such as a load pair, ends the run. | hvi cannot tell which registers the access names. A cache maintenance instruction on such an address is skipped. | Design |
| An x86-64 port no device claims reads `0xff`, and a write there is dropped. | hvi reports nothing, because Linux probes absent ports at every boot. | Design |
| The PL031 has no alarm, and ignores writes. | vm-superio does not implement the match register. The devicetree gives the RTC no interrupt, so the guest's driver offers no alarm: there is no `wakealarm` file, and `rtcwake` fails with EINVAL. The host's clock is authoritative, so `hwclock -w` does not move the RTC. | Design |
| One virtio-net NIC. | Same. Passing more than one networking flag silently uses the first that matches. | Design |
| No egress from the built-in `--net-stub` stack. | TCP is seen but never forwarded. Real egress needs `--net-gateway` or `--net-tap`. | Design |
| The built-in stack resolves no DNS name. | The guest gets a reply with no addresses. Name resolution needs `--net-gateway` or `--net-tap`. | Design |
| A tap write that fails drops the guest's frame. | The write fails when the send buffer is full, the tap is detached, its interface is down, or the kernel cannot allocate or accept the frame. The first failure writes one line to stderr. The ledger records the frame as egress before the write, so a dropped frame still appears in it, unless the ledger's buffer is full. The send buffer fills only when the tap's creator lowered it. | Design |
| A gateway frame above 64 KiB ends the relay. | The relay writes one line to stderr and shuts the gateway socket down, so the guest receives nothing more from the gateway and its own frames are dropped for the rest of the run. Every gateway's default MTU is far below 64 KiB. | Design |
| virtio-fs: one request queue per share on macOS, and no DAX window on either host. The macOS device also takes no indirect descriptors. A Linux export takes as many request queues as `num_queues=` and its daemon allow. | Throughput ceiling per share. | Design |
| virtio-fs: the export overlap check covers one process. | Two hvi processes can export the same tree, or a tree and a directory inside it, with one writable and one read-only. An owner and a mode a guest stores through the writable export, setuid and setgid included, reach the other guest. See [storage-and-sharing.md](storage-and-sharing.md#virtio-fs-shares). | Design |
| virtio-fs: the guest cannot set, read or remove `com.apple.` attributes. | The names are hidden: `LISTXATTR` omits them and the other three calls return `EOPNOTSUPP`. A guest copy of a quarantined file loses the quarantine. The gate covers attributes, not bytes, and on exFAT, FAT and some network volumes the guest can remove, truncate or replace the AppleDouble `._name` sidecar that holds them, so it can take attributes off a host file or put them on it. See [storage-and-sharing.md](storage-and-sharing.md#virtio-fs-shares). | Design |
| An x86-64 KVM guest has interrupt lines for 17 virtio devices, an arm64 KVM guest for 222, and a macOS guest for the SPIs of Hypervisor.framework's GIC. | The disks, the network, the agent's vsock device and the exports share them, in the order they are attached. A configuration with more devices fails the boot before the VM exists, rather than giving a device an interrupt the controller does not have. | Design |
| An x86-64 guest finds its devices through ACPI. | The DSDT describes every virtio-mmio device; the kernel command line carries no `virtio_mmio.device=`. A kernel without `CONFIG_ACPI`, or booted with `acpi=off`, sees no disk, network, vsock or export. | Design |
| A Linux export's daemon that stops answering holds the thread waiting on it. | During boot that is the boot. Once the guest runs, a device's activation and its reset wait for the daemon's answer with the export's virtio-mmio state locked. The vCPU that wrote DRIVER_OK or the reset waits, and so does any other vCPU that reads or writes the export's status, queue or config registers, until the VMM stops and ends the connection. A `CpuHandle::pause()` fails meanwhile, since the waiting vCPU cannot park. | Design |
| The agent socket relays at most 1023 connections at once. | A connection past the bound is accepted and closed at once, so the client reads EOF, as it does for a session the agent lost, and hvi logs that it reached the bound. A guest that never answers keeps the place of a client that wrote and then closed. See [embedding.md](embedding.md#what-the-guest-agent-must-provide). | Design |
| An agent socket raises the soft open-file limit. | By the descriptors that its connections hold at their bound, once for the process and as far as the hard limit allows. A program that embeds hvi keeps the raised limit after the VM stops. | Design |
| A Linux export's daemon that exits, or that a message to it fails on, ends that export. | hvi shuts the connection down after a failed message, so the daemon exits. The guest's requests on the export get no answer and hang. hvi does not reconnect and does not restart the daemon. | Design |
| With the split irqchip, an export's completion reaches the guest while the guest has its interrupt masked. | The IOAPIC holds an edge of hvi's own devices until the guest unmasks the input, but KVM delivers a write to a call eventfd at once. Linux handles an edge on a line it has disabled itself. | Design |
| With `--irqchip kernel`, an x86-64 export's completions pass through hvi. | A completion wakes an hvi thread, which raises the IOAPIC pin. A plain irqfd on a pin of KVM's in-kernel IOAPIC raises the line and lowers it at once, which a pin the guest has masked loses, and KVM delivers it from a kernel worker thread, which is slower. With the split irqchip and on arm64 the call eventfds are irqfds, and KVM delivers a completion with no hvi thread. | Design |
| With `--irqchip kernel`, KVM can delay a virtio interrupt by about 10 ms under sustained load. | The interrupts are level-triggered in that mode, and KVM's IOAPIC delays an interrupt after a long run of them in which the line was still high each time the guest ended the one before. The line is high then because hvi raises it for a request that completes while the guest drains the queue: hvi does not honor the driver's request to suppress interrupts meanwhile. Nothing is lost. | Design |
| With `--irqchip kernel`, console input that arrives while the guest has the serial port's interrupt masked can stall. | The serial port's interrupt is edge-triggered, and KVM's IOAPIC drops an edge that arrives while the guest has the pin masked, as Linux masks one to move its interrupt off a CPU that goes offline. The port's line stays high, so later input makes no edge. With the split irqchip the IOAPIC holds the edge. | Defect |
| A completion an export's daemon sends after a device reset, before the driver's next DRIVER_OK, still interrupts the guest. | With the split irqchip and on arm64 KVM the call eventfds are irqfds, which stay registered across a reset. A daemon that finishes a request it had in flight makes KVM deliver the interrupt, and the guest reads an interrupt status of 0 and counts one spurious interrupt. With `--irqchip kernel` hvi drops such a completion. | Design |
| `uid=` and `gid=` are macOS only. | On Linux ownership is the daemon's, so a `socket=` export refuses them, and the deprecated `--fs-uid` and `--fs-gid` do nothing there. virtiofsd 1.13 can translate ids with `--translate-uid` and `--translate-gid`. | Design |

## virtio-fs resource limits

| Limit | Consequence | Kind |
| --- | --- | --- |
| The node table has no cap. | `FORGET` is what shrinks it between device resets. A guest that never sends one grows the table until it resets the device. Guest-driven, unbounded. See [#34](https://github.com/brig-sh/hvi-vmm/issues/34). | Defect |
| A guest waiting on a lock is retried every 20 ms. | A `SETLKW` whose lock is held is parked on the device and retried without blocking: in the drain that serves the holder's unlock, and on the worker's tick for a lock a host process holds. A lock a host process gives up is seen within one tick. A parked request keeps its descriptor chain, so waiters may hold at most a quarter of a share's request ring, and a `SETLKW` that would take more fails with `ENOLCK`. INIT offers a largest request that fits beside them, 188 pages on a 256-entry ring. A flock conversion gives its held lock up before it waits, as `flock(2)` does. The wait cannot be interrupted: virtio-fs carries no `FUSE_INTERRUPT`, so a killed guest process stays in the wait until the lock is granted, as on any virtio-fs. | Design |
| The handle budget is per export, the descriptor table is per process. | Each export refuses `OPEN`/`OPENDIR` past its own budget with `ENFILE`. `CREATE`, `TMPFILE` and cached directory descriptors are not counted, so several busy exports can still exhaust the table. | Defect |
| The open file limit is raised when the first share is set up. | A boot with no share never raises it and never logs the line. macOS only. | Design |
| A node keeps at most 16 alias paths. | A file with more than 16 hard links inside a share can lose a name from the table. | Design |
| Symlink expansion stops at 40. | Deeply chained links end as `ELOOP`. | Design |
| The export root is resolved by full path once, before the guest starts. | The operator's path is canonicalized and opened once, and the root node's key is taken from that descriptor. The guest cannot influence this step. Resolution after it is by parent descriptor with `O_NOFOLLOW`. | Design |
| Under the sandbox, renaming an export root away leaves the guest's requests refused. | The Seatbelt grant is on the resolved root path. Until the root is back at that path, every request but SYNCFS gets `EPERM`. SYNCFS goes through the open root descriptor and keeps working. | Design |

## Guests and CPUs

| Limit | Consequence | Kind |
| --- | --- | --- |
| 254 vCPUs on x86-64. | The MP table and the ACPI tables give each vCPU a one-byte local APIC id and the IOAPIC the next one, so more vCPUs would share ids. x2APIC ids would lift the cap. | Design |
| 8 vCPUs on a GICv2 arm64 host. | GICv2 addresses at most 8 CPU interfaces. The guest's controller follows the host's, so this is not a choice. | Platform |
| 507 vCPUs on a GICv3 arm64 Linux host. | Each vCPU adds a redistributor frame from a fixed base, and the frames must end below the UART. Moving the UART or the redistributors higher would lift the cap. | Design |
| An x86-64 guest's workqueue watchdog counts a pause. | Linux's workqueue watchdog reads the kvm-clock mark a paused vCPU gets but does not act on it, so a pause longer than its threshold can make the guest report a workqueue lockup for a pool with work queued. | Platform |
| Frequent long pauses can hide a hung task in an x86-64 guest. | A pause the guest is told of resets its hung-task check, which covers the whole guest, so a pause of a second or more in each of the check's periods keeps a task hung in the kernel from being reported. | Platform |
| An arm64 guest is not told of a pause. | Linux on arm64 has no paravirtual way to learn of one, so a pause longer than the guest's lockup threshold can make it report a soft lockup when it resumes. An x86-64 guest is told through kvm-clock. | Platform |
| x86 vCPUs share one CPUID blob. | The APIC id a guest reports for a secondary CPU varies run to run. | Defect |
| The default `--cmdline` names `ttyAMA0`. | That is the arm64 console. The x86 backend appends `console=ttyS0` itself, so a guest still gets one, but the default leaves a dead `console=` and a bare `earlycon` on the line. | Design |
| `tools/mk-initramfs.py` builds an arm64 initramfs only. | An x86-64 guest needs its own. | Design |
| An x86-64 guest powers off through ACPI only. | A kernel built without `CONFIG_ACPI`, or booted with `acpi=off`, halts on `poweroff`. KVM handles the halt itself, so the run goes on until a signal stops it. `reboot -f` ends it as `SystemReset`. | Design |
| An x86-64 guest of the split irqchip, the default, has no PIT and no PIC. | A guest that needs the PIT or the PIC boots with `--irqchip kernel`. See [guest-images.md](guest-images.md#building-your-own). | Design |
| The split irqchip's IOAPIC serves what Linux programs: edge-triggered inputs, and fixed or lowest priority delivery to 8-bit destinations. | A level-triggered entry gets its route, but the IOAPIC keeps no remote IRR and ignores the guest's EOI, so it would not raise the input again while it stays high. An entry set for SMI, NMI, INIT or ExtINT delivery, or with a vector below 16, delivers nothing: the input holds an edge of hvi's own devices until the entry has a route, and KVM drops an export's completion meanwhile. An extended destination ID is not routed; KVM does not offer one to the guest, and 254 vCPUs need none. No hvi device raises a level-triggered interrupt on the split irqchip, and Linux sets its IOAPIC entries for fixed or lowest priority delivery. | Design |
| An x86-64 `vmlinux` boots without KASLR. | The kernel randomizes its placement in the `bzImage` decompressor, which a `vmlinux` skips. Boot a `bzImage` when KASLR matters. | Platform |
| `SystemReset` stops the process. | hvi never reboots a guest and never recovers one. A caller that wants a reboot starts a new run, through `spawn` after a sandboxed run on Linux. On macOS no run can follow one that entered the sandbox in the same process, so a reboot there takes a new process (see [embedding.md](embedding.md#stopping-a-run-from-the-host)). | Design |

## Observability

| Limit | Consequence | Kind |
| --- | --- | --- |
| The ledger is not lossless. | A VMM that is killed, crashes or panics can lose the records not written yet. A write that stalls until the 4 MiB buffer fills makes the ledger drop `block` and `net` records, and the ledger counts them. [observability.md](observability.md#when-a-record-reaches-the-file) says what each case loses. | Design |
| The ledger is not tamper-proof. | An ordinary file written by the VMM. Nothing signs or chains it. | Design |
| `net` records are per packet and egress only. | No flow aggregation. `direction` and `guest_initiated` are constants, not observations. Inbound frames produce no record. | Design |
| `ts` is host wall-clock. | It is not monotonic and can move backwards. | Design |
| TLS SNI is recorded only under `--net-tap` and `--net-gateway`. | The built-in stack records no SNI. | Design |
| An SNI value is a claim on the wire. | It is not proof of a connection, not application identity, and not authorization. Split ClientHellos, resumption, encrypted ClientHello and QUIC yield nothing. | Design |
| `--dump-memory` is denied by the default sandbox. | The file is created after confinement. On macOS use a destination inside a writable `--fs path=` directory, or `--no-sandbox`. On Linux only `--no-sandbox` works. See [#91](https://github.com/brig-sh/hvi-vmm/issues/91). | Defect |
| `--dump-after` needs the guest to still be running. | A guest that stops first produces no dump and no error. | Design |
| A dump is not a checkpoint. | Raw RAM only. No register, device or virtqueue state. Nothing can restore a VM from it. | Design |

## Confinement

| Limit | Consequence | Kind |
| --- | --- | --- |
| Confinement does not drop privilege. | No uid, gid or capability change exists in hvi. It narrows syscalls only. | Design |
| A thread a plugin starts outside `VmHandle::spawn` is unfiltered on Linux. | It starts in `on_attach`, before the filters are armed, and stays unfiltered. | Design |
| Only the `ioctl` rules carry an argument condition, on the request number. | `block` allows a short list of requests. `vmm` and `vcpu` refuse `TIOCSTI` and `TIOCLINUX` and allow every other request. Every allowed `ioctl` request, in all three, reaches every descriptor the process already holds. So does `sendmsg` under `vmm` and `vcpu`. | Design |
| `HVI_SECCOMP=log` turns enforcement off. | The kernel permits the off-list syscall and records it. It is not a softer mode. A glibc build still refuses an open, without a record. | Design |
| Selftests check specific probes. | A pass says those probes matched the profile. It is not proof the sandbox is secure. | Design |
| No external security audit. | Testing, not assurance. | Design |

## Benchmarking

| Limit | Consequence | Kind |
| --- | --- | --- |
| `write_bs_4k` is bimodal. | It lands near 0.85 s or near 2.1 s with nothing between. Its cause is open. Take at least five samples per side and compare the fast mode. | Defect |
| Run-to-run variation is 10 to 20 percent. | Anything smaller is not a result. | Platform |

## Reporting one

If a **Defect** row matters to you, an issue is welcome. If it is a way past
the guest boundary, report it privately: see [SECURITY.md](../SECURITY.md).

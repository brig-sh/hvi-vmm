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
| No published crate, no release, no tag. | Build from source. Pin a commit when you depend on it. | Design |
| The arm64/KVM backend is unit-tested on its stop path only. | Its only tests are the KVM stop tests in `src/hypervisor/kvm.rs`, of how a run stops: a vCPU thread that ends, a stop request, plugin threads, the lifecycle records, and a kick. They need `/dev/kvm`. The rest of that backend is cross-linted and booted. | Defect |

## Devices

| Limit | Consequence | Kind |
| --- | --- | --- |
| At most four virtio-blk disks. | No hotplug, no PCI at all. | Design |
| The PL031 has no alarm, and ignores writes. | vm-superio does not implement the match register. The devicetree gives the RTC no interrupt, so the guest's driver offers no alarm: there is no `wakealarm` file, and `rtcwake` fails with EINVAL. The host's clock is authoritative, so `hwclock -w` does not move the RTC. | Design |
| A portable guest has no PL031. | `portable-arm64-v1` keeps the devicetree and the device set it was published with, and `hvi-time` gives its guest the wall clock (`CLOCK_REALTIME`), so its devicetree has no PL031 node and its bus no PL031: the guest has no `/dev/rtc0`. Adding the device would take a new profile version. See [portable-profile.md](portable-profile.md). | Design |
| One virtio-net NIC. | Same. Passing more than one networking flag silently uses the first that matches. | Design |
| No egress from the built-in `--net-stub` stack. | TCP is seen but never forwarded. Real egress needs `--net-gateway` or `--net-tap`. | Design |
| The built-in stack cannot resolve DNS while confined. | The guest gets a reply with no addresses. Resolution needs a socket the sandbox denies. Only `--no-sandbox` resolves. See [#90](https://github.com/brig-sh/hvi-vmm/issues/90). | Defect |
| An unreachable `--net-gateway` falls back to the built-in stack. | A guest comes up with no egress and exit status zero. The warning line is the only signal. | Design |
| A tap write that fails drops the guest's frame. | The write fails when the send buffer is full, the tap is detached, its interface is down, or the kernel cannot allocate or accept the frame. The first failure writes one line to stderr. The ledger records the frame as egress before the write, so a dropped frame still appears in it, unless the ledger's buffer is full. The send buffer fills only when the tap's creator lowered it. | Design |
| A gateway frame above 64 KiB ends the relay. | The relay writes one line to stderr and shuts the gateway socket down, so the guest receives nothing more from the gateway and its own frames are dropped for the rest of the run. Every gateway's default MTU is far below 64 KiB. | Design |
| virtio-fs: one request queue per share on macOS, and no DAX window on either host. The macOS device also takes no indirect descriptors. A Linux export takes as many request queues as `num_queues=` and its daemon allow. | Throughput ceiling per share. | Design |
| virtio-fs: the export overlap check covers one process. | Two hvi processes can export the same tree, or a tree and a directory inside it, with one writable and one read-only. An owner and a mode a guest stores through the writable export, setuid and setgid included, reach the other guest. See [storage-and-sharing.md](storage-and-sharing.md#virtio-fs-shares). | Design |
| An x86-64 KVM guest has interrupt lines for 11 exports, an arm64 KVM guest for 216. | The next export fails the boot rather than taking an interrupt the controller does not have. | Design |
| A disk image is locked while a guest has it open. | A writable image takes an exclusive `flock` and a read-only one a shared `flock`, so a second hvi on a writable image, or an hvi writing an image another hvi reads, fails to boot with "the image is open elsewhere". Many guests can read one image. The lock holds against other hvi processes: Cloud Hypervisor and QEMU take OFD locks, which `flock` does not see, and a filesystem without a lock service, such as NFS without lockd, refuses the lock and so the boot. A writable block device is also opened `O_EXCL` on Linux, which holds against another device node for it and against a mount; a read-only open through another node is not held against a writer. | Design |
| An x86-64 guest finds its devices through ACPI. | The DSDT describes every virtio-mmio device; the kernel command line carries no `virtio_mmio.device=`. A kernel without `CONFIG_ACPI`, or booted with `acpi=off`, sees no disk, network, vsock or export. | Design |
| A Linux export's daemon that stops answering holds the thread waiting on it. | During boot that is the boot. Once the guest runs, only a device reset waits for the daemon's answer, so it is the vCPU that wrote the reset, until the VMM stops and ends the connection. | Design |
| A Linux export's daemon that exits ends that export. | The guest's requests on it get no answer and hang. hvi does not reconnect and does not restart the daemon. | Design |
| A Linux export's kicks and completions pass through hvi. | hvi has no ioeventfd or irqfd. A queue notify exits to hvi, which signals the daemon, and a completion wakes an hvi thread, which sets the line. Both could go to KVM instead. | Design |
| `uid=` and `gid=` are macOS only. | On Linux ownership is the daemon's, so a `socket=` export refuses them, and the deprecated `--fs-uid` and `--fs-gid` do nothing there. virtiofsd 1.13 can translate ids with `--translate-uid` and `--translate-gid`. | Design |

## virtio-fs resource limits

| Limit | Consequence | Kind |
| --- | --- | --- |
| The node table has no cap. | `FORGET` is what shrinks it between device resets. A guest that never sends one grows the table until it resets the device. Guest-driven, unbounded. See [#34](https://github.com/brig-sh/hvi-vmm/issues/34). | Defect |
| `SETLKW` blocks under the device mutex. | A guest waiting on a lock stalls that whole device, and any vCPU that accesses the device while it waits. That includes the vCPU that issued the request when the queue was shallow enough to drain inline. `boot` waits one second for the vCPUs once the run stops, then finishes the teardown and returns an error naming a stalled one, which keeps running. See [#32](https://github.com/brig-sh/hvi-vmm/issues/32). | Defect |
| The handle budget is per export, the descriptor table is per process. | Each export refuses `OPEN`/`OPENDIR` past its own budget with `ENFILE`. `CREATE`, `TMPFILE` and cached directory descriptors are not counted, so several busy exports can still exhaust the table. | Defect |
| The open file limit is raised when the first share is set up. | A boot with no share never raises it and never logs the line. macOS only. | Design |
| A node keeps at most 16 alias paths. | A file with more than 16 hard links inside a share can lose a name from the table. | Design |
| Symlink expansion stops at 40. | Deeply chained links end as `ELOOP`. | Design |
| A few call sites still pass a full path string to the host. | Containment is strong and tested rather than proven. Resolution is otherwise by parent descriptor with `O_NOFOLLOW`. | Defect |

## Guests and CPUs

| Limit | Consequence | Kind |
| --- | --- | --- |
| A portable guest's REALTIME drifts from the host between restores. | `hvi-time` runs REALTIME on the host's counter, not on its NTP-disciplined clock, so it moves away by the counter's error, up to about 30 ppm measured on rp2. Nothing resynchronises it until a restore. Run NTP in the guest if that matters. | Design |
| A portable guest's high-resolution `clock_gettime` is a system call. | The vDSO has no `hvi-time` mode, so it falls back to the syscall. Coarse clocks stay in the vDSO. | Design |
| The portable profile has no checkpoint yet. | `hvi-time` has its canonical state and restore, tested in one process (`HVI_TIME_TEST_RESTORE`), and KVM's vGICv2 is read and written in the software GIC's canonical form (`arch/aarch64/vgicv2.rs`). Moving a guest between hosts needs the checkpoint itself, which does not exist yet. | Defect |
| On KVM the `hvi-time` timer thread is an ordinary thread. | A few timer fires a minute land 0.5 to 3.5 ms late on a busy Pi 5. hvi does not ask for a real-time policy, which needs privileges. A late fire is never early. | Design |
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
| `--dump-memory` is denied by the default sandbox. | The file is created after confinement. Use a destination inside a writable `--fs path=` directory, or `--no-sandbox`. See [#91](https://github.com/brig-sh/hvi-vmm/issues/91). | Defect |
| `--dump-after` needs the guest to still be running. | A guest that stops first produces no dump and no error. | Design |
| A dump is not a checkpoint. | Raw RAM only. No register, device or virtqueue state. Nothing can restore a VM from it. | Design |

## Control socket

| Limit | Consequence | Kind |
| --- | --- | --- |
| A KVM checkpoint bundle cannot be restored yet. | On KVM each vCPU's state is partial: PC, PSTATE, the stack pointers and four translation registers on arm64, RIP and CR3 on x86-64. The interrupt controller and the guest counter are marked `not-captured`. `hvi restore` runs on HVF only. | Defect |
| An HVF bundle moves only to the same macOS build, CPU and hvi commit. | The `hv_gic_state` blob is opaque and versioned by the OS, and the restore refuses every machine profile difference: the macOS build, `MIDR_EL1`, every ID register, the counter frequency, the GIC layout, the hvi commit (and a build with uncommitted changes). | Platform |
| A restored guest's wall clock is behind. | Its counter goes on from the capture, so its `CLOCK_REALTIME` lags the host's by the time it was away, until the guest's own time sync corrects it. hvi does not set it. | Design |
| A restore resets the guest's vsock connections. | Their host ends stayed on the source. The guest sees each one reset. | Design |
| A guest using SME cannot be checkpointed. | A vCPU in SME streaming mode or with ZA storage on fails the capture: the schema has no place for its Z, P and ZA registers. Linux enters those modes only while a task uses SME. | Design |
| `GICR_CTLR` is not in the canonical GIC state. | Hypervisor.framework has no call that reads it. The HVF restore loads the `hv_gic_state` blob, which holds it, so only a future import of the canonical form would miss it. | Platform |
| A checkpoint stops the guest for the whole capture. | Downtime grows with the guest RAM in use: about 0.3 s for 100 MiB on an Apple M5 Pro, 1.2 s on a Raspberry Pi 5, 3 s for 350 MiB on the Pi. Each file is synced while the guest is stopped, so a host whose storage is busy stretches it: 14 s for 90 MiB on the Pi while a build ran. There are no pre-copy rounds. A client's reply timeout must allow for it. | Defect |
| A checkpoint needs `--checkpoint-root`. | Without it every `checkpoint` is refused. The bundle goes in a new or empty directory below the root, reached through no link. | Design |
| A guest with virtio-fs shares cannot be checkpointed. | Its share is host descriptors and inode numbers that do not move. A `--fs socket=` export's state is in the caller's daemon, which writes guest RAM outside the dirty log. The checkpoint is refused before anything pauses. | Design |
| The fence lives only as long as the process. | A fenced VM refuses `resume` until it stops. Nothing is written, so a caller that must survive a crash of the source records the fence itself. | Design |
| A secondary that starts during a checkpoint fails it. | A secondary on HVF that takes its `CPU_ON` after the export's wait ended is neither off nor exported, so the capture replies `capture_failed` and the caller tries again. The window is the guest's own CPU bring-up, early in its boot. | Design |
| A pause does not stop guest time. | The guest's counter keeps running while it is paused. On resume its clock has jumped by the pause, and timers that fell due fire at once. | Design |
| One client at a time. | A connected client that sends nothing keeps the next one waiting in the backlog. | Design |
| The socket has no authentication. | Anyone who can connect can pause or stop the VM. Its directory's permissions are the only control. | Design |
| A pause can find host input read but not yet delivered. | The console reader can hold one byte it read from the terminal, and the gateway relay the start of a frame whose rest has not arrived. Resume delivers both, so a pause loses nothing. A checkpoint taken then drops them: one keystroke, and one frame the guest's TCP sends again. | Design |
| The virtio-fs readahead workers are not held by a pause. | They fill the share's read cache, not guest RAM. A guest with a share is never eligible to move anyway: its profile refuses every destination. | Design |
| On macOS the profile file starts empty. | The boot vCPU writes it before the guest's first instruction, since only that thread can read `MIDR_EL1`. A reader that finds it empty waits, or asks the socket. | Platform |

## Confinement

| Limit | Consequence | Kind |
| --- | --- | --- |
| Confinement does not drop privilege. | No uid, gid or capability change exists in hvi. It narrows syscalls only. | Design |
| A thread a plugin starts outside `VmHandle::spawn` is unfiltered on Linux. | It starts in `attach`, before the filters are armed, and stays unfiltered. | Design |
| No seccomp rule carries argument conditions. | `ioctl` and `sendmsg` are unconstrained over every descriptor the process already holds. | Design |
| `HVI_SECCOMP=log` turns enforcement off. | The kernel permits the off-list syscall and records it. It is not a softer mode. | Design |
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

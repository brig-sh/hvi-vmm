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
| virtio-fs is macOS only. | The Linux backends carry no directory sharing at all. Use a disk image. | Design |
| Only three host targets are supported. | aarch64 macOS, aarch64 Linux and x86-64 Linux. On any other target the build stops with a compile error. | Design |
| The macOS backend needs macOS 15 or newer. | It calls `hv_gic_*`, which arrived in macOS 15. hvi runs no version check, so an older host fails when it first reaches the framework rather than with a clear message. | Platform |
| The KVM backends need kernel 4.11 or newer. | hvi stops a vCPU through `kvm_run.immediate_exit` and refuses to boot without `KVM_CAP_IMMEDIATE_EXIT`, which 4.11 added. | Platform |
| No published crate, no release, no tag. | Build from source. Pin a commit when you depend on it. | Design |
| The arm64/KVM backend is unit-tested on its stop path only. | Its only tests are the KVM stop tests in `src/hypervisor/kvm.rs`, of how a vCPU thread that ends stops the VM and how a kick ends a run, and they need `/dev/kvm`. The rest of that backend is cross-linted and booted. | Defect |

## Devices

| Limit | Consequence | Kind |
| --- | --- | --- |
| One virtio-blk disk. | No second disk, no hotplug, no PCI at all. | Design |
| virtio-blk serves one request at a time. | One worker thread takes the requests in order and makes one disk call at a time, as the vCPU did before it, so a guest that queues many gets no parallelism from the host, and a read waits behind a flush queued before it. A guest `dd` of 1 GiB in 1 MiB blocks onto its disk on rp2, five pairs alternating `c4131f5` (requests on the vCPU) and `802e6c1` (on the worker) with the host's caches dropped before each run, had medians of 752 and 737 MB/s without `conv=fsync` and 298 and 302 MB/s with it. That drive stalls, though: 6 of the 20 runs, 2 of `c4131f5` and 4 of `802e6c1`, took 8 to 380 MB/s, and the two of one pair logged NVMe I/O timeouts, so the comparison rests on the medians and not on a clean distribution. Without the stalls the runs took 751 to 820 and 737 to 800 MB/s without `conv=fsync`, and 290 to 301 and 302 to 306 MB/s with it. On the Mac the worker, at `ed47427` and `fca7c94`, was no slower either (medians of 2639 against 1758 MB/s without `conv=fsync`, 1554 against 1421 MB/s with it, 7 runs each); a flush there is `F_FULLFSYNC`, which Rust's `sync_data` calls on macOS, so the `conv=fsync` runs reach the drive, while the runs without it end in the host's page cache. | Design |
| One virtio-net NIC. | Same. Passing more than one networking flag silently uses the first that matches. | Design |
| No egress from the built-in `--net-stub` stack. | TCP is seen but never forwarded. Real egress needs `--net-gateway` or `--net-tap`. | Design |
| The built-in stack cannot resolve DNS while confined. | The guest gets a reply with no addresses. Resolution needs a socket the sandbox denies. Only `--no-sandbox` resolves. See [#90](https://github.com/brig-sh/hvi-vmm/issues/90). | Defect |
| An unreachable `--net-gateway` falls back to the built-in stack. | A guest comes up with no egress and exit status zero. The warning line is the only signal. | Design |
| A tap write that fails drops the guest's frame. | The write fails when the send buffer is full, the tap is detached, its interface is down, or the kernel cannot allocate or accept the frame. The first failure writes one line to stderr. The ledger records the frame as egress before the write, so a dropped frame still appears in it. The send buffer fills only when the tap's creator lowered it. | Design |
| A gateway frame above 64 KiB ends the relay. | The relay writes one line to stderr and shuts the gateway socket down, so the guest receives nothing more from the gateway and its own frames are dropped for the rest of the run. Every gateway's default MTU is far below 64 KiB. | Design |
| virtio-fs: one request queue per share, no DAX, no indirect descriptors. | Throughput ceiling per share. | Design |
| virtio-fs: the export overlap check covers one process. | Two hvi processes can export the same tree, or a tree and a directory inside it, with one writable and one read-only. An owner and a mode a guest stores through the writable export, setuid and setgid included, reach the other guest. See [storage-and-sharing.md](storage-and-sharing.md#virtio-fs-shares-macos-only). | Design |

## virtio-fs resource limits

| Limit | Consequence | Kind |
| --- | --- | --- |
| The node table has no cap. | `FORGET` is what shrinks it between device resets. A guest that never sends one grows the table until it resets the device. Guest-driven, unbounded. See [#34](https://github.com/brig-sh/hvi-vmm/issues/34). | Defect |
| `SETLKW` blocks under the device mutex. | A guest waiting on a lock stalls that whole device, and any vCPU that accesses the device while it waits. That includes the vCPU that issued the request when the queue was shallow enough to drain inline. `boot` waits for the vCPUs with no deadline, so it does not return until the lock is released. See [#32](https://github.com/brig-sh/hvi-vmm/issues/32). | Defect |
| The handle budget is per export, the descriptor table is per process. | Each export refuses `OPEN`/`OPENDIR` past its own budget with `ENFILE`. `CREATE`, `TMPFILE` and cached directory descriptors are not counted, so several busy exports can still exhaust the table. | Defect |
| The open file limit is raised when the first share is set up. | A boot with no share never raises it and never logs the line. macOS only. | Design |
| A node keeps at most 16 alias paths. | A file with more than 16 hard links inside a share can lose a name from the table. | Design |
| Symlink expansion stops at 40. | Deeply chained links end as `ELOOP`. | Design |
| A few call sites still pass a full path string to the host. | Containment is strong and tested rather than proven. Resolution is otherwise by parent descriptor with `O_NOFOLLOW`. | Defect |

## Guests and CPUs

| Limit | Consequence | Kind |
| --- | --- | --- |
| A portable guest's REALTIME drifts from the host between restores. | `hvi-time` runs REALTIME on the host's counter, not on its NTP-disciplined clock, so it moves away by the counter's error, up to about 30 ppm measured on rp2. Nothing resynchronises it until a restore or a host sleep. Run NTP in the guest if that matters. | Design |
| A portable guest's high-resolution `clock_gettime` is a system call. | The vDSO has no `hvi-time` mode, so it falls back to the syscall. Coarse clocks stay in the vDSO. | Design |
| A move between a Mac and a Pi is not run in CI. | `tools/migrate-e2e.sh` moves a portable guest each way and checks it (see [portable-profile.md](portable-profile.md#measured-results)), but only by hand: no CI runner has both a Mac and a Pi. Only stopped moves exist, so the guest is paused for the whole copy. | Defect |
| A native guest on a Mac that sleeps loses wall-clock time. | Hypervisor.framework's counter does not run while the Mac sleeps, so the guest's clocks stop with it, and the native profile has no `hvi-time` page to tell the guest. Its REALTIME should stay behind the host's by the sleep until it sets its own time; not measured. A portable guest's page is published again after a sleep (see [portable-profile.md](portable-profile.md#host-sleep)). | Defect |
| The portable host-sleep republish is tested without a real sleep. | Automation cannot put the Mac to sleep, so the live test (`tools/sleep-e2e.py`) moves the host clocks hvi reads with `HVI_TIME_TEST_SLEEP`. That proves the detection, the publish and the guest driver's step, not that a real sleep moves the sleep clock as expected. No Pi was suspended: whether its counter stops in a suspend is not known, and the republish is the same either way. | Defect |
| A portable guest on the Mac is not mitigated against Spectre v4. | It reads workaround 2 as not required, as on the Pi, so it reports "Not affected" on both hosts. On the Pi, KVM keeps the guest mitigated; on the Mac nothing does. Before, it reported "Vulnerable" on the Mac and was unmitigated all the same. | Platform |
| A KVM capture can miss a vCPU being turned on again. | A vCPU turned off and then on with a `CPU_ON` that KVM has not served yet still holds the registers it had when it went off, and is written as on; its restore resumes after its `CPU_OFF`. A first `CPU_ON` that KVM has not served fails the capture instead, and the guest stays paused. Linux turns vCPUs off and on only for CPU hotplug. | Defect |
| A portable restore loses two pieces of interrupt state through KVM. | KVM's GICv2 register view cannot tell a level interrupt's latch from its line, so one with both set comes out with the line only, and the vGICv2's SGI active source is not carried. | Platform |
| On KVM the `hvi-time` timer thread is an ordinary thread. | A few timer fires a minute land 0.5 to 3.5 ms late on a busy Pi 5. hvi does not ask for a real-time policy, which needs privileges. A late fire is never early. | Design |
| 8 vCPUs on a GICv2 arm64 host. | GICv2 addresses at most 8 CPU interfaces. The guest's controller follows the host's, so this is not a choice. A GICv3 host has no such cap. Not having this cap is not "unlimited": other limits still apply. | Platform |
| x86 vCPUs share one CPUID blob. | The APIC id a guest reports for a secondary CPU varies run to run. | Defect |
| The default `--cmdline` names `ttyAMA0`. | That is the arm64 console. The x86 backend appends `console=ttyS0` itself, so a guest still gets one, but the default leaves a dead `console=` and a bare `earlycon` on the line. | Design |
| `tools/mk-initramfs.py` builds an arm64 initramfs only. | An x86-64 guest needs its own. | Design |
| An x86-64 `vmlinux` boots without KASLR. | The kernel randomizes its placement in the `bzImage` decompressor, which a `vmlinux` skips. Boot a `bzImage` when KASLR matters. | Platform |
| The virtio-blk worker has not served a guest on x86-64 KVM. | Since `f05ac33` virtio-blk requests are served on a worker thread, which raises the device's line with `KVM_IRQ_LINE` under the `vmm` filter. Its unit tests and the seccomp selftest run on x86-64 in CI, but no x86-64 KVM guest has booted with a disk on it: the live checks ran on arm64 KVM and HVF only. | Defect |
| `SystemReset` stops the process. | hvi never reboots a guest and never recovers one. A caller that wants a reboot calls `boot` again. | Design |

## Observability

| Limit | Consequence | Kind |
| --- | --- | --- |
| The ledger is not lossless. | It drains when a new event arrives more than 100 ms after the last drain. Events before a quiet period stay buffered. A killed VMM loses the tail; a guest that stops on its own does not, because `boot` flushes before it returns. | Design |
| The ledger is not tamper-proof. | An ordinary file written by the VMM. Nothing signs or chains it. | Design |
| `net` records are per packet and egress only. | No flow aggregation. `direction` and `guest_initiated` are constants, not observations. Inbound frames produce no record. | Design |
| `ts` is host wall-clock. | It is not monotonic and can move backwards. | Design |
| TLS SNI is recorded only under `--net-tap` and `--net-gateway`. | The built-in stack records no SNI. | Design |
| An SNI value is a claim on the wire. | It is not proof of a connection, not application identity, and not authorization. Split ClientHellos, resumption, encrypted ClientHello and QUIC yield nothing. | Design |
| `--dump-memory` is denied by the default sandbox. | The file is created after confinement. Use a destination inside a `--share-rw` directory, or `--no-sandbox`. See [#91](https://github.com/brig-sh/hvi-vmm/issues/91). | Defect |
| `--dump-after` needs the guest to still be running. | A guest that stops first produces no dump and no error. | Design |
| A dump is not a checkpoint. | Raw RAM only. No register, device or virtqueue state. Nothing can restore a VM from it. | Design |

## Control socket

| Limit | Consequence | Kind |
| --- | --- | --- |
| A native KVM checkpoint bundle cannot be restored yet. | On arm64 the vCPUs are whole, but the vGICv3 and the guest counter are marked `not-captured`; on x86-64 each vCPU is partial too, RIP and CR3 only. `hvi restore` on KVM restores the portable profile only. | Defect |
| An HVF bundle moves only to the same macOS build, CPU and hvi commit. | The `hv_gic_state` blob is opaque and versioned by the OS, and the restore refuses every machine profile difference: the macOS build, `MIDR_EL1`, every ID register, the counter frequency, the GIC layout, the hvi commit (and a build with uncommitted changes). | Platform |
| A restored native guest's wall clock is behind. | Its counter goes on from the capture, so its `CLOCK_REALTIME` lags the host's by the time it was away, until the guest's own time sync corrects it. hvi does not set it. A portable guest's is corrected by `hvi-time`. | Design |
| A restore resets the guest's vsock connections. | Their host ends stayed on the source. The guest sees each one reset. | Design |
| A guest using SME cannot be checkpointed. | A vCPU in SME streaming mode or with ZA storage on fails the capture: the schema has no place for its Z, P and ZA registers. Linux enters those modes only while a task uses SME. | Design |
| `GICR_CTLR` is not in the canonical GIC state. | Hypervisor.framework has no call that reads it. The HVF restore loads the `hv_gic_state` blob, which holds it, so only a future import of the canonical form would miss it. | Platform |
| A checkpoint stops the guest for the whole capture. | Downtime grows with the guest RAM in use: about 0.3 s for 100 MiB on an Apple M5 Pro, 1.2 s on a Raspberry Pi 5, 3 s for 350 MiB on the Pi. Each file is synced while the guest is stopped, so a host whose storage is busy stretches it: 14 s for 90 MiB on the Pi while a build ran. A live move (`migrate`) copies RAM in rounds first; see [checkpoint.md](checkpoint.md#live-moves). A client's reply timeout must allow for it. | Defect |
| A live move of a guest that writes faster than the rounds copy is stopped for its last round. | The rounds end at the round cap, 5, and the final round, sent paused, is as large as what the guest writes in one round: 269 MB and 0.46 s on the Mac, 1.7 to 3.5 s on a Pi 5, for a guest rewriting 256 MiB of pages that do not compress, over a local socket. On a slower link it takes as long as those bytes take to cross it. | Design |
| On HVF a live move costs the guest one exit per 16 KiB granule it writes per round. | Hypervisor.framework keeps no dirty log, so hvi write-protects RAM and serves each first write to a granule: about 6 us end to end, 1 to 3 us of it in hvi. A guest rewriting 256 MiB takes about 16,700 of them per round. | Platform |
| A live move without disk rounds syncs the disk inside its pause. | When the disk has no base, the mover copies the source's disk whole, so it must be durable at the seal: hvi syncs it just before the pause, without the device's lock, and once more in the pause (`pause_sync_ms`). The second sync took 0 to 3 ms on the Mac and on a quiet Pi, but with an `O_DIRECT` writer beside it on a Pi a median of 300 ms and up to 586 ms, and once 11.6 s: on a disk that busy the first sync does not leave it little to do. A stream with disk rounds leaves the second sync out, since the destination holds every block and syncs its own copy; the source's file then rests on the guest's own flushes, as on any running guest, should the move fail and the guest run on (see [checkpoint.md](checkpoint.md#the-pause)). The guest keeps writing during the first sync, which took a median of 234 to 538 ms and once 10.2 s on that Pi, and the final rounds carry what it wrote meanwhile. | Design |
| A live move's disk rounds do not count towards convergence. | The rounds end on RAM alone, and the final disk round, sent paused, holds what the guest wrote to its disk since the round before. A guest that writes its disk fast stretches the pause by those blocks. | Design |
| A live move sends the disk by its blocks only with a base the boot was given. | The blocks are the ones hvi served since `--disk-base-sha256` named the disk as this boot opened it. A disk written before the boot, as a launcher that injects files into a copy of the image does, differs from the image in blocks hvi did not serve: the launcher names them with `--disk-written`, or passes the digest of the disk as hvi opens it and the destination holds that image. hvi does not check the bitmap against the disk; one that leaves a block out moves a disk without it. Without a base the stream has no disk rounds, and the mover copies the disk whole. | Design |
| `then: "fence"` fences a streaming source when its manifest is on the socket. | The client may not have read it yet. A fenced VM is streamed again only for the move that fenced it, by its `txid` and `epoch`; any other `migrate` is refused with `fenced`, since the first destination may already run the guest. The stream sent again moves the same RAM and disk, but its manifest's SHA-256 never equals the first's, so the mover compares the digests of the five documents instead, and hvi cannot tell whether the first destination resumed: the mover must make sure it did not before it restores the stream sent again. A source fenced by a `checkpoint`, or by a `migrate` that did not give both a `txid` and an `epoch`, cannot be streamed again: a caller whose stream did not arrive then aborts the move, and a source that stops first loses the guest. | Design |
| Writes through `GuestRam::memory()`, `host_ptr` or a mapping of the RAM's descriptor are not in guest RAM's dirty log. | Only the boot's loaders write through `memory()`, before any move. hvi's devices mark what they write through `host_ptr` with `mark_dirty`. A plugin gets the same `&GuestRam` from `VmHandle::ram` and `CpuHandle::ram`: its write accessors mark the log, but a plugin that writes through `host_ptr`, or maps `ram_fd`, must call `mark_dirty` after the write, or a live move misses it. | Design |
| A live move's stream is not authenticated. | Each frame and the manifest carry SHA-256 hashes, which catch damage, not a forger who rewrites both. Send it over a channel that is, such as ssh. | Design |
| A checkpoint needs `--checkpoint-root`. | Without it every `checkpoint` is refused. The bundle goes in a new or empty directory below the root, reached through no link. | Design |
| A guest with virtio-fs shares cannot be checkpointed. | Its share is host descriptors and inode numbers that do not move. The checkpoint is refused before anything pauses. | Design |
| The fence lives only as long as the process. | A fenced VM refuses `resume` until it stops. Nothing is written, so a caller that must survive a crash of the source records the fence itself. | Design |
| A secondary that starts during a checkpoint fails it. | A secondary on HVF that takes its `CPU_ON` after the export's wait ended is neither off nor exported, so the capture replies `capture_failed` and the caller tries again. The window is the guest's own CPU bring-up, early in its boot. | Design |
| A pause waits for the virtio-blk request in flight. | Since `f05ac33` the device's requests are served on a worker thread, not in the vCPU's exit, so a flush's `fdatasync` no longer stops a vCPU and a pause parks the vCPUs at once: on rp2 with an `O_DIRECT` writer beside a guest flushing in a loop, 30 of 30 moves parked in 0 ms, where `c4131f5` took up to 2237 ms and 13 of 30 took 100 ms or more, and the guest logged no RCU stall in 10 minutes of it (nor did it on `c4131f5`, so that run shows no difference). The worker holds the pause gate for the whole request, so the device state stays restorable as before, and the pause's gate waits for that one request with the vCPUs running: in each of two builds 2 of 30 moves waited 312 to 2120 ms there, and in one of them a third waited 3 ms. Meanwhile the other I/O threads are held too, so the network and the console deliver nothing. A `pause` waits up to 10 s for that request, as a move does, since a move's gate waited up to 2120 ms under the hog, past the 2 s a `pause` had before; a longer request still times it out, and the VM then runs on. What a move's pause still stops the guest for is the sync in it (see the row on the disk sync). | Design |
| A pause does not stop guest time. | The guest's counter keeps running while it is paused. On resume its clock has jumped by the pause, and timers that fell due fire at once. | Design |
| One client at a time. | A connected client that sends nothing keeps the next one waiting in the backlog. | Design |
| The socket has no authentication. | Anyone who can connect can pause or stop the VM, and, with a checkpoint root, read its disk with `disk-blocks`. Its directory's permissions are the only control. | Design |
| A pause can find host input read but not yet delivered. | The console reader can hold one byte it read from the terminal, and the gateway relay the start of a frame whose rest has not arrived. Resume delivers both, so a pause loses nothing. A checkpoint taken then drops them: one keystroke, and one frame the guest's TCP sends again. | Design |
| The virtio-fs readahead workers are not held by a pause. | They fill the share's read cache, not guest RAM. A guest with a share is never eligible to move anyway: its profile refuses every destination. | Design |
| On macOS the profile file starts empty. | The boot vCPU writes it before the guest's first instruction, since only that thread can read `MIDR_EL1`. A reader that finds it empty waits, or asks the socket. | Platform |

## Confinement

| Limit | Consequence | Kind |
| --- | --- | --- |
| Confinement does not drop privilege. | No uid, gid or capability change exists in hvi. It narrows syscalls only. | Design |
| A thread a plugin starts in `attach` is unfiltered on Linux. | It starts before the filters are armed and stays unfiltered. The `--dump-after` timer thread is one. It ends when it fires, `--dump-after` seconds after the boot starts. See [#92](https://github.com/brig-sh/hvi-vmm/issues/92). | Defect |
| On Linux with glibc, a confined run's malloc runs on one arena. | Every thread shares one malloc lock, as in the musl build. More arenas would make glibc open files from filtered threads (see [the allowlists' README](../resources/seccomp/README.md#no-openat-and-the-files-glibc-opens-by-itself)). A `--no-sandbox` run keeps glibc's default arenas. | Design |
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

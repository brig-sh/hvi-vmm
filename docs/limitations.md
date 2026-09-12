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
| A non-backend host builds a stub. | The shared code and unit tests compile everywhere. That build cannot run a guest. | Design |
| The macOS backend needs macOS 15 or newer. | It calls `hv_gic_*`, which arrived in macOS 15. hvi runs no version check, so an older host fails when it first reaches the framework rather than with a clear message. | Platform |
| No published crate, no release, no tag. | Build from source. Pin a commit when you depend on it. | Design |
| The arm64/KVM backend has no unit tests. | `src/machine_linux.rs` carries no `#[cfg(test)]` module, and no job runs a suite on arm64 Linux, so writing tests would also need a runner. The full suite runs on x86 Linux and macOS only. The weekly used-ring litmus does run one test binary on an arm64 Linux runner. | Defect |

## Devices

| Limit | Consequence | Kind |
| --- | --- | --- |
| One virtio-blk disk. | No second disk, no hotplug, no PCI at all. | Design |
| One virtio-net NIC. | Same. Passing more than one networking flag silently uses the first that matches. | Design |
| No egress from the built-in `--net` stack. | TCP is seen but never forwarded. Real egress needs `--net-gateway` or `--net-tap`. | Design |
| The built-in stack cannot resolve DNS while confined. | The guest gets a reply with no addresses. Resolution needs a socket the sandbox denies. Only `--no-sandbox` resolves. See [#90](https://github.com/brig-sh/hvi-vmm/issues/90). | Defect |
| `--net-mac` is read only in the tap branch. | Under `--net`, `--net-gateway` or on macOS it is accepted and discarded, with no message, even when malformed. | Design |
| An unreachable `--net-gateway` falls back to the built-in stack. | A guest comes up with no egress and exit status zero. The warning line is the only signal. | Design |
| The gateway reader skips an over-long framed length without consuming its payload. | A frame above 64 KiB loses alignment on the stream. See [#93](https://github.com/brig-sh/hvi-vmm/issues/93). | Defect |
| virtio-fs: one request queue per share, no DAX, no indirect descriptors. | Throughput ceiling per share. | Design |

## virtio-fs resource limits

| Limit | Consequence | Kind |
| --- | --- | --- |
| The node table has no cap. | `FORGET` is what shrinks it. A guest that never sends one grows the table for the life of the VM. Guest-driven, unbounded. See [#34](https://github.com/brig-sh/hvi-vmm/issues/34). | Defect |
| `SETLKW` blocks under the device mutex. | A guest waiting on a lock stalls that whole device, and stalls the vCPU that issued the request when the queue was shallow enough to drain inline. See [#32](https://github.com/brig-sh/hvi-vmm/issues/32). | Defect |
| The handle budget is per export, the descriptor table is per process. | Each export refuses `OPEN`/`OPENDIR` past its own budget with `ENFILE`. `CREATE`, `TMPFILE` and cached directory descriptors are not counted, so several busy exports can still exhaust the table. | Defect |
| The open file limit is raised when the first share is set up. | A boot with no share never raises it and never logs the line. macOS only. | Design |
| A node keeps at most 16 alias paths. | A file with more than 16 hard links inside a share can lose a name from the table. | Design |
| Symlink expansion stops at 40. | Deeply chained links end as `ELOOP`. | Design |
| A few call sites still pass a full path string to the host. | Containment is strong and tested rather than proven. Resolution is otherwise by parent descriptor with `O_NOFOLLOW`. | Defect |

## Guests and CPUs

| Limit | Consequence | Kind |
| --- | --- | --- |
| 8 vCPUs on a GICv2 arm64 host. | GICv2 addresses at most 8 CPU interfaces. The guest's controller follows the host's, so this is not a choice. A GICv3 host has no such cap. Not having this cap is not "unlimited": other limits still apply. | Platform |
| x86 vCPUs share one CPUID blob. | The APIC id a guest reports for a secondary CPU varies run to run. | Defect |
| The default `--cmdline` names `ttyAMA0`. | That is the arm64 console. The x86 backend appends `console=ttyS0` itself, so a guest still gets one, but the default leaves a dead `console=` and a bare `earlycon` on the line. | Design |
| `tools/mk-initramfs.py` builds an arm64 initramfs only. | An x86-64 guest needs its own. | Design |
| An x86-64 `vmlinux` boots without KASLR. | The kernel randomizes its placement in the `bzImage` decompressor, which a `vmlinux` skips. Boot a `bzImage` when KASLR matters. | Platform |
| `SystemReset` stops the process. | hvi never reboots a guest and never recovers one. A caller that wants a reboot calls `boot` again. | Design |

## Observability

| Limit | Consequence | Kind |
| --- | --- | --- |
| The ledger is not lossless. | It drains when a new event arrives more than 100 ms after the last drain. Events before a quiet period stay buffered. A killed VMM loses the tail. | Design |
| The ledger is not tamper-proof. | An ordinary file written by the VMM. Nothing signs or chains it. | Design |
| `net` records are per packet and egress only. | No flow aggregation. `direction` and `guest_initiated` are constants, not observations. Inbound frames produce no record. | Design |
| `ts` is host wall-clock. | It is not monotonic and can move backwards. | Design |
| TLS SNI is recorded only under `--net-tap` and `--net-gateway`. | The built-in stack records no SNI. | Design |
| An SNI value is a claim on the wire. | It is not proof of a connection, not application identity, and not authorization. Split ClientHellos, resumption, encrypted ClientHello and QUIC yield nothing. | Design |
| `--dump-memory` is denied by the default sandbox. | The file is created after confinement. Use a destination inside a `--share-rw` directory, or `--no-sandbox`. See [#91](https://github.com/brig-sh/hvi-vmm/issues/91). | Defect |
| `--dump-after` needs the guest to still be running. | A guest that stops first produces no dump and no error. | Design |
| A dump is not a checkpoint. | Raw RAM only. No register, device or virtqueue state. Nothing can restore a VM from it. | Design |

## Confinement

| Limit | Consequence | Kind |
| --- | --- | --- |
| Confinement does not drop privilege. | No uid, gid or capability change exists in hvi. It narrows syscalls only. | Design |
| The `--dump-after` timer thread is unfiltered on Linux. | It starts before the filters are armed and runs unfiltered for the life of the VM. See [#92](https://github.com/brig-sh/hvi-vmm/issues/92). | Defect |
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

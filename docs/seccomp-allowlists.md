# hvi seccomp-bpf allowlists

The lists are constants in `src/sandbox/seccomp/allowlists.rs`, compiled into
filters by `src/sandbox/seccomp/mod.rs` and installed per thread. The reasoning
behind the design lives in the module docs of `mod.rs`; this file covers what
you need to change a list safely.

## How a list is written

A list is an array of rules. A rule takes the syscall's number from libc's
constant, under a comment that says why the call is there:

```rust
// The ledger writer.
Rule::syscall(libc::SYS_pwrite64),
```

A rule can also match the request of an `ioctl`. No other rule matches an
argument. Each of `block`'s `ioctl` rules allows one request, which comes from
libc's constant, or is built as the header builds it where libc has none:

```rust
// The terminal restore of the fatal-signal handler and of the panic hook:
// tcsetattr.
Rule::ioctl(libc::TCSETS),
```

The one `ioctl` rule of `vmm` and `vcpu` allows every request but `TIOCSTI` and
`TIOCLINUX`:

```rust
Rule::ioctl_except(TERMINAL_INPUT),
```

A request is compared in its low 32 bits. The module docs of `mod.rs` say why.

The rules of one syscall are joined, so the syscall is allowed when any of them
matches. A call that matches no rule traps like an off-list syscall. A list
states a syscall once, or once per request it allows, and a test holds that.

Each list serves both architectures. An entry only one of them has is behind a
`cfg`. `poll` is the one syscall that differs: x86-64 has both `poll` and
`ppoll`, and aarch64 has `ppoll` alone, because aarch64 has no `poll` syscall.
`block`'s `KVM_IRQ_LINE` rule is the other entry behind a `cfg`, on x86-64 only.

A filter per kind of thread:

- `vcpu` is the tight one, for the vCPU threads. A vCPU thread serves its MMIO
  and port exits, so the virtio-mmio transport, the net and vsock device models,
  the vhost-user handover and the legacy devices run there, and the device
  models parse guest descriptors. A disk's requests run on the disk's worker, so
  `vcpu` allows no read or write at an offset, no seek and no file sync.
- `block` covers each disk's worker thread, which parses the disk's descriptors
  and runs its requests against the backing file. It alone allows `preadv` and
  `pwritev`, which move a request's data between the backing file and guest RAM.
- `vmm` covers the thread that calls `boot`, the other host-side I/O threads,
  the threads a plugin starts with `VmHandle::spawn`, the stop-signal thread and
  the ledger's writer. No other thread makes `preadv` or `pwritev`, so `vmm`
  does not allow them. It keeps `fdatasync` and `fsync`, which only a worker
  calls, so that `block` stays within it apart from those two.

Each list serves both x86-64 irqchip modes. `block`'s `KVM_IRQ_LINE` rule serves
the in-kernel irqchip only: with the split irqchip, a worker raises its disk's
interrupt with a `write` to an irqfd, as it does on arm64.

## Why these are not Firecracker's lists

Vendoring Firecracker's filters wholesale, with their copyright header, was the
obvious first move. They were measured instead, and that is a deliberate
deviation rather than an oversight.

Firecracker ships `x86_64-unknown-linux-musl.json` and
`aarch64-unknown-linux-musl.json`, musl only, and drives its devices with epoll
and io_uring. hvi's lists were measured on a glibc build, and hvi uses blocking
reads on dedicated threads. So their lists carry `io_uring_*` and `epoll_*`, and
on x86-64 `open` and `stat`, which we never call, and omit `statx`, `rseq`,
`set_robust_list`, `sched_getaffinity` and `clone3`, without which a glibc Rust
binary does not reach `main`. Copying them would have been simultaneously too
loose and fatally too tight, so no code or list of theirs is included here and
no attribution is owed.

What does transfer is their production experience about the rare paths a single
trace never shows. Entries our own trace did not produce have a comment that
starts with `Safety net:`, and most of those came from reading their lists.

The musl build shares the lists. musl can reach a different syscall than glibc
for the same library call, so `hvi seccomp-selftest` run on the musl binary is
the check for that.

## The files glibc opens by itself

No list carries an open syscall (`openat`, `openat2`, and on x86-64 `open`).
glibc's malloc opens two files on its own, from whichever thread is allocating
or freeing at the time: `/proc/sys/vm/overcommit_memory` the first time the heap
of a thread's arena shrinks, and `/sys/devices/system/cpu/online`, falling back
to `/proc/stat`, when a thread needs a new arena while more than eight exist. It
copes with each open failing, so a glibc build installs, on every thread and
before the allowlist, a second filter that fails those open syscalls with
`EPERM`, and adds them to the allowlist it compiles. The kernel takes the
strictest answer of a thread's filters, so an open is refused rather than
trapped, and the process still opens nothing. musl's malloc opens no file, so a
musl build installs the allowlist alone.

## Changing a list

Adding a syscall is granting a right to a process that parses guest-controlled
data, so the bar is a demonstrated need, not a suspicion:

1. Reproduce the need. `HVI_SECCOMP=log hvi boot ...` installs these same
   filters with the mismatch action changed to `log`, so the kernel lets the
   off-list syscall run and records it (`dmesg`, `auditctl`) while the VMM
   keeps running. That names the syscall. It also means enforcement is off for
   that run, so it is a diagnostic and never a way to operate. A glibc build
   still refuses an open under it, without a record.
2. Add it to the narrowest list that needs it, under a comment that says which
   code path calls it.
3. `cargo test` -- the unit tests check that every list compiles for the target
   arch, that `vcpu` stays a strict subset of `vmm`, and that `block` does too
   apart from `preadv` and `pwritev`, which only a disk's worker makes. They
   also check that no list ever gains `open*`, `socket`, `connect`, `execve`,
   `seccomp` or `prctl`, each of which would undo the reason the filters go in
   after setup. They check that `vcpu` gains no positioned read or write, seek
   or file sync, and which `ioctl` requests `block` allows. The opens a glibc
   build adds are compiled in by the code, behind the filter that refuses them.
   One more runs the `vmm` and `vcpu` `ioctl` rules of the test's own
   architecture over the refused requests and a few allowed ones.
4. `hvi seccomp-selftest` -- installs the real filters in child processes and
   checks what survives.

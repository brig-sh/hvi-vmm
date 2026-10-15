# hvi seccomp-bpf allowlists

One file per architecture, compiled into the binary by `src/sandbox/seccomp.rs`
and installed per thread. The reasoning behind the design lives in that module's
docs; this file covers what you need to change one of these safely.

The prose that would normally sit at the top of the JSON is here instead:
seccompiler parses **every** top-level key as a filter, so a `__comment` key is
a parse error, not a comment. Per-rule `"comment"` fields are supported and are
where each syscall's justification lives.

## Schema

seccompiler's, which is Firecracker's -- seccompiler was extracted from
Firecracker and reads the same files:

```json
{ "<thread>": { "default_action": "trap",     // mismatch: what happens off-list
                "filter_action": "allow",     // match: what happens on-list
                "filter": [ {"syscall": "read", "comment": "why"} ] } }
```

Three filters. `vcpu` is the tight one and the one that matters most, because
MMIO exits are serviced inline on the vCPU thread -- the virtio device models,
the code that parses guest descriptors, run there. `vmm` covers the main thread
and the host-side I/O threads. `control` is `vmm` plus the file calls a
checkpoint bundle needs, and only the control socket's thread installs it, and
only in a run started with `--checkpoint-root`. That thread parses the control
protocol, never guest data; a unit test holds `control` to `vmm` plus those
file calls.

## Why these are not Firecracker's lists

Vendoring Firecracker's filters wholesale, with their copyright header, was the
obvious first move. They were measured instead, and that is a deliberate
deviation rather than an oversight.

Firecracker ships `x86_64-unknown-linux-musl.json` and
`aarch64-unknown-linux-musl.json`, musl only, and drives its devices with epoll
and io_uring. hvi's lists were measured on a glibc build, and hvi uses blocking
reads on dedicated threads. So their lists carry `open`, `stat`, `io_uring_*`
and `epoll_*`, which we never call, and omit `openat`, `statx`, `rseq`,
`set_robust_list`, `sched_getaffinity` and `clone3`, without which a glibc Rust
binary does not reach `main`. Copying them would have been simultaneously too
loose and fatally too tight, so no code or list of theirs is included here and
no attribution is owed.

What does transfer is their production experience about the rare paths a single
trace never shows. Entries our own trace did not produce are marked
`"comment": "safety net: ..."`, and most of those came from reading their
lists.

The musl build shares the lists. musl can reach a different syscall than glibc
for the same library call, so `hvi seccomp-selftest` run on the musl binary is
the check for that.

## No `openat`, and the files glibc opens by itself

`vmm` and `vcpu` carry no `openat`. Every file hvi needs is open before the
filters go in, so a compromised device model cannot open one. The unit tests
hold both lists to that.

glibc's malloc does open two files on its own, from whichever thread is
allocating or freeing at the time:

- `/sys/devices/system/cpu/online`, to size its arena limit the first time a
  thread needs a new arena while more than eight exist (`malloc/arena.c`,
  `arena_get2`, which calls `__get_nprocs`). Every glibc reads it except the
  2.35 to 2.38 releases as first tagged, which asked `sched_getaffinity`
  there. Upstream went back to `__get_nprocs` in 2.39 (commit 472894d2cfee,
  BZ 30945), and the 2.35 to 2.38 release branches carry the same change, so
  any distribution that takes them reads the file too. Debian 12's 2.36 does.
- `/proc/sys/vm/overcommit_memory`, the first time the heap of an arena other
  than the main one shrinks (`check_may_shrink_heap`, called from
  `shrink_heap`). This read is in every glibc, unpatched upstream included.

Neither is specific to Debian or to arm64: an x86-64 host on a current glibc
reaches both. They were found on a Raspberry Pi 5 running Debian 12, whose
glibc 2.36-9+rpt2+deb12u12 and deb12u13 both trap. A guest with heavy
agent traffic kept enough vsock bridge threads allocating at once to reach
them, and the VMM died of `SIGSYS`. Allowing `openat` would undo the point of
the lists, so a confined run keeps glibc's malloc to its main arena instead.
`main` calls `mallopt(M_ARENA_MAX, 1)` once the arguments say the run is
confined, while the process still has one thread, and a KVM boot or restore
sets it again before its first thread. With the limit set, glibc never counts
CPUs, and with no other arena there is no other heap to shrink. A
`--no-sandbox` run installs no filter and keeps glibc's default arenas. `MALLOC_ARENA_MAX=4` in the
environment avoids the first read and not the second, so it is not a
workaround.

The cost is one malloc lock for the process, which is how the musl build
always runs. musl has no `mallopt` and its malloc opens no file, so on musl
there is nothing to set. Two selftest probes, `allocate on many threads at
once` and `free a thread's heap memory`, each reach one of these reads under
`vmm`. A new read in a later glibc would need a probe of its own.

## Changing a list

Adding a syscall is granting a right to a process that parses guest-controlled
data, so the bar is a demonstrated need, not a suspicion:

1. Reproduce the need. `HVI_SECCOMP=log hvi boot ...` installs these same
   filters with the mismatch action changed to `log`, so the kernel lets the
   off-list syscall run and records it (`dmesg`, `auditctl`) while the VMM
   keeps running. That names the syscall. It also means enforcement is off for
   that run, so it is a diagnostic and never a way to operate.
2. Add it to the narrowest filter that needs it, with a `comment` saying which
   code path calls it.
3. `cargo test` -- the unit tests check that both lists compile for the target
   arch, that `vcpu` stays a strict subset of `vmm`, and that neither list ever
   gains `open*`, `socket`, `connect`, `execve`, `seccomp` or `prctl`, each of
   which would undo the reason the filters go in after setup.
4. `hvi seccomp-selftest` -- installs the real filters in child processes and
   checks what survives.

`poll` is the only name that differs between the two files: x86-64 has both
`poll` and `ppoll`, and aarch64 has `ppoll` alone, because aarch64 has no
`poll` syscall. That asymmetry is why the two files are not generated from one
source, and the compile test is what catches getting it wrong.

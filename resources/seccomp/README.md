# hvi seccomp-bpf allowlists

One file per architecture, compiled into the binary by `src/seccomp.rs` and
installed per thread. The reasoning behind the design lives in that module's
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

Two threads. `vcpu` is the tight one and the one that matters most, because
MMIO exits are serviced inline on the vCPU thread -- the virtio device models,
the code that parses guest descriptors, run there. `vmm` covers the main thread
and the host-side I/O threads.

## Why these are not Firecracker's lists

Vendoring Firecracker's filters wholesale, with their copyright header, was the
obvious first move. They were measured instead, and that is a deliberate
deviation rather than an oversight.

Firecracker ships `x86_64-unknown-linux-musl.json` and
`aarch64-unknown-linux-musl.json` -- musl only -- and drives its devices with
epoll and io_uring. hvi is glibc and uses blocking reads on dedicated threads.
So their lists carry `open`, `stat`, `io_uring_*` and `epoll_*`, which we never
call, and omit `openat`, `statx`, `rseq`, `set_robust_list`,
`sched_getaffinity` and `clone3`, without which a glibc Rust binary does not
reach `main`. Copying them would have been simultaneously too loose and fatally
too tight, so no code or list of theirs is included here and no attribution is
owed.

What does transfer is their production experience about the rare paths a single
trace never shows. Entries our own trace did not produce are marked
`"comment": "safety net: ..."`, and most of those came from reading their
lists.

## Changing a list

Adding a syscall is granting a right to a process that parses guest-controlled
data, so the bar is a demonstrated need, not a suspicion:

1. Reproduce the need. `HVI_SECCOMP=log hvi boot ...` installs these same
   filters with the mismatch action changed to `log`, so the kernel records
   what would have been killed (`dmesg`, `auditctl`) while the VMM keeps
   running. That names the syscall.
2. Add it to the narrowest filter that needs it, with a `comment` saying which
   code path calls it.
3. `cargo test` -- the unit tests check that both lists compile for the target
   arch, that `vcpu` stays a strict subset of `vmm`, and that neither list ever
   gains `open*`, `socket`, `connect`, `execve`, `seccomp` or `prctl`, each of
   which would undo the reason the filters go in after setup.
4. `hvi seccomp-selftest` -- installs the real filters in child processes and
   checks what survives.

`poll` is x86-only; aarch64 spells it `ppoll`. That asymmetry is why the two
files are not generated from one source, and the compile test is what catches
getting it wrong.

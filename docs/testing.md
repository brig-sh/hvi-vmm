# What runs where

Six kinds of check guard this repository, and they are not equally strong.
Keep them apart when you read a green tick.

| Evidence | What it proves |
| --- | --- |
| Compiles for a target | The code type-checks there. Nothing runs. |
| Unit tests | The tested functions behave. No guest, no virtqueue, no VM exit. |
| Confinement selftests | Specific probes are allowed or denied. Not that the sandbox is secure. |
| Used-ring litmus | Demonstrates a memory-ordering defect and its fix. Not a reliable regression catcher. |
| Live boot | A real guest reached a real gate on real hardware. |
| Performance gate | This branch is not slower than its merge base, by two measures. |

## Before you push

```sh
tools/gates.sh
```

It runs the CI checks a developer machine can run, and names every check it
skipped so a run with a skip never reports a bare `ok`.

Always runs: `tools/tidy.sh --check` and `cargo test`.

Skipped when its tool is missing, and named: the three cross-lints, for
aarch64 glibc and for x86-64 and aarch64 musl (each needs its rustup target),
`cargo deny check`, the workflow lint (actionlint and shellcheck), and the
spell check (typos).

One skip it does not count: `tools/tidy.sh` drops the comment-reflow pass when
the nightly pinned in `pins.env` is not installed. It says so on stderr, and
`gates.sh` still prints `ok`. Install it, or CI finds what you missed:

```sh
. ./pins.env && rustup toolchain install "$RUSTFMT_NIGHTLY" \
    --profile minimal --component rustfmt
```

`--with-perf` adds the virtio-fs performance gate. It is macOS only and builds
the merge base as well as the branch, so it costs more than everything else
together.

Three checks cannot run on any developer machine: the other host's backend,
the live boots, and the commit-message lint, which needs a pull request's
commit range.

## The unit suite

```sh
cargo test
```

Only the backend for your host target compiles, so the suite you run is the
portable core plus your own backend.

Where it actually runs in CI:

| Where | What runs |
| --- | --- |
| x86-64 Linux (`ubuntu-latest`) | The full suite. On a push to `main` it runs once under `cargo llvm-cov` instead, and the profile goes to Codecov, which is what the coverage badge reads. |
| macOS 15 | The full suite, including the macOS backend and virtio-fs. |
| arm64 Linux | The full suite in the release profile, on both self-hosted arm64/KVM runners, reusing the live boot's build. |
| x86-64 Linux, musl (`ubuntu-latest`) | The full suite for `x86_64-unknown-linux-musl`, then the seccomp selftest on the static binary. |
| arm64 Linux, musl (`ubuntu-24.04-arm`) | The full suite for `aarch64-unknown-linux-musl`, then the seccomp selftest on the static binary. |

`src/arch/x86_64/kvm.rs` has unit tests and they run on `ubuntu-latest`, so the
x86-64/KVM backend is unit-tested. `src/arch/aarch64/kvm.rs` has none. The KVM
stop tests in `src/hypervisor/kvm.rs` run on whichever KVM backend the host has,
and they need `/dev/kvm`.

The used-ring litmus, the virtio-fs benchmarks and the KVM stop tests are
`#[ignore]`d and do not run in a normal `cargo test`.

The stop tests boot a guest on the terminal, and two of them find a thread by
name. Run them one at a time, with stdin redirected, as a user who can open
`/dev/kvm`:

```sh
cargo test --release kvm::stop_tests:: -- \
  --ignored --test-threads=1 </dev/null
```

## The confinement selftests

```sh
hvi sandbox-selftest    # macOS
hvi seccomp-selftest    # Linux
```

Neither needs a hypervisor or privileges, so a hosted runner that cannot boot
a guest can still fail a bad profile or a bad list. CI runs the Seatbelt one
on hosted macOS, and the seccomp one on hosted x86 Linux, on both hosted musl
builds and on the self-hosted arm64 runners. The aarch64 list runs on the
hosted arm64 musl build, and the self-hosted runners are the only place it
runs on the glibc build.

The macOS job asserts the success line, so a change of runner image cannot
quietly turn the step into a no-op.

## The live boots

Three jobs boot a real guest on hardware the project owns. They assert on the
console log:

| Job | Runner | Asserts |
| --- | --- | --- |
| `boot-x86` | self-hosted x86 with `/dev/kvm` | `Linux version`; `seccomp: on`; the userspace or VFS gate; both processors online with `--cpus 2`; the guest starts on kvm-clock and finds the TSC-deadline timer. Then the `vmlinux` that `scripts/extract-vmlinux` unpacks from the same image reaches the gate, and a 4096 MiB guest's e820 shows the three usable ranges of RAM split around the MMIO hole. A guest's `poweroff -f` ends the run as `SystemOff`, and its `reboot -f` ends it as `SystemReset` both with ACPI and with `acpi=off`. Also runs the virtio-blk sizing test against a real loop device, and the vCPU stop tests. |
| `boot-arm64-hvf` | self-hosted Apple silicon | `hvi smoke`, `hvi smoke --shm`, then a boot reaching `Linux version` and `HVI-INITRAMFS-UP`. |
| `boot-unikraft-hvf` | self-hosted Apple silicon | Two public Unikraft images, over four boots. A DHCP boot asserts the banner, `Set IPv4 address 10.0.2.15` and `Listening on port 8123`, with a share attached so the VMM has to place a virtio-fs device -- no other job does. A second boot passes `netdev.ip=` and asserts the guest took `10.0.2.99` and did *not* fall through to `10.0.2.15`, which is what fails if an image loses `CONFIG_LIBUKNETDEV_EINFO_LIBPARAM`. A third boots a padded cpio -- the pinned one is two whole pages, so the job adds 512 bytes to make the length ragged -- and asserts the banner, no memory-region assertion failure, and no `nginx:` error line. |
| `boot-arm64-kvm` | self-hosted arm64, two hosts | A matrix over a GIC-400 host and a GICv3 host, so both vGIC paths run. Each runs the unit suite, the vCPU stop tests, the aarch64 seccomp selftest, a boot that checks the guest gets pointer authentication when the host CPU and the guest kernel have it, a boot on a real tap when one can be created, and a check that an unusable tap refuses to boot and names the interface. |

`boot-x86` skips itself with a warning when the runner has no `/dev/kvm`. A
skip is not a pass.

The self-hosted lanes are withheld from pull requests opened from a fork,
because these are persistent machines rather than ephemeral VMs. A fork still
gets every hosted job.

They are self-hosted for two reasons. No GitHub-hosted arm64 runner exposes
`/dev/kvm`, and the hosted macOS images do not give a guest
Hypervisor.framework. The entitlement is not the reason: an ad-hoc signature
works with SIP enabled and with no terminal session.

The boot jobs upload their logs on failure. The two arm64 Linux-guest jobs
also upload the event ledger. `boot-x86` and `boot-unikraft-hvf` do not pass
`--events`, so they record none.

## The checkpoint end-to-end test

`tools/checkpoint-e2e.sh` moves a running guest from one hvi process to
another on the same host, and checks that it carried on rather than
rebooting. No CI job runs it yet; run it by hand on Apple silicon, with a
signed release build, or with `--portable` on an arm64 KVM host too:

```sh
python3 tools/mk-initramfs.py --checkpoint-workload \
    --out target/initramfs-workload.cpio
tools/checkpoint-e2e.sh --hvi target/release/hvi --kernel Image \
    --initramfs target/initramfs-workload.cpio --out /tmp/e2e --cpus 2 --mem 512
```

The build must be of a commit with no uncommitted changes, since a restore
refuses a profile whose hvi was built with them. The disk is an ext4 image the
script makes with `mke2fs` from e2fsprogs, and reads back with `debugfs`; it
exits 2 when either is missing. `--no-disk` runs without a disk.

The workload is a loop that keeps a count in a shell variable, prints it every
200 ms with the guest's uptime and wall clock, and holds a file open on fd 3
after unlinking it. It also writes and syncs a file on `/dev/vda`. Beside it,
a CPU-bound `awk` at the lowest priority sums 0.25 into a double and prints
the count and the sum every 500000 additions. It is on a vCPU most of the
time, so a capture most likely finds its floating-point registers and its
thread pointer live in the vCPU, and a wrong restore of them shows as a sum
that is not exact or a count that does not go on. That is a likely catch,
not a certain one. The script:

1. boots the guest with a control socket, a checkpoint root, the disk, the
   stub network and an agent socket, and gives it the host's wall clock;
2. checkpoints it with `then: "fence"` and starts `hvi restore` as a second
   process with its own sockets, then sends `resume` once it reports
   `restored-paused`;
3. checks that the count and the `awk` sum go on from the captured ones,
   that no boot banner appears, that the guest's monotonic and wall clocks
   go on from the capture, that the fenced source printed nothing more, and
   that a second restore of the bundle onto the running guest's disk fails
   on the disk lock;
4. asks the guest, over the console, to print its count, read fd 3 and the
   disk file, write and sync another file and time a `sleep 5` against the
   host;
5. moves the guest once more, into a third process, holds it
   `restored-paused` for a second and checks that it printed nothing and its
   clock did not move, then resumes it and checks it counts on;
6. stops every process, checks that the disk generation in `disk.json` grew
   from the first move to the second, and reads the post-restore file from
   the image on the host with `debugfs`.

It prints each check and writes `summary.json` with `pause_ms`,
`capture_ms`, the bundle size, the time from starting `hvi restore` to its
`restored-paused` reply, and the downtime from the checkpoint request, and
from its reply, to the `resume` reply. It exits 1 when a check failed.
[checkpoint.md](checkpoint.md#timings) has the figures.

`--portable` boots the portable profile instead, on the Mac or on a Pi 5,
with the portable kernel and an initramfs that also holds `el0check` and
`tfd` (`tools/guest/tfd.c`), both static arm64 binaries. `el0check.c` is not
in this repository: it is the acceptance test of the portable kernel's EL0
counter patch, GPL-2.0, and is kept with that kernel's two patches as
`test/el0check.c`, beside `patches/`. Build each with
`gcc -O2 -static`:

```sh
python3 tools/mk-initramfs.py --checkpoint-workload --add el0check --add tfd \
    --out target/initramfs-portable.cpio
tools/checkpoint-e2e.sh --hvi target/release/hvi --kernel Image-portable \
    --initramfs target/initramfs-portable.cpio --out /tmp/e2e-p --cpus 1 \
    --mem 512 --portable
```

Just before the capture it starts a 6 s `timerfd` and a 6 s `sleep`. Beside
the checks above, it checks that the clocksource is `hvi-time` and
`el0check` passes before and after the move, that both timers fire after
the resume 6 s of guest time after they were armed, that the guest driver
logged the move, generation 4, and counts it (`migrations=1`, or up to one
per vCPU: the driver runs its migration work again on a vCPU that takes
`GEN_CHANGED` after the work has run), and that the guest's wall clock
is the host's again. The uptime the ticks carry is `CLOCK_BOOTTIME`, which
`hvi-time` moves on by the downtime, so the continuity checks take the
downtime the restore logged off.

## Toolchain versions

Four places declare a Rust version. The first two hold the build pin, and the
other two step outside it:

| Where | Value | Meaning |
| --- | --- | --- |
| `Cargo.toml` `rust-version` | 1.95.0 | The oldest Rust that builds hvi, held to the build pin. `tools/tidy.sh` fails when the two differ. |
| `rust-toolchain.toml` | 1.95.0 | The build pin. Every job that uses the shared setup gets this. |
| `pins.env` `RUSTFMT_NIGHTLY` | nightly-2026-08-30 | The nightly whose rustfmt runs the comment reflow. `wrap_comments` is nightly-only. |
| The cargo-deny lane | `stable` | Steps outside the pin deliberately. |

Only `tidy-portable` installs the reflow nightly, so it is the one job that
runs that check.

## The performance gate

`tools/perf-gate.sh` builds the branch and its merge base on the same machine
in the same run and compares two things:

- **Host operations per round.** It fails when the count goes **up**. A
  decrease is reported and passes.
- **Wall time.** It fails when the branch is more than 1.5 times slower.

`--base <ref>`, `--samples <n>` and `--limit <ratio>`, or `PERF_GATE_BASE`,
`PERF_GATE_SAMPLES` and `PERF_GATE_LIMIT`, override the merge base, the five
samples per side and the ceiling.

It runs on the Apple-silicon runner for same-repo pull requests only, and it
needs `fetch-depth: 0`, because a shallow clone has no merge base.

See [benchmarking.md](benchmarking.md).

## Scheduled workflows

Three run outside the two entry workflows. Each reports through a tracking
issue and leaves `main` green: a failure files or updates one issue, and the
next green run closes it.

- `audit-deps.yml`: `cargo deny check` against the lockfile every Monday, for
  advisories that arrive between changes.
- `stress-weekly.yml`: the `#[ignore]`d used-ring litmus on a self-hosted
  arm64 runner every Monday. It demonstrates the ordering defect and the fence
  that removes it. It is not reliable enough to gate a pull request.
- `schedule-reflow-drift.yml`: monthly, runs the reflow on the latest nightly
  and compares it with the pin, so the pin advances deliberately.

## Distribution

There is none. No git tag exists, no workflow publishes a crate, and no
workflow produces a release artifact. The only uploads anywhere are failure
logs. Anything that tells a reader to install hvi is wrong.

## See also

- [../CONTRIBUTING.md](../CONTRIBUTING.md) for commits, branches and pull
  requests.
- [benchmarking.md](benchmarking.md) for measuring a virtio-fs change.

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

The stop tests boot a guest on the terminal, and one of them finds the secondary
vCPU's thread and descriptors by name. Run them one at a time, with stdin
redirected, as a user who can open `/dev/kvm`:

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
| `boot-x86` | self-hosted x86 with `/dev/kvm` | `Linux version`; `seccomp: on`; the userspace or VFS gate; both processors online with `--cpus 2`. Then the `vmlinux` that `scripts/extract-vmlinux` unpacks from the same image reaches the gate, and a 4096 MiB guest's e820 shows the three usable ranges of RAM split around the MMIO hole. Also runs the virtio-blk sizing test against a real loop device, and the vCPU stop tests. |
| `boot-arm64-hvf` | self-hosted Apple silicon | `hvi smoke`, `hvi smoke --shm`, then a boot reaching `Linux version` and `HVI-INITRAMFS-UP`. |
| `boot-unikraft-hvf` | self-hosted Apple silicon | Two public Unikraft images, over four boots. A DHCP boot asserts the banner, `Set IPv4 address 10.0.2.15` and `Listening on port 8123`, with a share attached so the VMM has to place a virtio-fs device -- no other job does. A second boot passes `netdev.ip=` and asserts the guest took `10.0.2.99` and did *not* fall through to `10.0.2.15`, which is what fails if an image loses `CONFIG_LIBUKNETDEV_EINFO_LIBPARAM`. A third boots a padded cpio -- the pinned one is two whole pages, so the job adds 512 bytes to make the length ragged -- and asserts the banner, no memory-region assertion failure, and no `nginx:` error line. |
| `boot-arm64-kvm` | self-hosted arm64, two hosts | A matrix over a GIC-400 host and a GICv3 host, so both vGIC paths run. Each runs the unit suite, the vCPU stop tests, the aarch64 seccomp selftest, a boot, a boot on a real tap when one can be created, and a check that an unusable tap refuses to boot and names the interface. |

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
the count and the sum every 500000 additions. Its sums show that the guest's
floating-point work goes on after a move, but not that a restore loaded the
registers: busybox `awk` keeps its sum in memory, and a task off the CPU
keeps its registers in guest RAM, so a restore that lost every SIMD register
still gave exact sums. Step 5 checks the registers instead. The script:

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
   clock did not move. It checkpoints it there with `then: "continue"` and
   checks that every vCPU register in `cpu.json` and the interrupt
   controller and timer state in `platform.json` equal the bundle's, less
   the host's monotonic clock at the capture, and that the guest is still
   `restored-paused`. Then it resumes it and checks it counts on;
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
logged the move, generation 4, and counts it once (`migrations=1`), and that
the guest's wall clock is the host's again.

With more than one vCPU the count can come out higher, up to one per vCPU.
That is a defect of the portable kernel's `hvi-time` driver: it runs its
migration work for each vCPU that takes `GEN_CHANGED`, so it logs one
move more than once and moves the wall clock again each time, by about
1 µs. The fix is for the driver to remember the last generation it
handled. Until then the script reports such a count as `xfail`, an
expected failure that does not fail the run, and lists it under
`expected_failures` in `summary.json`. The uptime the ticks carry is `CLOCK_BOOTTIME`, which
`hvi-time` moves on by the downtime, so the continuity checks take the
downtime the restore logged off.

## The migration end-to-end test

`tools/migrate-e2e.sh` moves a running portable guest from one host to
another, stopped, and checks that it carried on rather than rebooting. It
was written for a Mac and a Raspberry Pi 5, in either direction, but takes
any two hosts that run the portable profile, and one host as both. Run it
from a machine that can reach both hosts over ssh without a password; a
host given as `local` is that machine. No CI job runs it.

Each host needs hvi built from one commit with no uncommitted changes, or
the restore refuses the bundle (on macOS, signed), plus python3 and rsync.
The source needs `mke2fs`, the destination `e2fsck` and `debugfs`. The
guest is the portable kernel and the checkpoint workload with three static
helpers: `el0check` (see above), `tfd` (`tools/guest/tfd.c`) and `clk`
(`tools/guest/clk.c`), which prints the guest's `CLOCK_REALTIME`,
`CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` in nanoseconds every 250 ms. Build
the helpers with `gcc -O2 -static` on an arm64 Linux host, and copy one
initramfs to both hosts:

```sh
python3 tools/mk-initramfs.py --checkpoint-workload --add el0check --add tfd \
    --add clk --out target/initramfs-migrate.cpio
tools/migrate-e2e.sh --src local --dst rp2 \
    --src-hvi target/release/hvi --dst-hvi /home/pi/hvi/target/release/hvi \
    --kernel Image-portable --initramfs target/initramfs-migrate.cpio \
    --src-dir /tmp/mig-src --dst-dir /home/pi/mig --out /tmp/mig-out
```

`--kernel`, `--initramfs`, `--src-hvi` and `--src-dir` are paths on the
source host, and `--dst-hvi` and `--dst-dir` on the destination. The script
empties both directories first. Each host runs its own half of the test, a
driver the script copies there, so that every console line is stamped
with the clock of the host whose hvi printed it, never across ssh. The
script:

1. measures each host's wall clock against its own, over one ssh session;
2. boots the guest on the source with an ext4 disk and the stub network,
   starts `clk`, turns off the console's echo, and records the guest's
   `Features` line and `/proc/interrupts`;
3. arms a 6 s `timerfd` and a 6 s `sleep`, checkpoints the guest with
   `then: "fence"`, checks that both timers were still pending, and stops
   the source;
4. copies the bundle and the disk with `rsync -S -a --stats`;
5. restores the bundle on the destination, onto the copied disk, and
   resumes it.

It then checks on the destination:

- the count goes on by one, the `awk` sums stay exact, and no boot banner
  appears;
- the guest driver logs generation 4 at the destination's counter rate, and
  counts the move once (`migrations=1`);
- both timers fire after the resume, 6 s of guest time after they were
  armed;
- the workload's request: fd 3, the file written before the move, a write
  after it, `el0check`, the clocksource, and a `sleep 5` against the host;
- the `Features` line is the source's, and the `hvi-time`, PL011 and
  virtio-blk interrupt counts go on from the source's and grow;
- `clk` printed every line across the move, `CLOCK_MONOTONIC` never stepped
  back, and its gap over the move is one period: the downtime does not
  show on it;
- `CLOCK_REALTIME` is within 100 ms of the destination host's clock, over
  the first 10 s after the driver's fix-up, and again after `--drift-secs`
  (600 by default), from which it gives the drift in ppm;
- after the guest unmounts its disk and stops, `e2fsck -fn` finds the image
  clean and `debugfs` reads the file written after the move.

`summary.json` in `--out` holds the timings: `pause_ms` and `capture_ms`
from the fence, the copy's time, bytes and rate, the restore's time to
`restored-paused`, and the downtime three ways (on the script's clock from
the fence request to the resume reply, from the two hosts' wall clocks, and
as `hvi-time` moved the guest's wall clock). It exits 1 when a check failed.

`--recapture` checkpoints the restored guest again before it resumes, with
`then: "continue"`, and checks that its vCPU and platform state equal the
bundle's. Across backends the registers only HVF has must be 0 there. That
capture is inside the downtime, so take the timings from a run without it.

`--negative` runs the refusals instead, on the destination, against the
bundle a run without it left in `--dst-dir`:

- a native bundle of the source, booted with `--profile native`;
- copies of the portable bundle with the vCPU count or the RAM size changed
  in `profile.json` and the manifest sealed again, so that the check of
  the machine fires and not the digest; with one byte of `ram.bin`
  changed; and with `cpu.json` cut short. Each goes to `checkpoint-verify`
  and to `restore`;
- a restore without `--disk`;
- on a KVM destination, a restore and a portable boot on a host whose KVM
  offers no vGICv2. An `LD_PRELOAD` shim, built there with `cc`, fails
  `KVM_CREATE_DEVICE` for `KVM_DEV_TYPE_ARM_VGIC_V2` with `ENODEV`, as a
  GICv3-only host does.

Results and the exact commands are in
[portable-profile.md](portable-profile.md#measured-results).

A Mac that sleeps stops its guest's clocks, since Hypervisor.framework's
counter does not run in sleep, and nothing sets the guest's wall clock
again on wake. Keep the Mac awake through a run (`caffeinate -i`, and the
lid open on battery), or its drift figures measure the sleep.

## Toolchain versions

Four version declarations, and they mean different things:

| Where | Value | Meaning |
| --- | --- | --- |
| `Cargo.toml` `rust-version` | 1.77 | The MSRV floor. A compatibility claim. **No CI job builds at it**, so it is not enforced. |
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

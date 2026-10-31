# What runs where

Seven kinds of check guard this repository, and they are not equally strong.
Keep them apart when you read a green tick.

| Evidence | What it proves |
| --- | --- |
| Compiles for a target | The code type-checks there. Nothing runs. |
| Unit tests | The tested functions behave. No guest, no virtqueue, no VM exit. |
| Confinement selftests | Specific probes are allowed or denied. Not that the sandbox is secure. |
| Used-ring litmus | Demonstrates a memory-ordering defect and its fix. Not a reliable regression catcher. |
| Live boot | A real guest reached a real gate on real hardware. |
| E2E suite | The release build of hvi, confined, ran a guest that drove a device, and the run stopped as expected. |
| Performance gate | This branch is not slower than its merge base, by two measures. |

## Before you push

```sh
tools/gates.sh
```

It runs the CI checks a developer machine can run, and names every check it
skipped so a run with a skip never reports a bare `ok`.

Always runs: `tools/tidy.sh --check`, `cargo test` and the e2e workspace's unit
tests.

Skipped when its tool is missing, and named: the three cross-lints, for aarch64
glibc and for x86-64 and aarch64 musl (each needs its rustup target),
`cargo deny check` over both lockfiles, the workflow and script lint (actionlint
and shellcheck), and the spell check (typos).

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

`--with-e2e` adds the e2e suite, which needs the hypervisor; see [the e2e
suite](#the-e2e-suite).

Four checks cannot run on any developer machine: the other host's backend, the
live boots, the e2e filter-name check, which needs every backend's test list,
and the commit-message lint, which needs a pull request's commit range.

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

`src/arch/x86_64/kvm/` has unit tests and they run on `ubuntu-latest`, so the
x86-64/KVM backend is unit-tested. `src/arch/aarch64/kvm/` has none. The KVM
stop tests in `src/hypervisor/kvm.rs` run on whichever KVM backend the host has,
and they need `/dev/kvm`.

The used-ring litmus, the virtio-fs benchmarks and the KVM stop tests are
`#[ignore]`d and do not run in a normal `cargo test`.

The stop tests boot a guest on the terminal, and two of them find a thread by
name. Run them with the `kvm` profile in `.config/nextest.toml`, which runs each
in a process of its own, as a user who can open `/dev/kvm`:

```sh
cargo nextest run --cargo-profile release --profile kvm --run-ignored only
```

With plain `cargo test`, run them one at a time, with stdin redirected:

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

The e2e suite covers most of what these jobs check, through the exit status and
the ledger rather than the console.

## The e2e suite

`e2e/` boots real guests under the release `hvi` binary, with its default
confinement, and checks each run from outside the process: hvi's exit status,
its `guest stopped:` line and the event ledger. It runs under cargo-nextest.
[e2e/README.md](../e2e/README.md) covers the setup it needs, running it, its
layout, and adding a test.

### Tiers

| Profile | What it runs | Where |
| --- | --- | --- |
| `default` | Every test off the probation and nightly lists. | Pull requests and `main`. |
| `full` | Every test. | `schedule-e2e-nightly.yml`. |

A new or flaky test stays on the probation list until it has passed seven
nightly runs in a row, and a test too slow for every pull request stays on the
nightly list, so neither runs on a pull request.

The default profile retries a failed test once. One that passes only on its
retry is reported as flaky and still fails the run, so a race shows up as a
failure rather than as a pass. A test that pins a bug not fixed yet carries
`#[ignore]`, and the nightly run reports any that now pass.

### Where it runs in CI

| Where | What runs |
| --- | --- |
| Self-hosted x86, arm64/KVM (vGICv2 and vGICv3) and Apple silicon | `test-e2e.yml`: the `default` profile for same-repository pull requests and `main`. `schedule-e2e-nightly.yml` runs the `full` profile there every night. |
| The same runners, on a pull request | `e2e/tools/check-probation.sh`: every new test is on the probation or nightly list, and a test that leaves the nightly list goes on probation. |
| `ubuntu-latest`, once every backend has passed | The filter-name check: each exact name in the nextest filters names a test on some backend. |
| x86-64 Linux (`ubuntu-latest`) | The e2e workspace's unit tests, which need no hypervisor, so a fork's pull request runs them too. |

## Toolchain versions

Four places declare a Rust version. The first two hold the build pin, and the
other two step outside it:

| Where | Value | Meaning |
| --- | --- | --- |
| `Cargo.toml` and `e2e/Cargo.toml` `rust-version` | 1.95.0 | The oldest Rust that builds hvi and its e2e suite, held to the build pin. `tools/tidy.sh` fails when either differs from it. |
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

Four run outside the two entry workflows. Each reports through a tracking issue
and leaves `main` green: a failure files or updates one issue, and the next
green run closes it.

- `audit-deps.yml`: `cargo deny check` against both lockfiles every Monday, for
  advisories that arrive between changes.
- `schedule-e2e-nightly.yml`: the e2e suite's `full` profile on every backend,
  every night. It also runs the ignored tests and names any that now pass, and
  reports the tests ready to leave probation.
- `stress-weekly.yml`: the `#[ignore]`d used-ring litmus on a self-hosted
  arm64 runner every Monday. It demonstrates the ordering defect and the fence
  that removes it. It is not reliable enough to gate a pull request.
- `schedule-reflow-drift.yml`: monthly, runs the reflow on the latest nightly
  and compares it with the pin, so the pin advances deliberately.

## Distribution

No crate is published. Binaries come from two lanes that call the same
`build-binaries.yml` and `publish-binaries.yml`:

- [`main-build-and-publish.yml`](../.github/workflows/main-build-and-publish.yml):
  every push to `main`, once the suites pass, as development builds in
  `ghcr.io/brig-sh/hvi-binaries:<target>-<sha>`.
- [`tag-release.yml`](../.github/workflows/tag-release.yml): a `vX.Y.Z` tag, as
  `<target>-vX.Y.Z` and a GitHub release, with the macOS binary signed with the
  Developer ID and notarized.

[CONTRIBUTING.md](../CONTRIBUTING.md#releasing) covers cutting a release, and
the README covers verifying one.

## See also

- [../CONTRIBUTING.md](../CONTRIBUTING.md) for commits, branches and pull
  requests.
- [benchmarking.md](benchmarking.md) for measuring a virtio-fs change.

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

Skipped when its tool is missing, and named: the aarch64 cross-lint (needs the
rustup target), `cargo deny check`, the workflow lint (actionlint and
shellcheck), and the spell check (typos).

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
| arm64 Linux | No suite. The weekly litmus job builds and runs one test binary there. |

`src/machine_x86.rs` has unit tests and they run on `ubuntu-latest`, so the
x86-64/KVM backend is unit-tested. `src/machine_linux.rs` has none.

Three tests are `#[ignore]`d and do not run in a normal `cargo test`: the
used-ring litmus and the virtio-fs benchmarks.

## The confinement selftests

```sh
hvi sandbox-selftest    # macOS
hvi seccomp-selftest    # Linux
```

Neither needs a hypervisor or privileges, so a hosted runner that cannot boot
a guest can still fail a bad profile or a bad list. CI runs the seccomp one on
hosted x86 Linux, the Seatbelt one on hosted macOS, and the aarch64 seccomp
one on the self-hosted arm64 runners, which is the only place that list is
exercised rather than merely compiled.

The macOS job asserts the success line, so a change of runner image cannot
quietly turn the step into a no-op.

## The live boots

Three jobs boot a real guest on hardware the project owns. They assert on the
console log:

| Job | Runner | Asserts |
| --- | --- | --- |
| `boot-x86` | self-hosted x86 with `/dev/kvm` | `Linux version`; `seccomp: on`; the userspace or VFS gate; both processors online with `--cpus 2`. Also runs the virtio-blk sizing test against a real loop device. |
| `boot-arm64-hvf` | self-hosted Apple silicon | `hvi smoke`, `hvi smoke --shm`, then a boot reaching `Linux version` and `HVI-INITRAMFS-UP`. |
| `boot-arm64-kvm` | self-hosted arm64, two hosts | A matrix over a GIC-400 host and a GICv3 host, so both vGIC paths run. Each does the aarch64 seccomp selftest, a boot, a boot on a real tap when one can be created, and a check that an unusable tap refuses to boot and names the interface. |

`boot-x86` skips itself with a warning when the runner has no `/dev/kvm`. A
skip is not a pass.

The self-hosted lanes are withheld from pull requests opened from a fork,
because these are persistent machines rather than ephemeral VMs. A fork still
gets every hosted job.

They are self-hosted for two reasons. No GitHub-hosted arm64 runner exposes
`/dev/kvm`, and the hosted macOS images do not give a guest
Hypervisor.framework. The entitlement is not the reason: an ad-hoc signature
works with SIP enabled and with no terminal session.

The boot jobs upload their logs on failure. The two arm64 jobs also upload the
event ledger. `boot-x86` does not pass `--events`, so it records none.

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

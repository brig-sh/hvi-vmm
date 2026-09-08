# Contributing

## Before you push

`tools/tidy.sh` is the one command to run before you push. It formats the tree,
reflows comments to 80 columns, then runs clippy and rustdoc:

```sh
tools/tidy.sh              # format + reflow (fixes in place), clippy, doc
cargo test                 # the unit suite
```

The fmt and reflow passes rewrite the tree in place. CI runs the same script
with `--check`, the read-only variant that verifies without writing, so a clean
local run means a green `validate-code`. The reflow needs the nightly rustfmt
pinned in `pins.env` (`wrap_comments` is nightly-only); without that exact
toolchain the script says so and skips that pass, and CI catches what you
missed.

`tools/gates.sh` runs the CI checks a developer machine can run, in one
command: `tidy.sh --check`, the aarch64 cross-lint, `cargo test`, `cargo deny
check`, the workflow lint and the spell check. `tidy.sh` and `cargo test`
always run. The other four need something the pinned toolchain does not
supply (the `aarch64-unknown-linux-gnu` target, `cargo-deny`, `actionlint`
plus `shellcheck`, `typos`), so each is skipped when it is missing and every
skip is named in the closing line -- the script never reports a bare `ok`
when something did not run. `--with-perf` adds the virtio-fs performance
gate (`tools/perf-gate.sh`, macOS only), which builds the merge base as well
as the branch and so costs more than every other check together. The live
boots, the other host's backend and the commit-message lint stay CI's job.

Only the backend for your host target is compiled: the macOS/hvf one on Apple
silicon, x86-64/KVM on an x86 Linux box. To lint a backend you have no host for,
pass its target:

```sh
rustup target add aarch64-unknown-linux-gnu
tools/tidy.sh --check --lint-only --target aarch64-unknown-linux-gnu
```

`--lint-only` skips the fmt and reflow passes, which are target-independent
anyway, and runs just clippy and rustdoc for that target.

The toolchain is pinned in `rust-toolchain.toml`, so everyone lints against the
same compiler. `rust-version` in `Cargo.toml` is a different thing: the MSRV
floor, not the build pin.

## Branches

`main` is always releasable and protected; changes land through pull requests.
Work on short-lived branches named for what they carry -- `feat/<description>`,
`fix/<issue>-<description>`, `docs/<description>` -- and delete them once
merged. Rebase on `main` instead of merging `main` into your branch, so the
eventual history is linear and the PR diff shows only your change.

## Commits

Each commit should be one logical change that builds and passes tests **on its
own**, so `git bisect` stays usable and a revert stays surgical. In practice
that means: keep a mechanical refactor in its own commit ahead of the change it
enables, don't mix unrelated fixes in, and rebase away "fix typo from previous
commit" before asking for review. Rewrite history freely while the branch is
yours; once review has started, append fixup commits so reviewers can see what
changed between rounds, and squash before merge.

Sign off every commit with `git commit -s`, which adds the `Signed-off-by`
trailer and certifies the [DCO](https://developercertificate.org/). CI rejects
a commit without one.

Conventional Commits, `type(scope): Subject`:

```
feat(virtio): Advertise the flush feature on virtio-blk

A guest that sets VIRTIO_BLK_F_FLUSH expects fsync on a flush request;
without the feature bit a filesystem's barriers are silently dropped,
so a crash loses writes the guest was told were durable.

Refs #14.

Signed-off-by: Anastassios Nanos <ananos@nofire.ai>
```

The rules CI enforces per pull request, from
`.github/linters/commitlint.config.mjs`:

- header within 72 columns, subject capitalized and without a trailing period
- scope lowercase (machine, x86, virtio, boot, layout, fdt, ci, docs)
- body prose wrapped at 72 columns, trailers and table rows exempt
- a `Signed-off-by` trailer on every commit (DCO)

Two of those are deliberately stricter or different from the general
convention, and are called out here so nobody has to guess which wins: the
subject is **capitalized** (`Add the flush feature`, not `add the flush
feature`), and the body wraps at **72** columns, not 80. The linter in
`.github/linters/` is the authority for this repository either way.

Spelling is checked over the tree and over the commit messages a pull request
adds, sharing one dictionary in `.github/linters/typos.toml`. When it flags a
domain term (a register name, an acronym), add the word there instead of
rewording the comment.

## Pull requests

Open as a draft while the work is in progress, and mark it ready only when CI
is green and the commits are in their final shape. Fill in the template: what
the change does, why, and how it was tested. Keep one logical change per pull
request -- a drive-by fix in an unrelated file slows the review and complicates
the revert.

A pull request is mergeable when CI is green (including the commit-message
lint), the approvals are in place, the branch is rebased on `main`, and every
commit is signed off. We rebase-and-merge, so the commits land in `main`
verbatim -- which is why each one is linted and expected to stand alone.

## What CI checks, and what it deliberately doesn't

A pull request runs `.github/workflows/pr-build-and-verify.yml` and a push to
`main` runs `main-build-and-verify.yml`. Both are thin entry workflows calling
the same reusable ones. The shared `.github/actions/setup-rust` composite
installs the pinned toolchain, adds any cross target and restores the cargo
cache.

`validate-commits.yml` (pull requests only, since a rebase-and-merge lands the
commits on `main` verbatim):

- **lint-commit-messages**: the conventions above, per commit, reported by short
  SHA so you know which one to fix.
- **check-spelling**: the tree and the commit messages the pull request adds.

`validate-code.yml` (lint, read-only):

- **tidy-portable**: `tools/tidy.sh --check` on x86 Linux. This job owns
  formatting for the whole tree -- rustfmt does not evaluate `cfg`, so it
  reaches every module, including the backends that runner cannot build.
- **tidy-linux-aarch64**: clippy and rustdoc for `aarch64-unknown-linux-gnu`,
  cross-checked from the x86 runner. No cross-linker is needed for either.
- **tidy-macos-hvf**: the same two on `macos-15`, for the
  Hypervisor.framework backend.
- **lint-workflows**: actionlint plus shellcheck over the workflows
  themselves, with both binaries version-pinned and sha256-verified. The
  self-hosted runner labels live in `.github/actionlint.yaml`.
- **check-deps**: `cargo deny check` over the lockfile: RUSTSEC advisories,
  licenses, duplicate versions and registry sources, per `deny.toml`. The
  tool pin and the invocation live in the `.github/actions/cargo-deny`
  composite, shared with the weekly lane below.

`build-and-test.yml`:

- **test-portable**: `cargo test` on x86 Linux. On a push to `main` the
  suite runs once under `cargo llvm-cov` instead, which gives the same pass
  or fail plus an lcov profile that is uploaded to Codecov for the README
  badge; the upload never fails the run. A pull request does not pay for the
  instrumentation.
- **seccomp-x86**: `hvi seccomp-selftest` on x86 Linux, which installs the
  shipped filters in child processes and needs no KVM.
- **build-and-test-macos**: build, test and ad-hoc sign with the entitlement on
  `macos-15`, which is where the in-kernel GICv3 API (`hv_gic_*`) exists, then
  `hvi sandbox-selftest`, asserting its success line so an Intel runner image
  cannot turn the step into a no-op.
- **boot-x86**: a live boot of a real Linux kernel to the userspace/VFS gate
  with `--cpus 2`, so SMP AP bringup is asserted too, on a self-hosted x86
  runner with real `/dev/kvm` (label `kvm`). The job skips itself with a
  warning if the runner has no KVM.
- **boot-arm64-hvf**: `hvi smoke`, `hvi smoke --shm` (which spawns
  `smoke-shm-verify` in a child process and fails when that child fails), and a
  live boot on a self-hosted Apple-silicon runner, under an alarm wrapper
  because macOS ships no `timeout`.
- **boot-arm64-kvm**: a matrix over two self-hosted arm64 hosts, vGICv2
  (`nbfc`) and vGICv3 (`gicv3`). Each runs the aarch64 seccomp selftest, a live
  boot, a boot on a real tap when the runner can create one (skipped with a
  warning otherwise), and a check that an unusable tap refuses to boot and names
  the interface in the error.
- **perf-virtiofs**: `tools/perf-gate.sh` on the Apple-silicon runner, for
  same-repo pull requests only. It builds the branch and its merge base on the
  same machine in the same run, requires the metadata workload's host-operation
  count to be equal, and fails when the branch is more than 1.5x slower.

The three boot jobs and the perf gate run on persistent machines the project
owns, so they are withheld from pull requests opened from a fork; a fork still
gets every hosted job. The arm64 boots need self-hosted runners because no
GitHub-hosted arm64 runner exposes `/dev/kvm` and a live macOS boot needs the
hypervisor entitlement plus an interactive host (AMFI). The x86 boot moved to a
self-hosted runner because the hosted image's kernel package fetch wedged
repeatedly; a persistent runner installs it once.

Every job carries a `timeout-minutes` cap, so a wedged job cannot hold a
self-hosted runner for the six-hour default. The boot jobs upload their logs
and the event ledger as artifacts when they fail.

One known gap: the unit tests of the arm64-Linux modules run nowhere. `cargo
test` runs on x86 Linux and on macOS only, and the arm64/KVM jobs build and
boot without a test step. Those modules are cross-linted, not unit-tested.
This waits on a decision about the runner pool.

Three scheduled workflows run outside the two entry points. Each reports
through a tracking issue and leaves `main` green: a failure files or updates
one issue, and the next green run closes it. They are the only workflows
granted `issues: write`.

- `audit-deps.yml`: `cargo deny check` against the lockfile on `main` every
  Monday, for advisories that arrive between changes. Nothing about a new
  advisory is fixed by reverting, so a red `main` would be noise.
- `stress-weekly.yml`: the `#[ignore]`d used-ring litmus test on a self-hosted
  arm64 runner every Monday. It demonstrates the ordering defect and the fence
  that removes it; it is not reliable enough to gate a pull request.
- `schedule-reflow-drift.yml`: monthly, runs the comment reflow on the latest
  nightly and compares it with the pinned one in `pins.env`, so the pin is
  advanced deliberately when the two disagree.

External actions are pinned to commit SHAs, with the version in a comment.
Renovate keeps those pins, the Cargo dependencies and the commitlint tooling
updated (`.github/renovate.json`). The cargo-deny pin is an action input, not
a `uses:` ref, so a custom manager in that file covers it.

## AI policy

AI-assisted development is welcome in hvi-vmm. See [AI_POLICY.md](AI_POLICY.md).

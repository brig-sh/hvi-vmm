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
local run means a green `validate-code`. The reflow needs a nightly rustfmt
(`wrap_comments` is nightly-only); without one the script says so and skips that
pass, and CI catches what you missed.

`tools/gates.sh` runs the CI checks a developer machine can run, in one
command: `tidy.sh --check`, the aarch64 cross-lint, `cargo test`, `cargo deny
check`, the workflow lint and the spell check. The last four need tools
outside the pinned toolchain, so each is skipped when its tool is missing and
every skip is named in the closing line -- the script never reports a bare
`ok` when something did not run. The live boots, the other host's backend and
the commit-message lint stay CI's job.

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
merged. Rebase on `main` rather than merging `main` into your branch, so the
eventual history is linear and the PR diff is honest.

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
feature`), and the body wraps at **72** columns rather than 80. The linter in
`.github/linters/` is the authority for this repository either way.

Spelling is checked over the tree and over the commit messages a pull request
adds, sharing one dictionary in `.github/linters/typos.toml`. When it flags a
domain term (a register name, an acronym), add the word there rather than
rewording the comment.

## Pull requests

Open as a draft while the work is in progress, and mark it ready only when CI
is green and the commits are in their final shape. Fill in the template: what
the change does, why, and how it was tested. Keep one logical change per pull
request -- a drive-by fix in an unrelated file slows the review and complicates
the revert.

If an LLM or AI assistant helped, say so in the description. The author is
accountable for every line regardless of how it was produced, so review it as
if you had typed it.

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

- **test-portable**: `cargo test` on x86 Linux.
- **build-and-test-macos**: build, test and ad-hoc sign with the entitlement on
  `macos-15`, which is where the in-kernel GICv3 API (`hv_gic_*`) exists.
- **boot-x86**: a live boot of a real Linux kernel to the userspace/VFS gate
  with `--cpus 2`, so SMP AP bringup is asserted too.
- **boot-arm64-hvf** / **boot-arm64-kvm**: the same for the two arm64
  backends, on self-hosted runners. The hvf job also runs `hvi smoke` and
  `hvi smoke --shm`; the `--shm` run spawns `smoke-shm-verify` in a child
  process and fails when that child fails.

The arm64 boots need self-hosted runners: GitHub-hosted arm64 runners expose no
`/dev/kvm`, and a live macOS boot needs the hypervisor entitlement plus an
interactive host (AMFI). Where no such runner is available the backends are
still compile- and lint-checked. The x86 live jobs skip themselves with a
warning if a runner turns up without `/dev/kvm`.

Every job carries a `timeout-minutes` cap, so a wedged job cannot hold a
self-hosted runner for the six-hour default. The boot jobs upload their logs
and the event ledger as artifacts when they fail.

One known gap: the unit tests of the arm64-Linux modules run nowhere. `cargo
test` runs on x86 Linux and on macOS only, and the arm64/KVM jobs build and
boot without a test step. Those modules are cross-linted, not unit-tested.
This waits on a decision about the runner pool.

`audit-deps.yml` is a third entry workflow, called by neither of the two
above. It runs `cargo deny check` against the lockfile on `main` every
Monday, for advisories that arrive between changes. It is advisory rather
than blocking: a failure files a tracking issue labelled `dependency-audit`,
or comments on the open one, and the next green run closes it. Nothing about
a new advisory is fixed by reverting, so a red `main` would be noise. This is
the only workflow granted `issues: write`, and the only scheduled one.

External actions are pinned to commit SHAs, with the version in a comment.
Renovate keeps those pins, the Cargo dependencies and the commitlint tooling
updated (`.github/renovate.json`). The cargo-deny pin is an action input
rather than a `uses:` ref, so a custom manager in that file covers it.

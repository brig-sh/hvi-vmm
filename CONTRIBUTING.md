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
skip it probes for is named in the closing line. One skip is not counted
there: `tidy.sh` drops the comment-reflow pass when the pinned nightly is
missing, says so on stderr, and `gates.sh` still prints `ok`. Install that
nightly, or CI finds what you missed. `--with-perf` adds the virtio-fs performance
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
same compiler. `rust-version` in `Cargo.toml` (1.77) is a different thing: the
MSRV floor, a compatibility claim rather than the build pin. No CI job builds
at that floor, so nothing enforces it. Treat a change that raises it as
something a reviewer has to notice.

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

[docs/testing.md](docs/testing.md) is the full account: which jobs run on
which runners, what each boot job asserts, the toolchain versions, and the
performance gate. What matters when you open a pull request:

A pull request runs `.github/workflows/pr-build-and-verify.yml` and a push to
`main` runs `main-build-and-verify.yml`. Both are thin entry workflows calling
the same reusable ones.

- **validate-commits** (pull requests only, since a rebase-and-merge lands the
  commits on `main` verbatim): the commit conventions above, per commit and
  reported by short SHA, plus a spell check over the tree and over the
  messages the pull request adds.
- **validate-code**: `tools/tidy.sh --check` on x86 Linux, which owns
  formatting for the whole tree because rustfmt does not evaluate `cfg` and so
  reaches modules that runner cannot build. Then clippy and rustdoc for the
  arm64/KVM backend cross-checked from the same runner and for the hvf backend
  on `macos-15`, actionlint with shellcheck over the workflows, and
  `cargo deny check` over the lockfile.
- **build-and-test**: the unit suite on x86 Linux and on `macos-15`, the two
  confinement selftests, and then the live boots on the self-hosted runners.

`tools/gates.sh` runs everything in that list a developer machine can run.
Three checks cannot run anywhere but CI: the other host's backend, the live
boots, and the commit-message lint, which needs a pull request's commit range.

The self-hosted lanes, which are the three live boots and the performance
gate, are withheld from pull requests opened from a fork, because they run on
persistent machines the project owns rather than ephemeral VMs. A fork still
gets every hosted job.

Every job carries a `timeout-minutes` cap. The boot jobs upload their logs as
artifacts when they fail, and the two arm64 boots also upload the event
ledger.

One known gap: the arm64/KVM backend has no unit tests. `src/machine_linux.rs`
carries no test module, and no job runs a suite on arm64 Linux, so closing the
gap needs tests and a runner for them. This waits on a decision about the
runner pool.

Three scheduled workflows run outside the two entry points, each reporting
through a tracking issue so `main` stays green: the weekly dependency audit,
the weekly used-ring litmus on arm64, and a monthly check that the pinned
reflow nightly still agrees with the latest one.

External actions are pinned to commit SHAs, with the version in a comment.
Renovate keeps those pins, the Cargo dependencies and the commitlint tooling
updated (`.github/renovate.json`).

## AI policy

AI-assisted development is welcome in hvi-vmm. See [AI_POLICY.md](AI_POLICY.md).

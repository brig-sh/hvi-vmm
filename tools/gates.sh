#!/usr/bin/env bash
# The local gate: run the CI checks that a developer machine can run, in one
# command, so a push is not the first place a lint failure shows up.
#
# What it runs, and what CI job each stands in for:
#
#   tools/tidy.sh --check                    validate-code / tidy-portable
#                                            (or tidy-macos-hvf on a mac:
#                                            only the host backend compiles)
#   tools/tidy.sh --check --lint-only \
#     --target aarch64-unknown-linux-gnu     validate-code / tidy-linux-aarch64
#   cargo test                               build-and-test / test-portable
#                                            (or build-and-test-macos)
#   cargo deny check                         validate-code / check-deps
#   actionlint -shellcheck=shellcheck        validate-code / lint-workflows
#   typos --config .github/linters/typos.toml
#                                            validate-commits / check-spelling
#
# The last four need tools that are not part of the pinned Rust toolchain.
# Each is skipped when absent, and every skip is named in the closing line:
# a run that skipped something never reports a bare "ok", because a skipped
# check read as a passed one is the failure this script exists to prevent.
#
# What it cannot cover at all, on any machine: the other host's backend (only
# the host target compiles), the live boots (they need /dev/kvm or the
# hypervisor entitlement plus self-hosted runners), and the commit-message
# lint, which reads the pull request's commit range.
set -euo pipefail
cd "$(dirname "$0")/.."

skipped=()

# Lint for the host backend: fmt, comment reflow, clippy, rustdoc.
tools/tidy.sh --check

# The arm64-Linux backend, cross-checked. Needs the target installed; CI
# always has it, a developer machine may not.
if rustup target list --installed 2>/dev/null | grep -qx aarch64-unknown-linux-gnu; then
    tools/tidy.sh --check --lint-only --target aarch64-unknown-linux-gnu
else
    skipped+=("aarch64-linux cross-lint (rustup target add aarch64-unknown-linux-gnu)")
fi

# The unit suite for this host's backend plus the portable core.
cargo test

# The dependency audit, the same command check-deps runs. Without deny.toml
# cargo-deny falls back to its own defaults, which is a different check with
# different answers, so treat a missing config as "not run" rather than
# reporting a result the CI job would never produce.
if ! command -v cargo-deny >/dev/null 2>&1; then
    skipped+=("dependency audit (cargo install cargo-deny --locked)")
elif [ ! -f deny.toml ]; then
    skipped+=("dependency audit (no deny.toml in this tree)")
else
    cargo deny check
fi

# The workflows themselves. CI pins and sha256-verifies both binaries; here
# whatever is on PATH is close enough to catch a mistake before pushing.
if command -v actionlint >/dev/null 2>&1 && command -v shellcheck >/dev/null 2>&1; then
    actionlint -shellcheck=shellcheck
else
    skipped+=("workflow lint (needs actionlint and shellcheck on PATH)")
fi

# Spelling, over the tree. CI also checks the commit messages a pull request
# adds, which needs the pull request's range and so cannot run here.
if command -v typos >/dev/null 2>&1; then
    typos --config .github/linters/typos.toml
else
    skipped+=("spell check (cargo install typos-cli)")
fi

if [ ${#skipped[@]} -eq 0 ]; then
    echo "gates: ok"
else
    echo "gates: ok, but ${#skipped[@]} check(s) DID NOT RUN:"
    for item in "${skipped[@]}"; do
        echo "  - $item"
    done
    echo "gates: CI still runs all of them."
fi

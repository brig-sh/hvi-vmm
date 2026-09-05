#!/usr/bin/env bash
# Runs the CI checks that a developer machine can run, in one command, so a
# push is not the first place that a failure appears.
#
# Each check below, and the CI job it stands for:
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
# The last four need tools that the pinned Rust toolchain does not supply.
# The script skips a check when its tool is absent, and names every skip in
# the closing line. A run with a skip never reports a plain "ok", because a
# reader must not take a skipped check for one that passed.
#
# Three CI checks cannot run here on any machine: the backend of the other
# host, because only the host target compiles; the live boots, which need
# /dev/kvm or the hypervisor entitlement on a self-hosted runner; and the
# commit-message lint, which reads the commit range of a pull request.
set -euo pipefail
cd "$(dirname "$0")/.."

skipped=()

# Lint for the host backend: format, comment reflow, clippy and rustdoc.
tools/tidy.sh --check

# The arm64-Linux backend, cross-checked. This needs the target installed.
# CI always has it, and a developer machine can lack it.
if rustup target list --installed 2>/dev/null | grep -qx aarch64-unknown-linux-gnu; then
    tools/tidy.sh --check --lint-only --target aarch64-unknown-linux-gnu
else
    skipped+=("aarch64-linux cross-lint (rustup target add aarch64-unknown-linux-gnu)")
fi

# The unit suite for this host's backend plus the portable core.
cargo test

# The dependency audit, the command that check-deps runs. Without deny.toml,
# cargo-deny uses its own defaults and answers a different question, so
# report an absent configuration as a skip. A result that the CI job would
# never produce is worse than no result.
if ! command -v cargo-deny >/dev/null 2>&1; then
    skipped+=("dependency audit (cargo install cargo-deny --locked)")
elif [ ! -f deny.toml ]; then
    skipped+=("dependency audit (no deny.toml in this tree)")
else
    cargo deny check
fi

# The workflows themselves. CI pins both binaries and verifies their sha256.
# Here, the versions on PATH are near enough to find a mistake before a push.
if command -v actionlint >/dev/null 2>&1 && command -v shellcheck >/dev/null 2>&1; then
    actionlint -shellcheck=shellcheck
else
    skipped+=("workflow lint (needs actionlint and shellcheck on PATH)")
fi

# Spelling, over the tree. CI also checks the commit messages that a pull
# request adds. That needs the commit range, so it cannot run here.
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

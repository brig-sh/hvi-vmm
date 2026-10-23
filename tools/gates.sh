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
#   tools/tidy.sh --check --lint-only \
#     --target x86_64-unknown-linux-musl     validate-code / tidy-linux-musl
#   tools/tidy.sh --check --lint-only \
#     --target aarch64-unknown-linux-musl    validate-code / tidy-linux-musl-arm64
#   cargo test --workspace                   build-and-test / test-portable
#                                            (or build-and-test-macos)
#   cargo test --locked --manifest-path e2e/Cargo.toml --lib
#                                            build-and-test / test-portable
#   cargo deny check (root and e2e/)         validate-code / check-deps
#   actionlint -shellcheck=shellcheck        validate-code / lint-workflows
#     and then shellcheck e2e/tools/*.sh e2e/guest/init
#   typos --config .github/linters/typos.toml
#                                            validate-commits / check-spelling
#
# tidy.sh and the two cargo test runs always run. The rest need something the
# pinned Rust toolchain does not supply: the rustup target for each cross-lint
# (aarch64 glibc, x86-64 musl and aarch64 musl), and the binaries for
# cargo-deny, actionlint plus shellcheck, and typos. The script skips a check
# when its tool is absent, and names every skip in the closing line. A run with
# a skip never reports a plain "ok", because a reader must not take a skipped
# check for one that passed.
#
# The virtio-fs performance gate (build-and-test / perf-virtiofs) is not in
# that list because it builds the merge base as well as the branch, so it
# costs more than everything above put together. Pass --with-perf to include
# it; it is macOS-only, since that is where the device compiles.
#
# The e2e suite (test-e2e / test) boots real guests, so it needs /dev/kvm or
# Hypervisor.framework, and cargo-nextest. Its setup builds the guest agent, and
# on Linux hvi as well, for the musl rustup target of the host's architecture,
# such as x86_64-unknown-linux-musl. On Linux it also needs virtiofsd and the
# tap that e2e/tools/provision.sh creates; e2e/README.md says how to set these
# up. --with-e2e includes it.
#
# Two of the suite's checks are not here. e2e/tools/check-filters.sh checks the
# names in the filters against every backend's tests, which only CI has. The
# probation check compares a change with the commit it is based on, so run
# e2e/tools/check-probation.sh <base> for it.
#
# Three CI checks cannot run here on any machine: the backend of the other
# host, because only the host target compiles; the live boots, which need
# /dev/kvm or the hypervisor entitlement on a self-hosted runner; and the
# commit-message lint, which reads the commit range of a pull request.
set -euo pipefail
cd "$(dirname "$0")/.."

with_perf=no
with_e2e=no
while [ $# -gt 0 ]; do
    case "$1" in
        --with-perf) with_perf=yes; shift ;;
        --with-e2e) with_e2e=yes; shift ;;
        *) echo "usage: $0 [--with-perf] [--with-e2e]" >&2; exit 2 ;;
    esac
done

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

# The x86-64/KVM backend against musl, the libc the published static binary
# links. Lint only, like the cross-check above, so no musl linker is needed.
if rustup target list --installed 2>/dev/null | grep -qx x86_64-unknown-linux-musl; then
    tools/tidy.sh --check --lint-only --target x86_64-unknown-linux-musl
else
    skipped+=("x86_64-musl lint (rustup target add x86_64-unknown-linux-musl)")
fi

# The arm64/KVM backend against musl. The `libc` crate declares a different
# set of functions for musl than for glibc, so this lint can fail where the
# aarch64 glibc one above passes.
if rustup target list --installed 2>/dev/null | grep -qx aarch64-unknown-linux-musl; then
    tools/tidy.sh --check --lint-only --target aarch64-unknown-linux-musl
else
    skipped+=("aarch64-musl lint (rustup target add aarch64-unknown-linux-musl)")
fi

# The unit suite for this host's backend plus the portable core, the
# build-version crate beside them, and the e2e workspace's unit tests, which
# need no hypervisor.
cargo test --workspace
cargo test --locked --manifest-path e2e/Cargo.toml --lib

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
    cargo deny --locked --manifest-path e2e/Cargo.toml --workspace --config deny.toml check
fi

# The workflows themselves. CI pins both binaries and verifies their sha256.
# Here, the versions on PATH are near enough to find a mistake before a push.
if command -v actionlint >/dev/null 2>&1 && command -v shellcheck >/dev/null 2>&1; then
    actionlint -shellcheck=shellcheck
    shellcheck e2e/tools/*.sh e2e/guest/init
else
    skipped+=("workflow and script lint (needs actionlint and shellcheck on PATH)")
fi

# Spelling, over the tree. CI also checks the commit messages that a pull
# request adds. That needs the commit range, so it cannot run here.
if command -v typos >/dev/null 2>&1; then
    typos --config .github/linters/typos.toml
else
    skipped+=("spell check (cargo install typos-cli)")
fi

# The performance gate, opt-in: see the note at the top.
if [ "$with_perf" = yes ]; then
    tools/perf-gate.sh
else
    skipped+=("virtio-fs performance gate (tools/gates.sh --with-perf)")
fi

# The e2e suite, opt-in: see the note at the top.
if [ "$with_e2e" = yes ]; then
    cargo nextest run --locked --manifest-path e2e/Cargo.toml
else
    skipped+=("e2e suite (tools/gates.sh --with-e2e)")
fi

if [ ${#skipped[@]} -eq 0 ]; then
    echo "gates: ok"
else
    echo "gates: ok, but ${#skipped[@]} check(s) DID NOT RUN:"
    for item in "${skipped[@]}"; do
        echo "  - $item"
    done
    echo "gates: CI still runs all of them, but a pull request from a fork skips the self-hosted ones."
fi

#!/usr/bin/env bash
#
# Format, reflow, lint and doc-check the tree. Run it before you push; CI runs
# the same steps with --check (validate-code.yml).
#
# Default (fix) mode rewrites formatting and comment width in place. --check is
# the read-only variant: it verifies and fails instead of writing.
#
# Only the backend for the host target is compiled: the macOS/hvf backend on
# Apple silicon, the x86-64/KVM backend on an x86 Linux box. Pass
# --target <triple> to lint another backend without a runner for it, e.g.
#
#   tools/tidy.sh --check --target aarch64-unknown-linux-gnu
#
# Written for the bash 3.2 that ships with macOS.

set -euo pipefail

CHECK=0
LINT_ONLY=0
TARGET=""

usage() {
  echo "usage: tools/tidy.sh [--check] [--lint-only] [--target <triple>]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1; shift ;;
    --lint-only) LINT_ONLY=1; shift ;;
    --target) [ $# -ge 2 ] || usage; TARGET="$2"; shift 2 ;;
    --target=*) TARGET="${1#--target=}"; shift ;;
    -h|--help) usage ;;
    *) echo "tidy: unknown argument: $1" >&2; usage ;;
  esac
done

cd "$(dirname "$0")/.."

# Echo each command before running it, so a failure is reproducible by hand.
run() {
  echo "+ $*"
  "$@"
}

# rustfmt's comment reflow (wrap_comments) is nightly-only, so the reflow pass
# is a second `cargo +nightly fmt` over the tree the stable pass just formatted.
# It is skipped, loudly, when no nightly is installed: a missing nightly should
# not block a local tidy, but CI installs one so the check is never skipped
# there.
have_nightly() {
  rustup toolchain list 2>/dev/null | grep -q '^nightly'
}

TARGET_ARGS=""
if [ -n "$TARGET" ]; then
  TARGET_ARGS="--target $TARGET"
fi

# Formatting is target-independent, so the per-target lint jobs in CI pass
# --lint-only and let the host job own the one fmt pass over the tree.
if [ "$LINT_ONLY" = 1 ]; then
  echo "tidy: --lint-only, skipping fmt and reflow"
elif [ "$CHECK" = 1 ]; then
  run cargo fmt --all -- --check
  if have_nightly; then
    run cargo +nightly fmt --all -- \
      --config wrap_comments=true,comment_width=80 --check
  else
    echo "tidy: no nightly toolchain, skipping the comment-reflow check" >&2
  fi
else
  run cargo fmt --all
  if have_nightly; then
    run cargo +nightly fmt --all -- \
      --config wrap_comments=true,comment_width=80
  else
    echo "tidy: no nightly toolchain, skipping the comment reflow" >&2
  fi
fi

# clippy and doc are report-only in both modes: neither writes to the tree, and
# both are hard errors on any warning.
# shellcheck disable=SC2086 # TARGET_ARGS is a deliberate word split
run cargo clippy --all-targets $TARGET_ARGS -- -D warnings

# Private items are documented too, because the doc comments on them are held to
# the same standard as the public ones; --no-deps keeps the check to this repo.
echo "+ RUSTDOCFLAGS=-D warnings cargo doc --no-deps --document-private-items $TARGET_ARGS"
# shellcheck disable=SC2086
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items $TARGET_ARGS

echo "tidy: ok"

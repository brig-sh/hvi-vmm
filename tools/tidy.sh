#!/usr/bin/env bash
#
# Check rust-version against the toolchain pin, then format, reflow, lint and
# doc-check the tree. Run it before you push; CI runs the same steps with
# --check (validate-code.yml).
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
# Without --target it also tidies the e2e suite in e2e/, a workspace of its own.
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

# The pinned nightly for the comment-reflow check lives in pins.env.
# shellcheck disable=SC1091 # pins.env is a committed sibling, sourced at runtime
. ./pins.env

# Echo each command before running it, so a failure is reproducible by hand.
run() {
  echo "+ $*"
  "$@"
}

# rustfmt's comment reflow (wrap_comments) is nightly-only, so the reflow pass
# is a second `cargo fmt` on the pinned nightly (pins.env) over the tree the
# stable pass just formatted. It is skipped, loudly, when that nightly is not
# installed: a missing nightly should not block a local tidy, but CI installs
# it so the check is never skipped there.
have_nightly() {
  rustup toolchain list 2>/dev/null | grep -q "^$RUSTFMT_NIGHTLY"
}

# Prints the value of key $2 in file $1, from a line of the form key = "value".
pinned() {
  sed -n "s/^$2 = \"\\([^\"]*\\)\".*/\\1/p" "$1"
}

# rust-version names the release rust-toolchain.toml pins, in the crate's
# manifest and in the e2e suite's; see Cargo.toml.
CHANNEL=$(pinned rust-toolchain.toml channel)
if [ -z "$CHANNEL" ]; then
  echo "tidy: cannot read channel from rust-toolchain.toml" >&2
  exit 1
fi
for manifest in Cargo.toml e2e/Cargo.toml; do
  version=$(pinned "$manifest" rust-version)
  if [ -z "$version" ]; then
    echo "tidy: cannot read rust-version from $manifest" >&2
    exit 1
  fi
  if [ "$version" != "$CHANNEL" ]; then
    echo "tidy: $manifest sets rust-version $version but rust-toolchain.toml pins $CHANNEL; set both to the same release" >&2
    exit 1
  fi
done

TARGET_ARGS=""
if [ -n "$TARGET" ]; then
  TARGET_ARGS="--target $TARGET"
fi

# Formats, reflows, lints and doc-checks the workspace whose manifest is $1. The
# remaining arguments go to clippy and rustdoc.
tidy_workspace() {
  manifest=$1
  shift
  # Formatting is target-independent, so the per-target lint jobs in CI pass
  # --lint-only and let the host job own the one fmt pass over the tree.
  if [ "$LINT_ONLY" = 1 ]; then
    echo "tidy: --lint-only, skipping fmt and reflow for $manifest"
  elif [ "$CHECK" = 1 ]; then
    run cargo fmt --manifest-path "$manifest" --all -- --check
    if have_nightly; then
      run cargo "+$RUSTFMT_NIGHTLY" fmt --manifest-path "$manifest" --all -- \
        --config wrap_comments=true,comment_width=80 --check
    else
      echo "tidy: $RUSTFMT_NIGHTLY not installed, skipping the comment-reflow check" >&2
    fi
  else
    run cargo fmt --manifest-path "$manifest" --all
    if have_nightly; then
      run cargo "+$RUSTFMT_NIGHTLY" fmt --manifest-path "$manifest" --all -- \
        --config wrap_comments=true,comment_width=80
    else
      echo "tidy: $RUSTFMT_NIGHTLY not installed, skipping the comment reflow" >&2
    fi
  fi

  # clippy and doc are report-only in both modes: neither writes to the tree,
  # and both are hard errors on any warning.
  run cargo clippy --manifest-path "$manifest" --all-targets "$@" -- -D warnings

  # Private items are documented too, because the doc comments on them are held
  # to the same standard as the public ones; --no-deps keeps the check to this
  # repo.
  echo "+ RUSTDOCFLAGS=-D warnings cargo doc --manifest-path $manifest --no-deps --document-private-items $*"
  RUSTDOCFLAGS="-D warnings" cargo doc --manifest-path "$manifest" --no-deps \
    --document-private-items "$@"
}

# --workspace, so the build-script helper beside the VMM is held to the same
# lints.
# shellcheck disable=SC2086 # TARGET_ARGS is a deliberate word split
tidy_workspace Cargo.toml --workspace $TARGET_ARGS

# The e2e workspace runs on the host, so it is linted for the host only, not
# once per cross target. Its guest agent runs on the guest's musl target, so a
# run with a musl --target lints the agent for that target too.
if [ -z "$TARGET" ]; then
  tidy_workspace e2e/Cargo.toml --workspace
fi
case "$TARGET" in
  *-unknown-linux-musl)
    run cargo clippy --manifest-path e2e/Cargo.toml -p hvi-e2e-agent \
      --all-targets --target "$TARGET" -- -D warnings
    ;;
esac

echo "tidy: ok"

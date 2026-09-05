#!/usr/bin/env bash
# Build, ad-hoc code-sign with the hypervisor entitlement, and run hvi.
#
# Hypervisor.framework refuses to initialise without the
# com.apple.security.hypervisor entitlement, and AMFI refuses entitled binaries
# launched from a background/headless job — so this MUST be run interactively in
# a terminal on the Apple-silicon host, not from a CI or background context.
#
# Usage:  crates/hvi/run.sh [--release] [<subcommand and args...>]
#   e.g.  crates/hvi/run.sh boot --kernel <Image> --mem-mib 1024
set -euo pipefail

# Plain vars, not an array: macOS ships bash 3.2, where expanding an empty
# array under `set -u` is itself an "unbound variable" error.
PROFILE_DIR=debug
RELEASE=0
if [[ "${1:-}" == "--release" ]]; then
	PROFILE_DIR=release
	RELEASE=1
	shift
fi
# Everything left is forwarded to the binary (subcommand + its args).

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/target/$PROFILE_DIR/hvi"
ENTITLEMENTS="$REPO_ROOT/crates/hvi/hvi.entitlements"

if [[ "$RELEASE" == "1" ]]; then
	cargo build -p hvi --release
else
	cargo build -p hvi
fi

# Ad-hoc signature ("-") is enough for a locally-run entitled binary.
codesign --sign - --entitlements "$ENTITLEMENTS" --force --options runtime "$BIN"

# "$@" is safe under `set -u` even when empty (unlike an empty array). With no
# args the binary runs the default M0 smoke test.
echo "running $BIN $*"
exec "$BIN" "$@"

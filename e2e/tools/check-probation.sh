#!/usr/bin/env bash
# Checks that every e2e test a change adds is on the probation list or the
# nightly list in e2e/.config/nextest.toml, and that every test it takes off the
# nightly list goes on probation, so a test passes nightly before it can fail
# someone else's change.
#
#   e2e/tools/check-probation.sh <base-commit>
#
# It lists the tests at the base commit, in a worktree of its own, and at HEAD.
# A base without the suite has nothing to compare against and passes.
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <base-commit>" >&2; exit 2; }
base=$1
e2e=$(cd "$(dirname "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-$e2e/target}

# Prints "binary-id test-name" for each test in the suite at $1, built in the
# target directory $2, then sorts it. Further arguments go to cargo nextest
# list. The workspace's unit tests boot no guest and need no probation, so only
# the suite's test binaries are listed.
list() {
  dir=$1
  target_dir=$2
  shift 2
  (cd "$dir" && CARGO_TARGET_DIR=$target_dir cargo nextest list \
    --message-format oneline --color never -E 'kind(test)' "$@") | sort
}

# Tests live in e2e/, so a change outside it adds none.
if git -C "$e2e" diff --quiet "$base" HEAD -- .; then
  echo "check-probation: the change does not touch e2e/"
  exit 0
fi

base_tree=$(mktemp -d)
trap 'git -C "$e2e" worktree remove --force "$base_tree" >/dev/null 2>&1 || true' EXIT
git -C "$e2e" worktree add --detach --quiet "$base_tree" "$base"
if [ ! -d "$base_tree/e2e" ]; then
  echo "check-probation: the base has no e2e suite"
  exit 0
fi

# The base builds in a target directory of its own. Cargo names the artifacts of
# a path package the same in both trees, so a shared one would let a build of
# the base pass as up to date for HEAD.
#
# Both lists leave the ignored tests out, since a test that pins a bug runs only
# in the pinned profile. A test whose ignore is removed therefore counts as new
# and goes on probation too.
#
# A new test that the default profile runs is on neither the probation list nor
# the nightly list, since the profile leaves out both.
before=$(list "$base_tree/e2e" "$target/check-probation" --ignore-default-filter)
after=$(list "$e2e" "$target" --ignore-default-filter)
by_default=$(list "$e2e" "$target" --profile default)
added=$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after"))
missing=$(comm -12 <(printf '%s\n' "$added") <(printf '%s\n' "$by_default"))

# A test that leaves the base's nightly list and runs in the default profile
# skipped probation.
was_nightly=$("$e2e/tools/probation-filter.sh" --names --nightly \
  "$base_tree/e2e/.config/nextest.toml")
skipped=$(awk 'NR == FNR { nightly[$0] = 1; next } $2 in nightly' \
  <(printf '%s\n' "$was_nightly") <(printf '%s\n' "$by_default"))

failed=0
if [ -n "$missing" ]; then
  echo "check-probation: these new tests are on neither the probation list nor the nightly list in e2e/.config/nextest.toml:" >&2
  printf '%s\n' "$missing" | sed 's/^/  /' >&2
  echo "check-probation: the check goes by name, so a renamed or moved test counts as new, as does one whose ignore was removed" >&2
  failed=1
fi
if [ -n "$skipped" ]; then
  echo "check-probation: these tests left the nightly list but are not on the probation list in e2e/.config/nextest.toml:" >&2
  printf '%s\n' "$skipped" | sed 's/^/  /' >&2
  failed=1
fi
[ "$failed" = 0 ] || exit 1
echo "check-probation: every new test is on the probation or nightly list, and every test that left the nightly list is on probation"

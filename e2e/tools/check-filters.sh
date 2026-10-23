#!/usr/bin/env bash
# Checks that every exact test name in the e2e nextest filters names a test that
# exists.
#
# nextest ignores an exact name that matches no test and reports nothing. A test
# on the probation list that is then renamed would drop off the list unnoticed
# and start running on pull requests, and a renamed test that an override names
# would lose the override.
#
#   e2e/tools/check-filters.sh [list...]
#
# With no arguments it checks against this host's tests. Some tests build on one
# backend only, so it can instead check against the union of lists. Each list is
# the oneline output of cargo nextest list on one backend.
set -euo pipefail

# The lists are read before the change of directory, so their paths may be
# relative to where the script was run.
listed=""
if [ $# -gt 0 ]; then
  listed=$(cat "$@" | awk '{ print $2 }' | sort -u)
fi
cd "$(dirname "$0")/.."

names=$(grep -v '^[[:space:]]*#' .config/nextest.toml \
  | { grep -o 'test(=[^)]*)' || true; } | sed 's/^test(=//; s/)$//' | sort -u)
if [ -z "$names" ]; then
  echo "check-filters: the filters name no test exactly"
  exit 0
fi

if [ $# -eq 0 ]; then
  listed=$(cargo nextest list --ignore-default-filter --run-ignored all \
    --message-format oneline --color never | awk '{ print $2 }')
fi
missing=0
for name in $names; do
  if ! grep -qxF "$name" <<<"$listed"; then
    echo "check-filters: no test is named $name" >&2
    missing=1
  fi
done
exit $missing

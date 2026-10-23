#!/usr/bin/env bash
# Prints one of the two lists the default profile's filter in
# e2e/.config/nextest.toml leaves out: the probation list, or with --nightly the
# nightly list. It prints the nextest filter that selects the tests on the list,
# or with --names their names, one per line. An empty list prints none(), or
# nothing with --names.
#
#   e2e/tools/probation-filter.sh [--names] [--nightly] [config | -]
#
# A config of - is read from standard input. Every entry must name a test
# exactly, as test(=name), so the tools that read the lists agree on them.
set -euo pipefail

names=no
list=probation
while [ $# -gt 0 ]; do
  case $1 in
    --names) names=yes ;;
    --nightly) list=nightly ;;
    *) break ;;
  esac
  shift
done
config=${1:-"$(dirname "$0")/../.config/nextest.toml"}
[ "$config" = - ] && config=/dev/stdin

case $list in
  probation) part='not (\(.*\)) and not (.*)' ;;
  nightly) part='not (.*) and not (\(.*\))' ;;
esac
filter=$(sed -n "s/^default-filter = \"$part\"\$/\\1/p" "$config" | head -n 1)
entry='test\(=[^()|]*\)'
if [ -z "$filter" ]; then
  echo "probation-filter: the default profile's filter does not read" \
    "\"not (<probation list>) and not (<nightly list>)\"" >&2
  exit 1
fi
if [ "$filter" != "none()" ] &&
  ! grep -qxE "$entry( \| $entry)*" <<<"$filter"; then
  echo "probation-filter: the $list list \"$filter\" is not" \
    "\"test(=name) | ...\" or \"none()\"" >&2
  exit 1
fi

if [ "$names" = no ]; then
  echo "$filter"
elif [ "$filter" != "none()" ]; then
  grep -oE "$entry" <<<"$filter" | sed 's/^test(=//; s/)$//'
fi

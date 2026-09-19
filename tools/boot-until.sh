#!/usr/bin/env bash
# Runs a guest and stops it once its console has printed what the caller is
# waiting for.
#
# A plain timeout only ends a boot when the guest ends it. The Linux guest in
# CI powers itself off, so its timeout is a cap it never reaches. The Unikraft
# guests are servers with no poweroff path. Their timeout is the whole runtime
# of the step, and the lines the step asserts on arrive long before it fires.
#
# The seconds argument is that cap. It bounds a guest that never prints the
# patterns, and a boot that does print them no longer waits for it.
#
# --settle holds the guest for that many seconds after the last pattern
# matches. It is for a step that asserts a message never appeared. Stopping on
# the first match would cut the window that message had to arrive in, and the
# step would pass without having looked.
#
# Exits 0 whether the patterns matched or not. The caller greps the log, so
# the assertion and the error it prints stay in one place.
#
# usage: boot-until.sh <log> <seconds> [--settle <seconds>] <pattern>... \
#          -- <command>...
set -euo pipefail

usage() {
  echo "usage: $0 <log> <seconds> [--settle <n>] <pattern>... -- <cmd>..." >&2
  exit 2
}

[ $# -ge 4 ] || usage
log=$1
shift
deadline=$1
shift

settle=0
if [ "${1:-}" = "--settle" ]; then
  [ $# -ge 2 ] || usage
  settle=$2
  shift 2
fi

patterns=()
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
  patterns[${#patterns[@]}]=$1
  shift
done
[ "${1:-}" = "--" ] || usage
shift
[ $# -ge 1 ] || usage
[ ${#patterns[@]} -ge 1 ] || usage

: >"$log"
"$@" </dev/null >"$log" 2>&1 &
vmm=$!
# bash writes "Terminated" to stderr for a background job it still tracks, and
# stopping the VMM is how this script ends. In a CI log that line reads as a
# failure of the step.
disown "$vmm" 2>/dev/null || true

# The VMM holds a VM, so it gets SIGTERM and a moment to release it first.
stop() {
  kill "$vmm" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! kill -0 "$vmm" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  kill -9 "$vmm" 2>/dev/null || true
}
trap stop EXIT

start=$(date +%s)
while :; do
  matched=1
  for p in ${patterns[@]+"${patterns[@]}"}; do
    grep -aq -- "$p" "$log" 2>/dev/null || {
      matched=0
      break
    }
  done
  if [ "$matched" -eq 1 ]; then
    echo "boot-until: matched after $(($(date +%s) - start))s, settling ${settle}s"
    sleep "$settle"
    exit 0
  fi
  # A guest that exited on its own will print nothing more.
  if ! kill -0 "$vmm" 2>/dev/null; then
    echo "boot-until: the guest exited before every pattern matched"
    exit 0
  fi
  if [ $(($(date +%s) - start)) -ge "$deadline" ]; then
    echo "boot-until: ${deadline}s deadline reached"
    exit 0
  fi
  sleep 0.2
done

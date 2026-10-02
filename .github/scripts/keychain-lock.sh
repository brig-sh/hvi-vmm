#!/bin/sh
# One signing job at a time on a shared Mac.
#
# The `notary` runners are a few physical Macs shared with hull's and brig's
# signing jobs. A signing job puts its own ephemeral keychain on the user
# keychain search list, then takes it back off when it is done. Two of them at
# once is errSecInternalComponent, or one job's cleanup dropping the other's
# keychain mid-sign.
#
# A GitHub concurrency group cannot carry this: it serializes one repository's
# runs, not the jobs of every repository on the Mac. This lock lives on the Mac
# instead. It is hull's scripts/keychain-lock.sh, and the two must take the
# same directory in the same way, or they stop excluding each other.
#
#   keychain-lock.sh acquire   before the keychain is created
#   keychain-lock.sh release   once the keychain is gone
#
# mkdir is the atomic step. A lock older than HULL_KEYCHAIN_LOCK_STALE seconds
# belongs to a job that died without its cleanup, and is taken over. The owner
# file is written once, so its age is how long the lock has been held, not
# whether its holder is alive. That is why every job that takes the lock sets
# timeout-minutes below STALE (75 against 90): a lock older than STALE cannot
# belong to a running job. WAIT is below that timeout, so a waiter reports
# who holds the lock before its own job is killed.
set -eu

LOCK="${HULL_KEYCHAIN_LOCK:-/Users/Shared/hull-keychain.lock}"
STALE="${HULL_KEYCHAIN_LOCK_STALE:-5400}"
WAIT="${HULL_KEYCHAIN_LOCK_WAIT:-3600}"
POLL="${HULL_KEYCHAIN_LOCK_POLL:-10}"
OWNER="${GITHUB_RUN_ID:-local}.${GITHUB_RUN_ATTEMPT:-0}.${GITHUB_JOB:-job}"

holder() { cat "$LOCK/owner" 2> /dev/null || echo "unknown"; }

# Seconds since a path last changed, or nothing when it is gone.
since() {
  m="$(stat -f %m "$1" 2> /dev/null)" || return 0
  echo $(( $(date +%s) - m ))
}

# The lock's age: from the owner file, or from the directory when the holder
# died before writing one. Nothing when no lock exists.
age() {
  since "$LOCK/owner" | grep . || since "$LOCK"
}

# Take over a stale lock. The takeover is itself a mkdir lock, and staleness is
# checked again under it, so two waiters that both saw the same stale lock
# cannot both remove it: the second finds the first's fresh lock instead. The
# takeover lock is held for a moment, so one older than a minute was left by a
# job killed inside this function and is cleared.
take_over() {
  t="$(since "$LOCK.takeover")"
  if [ -n "$t" ] && [ "$t" -gt 60 ]; then rmdir "$LOCK.takeover" 2> /dev/null || true; fi
  mkdir "$LOCK.takeover" 2> /dev/null || return 0
  a="$(age)"
  if [ -n "$a" ] && [ "$a" -gt "$STALE" ]; then
    echo "keychain-lock: taking over a lock held for ${a}s by $(holder)" >&2
    rm -rf "$LOCK"
  fi
  rmdir "$LOCK.takeover"
}

case "${1:-}" in
  acquire)
    waited=0
    until mkdir "$LOCK" 2> /dev/null; do
      a="$(age)"
      if [ -n "$a" ] && [ "$a" -gt "$STALE" ]; then
        take_over
        continue
      fi
      if [ "$waited" -ge "$WAIT" ]; then
        echo "keychain-lock: gave up after ${WAIT}s, held by $(holder)" >&2
        exit 1
      fi
      [ $(( waited % 60 )) -ne 0 ] \
        || echo "keychain-lock: waiting, held by $(holder)" >&2
      sleep "$POLL"
      waited=$(( waited + POLL ))
    done
    echo "$OWNER" > "$LOCK/owner"
    echo "keychain-lock: acquired by $OWNER" >&2
    ;;
  release)
    # Only this job's own lock. A lock taken over as stale belongs to someone
    # else by now, and removing it would let a third job in beside them.
    if [ "$(holder)" = "$OWNER" ]; then
      rm -rf "$LOCK"
      echo "keychain-lock: released by $OWNER" >&2
    fi
    ;;
  *)
    echo "usage: keychain-lock.sh acquire|release" >&2
    exit 2
    ;;
esac

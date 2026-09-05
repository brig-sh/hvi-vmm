#!/usr/bin/env bash
# Fails when a change makes the virtio-fs device measurably slower.
#
# The unit suite cannot see a change of this kind. Every test drives the FUSE
# handlers and asserts on what they return, so a handler that returns the same
# answer twice as slowly passes all of them. Two changes have already proved
# that: #30, where a containment check more than doubled the metadata path,
# and the one the fsbench README records, which made small writes 2.6x slower.
#
# This gate has two halves, and the first is the one that matters.
#
# Host operations are exact. The benchmark reports how many host calls the
# device spent per round, and that number does not move unless the code
# changed what it asks the kernel for. It is compared for equality. There is
# no tolerance because there is no noise.
#
# Time is noisy, so it is the backstop rather than the gate. Both sides are
# measured on this machine, in this run, so the comparison does not depend on
# what the runner is -- which is why the base is built here rather than read
# from a number stored in the repository, where it would be right for one
# class of hardware only.
#
# Sampling follows what the fsbench README tells a reader to do: take several
# samples and compare the fastest of each side. A minimum is the sample least
# contaminated by whatever else the machine was doing.
#
# The device compiles on macOS/Apple silicon only, so this runs there.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE="${PERF_GATE_BASE:-origin/main}"
SAMPLES="${PERF_GATE_SAMPLES:-5}"
# 1.5x catches a regression the size of #30, which was 2.4x, and clears the
# noise floor: the fsbench README puts that at 10 to 20 percent, and the
# metadata benchmark measured 4 percent across six runs on an idle Apple
# silicon host.
LIMIT="${PERF_GATE_LIMIT:-1.5}"

while [ $# -gt 0 ]; do
    case "$1" in
        --base) BASE="$2"; shift 2 ;;
        --samples) SAMPLES="$2"; shift 2 ;;
        --limit) LIMIT="$2"; shift 2 ;;
        *) echo "usage: $0 [--base REF] [--samples N] [--limit RATIO]" >&2; exit 2 ;;
    esac
done

if [ "$(uname -s)" != "Darwin" ]; then
    echo "perf-gate: virtio-fs compiles on macOS only; nothing to measure here"
    exit 0
fi

# Runs the benchmark SAMPLES times in $1 and prints "<min us> <host ops>".
# The op count is read from the first sample: it is exact, so every sample
# agrees, and a run where they do not agree is itself a failure.
measure() {
    local dir="$1" i out us ops best="" first_ops=""
    for i in $(seq 1 "$SAMPLES"); do
        out=$(cd "$dir" && cargo test --release --quiet -- \
            --ignored --nocapture bench_metadata_workload 2>/dev/null)
        us=$(printf '%s\n' "$out" | sed -n 's/.*=> \([0-9.]*\) us\/request/\1/p')
        ops=$(printf '%s\n' "$out" | sed -n 's/BENCH metadata: \([0-9]*\) host ops per round.*/\1/p')
        if [ -z "$us" ] || [ -z "$ops" ]; then
            echo "perf-gate: the benchmark in $dir printed no result" >&2
            printf '%s\n' "$out" >&2
            exit 1
        fi
        if [ -z "$first_ops" ]; then
            first_ops="$ops"
        elif [ "$ops" != "$first_ops" ]; then
            echo "perf-gate: host operations are not deterministic in $dir" >&2
            echo "perf-gate: sample 1 spent $first_ops, sample $i spent $ops" >&2
            exit 1
        fi
        if [ -z "$best" ] || awk "BEGIN{exit !($us < $best)}"; then
            best="$us"
        fi
    done
    echo "$best $first_ops"
}

base_sha=$(git merge-base HEAD "$BASE")
work=$(mktemp -d)
# The worktree is the only thing this script creates, so remove it however the
# script ends. `git worktree remove` needs the checkout to still be there.
# shellcheck disable=SC2329  # invoked by the trap below
cleanup() {
    git worktree remove --force "$work/base" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

echo "perf-gate: base $BASE ($(git rev-parse --short "$base_sha")), $SAMPLES samples each"
git worktree add --detach -q "$work/base" "$base_sha"

read -r base_us base_ops <<EOF
$(measure "$work/base")
EOF
read -r head_us head_ops <<EOF
$(measure ".")
EOF

echo "perf-gate: base  ${base_us} us/request, ${base_ops} host ops per round"
echo "perf-gate: head  ${head_us} us/request, ${head_ops} host ops per round"

status=0

if [ "$head_ops" != "$base_ops" ]; then
    if [ "$head_ops" -gt "$base_ops" ]; then
        echo "perf-gate: FAIL the device now spends $head_ops host operations per round, up from $base_ops"
        echo "perf-gate:      this count is exact. If the change is deliberate, say so and move the number."
        status=1
    else
        echo "perf-gate: the device spends $head_ops host operations per round, down from $base_ops"
    fi
fi

ratio=$(awk "BEGIN{printf \"%.2f\", $head_us / $base_us}")
if awk "BEGIN{exit !($head_us > $base_us * $LIMIT)}"; then
    echo "perf-gate: FAIL the metadata path is ${ratio}x slower, over the ${LIMIT}x limit"
    status=1
else
    echo "perf-gate: time ${ratio}x of base, within the ${LIMIT}x limit"
fi

exit "$status"

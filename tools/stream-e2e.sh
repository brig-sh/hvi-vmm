#!/usr/bin/env bash
# Moves a running guest between two hvi processes with a live move, and
# checks that it carried on rather than rebooting.
#
# The source streams itself with the control socket's `migrate` op: its
# RAM in rounds while the guest runs, then the last round and its state
# paused. This script relays the stream, frame by frame, from the source's
# control connection through a Unix socket into `hvi restore
# --from-stream` in a second process, then resumes the guest there, and
# moves it once more into a third. It is tools/checkpoint-e2e.sh --stream:
# the same workload and checks (the count, the open unlinked file, the disk,
# the timers, the floating-point sum, the boot_id), plus the rounds, bytes,
# dirty rates, compression, write faults and downtime of each move in
# summary.json.
#
# Usage:
#   tools/stream-e2e.sh --hvi target/release/hvi --kernel Image \
#       --initramfs INITRAMFS --out DIR [--cpus 2] [--mem 512] [--no-disk] \
#       [--portable] [--dirty-mib 256 [--dirty-once SECS]] [--disk-whole] \
#       [--disk-churn]
#
# The disk moves in the stream's disk rounds onto a copy of its base image
# kept beside it, and each restored disk must hash as the source's did at
# its fence; --disk-whole moves it the old way, the restore reopening the
# source's image. --disk-churn keeps the guest writing its disk through the
# moves.
#
# --dirty-mib N needs /dirty in the initramfs (tools/guest/dirty.c, built
# static; tools/mk-initramfs.py --add): the guest then rewrites N MiB of
# pseudo-random pages over and over during the move, which keeps it from
# converging, so the rounds stop at the round cap, and checks that no page
# lost a write. A page rewritten in every pass hides a write lost in a
# round taken with the guest running, since the next round sends it again;
# --dirty-once SECS writes each page once per SECS seconds instead, so such
# a loss fails the check. Exits 0 when every check passed.
set -euo pipefail
exec "$(dirname "$0")/checkpoint-e2e.sh" --stream "$@"

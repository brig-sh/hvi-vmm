#!/usr/bin/env bash
# Boots a guest against one virtio-fs share and reports how long a workload
# takes inside it. Unit tests cannot see any of this: they exercise the FUSE
# handlers directly, with no guest, no virtqueue and no VM exits -- which is
# how a change that made small writes 2.6x slower passed all of them.
#
# Usage:
#   tools/fsbench/run.sh --hvi <binary> --kernel <Image> --busybox <binary> \
#                        --tree <dir> [--workload walk|write|concurrent] \
#                        [--cache auto|always|none] [--mem-mib N] [--cpus N]
#
# --tree is shared read-write as tag "bench" and IS WRITTEN TO (the workloads
# create and delete files under _scratch). Point it at a copy, not at anything
# you care about.
#
# The guest needs a static aarch64 busybox; hull's container-initrd carries
# one, so extracting from there is the easy way to get it:
#   mkdir -p /tmp/ci && (cd /tmp/ci && cpio -idm < .../container-initrd)
#   tools/fsbench/run.sh --busybox /tmp/ci/busybox ...
#
# Comparing two builds means running it twice and diffing, alternating the
# order so host cache warmth does not favour whichever went second.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HVI=""
KERNEL=""
BUSYBOX=""
TREE=""
WORKLOAD=walk
CACHE=""
MEM_MIB=2048
CPUS=2
TIMEOUT=300

while [ $# -gt 0 ]; do
	case "$1" in
	--hvi) HVI=$2; shift 2 ;;
	--kernel) KERNEL=$2; shift 2 ;;
	--busybox) BUSYBOX=$2; shift 2 ;;
	--tree) TREE=$2; shift 2 ;;
	--workload) WORKLOAD=$2; shift 2 ;;
	--cache) CACHE=$2; shift 2 ;;
	--mem-mib) MEM_MIB=$2; shift 2 ;;
	--cpus) CPUS=$2; shift 2 ;;
	--timeout) TIMEOUT=$2; shift 2 ;;
	-h | --help) sed -n '2,28p' "$0"; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

for req in HVI KERNEL BUSYBOX TREE; do
	if [ -z "${!req}" ]; then
		echo "missing --$(echo "$req" | tr '[:upper:]' '[:lower:]')" >&2
		exit 2
	fi
done
GUEST="$HERE/guest-$WORKLOAD.sh"
[ -f "$GUEST" ] || { echo "no such workload: $WORKLOAD" >&2; exit 2; }
[ -d "$TREE" ] || { echo "--tree is not a directory: $TREE" >&2; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Assemble the initramfs: busybox, the workload as /init, and the mount points
# it needs. Nothing else -- the point is to measure virtio-fs, not a distro.
mkdir -p "$WORK/root/proc" "$WORK/root/sys" "$WORK/root/dev" "$WORK/root/rw"
cp "$BUSYBOX" "$WORK/root/busybox"
cp "$GUEST" "$WORK/root/init"
chmod +x "$WORK/root/busybox" "$WORK/root/init"
(cd "$WORK/root" && find . | cpio -o -H newc 2>/dev/null) > "$WORK/initrd"

SHARE_OPT=""
[ -n "$CACHE" ] && SHARE_OPT="cache=$CACHE"

echo "# hvi      : $HVI"
echo "# workload : $WORKLOAD"
echo "# tree     : $TREE"
echo "# cache    : ${CACHE:-auto (default)}"

# Empty-string args would become a stray argv entry, so build the command up
# rather than interpolating a possibly-empty SHARE_OPT.
set -- boot --kernel "$KERNEL" --initramfs "$WORK/initrd" \
	--share-rw "$TREE" bench
[ -n "$SHARE_OPT" ] && set -- "$@" "$SHARE_OPT"
set -- "$@" --cmdline "rdinit=/init console=ttyAMA0 panic=1" \
	--mem-mib "$MEM_MIB" --cpus "$CPUS"

"$HVI" "$@" >"$WORK/log" 2>&1 &
PID=$!
i=0
while [ $i -lt "$TIMEOUT" ]; do
	kill -0 $PID 2>/dev/null || break
	sleep 1
	i=$((i + 1))
done
if kill -0 $PID 2>/dev/null; then
	echo "TIMEOUT after ${TIMEOUT}s; killing the VM" >&2
	kill -9 $PID 2>/dev/null || true
fi
wait $PID 2>/dev/null || true

if ! grep -q '^BENCHMARK_END' "$WORK/log"; then
	if grep -q 'operation not allowed by the system' "$WORK/log"; then
		echo "hvi could not start a VM: the binary needs the hypervisor" >&2
		echo "entitlement, and a rebuild invalidates the signature. Re-sign it:" >&2
		echo "  codesign --sign - --entitlements hvi.entitlements --force \\" >&2
		echo "           --options runtime $HVI" >&2
		exit 1
	fi
	echo "the workload did not finish; last lines of the guest console:" >&2
	tail -25 "$WORK/log" >&2
	exit 1
fi
grep '^BENCH ' "$WORK/log"

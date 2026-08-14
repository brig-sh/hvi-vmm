#!/busybox sh
# Write workload, swept across block sizes. The sweep is the point: a small
# block size is many small FUSE requests and shows per-request cost, a large
# one is few large requests and shows the data path. A change can easily help
# one and hurt the other, which is exactly how the worker-thread handoff cost
# went unnoticed.
BB=/busybox
$BB mount -t proc proc /proc 2>/dev/null
$BB mount -t sysfs sys /sys 2>/dev/null
$BB mount -t devtmpfs dev /dev 2>/dev/null

now() { $BB cut -d' ' -f1 /proc/uptime; }
delta() { $BB awk -v a="$1" -v b="$2" 'BEGIN{printf "%.2f", b-a}'; }

$BB mkdir -p /rw
$BB mount -t virtiofs bench /rw || {
	echo "BENCH FATAL: cannot mount tag bench"
	$BB poweroff -f
}
$BB mkdir -p /rw/_scratch

echo "BENCHMARK_BEGIN"
# 256 MiB at each block size.
for bs in 4k 64k 1M; do
	case $bs in
	4k) count=65536 ;;
	64k) count=4096 ;;
	*) count=256 ;;
	esac
	t0=$(now)
	$BB dd if=/dev/zero of=/rw/_scratch/w bs=$bs count=$count 2>/dev/null
	$BB sync
	t1=$(now)
	echo "BENCH write_bs_$bs bytes=268435456 secs=$(delta "$t0" "$t1")"
	$BB rm -f /rw/_scratch/w
	$BB sync
done

big=$($BB find /rw -type f -size +4000k 2>/dev/null | $BB head -n 1)
if [ -n "$big" ]; then
	sz=$($BB stat -c %s "$big" 2>/dev/null)
	t0=$(now)
	$BB dd if="$big" of=/dev/null bs=1M 2>/dev/null
	t1=$(now)
	echo "BENCH read_seq bytes=$sz secs=$(delta "$t0" "$t1")"
fi

$BB rm -rf /rw/_scratch
echo "BENCHMARK_END"
$BB poweroff -f

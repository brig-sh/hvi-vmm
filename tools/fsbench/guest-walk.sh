#!/busybox sh
# Metadata workload: what a build tree, an `ls -R` or a source checkout does.
# Mount the share directly -- no overlay, no tmpfs root -- so the numbers are
# virtio-fs's and not the boot machinery's.
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

t0=$(now)
files=$($BB find /rw -type f 2>/dev/null | $BB wc -l)
t1=$(now)
echo "BENCH walk_find files=$files secs=$(delta "$t0" "$t1")"

t0=$(now)
$BB ls -lR /rw >/dev/null 2>&1
t1=$(now)
echo "BENCH walk_lslr secs=$(delta "$t0" "$t1")"

# The repeat walk is what the attribute/entry timeouts collapse: with non-zero
# timeouts the guest answers from its own cache instead of re-asking the host.
t0=$(now)
$BB find /rw -type f >/dev/null 2>&1
t1=$(now)
echo "BENCH walk_again secs=$(delta "$t0" "$t1")"

# stat() every file: LOOKUP+GETATTR with no readdir batching to hide it.
t0=$(now)
$BB find /rw -type f -exec $BB stat -c %s {} + >/dev/null 2>&1
t1=$(now)
echo "BENCH stat_all secs=$(delta "$t0" "$t1")"

t0=$(now)
i=0
while [ $i -lt 600 ]; do
	echo payload > /rw/_scratch/s-$i
	i=$((i + 1))
done
$BB sync
t1=$(now)
echo "BENCH create_small n=600 secs=$(delta "$t0" "$t1")"

t0=$(now)
$BB rm -rf /rw/_scratch
$BB sync
t1=$(now)
echo "BENCH unlink secs=$(delta "$t0" "$t1")"

echo "BENCHMARK_END"
$BB poweroff -f

#!/busybox sh
# Concurrent workload. A single-threaded walk cannot exercise queue depth, so
# it cannot tell you whether servicing requests off the vCPU thread helped or
# hurt -- run this alongside guest-walk.sh, never instead of it.
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

# Four top-level subtrees, whatever the shared tree happens to contain.
SUBS=$($BB find /rw -mindepth 1 -maxdepth 1 -type d 2>/dev/null | $BB head -n 4)
if [ -z "$SUBS" ]; then
	echo "BENCH FATAL: shared tree has no subdirectories to split across walkers"
	$BB poweroff -f
fi

echo "BENCHMARK_BEGIN"

t0=$(now)
for d in $SUBS; do
	$BB find "$d" -type f >/dev/null 2>&1
done
t1=$(now)
echo "BENCH serial secs=$(delta "$t0" "$t1")"

t0=$(now)
for d in $SUBS; do
	$BB find "$d" -type f >/dev/null 2>&1 &
done
wait
t1=$(now)
echo "BENCH concurrent4 secs=$(delta "$t0" "$t1")"

t0=$(now)
for d in $SUBS $SUBS; do
	$BB find "$d" -type f >/dev/null 2>&1 &
done
wait
t1=$(now)
echo "BENCH concurrent8 secs=$(delta "$t0" "$t1")"

t0=$(now)
i=0
while [ $i -lt 4 ]; do
	($BB find /rw -type f -size +200k 2>/dev/null | $BB head -n 40 | while read -r f; do
		$BB cat "$f" >/dev/null 2>&1
	done) &
	i=$((i + 1))
done
wait
t1=$(now)
echo "BENCH read_streams4 secs=$(delta "$t0" "$t1")"

echo "BENCHMARK_END"
$BB poweroff -f

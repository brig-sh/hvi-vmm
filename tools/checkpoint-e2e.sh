#!/usr/bin/env bash
# Moves a running guest from one hvi process to another on this Mac, and
# checks that it carried on rather than rebooting.
#
# The guest runs the workload `tools/mk-initramfs.py --checkpoint-workload`
# builds: a loop that counts in a shell variable every 200 ms and prints the
# count with the guest's wall clock, a file it holds open on fd 3 after
# unlinking it, a file it wrote and synced on an ext4 /dev/vda, and a
# CPU-bound awk that sums a double and prints it with its count.
#
# 1. Boot the guest with --control-sock, --checkpoint-root, --disk,
#    --net-stub and --agent-sock, and let it count.
# 2. Checkpoint it with then=fence.
# 3. Start `hvi restore` as a second process with its own sockets, wait for
#    it to report restored-paused, and resume it. Stop the fenced source.
# 4. Check the restored guest: its count and the awk's sum go on from the
#    captured ones and no boot banner appears; a second restore of the
#    bundle onto its disk is refused; on request it reads fd 3 and the disk
#    file, writes and syncs another, and a `sleep 5` takes 5 s of host
#    time. Its wall clock goes on from the captured time.
# 5. Move it once more, into a third process. Hold that one restored-paused
#    for a second and check the guest did not run. Checkpoint it there with
#    then=continue and check that its vCPU and platform state equal the
#    bundle's: the restore loaded every register it was given. Then resume
#    it and check it counts on. Stop both, check the disk generation grew over the
#    moves, and read the file the guest wrote from the image on the host.
#
# With --stream both moves are live moves instead: the source streams
# itself with the control socket's `migrate` op while the guest runs, and
# the script relays the stream through a Unix socket into the next process,
# `hvi restore --from-stream` (tools/stream-e2e.sh runs this mode). The
# checks are the same, but the second restore of the first bundle onto the
# running guest's disk, which needs a bundle directory; the documents each
# restore keeps (--stream-keep) stand in for the bundle where a check reads
# one. The guest also prints its boot_id before and after, which must not
# change. --dirty-mib N starts /dirty (tools/guest/dirty.c) in the guest
# before the move, writing N MiB of pseudo-random pages over and over; it
# must report no page that lost a write, and go on counting after each
# move. summary.json then also holds each move's rounds, bytes, dirty
# rates, compression, write faults and downtime: from the end of the last
# round taken with the guest running to the resume reply. --dirty-once SECS
# makes /dirty write each page once per cycle of SECS seconds instead, in
# a shuffled order, so that a write lost in any round, not only the final
# one, leaves a page that fails its check.
#
# With --stream and a disk, the disk moves in the stream too: the source
# boots with --disk-base-sha256 of the fresh image, a copy of which is kept
# as the base, and each restore gets a new copy of the base as its --disk,
# which the stream's disk rounds make into the guest's disk. After each
# fence the restored disk, held restored-paused, must hash as the source's
# disk does. --disk-whole moves it the old way instead: no base, no disk
# rounds, and the restore reopens the source's own image. --disk-churn
# rewrites a 1 MiB file on the guest's disk with fsync in a loop through
# the moves, so the rounds taken with the guest running carry blocks.
#
# With --portable the guest boots the portable profile
# (--profile portable-arm64-v1) and the kernel must be the portable one,
# with hvi-time. The initramfs must then hold /el0check and /tfd
# (tools/mk-initramfs.py --checkpoint-workload --add el0check --add tfd;
# tools/guest/el0check.c and tools/guest/tfd.c, both built static). Just
# before the capture the
# script starts a 6 s timerfd and a 6 s sleep, and checks after the
# restore: the clocksource is hvi-time, el0check passes, the guest driver
# logged the migration (generation 4) and counts it, both timers fire
# after the resume 6 s of guest time after they were armed, and the
# guest's wall clock is the host's again.
#
# Usage:
#   tools/checkpoint-e2e.sh --hvi target/release/hvi --kernel Image \
#       --initramfs target/initramfs-workload.cpio --out DIR \
#       [--cpus 2] [--mem 512] [--no-disk] [--portable] [--stream]
#       [--dirty-mib N [--dirty-once SECS]] [--disk-whole] [--disk-churn]
#
# DIR receives the checkpoint root (with the bundle), the disk image, both
# processes' consoles, their profiles and summary.json with the timings.
# The disk needs mke2fs and debugfs from e2fsprogs (Homebrew: brew install
# e2fsprogs), found on PATH or in /opt/homebrew/opt/e2fsprogs/sbin; without
# them, pass --no-disk. Sockets go in a short directory under /tmp, since a socket path
# is limited to 104 bytes on macOS. Exits 0 when every check passed.
set -euo pipefail

hvi="" kernel="" initramfs="" out="" cpus=2 mem=512 disk=yes portable=no stream=no dirty=0 dirty_once=0
disk_whole=no churn=no
while [ $# -gt 0 ]; do
    case "$1" in
        --hvi) hvi="$2"; shift 2 ;;
        --kernel) kernel="$2"; shift 2 ;;
        --initramfs) initramfs="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --cpus) cpus="$2"; shift 2 ;;
        --mem) mem="$2"; shift 2 ;;
        --no-disk) disk=no; shift ;;
        --portable) portable=yes; shift ;;
        --stream) stream=yes; shift ;;
        --dirty-mib) dirty="$2"; shift 2 ;;
        --dirty-once) dirty_once="$2"; shift 2 ;;
        --disk-whole) disk_whole=yes; shift ;;
        --disk-churn) churn=yes; shift ;;
        *) echo "usage: $0 --hvi PATH --kernel PATH --initramfs PATH --out DIR [--cpus N] [--mem MIB] [--no-disk] [--portable] [--stream] [--dirty-mib N [--dirty-once SECS]] [--disk-whole] [--disk-churn]" >&2; exit 2 ;;
    esac
done
for v in hvi kernel initramfs out; do
    if [ -z "${!v}" ]; then
        echo "$0: --$v is required" >&2
        exit 2
    fi
done

mkdir -p "$out"
out="$(cd "$out" && pwd -P)"
root="$out/root"
rm -rf "$root"
mkdir -m 700 "$root"
image="" debugfs=""
if [ "$disk" = yes ]; then
    sbin=/opt/homebrew/opt/e2fsprogs/sbin
    [ -x "$sbin/mke2fs" ] || sbin=/sbin
    mke2fs="$(command -v mke2fs || echo "$sbin/mke2fs")"
    debugfs="$(command -v debugfs || echo "$sbin/debugfs")"
    for tool in "$mke2fs" "$debugfs"; do
        if [ ! -x "$tool" ]; then
            echo "$0: $(basename "$tool") not found; install e2fsprogs or pass --no-disk" >&2
            exit 2
        fi
    done
    image="$out/disk.img"
    rm -f "$image"
    "$mke2fs" -q -t ext4 -F "$image" 64M
fi
socks="$(mktemp -d /tmp/hvi-e2e.XXXXXX)"
trap 'rm -rf "$socks"' EXIT

python3 - "$hvi" "$kernel" "$initramfs" "$out" "$root" "$socks" "$cpus" "$mem" "$image" \
    "$debugfs" "$portable" "$stream" "$dirty" "$dirty_once" "$disk_whole" "$churn" <<'PY'
import hashlib, json, os, re, shutil, socket, subprocess, sys, threading, time

(hvi, kernel, initramfs, out, root, socks, cpus, mem, image, debugfs, portable, stream,
 dirty, dirty_once, disk_whole, churn) = sys.argv[1:]
portable = portable == "yes"
stream = stream == "yes"
churn = churn == "yes"
# The disk moves in the stream's disk rounds onto a copy of its base.
by_blocks = stream and bool(image) and disk_whole != "yes"
dirty = int(dirty)
dirty_once = int(dirty_once)
# A timer armed before a live move must still be pending when it ends:
# with a busy guest the rounds can take several seconds.
TIMER_S = 20 if dirty else 6
t0 = time.monotonic()
# Host wall-clock time at monotonic time t0, to read a line's host time.
wall_t0 = time.time() - (time.monotonic() - t0)
failures = []


def now():
    return time.monotonic() - t0


class Guest:
    """One hvi process, its console lines with the host time each arrived."""

    def __init__(self, name, cmd):
        self.name, self.lines = name, []
        self.log = open(os.path.join(out, f"{name}.log"), "w")
        self.note("host: " + " ".join(cmd))
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
        threading.Thread(target=self.read, daemon=True).start()

    def note(self, s):
        t = now()
        self.lines.append((t, s))
        self.log.write(f"[{t:9.3f}] {s}\n")
        self.log.flush()

    def read(self):
        for raw in self.p.stdout:
            self.note("out: " + raw.decode(errors="replace").rstrip("\r\n"))

    def wait_for(self, pattern, timeout, after=0.0):
        end = time.monotonic() + timeout
        rx = re.compile(pattern)
        while time.monotonic() < end:
            for t, s in list(self.lines):
                if t >= after and s.startswith("out: ") and rx.search(s[5:]):
                    return t, s[5:]
            if self.p.poll() is not None:
                break
            time.sleep(0.02)
        return None

    def type(self, text):
        self.note(f"host: types {text!r}")
        self.p.stdin.write(text.encode())
        self.p.stdin.flush()

    def outputs(self, pattern, after=0.0):
        rx = re.compile(pattern)
        return [(t, s[5:]) for t, s in list(self.lines)
                if t >= after and s.startswith("out: ") and rx.search(s[5:])]


class Control:
    def __init__(self, guest, path, timeout=30):
        end = time.monotonic() + timeout
        while True:
            try:
                self.s = socket.socket(socket.AF_UNIX)
                self.s.connect(path)
                break
            except OSError:
                if time.monotonic() > end or guest.p.poll() is not None:
                    raise
                time.sleep(0.01)
        self.f, self.guest = self.s.makefile("rwb"), guest

    def ask(self, **req):
        line = json.dumps(dict(v=1, **req))
        sent = now()
        self.f.write(line.encode() + b"\n")
        self.f.flush()
        reply = self.f.readline().decode().rstrip("\n")
        got = now()
        self.guest.note(f"ctl: {line} -> {reply} ({(got - sent) * 1000:.1f} ms)")
        return json.loads(reply), got


def downtime(guest, before=0.0):
    """Returns how far hvi-time moved the portable guest's wall clock and
    CLOCK_BOOTTIME at its restore, less `before`, in seconds; 0 for a
    native guest, whose clocks do not move."""
    if not portable:
        return 0.0
    got = guest.wait_for(r"hvi-time: published generation .* downtime total \d+ ns", 10)
    total = int(re.search(r"downtime total (\d+) ns", got[1]).group(1)) if got else 0
    return total / 1e9 - before


def check(ok, what):
    print(("  ok   " if ok else "  FAIL ") + what, flush=True)
    if not ok:
        failures.append(what)


def tick(s):
    """Returns a TICK line's count, guest uptime and guest wall clock."""
    m = re.search(r"TICK (\d+) (\d+\.\d+) (\d+)", s)
    return (int(m.group(1)), float(m.group(2)), int(m.group(3))) if m else None


# The sleep's start and end lines, with the guest's uptime. The shell's
# prompt may come first on the line when the output lands as it prints it.
NANOSLEEP_START = r"(?:^|# )NANOSLEEP-START ([0-9.]+)"
NANOSLEEP_END = r"(?:^|# )NANOSLEEP-END ([0-9.]+)"


# The awk prints its count and sum every FP_STEP additions of 0.25.
FP_STEP = 500000


def fp(s):
    """Returns an FP line's count and sum."""
    m = re.search(r"FP (\d+) (\S+)$", s)
    return (int(m.group(1)), float(m.group(2))) if m else None


def fp_goes_on(before, after, where):
    """Checks the awk's lines across a move: every sum exact, and the first
    line after the move the next after the last one before it."""
    lines = [fp(s) for _, s in before.outputs(r"FP ") + after.outputs(r"FP ")]
    exact = all(x == n * 0.25 for n, x in lines)
    last = [fp(s)[0] for t, s in before.outputs(r"FP ")]
    first = after.wait_for(r"FP \d+ ", 30)
    check(not before.outputs(r"FP-BAD") and not after.outputs(r"FP-BAD") and exact
          and bool(last) and first is not None and fp(first[1])[0] == last[-1] + FP_STEP,
          f"the awk's floating-point sum goes on {where}: last before {last[-1] if last else None}, "
          f"first after {fp(first[1])[0] if first else None}, every sum exact: {exact}")


def state_differences(a, b):
    """Returns where bundle b's vCPU and platform state differ from bundle
    a's, by vCPU and key, and by platform part and key."""
    def load(d, name):
        with open(os.path.join(d, name)) as f:
            return json.load(f)

    def keys(where, x, y):
        return [f"{where}.{k}" for k in sorted(set(x) | set(y)) if x.get(k) != y.get(k)]

    ca, cb = load(a, "cpu.json")["vcpus"], load(b, "cpu.json")["vcpus"]
    why = [] if len(ca) == len(cb) else [f"vCPU count {len(ca)} then {len(cb)}"]
    for va, vb in zip(ca, cb):
        why += keys(f"vcpu{va.get('id')}", va, vb)
        for part in ("regs", "sysregs"):
            if isinstance(va.get(part), dict) and isinstance(vb.get(part), dict):
                why += keys(f"vcpu{va.get('id')}.{part}", va[part], vb[part])
        if va.get("simd") != vb.get("simd"):
            why += [f"vcpu{va.get('id')}.q{n}" for n, (x, y)
                    in enumerate(zip(va.get("simd") or [], vb.get("simd") or [])) if x != y]
    pa, pb = load(a, "platform.json"), load(b, "platform.json")
    why += keys("platform.irq", pa.get("irq") or {}, pb.get("irq") or {})
    ta, tb = dict(pa.get("timer") or {}), dict(pb.get("timer") or {})
    # The host's own clock at the capture, which a later capture reads later.
    ta.pop("host_monotonic_at_capture_ns", None)
    tb.pop("host_monotonic_at_capture_ns", None)
    why += keys("platform.timer", ta, tb)
    return why


def stream_move(name, ctl, keep, txid, epoch, args):
    """Moves the guest behind the control connection `ctl` into a new
    process `name` with a live move: starts `hvi restore --from-stream` on a
    relay socket, asks the source to `migrate` with then=fence, and relays
    each frame of the stream from the control connection to the restore, up
    to the manifest. Returns the reply, the new process and the times the
    request was sent, the manifest relayed and the reply read."""
    relay = f"{socks}/{name}-relay.sock"
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(relay)
    listener.listen(1)
    listener.settimeout(60)
    dst = Guest(name, [hvi, "restore", "--from-stream", relay, "--stream-keep", keep] + args)
    conn, _ = listener.accept()
    listener.close()
    line = json.dumps(dict(v=1, op="migrate", then="fence", txid=txid, epoch=epoch))
    sent = now()
    ctl.f.write(line.encode() + b"\n")
    ctl.f.flush()
    frames, reply, manifest_at = {}, None, None
    while True:
        header = ctl.f.readline()
        if not header:
            break
        h = json.loads(header)
        if "component" not in h:
            reply = h  # the source ended the stream early
            break
        body = b""
        while len(body) < h["size"]:
            more = ctl.f.read(h["size"] - len(body))
            if not more:
                break
            body += more
        conn.sendall(header)
        conn.sendall(body)
        frames[h["component"]] = frames.get(h["component"], 0) + 1
        if h["component"] == "manifest.json":
            manifest_at = now()
            reply = json.loads(ctl.f.readline())
            break
    got = now()
    conn.close()
    ctl.guest.note(f"ctl: {line} -> {json.dumps(reply)} ({(got - sent) * 1000:.1f} ms), "
                   f"frames relayed {frames}")
    return reply or {}, dst, sent, manifest_at or got, got


def stream_summary(reply, resume_wall=None):
    """Returns what a live move's reply says about its rounds, with the
    downtime from the end of the last round with the guest running to
    `resume_wall`, the host time of the resume reply."""
    st = reply.get("stats") or {}
    raw, wire = st.get("ram_raw_bytes") or 0, st.get("ram_stream_bytes") or 0
    keep = ("round", "in_pause", "pages", "data_pages", "bytes", "ms", "dirty_pages_per_s")
    summary = {k: st.get(k) for k in (
        "stop_reason", "threshold_bytes", "precopy_ms", "pause_ms", "paused_ms",
        "final_round_bytes", "ram_present_bytes", "ram_raw_bytes", "ram_stream_bytes",
        "stream_bytes", "write_granule", "write_faults", "write_fault_ns")}
    summary["rounds"] = [{k: r.get(k) for k in keep} for r in st.get("rounds") or []]
    summary["compression_ratio"] = round(raw / wire, 2) if wire else None
    for k in ("disk_raw_bytes", "disk_stream_bytes", "disk_sync_ms", "gate_ms", "park_ms"):
        summary[k] = st.get(k)
    dkeep = ("name", "round", "in_pause", "blocks", "raw_bytes", "bytes", "ms", "max_lock_us")
    summary["disk_rounds"] = [{k: r.get(k) for k in dkeep} for r in st.get("disk_rounds") or []]
    draw, dwire = summary["disk_raw_bytes"] or 0, summary["disk_stream_bytes"] or 0
    summary["disk_compression_ratio"] = round(draw / dwire, 2) if dwire else None
    if resume_wall is not None and st.get("precopy_end_unix_ms"):
        summary["downtime_precopy_end_to_resume_ms"] = round(
            resume_wall * 1000 - st["precopy_end_unix_ms"], 1)
    return summary


def check_disk_rounds(move, where):
    """Checks that `move` took the disk in rounds: one before each RAM
    round, the last one paused."""
    d, r = move.get("disk_rounds") or [], move.get("rounds") or []
    check(len(d) == len(r) and len(d) >= 2 and d[-1]["in_pause"]
          and d[-1]["name"] == "disk-round-final"
          and not any(x["in_pause"] for x in d[:-1]),
          f"{where} took the disk in {len(d)} round(s) for {len(r)} RAM round(s), the last "
          f"one paused: " + ", ".join(f"{x['name']} {x['blocks']} blocks / {x['bytes']} B"
                                     for x in d))


def dirty_goes_on(guest, after, where):
    """Checks that /dirty writes on in `guest` after `after` and that no
    page it wrote lost a write.

    The first pass reported after `after` may have begun before the move,
    so it checked some pages before the move only; the pass after it
    checks every page after the move."""
    if not dirty:
        return
    pass_line = r"DIRTY pass (\d+) bad \d+"
    first = guest.wait_for(pass_line, 20, after=after)
    got = None
    if first:
        n = int(re.search(pass_line, first[1]).group(1))
        end = time.monotonic() + 20
        while got is None and time.monotonic() < end:
            got = next((line for line in guest.outputs(pass_line, after=first[0])
                        if int(re.search(pass_line, line[1]).group(1)) > n), None)
            time.sleep(0.05)
    bad = [s for _, s in guest.outputs(r"DIRTY-BAD")]
    check(got is not None and " bad 0 " in got[1] and not bad,
          f"/dirty writes on {where} and every page held its last write, through a pass "
          f"begun after the move: {got[1] if got else None}, {len(bad)} DIRTY-BAD line(s) "
          f"{bad[:2]}")


def counted_twice(before, after):
    """Returns the counts that both `before` and `after` printed: a guest
    that ran on after the state the next one resumed from."""
    def counts(guest):
        return {c[0] for c in (tick(s) for _, s in guest.outputs(r"TICK ")) if c}
    return sorted(counts(before) & counts(after))


def boot_id(guest, after=0.0):
    """Returns the guest's boot_id, read through its console."""
    guest.type('echo "BOOTID $(cat /proc/sys/kernel/random/boot_id)"\n')
    got = guest.wait_for(r"BOOTID ([0-9a-f-]{36})$", 10, after=after)
    return re.search(r"BOOTID ([0-9a-f-]{36})$", got[1]).group(1) if got else None


def sha256_of(path):
    """Returns the SHA-256 of the file at `path`, as hex."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def clone_base(name):
    """Returns the path of a new copy of the base image, for a restore's
    --disk: an APFS clone on a Mac, a reflink or a copy elsewhere."""
    path = os.path.join(out, name)
    if os.path.exists(path):
        os.remove(path)
    if sys.platform == "darwin":
        subprocess.run(["cp", "-c", base_image, path], check=True)
    else:
        subprocess.run(["cp", "--reflink=auto", base_image, path], check=True)
    return path


net = ["--net-stub"]
base = []
base_image = None
if by_blocks:
    # The base is the image as the source boots from it.
    base_image = os.path.join(out, "base.img")
    shutil.copyfile(image, base_image)
    base = ["--disk-base-sha256", sha256_of(image)]
common = net + (["--disk", image] if image else [])
profile = ["--profile", "portable-arm64-v1"] if portable else []
src = Guest("source", [hvi, "boot", "--kernel", kernel, "--initramfs", initramfs,
                       "--cpus", cpus, "--mem-mib", mem] + profile + base + [
                       "--control-sock", f"{socks}/src.sock", "--checkpoint-root", root,
                       "--agent-sock", f"{socks}/src-agent.sock",
                       "--profile-out", os.path.join(out, "source-profile.json")] + common)
print(f"checkpoint e2e: {cpus} vCPU(s), {mem} MiB, disk {'yes' if image else 'no'}, "
      f"profile {'portable-arm64-v1' if portable else 'native'}, "
      f"{'live moves (migrate)' if stream else 'checkpoint bundles'}"
      f"{f', /dirty {dirty} MiB' if dirty else ''}", flush=True)
# The native guest has no RTC, so its wall clock starts at 0. Give it this
# host's, so its drift over the move can be read against the host's. The
# portable guest's hvi-time gives it the host's at boot.
if src.wait_for(r"TICK 3 ", 120) and not portable:
    src.type(f"date -s @{int(time.time())} >/dev/null\n")
ready = src.wait_for(r"TICK 15 ", 120)
check(ready is not None, "the source guest booted and counts")
if image:
    check(bool(src.outputs(r"DISK-READY written-before ")), "the source wrote and synced /mnt/before")
if portable:
    check(bool(src.outputs(r"EL0CHECK PASS")), "the source guest's EL0 reads the synthetic counter")
    check(bool(src.outputs(r"^CLOCKSOURCE hvi-time$")), "the source guest's clocksource is hvi-time")
if not ready:
    src.p.kill()
    sys.exit(1)
boot_before = boot_id(src)
check(boot_before is not None, f"the source guest's boot_id: {boot_before}")
if dirty:
    src.type(f"/dirty {dirty} rand {dirty_once} &\n" if dirty_once else f"/dirty {dirty} &\n")
    check(src.wait_for(r"DIRTY-READY ", 60) is not None
          and src.wait_for(r"DIRTY pass ", 30) is not None,
          f"/dirty writes {dirty} MiB "
          + (f"once every {dirty_once} s" if dirty_once else "over and over")
          + " in the source guest")
if churn and image:
    src.type("( while :; do /bin/busybox dd if=/dev/urandom of=/mnt/churn bs=65536 count=16 "
             "conv=fsync 2>/dev/null; /bin/busybox sleep 0.1; done ) &\n")
if portable:
    # Two timers armed just before the capture, which must fire after the
    # resume, 6 s of guest time after they were armed.
    src.type(f"/tfd {TIMER_S} &\n")
    src.type("/bin/busybox echo \"NANOSLEEP-START $(/bin/busybox cut -d' ' -f1 /proc/uptime)\"; "
             f"( /bin/busybox sleep {TIMER_S}; /bin/busybox echo \"NANOSLEEP-END "
             "$(/bin/busybox cut -d' ' -f1 /proc/uptime)\" ) &\n")
    armed = src.wait_for(r"TIMERFD-ARMED ", 10) and src.wait_for(NANOSLEEP_START, 10)
    check(bool(armed), "a timerfd and a sleep are armed before the capture")

# The move itself runs straight through, as a caller would run it, so its
# timings are the move's: the checks that need a pause come afterwards.
sctl = Control(src, f"{socks}/src.sock")
bundle = os.path.join(root, "move")
dst_disk = clone_base("disk-restored.img") if by_blocks else image
dst_args = ["--control-sock", f"{socks}/dst.sock", "--checkpoint-root", root,
            "--agent-sock", f"{socks}/dst-agent.sock",
            "--profile-out", os.path.join(out, "restored-profile.json")] + net + (
                ["--disk", dst_disk] if image else [])
if stream:
    # The restore builds the VM once the manifest is in; until then it
    # applies the rounds as they come.
    fence, dst, fence_sent, spawned_at, fence_at = stream_move(
        "restored", sctl, bundle, "e2e-1", 1, dst_args)
else:
    fence_sent = now()
    fence, fence_at = sctl.ask(op="checkpoint", dir=bundle, then="fence", txid="e2e-1", epoch=1)
    spawned_at = now()
    dst = Guest("restored", [hvi, "restore", "--from", bundle] + dst_args)
dctl = Control(dst, f"{socks}/dst.sock")
status, status_at = dctl.ask(op="status")
disk_check_s = 0.0
if by_blocks:
    # Both still: the source fenced, the destination restored-paused. The
    # hashing delays the resume, so it is taken out of the downtime below.
    hashed_at = now()
    disk_sums = (sha256_of(image), sha256_of(dst_disk))
    disk_check_s = now() - hashed_at
resumed, resume_at = dctl.ask(op="resume")
stream_moves = [stream_summary(fence, wall_t0 + resume_at)] if stream else []
if stream_moves and stream_moves[0].get("downtime_precopy_end_to_resume_ms") is not None:
    stream_moves[0]["disk_check_ms"] = round(disk_check_s * 1000, 1)
    stream_moves[0]["downtime_less_disk_check_ms"] = round(
        stream_moves[0]["downtime_precopy_end_to_resume_ms"] - disk_check_s * 1000, 1)

check(fence.get("ok") is True and fence.get("state") == "fenced",
      ("migrate" if stream else "checkpoint") + " then=fence"
      + (f": {fence.get('code')}: {fence.get('error')}" if not fence.get("ok") else ""))
if stream_moves:
    rounds = stream_moves[0]["rounds"]
    check(len(rounds) >= 2 and rounds[-1]["in_pause"] and not any(r["in_pause"] for r in rounds[:-1]),
          f"the move took {len(rounds)} RAM round(s), the last one paused, "
          f"stopping as {stream_moves[0]['stop_reason']}: "
          + ", ".join(f"{r['pages']} pages / {r['bytes']} B" for r in rounds))
stats = fence.get("stats", {})
if by_blocks:
    check_disk_rounds(stream_moves[0], "the move")
    check(disk_sums[0] == disk_sums[1],
          f"the restored disk is the source's at the fence: sha256 {disk_sums[0][:16]} on the "
          f"source, {disk_sums[1][:16]} restored from the base and the disk rounds")
check(status.get("state") == "restored-paused", f"the restore reports restored-paused ({status})")
check(resumed.get("state") == "running", "resume")
restore_ms = (status_at - spawned_at) * 1000
before = [(t, tick(s)) for t, s in src.outputs(r"TICK ") if t <= fence_at]
last_tick_at, (last_n, last_uptime, last_wall) = before[-1]
# A fenced source prints nothing after the reply. Whether it ran on after
# its pause, during the final round, is not read from the host's clock: a
# console line can reach this script a second late on a busy host. The
# count shows it instead: a source that ran past the state the destination
# resumed from prints counts the destination prints again (checked below).
late = src.outputs(r"TICK ", after=(fence_at if stream else fence_sent) + 0.1)
check(not late, f"the fenced source printed nothing after the fence reply: {late[:2]}")
if stream:
    kept = sorted(os.listdir(bundle)) if os.path.isdir(bundle) else []
    want = sorted(["profile.json", "cpu.json", "platform.json", "devices.json", "session.json",
                   "manifest.json"] + (["disk.json"] if image else []))
    check(kept == want, f"the restore kept the stream's documents and no RAM: {kept}")
else:
    verify = subprocess.run([hvi, "checkpoint-verify", bundle], capture_output=True, text=True)
    src.note("verify: " + (verify.stdout + verify.stderr).replace("\n", " | "))
    check(verify.returncode == 0 and "complete: every part a restore needs is captured" in verify.stdout,
          "checkpoint-verify: the bundle is complete")
stopped, _ = sctl.ask(op="stop")
try:
    src_rc = src.p.wait(timeout=20)
except subprocess.TimeoutExpired:
    src.p.kill()
    src_rc = None
check(src_rc == 0, f"the fenced source stopped (exit {src_rc})")

first = dst.wait_for(r"TICK ", 10)
check(first is not None, "the restored guest counts again")
wall_lag = None
if first:
    first_at, line = first
    n, uptime, wall = tick(line)
    check(n == last_n + 1, f"the count goes on: last before the fence {last_n}, first after {n}")
    twice = counted_twice(src, dst)
    check(not twice, f"no count was printed by both guests: {twice[:3]}")
    host_gap = first_at - last_tick_at
    # The ticks carry /proc/uptime, CLOCK_BOOTTIME, which on the portable
    # profile moves on by the downtime; its monotonic clock does not.
    moved = downtime(dst)
    check(uptime - last_uptime - moved < 0.5,
          f"the guest's monotonic clock goes on from the capture: {uptime - last_uptime:.2f} s "
          f"between the two ticks in the guest ({moved:.3f} s of it the downtime its clock "
          f"was moved by), {host_gap:.3f} s on the host")
    if portable:
        # hvi-time moved the guest's wall clock by the downtime. `date +%s`
        # is whole seconds, so it reads up to 1 s behind the host.
        host_wall = wall_t0 + first_at
        check(-0.2 <= host_wall - wall <= 1.5,
              f"the guest's wall clock is the host's again: guest {wall}, host {host_wall:.3f}")
    else:
        check(0 <= wall - last_wall <= 1,
              f"the guest's wall clock goes on from the captured time: {last_wall} then {wall}")
    # The native guest gets no realtime correction without a guest agent,
    # so its wall clock now lags the host's by the time it was away.
    wall_lag = time.time() - wall
check(not dst.outputs(r"Booting Linux|HVI-WORKLOAD-BOOT|ARM64 guest on hvi|DISK-READY"),
      "no boot banner in the restored guest: it did not reboot")
fp_goes_on(src, dst, "over the move")

timers = {}
if portable:
    fired = dst.wait_for(r"TIMERFD-FIRED ", TIMER_S + 9)
    if fired:
        elapsed = float(fired[1].split()[2])
        timers["timerfd_guest_s"] = elapsed
        check(fired[0] > resume_at and TIMER_S - 0.01 <= elapsed <= TIMER_S + 0.3,
              f"the timerfd armed before the capture fired after the resume, {elapsed:.3f} s "
              f"of guest time after it was armed")
    else:
        check(False, "the timerfd armed before the capture fired")
    end = dst.wait_for(NANOSLEEP_END, TIMER_S + 9)
    start = src.outputs(NANOSLEEP_START)
    if end and start:
        # /proc/uptime is CLOCK_BOOTTIME, which hvi-time moves on by the
        # downtime, as it does the wall clock.
        slept = (float(re.search(NANOSLEEP_END, end[1]).group(1))
                 - float(re.search(NANOSLEEP_START, start[0][1]).group(1)) - downtime(dst))
        timers["nanosleep_guest_s"] = round(slept, 3)
        check(end[0] > resume_at and TIMER_S - 0.03 <= slept <= TIMER_S + 0.3,
              f"the sleep armed before the capture ended after the resume, {slept:.2f} s of "
              f"guest monotonic time after it began")
    else:
        check(False, "the sleep armed before the capture ended")

dirty_goes_on(dst, resume_at, "after the move")
boot_after = boot_id(dst, resume_at)
check(boot_after is not None and boot_after == boot_before,
      f"the guest's boot_id is the same after the move: {boot_before} then {boot_after}")
if image and not stream:
    # hvi does not consume a bundle, so the disk lock is what keeps a second
    # guest off the disk the restored one writes. A stream is read once.
    dup = subprocess.run([hvi, "restore", "--from", bundle,
                          "--control-sock", f"{socks}/dup.sock", "--checkpoint-root", root,
                          "--agent-sock", f"{socks}/dup-agent.sock"] + common,
                         stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    dst.note("second restore: exit %d: %s" % (dup.returncode, dup.stderr.replace("\n", " | ")))
    check(dup.returncode == 1 and "the image is open elsewhere" in dup.stderr
          and not os.path.exists(f"{socks}/dup.sock"),
          f"a second restore onto the running guest's disk is refused (exit {dup.returncode})")

dst.type("touch /tmp/go\n")
got = dst.wait_for(r"(?<!NANO)SLEEP-END ", 30)
check(got is not None, "the workload answered the request")
counter = dst.outputs(r"COUNTER ")
check(bool(counter) and int(counter[0][1].split()[1]) > last_n, f"the count after the restore: {counter[:1]}")
check(bool(dst.outputs(r"FD3 kept open after unlink$")), "the unlinked file is still readable on fd 3")
if portable:
    go = counter[0][0] if counter else 0.0
    check(bool(dst.outputs(r"EL0CHECK PASS", after=go)),
          "after the restore, EL0 still reads the synthetic counter")
    check(bool(dst.outputs(r"^CLOCKSOURCE hvi-time$", after=go)),
          "after the restore, the clocksource is still hvi-time")
    moves = dst.outputs(r"^MIGRATION .*hvi-time: generation \d+:", after=go)
    generations = {re.search(r"generation (\d+):", s).group(1) for _, s in moves}
    check(len(moves) == 1 and generations == {"4"},
          f"the guest driver logged the move once, generation 4: {len(moves)} line(s), "
          f"generations {sorted(generations)}")
    snap = dst.outputs(r"EL0CHECK snapshot1: .* migrations=", after=go)
    count = int(snap[0][1].split("migrations=")[1]) if snap else None
    check(count == 1, f"the guest driver counts the move once: migrations={count} on {cpus} vCPU(s)")
after_n = None
if image:
    check(bool(dst.outputs(r"DISK-BEFORE written-before ")), "the file written before the move is on the disk")
    written = dst.outputs(r"DISK-AFTER written-after \d+")
    check(bool(written), "a write after the restore works")
    after_n = written[0][1].split()[-1] if written else None
start, end = dst.outputs(r"(?<!NANO)SLEEP-START "), dst.outputs(r"(?<!NANO)SLEEP-END ")
if start and end:
    host_sleep = end[0][0] - start[0][0]
    guest_sleep = float(end[0][1].split()[1]) - float(start[0][1].split()[1])
    check(4.5 < host_sleep < 6.0, f"sleep 5 took {host_sleep:.2f} s of host time ({guest_sleep:.2f} s in the guest)")
else:
    host_sleep = guest_sleep = None
    check(False, "the sleep was timed")

# A restored guest is a guest like any other: move it once more.
again_at = now()
third_disk = clone_base("disk-again.img") if by_blocks else image
third_args = ["--control-sock", f"{socks}/third.sock", "--checkpoint-root", root,
              "--agent-sock", f"{socks}/third-agent.sock"] + net + (
                  ["--disk", third_disk] if image else [])
if stream:
    fence2, third, _, manifest2_at, fence2_at = stream_move(
        "restored-again", dctl, os.path.join(root, "move-again"), "e2e-2", 2, third_args)
else:
    fence2, fence2_at = dctl.ask(op="checkpoint", dir=os.path.join(root, "move-again"),
                                 then="fence", txid="e2e-2", epoch=2)
    third = Guest("restored-again", [hvi, "restore", "--from", os.path.join(root, "move-again")]
                  + third_args)
check(fence2.get("state") == "fenced",
      "the restored guest " + ("streams" if stream else "checkpoints") + " again")
tctl = Control(third, f"{socks}/third.sock")
status3, status3_at = tctl.ask(op="status")
if stream:
    stream_moves.append(stream_summary(fence2))
    stream_moves[-1]["manifest_to_restored_paused_ms"] = round(
        (status3_at - manifest2_at) * 1000, 1)
if by_blocks:
    check_disk_rounds(stream_moves[-1], "the second move")
    sums = (sha256_of(dst_disk), sha256_of(third_disk))
    check(sums[0] == sums[1],
          f"the disk restored in the third process is the second one's at its fence: "
          f"{sums[0][:16]}, {sums[1][:16]}")
# Held restored-paused for five tick periods: a guest that ran in that time
# would print, and its clock would have moved on by the time it resumes.
time.sleep(1.0)
held, _ = tctl.ask(op="status")
time.sleep(0.1)
check(held.get("state") == "restored-paused" and held.get("vcpus_parked") == int(cpus)
      and not third.outputs(r"TICK |FP "),
      f"the guest did not run while restored-paused for 1 s ({held})")
# Capture it again before it resumes: a restore must load every register
# and the platform state it was given, and a guest that has not run since
# holds them still. The awk's sums cannot show this, because a task that is
# off the CPU keeps its registers in guest RAM.
recapture = os.path.join(root, "paused-recapture")
again, _ = tctl.ask(op="checkpoint", dir=recapture, then="continue", txid="e2e-3", epoch=3)
still, _ = tctl.ask(op="status")
check(again.get("ok") is True and still.get("state") == "restored-paused"
      and still.get("vcpus_parked") == int(cpus),
      f"a checkpoint while restored-paused keeps the guest restored-paused ({still})")
if again.get("ok") is True:
    loaded = state_differences(os.path.join(root, "move-again"), recapture)
    check(not loaded, "the restore loaded the vCPU and platform state it was given"
          + (": differs in " + ", ".join(loaded) if loaded else ""))
tctl.ask(op="resume")
# A live move pauses the guest only at the end of its rounds, just before
# its reply; a checkpoint, as soon as it is asked for.
fenced2_at = fence2_at if stream else again_at
last2 = [tick(s)[0] for t, s in dst.outputs(r"TICK ") if t <= fenced2_at + 0.1]
# The guest's last uptime reading before the second fence: the last tick,
# or the end of the sleep that came after it.
uptime2 = max([tick(s)[1] for t, s in dst.outputs(r"TICK ") if t <= fenced2_at + 0.1]
              + [float(s.split()[1]) for t, s in dst.outputs(r"(?<!NANO)SLEEP-END ")], default=None)
moved = third.wait_for(r"TICK ", 10)
on = tick(moved[1])[1] - uptime2 if moved and uptime2 is not None else None
if on is not None:
    on -= downtime(third, downtime(dst))
check(status3.get("state") == "restored-paused" and moved is not None
      and tick(moved[1])[0] == last2[-1] + 1 and on is not None and on < 0.5,
      f"it resumes in a third process and counts on from {last2[-1] if last2 else None}, "
      f"its uptime {on} s on from the last reading before the move")
check(not third.outputs(r"Booting Linux|HVI-WORKLOAD-BOOT"), "the third process did not reboot it")
twice = counted_twice(dst, third)
check(not twice, f"no count was printed by both guests of the second move: {twice[:3]}")
fp_goes_on(dst, third, "over the second move")
dirty_goes_on(third, moved[0] if moved else 0.0, "after the second move")

stop, _ = dctl.ask(op="stop")
try:
    dst_rc = dst.p.wait(timeout=20)
except subprocess.TimeoutExpired:
    dst.p.kill()
    dst_rc = None
check(dst_rc == 0, f"stop ends the fenced restored guest (exit {dst_rc})")
tctl.ask(op="stop")
try:
    third_rc = third.p.wait(timeout=20)
except subprocess.TimeoutExpired:
    third.p.kill()
    third_rc = None
check(third_rc == 0, f"stop ends the guest in the third process (exit {third_rc})")
generations = None
if image:
    # The guest stopped without unmounting, so recent metadata may be in
    # the journal only, which debugfs does not replay: it may then refuse
    # the image or miss the file. Replay it on a copy first, as a mount
    # would.
    replayed = os.path.join(out, "replayed.img")
    shutil.copyfile(third_disk, replayed)
    e2fsck = os.path.join(os.path.dirname(debugfs), "e2fsck")
    subprocess.run([e2fsck if os.path.exists(e2fsck) else "e2fsck", "-fy", replayed],
                   capture_output=True)
    cat = subprocess.run([debugfs, "-R", "cat /after", replayed], capture_output=True,
                         text=True)
    os.remove(replayed)
    check(after_n is not None and cat.stdout.strip() == f"written-after {after_n}",
          f"the image holds the post-restore write: {cat.stdout.strip()!r}")
    generations = []
    for name in ("move", "move-again"):
        with open(os.path.join(root, name, "disk.json")) as f:
            generations.append(json.load(f)["generation"])
    check(0 < generations[0] < generations[1],
          f"the disk generation grows over the moves: {generations}")

bundle_bytes = sum(os.path.getsize(os.path.join(bundle, f)) for f in os.listdir(bundle))
summary = {
    "cpus": int(cpus), "mem_mib": int(mem), "disk": bool(image),
    "pause_ms": stats.get("pause_ms"), "capture_ms": stats.get("capture_ms"),
    "ram_present_bytes": stats.get("ram_present_bytes"), "bundle_bytes": stats.get("bundle_bytes"),
    "bundle_bytes_on_disk": bundle_bytes,
    "restore_to_restored_paused_ms": round(restore_ms, 1),
    "resume_reply_ms": round((resume_at - status_at) * 1000, 1),
    "downtime_fence_reply_to_resume_reply_ms": round((resume_at - fence_at) * 1000, 1),
    "downtime_checkpoint_request_to_resume_reply_ms": round((resume_at - fence_sent) * 1000, 1),
    "last_count_before": last_n, "host_sleep_s": host_sleep, "guest_sleep_s": guest_sleep,
    "guest_wall_clock_lag_s": wall_lag,
    "disk_generations": generations,
    "portable": portable, **timers,
    "stream": stream, "dirty_mib": dirty, "dirty_once_s": dirty_once, "moves": stream_moves,
    "disk_by_blocks": by_blocks, "disk_churn": churn,
    "failures": failures,
}
with open(os.path.join(out, "summary.json"), "w") as f:
    json.dump(summary, f, indent=1)
print(json.dumps(summary), flush=True)
sys.exit(1 if failures else 0)
PY

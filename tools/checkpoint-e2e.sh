#!/usr/bin/env bash
# Moves a running guest from one hvi process to another on this Mac, and
# checks that it carried on rather than rebooting.
#
# The guest runs the workload `tools/mk-initramfs.py --checkpoint-workload`
# builds: a loop that counts in a shell variable every 200 ms and prints the
# count with the guest's wall clock, a file it holds open on fd 3 after
# unlinking it, and a file it wrote and synced on an ext4 /dev/vda.
#
# 1. Boot the guest with --control-sock, --checkpoint-root, --disk,
#    --net-stub and --agent-sock, and let it count.
# 2. Checkpoint it with then=fence.
# 3. Start `hvi restore` as a second process with its own sockets, wait for
#    it to report restored-paused, and resume it. Stop the fenced source.
# 4. Check the restored guest: its count goes on from the captured one and no
#    boot banner appears; on request it reads fd 3 and the disk file, writes
#    and syncs another, and a `sleep 5` takes 5 s of host time. Its wall
#    clock goes on from the captured time.
# 5. Move it once more, into a third process, and check it counts on there.
#    Stop both, and read the file the guest wrote from the image on the
#    host.
#
# Usage:
#   tools/checkpoint-e2e.sh --hvi target/release/hvi --kernel Image \
#       --initramfs target/initramfs-workload.cpio --out DIR \
#       [--cpus 2] [--mem 512] [--no-disk]
#
# DIR receives the checkpoint root (with the bundle), the disk image, both
# processes' consoles, their profiles and summary.json with the timings.
# The disk needs mke2fs from e2fsprogs (Homebrew: brew install e2fsprogs),
# found on PATH or in /opt/homebrew/opt/e2fsprogs/sbin; without it, pass
# --no-disk. Sockets go in a short directory under /tmp, since a socket path
# is limited to 104 bytes on macOS. Exits 0 when every check passed.
set -euo pipefail

hvi="" kernel="" initramfs="" out="" cpus=2 mem=512 disk=yes
while [ $# -gt 0 ]; do
    case "$1" in
        --hvi) hvi="$2"; shift 2 ;;
        --kernel) kernel="$2"; shift 2 ;;
        --initramfs) initramfs="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --cpus) cpus="$2"; shift 2 ;;
        --mem) mem="$2"; shift 2 ;;
        --no-disk) disk=no; shift ;;
        *) echo "usage: $0 --hvi PATH --kernel PATH --initramfs PATH --out DIR [--cpus N] [--mem MIB] [--no-disk]" >&2; exit 2 ;;
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
image=""
if [ "$disk" = yes ]; then
    mke2fs="$(command -v mke2fs || echo /opt/homebrew/opt/e2fsprogs/sbin/mke2fs)"
    if [ ! -x "$mke2fs" ]; then
        echo "$0: mke2fs not found; install e2fsprogs or pass --no-disk" >&2
        exit 2
    fi
    image="$out/disk.img"
    rm -f "$image"
    "$mke2fs" -q -t ext4 -F "$image" 64M
fi
socks="$(mktemp -d /tmp/hvi-e2e.XXXXXX)"
trap 'rm -rf "$socks"' EXIT

python3 - "$hvi" "$kernel" "$initramfs" "$out" "$root" "$socks" "$cpus" "$mem" "$image" <<'PY'
import json, os, re, socket, subprocess, sys, threading, time

hvi, kernel, initramfs, out, root, socks, cpus, mem, image = sys.argv[1:]
debugfs = next(
    (p for p in [*(os.path.join(d, "debugfs") for d in os.environ.get("PATH", "").split(":")),
                 "/opt/homebrew/opt/e2fsprogs/sbin/debugfs"] if os.access(p, os.X_OK)),
    None)
t0 = time.monotonic()
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


def check(ok, what):
    print(("  ok   " if ok else "  FAIL ") + what, flush=True)
    if not ok:
        failures.append(what)


def tick(s):
    """Returns a TICK line's count, guest uptime and guest wall clock."""
    m = re.search(r"TICK (\d+) (\d+\.\d+) (\d+)", s)
    return (int(m.group(1)), float(m.group(2)), int(m.group(3))) if m else None


common = ["--net-stub"] + (["--disk", image] if image else [])
src = Guest("source", [hvi, "boot", "--kernel", kernel, "--initramfs", initramfs,
                       "--cpus", cpus, "--mem-mib", mem,
                       "--control-sock", f"{socks}/src.sock", "--checkpoint-root", root,
                       "--agent-sock", f"{socks}/src-agent.sock",
                       "--profile-out", os.path.join(out, "source-profile.json")] + common)
print(f"checkpoint e2e: {cpus} vCPU(s), {mem} MiB, disk {'yes' if image else 'no'}", flush=True)
# The guest has no RTC, so its wall clock starts at 0. Give it this host's,
# so its drift over the move can be read against the host's.
if src.wait_for(r"TICK 3 ", 120):
    src.type(f"date -s @{int(time.time())} >/dev/null\n")
ready = src.wait_for(r"TICK 15 ", 120)
check(ready is not None, "the source guest booted and counts")
if image:
    check(bool(src.outputs(r"DISK-READY written-before ")), "the source wrote and synced /mnt/before")
if not ready:
    src.p.kill()
    sys.exit(1)

# The move itself runs straight through, as a caller would run it, so its
# timings are the move's: the checks that need a pause come afterwards.
sctl = Control(src, f"{socks}/src.sock")
bundle = os.path.join(root, "move")
fence_sent = now()
fence, fence_at = sctl.ask(op="checkpoint", dir=bundle, then="fence", txid="e2e-1", epoch=1)
spawned_at = now()
dst = Guest("restored", [hvi, "restore", "--from", bundle,
                         "--control-sock", f"{socks}/dst.sock", "--checkpoint-root", root,
                         "--agent-sock", f"{socks}/dst-agent.sock",
                         "--profile-out", os.path.join(out, "restored-profile.json")] + common)
dctl = Control(dst, f"{socks}/dst.sock")
status, status_at = dctl.ask(op="status")
resumed, resume_at = dctl.ask(op="resume")

check(fence.get("ok") is True and fence.get("state") == "fenced", "checkpoint then=fence")
stats = fence.get("stats", {})
check(status.get("state") == "restored-paused", f"the restore reports restored-paused ({status})")
check(not dst.outputs(r"TICK ", after=0) or min(t for t, _ in dst.outputs(r"TICK ")) > resume_at,
      "the restored guest did not run before resume")
check(resumed.get("state") == "running", "resume")
restore_ms = (status_at - spawned_at) * 1000
before = [(t, tick(s)) for t, s in src.outputs(r"TICK ") if t <= fence_at]
last_tick_at, (last_n, last_uptime, last_wall) = before[-1]
check(not src.outputs(r"TICK ", after=fence_sent + 0.1), "the fenced source printed nothing more")
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
    host_gap = first_at - last_tick_at
    check(uptime - last_uptime < 0.5,
          f"the guest's monotonic clock goes on from the capture: {uptime - last_uptime:.2f} s "
          f"between the two ticks in the guest, {host_gap:.3f} s on the host")
    check(0 <= wall - last_wall <= 1,
          f"the guest's wall clock goes on from the captured time: {last_wall} then {wall}")
    # The policy: no realtime correction without a guest agent, so the
    # guest's wall clock now lags the host's by the time it was away.
    wall_lag = time.time() - wall
check(not dst.outputs(r"Booting Linux|HVI-WORKLOAD-BOOT|ARM64 guest on hvi|DISK-READY"),
      "no boot banner in the restored guest: it did not reboot")

dst.type("touch /tmp/go\n")
got = dst.wait_for(r"SLEEP-END ", 30)
check(got is not None, "the workload answered the request")
counter = dst.outputs(r"COUNTER ")
check(bool(counter) and int(counter[0][1].split()[1]) > last_n, f"the count after the restore: {counter[:1]}")
check(bool(dst.outputs(r"FD3 kept open after unlink$")), "the unlinked file is still readable on fd 3")
after_n = None
if image:
    check(bool(dst.outputs(r"DISK-BEFORE written-before ")), "the file written before the move is on the disk")
    written = dst.outputs(r"DISK-AFTER written-after \d+")
    check(bool(written), "a write after the restore works")
    after_n = written[0][1].split()[-1] if written else None
start, end = dst.outputs(r"SLEEP-START "), dst.outputs(r"SLEEP-END ")
if start and end:
    host_sleep = end[0][0] - start[0][0]
    guest_sleep = float(end[0][1].split()[1]) - float(start[0][1].split()[1])
    check(4.5 < host_sleep < 6.0, f"sleep 5 took {host_sleep:.2f} s of host time ({guest_sleep:.2f} s in the guest)")
else:
    host_sleep = guest_sleep = None
    check(False, "the sleep was timed")

# A restored guest is a guest like any other: move it once more.
again_at = now()
fence2, _ = dctl.ask(op="checkpoint", dir=os.path.join(root, "move-again"), then="fence",
                     txid="e2e-2", epoch=2)
check(fence2.get("state") == "fenced", "the restored guest checkpoints again")
third = Guest("restored-again", [hvi, "restore", "--from", os.path.join(root, "move-again"),
                                 "--control-sock", f"{socks}/third.sock",
                                 "--checkpoint-root", root,
                                 "--agent-sock", f"{socks}/third-agent.sock"] + common)
tctl = Control(third, f"{socks}/third.sock")
status3, _ = tctl.ask(op="status")
tctl.ask(op="resume")
last2 = [tick(s)[0] for t, s in dst.outputs(r"TICK ") if t <= again_at + 0.1]
moved = third.wait_for(r"TICK ", 10)
check(status3.get("state") == "restored-paused" and moved is not None
      and tick(moved[1])[0] == last2[-1] + 1,
      f"it resumes in a third process and counts on from {last2[-1] if last2 else None}")
check(not third.outputs(r"Booting Linux|HVI-WORKLOAD-BOOT"), "the third process did not reboot it")

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
if image and debugfs and after_n:
    cat = subprocess.run([debugfs, "-R", "cat /after", image], capture_output=True, text=True)
    check(cat.stdout.strip() == f"written-after {after_n}",
          f"the image holds the post-restore write: {cat.stdout.strip()!r}")

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
    "failures": failures,
}
with open(os.path.join(out, "summary.json"), "w") as f:
    json.dump(summary, f, indent=1)
print(json.dumps(summary), flush=True)
sys.exit(1 if failures else 0)
PY

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
# With --portable the guest boots the portable profile
# (--profile portable-arm64-v1) and the kernel must be the portable one,
# with hvi-time. The initramfs must then hold /el0check and /tfd
# (tools/mk-initramfs.py --checkpoint-workload --add el0check --add tfd;
# el0check is test/el0check.c, kept with the portable kernel's patches
# and not in this repository, and tfd is tools/guest/tfd.c, both built
# static). Just before the capture the
# script starts a 6 s timerfd and a 6 s sleep, and checks after the
# restore: the clocksource is hvi-time, el0check passes, the guest driver
# logged the migration (generation 4) and counts it, both timers fire
# after the resume 6 s of guest time after they were armed, and the
# guest's wall clock is the host's again.
#
# Usage:
#   tools/checkpoint-e2e.sh --hvi target/release/hvi --kernel Image \
#       --initramfs target/initramfs-workload.cpio --out DIR \
#       [--cpus 2] [--mem 512] [--no-disk] [--portable]
#
# DIR receives the checkpoint root (with the bundle), the disk image, both
# processes' consoles, their profiles and summary.json with the timings.
# The disk needs mke2fs and debugfs from e2fsprogs (Homebrew: brew install
# e2fsprogs), found on PATH or in /opt/homebrew/opt/e2fsprogs/sbin; without
# them, pass --no-disk. Sockets go in a short directory under /tmp, since a socket path
# is limited to 104 bytes on macOS. Exits 0 when every check passed.
set -euo pipefail

hvi="" kernel="" initramfs="" out="" cpus=2 mem=512 disk=yes portable=no
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
        *) echo "usage: $0 --hvi PATH --kernel PATH --initramfs PATH --out DIR [--cpus N] [--mem MIB] [--no-disk] [--portable]" >&2; exit 2 ;;
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
    "$debugfs" "$portable" <<'PY'
import json, os, re, socket, subprocess, sys, threading, time

hvi, kernel, initramfs, out, root, socks, cpus, mem, image, debugfs, portable = sys.argv[1:]
portable = portable == "yes"
t0 = time.monotonic()
# Host wall-clock time at monotonic time t0, to read a line's host time.
wall_t0 = time.time() - (time.monotonic() - t0)
failures = []
# Checks that fail for a known defect outside hvi, by name and defect.
expected_failures = []


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


def xfail(what, defect):
    """Reports a check that fails for a known defect outside hvi. It does
    not fail the run, and summary.json lists it."""
    print(f"  xfail {what} (expected: {defect})", flush=True)
    expected_failures.append({"check": what, "defect": defect})


def tick(s):
    """Returns a TICK line's count, guest uptime and guest wall clock."""
    m = re.search(r"TICK (\d+) (\d+\.\d+) (\d+)", s)
    return (int(m.group(1)), float(m.group(2)), int(m.group(3))) if m else None


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


common = ["--net-stub"] + (["--disk", image] if image else [])
profile = ["--profile", "portable-arm64-v1"] if portable else []
src = Guest("source", [hvi, "boot", "--kernel", kernel, "--initramfs", initramfs,
                       "--cpus", cpus, "--mem-mib", mem] + profile + [
                       "--control-sock", f"{socks}/src.sock", "--checkpoint-root", root,
                       "--agent-sock", f"{socks}/src-agent.sock",
                       "--profile-out", os.path.join(out, "source-profile.json")] + common)
print(f"checkpoint e2e: {cpus} vCPU(s), {mem} MiB, disk {'yes' if image else 'no'}, "
      f"profile {'portable-arm64-v1' if portable else 'native'}", flush=True)
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
if portable:
    # Two timers armed just before the capture, which must fire after the
    # resume, 6 s of guest time after they were armed.
    src.type("/tfd 6 &\n")
    src.type("/bin/busybox echo \"NANOSLEEP-START $(/bin/busybox cut -d' ' -f1 /proc/uptime)\"; "
             "( /bin/busybox sleep 6; /bin/busybox echo \"NANOSLEEP-END "
             "$(/bin/busybox cut -d' ' -f1 /proc/uptime)\" ) &\n")
    armed = src.wait_for(r"TIMERFD-ARMED ", 10) and src.wait_for(r"^NANOSLEEP-START [0-9]", 10)
    check(bool(armed), "a timerfd and a sleep are armed before the capture")

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
    fired = dst.wait_for(r"TIMERFD-FIRED ", 15)
    if fired:
        elapsed = float(fired[1].split()[2])
        timers["timerfd_guest_s"] = elapsed
        check(fired[0] > resume_at and 5.99 <= elapsed <= 6.3,
              f"the timerfd armed before the capture fired after the resume, {elapsed:.3f} s "
              f"of guest time after it was armed")
    else:
        check(False, "the timerfd armed before the capture fired")
    end = dst.wait_for(r"^NANOSLEEP-END [0-9]", 15)
    start = src.outputs(r"^NANOSLEEP-START [0-9]")
    if end and start:
        # /proc/uptime is CLOCK_BOOTTIME, which hvi-time moves on by the
        # downtime, as it does the wall clock.
        slept = float(end[1].split()[1]) - float(start[0][1].split()[1]) - downtime(dst)
        timers["nanosleep_guest_s"] = round(slept, 3)
        check(end[0] > resume_at and 5.97 <= slept <= 6.3,
              f"the sleep armed before the capture ended after the resume, {slept:.2f} s of "
              f"guest monotonic time after it began")
    else:
        check(False, "the sleep armed before the capture ended")

if image:
    # hvi does not consume a bundle, so the disk lock is what keeps a second
    # guest off the disk the restored one writes.
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
    check(generations == {"4"}, f"the guest driver logged the move, generation 4: {sorted(generations)}")
    snap = dst.outputs(r"EL0CHECK snapshot1: .* migrations=", after=go)
    count = int(snap[0][1].split("migrations=")[1]) if snap else None
    counted = f"the guest driver counts the move once: migrations={count} on {cpus} vCPU(s)"
    if count is not None and int(cpus) > 1 and 1 < count <= int(cpus):
        # A defect of the portable kernel's hvi-time driver: it runs its
        # migration work once for each vCPU that takes GEN_CHANGED, so it
        # logs and counts one move up to once per vCPU, and moves the wall
        # clock again each time.
        xfail(counted, "the hvi-time driver handles one generation once per vCPU")
    else:
        check(count == 1, counted)
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
fence2, _ = dctl.ask(op="checkpoint", dir=os.path.join(root, "move-again"), then="fence",
                     txid="e2e-2", epoch=2)
check(fence2.get("state") == "fenced", "the restored guest checkpoints again")
third = Guest("restored-again", [hvi, "restore", "--from", os.path.join(root, "move-again"),
                                 "--control-sock", f"{socks}/third.sock",
                                 "--checkpoint-root", root,
                                 "--agent-sock", f"{socks}/third-agent.sock"] + common)
tctl = Control(third, f"{socks}/third.sock")
status3, _ = tctl.ask(op="status")
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
last2 = [tick(s)[0] for t, s in dst.outputs(r"TICK ") if t <= again_at + 0.1]
# The guest's last uptime reading before the second fence: the last tick,
# or the end of the sleep that came after it.
uptime2 = max([tick(s)[1] for t, s in dst.outputs(r"TICK ") if t <= again_at + 0.1]
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
fp_goes_on(dst, third, "over the second move")

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
    cat = subprocess.run([debugfs, "-R", "cat /after", image], capture_output=True, text=True)
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
    "failures": failures,
    "expected_failures": expected_failures,
}
with open(os.path.join(out, "summary.json"), "w") as f:
    json.dump(summary, f, indent=1)
print(json.dumps(summary), flush=True)
sys.exit(1 if failures else 0)
PY

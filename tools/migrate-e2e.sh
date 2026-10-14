#!/usr/bin/env bash
# Moves a running portable guest from one host to another, stopped: fence
# it on the source, copy the bundle and the disk with `rsync -S`, restore
# it on the destination, resume it, and check that it carried on rather
# than rebooting. Either host may be this one ("local") or an ssh
# destination, and they may be one host. Run from the machine that holds
# the script; each host needs python3 and rsync, and the source host
# mke2fs (and e2fsck and debugfs for the checks after the move).
#
# Each host runs its half of the test itself (a driver the script copies
# there), so every console line is stamped with the clock of the host
# whose hvi printed it, never across ssh. The script here starts both
# halves, sends the fence, runs the copy, and tells the destination to
# restore.
#
# The guest is the checkpoint workload (tools/mk-initramfs.py
# --checkpoint-workload --add el0check --add tfd --add clk), on the
# portable kernel, with an ext4 disk and the stub network. The source:
#
# 1. boots it with --profile portable-arm64-v1, starts /clk (which prints
#    the guest's REALTIME, MONOTONIC and BOOTTIME in ns every 250 ms), and
#    records the Features line of /proc/cpuinfo and /proc/interrupts;
# 2. arms a 6 s timerfd and a 6 s sleep, then on the fence request
#    checkpoints the guest with then=fence and stops it.
#
# The script copies the bundle, the disk and the source's record with
# `rsync -S -a --stats`. The destination then restores the bundle onto the
# copied disk, resumes it, and checks:
#
# - the count goes on by one, the awk's sums stay exact, no boot banner;
# - MONOTONIC never steps back, and its gap over the move is one /clk
#   period: the downtime does not show;
# - after the guest driver logs generation 4, REALTIME is within 100 ms of
#   the destination host's clock;
# - the timerfd and the sleep armed before the capture fire after the
#   resume, 6 s of guest time after they were armed;
# - the workload's request (`touch /tmp/go`): the count, fd 3 (a file held
#   open after its unlink), the file written before the move, a write after
#   it, el0check, the clocksource, the driver's log and migrations=1, and a
#   `sleep 5` against the host;
# - the Features line is the one the source printed, and the hvi-time,
#   PL011 and virtio-blk interrupt counts go on from the source's and grow;
# - for --drift-secs (600 by default), REALTIME against the host's clock:
#   the offset at the start and at the end, and the drift in ppm;
# - after a stop, `e2fsck -fn` finds the image clean and debugfs reads the
#   file written after the move.
#
# --recapture checkpoints the restored guest again before the resume, with
# then=continue, and checks that its vCPU and platform state equal the
# bundle's (across backends, the registers only HVF has must be 0): the
# restore loaded what it was given. That capture is inside the downtime;
# its time is in the summary.
#
# --negative runs the refusals instead, each on the destination:
# a native bundle of the source (booted with --profile native) is refused;
# copies of the portable bundle with the vCPU count or the RAM size changed
# in profile.json and the manifest sealed again, with one byte of ram.bin
# changed, and with cpu.json cut short, are refused by checkpoint-verify
# and by restore; a restore without --disk is refused; and on a KVM
# destination, a restore and a portable boot are refused when KVM offers no
# vGICv2 (an LD_PRELOAD shim, built there with cc, fails
# KVM_CREATE_DEVICE for KVM_DEV_TYPE_ARM_VGIC_V2 with ENODEV, as a
# GICv3-only host does). --negative needs a portable bundle from an earlier
# run in --dst-dir, and for that boot the kernel and initramfs on the
# destination (--dst-kernel, --dst-initramfs; by default the source's
# paths).
#
# Usage:
#   tools/migrate-e2e.sh --src HOST --dst HOST \
#       --src-hvi PATH --dst-hvi PATH --kernel PATH --initramfs PATH \
#       --src-dir DIR --dst-dir DIR --out DIR \
#       [--cpus 1] [--mem 512] [--drift-secs 600] [--recapture]
#       [--negative [--dst-kernel PATH] [--dst-initramfs PATH]]
#
# HOST is "local" or an ssh destination. --src-hvi, --kernel, --initramfs
# and --src-dir are paths on the source host, --dst-hvi and --dst-dir on
# the destination. Each dir is emptied first; with --negative only what
# it writes there is removed, the bundle is kept. On macOS the hvi must be
# signed. Both hvi binaries must be built from one commit with no
# uncommitted changes, or the restore refuses the bundle. --out (here)
# receives each half's record and summary.json with the timings. Exits 0
# when every check passed.
set -euo pipefail

src="" dst="" src_hvi="" dst_hvi="" kernel="" initramfs="" src_dir="" dst_dir="" out=""
dst_kernel="" dst_initramfs=""
cpus=1 mem=512 drift=600 negative=no recapture=no
usage() {
    echo "usage: $0 --src HOST --dst HOST --src-hvi PATH --dst-hvi PATH --kernel PATH" \
        "--initramfs PATH --src-dir DIR --dst-dir DIR --out DIR [--cpus N] [--mem MIB]" \
        "[--drift-secs S] [--recapture] [--negative [--dst-kernel PATH]" \
        "[--dst-initramfs PATH]]" >&2
    exit 2
}
while [ $# -gt 0 ]; do
    case "$1" in
        --src) src="$2"; shift 2 ;;
        --dst) dst="$2"; shift 2 ;;
        --src-hvi) src_hvi="$2"; shift 2 ;;
        --dst-hvi) dst_hvi="$2"; shift 2 ;;
        --kernel) kernel="$2"; shift 2 ;;
        --initramfs) initramfs="$2"; shift 2 ;;
        --dst-kernel) dst_kernel="$2"; shift 2 ;;
        --dst-initramfs) dst_initramfs="$2"; shift 2 ;;
        --src-dir) src_dir="$2"; shift 2 ;;
        --dst-dir) dst_dir="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --cpus) cpus="$2"; shift 2 ;;
        --mem) mem="$2"; shift 2 ;;
        --drift-secs) drift="$2"; shift 2 ;;
        --negative) negative=yes; shift ;;
        --recapture) recapture=yes; shift ;;
        *) usage ;;
    esac
done
for v in src dst src_hvi dst_hvi kernel initramfs src_dir dst_dir out; do
    [ -n "${!v}" ] || { echo "$0: --${v//_/-} is required" >&2; exit 2; }
done
dst_kernel="${dst_kernel:-$kernel}" dst_initramfs="${dst_initramfs:-$initramfs}"
mkdir -p "$out"
out="$(cd "$out" && pwd -P)"

# The half of the test that runs on each host.
cat > "$out/migrate-leg.py" <<'LEG'
import hashlib, json, os, re, shutil, socket, subprocess, sys, tempfile, threading, time

t0 = time.monotonic()
CLK_PERIOD = 0.25
# Registers only HVF has, which a KVM capture does not hold, at 0 under the
# baseline (docs/checkpoint.md, The KVM registers).
HVF_ONLY = {"APIAKEYLO_EL1", "APIAKEYHI_EL1", "APIBKEYLO_EL1", "APIBKEYHI_EL1",
            "APDAKEYLO_EL1", "APDAKEYHI_EL1", "APDBKEYLO_EL1", "APDBKEYHI_EL1",
            "APGAKEYLO_EL1", "APGAKEYHI_EL1", "SCXTNUM_EL0", "SCXTNUM_EL1",
            "TPIDR2_EL0", "SMCR_EL1", "SMPRI_EL1"}
checks = []


def now():
    return time.monotonic() - t0


def event(kind, **data):
    """One line to the script that started this half."""
    sys.stdout.write("EVENT " + json.dumps(dict(event=kind, **data)) + "\n")
    sys.stdout.flush()


def check(ok, what):
    checks.append({"ok": bool(ok), "check": what})
    event("check", ok=bool(ok), check=what)


def tool(name):
    for d in os.environ.get("PATH", "").split(":") + [
            "/opt/homebrew/opt/e2fsprogs/sbin", "/usr/local/opt/e2fsprogs/sbin", "/sbin",
            "/usr/sbin"]:
        p = os.path.join(d, name)
        if os.access(p, os.X_OK):
            return p
    return None


class Guest:
    """One hvi process; each console line with this host's clocks."""

    def __init__(self, name, cmd, d, env=None):
        self.lines = []
        self.log = open(os.path.join(d, f"{name}.log"), "w")
        self.log.write("host: " + " ".join(cmd) + "\n")
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, env=env)
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        for raw in self.p.stdout:
            wall, t = time.time(), now()
            # The shell's prompt can lead a line another process printed.
            s = re.sub(r"^(~ # )+", "", raw.decode(errors="replace").rstrip("\r\n"))
            self.lines.append((t, wall, s))
            self.log.write(f"[{t:9.3f} {wall:.6f}] {s}\n")
            self.log.flush()

    def find(self, pattern, after=0.0):
        rx = re.compile(pattern)
        return [(t, w, s) for t, w, s in list(self.lines) if t >= after and rx.search(s)]

    def wait_for(self, pattern, timeout, after=0.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            hit = self.find(pattern, after)
            if hit:
                return hit[0]
            if self.p.poll() is not None:
                break
            time.sleep(0.02)
        return None

    def type(self, text):
        self.log.write(f"host: types {text!r}\n")
        self.p.stdin.write(text.encode())
        self.p.stdin.flush()

    def stop(self, sock):
        try:
            ask(sock, op="stop")
        except OSError:
            pass
        try:
            return self.p.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return None


def ask(path, timeout=30, **req):
    end = time.monotonic() + timeout
    while True:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(path)
            break
        except OSError:
            if time.monotonic() > end:
                raise
            time.sleep(0.005)
    f = s.makefile("rwb")
    sent_wall, sent = time.time(), now()
    f.write(json.dumps(dict(v=1, **req)).encode() + b"\n")
    f.flush()
    reply = json.loads(f.readline())
    s.close()
    return reply, sent, now(), sent_wall, time.time()


def clk(s):
    m = re.search(r"^CLK (\d+) (\d+) (\d+) (\d+)$", s)
    return tuple(int(x) for x in m.groups()) if m else None


def tick(s):
    m = re.search(r"TICK (\d+) (\d+\.\d+) (\d+)", s)
    return (int(m.group(1)), float(m.group(2))) if m else None


def irqs(g, tag, after=0.0):
    """Sums each /proc/interrupts line of snapshot `tag` over the CPUs."""
    got = {}
    for _, _, s in g.find(rf"^IRQ-{tag}\s+\d+:", after):
        f = s.split()[2:]
        n = 0
        while n < len(f) and f[n].isdigit():
            n += 1
        got[" ".join(f[n:])] = sum(int(x) for x in f[:n])
    return got


def irq_lines(profile):
    """The interrupt names of hvi-time, the PL011 and virtio-blk."""
    by = {d["kind"]: d.get("irq") for d in profile["devices"]}
    return {"hvi-time": "hvi-time", "pl011": "uart-pl011",
            "virtio-blk": f"GIC-0 {by.get('virtio-blk')} Level"}


def pick(snapshot, key):
    for name, n in snapshot.items():
        if key in name:
            return n
    return None


def probe(g, tag):
    g.type(f"/bin/busybox echo \"FEATURES-{tag} $(/bin/busybox grep -m1 Features "
           f"/proc/cpuinfo)\"; /bin/busybox sed 's/^/IRQ-{tag} /' /proc/interrupts; "
           f"/bin/busybox echo PROBE-END-{tag}\n")
    return g.wait_for(rf"^PROBE-END-{tag}$", 15)


def features(g, tag):
    hit = g.find(rf"^FEATURES-{tag} Features\s*:")
    return hit[-1][2].split(":", 1)[1].strip() if hit else None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def wait_line(what):
    line = sys.stdin.readline().strip()
    if line != what:
        event("error", error=f"expected {what!r} on stdin, got {line!r}")
        sys.exit(1)


def source(hvi, kernel, initramfs, d, cpus, mem):
    move = os.path.join(d, "move")
    root = os.path.join(move, "root")
    os.makedirs(root, mode=0o700)
    socks = tempfile.mkdtemp(prefix="hvim", dir="/tmp")
    image = os.path.join(move, "disk.img")
    mke2fs = tool("mke2fs")
    if not mke2fs:
        event("error", error="mke2fs not found on the source host")
        sys.exit(2)
    subprocess.run([mke2fs, "-q", "-t", "ext4", "-F", image, "64M"], check=True)
    sock = f"{socks}/s.sock"
    g = Guest("source", [hvi, "boot", "--kernel", kernel, "--initramfs", initramfs,
                         "--profile", "portable-arm64-v1", "--cpus", cpus, "--mem-mib", mem,
                         "--disk", image, "--net-stub", "--control-sock", sock,
                         "--checkpoint-root", root,
                         "--profile-out", os.path.join(d, "source-profile.json")], d)
    if g.wait_for(r"TICK 2 ", 120):
        # The console does not echo what the script types from here on, so
        # the echo cannot split a line the guest prints.
        g.type("/bin/busybox stty -echo\n")
        g.type("/clk 250 &\n")
    ready = g.wait_for(r"TICK 15 ", 120)
    check(ready is not None, "the source guest booted and counts")
    if not ready:
        g.p.kill()
        event("failed")
        sys.exit(1)
    check(bool(g.find(r"DISK-READY written-before ")), "the source wrote and synced /mnt/before")
    check(bool(g.find(r"EL0CHECK PASS")), "the source guest's EL0 reads the synthetic counter")
    check(bool(g.find(r"^CLOCKSOURCE hvi-time$")), "the source guest's clocksource is hvi-time")
    check(probe(g, "before") is not None, "the source printed its Features line and interrupts")
    clks = [(t, w, clk(s)) for t, w, s in g.find(r"^CLK \d+ ")]
    offsets = [w - c[1] / 1e9 for _, w, c in clks]
    g.type("/tfd 6 &\n")
    armed = g.wait_for(r"TIMERFD-ARMED [0-9]", 5)
    g.type("/bin/busybox echo \"NANOSLEEP-START $(/bin/busybox cut -d' ' -f1 /proc/uptime)\"; "
           "( /bin/busybox sleep 6; /bin/busybox echo \"NANOSLEEP-END "
           "$(/bin/busybox cut -d' ' -f1 /proc/uptime)\" ) &\n")
    armed = armed and g.wait_for(r"NANOSLEEP-START [0-9]", 5)
    check(bool(armed), "a timerfd and a sleep are armed before the capture")
    if not armed:
        # Fencing now would test nothing: the timers may fire before it.
        g.stop(sock)
        event("failed", error="the timers were not armed")
        sys.exit(1)
    event("ready")
    wait_line("fence")
    fence, sent, got, sent_wall, got_wall = ask(sock, op="checkpoint",
                                                dir=os.path.join(root, "ck"), then="fence",
                                                txid="migrate-1", epoch=1)
    check(fence.get("ok") is True and fence.get("state") == "fenced", "checkpoint then=fence")
    check(not g.find(r"TIMERFD-FIRED|NANOSLEEP-END"), "both timers were pending at the capture")
    rc = g.stop(sock)
    stopped = now()
    check(rc == 0, f"the fenced source stopped (exit {rc})")
    check(not g.find(r"^TICK ", after=got + 0.05), "the fenced source printed nothing more")
    ticks = [(t, tick(s)) for t, _, s in g.find(r"TICK \d+ ") if t <= got]
    clks = [c for _, _, c in [(t, w, clk(s)) for t, w, s in g.find(r"^CLK \d+ ")]]
    fps = [s for _, _, s in g.find(r"FP \d+ ")]
    profile = json.load(open(os.path.join(d, "source-profile.json")))
    lines = irq_lines(profile)
    before = irqs(g, "before")
    started = g.find(r"NANOSLEEP-START [0-9]")
    timerfd = g.find(r"TIMERFD-ARMED [0-9]")
    record = {
        "host": socket.gethostname(), "git_sha": profile["hvi_build"]["git_sha"],
        "backend": profile["backend"], "counter_freq_hz": profile["counter_freq_hz"],
        "fence": fence, "fence_request_wall": sent_wall, "fence_reply_wall": got_wall,
        "fence_ms": round((got - sent) * 1000, 1), "stop_ms": round((stopped - got) * 1000, 1),
        "last_tick": ticks[-1][1][0], "last_uptime": ticks[-1][1][1],
        "last_clk": clks[-1], "clks": clks[-40:], "last_fp": fps[-1] if fps else None,
        "features": features(g, "before"),
        "irqs": {k: pick(before, v) for k, v in lines.items()},
        "irq_lines": lines,
        "nanosleep_start": float(re.search(r"NANOSLEEP-START (\S+)", started[0][2]).group(1)),
        "timerfd_armed": float(re.search(r"TIMERFD-ARMED (\S+)", timerfd[0][2]).group(1)),
        "wall_offset_ms": [round(o * 1000, 3) for o in offsets[-20:]],
        "checks": checks,
    }
    with open(os.path.join(move, "source.json"), "w") as f:
        json.dump(record, f, indent=1)
    event("fenced", **{k: v for k, v in record.items() if k not in ("clks", "checks")})
    event("disk", sha256=sha256(image))
    event("done", failures=[c["check"] for c in checks if not c["ok"]])


def differences(a, b):
    """Where bundle b's vCPU and platform state differ from bundle a's,
    across backends: the registers only HVF has must be at 0."""
    load = lambda d, n: json.load(open(os.path.join(d, n)))
    why = []
    for va, vb in zip(load(a, "cpu.json")["vcpus"], load(b, "cpu.json")["vcpus"]):
        cpu = f"vcpu{va['id']}"
        for k in ("power", "regs"):
            if va.get(k) != vb.get(k):
                why.append(f"{cpu}.{k}")
        why += [f"{cpu}.q{n}" for n, (x, y) in enumerate(zip(va["simd"], vb["simd"])) if x != y]
        sa, sb = va.get("sysregs", {}), vb.get("sysregs", {})
        why += [f"{cpu}.{k}" for k in sorted(set(sa) & set(sb)) if sa[k] != sb[k]]
        for k in sorted(set(sa) ^ set(sb)):
            v = sa.get(k, sb.get(k))
            if k not in HVF_ONLY or int(v, 16) != 0:
                why.append(f"{cpu}.{k} only on one side ({v})")
    pa, pb = load(a, "platform.json"), load(b, "platform.json")
    for part in ("irq", "timer"):
        x, y = dict(pa[part]), dict(pb[part])
        x.pop("host_monotonic_at_capture_ns", None)
        y.pop("host_monotonic_at_capture_ns", None)
        why += [f"platform.{part}.{k}" for k in sorted(set(x) | set(y)) if x.get(k) != y.get(k)]
    return why


def median(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2] if xs else None


def dest(hvi, d, drift_secs, recapture):
    move = os.path.join(d, "move")
    root = os.path.join(d, "root2")
    socks = tempfile.mkdtemp(prefix="hvim", dir="/tmp")
    sock = f"{socks}/d.sock"
    event("waiting")
    wait_line("go")
    go = now()
    os.makedirs(root, mode=0o700, exist_ok=True)
    src = json.load(open(os.path.join(move, "source.json")))
    bundle, image = os.path.join(move, "root", "ck"), os.path.join(move, "disk.img")
    g = Guest("dest", [hvi, "restore", "--from", bundle, "--disk", image, "--net-stub",
                       "--control-sock", sock, "--checkpoint-root", root,
                       "--profile-out", os.path.join(d, "dest-profile.json")], d)
    status, _, status_at, _, _ = ask(sock, op="status")
    recaptured = None
    if recapture:
        # Capture the guest again before it runs, and compare the state with
        # the bundle's: the restore loaded what it was given. Its time is
        # inside the downtime, and reported apart.
        recap = os.path.join(root, "recap")
        again, sent, got, _, _ = ask(sock, op="checkpoint", dir=recap, then="continue",
                                     txid="migrate-2", epoch=2)
        still = ask(sock, op="status")[0]
        why = differences(bundle, recap) if again.get("ok") else ["no capture"]
        recaptured = {"ms": round((got - sent) * 1000, 1), "differences": why}
        check(again.get("ok") is True and still.get("state") == "restored-paused" and not why,
              "a capture before the resume holds the bundle's vCPU and platform state"
              + (": differs in " + ", ".join(why) if why else ""))
    resumed, _, resume_at, _, resume_wall = ask(sock, op="resume")
    event("resumed", restore_ms=round((status_at - go) * 1000, 1),
          resume_ms=round((resume_at - status_at) * 1000, 1), resume_reply_wall=resume_wall)
    check(status.get("state") == "restored-paused", f"the restore reports restored-paused ({status})")
    check(resumed.get("state") == "running", "resume")

    first = g.wait_for(r"TICK \d+ ", 15)
    check(first is not None and tick(first[2])[0] == src["last_tick"] + 1,
          f"the count goes on: last before {src['last_tick']}, "
          f"first after {tick(first[2])[0] if first else None}")
    fixed = g.wait_for(r"hvi-time: generation 4: ", 15)
    check(fixed is not None, f"the guest driver took the new generation: {fixed[2] if fixed else None}")
    fired = g.wait_for(r"TIMERFD-FIRED [0-9.]+ [0-9.]+", 15)
    elapsed = (float(re.search(r"TIMERFD-FIRED \S+ (\S+)", fired[2]).group(1))
               if fired else None)
    check(fired is not None and fired[0] > resume_at and 5.99 <= elapsed <= 6.3,
          f"the timerfd armed before the capture fired after the resume, {elapsed} s of guest "
          f"time after it was armed")
    end = g.wait_for(r"NANOSLEEP-END [0-9.]+", 15)
    moved = None
    published = g.wait_for(r"published generation .* downtime total \d+ ns", 5)
    if published:
        moved = int(re.search(r"downtime total (\d+) ns", published[2]).group(1)) / 1e9
    slept = (float(re.search(r"NANOSLEEP-END (\S+)", end[2]).group(1))
             - src["nanosleep_start"] - (moved or 0) if end else None)
    check(end is not None and end[0] > resume_at and slept is not None and 5.97 <= slept <= 6.3,
          f"the sleep armed before the capture ended after the resume, {slept} s of guest "
          f"monotonic time after it began")
    check(probe(g, "after") is not None, "the restored guest printed its Features line and "
          "interrupts")
    g.type("touch /tmp/go\n")
    done = g.wait_for(r"(?<!NANO)SLEEP-END ", 40)
    check(done is not None, "the workload answered the request")
    counter = g.find(r"^COUNTER \d+")
    check(bool(counter) and int(counter[0][2].split()[1]) > src["last_tick"],
          f"the count after the restore: {counter[0][2] if counter else None}")
    check(bool(g.find(r"^FD3 kept open after unlink$")), "the unlinked file is readable on fd 3")
    check(bool(g.find(r"^DISK-BEFORE written-before ")), "the file written before the move is "
          "on the disk")
    written = g.find(r"^DISK-AFTER written-after \d+")
    check(bool(written), "a write after the restore works")
    after_n = written[0][2].split()[-1] if written else None
    check(bool(g.find(r"EL0CHECK PASS", after=go)), "after the restore, el0check passes")
    check(bool(g.find(r"^CLOCKSOURCE hvi-time$", after=go)), "the clocksource is still hvi-time")
    logged = g.find(r"^MIGRATION .*hvi-time: generation \d+:")
    gens = sorted({re.search(r"generation (\d+):", s).group(1) for _, _, s in logged})
    check(gens == ["4"], f"the driver logged the move, generation 4: {gens}")
    snap = g.find(r"EL0CHECK snapshot1: .* migrations=", after=go)
    count = int(snap[-1][2].split("migrations=")[1]) if snap else None
    check(count == 1, f"the driver counts the move once: migrations={count}")
    rate = re.search(r"counter (\d+) Hz", fixed[2]).group(1) if fixed else None
    sleep = (g.find(r"(?<!NANO)SLEEP-START "), g.find(r"(?<!NANO)SLEEP-END "))
    host_sleep = sleep[1][0][0] - sleep[0][0][0] if sleep[0] and sleep[1] else None
    check(host_sleep is not None and 4.9 < host_sleep < 5.5,
          f"sleep 5 took {host_sleep} s of host time")
    check(not g.find(r"Booting Linux|HVI-WORKLOAD-BOOT|ARM64 guest on hvi|DISK-READY"),
          "no boot banner: the guest did not reboot")
    fps = g.find(r"FP \d+ ")
    bad = g.find(r"FP-BAD")
    check(not bad and bool(fps) and src["last_fp"] is not None
          and int(fps[0][2].split()[1]) == int(src["last_fp"].split()[1]) + 500000,
          f"the awk's sums go on: last before {src['last_fp']}, first after "
          f"{fps[0][2] if fps else None}")
    feat = features(g, "after")
    check(feat is not None and feat == src["features"],
          f"the Features line is the source's: {feat!r}")
    probe2 = probe(g, "later")
    before = src["irqs"]
    after = {k: pick(irqs(g, "after"), v) for k, v in src["irq_lines"].items()}
    later = {k: pick(irqs(g, "later"), v) for k, v in src["irq_lines"].items()}
    for k in ("hvi-time", "pl011", "virtio-blk"):
        b, a, l = before.get(k), after.get(k), later.get(k)
        check(probe2 is not None and None not in (b, a, l) and b <= a < l,
              f"{k} interrupts go on and grow: {b} before the move, {a} and {l} after")

    # The clocks against this host's.
    deadline = time.monotonic() + drift_secs
    while time.monotonic() < deadline:
        left = deadline - time.monotonic()
        time.sleep(min(60, max(0, left)))
        recent = g.find(r"^CLK \d+ ", after=now() - 5)
        last = recent[-1] if recent else None
        event("drift", left_s=round(max(0, deadline - time.monotonic())),
              offset_ms=round((last[1] - clk(last[2])[1] / 1e9) * 1000, 3) if last else None)
    clks = [(t, w, clk(s)) for t, w, s in g.find(r"^CLK \d+ ")]
    joined = [tuple(c) for c in src["clks"]] + [c for _, _, c in clks]
    seq = all(b[0] == a[0] + 1 for a, b in zip(joined, joined[1:]))
    mono_ok = all(b[2] > a[2] for a, b in zip(joined, joined[1:]))
    check(seq and mono_ok, f"/clk printed every line and MONOTONIC never stepped back over "
          f"{len(joined)} lines")
    gap = (clks[0][2][2] - src["last_clk"][2]) / 1e9 if clks else None
    real_jump = (clks[0][2][1] - src["last_clk"][1]) / 1e9 if clks else None
    check(gap is not None and 0 < gap < CLK_PERIOD + 0.25,
          f"MONOTONIC across the move: {gap} s between the last line before and the first "
          f"after (REALTIME {real_jump} s): the downtime does not show")
    after_fix = [(t, w, c) for t, w, c in clks if fixed and t >= fixed[0] + 0.5]
    offsets = [(t, w - c[1] / 1e9) for t, w, c in after_fix]
    worst = max((abs(o) for _, o in offsets[:40]), default=None)
    typical = median([abs(o) for _, o in offsets[:40]])
    check(worst is not None and worst < 0.1,
          f"REALTIME after the fix-up is within 100 ms of this host's: worst "
          f"{worst * 1000 if worst is not None else None} ms over the first 10 s, "
          f"median {typical * 1000 if typical is not None else None} ms")
    span = offsets[-1][0] - offsets[0][0] if offsets else 0
    start_off = median([o for t, o in offsets if t <= offsets[0][0] + 10]) if offsets else None
    end_off = median([o for t, o in offsets if t >= offsets[-1][0] - 10]) if offsets else None
    # Offsets are the host's clock less the guest's: a guest that runs slow
    # lets them grow, and its drift is negative.
    drift_ppm = (-(end_off - start_off) / span * 1e6) if offsets and span > 0 else None
    check(end_off is not None and abs(end_off) < 0.1,
          f"REALTIME after {span:.0f} s is within 100 ms of this host's: "
          f"{end_off * 1000 if end_off is not None else None} ms")

    # Unmount the disk, so that the image a stop leaves is clean.
    g.type("/bin/busybox sync; /bin/busybox umount /mnt && /bin/busybox echo DISK-UNMOUNTED\n")
    check(g.wait_for(r"^DISK-UNMOUNTED$", 15) is not None, "the guest unmounted its disk")
    rc = g.stop(sock)
    check(rc == 0, f"stop ends the restored guest (exit {rc})")
    e2fsck, debugfs = tool("e2fsck"), tool("debugfs")
    fsck = subprocess.run([e2fsck, "-fn", image], capture_output=True, text=True) if e2fsck else None
    check(fsck is not None and fsck.returncode == 0, f"e2fsck -fn finds the image clean "
          f"(exit {fsck.returncode if fsck else None})")
    cat = subprocess.run([debugfs, "-R", "cat /after", image], capture_output=True,
                         text=True) if debugfs else None
    check(cat is not None and after_n is not None and cat.stdout.strip() == f"written-after {after_n}",
          f"the image holds the post-restore write: {cat.stdout.strip() if cat else None!r}")
    profile = json.load(open(os.path.join(d, "dest-profile.json")))
    record = {
        "host": socket.gethostname(), "git_sha": profile["hvi_build"]["git_sha"],
        "backend": profile["backend"], "counter_freq_hz": profile["counter_freq_hz"],
        "restore_ms": round((status_at - go) * 1000, 1),
        "resume_ms": round((resume_at - status_at) * 1000, 1),
        "resume_reply_wall": resume_wall,
        "guest_downtime_s": moved, "driver_rate_hz": rate,
        "timerfd_guest_s": elapsed, "nanosleep_guest_s": slept, "host_sleep_s": host_sleep,
        "mono_gap_s": gap, "realtime_jump_s": real_jump,
        "realtime_worst_first_10s_ms": worst * 1000 if worst is not None else None,
        "realtime_median_first_10s_ms": typical * 1000 if typical is not None else None,
        "realtime_offset_start_ms": start_off * 1000 if start_off is not None else None,
        "realtime_offset_end_ms": end_off * 1000 if end_off is not None else None,
        "drift_window_s": round(span, 1), "guest_drift_ppm": drift_ppm,
        "offset_series_ms": [(round(t - offsets[0][0]), round(o * 1000, 3))
                             for n, (t, o) in enumerate(offsets) if n % 240 == 0],
        "recapture": recaptured,
        "features": feat, "irqs_before": before, "irqs_after": after, "irqs_later": later,
        "checks": checks,
    }
    with open(os.path.join(d, "dest.json"), "w") as f:
        json.dump(record, f, indent=1)
    event("done", record=record, failures=[c["check"] for c in checks if not c["ok"]])


def native(hvi, kernel, initramfs, d, cpus, mem):
    """Boots the native profile and fences it into d/native/root/ck."""
    root = os.path.join(d, "native", "root")
    os.makedirs(root, mode=0o700)
    socks = tempfile.mkdtemp(prefix="hvim", dir="/tmp")
    sock = f"{socks}/n.sock"
    g = Guest("native", [hvi, "boot", "--kernel", kernel, "--initramfs", initramfs,
                         "--cpus", cpus, "--mem-mib", mem, "--net-stub",
                         "--control-sock", sock, "--checkpoint-root", root], d)
    check(g.wait_for(r"TICK 5 ", 120) is not None, "the native guest booted and counts")
    fence = ask(sock, op="checkpoint", dir=os.path.join(root, "ck"), then="fence")[0]
    check(fence.get("state") == "fenced", "the native guest fenced")
    check(g.stop(sock) == 0, "the native guest stopped")
    event("done", failures=[c["check"] for c in checks if not c["ok"]])


def reseal(b):
    """Writes the manifest of bundle b again for its components as they are."""
    mpath = os.path.join(b, "manifest.json")
    m = json.load(open(mpath))
    for c in m["components"]:
        p = os.path.join(b, c["path"])
        c["size"], c["sha256"] = os.path.getsize(p), sha256(p)
        if c["name"] == "profile":
            m["profile_sha256"] = c["sha256"]
    with open(mpath, "w") as f:
        json.dump(m, f, indent=2)


SHIM = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <linux/kvm.h>
#include <stdarg.h>
#include <sys/ioctl.h>
/* Fails KVM_CREATE_DEVICE for a vGICv2 as a GICv3-only host does. */
int ioctl(int fd, unsigned long req, ...)
{
	static int (*real)(int, unsigned long, ...);
	va_list ap;
	void *arg;

	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (!real)
		real = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
	if (req == KVM_CREATE_DEVICE &&
	    ((struct kvm_create_device *)arg)->type == KVM_DEV_TYPE_ARM_VGIC_V2) {
		errno = ENODEV;
		return -1;
	}
	return real(fd, req, arg);
}
"""


def refuse(hvi, d, kernel, initramfs):
    """Runs each refusal on this host."""
    results = []
    socks = tempfile.mkdtemp(prefix="hvin", dir="/tmp")
    good = os.path.join(d, "move", "root", "ck")
    image = os.path.join(d, "move", "disk.img")
    neg = os.path.join(d, "neg")
    shutil.rmtree(neg, ignore_errors=True)
    os.makedirs(neg, mode=0o700)

    def restore(name, bundle, flags, env=None, want=""):
        cmd = [hvi, "restore", "--from", bundle, "--control-sock", f"{socks}/{name}.sock",
               "--checkpoint-root", neg] + flags
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=120, env=env)
        err = r.stderr.strip().splitlines()
        reasons = [l.strip() for l in err if l.strip().startswith("- ") or "cannot" in l
                   or "refus" in l or "needs" in l or "mismatch" in l or "error" in l.lower()]
        ok = r.returncode != 0 and want in r.stderr and not os.path.exists(f"{socks}/{name}.sock")
        results.append({"case": name, "command": "restore", "exit": r.returncode,
                        "stderr": err[-12:], "ok": ok})
        check(ok, f"{name}: restore refused (exit {r.returncode}): "
              + " | ".join(reasons[-6:] or err[-3:]))

    def verify(name, bundle, want_fail=True):
        r = subprocess.run([hvi, "checkpoint-verify", bundle], capture_output=True, text=True)
        tail = (r.stdout + r.stderr).strip().splitlines()[-2:]
        ok = (r.returncode != 0) == want_fail
        results.append({"case": name, "command": "checkpoint-verify", "exit": r.returncode,
                        "output": tail, "ok": ok})
        check(ok, f"{name}: checkpoint-verify exit {r.returncode}: {' | '.join(tail)}")

    def copy(name):
        b = os.path.join(neg, name)
        shutil.copytree(good, b)
        return b

    flags = ["--disk", image, "--net-stub"]
    nat = os.path.join(d, "native", "root", "ck")
    if os.path.isdir(nat):
        restore("native-bundle", nat, ["--net-stub"], want="this host cannot resume the bundle")
    b = copy("vcpus-2")
    p = json.load(open(os.path.join(b, "profile.json")))
    p["vcpus"] = 2
    json.dump(p, open(os.path.join(b, "profile.json"), "w"), separators=(",", ":"))
    reseal(b)
    verify("vcpus-2", b)
    restore("vcpus-2", b, flags)
    b = copy("mem-1024")
    p = json.load(open(os.path.join(b, "profile.json")))
    p["ram_regions"][0]["size"] = 1024 << 20
    json.dump(p, open(os.path.join(b, "profile.json"), "w"), separators=(",", ":"))
    reseal(b)
    verify("mem-1024", b)
    restore("mem-1024", b, flags)
    b = copy("ram-byte")
    with open(os.path.join(b, "ram.bin"), "r+b") as f:
        f.seek(os.path.getsize(os.path.join(b, "ram.bin")) // 2)
        x = f.read(1)
        f.seek(-1, 1)
        f.write(bytes([x[0] ^ 0x01]))
    verify("ram-byte", b)
    restore("ram-byte", b, flags)
    b = copy("cpu-short")
    with open(os.path.join(b, "cpu.json"), "r+b") as f:
        f.truncate(os.path.getsize(os.path.join(b, "cpu.json")) // 2)
    verify("cpu-short", b)
    restore("cpu-short", b, flags)
    restore("no-disk", good, ["--net-stub"], want="--disk")
    if sys.platform.startswith("linux") and os.path.exists("/dev/kvm"):
        src = os.path.join(neg, "novgicv2.c")
        so = os.path.join(neg, "novgicv2.so")
        open(src, "w").write(SHIM)
        cc = subprocess.run(["cc", "-O2", "-shared", "-fPIC", "-o", so, src, "-ldl"],
                            capture_output=True, text=True)
        check(cc.returncode == 0, f"built the no-vGICv2 shim: {cc.stderr.strip()[-200:]}")
        env = dict(os.environ, LD_PRELOAD=so)
        restore("no-vgicv2", good, flags, env=env, want="vGICv2")
        r = subprocess.run([hvi, "boot", "--kernel", kernel, "--initramfs", initramfs,
                            "--profile", "portable-arm64-v1", "--net-stub"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=60, env=env)
        err = r.stderr.strip().splitlines()
        ok = r.returncode != 0 and "vGICv2" in r.stderr
        results.append({"case": "no-vgicv2", "command": "boot", "exit": r.returncode,
                        "stderr": err[-4:], "ok": ok})
        check(ok, f"no-vgicv2: portable boot refused (exit {r.returncode}): {err[-1] if err else ''}")
    json.dump(results, open(os.path.join(d, "negative.json"), "w"), indent=1)
    event("done", results=results, failures=[c["check"] for c in checks if not c["ok"]])


if __name__ == "__main__":
    role, args = sys.argv[1], sys.argv[2:]
    if role == "source":
        source(*args)
    elif role == "dest":
        dest(args[0], args[1], float(args[2]), args[3] == "yes")
    elif role == "native":
        native(*args)
    elif role == "refuse":
        refuse(*args)
    elif role == "clock":
        print(f"{time.time():.6f}")
LEG

python3 - "$out" "$src" "$dst" "$src_hvi" "$dst_hvi" "$kernel" "$initramfs" "$src_dir" \
    "$dst_dir" "$cpus" "$mem" "$drift" "$negative" "$recapture" "$dst_kernel" "$dst_initramfs" \
    <<'PY'
import json, os, subprocess, sys, threading, time

(out, src, dst, src_hvi, dst_hvi, kernel, initramfs, src_dir, dst_dir, cpus, mem, drift,
 negative, recapture, dst_kernel, dst_initramfs) = sys.argv[1:]
leg_local = os.path.join(out, "migrate-leg.py")
failures = []
t0 = time.monotonic()
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=15",
       "-o", "ServerAliveCountMax=8"]


def say(s):
    print(f"[{time.monotonic() - t0:8.3f}] {s}", flush=True)


def run(host, cmd, **kw):
    """Runs a shell command on host, here or over ssh."""
    if host == "local":
        return subprocess.run(["sh", "-c", cmd], **kw)
    return subprocess.run(SSH + [host, cmd], **kw)


def prepare(host, d, wipe):
    """Empties d, or with wipe a list of names, only those, and copies the
    driver there."""
    gone = " ".join(f"'{d}/{w}'" for w in wipe) if wipe else f"'{d}'"
    run(host, f"rm -rf {gone} && mkdir -p '{d}'", check=True)
    if host == "local":
        subprocess.run(["cp", leg_local, d], check=True)
    else:
        subprocess.run(["scp", "-q", leg_local, f"{host}:{d}/"], check=True)


class Leg:
    """One half of the test, running on its host."""

    def __init__(self, name, host, d, args):
        self.name, self.events, self.cond = name, [], threading.Condition()
        cmd = ["python3", "-u", f"{d}/migrate-leg.py"] + args
        if host != "local":
            cmd = SSH + [host, " ".join(f"'{a}'" for a in cmd)]
        self.log = open(os.path.join(out, f"{name}.events"), "w")
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        for line in self.p.stdout:
            self.log.write(line)
            self.log.flush()
            if not line.startswith("EVENT "):
                say(f"{self.name}: {line.rstrip()}")
                continue
            e = json.loads(line[6:])
            e["_at"] = time.monotonic() - t0
            if e["event"] == "check":
                say(f"{self.name}: {'  ok  ' if e['ok'] else '  FAIL'} {e['check']}")
                if not e["ok"]:
                    failures.append(f"{self.name}: {e['check']}")
            elif e["event"] == "drift":
                say(f"{self.name}: drift, {e['left_s']} s left, offset {e['offset_ms']} ms")
            elif e["event"] not in ("done",):
                say(f"{self.name}: {e['event']}")
            with self.cond:
                self.events.append(e)
                self.cond.notify_all()
        with self.cond:
            self.events.append({"event": "exit", "_at": time.monotonic() - t0})
            self.cond.notify_all()

    def wait(self, kind, timeout=1800):
        end = time.monotonic() + timeout
        with self.cond:
            while True:
                for e in self.events:
                    if e["event"] == kind:
                        return e
                    if e["event"] in ("exit", "error", "failed") and kind != "exit":
                        raise SystemExit(f"{self.name} ended before {kind}: {e}")
                left = end - time.monotonic()
                if left <= 0:
                    raise SystemExit(f"{self.name}: no {kind} in {timeout} s")
                self.cond.wait(left)

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()


def clock_offset(host):
    """Returns this host's wall clock less host's, and the round trip it was
    read in: the shortest of 20 over one ssh session. 0 for this host."""
    if host == "local":
        return 0.0, 0.0
    p = subprocess.Popen(SSH + [host, "python3 -u -c \"import sys, time\n"
                                "for _ in sys.stdin: print('%.6f' % time.time(), flush=True)\""],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    best = None
    for _ in range(20):
        a = time.time()
        p.stdin.write("t\n")
        p.stdin.flush()
        there = float(p.stdout.readline())
        b = time.time()
        if best is None or b - a < best[1]:
            best = ((a + b) / 2 - there, b - a)
    p.stdin.close()
    p.wait()
    return round(best[0], 6), round(best[1], 6)


def rsync(what_src, what_dst):
    """Copies src_dir/what_src/ to dst_dir/what_dst/ with rsync -S, run
    here when either end is this host and on the source otherwise, and
    returns the seconds, its stats and the command."""
    a = f"{src_dir}/{what_src}/"
    b = f"{dst_dir}/{what_dst}/"
    if src == "local" and dst == "local":
        cmd = ["rsync", "-S", "-a", "--stats", a, b]
    elif src == dst:
        cmd = SSH + [src, f"rsync -S -a --stats '{a}' '{b}'"]
    elif src == "local":
        cmd = ["rsync", "-S", "-a", "--stats", a, f"{dst}:{b}"]
    elif dst == "local":
        cmd = ["rsync", "-S", "-a", "--stats", f"{src}:{a}", b]
    else:
        cmd = SSH + [src, f"rsync -S -a --stats '{a}' '{dst}:{b}'"]
    say("copy: " + " ".join(cmd))
    start = time.monotonic()
    r = subprocess.run(cmd, capture_output=True, text=True)
    secs = time.monotonic() - start
    stats = {}
    for line in r.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            stats[k.strip()] = v.strip()
    if r.returncode != 0:
        raise SystemExit(f"rsync failed ({r.returncode}): {r.stderr.strip()}")
    return secs, stats, " ".join(cmd)


def num(s):
    return int(s.split()[0].replace(",", "")) if s else None


offsets = {"src": clock_offset(src), "dst": clock_offset(dst)}
say(f"clock offsets (here less host, round trip): {offsets}")
# --negative uses the bundle an earlier run left in --dst-dir.
keep = ["native", "neg"] if negative == "yes" else None
prepare(src, src_dir, keep)
prepare(dst, dst_dir, keep)
summary = {"src": src, "dst": dst, "cpus": int(cpus), "mem_mib": int(mem),
           "clock_offsets_s": offsets}

if negative == "yes":
    nat = Leg("native", src, src_dir, ["native", src_hvi, kernel, initramfs, src_dir, cpus, mem])
    nat.wait("done", 300)
    nat.p.wait()
    rsync("native", "native")
    ref = Leg("refuse", dst, dst_dir, ["refuse", dst_hvi, dst_dir, dst_kernel, dst_initramfs])
    summary["negative"] = ref.wait("done", 900)["results"]
    ref.p.wait()
else:
    source = Leg("source", src, src_dir, ["source", src_hvi, kernel, initramfs, src_dir, cpus,
                                          mem])
    dest = Leg("dest", dst, dst_dir, ["dest", dst_hvi, dst_dir, drift, recapture])
    source.wait("ready", 300)
    dest.wait("waiting", 60)
    fence_sent = time.monotonic()
    source.send("fence")
    fenced = source.wait("fenced", 120)
    fenced_at = time.monotonic()
    copy_s, stats, copy_cmd = rsync("move", "move")
    say(f"copy: {copy_s:.3f} s, {stats.get('Total file size')} in files")
    go_at = time.monotonic()
    dest.send("go")
    resumed = dest.wait("resumed", 120)
    resumed_at = time.monotonic()
    disk = source.wait("disk", 120)
    source.wait("done", 120)
    done = dest.wait("done", float(drift) + 600)
    rec = done["record"]
    down_wall = ((rec["resume_reply_wall"] + offsets["dst"][0])
                 - (fenced["fence_request_wall"] + offsets["src"][0]))
    # rsync 3 and openrsync name their totals differently; the bytes on
    # the wire are what this end sent or received, whichever is larger.
    sent = max(num(stats.get("Total bytes sent") or stats.get("Total sent")) or 0,
               num(stats.get("Total bytes received") or stats.get("Total received")) or 0)
    size = num(stats.get("Total file size"))
    summary.update({
        "git_sha": {"src": fenced["git_sha"], "dst": rec["git_sha"]},
        "backend": {"src": fenced["backend"], "dst": rec["backend"]},
        "counter_freq_hz": {"src": fenced["counter_freq_hz"], "dst": rec["counter_freq_hz"]},
        "source_wall_offset_ms": fenced["wall_offset_ms"],
        "pause_ms": fenced["fence"]["stats"].get("pause_ms"),
        "capture_ms": fenced["fence"]["stats"].get("capture_ms"),
        "ram_present_bytes": fenced["fence"]["stats"].get("ram_present_bytes"),
        "bundle_bytes": fenced["fence"]["stats"].get("bundle_bytes"),
        "fence_reply_ms": fenced["fence_ms"], "source_stop_ms": fenced["stop_ms"],
        "copy_s": round(copy_s, 3), "copy_command": copy_cmd,
        "copy_file_bytes": size, "copy_bytes_on_wire": sent, "copy_stats": stats,
        "copy_mb_per_s_on_wire": round(sent / copy_s / 1e6, 2) if sent else None,
        "copy_mb_per_s_files": round(size / copy_s / 1e6, 2) if size else None,
        "restore_to_restored_paused_ms": rec["restore_ms"], "resume_reply_ms": rec["resume_ms"],
        "downtime_here_s": round(resumed_at - fence_sent, 3),
        "downtime_wall_s": round(down_wall, 3),
        "guest_downtime_s": rec["guest_downtime_s"],
        "source_disk_sha256": disk["sha256"],
        "dest": rec,
    })
    source.p.wait()
    dest.p.wait()

summary["failures"] = failures
with open(os.path.join(out, "summary.json"), "w") as f:
    json.dump(summary, f, indent=1)
print(json.dumps({k: v for k, v in summary.items() if k not in ("dest", "negative")}), flush=True)
sys.exit(1 if failures else 0)
PY

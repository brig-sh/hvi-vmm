#!/usr/bin/env python3
"""Checks hvi-time's publish after a host sleep on a running portable guest.

Boots the portable profile with the workload initramfs and starts `/clk 50`,
which prints the guest's REALTIME, MONOTONIC and BOOTTIME every 50 ms. Each
console line is stamped with this host's wall clock on receipt. Then:

- `--mode hook` sets `HVI_TIME_TEST_SLEEP=<at>,<secs>`: `<at>` seconds after
  the device is made, the host wall clock and sleep clock as hvi reads them
  move `<secs>` ahead. To hvi that is a sleep of `<secs>` with the guest's
  counter stopped. The checks: hvi logs one `the host slept` line, the guest
  driver logs the publish once and counts it in `host_sleeps`, not in
  `migrations`, the guest's REALTIME reads host + `<secs>` within a second of
  the publish and stays there, and MONOTONIC never goes back.
- `--mode sigstop` stops the hvi process for `<stop>` seconds. That is not a
  sleep: the guest's counter runs on with the host's wall clock. The checks:
  nothing is published, the generation and both counts stay, the guest's
  REALTIME reads the host's once the console has drained, and MONOTONIC never
  goes back.

The initramfs is the one tools/migrate-e2e.sh uses: `tools/mk-initramfs.py
--checkpoint-workload --add el0check --add tfd --add clk`. A kernel without
the fourth patch of the hvi-time series has no `host_sleeps`; the script
then reports it as missing and fails.

Usage:
    tools/sleep-e2e.py --mode hook|sigstop --hvi PATH --kernel Image \\
        --initramfs initramfs-migrate.cpio --out DIR [--cpus 2] [--mem 512] \\
        [--at 25] [--secs 30] [--stop 10]

DIR receives console.log (each line stamped with the seconds since the start
and the host's wall clock) and summary.json. Exits 0 when every check passed.
"""
import argparse
import json
import os
import re
import signal
import statistics
import subprocess
import sys
import threading
import time

ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
ap.add_argument("--mode", choices=["hook", "sigstop"], required=True)
ap.add_argument("--hvi", required=True)
ap.add_argument("--kernel", required=True)
ap.add_argument("--initramfs", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--cpus", default="2")
ap.add_argument("--mem", default="512")
ap.add_argument("--at", type=float, default=25.0)
ap.add_argument("--secs", type=float, default=30.0)
ap.add_argument("--stop", type=float, default=10.0)
args = ap.parse_args()

os.makedirs(args.out, exist_ok=True)
log = open(os.path.join(args.out, "console.log"), "w")
lines = []
env = dict(os.environ)
env.pop("HVI_TIME_TEST_SLEEP", None)
if args.mode == "hook":
    env["HVI_TIME_TEST_SLEEP"] = f"{args.at},{args.secs}"
cmd = [args.hvi, "boot", "--kernel", args.kernel, "--initramfs", args.initramfs,
       "--profile", "portable-arm64-v1", "--cpus", args.cpus, "--mem-mib", args.mem]
log.write("host: " + " ".join(cmd) + f" (mode {args.mode})\n")
t0 = time.time()
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, env=env)


def read():
    for raw in p.stdout:
        w = time.time()
        s = re.sub(r"^(~ # )+", "", raw.decode(errors="replace").rstrip("\r\n"))
        lines.append((w, s))
        log.write(f"[{w - t0:9.3f} {w:.6f}] {s}\n")
        log.flush()


threading.Thread(target=read, daemon=True).start()


def find(rx, after=0.0):
    r = re.compile(rx)
    return [(w, s) for w, s in list(lines) if w >= after and r.search(s)]


def wait_for(rx, timeout, after=0.0):
    end = time.time() + timeout
    while time.time() < end:
        hit = find(rx, after)
        if hit:
            return hit[0]
        time.sleep(0.02)
    return None


def type_(text):
    log.write(f"host: types {text!r}\n")
    p.stdin.write(text.encode())
    p.stdin.flush()


def snapshot(tag):
    mark = time.time()
    type_(f"echo SNAP-{tag} $(/bin/busybox cat /sys/kernel/hvi_time/snapshot)\n")
    hit = wait_for(rf"^SNAP-{tag} ", 10, mark)
    return hit[1] if hit else None


def field(snap, name):
    m = re.search(rf"\b{name}=(\d+)", snap or "")
    return int(m.group(1)) if m else None


failures = []
summary = {"mode": args.mode, "cpus": int(args.cpus), "mem_mib": int(args.mem),
           "kernel": args.kernel, "initramfs": args.initramfs}


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what, flush=True)
    if not ok:
        failures.append(what)


event_at = resumed = None
try:
    if not wait_for(r"TICK 2 ", 120):
        sys.exit("sleep e2e: the workload never printed TICK 2")
    type_("/bin/busybox stty -echo\n")
    time.sleep(0.5)
    type_("/clk 50 &\n")
    if not wait_for(r"^CLK \d+ ", 10):
        sys.exit("sleep e2e: /clk printed nothing")
    summary["snapshot_before"] = snapshot("before")
    if args.mode == "hook":
        event_at = t0 + args.at
        if time.time() > event_at - 2:
            sys.exit(f"sleep e2e: the guest was not ready {args.at} s after the start")
        time.sleep(max(0.0, event_at + 8 - time.time()))
    else:
        time.sleep(3)
        event_at = time.time()
        os.kill(p.pid, signal.SIGSTOP)
        time.sleep(args.stop)
        os.kill(p.pid, signal.SIGCONT)
        resumed = time.time()
        summary["stopped_s"] = round(resumed - event_at, 3)
        time.sleep(5)
    summary["snapshot_after"] = snapshot("after")
    mark = time.time()
    type_("/bin/busybox dmesg | /bin/busybox grep 'hvi-time: generation' | "
          "/bin/busybox sed 's/^/MIG /'; echo MIG-END\n")
    wait_for(r"^MIG-END", 10, mark)
    summary["driver_lines"] = [s for _, s in find(r"^MIG ")]
    summary["hvi_lines"] = [s for _, s in find(r"hvi-time: the host slept|hvi-time test sleep")]
finally:
    p.kill()
    p.wait()

expect = args.secs if args.mode == "hook" else 0.0
clk = []
for w, s in lines:
    m = re.match(r"^CLK (\d+) (\d+) (\d+) (\d+)", s)
    if m:
        # (stamp, guest REALTIME minus the stamp, guest MONOTONIC)
        clk.append((w, int(m.group(2)) / 1e9 - w, int(m.group(3)) / 1e9))
woke = find(r"hvi-time: the host slept")
after = [(w, o) for w, o, _ in clk if w >= event_at]
first_ok = next((w for w, o in after if abs(o - expect) < 0.1), None)
if args.mode == "hook":
    settled = [o - expect for w, o in after if first_ok is not None and w > first_ok]
else:
    # The console prints what clk wrote while stopped all at once; from 2 s
    # after the resume each line is on time.
    settled = [o for w, o in after if w > resumed + 2]
before, after_snap = summary["snapshot_before"], summary["snapshot_after"]
gen0, gen1 = field(before, "generation"), field(after_snap, "generation")
sleeps, migrations = field(after_snap, "host_sleeps"), field(after_snap, "migrations")
steps_back = sum(1 for a, b in zip(clk, clk[1:]) if b[2] < a[2])
summary.update({
    "expect_offset_s": expect,
    "clk_lines": len(clk),
    "event_wall": round(event_at, 3),
    "hvi_republish_after_event_s": round(woke[0][0] - event_at, 3) if woke else None,
    "first_aligned_after_event_s": round(first_ok - event_at, 3) if first_ok else None,
    "first_aligned_after_republish_ms":
        round((first_ok - woke[0][0]) * 1e3, 1) if (first_ok and woke) else None,
    "settled_offset_ms": [round(min(settled) * 1e3, 3), round(statistics.median(settled) * 1e3, 3),
                          round(max(settled) * 1e3, 3)] if settled else None,
    "monotonic_steps_back": steps_back,
})

check(len(clk) > 100, f"/clk printed {len(clk)} lines")
check(steps_back == 0, f"MONOTONIC never went back ({steps_back} steps back)")
check(sleeps is not None, "the driver's snapshot has host_sleeps (fourth patch)")
# A stamp is taken after the guest printed its line, so a right clock reads
# at or before it; the median allows for the console's latency.
check(bool(settled) and max(settled) < 0.001 and statistics.median(settled) > -0.005,
      f"guest REALTIME minus (host + {expect:g} s), min/median/max ms: "
      f"{summary['settled_offset_ms']}")
if args.mode == "hook":
    check(len(woke) == 1, f"hvi logged the host sleep once: {len(woke)} line(s)")
    check(first_ok is not None and bool(woke) and first_ok - woke[0][0] < 1.0,
          f"REALTIME was the host's {summary['first_aligned_after_republish_ms']} ms "
          "after the publish")
    check(gen0 is not None and gen1 == gen0 + 2, f"the generation went {gen0} to {gen1}")
    check(len(summary["driver_lines"]) == 1,
          f"the driver logged the publish once: {len(summary['driver_lines'])} line(s)")
    check(sleeps == 1 and migrations == 0,
          f"the driver counted a host sleep: host_sleeps={sleeps} migrations={migrations}")
else:
    check(not woke, f"hvi published nothing: {len(woke)} host-sleep line(s)")
    check(gen0 is not None and gen1 == gen0, f"the generation stayed: {gen0} to {gen1}")
    check(not summary["driver_lines"], "the driver logged no publish")
    check(sleeps == 0 and migrations == 0,
          f"the driver counted nothing: host_sleeps={sleeps} migrations={migrations}")

summary["failures"] = failures
with open(os.path.join(args.out, "summary.json"), "w") as f:
    json.dump(summary, f, indent=1)
print(f"sleep e2e ({args.mode}): {'ok' if not failures else f'{len(failures)} check(s) failed'}")
sys.exit(1 if failures else 0)

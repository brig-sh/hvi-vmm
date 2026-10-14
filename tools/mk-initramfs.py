#!/usr/bin/env python3
"""Build a minimal arm64 initramfs (newc cpio) for an hvi arm64 boot.

Transcodes an Alpine aarch64 minirootfs tarball straight into a newc cpio in
memory -- no root, no `cpio`/`mknod` (macOS can't create device nodes without
root, and the cpio format carries them as metadata anyway). Injects an `/init`
that mounts the pseudo-filesystems, configures eth0 for the built-in network
stack when there is one, prints a userspace banner and drops to a shell on the
console; hvi feeds host stdin to the guest UART, and Ctrl-] is reserved for
the plugin request key. When the shell exits, init powers off via PSCI.

Usage:
    tools/mk-initramfs.py [--out target/initramfs.cpio]
                          [--alpine-version 3.20.10] [--cache <dir>]
                          [--keep-alive SECS] [--net-static ADDR/PLEN,GW]
                          [--checkpoint-workload]

--keep-alive replaces the shell with a "HVI-INITRAMFS-UP" line, a sleep of
SECS and a power-off, for an unattended run such as CI. --net-static replaces
the eth0 block with a static address, a default route via GW and three pings
of it, for a tap boot where GW is the host side of the tap. CI uses both.

--checkpoint-workload starts the workload tools/checkpoint-e2e.sh checks a
restore against before the shell: a loop that counts in a shell variable
every 200 ms and prints the count with the guest's uptime (its monotonic
clock, to 10 ms) and its wall clock (`date +%s`), holds a file
open on fd 3 after unlinking it, and writes and syncs a file on an ext4
/dev/vda when there is one. When /tmp/go appears (the script types `touch
/tmp/go` on the console after the restore) the loop prints its count, reads
fd 3 and the disk file, writes and syncs a second file, and times a sleep 5.

The tarball is fetched once and cached (default: alongside --out).
"""

import argparse
import io
import os
import sys
import tarfile
import urllib.request

INIT = b"""#!/bin/sh
/bin/busybox mount -t proc     proc     /proc
/bin/busybox mount -t sysfs    sysfs    /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
# Static network config (matches the user-space virtio-net backend); harmless
# if there is no eth0 (booted without --net-stub).
if [ -e /sys/class/net/eth0 ]; then
	/bin/busybox ip link set eth0 up
	/bin/busybox ip addr add 10.0.2.15/24 dev eth0
	/bin/busybox ip route add default via 10.0.2.2
	/bin/busybox echo "nameserver 10.0.2.3" > /etc/resolv.conf
fi
/bin/busybox echo ""
/bin/busybox echo "==================================================="
/bin/busybox echo "  ARM64 guest on hvi / hvf  --  interactive"
/bin/busybox uname -a
/bin/busybox echo "  alpine $(/bin/busybox cat /etc/alpine-release 2>/dev/null), type 'poweroff -f' or 'exit' to stop"
/bin/busybox echo "==================================================="
# Interactive shell on the console (stdin/out are /dev/console = ttyAMA0).
/bin/busybox sh
# When the shell exits, power off cleanly (PSCI SYSTEM_OFF).
/bin/busybox poweroff -f
"""

# The same init, minus the interactive shell: it holds the guest in a stable
# userspace for a fixed window and then powers off. That is what an unattended
# run needs -- the guest has to still be up when the check runs, and `sh` on a
# console with no input would simply block forever.
KEEP_ALIVE_TAIL = b"""/bin/busybox echo "HVI-INITRAMFS-UP"
/bin/busybox sleep %d
/bin/busybox poweroff -f
"""

# The checkpoint workload (--checkpoint-workload), inserted before the shell.
# Everything it checks lives in the loop's own process: the count in a shell
# variable, and the unlinked file on fd 3, so only a guest that kept that
# process's memory and descriptors can print them after a restore.
CHECKPOINT_WORKLOAD = b"""# Checkpoint workload (--checkpoint-workload).
/bin/busybox echo "HVI-WORKLOAD-BOOT"
if [ -b /dev/vda ]; then
	/bin/busybox mkdir -p /mnt
	if /bin/busybox mount -t ext4 /dev/vda /mnt; then
		/bin/busybox echo "written-before $(/bin/busybox cut -d' ' -f1 /proc/uptime)" > /mnt/before
		/bin/busybox sync
		/bin/busybox echo "DISK-READY $(/bin/busybox cat /mnt/before)"
	fi
fi
(
	/bin/busybox echo "kept open after unlink" > /tmp/unlinked
	exec 3< /tmp/unlinked
	/bin/busybox rm /tmp/unlinked
	n=0
	while true; do
		n=$((n+1))
		/bin/busybox echo "TICK $n $(/bin/busybox cut -d' ' -f1 /proc/uptime) $(/bin/busybox date +%s)"
		if [ -e /tmp/go ]; then
			/bin/busybox rm /tmp/go
			/bin/busybox echo "COUNTER $n"
			/bin/busybox echo "FD3 $(/bin/busybox cat <&3)"
			if [ -e /mnt/before ]; then
				/bin/busybox echo "DISK-BEFORE $(/bin/busybox cat /mnt/before)"
				/bin/busybox echo "written-after $n" > /mnt/after
				/bin/busybox sync
				/bin/busybox echo "DISK-AFTER $(/bin/busybox cat /mnt/after)"
			fi
			/bin/busybox echo "SLEEP-START $(/bin/busybox cut -d' ' -f1 /proc/uptime)"
			/bin/busybox sleep 5
			/bin/busybox echo "SLEEP-END $(/bin/busybox cut -d' ' -f1 /proc/uptime)"
		fi
		/bin/busybox sleep 0.2
	done
) &
"""

# Replacement eth0 block for a tap-mode boot (--net-static): a caller-chosen
# static address instead of the built-in stack's 10.0.2.15, plus a few pings of
# the gateway -- the host side of the tap -- so the console log carries proof of
# real bidirectional traffic, not just a configured interface.
NET_STATIC = b"""# Static tap-mode network (--net-static); the pings prove the tap path.
if [ -e /sys/class/net/eth0 ]; then
\t/bin/busybox ip link set eth0 up
\t/bin/busybox ip addr add %s dev eth0
\t/bin/busybox ip route add default via %s
\t/bin/busybox ping -c 3 %s
fi
"""

# newc mode bits.
S_IFREG = 0o100000
S_IFDIR = 0o040000
S_IFLNK = 0o120000
S_IFCHR = 0o020000


class CpioWriter:
    """Accumulates newc ("070701") cpio entries."""

    def __init__(self):
        self.buf = bytearray()
        self.ino = 0

    def _field(self, val):
        return b"%08X" % (val & 0xFFFFFFFF)

    def add(self, name, mode, data=b"", nlink=1, rdevmajor=0, rdevminor=0):
        self.ino += 1
        name_bytes = name.encode() + b"\x00"
        hdr = b"070701"
        hdr += self._field(self.ino)
        hdr += self._field(mode)
        hdr += self._field(0)  # uid
        hdr += self._field(0)  # gid
        hdr += self._field(nlink)
        hdr += self._field(0)  # mtime
        hdr += self._field(len(data))
        hdr += self._field(0)  # devmajor
        hdr += self._field(0)  # devminor
        hdr += self._field(rdevmajor)
        hdr += self._field(rdevminor)
        hdr += self._field(len(name_bytes))
        hdr += self._field(0)  # check
        self.buf += hdr
        self.buf += name_bytes
        self._pad(len(hdr) + len(name_bytes))
        self.buf += data
        self._pad(len(data))

    def _pad(self, n):
        if n % 4:
            self.buf += b"\x00" * (4 - n % 4)

    def finish(self):
        # Trailer entry, then pad to a 512-byte block.
        self.add("TRAILER!!!", 0)
        if len(self.buf) % 512:
            self.buf += b"\x00" * (512 - len(self.buf) % 512)
        return bytes(self.buf)


def build(tar_bytes, keep_alive=None, net_static=None, workload=False):
    cpio = CpioWriter()
    seen_dirs = set()

    def ensure_dir(path):
        if path and path not in seen_dirs:
            seen_dirs.add(path)
            cpio.add(path, S_IFDIR | 0o755)

    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        for m in tar:
            name = m.name.lstrip("./")
            if not name:
                continue
            if m.isdir():
                ensure_dir(name)
                seen_dirs.add(name)
            elif m.isreg():
                data = tar.extractfile(m).read()
                cpio.add(name, S_IFREG | (m.mode & 0o7777), data)
            elif m.issym() or m.islnk():
                target = m.linkname.encode()
                cpio.add(name, S_IFLNK | 0o777, target)
            # Skip device nodes / fifos from the tarball; we add our own below.

    # The pieces the kernel needs to run init with working stdio.
    ensure_dir("dev")
    ensure_dir("proc")
    ensure_dir("sys")
    cpio.add("dev/console", S_IFCHR | 0o600, rdevmajor=5, rdevminor=1)
    cpio.add("dev/null", S_IFCHR | 0o666, rdevmajor=1, rdevminor=3)
    init = INIT
    if net_static is not None:
        # Swap the built-in-stack eth0 block (comment included) for the static
        # tap-mode one.
        addr, gw = net_static.split(",", 1)
        start = init.index(b"# Static network config")
        end = init.index(b"fi\n", start) + len(b"fi\n")
        block = NET_STATIC % (addr.encode(), gw.encode(), gw.encode())
        init = init[:start] + block + init[end:]
    if workload:
        # Start the workload just before the interactive shell.
        marker = b"# Interactive shell on the console"
        head, tail = init.split(marker, 1)
        init = head + CHECKPOINT_WORKLOAD + marker + tail
    if keep_alive is not None:
        # Replace everything from the interactive shell onwards.
        head = init.split(b"# Interactive shell on the console")[0]
        init = head + KEEP_ALIVE_TAIL % keep_alive
    cpio.add("init", S_IFREG | 0o755, init)
    return cpio.finish()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="target/initramfs.cpio")
    ap.add_argument("--alpine-version", default="3.20.10")
    ap.add_argument("--cache", default=None)
    ap.add_argument(
        "--keep-alive",
        type=int,
        metavar="SECS",
        help="run unattended: hold userspace for SECS then power off, instead "
        "of dropping to an interactive shell (for unattended CI runs)",
    )
    ap.add_argument(
        "--net-static",
        metavar="ADDR/PLEN,GW",
        help="replace the built-in-stack eth0 config: bring eth0 up on "
        "ADDR/PLEN, route via GW, and ping GW a few times (for the CI tap "
        "boot, where GW is the host side of the tap)",
    )
    ap.add_argument(
        "--checkpoint-workload",
        action="store_true",
        help="start the workload tools/checkpoint-e2e.sh checks a restore "
        "against before the shell",
    )
    args = ap.parse_args()

    ver = args.alpine_version
    branch = "v" + ".".join(ver.split(".")[:2])
    fname = f"alpine-minirootfs-{ver}-aarch64.tar.gz"
    url = f"https://dl-cdn.alpinelinux.org/alpine/{branch}/releases/aarch64/{fname}"

    cache_dir = args.cache or os.path.dirname(os.path.abspath(args.out)) or "."
    os.makedirs(cache_dir, exist_ok=True)
    cached = os.path.join(cache_dir, fname)

    if not os.path.exists(cached):
        print(f"fetching {url}", file=sys.stderr)
        urllib.request.urlretrieve(url, cached)
    else:
        print(f"using cached {cached}", file=sys.stderr)

    with open(cached, "rb") as f:
        import gzip

        tar_bytes = gzip.decompress(f.read())

    out = build(tar_bytes, args.keep_alive, args.net_static, args.checkpoint_workload)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "wb") as f:
        f.write(out)
    print(f"wrote {len(out)} bytes -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()

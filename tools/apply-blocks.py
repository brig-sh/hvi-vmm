#!/usr/bin/env python3
"""Apply disk blocks that hvi's disk-blocks op streams onto a copy of a base image.

A mover that holds the image a guest booted from writes the blocks the guest
changed into its own copy of that image, and so gets the guest's disk without
copying all of it. This is that step, for testing and for reference. The
stream format is described in docs/checkpoint.md ("Moving the disk by its
blocks"): batches, each a JSON header line followed by `size` bytes, and then
the op's reply line, which carries a "v" key.

Usage:
    tools/apply-blocks.py --image COPY [--stream FILE]
    tools/apply-blocks.py --image COPY --sock CONTROL_SOCK --round K
    tools/apply-blocks.py --image COPY --sock CONTROL_SOCK --blocks 3,4,9

With --stream (or with neither --stream nor --sock) the stream is read from
FILE or stdin. With --sock the tool asks hvi's control socket for the blocks
of round K, the round the last disk-dirty read, or for the listed blocks, and
applies them as they arrive.

Every batch is checked before it is written: its header must be one this tool
knows, its blocks must be adjacent and inside the image, its offset must be
its first block's, and its bytes must have the SHA-256 the header gives. The
image is never grown. On success it prints one JSON line: the blocks, bytes
and batches applied, and hvi's reply. It exits 1 on any refusal, leaving the
batches before the bad one applied.
"""

import argparse
import hashlib
import json
import os
import socket
import sys

BLOCK = 64 << 10
HEADER_KEYS = {"component", "batch", "first", "count", "offset", "size", "sha256"}
MAX_LINE = 64 << 10


def fail(why):
    print(f"apply-blocks: {why}", file=sys.stderr)
    sys.exit(1)


def read_line(stream):
    line = stream.readline(MAX_LINE + 1)
    if not line:
        fail("the stream ended before the reply line")
    if len(line) > MAX_LINE or not line.endswith(b"\n"):
        fail("a line is too long or the stream ended inside it")
    return json.loads(line)


def read_exact(stream, n):
    parts = []
    while n > 0:
        chunk = stream.read(min(n, 1 << 20))
        if not chunk:
            fail("the stream ended inside a batch")
        parts.append(chunk)
        n -= len(chunk)
    return b"".join(parts)


def apply(stream, fd, image_size):
    """Applies every batch on `stream` to `fd`; returns the totals and the reply."""
    blocks = byte_count = batches = 0
    while True:
        value = read_line(stream)
        if not isinstance(value, dict):
            fail(f"not a JSON object: {value!r}")
        if "v" in value:
            if not value.get("ok"):
                fail(f"hvi refused: {value.get('code')}: {value.get('error')}")
            return {"blocks": blocks, "bytes": byte_count, "batches": batches, "reply": value}
        if set(value) != HEADER_KEYS or value["component"] != "disk-blocks":
            fail(f"not a batch header: {value!r}")
        first, count, offset, size = (value[k] for k in ("first", "count", "offset", "size"))
        if not all(isinstance(x, int) and x >= 0 for x in (first, count, offset, size)):
            fail(f"batch {value['batch']}: a field is not a count")
        if value["batch"] != batches:
            fail(f"batch {value['batch']} came where batch {batches} was due")
        if count == 0 or offset != first * BLOCK:
            fail(f"batch {batches}: offset {offset} is not block {first}'s")
        if offset + size > image_size:
            fail(f"batch {batches}: bytes {offset}+{size} run past the {image_size}-byte image")
        whole = count * BLOCK
        # Every block is whole but the image's last, which may be short.
        if size != whole and not (size < whole and size > whole - BLOCK and offset + size == image_size):
            fail(f"batch {batches}: {size} bytes is not {count} block(s)")
        data = read_exact(stream, size)
        if hashlib.sha256(data).hexdigest() != value["sha256"]:
            fail(f"batch {batches}: the bytes do not match their SHA-256")
        os.pwrite(fd, data, offset)
        blocks += count
        byte_count += size
        batches += 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--image", required=True, help="the copy of the base image to write into")
    ap.add_argument("--stream", help="a file holding the stream (default: stdin)")
    ap.add_argument("--sock", help="hvi's control socket, to ask for the blocks")
    ap.add_argument("--round", type=int, help="with --sock: the round to fetch")
    ap.add_argument("--blocks", help="with --sock: comma-separated block numbers to fetch")
    args = ap.parse_args()

    fd = os.open(args.image, os.O_RDWR)
    image_size = os.fstat(fd).st_size
    if args.sock:
        if (args.round is None) == (args.blocks is None):
            fail("with --sock, give --round or --blocks")
        request = {"v": 1, "op": "disk-blocks"}
        if args.round is not None:
            request["round"] = args.round
        else:
            request["blocks"] = [int(b) for b in args.blocks.split(",") if b]
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.connect(args.sock)
        conn.sendall(json.dumps(request).encode() + b"\n")
        stream = conn.makefile("rb", buffering=1 << 20)
    elif args.stream:
        stream = open(args.stream, "rb")
    else:
        stream = sys.stdin.buffer
    result = apply(stream, fd, image_size)
    os.fsync(fd)
    os.close(fd)
    print(json.dumps(result))


if __name__ == "__main__":
    main()

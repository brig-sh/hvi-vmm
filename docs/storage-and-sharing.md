# Disks and directory shares

A guest gets storage two ways: one virtio-blk disk, and any number of
virtio-fs directory shares. A guest can have both at once, and either on its
own.

## virtio-blk: `--disk <file>`

`--disk` backs one block device from one host file or block device. There is
no second disk and no hotplug.

```sh
hvi boot --kernel <Image> --disk disk.img
```

The guest sees `/dev/vda`. hvi advertises `VIRTIO_BLK_F_FLUSH` and honours a
flush request with a real sync, so a filesystem's barriers are not silently
dropped.

Every request emits a `block` record into the ledger when `--events` is set:

```json
{"sandbox_id":"hvi","ts":1788992154877294000,"provenance":"boundary","source":"block","payload":{"lba":0,"len":4096,"rw":"r"}}
```

`HVI_BLK_TRACE=1` also logs each request to stderr. It is off by default
because it costs a synchronous write per request.

## virtio-fs shares

`--share-ro` and `--share-rw` export a host directory to the guest over
virtio-fs. The flags mean the same thing on both hosts; what serves them
differs.

On **macOS** hvi answers the guest's FUSE requests itself. There is no macFUSE
mount, no block image, no DAX window and no indirect descriptors.

On **Linux** the export is served by `virtiofsd`, which hvi starts, one daemon
per export. hvi is the virtio-mmio transport in front of it: the daemon maps
guest RAM through the memfd that backs it and walks the virtqueues in its own
process. See [Serving a Linux export](#serving-a-linux-export) for the daemon
and its options.

```sh
hvi boot --kernel <Image> \
  --share-ro /path/to/source code \
  --share-rw /path/to/scratch work cache=none
```

Inside the guest, mount by tag:

```sh
mount -t virtiofs code /mnt/code
```

Each share becomes its own device, with its own access mode and cache policy.
Repeat the flag for more. A tag is 1 to 36 bytes, carries no NUL, and must be
unique.

Two shares may not cover the same host directory, or one the other's parent,
while disagreeing on write permission. The guest reaches the same inodes
through either tag, so the read-only one would promise something the writable
one hands back. A boot that asks for both is refused, with the pair named.
Nesting with the same mode is fine.

### Access modes

A read-only share answers `EROFS` to every mutation:

```text
touch: /mnt/code/new: Read-only file system
```

A writable share supports file and directory handles, hard links, the atomic
rename variants, timestamps, xattrs, advisory locks (OFD locks on the host),
allocation, hole punching, zeroing, seek, `copy_file_range`, `statx`,
`statfs`, FIFOs, tmpfiles and Unix sockets.

Device nodes are refused. `OPEN` refuses anything that is not a regular file,
because opening a FIFO under the device mutex blocked the VM.

Unix sockets are served from inside the device. The socket inode lives in hvi,
by path, and never reaches the host filesystem. The guest kernel's own socket
table carries the traffic.

### Cache policy

A trailing `cache=auto|always|none` on a share selects how long the guest may
trust what it has.

| Policy | Attribute and entry timeout | Page cache | Use when |
| --- | --- | --- | --- |
| `auto` (default) | 5 s on a writable share, 60 s on a read-only one | kept across opens | the normal case |
| `none` | 0 s | not kept | the host mutates the tree while the guest runs |
| `always` | same as `auto` | writeback cache added, writable shares only | many small writes to one file |

The timeout depends on the **access mode**, not only on the policy. A
read-only share cannot go stale from the guest's own writes, so it gets a
minute under both `auto` and `always`.

`cache=always` on a read-only share is accepted and negotiates no writeback
cache, so it behaves as `auto`.

CAUTION: `cache=always` is correct only when the guest is the sole writer. It
hands mtime, ctime and size to the guest. If the host writes to the same tree,
the guest will serve stale data and stale metadata.

`always` is a trade, not a win. Measured with `tools/fsbench` writing 256 MiB
to a writable share: at `dd bs=4k` it batched 65536 requests down to a few
hundred and ran 2.4 times faster, and at `bs=1M` it ran 3.7 times slower,
because the guest's writeback path then costs more than the requests it saves.

### Serving a Linux export

On Linux the export is served by `virtiofsd`, the daemon from the virtio-fs
project. hvi starts one per export before the guest runs, and the pair speaks
vhost-user: hvi sends the rings and the memfd that backs guest RAM, the daemon
maps that memory and answers the guest's FUSE requests in its own process.

hvi looks for the binary in `--virtiofsd <path>`, then `HVI_VIRTIOFSD`, then
`PATH`, then `/usr/libexec/virtiofsd` and the other usual locations. It fails
the boot when it finds none, naming where it looked.

```sh
hvi boot --kernel <bzImage> \
  --virtiofsd /usr/libexec/virtiofsd \
  --share-rw /path/to/scratch work
```

The connection never touches the filesystem. hvi binds a socket in the
abstract namespace, connects to it, and hands the listening descriptor to the
daemon, which accepts the connection already queued on it. There is no socket
file and nothing to clean up.

A caller that runs its own daemons names them instead:

```sh
hvi boot --kernel <bzImage> \
  --share-rw /cntrRootfs fs0 --share-sock fs0=/tmp/vhostqemu
```

`--share-sock <tag>=<socket>` attaches the export to a daemon already
listening there, and hvi starts none of its own. This is the shape urunc uses:
it starts a virtiofsd per container before the monitor and passes the socket
down.

The guest can mount an export as its root, which is what a container boot
does: `root=fs0 rw rootfstype=virtiofs` on the kernel command line, with no
block device in the machine at all.

Three things about this backend are worth knowing:

- **A read-only export needs virtiofsd 1.11 or newer**, which is where
  `--readonly` arrived. hvi refuses the boot on an older daemon rather than
  serving the export writable. A writable export works on any version it has
  been run against, 1.10 included. This is a check on the daemon hvi starts.
  An export attached with `--share-sock` is served by a daemon someone else
  started, and vhost-user has no message that asks a backend what it refuses,
  so there the mode is the caller's to enforce; hvi says so at boot and
  carries on.
- **The daemon's sandbox is `namespace` when hvi runs as root, and `none`
  otherwise**, because unsharing a mount namespace needs privileges an
  unprivileged VMM does not have.
- **No file-level events.** A request the daemon serves never crosses the VMM,
  so the ledger records nothing for it. `--events` still carries the block and
  network boundaries.

`HVI_VIRTIOFSD_LOG` sets the daemon's log level, which is `warn` by default so
the daemon stays off the guest's console. A mount that does not come up is the
case where `HVI_VIRTIOFSD_LOG=debug` is worth having.

### Ownership: `--fs-uid` and `--fs-gid` (macOS)

Both default to 0, so a workload running as root sees the host's files as
root. A guest running as an unprivileged user needs its own uid here, or the
guest kernel refuses every write before the request reaches hvi.

The mapping applies to host files that carry no stored ownership. A file the
guest creates or chowns keeps the identity the guest asked for, recorded in a
private host xattr under `com.nofire.hvi.`, so a mode-000 file or an arbitrary
guest owner survives a restart without being imposed on the host. The guest
cannot read or forge that attribute: `SETXATTR` on the prefix returns `EPERM`,
`GETXATTR` returns `ENODATA`, and `LISTXATTR` filters it out.

These two flags are process-global, not per share. They are set once before
any share is served, and they are not part of `BootConfig`. See
[embedding.md](embedding.md#configuration-outside-bootconfig).

### Containment (macOS)

Resolution goes through the parent directory's descriptor with `O_NOFOLLOW` on
each component, so containment follows from how the descriptor was obtained
rather than from inspecting a path string afterwards. A lint refuses
`canonicalize` inside the device.

A symlink stored in a share is resolved the guest's way. An absolute target
restarts at the export root, a relative one continues from where it was found,
a target that climbs is clamped at the root, and a cycle ends as `ELOOP` after
40 expansions.

A few call sites still hand the host a full path string, so the host kernel
walks the intermediate components itself. Treat containment as strong and
tested, not as proven.

### Limits worth knowing before you share real data

- **The node table has no cap.** `FORGET` is what shrinks it between device
  resets. A guest that never sends one grows the table until it resets the
  device.
- **`SETLKW` blocks under the device mutex.** A guest waiting on a lock stalls
  that whole device, and stalls the vCPU that issued the request whenever the
  queue was shallow enough to be drained inline.
- **The descriptor budget is per export, the descriptor table is per process.**
  Each export refuses an `OPEN` or `OPENDIR` past its budget with `ENFILE`.
  The budget is the process file limit less a reserve of 128. `CREATE` and
  `TMPFILE` are not counted against it, and directory descriptors cached for
  readdir are not either, so several busy exports can still exhaust the table.
- **One request queue per share**, plus a hiprio queue. No DAX window.
- The open file limit is raised when the **first share** is set up, not at
  startup, and only on macOS. A boot with no share never raises it and never
  logs the line.
- The node table, the descriptor budget and the lock behaviour above are the
  macOS device's. On Linux those belong to `virtiofsd`, and its own
  documentation covers them.

Each export reports its peak handle count on a clean stop:

```text
[hvi] virtio-fs[0]: peak 1 of 1048448 guest handles
```

### What to share

CAUTION: A writable share gives a hostile guest write access to that host
directory tree, bounded by the export root and by the process's own
permissions. Give `--share-rw` a directory you can afford to lose. For a
development workload, an instance-owned APFS clone is the right shape. For a
shared cache that several guests read, use `--share-ro`.

On Linux, a read-only export is enforced by the daemon, which answers `EROFS`
to every mutation. What bounds a writable one depends on how hvi runs. As
root the daemon gets its own mount and pid namespace, as above. Unprivileged
it runs with `--sandbox none`, and the bound is then the daemon's own path
resolution within the shared directory: it runs as the same user as the VMM,
outside the VMM's seccomp filter, and reaches whatever that user reaches.

The macOS Seatbelt profile grants exactly one rule per export, by resolved
root path: `file-read*` for a read-only share and `file-read* file-write*` for
a writable one, on top of a deny-default profile. Nothing else on the host
filesystem is writable. See [security.md](security.md).

## See also

- [benchmarking.md](benchmarking.md) for measuring a change to the device.
- [cli.md](cli.md) for the flags and their defaults.
- [architecture.md](architecture.md#devices) for the device model.

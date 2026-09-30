# Disks and directory shares

A guest gets storage two ways: up to four virtio-blk disks, and any number of
virtio-fs directory shares. A guest can have both at once, and either on its
own.

## virtio-blk: `--disk <file>` and `--disk path=<file>,...`

Each `--disk` backs one block device from one host file or block device. The
flag is repeatable, at most four disks in all, and takes either a bare path or
Cloud Hypervisor's `path=<file>[,readonly=on|off][,serial=<id>]`. There is no
hotplug.

```sh
hvi boot --kernel <Image> \
  --disk path=lower.img,readonly=on,serial=lower --disk path=upper.img,serial=upper
```

Every disk is its own virtio-mmio device. hvi advertises `VIRTIO_BLK_F_FLUSH`
and honours a flush request with a real sync, so a filesystem's barriers are not
silently dropped.

A `readonly=on` disk is opened `O_RDONLY`, so an image hvi may not write still
attaches. hvi advertises `VIRTIO_BLK_F_RO` for it and refuses any write the
guest sends anyway with an I/O error. A flush on it succeeds, since nothing was
written.

The image is locked for as long as the guest has it open: shared for a read-only
disk, exclusive for a writable one, with `flock`. A second hvi on a writable
image fails to boot, and so does an hvi writing an image another hvi reads. Any
number of guests can read one image, which is how one lower image serves many
sandboxes. Within one guest, an image may back two read-only disks and nothing
else. The lock is between hvi processes: Cloud Hypervisor and QEMU lock with
`fcntl`, which `flock` does not see. A writable block device is also opened
`O_EXCL` on Linux, so it holds against another device node for the same device
and against a mount; a read-only open claims nothing, so a reader through
another node is not held against a writer. The lock on a block device is retried
for a second while udev holds the device after `losetup`. On a filesystem
without a lock service, such as NFS without lockd, the lock fails and so does
the boot.

The guest sees the disks as `/dev/vda`, `/dev/vdb` and so on, in command-line
order. That order follows probing and is not a contract. Each disk also has a
serial, which the guest reads from `/sys/block/vdX/serial`. `serial=` sets it, 1
to 20 printable ASCII bytes, and a disk without one answers `disk<N>` with `N`
its 0-based position. Two disks may not share a serial. Pick a disk by serial:

```sh
for d in /sys/block/vd*; do
  [ "$(cat "$d/serial")" = lower ] && echo "/dev/${d##*/}"
done
```

Every read or write that succeeds emits a `block` record into the ledger when
`--events` is set, unless the ledger's buffer is full (see
[observability.md](observability.md#when-a-record-reaches-the-file)). `disk` is
the disk's serial, so the records of two disks can be told apart:

```json
{"sandbox_id":"hvi","ts":1788992154877294000,"provenance":"boundary","source":"block","payload":{"disk":"disk0","lba":0,"len":4096,"rw":"r"}}
```

`HVI_BLK_TRACE=1` also logs each request to stderr. It is off by default
because it costs a synchronous write per request.

## virtio-fs shares

virtio-fs exports a host directory to the guest. Who serves it depends on the
host.

Every export is one `--fs`, in Cloud Hypervisor's comma-separated syntax.

On **macOS** hvi answers the guest's FUSE requests itself, and
`--fs tag=<tag>,path=<dir>` names the directory. There is no macFUSE mount, no
block image, no DAX window and no indirect descriptors. `--share-ro <dir> <tag>`
and `--share-rw <dir> <tag>` are the old form, which still works and prints a
note.

On **Linux** the caller runs a vhost-user daemon, such as `virtiofsd`, for each
export, and passes its socket with `--fs tag=<tag>,socket=<socket>`. hvi is the
virtio-mmio transport in front of it: the daemon maps guest RAM through the
memfd that backs it and walks the virtqueues in its own process. See
[Serving a Linux export](#serving-a-linux-export).

```sh
hvi boot --kernel <Image> \
  --fs tag=code,path=/path/to/source,readonly=on \
  --fs tag=work,path=/path/to/scratch,cache=none,uid=1000,gid=1000
```

Inside the guest, mount by tag:

```sh
mount -t virtiofs code /mnt/code
```

Each share becomes its own device, with its own access mode, cache policy and
owner. Repeat the flag for more. On macOS an export takes `readonly=on|off`
(off by default), `cache=auto|always|none` and `uid=`/`gid=`; on Linux those
are the daemon's, and only `num_queues=` and `queue_size=` apply. A tag is 1 to 36 bytes, carries no NUL, and must be
unique.

Two shares may not cover the same host directory, or one the other's parent,
while disagreeing on write permission. The guest reaches the same inodes
through either tag, so the read-only one would promise something the writable
one hands back. A boot that asks for both is refused, with the pair named.
Nesting with the same mode is fine.

The check covers the shares of one hvi process. Two processes can export the
same tree, or a tree and a directory inside it, with one export writable and the
other read-only. Neither process refuses that. A guest on the writable share can
then store an owner and a mode on a file, setuid and setgid included (see
[Ownership](#ownership-uid-and-gid-macos)), and the other guest's kernel
honors them. Export one tree to two sandboxes only when each may change what the
other runs.

### Access modes

A read-only share answers `EROFS` to every mutation:

```text
touch: /mnt/code/new: Read-only file system
```

A writable share supports file and directory handles, hard links, the atomic
rename variants, timestamps, xattrs, advisory locks (OFD locks on the host;
a request for a held lock waits parked on the device, retried without
blocking, so it holds up no other request),
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

| Policy | Attribute and entry timeout | Missing-name timeout | Page cache | Use when |
| --- | --- | --- | --- | --- |
| `auto` (default) | 5 s on a writable share, 60 s on a read-only one | 5 s | kept across opens | the normal case |
| `none` | 0 s | 0 s, and a miss answers ENOENT | not kept | the host mutates the tree while the guest runs |
| `always` | same as `auto` | 5 s | writeback cache added, writable shares only | many small writes to one file |

The timeout depends on the **access mode**, not only on the policy. A
read-only share cannot go stale from the guest's own writes, so it gets a
minute under both `auto` and `always`.

A name that does not exist is a separate case, and it is capped at 5 s on
both share modes. A guest that has cached a *present* entry finds out it is
wrong the moment it uses it, because the open reaches hvi and fails there. A
guest that has cached an *absent* one does not: its own kernel answers the
open, so a file created on the host afterwards stays invisible until the
entry expires. On a read-only share the guest cannot create the name itself
either, which is the other way such an entry would go away.

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

On Linux an export is served by a vhost-user daemon the caller runs, such as
`virtiofsd` from the virtio-fs project. hvi starts no daemon. It connects to the
daemon's socket before the guest runs, and the pair speaks vhost-user: hvi sends
the rings and the memfd that backs guest RAM, and the daemon maps that memory
and answers the guest's FUSE requests in its own process. Cloud Hypervisor and
QEMU split the work the same way, and libvirt, Kata and urunc start the daemon
for them.

```sh
virtiofsd --socket-path=/run/hvi/fs0.sock --shared-dir /path/to/scratch \
  --sandbox namespace --cache auto &
hvi boot --kernel <bzImage> --fs tag=fs0,socket=/run/hvi/fs0.sock
```

`--fs` takes Cloud Hypervisor's syntax,
`tag=<tag>,socket=<socket>[,num_queues=<n>][,queue_size=<size>]`, with its
defaults: one request queue and a queue size of 1024. An export may have at most
one request queue per vCPU, and the daemon has to serve them all. virtiofsd
serves one, so `num_queues` above 1 needs another daemon. The queue size is a
power of two up to 32768.

That is all hvi knows of an export. The directory, whether the guest may write
it, the cache policy and the daemon's sandbox are all options of the daemon. So
the Linux backends refuse a `path=` export, and the overlap rule above does not
apply.

A runtime can start the daemon and hvi at once, as urunc does for its other
monitors. So hvi waits for the socket, up to 60 seconds, as Cloud Hypervisor
does. It retries while the socket is missing or refuses the connection, and
fails the boot on any other error at once. urunc's hvi backend does not attach
shares yet.

The guest can mount an export as its root, which is what a container boot
does: `root=fs0 rw rootfstype=virtiofs` on the kernel command line, with no
block device in the machine at all.

Two things about this backend are worth knowing:

- **Read-only is the daemon's.** vhost-user has no message that asks a daemon
  what it refuses, so hvi cannot check the mode. virtiofsd takes `--readonly`
  from 1.13, and an older one exits on the flag rather than serving the export
  writable.
- **No file-level events.** A request the daemon serves never crosses the VMM,
  so the ledger records nothing for it. `--events` still carries the block and
  network boundaries.

### Ownership: `uid=` and `gid=` (macOS)

The host user's files appear in the guest as `uid`:`gid` of their export. Both
default to 0, so a workload running as root sees the host's files as root. A
guest running as an unprivileged user needs its own uid here, or the guest
kernel refuses every write before the request reaches hvi. Files other host
users own keep their own ids.

The mapping applies to host files that carry no stored ownership. A file the
guest creates or chowns keeps the identity the guest asked for, recorded in a
private host xattr under `com.nofire.hvi.`, so a mode-000 file or an arbitrary
guest owner survives a restart without being imposed on the host. The guest
cannot read or forge that attribute: `SETXATTR` on the prefix returns `EPERM`,
`GETXATTR` returns `ENODATA`, and `LISTXATTR` filters it out.

Each export has its own pair, in `FsShare`. The deprecated `--fs-uid` and
`--fs-gid` set the pair of every `--share-ro`/`--share-rw` export.

On Linux the daemon decides ownership; virtiofsd 1.13 and newer translate ids
with `--translate-uid` and `--translate-gid`. hvi refuses `uid=` and `gid=` on a
`socket=` export, since it cannot apply them.

### Containment (macOS)

Resolution goes through the parent directory's descriptor with `O_NOFOLLOW` on
each component, so containment follows from how the descriptor was obtained
rather than from inspecting a path string afterwards. A lint refuses
`canonicalize` inside the device.

A symlink stored in a share is resolved the guest's way. An absolute target
restarts at the export root, a relative one continues from where it was found,
a target that climbs is clamped at the root, and a cycle ends as `ELOOP` after
40 expansions.

The export root is the one path the host resolves whole, when the share is
set up and before the guest starts. The host kernel walks its intermediate
components itself. Treat containment as strong and tested, not as proven.

### Limits worth knowing before you share real data

- **The node table has no cap.** `FORGET` is what shrinks it between device
  resets. A guest that never sends one grows the table until it resets the
  device.
- **The descriptor budget is per export, the descriptor table is per process.**
  Each export refuses an `OPEN` or `OPENDIR` past its budget with `ENFILE`.
  The budget is the process file limit less a reserve of 128. `CREATE` and
  `TMPFILE` are not counted against it, and directory descriptors cached for
  readdir are not either, so several busy exports can still exhaust the table.
- **One request queue per share on macOS**, plus a hiprio queue. A Linux
  export takes `num_queues=`. No DAX window. The
  device reports no shared memory region, and a guest built with `FUSE_DAX`
  binds the device without DAX.
- The open file limit is raised when the **first share** is set up, not at
  startup, and only on macOS. A boot with no share never raises it and never
  logs the line.
- The node table, the descriptor budget and the lock behaviour above are the
  macOS device's. On Linux those belong to the daemon, and its own
  documentation covers them.

Each export reports its peak handle count on a clean stop:

```text
[hvi] virtio-fs[0]: peak 1 of 1048448 guest handles
```

### What to share

CAUTION: A writable share gives a hostile guest write access to that host
directory tree, bounded by the export root and by the process's own
permissions. Give a writable export a directory you can afford to lose. For a
development workload, an instance-owned APFS clone is the right shape. For a
shared cache that several guests read, use `readonly=on`.

On Linux the daemon decides what the guest reaches, outside the VMM's seccomp
filter. virtiofsd with `--readonly` answers `EROFS` to every mutation. With
`--sandbox namespace` it gets its own mount and pid namespace, which needs
`CAP_SYS_ADMIN`. With `--sandbox none` it keeps its own seccomp filter, but it
has no mount namespace and no chroot. The bound is then its own path resolution
within the shared directory, and it reaches whatever its user reaches.

The macOS Seatbelt profile grants exactly one rule per export, by resolved
root path: `file-read*` for a read-only share and `file-read* file-write*` for
a writable one, on top of a deny-default profile. Nothing else on the host
filesystem is writable. A writable export also brings the one fsctl SYNCFS
needs, `FSIOC_SYNC_VOLUME`, and no other. See [security.md](security.md).

SYNCFS on a writable export flushes every file the guest holds open, then
syncs the export's volume, drive cache included, before it answers. That
covers the volume the export root is on. The sync goes through the root's
descriptor, so it stays on that volume if the root's path is renamed or
replaced later. A second volume mounted inside the export is not synced by it.

SMB cannot sync a volume this way. On an export there, the first SYNCFS fails
with `ENOSYS`, and the guest's FUSE client stops sending SYNCFS for that
mount.

## See also

- [benchmarking.md](benchmarking.md) for measuring a change to the device.
- [cli.md](cli.md) for the flags and their defaults.
- [architecture.md](architecture.md#devices) for the device model.

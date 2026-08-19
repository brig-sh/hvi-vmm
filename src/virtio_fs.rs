//! Virtio-fs over virtio-mmio.
//!
//! This is the directory-sharing equivalent of the macOS Virtualization
//! framework's `VZVirtioFileSystemDeviceConfiguration`: the guest speaks the
//! normal virtio-fs/FUSE wire protocol and the VMM serves it directly from an
//! unpacked host directory.  There is no host FUSE mount, no macFUSE
//! dependency, and no block-image conversion.
//!
//! The backend intentionally starts with the conservative shape needed to
//! boot an OCI bundle: one request queue, no DAX window, no indirect
//! descriptors. Each device is independently read-only or read-write, allowing
//! an immutable OCI cache to remain protected while an instance-owned APFS
//! clone or an explicit volume is exported without a block image.

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{
    DirBuilderExt, DirEntryExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(target_os = "macos")]
use std::os::darwin::fs::MetadataExt as DarwinMetadataExt;

use crate::config::CachePolicy;
use crate::guestmem::GuestRam;
use crate::virtio::{reg, Queue, QUEUE_NUM_MAX};

const MAGIC_VALUE: u64 = 0x7472_6976;
const VIRTIO_FS_ID: u64 = 26;
const VENDOR: u64 = 0x4649_4f4e;
const F_VERSION_1_HI: u32 = 1;

const NUM_QUEUES: usize = 2;
const TAG_LEN: usize = 36;
const CONFIG_LEN: usize = TAG_LEN + 4;
const MAX_REQUEST: usize = 2 << 20;
const MAX_WRITE: u32 = 1 << 20;

const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;

/// Largest iovec count a single `preadv`/`pwritev` may carry. `libc::IOV_MAX`
/// is only defined for BSD-family targets in the `libc` crate; on Linux this
/// is `UIO_MAXIOV`, kernel-enforced and stable since 2.6.18.
#[cfg(target_os = "macos")]
const IOV_MAX: usize = libc::IOV_MAX as usize;
#[cfg(target_os = "linux")]
const IOV_MAX: usize = 1024;

const FUSE_ROOT_ID: u64 = 1;
const IN_HEADER_LEN: usize = 40;
const OUT_HEADER_LEN: usize = 16;

// FUSE opcodes used by the filesystem.
const LOOKUP: u32 = 1;
const FORGET: u32 = 2;
const GETATTR: u32 = 3;
const SETATTR: u32 = 4;
const READLINK: u32 = 5;
const SYMLINK: u32 = 6;
const MKNOD: u32 = 8;
const MKDIR: u32 = 9;
const UNLINK: u32 = 10;
const RMDIR: u32 = 11;
const RENAME: u32 = 12;
const LINK: u32 = 13;
const OPEN: u32 = 14;
const READ: u32 = 15;
const WRITE: u32 = 16;
const STATFS: u32 = 17;
const RELEASE: u32 = 18;
const FSYNC: u32 = 20;
const SETXATTR: u32 = 21;
const GETXATTR: u32 = 22;
const LISTXATTR: u32 = 23;
const REMOVEXATTR: u32 = 24;
const FLUSH: u32 = 25;
const INIT: u32 = 26;
const OPENDIR: u32 = 27;
const READDIR: u32 = 28;
const RELEASEDIR: u32 = 29;
const FSYNCDIR: u32 = 30;
const GETLK: u32 = 31;
const SETLK: u32 = 32;
const SETLKW: u32 = 33;
const ACCESS: u32 = 34;
const CREATE: u32 = 35;
const DESTROY: u32 = 38;
const POLL: u32 = 40;
const BATCH_FORGET: u32 = 42;
const FALLOCATE: u32 = 43;
const READDIRPLUS: u32 = 44;
const RENAME2: u32 = 45;
const LSEEK: u32 = 46;
const COPY_FILE_RANGE: u32 = 47;
const SYNCFS: u32 = 50;
const TMPFILE: u32 = 51;
const STATX: u32 = 52;

// Linux open flags carried on the wire. They must never be passed directly to
// macOS, whose constants differ.
const LINUX_O_ACCMODE: u32 = 0x3;
const LINUX_O_WRONLY: u32 = 0x1;
const LINUX_O_RDWR: u32 = 0x2;
const LINUX_O_EXCL: u32 = 0x80;
const LINUX_O_TRUNC: u32 = 0x200;
const LINUX_O_APPEND: u32 = 0x400;

const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_FH: u32 = 1 << 6;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;
const FATTR_LOCKOWNER: u32 = 1 << 9;
const FATTR_CTIME: u32 = 1 << 10;
const FATTR_KILL_SUIDGID: u32 = 1 << 11;

const FUSE_GETATTR_FH: u32 = 1;
const FUSE_FSYNC_FDATASYNC: u32 = 1;
const FUSE_OPEN_KILL_SUIDGID: u32 = 1;
const FUSE_WRITE_KILL_SUIDGID: u32 = 1 << 2;
const FUSE_LK_FLOCK: u32 = 1;
const FUSE_RELEASE_FLOCK_UNLOCK: u32 = 1 << 1;
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;
const RENAME_WHITEOUT: u32 = 4;

const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
const FALLOC_FL_ZERO_RANGE: u32 = 0x10;
const FALLOC_FL_INSERT_RANGE: u32 = 0x20;
const FALLOC_FL_UNSHARE_RANGE: u32 = 0x40;

const LINUX_XATTR_CREATE: u32 = 1;
const LINUX_XATTR_REPLACE: u32 = 2;

// macOS cannot apply arbitrary Linux owners from an unprivileged VMM, and
// applying a guest mode such as 0000 to the host inode would prevent the VMM
// itself from serving later requests. Persist the guest-visible metadata in
// private, no-follow xattrs while retaining host-owner access.
const HVI_XATTR_PREFIX: &[u8] = b"com.nubificus.hvi.";
const HVI_XATTR_LINUX_ATTR: &[u8] = b"com.nubificus.hvi.linux-attr";

const LINUX_F_RDLCK: u32 = 0;
const LINUX_F_WRLCK: u32 = 1;
const LINUX_F_UNLCK: u32 = 2;

const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;
const S_IFREG: u32 = 0o100000;
const S_IFSOCK: u32 = 0o140000;
/// `DT_SOCK`, the readdir type byte for a socket.
const DT_SOCK: u32 = 12;

// Linux errno values. Host errno numbers are not portable from macOS to the
// Linux guest, so errors are translated explicitly.
const ENOENT: i32 = 2;
const EPERM: i32 = 1;
const EIO: i32 = 5;
const ENXIO: i32 = 6;
const EBADF: i32 = 9;
const EAGAIN: i32 = 11;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const EXDEV: i32 = 18;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const EFBIG: i32 = 27;
const ENOSPC: i32 = 28;
const EROFS: i32 = 30;
const ENOSYS: i32 = 38;
const ENOTEMPTY: i32 = 39;
const ELOOP: i32 = 40;
const ERANGE: i32 = 34;
const EDEADLK: i32 = 35;
const ENODATA: i32 = 61;
const EOPNOTSUPP: i32 = 95;
// Linux generic errno values, like the rest of this block. These were missing,
// and io_errno's catch-all reported every one of them to the guest as EIO.
//
// EMFILE is the one that mattered: hvi pins a host file descriptor for every
// open guest handle, and with the macOS default soft limit of 256 a build
// inside the guest exhausts them. The guest then sees "Input/output error" on
// random unrelated files -- a Go build failing to open package archives, gcc
// unable to execute its own cc1 -- with nothing to suggest the real cause.
// Reproduced by booting the same image twice: at `ulimit -n 256` the guest
// fails all over, at 8192 the identical workload is clean.
const ENOMEM: i32 = 12;
const EBUSY: i32 = 16;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ETXTBSY: i32 = 26;
const EMLINK: i32 = 31;
const ENAMETOOLONG: i32 = 36;
const ENOLCK: i32 = 37;
const EOVERFLOW: i32 = 75;
const ESTALE: i32 = 116;
const EDQUOT: i32 = 122;

struct FileHandle {
    file: File,
    writable: bool,
    path: PathBuf,
    temporary_path: Option<PathBuf>,
}

/// What a handler produced. `Direct` means the handler already placed its
/// payload in the guest's output descriptors, past the reply header, and
/// `handle_chain` has nothing left to copy.
enum Reply {
    Buffered(Vec<u8>),
    Direct(usize),
}

#[derive(Clone, Copy)]
struct RequestContext {
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy)]
struct GuestAttr {
    mode: u32,
    uid: u32,
    gid: u32,
}

/// One `fs::read_dir` entry captured at OPENDIR time.
#[derive(Clone)]
struct DirEntryInfo {
    name: OsString,
    /// `d_ino` from the same dirent; free on both macOS and Linux, unlike a
    /// stat, so plain (non-plus) READDIR never needs one for the inode number
    /// it reports.
    ino: u64,
    /// From `d_type` at opendir time; `None` when the host returned DT_UNKNOWN
    /// and a stat is genuinely required.
    file_type: Option<std::fs::FileType>,
}

struct DirHandle {
    file: File,
    entries: Vec<DirEntryInfo>,
}

/// A guest-created Unix socket, held in the device rather than on the host.
/// See `VirtioFs::sockets`.
#[derive(Clone, Copy)]
struct SocketNode {
    /// `S_IFSOCK` and the permission bits. Kept here so `chmod` on a socket
    /// works: a caller may well insist on 0700 before it will use one.
    mode: u32,
    uid: u32,
    gid: u32,
    /// Stable for the socket's whole life. A guest that looks the path up
    /// again after its cache is dropped has to arrive at the same inode, or
    /// the socket the server is bound to becomes unreachable.
    ino: u64,
    /// Seconds and nanoseconds since the epoch, reported for all three of
    /// atime, mtime and ctime.
    ///
    /// There is no host file to read a time off, and reporting zero -- which
    /// this did at first -- dates every socket to 1 January 1970. That is
    /// visibly wrong in a listing and worse than cosmetic for anything that
    /// ages or sorts what it finds in a directory, `/tmp` reapers being the
    /// obvious example.
    time: (u64, u32),
}

/// Now, as a `(seconds, nanoseconds)` pair since the epoch.
///
/// A clock that is somehow before the epoch reports zero rather than
/// panicking: a socket with a strange timestamp is not worth failing a
/// `bind` over.
fn now_parts() -> (u64, u32) {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => (d.as_secs(), d.subsec_nanos()),
        Err(_) => (0, 0),
    }
}

/// The `st_dev` synthetic inodes are numbered under.
///
/// `inode_ids` is keyed by the host's `(dev, ino)`, so a synthetic node needs
/// a device number no `stat` can return. macOS `dev_t` is 32-bit, so the top
/// of the 64-bit space cannot collide.
const SOCKET_DEV: u64 = u64::MAX;

struct Node {
    key: (u64, u64),
    paths: Vec<PathBuf>,
    lookups: u64,
    /// Cached `com.nubificus.hvi.linux-attr`. `Some(None)` means "checked, not
    /// present" so a miss costs no syscall either. Invalidated whenever this
    /// module writes the xattr or changes ownership/mode. macOS only; on
    /// Linux `guest_attr` has no xattr path, so this is simply never filled.
    guest_attr: Option<Option<GuestAttr>>,
}

/// A virtio-fs device exporting exactly one canonical host directory.
pub struct VirtioFs {
    root: PathBuf,
    writable: bool,
    cache_policy: CachePolicy,
    tag: [u8; TAG_LEN],
    status: u32,
    dev_feat_sel: u32,
    queue_sel: u32,
    queues: [Queue; NUM_QUEUES],
    interrupt_status: u32,
    /// Bitmask of queue indices notified since the last drain: bit `i` set
    /// means queue `i` had a `QUEUE_NOTIFY` land on it. Set by the vCPU
    /// thread in `mmio`, cleared by `take_notified`/`drain_notified`, which
    /// only the worker thread calls. Both sides only ever touch it with the
    /// device mutex held (this struct sits behind `Arc<Mutex<VirtioFs>>` in
    /// `machine_macos`), so a plain `u32` is enough -- no atomic needed. A
    /// notify that lands while the worker is mid-drain just sets a bit the
    /// worker's next `take_notified` in the same drain pass will see (this
    /// field is a bitmask, not a count, so a queue notified twice before a
    /// drain still only costs one `process_queue` call); the worker's
    /// post-drain recheck (see `spawn_fs_worker`) is what catches a notify
    /// that lands after the drain but before the worker parks again.
    notified: u32,
    nodes: HashMap<u64, Node>,
    inode_ids: HashMap<(u64, u64), u64>,
    next_node: u64,
    /// Unix sockets the guest has bound inside a share, by path.
    ///
    /// They live here rather than on the host because a socket needs the
    /// filesystem for exactly two things -- an inode reporting `S_IFSOCK`,
    /// and an identity stable enough that a later lookup finds the same one.
    /// The rendezvous and every byte of data belong to the guest kernel's own
    /// unix socket table, and no FUSE request ever carries socket traffic, so
    /// there is nothing the host has to store.
    ///
    /// Keeping them out of the share is the point rather than a limitation.
    /// The host cannot make one anyway -- `mknod(S_IFSOCK)` is EPERM on macOS
    /// without root, and `bind(2)` cannot reach these paths at all, since a
    /// share's host path is routinely longer than `sun_path`'s 104 bytes --
    /// and serving them from here keeps a guest-controlled inode type off the
    /// host filesystem, which is what the device refused them for to begin
    /// with.
    sockets: HashMap<PathBuf, SocketNode>,
    next_socket_ino: u64,
    handles: HashMap<u64, FileHandle>,
    dir_handles: HashMap<u64, DirHandle>,
    next_handle: u64,
    next_tmpfile: u64,
    /// How many READs and WRITEs took the zero-copy `preadv`/`pwritev` path.
    ///
    /// Both direct paths fall back to the buffered one by returning `None`,
    /// which is correct but indistinguishable from the fast path by result
    /// alone -- so without a counter a regression that disables zero-copy
    /// entirely still passes every behavioural test. `Cell` because
    /// `read_direct` only needs `&self`.
    zero_copy: Cell<(u64, u64)>,
}

impl VirtioFs {
    /// Creates an export. `root` must already be canonical so the same exact
    /// path and access mode can be granted by Seatbelt.
    pub fn new(
        root: PathBuf,
        tag: &str,
        writable: bool,
        cache_policy: CachePolicy,
    ) -> io::Result<Self> {
        if !root.is_absolute() || !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "virtio-fs root must be an absolute directory",
            ));
        }
        let bytes = tag.as_bytes();
        if bytes.is_empty() || bytes.len() > TAG_LEN || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "virtio-fs tag must be 1..=36 bytes and contain no NUL",
            ));
        }
        let mut tag_buf = [0u8; TAG_LEN];
        tag_buf[..bytes.len()].copy_from_slice(bytes);
        // Every node path is built from this one, so resolve it here rather
        // than trusting the caller to have done it: `..` at the export root is
        // compared against it, and a mix of resolved and unresolved forms
        // would make that comparison depend on how the caller spelled the
        // path.
        let root = fs::canonicalize(&root)?;
        let mut nodes = HashMap::new();
        let root_meta = fs::symlink_metadata(&root)?;
        nodes.insert(
            FUSE_ROOT_ID,
            Node {
                key: (root_meta.dev(), root_meta.ino()),
                paths: vec![root.clone()],
                lookups: u64::MAX,
                guest_attr: None,
            },
        );
        let mut inode_ids = HashMap::new();
        inode_ids.insert((root_meta.dev(), root_meta.ino()), FUSE_ROOT_ID);
        Ok(Self {
            root,
            writable,
            cache_policy,
            tag: tag_buf,
            status: 0,
            dev_feat_sel: 0,
            queue_sel: 0,
            queues: std::array::from_fn(|_| Queue::default()),
            interrupt_status: 0,
            notified: 0,
            nodes,
            inode_ids,
            next_node: FUSE_ROOT_ID + 1,
            sockets: HashMap::new(),
            next_socket_ino: 1,
            handles: HashMap::new(),
            dir_handles: HashMap::new(),
            next_handle: 1,
            next_tmpfile: 1,
            zero_copy: Cell::new((0, 0)),
        })
    }

    /// `(reads, writes)` served zero-copy since boot.
    #[cfg(test)]
    fn zero_copy_counts(&self) -> (u64, u64) {
        self.zero_copy.get()
    }

    fn note_zero_copy_read(&self) {
        let (r, w) = self.zero_copy.get();
        self.zero_copy.set((r + 1, w));
    }

    fn note_zero_copy_write(&self) {
        let (r, w) = self.zero_copy.get();
        self.zero_copy.set((r, w + 1));
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn irq_level(&self) -> bool {
        self.interrupt_status != 0
    }

    fn queue(&mut self) -> Option<&mut Queue> {
        self.queues.get_mut(self.queue_sel as usize)
    }

    /// Services a virtio-mmio register access.
    ///
    /// `QUEUE_NOTIFY` never runs a FUSE request here: it only records the
    /// queue index in `notified` and returns. That is what keeps the vCPU
    /// off the host filesystem -- `spawn_fs_worker` (`machine_macos.rs`) is
    /// the thread that actually calls `process_queue`, off the exit path
    /// entirely. Every other register (status, queue programming, config
    /// reads, `INTERRUPT_ACK`) is cheap and stays handled inline here, same
    /// as before.
    pub fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64 {
        let v = value as u32;
        if is_write {
            match offset {
                reg::DEVICE_FEATURES_SEL => self.dev_feat_sel = v,
                reg::DRIVER_FEATURES_SEL | reg::DRIVER_FEATURES => {}
                reg::QUEUE_SEL => self.queue_sel = v,
                reg::QUEUE_NUM => {
                    if let Some(queue) = self.queue() {
                        queue.set_num(v);
                    }
                }
                reg::QUEUE_READY => {
                    if let Some(queue) = self.queue() {
                        queue.set_ready(v, mem);
                    }
                }
                reg::QUEUE_NOTIFY if (v as usize) < NUM_QUEUES => {
                    self.notified |= 1 << v;
                }
                reg::INTERRUPT_ACK => self.interrupt_status &= !v,
                reg::STATUS => self.status = v,
                reg::QUEUE_DESC_LOW => {
                    if let Some(queue) = self.queue() {
                        queue.set_desc_lo(v);
                    }
                }
                reg::QUEUE_DESC_HIGH => {
                    if let Some(queue) = self.queue() {
                        queue.set_desc_hi(v);
                    }
                }
                reg::QUEUE_DRIVER_LOW => {
                    if let Some(queue) = self.queue() {
                        queue.set_avail_lo(v);
                    }
                }
                reg::QUEUE_DRIVER_HIGH => {
                    if let Some(queue) = self.queue() {
                        queue.set_avail_hi(v);
                    }
                }
                reg::QUEUE_DEVICE_LOW => {
                    if let Some(queue) = self.queue() {
                        queue.set_used_lo(v);
                    }
                }
                reg::QUEUE_DEVICE_HIGH => {
                    if let Some(queue) = self.queue() {
                        queue.set_used_hi(v);
                    }
                }
                _ => {}
            }
            return 0;
        }

        match offset {
            reg::MAGIC => MAGIC_VALUE,
            reg::VERSION => 2,
            reg::DEVICE_ID => VIRTIO_FS_ID,
            reg::VENDOR_ID => VENDOR,
            reg::DEVICE_FEATURES if self.dev_feat_sel == 1 => u64::from(F_VERSION_1_HI),
            reg::QUEUE_NUM_MAX if (self.queue_sel as usize) < NUM_QUEUES => {
                u64::from(QUEUE_NUM_MAX)
            }
            reg::QUEUE_READY => self
                .queues
                .get(self.queue_sel as usize)
                .map_or(0, |queue| u64::from(queue.is_ready())),
            reg::INTERRUPT_STATUS => u64::from(self.interrupt_status),
            reg::STATUS => u64::from(self.status),
            _ if offset >= reg::CONFIG => self.read_config((offset - reg::CONFIG) as usize),
            _ => 0,
        }
    }

    fn read_config(&self, offset: usize) -> u64 {
        let mut cfg = [0u8; CONFIG_LEN];
        cfg[..TAG_LEN].copy_from_slice(&self.tag);
        cfg[TAG_LEN..].copy_from_slice(&1u32.to_le_bytes());
        let mut word = [0u8; 8];
        for (i, byte) in word.iter_mut().enumerate() {
            if let Some(value) = cfg.get(offset + i) {
                *byte = *value;
            }
        }
        u64::from_le_bytes(word)
    }

    /// Clears and returns the set of queues notified since the last call.
    /// Only `drain_notified` calls this; kept separate so a test can
    /// observe the bitmask `mmio` left behind without also draining it.
    pub(crate) fn take_notified(&mut self) -> u32 {
        std::mem::take(&mut self.notified)
    }

    /// Drains every queue flagged by a `QUEUE_NOTIFY` since the last drain.
    /// This is the worker thread's side of Stage A: `mmio` (the vCPU thread)
    /// only ever sets bits in `notified`, and this is the only thing that
    /// clears them and actually calls `process_queue`. Always called with
    /// the device mutex held, and never from the vCPU thread.
    pub(crate) fn drain_notified(&mut self, mem: &GuestRam) {
        self.drain_notified_bounded(mem, u16::MAX);
    }

    /// Drains every flagged queue, servicing at most `budget` chains from
    /// each. Returns true when work remained, meaning the caller should hand
    /// the rest to the worker thread instead of finishing it itself.
    ///
    /// This is what lets the vCPU service a shallow queue in its own exit.
    /// Waking the worker costs a park/unpark and a context switch -- around
    /// 20us measured -- which is far more than a virtio-fs request against a
    /// warm local filesystem actually takes (a 4 KiB write is ~7us of host
    /// time). Handing every request over therefore made small-write workloads
    /// 2.6x slower than servicing them inline. Deep queues still go to the
    /// worker, where the handoff is amortised over many requests and the
    /// overlap with the guest is what matters.
    pub(crate) fn drain_notified_bounded(&mut self, mem: &GuestRam, budget: u16) -> bool {
        let mask = self.take_notified();
        let mut remaining = false;
        for idx in 0..NUM_QUEUES {
            if mask & (1 << idx) != 0 && self.process_queue_bounded(mem, idx, budget) {
                // Re-flag: the queue still has chains the budget did not
                // cover, and `take_notified` has already cleared the bit.
                self.notified |= 1 << idx;
                remaining = true;
            }
        }
        remaining
    }

    /// Services at most `budget` chains from `queue_idx`. Returns true when
    /// the queue still had work left over, so a bounded caller knows to hand
    /// the remainder on rather than dropping it.
    pub(crate) fn process_queue_bounded(
        &mut self,
        mem: &GuestRam,
        queue_idx: usize,
        budget: u16,
    ) -> bool {
        if !self.queues[queue_idx].is_ready() {
            return false;
        }
        let Some(pending) = self.queues[queue_idx].pending(mem) else {
            return false;
        };
        let take = pending.min(budget);
        let mut last = self.queues[queue_idx].last_avail();
        let mut serviced = false;
        for _ in 0..take {
            let Some(slot) = self.queues[queue_idx].avail_slot(last) else {
                break;
            };
            let Ok(head) = mem.read_u16(slot) else {
                break;
            };
            let used = self.handle_chain(mem, queue_idx, head);
            self.queues[queue_idx].push_used(mem, head, used);
            last = last.wrapping_add(1);
            serviced = true;
        }
        self.queues[queue_idx].set_last_avail(last);
        if serviced {
            self.interrupt_status |= 1;
        }
        take < pending
    }

    fn handle_chain(&mut self, mem: &GuestRam, queue_idx: usize, head: u16) -> u32 {
        let q = &self.queues[queue_idx];
        // Descriptor-lists, not a concatenated buffer: Linux always lays a
        // request out as header(+small fixed args) in the input descriptors
        // and any bulk payload in its own descriptor(s), which is what lets
        // READ/WRITE go straight to/from guest RAM below instead of through
        // an intermediate copy.
        let mut input: Vec<(u64, u32)> = Vec::new();
        let mut output: Vec<(u64, u32)> = Vec::new();
        let mut total_in = 0usize;
        let mut desc = head;
        for _ in 0..q.size() {
            let Some(da) = q.desc_addr(desc) else {
                return 0;
            };
            let (Ok(addr), Ok(len), Ok(flags), Ok(next)) = (
                mem.read_u64(da),
                mem.read_u32(da + 8),
                mem.read_u16(da + 12),
                mem.read_u16(da + 14),
            ) else {
                return 0;
            };
            if flags & DESC_WRITE != 0 {
                output.push((addr, len));
            } else {
                let Some(total) = total_in.checked_add(len as usize) else {
                    return 0;
                };
                if total > MAX_REQUEST {
                    return 0;
                }
                total_in = total;
                input.push((addr, len));
            }
            if flags & DESC_NEXT == 0 {
                break;
            }
            desc = next;
        }
        if total_in < IN_HEADER_LEN || output.is_empty() {
            return 0;
        }
        let max_out: usize = output.iter().map(|(_, len)| *len as usize).sum();
        match self.handle_fuse_desc(mem, &input, &output, max_out) {
            Reply::Direct(n) => n as u32,
            Reply::Buffered(response) => {
                if response.len() > max_out {
                    return 0;
                }
                let mut copied = 0usize;
                for (addr, len) in output {
                    if copied == response.len() {
                        break;
                    }
                    let n = (len as usize).min(response.len() - copied);
                    if mem.write(addr, &response[copied..copied + n]).is_err() {
                        return copied as u32;
                    }
                    copied += n;
                }
                copied as u32
            }
        }
    }

    /// Descriptor-aware dispatch, called from `handle_chain`. `handle_fuse`
    /// itself is untouched and keeps its exact signature -- every opcode
    /// other than READ/WRITE, and any READ/WRITE that does not fit the
    /// direct path, ends up here reconstructing the same concatenated
    /// request buffer `handle_chain` used to build unconditionally before
    /// this change, and handing it to `handle_fuse` exactly as before. That
    /// is also the whole of what the 22 pre-existing tests exercise, since
    /// they call `handle_fuse` directly with no `GuestRam` at all.
    ///
    /// Only READ and WRITE ever take the direct path below, and only when
    /// the shape is exactly what they need (a real file handle, descriptor
    /// counts under `IOV_MAX`, the declared size matching what the
    /// descriptors actually carry).
    fn handle_fuse_desc(
        &mut self,
        mem: &GuestRam,
        input: &[(u64, u32)],
        output: &[(u64, u32)],
        max_out: usize,
    ) -> Reply {
        let mut header = [0u8; IN_HEADER_LEN];
        if gather(mem, input, 0, &mut header).is_err() {
            return Reply::Buffered(error_response(0, EIO));
        }
        let declared = get_u32(&header, 0).unwrap_or(0) as usize;
        let opcode = get_u32(&header, 4).unwrap_or(0);
        let unique = get_u64(&header, 8).unwrap_or(0);

        let direct = match opcode {
            READ => self.read_direct(mem, unique, declared, input, output, max_out),
            WRITE => {
                let nodeid = get_u64(&header, 16).unwrap_or(0);
                self.write_direct(mem, nodeid, unique, declared, input)
            }
            _ => None,
        };
        if let Some(reply) = direct {
            return reply;
        }

        let total: usize = input.iter().map(|(_, len)| *len as usize).sum();
        let mut request = vec![0u8; total];
        if gather(mem, input, 0, &mut request).is_err() {
            return Reply::Buffered(error_response(unique, EIO));
        }
        Reply::Buffered(self.handle_fuse(&request, max_out))
    }

    fn handle_fuse(&mut self, raw: &[u8], max_out: usize) -> Vec<u8> {
        let declared = get_u32(raw, 0).unwrap_or(0) as usize;
        let opcode = get_u32(raw, 4).unwrap_or(0);
        let unique = get_u64(raw, 8).unwrap_or(0);
        let nodeid = get_u64(raw, 16).unwrap_or(0);
        let request_context = RequestContext {
            uid: get_u32(raw, 24).unwrap_or(0),
            gid: get_u32(raw, 28).unwrap_or(0),
        };
        if declared < IN_HEADER_LEN || declared > raw.len() {
            return error_response(unique, EINVAL);
        }
        let payload = &raw[IN_HEADER_LEN..declared];
        let result = match opcode {
            FORGET => {
                self.forget(nodeid, payload);
                return Vec::new();
            }
            BATCH_FORGET => {
                self.batch_forget(payload);
                return Vec::new();
            }
            DESTROY => return Vec::new(),
            INIT => self.init(payload),
            LOOKUP => self.lookup(nodeid, payload),
            GETATTR => self.getattr(nodeid, payload),
            SETATTR => self.setattr(nodeid, payload),
            READLINK => self.readlink(nodeid),
            SYMLINK => self.symlink(nodeid, payload, request_context),
            MKNOD => self.mknod(nodeid, payload, request_context),
            MKDIR => self.mkdir(nodeid, payload, request_context),
            UNLINK => self.remove(nodeid, payload, false),
            RMDIR => self.remove(nodeid, payload, true),
            RENAME => self.rename(nodeid, payload, false),
            RENAME2 => self.rename(nodeid, payload, true),
            LINK => self.link(nodeid, payload),
            OPEN => self.open(nodeid, payload, false),
            OPENDIR => self.open(nodeid, payload, true),
            READ => self.read(nodeid, payload, max_out.saturating_sub(OUT_HEADER_LEN)),
            WRITE => self.write(nodeid, payload),
            READDIR => self.readdir(
                nodeid,
                payload,
                max_out.saturating_sub(OUT_HEADER_LEN),
                false,
            ),
            STATFS => self.statfs(),
            ACCESS => self.access(nodeid, payload),
            CREATE => self.create(nodeid, payload, request_context),
            SETXATTR => self.setxattr(nodeid, payload),
            GETXATTR => self.getxattr(nodeid, payload),
            LISTXATTR => self.listxattr(nodeid, payload),
            REMOVEXATTR => self.removexattr(nodeid, payload),
            RELEASE => self.release(payload),
            RELEASEDIR => self.release_dir(payload),
            FLUSH => self.flush(payload),
            FSYNC => self.fsync(payload),
            FSYNCDIR => self.fsync_dir(payload),
            GETLK => self.lock(payload, GETLK),
            SETLK => self.lock(payload, SETLK),
            SETLKW => self.lock(payload, SETLKW),
            POLL => self.poll(payload),
            FALLOCATE => self.fallocate(payload),
            READDIRPLUS => self.readdir(
                nodeid,
                payload,
                max_out.saturating_sub(OUT_HEADER_LEN),
                true,
            ),
            LSEEK => self.lseek(payload),
            COPY_FILE_RANGE => self.copy_file_range(payload),
            SYNCFS => self.syncfs(),
            TMPFILE => self.tmpfile(nodeid, payload, request_context),
            STATX => self.statx(nodeid, payload),
            39 => Err(ENOTTY), // IOCTL: regular files can use libc fallbacks.
            48 | 49 => Err(EOPNOTSUPP), // No DAX mapping window.
            _ => Err(ENOSYS),
        };
        match result {
            Ok(payload) => success_response(unique, &payload),
            Err(errno) => error_response(unique, errno),
        }
    }

    fn init(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let major = get_u32(input, 0).ok_or(EINVAL)?;
        let minor = get_u32(input, 4).ok_or(EINVAL)?;
        let readahead = get_u32(input, 8).unwrap_or(0);
        let guest_flags = get_u32(input, 12).unwrap_or(0);
        if major != 7 {
            let mut out = Vec::with_capacity(8);
            put_u32(&mut out, 7);
            put_u32(&mut out, 39);
            return Ok(out);
        }
        const ASYNC_READ: u32 = 1 << 0;
        const POSIX_LOCKS: u32 = 1 << 1;
        const ATOMIC_O_TRUNC: u32 = 1 << 3;
        const EXPORT_SUPPORT: u32 = 1 << 4;
        const BIG_WRITES: u32 = 1 << 5;
        const FLOCK_LOCKS: u32 = 1 << 10;
        const AUTO_INVAL_DATA: u32 = 1 << 12;
        const DO_READDIRPLUS: u32 = 1 << 13;
        const READDIRPLUS_AUTO: u32 = 1 << 14;
        const MAX_PAGES: u32 = 1 << 22;
        const CACHE_SYMLINKS: u32 = 1 << 23;
        const HANDLE_KILLPRIV_V2: u32 = 1 << 28;
        const SETXATTR_EXT: u32 = 1 << 29;
        // Every LOOKUP/READDIR the guest issues in parallel is independent of
        // every other -- there is no shared cursor or lock this backend needs
        // to serialise them for.
        const PARALLEL_DIROPS: u32 = 1 << 18;
        // Hands mtime/ctime/size ownership to the guest, which then batches
        // writes into large aligned WRITEs instead of round-tripping through
        // us for every page. Only correct when the guest is the sole writer,
        // which is exactly what CachePolicy::Always asserts.
        const WRITEBACK_CACHE: u32 = 1 << 16;
        let mut supported = ASYNC_READ
            | POSIX_LOCKS
            | ATOMIC_O_TRUNC
            | EXPORT_SUPPORT
            | BIG_WRITES
            | FLOCK_LOCKS
            | AUTO_INVAL_DATA
            | DO_READDIRPLUS
            | READDIRPLUS_AUTO
            | MAX_PAGES
            | HANDLE_KILLPRIV_V2
            | SETXATTR_EXT
            | PARALLEL_DIROPS;
        // Read-only shares always get this (cannot go stale from the guest's
        // side); writable shares only when the operator opted into caching.
        if !self.writable || self.cache_policy != CachePolicy::None {
            supported |= CACHE_SYMLINKS;
        }
        if self.writable && self.cache_policy == CachePolicy::Always {
            supported |= WRITEBACK_CACHE;
        }
        let mut out = Vec::with_capacity(64);
        put_u32(&mut out, 7);
        put_u32(&mut out, minor.min(39));
        put_u32(&mut out, readahead);
        put_u32(&mut out, guest_flags & supported);
        put_u16(&mut out, 64);
        put_u16(&mut out, 48);
        put_u32(&mut out, MAX_WRITE);
        put_u32(&mut out, 1); // nanosecond timestamp granularity
        put_u16(&mut out, (MAX_WRITE / 4096) as u16);
        put_u16(&mut out, 0); // no DAX mapping window
        put_u32(&mut out, 0); // flags2
        out.resize(64, 0);
        Ok(out)
    }

    fn lookup(&mut self, parent: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        let end = input.iter().position(|b| *b == 0).ok_or(EINVAL)?;
        let name = &input[..end];
        if name.is_empty() || name.contains(&b'/') {
            return Err(EINVAL);
        }
        let parent_path = self.node_path(parent)?.to_owned();
        let path = if name == b"." {
            parent_path
        } else if name == b".." {
            if parent_path == self.root {
                self.root.clone()
            } else {
                parent_path.parent().unwrap_or(&self.root).to_owned()
            }
        } else {
            parent_path.join(OsStr::from_bytes(name))
        };
        // A socket this device holds has no host entry to stat, so it is
        // looked for before the error is reported rather than after.
        if let Some(socket) = self.sockets.get(&path).copied() {
            let node = self.socket_node_id(&path, socket.ino);
            self.remember_lookup(node);
            return Ok(socket_entry_out(node, socket));
        }
        let meta = fs::symlink_metadata(&path).map_err(io_errno)?;
        let node = self.node_for(path.clone(), &meta);
        self.remember_lookup(node);
        Ok(self.entry_out(node, &path, &meta))
    }

    fn getattr(&mut self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        if let Some((_, socket)) = self.socket_at(node) {
            return Ok(socket_attr_out(node, socket));
        }
        let flags = get_u32(input, 0).unwrap_or(0);
        let fh = get_u64(input, 8).unwrap_or(0);
        let (path, meta) = if flags & FUSE_GETATTR_FH != 0 {
            let handle = self.handles.get(&fh).ok_or(EBADF)?;
            let meta = handle.file.metadata().map_err(io_errno)?;
            (handle.path.clone(), meta)
        } else {
            let path = self.node_path(node)?.to_owned();
            let meta = fs::symlink_metadata(&path).map_err(io_errno)?;
            (path, meta)
        };
        Ok(self.attr_out(node, &path, &meta))
    }

    fn setattr(&mut self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let valid = get_u32(input, 0).ok_or(EINVAL)?;
        // A socket's attributes live in this device, so a chmod or chown of
        // one updates the record instead of reaching for a file that is not
        // there. This is not academic: a program may refuse to use a socket
        // whose directory or mode is not what it left it as.
        if let Some((path, mut socket)) = self.socket_at(node) {
            if valid & FATTR_MODE != 0 {
                let mode = get_u32(input, 68).ok_or(EINVAL)?;
                socket.mode = S_IFSOCK | (mode & 0o7777);
            }
            if valid & FATTR_UID != 0 {
                socket.uid = get_u32(input, 76).ok_or(EINVAL)?;
            }
            if valid & FATTR_GID != 0 {
                socket.gid = get_u32(input, 80).ok_or(EINVAL)?;
            }
            // `touch` on a socket is legal and a guest may well do it, so an
            // explicit time is taken and a "now" request is answered with the
            // clock rather than ignored.
            if valid & (FATTR_MTIME_NOW | FATTR_ATIME_NOW) != 0 {
                socket.time = now_parts();
            } else if valid & FATTR_MTIME != 0 {
                socket.time = (
                    get_u64(input, 40).ok_or(EINVAL)?,
                    get_u32(input, 60).ok_or(EINVAL)?,
                );
            } else if valid & FATTR_ATIME != 0 {
                socket.time = (
                    get_u64(input, 32).ok_or(EINVAL)?,
                    get_u32(input, 56).ok_or(EINVAL)?,
                );
            }
            self.sockets.insert(path, socket);
            return Ok(socket_attr_out(node, socket));
        }
        let fh = get_u64(input, 8).ok_or(EINVAL)?;
        let size = get_u64(input, 16).ok_or(EINVAL)?;
        let atime = get_u64(input, 32).ok_or(EINVAL)?;
        let mtime = get_u64(input, 40).ok_or(EINVAL)?;
        let atime_nsec = get_u32(input, 56).ok_or(EINVAL)?;
        let mtime_nsec = get_u32(input, 60).ok_or(EINVAL)?;
        let mode = get_u32(input, 68).ok_or(EINVAL)?;
        let uid = get_u32(input, 76).ok_or(EINVAL)?;
        let gid = get_u32(input, 80).ok_or(EINVAL)?;
        let known = FATTR_MODE
            | FATTR_UID
            | FATTR_GID
            | FATTR_SIZE
            | FATTR_ATIME
            | FATTR_MTIME
            | FATTR_FH
            | FATTR_ATIME_NOW
            | FATTR_MTIME_NOW
            | FATTR_LOCKOWNER
            | FATTR_CTIME
            | FATTR_KILL_SUIDGID;
        if valid & !known != 0 {
            return Err(EINVAL);
        }

        let path = if valid & FATTR_FH == 0 {
            Some(self.node_path(node)?.to_owned())
        } else {
            None
        };
        let handle = if valid & FATTR_FH != 0 {
            Some(self.handles.get(&fh).ok_or(EBADF)?)
        } else {
            None
        };
        let metadata_path = handle
            .map(|handle| handle.path.as_path())
            .or(path.as_deref())
            .ok_or(EINVAL)?;

        if valid & FATTR_SIZE != 0 {
            if let Some(handle) = handle {
                if !handle.writable {
                    return Err(EBADF);
                }
                handle.file.set_len(size).map_err(io_errno)?;
            } else {
                let file = open_host_file(path.as_deref().ok_or(EINVAL)?, LINUX_O_WRONLY, false, 0)
                    .map_err(io_errno)?;
                file.set_len(size).map_err(io_errno)?;
            }
        }

        if valid & (FATTR_UID | FATTR_GID) != 0 {
            #[cfg(target_os = "macos")]
            {
                let current_meta = if let Some(handle) = handle {
                    handle.file.metadata().map_err(io_errno)?
                } else {
                    fs::symlink_metadata(metadata_path).map_err(io_errno)?
                };
                let mut guest = guest_attr(Some(metadata_path), &current_meta);
                if valid & FATTR_UID != 0 {
                    guest.uid = uid;
                }
                if valid & FATTR_GID != 0 {
                    guest.gid = gid;
                }
                set_guest_attr(metadata_path, guest)?;
            }
            #[cfg(target_os = "linux")]
            {
                let host_uid = if valid & FATTR_UID != 0 {
                    Some(guest_uid_to_host(uid))
                } else {
                    None
                };
                let host_gid = if valid & FATTR_GID != 0 {
                    Some(guest_gid_to_host(gid))
                } else {
                    None
                };
                if let Some(handle) = handle {
                    host_fchown(&handle.file, host_uid, host_gid)?;
                } else {
                    host_lchown(path.as_deref().ok_or(EINVAL)?, host_uid, host_gid)?;
                }
            }
        }

        if valid & (FATTR_MODE | FATTR_KILL_SUIDGID) != 0 {
            let current_meta = if let Some(handle) = handle {
                handle.file.metadata().map_err(io_errno)?
            } else {
                fs::symlink_metadata(path.as_deref().ok_or(EINVAL)?).map_err(io_errno)?
            };
            let mut new_mode = if valid & FATTR_MODE != 0 {
                mode & 0o7777
            } else {
                guest_attr(Some(metadata_path), &current_meta).mode & 0o7777
            };
            if valid & FATTR_KILL_SUIDGID != 0 {
                new_mode &= !0o6000;
            }
            #[cfg(target_os = "macos")]
            {
                if !current_meta.file_type().is_symlink() {
                    let host_mode = host_creation_mode(new_mode, current_meta.is_dir());
                    if let Some(handle) = handle {
                        handle
                            .file
                            .set_permissions(Permissions::from_mode(host_mode))
                            .map_err(io_errno)?;
                    } else {
                        host_lchmod(path.as_deref().ok_or(EINVAL)?, host_mode)?;
                    }
                }
                let mut guest = guest_attr(Some(metadata_path), &current_meta);
                guest.mode = (current_meta.mode() & S_IFMT) | new_mode;
                set_guest_attr(metadata_path, guest)?;
            }
            #[cfg(target_os = "linux")]
            {
                if let Some(handle) = handle {
                    handle
                        .file
                        .set_permissions(Permissions::from_mode(new_mode))
                        .map_err(io_errno)?;
                } else {
                    host_lchmod(path.as_deref().ok_or(EINVAL)?, new_mode)?;
                }
            }
        }

        if valid & (FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW) != 0 {
            let times = fuse_times(valid, atime, atime_nsec, mtime, mtime_nsec)?;
            if let Some(handle) = handle {
                host_futimens(&handle.file, &times)?;
            } else {
                host_lutimens(path.as_deref().ok_or(EINVAL)?, &times)?;
            }
        }

        // Clone the path out from under `handle` (rather than keep borrowing
        // it) so the borrow of `self.handles` ends here, before the `&mut
        // self` calls below that invalidate the cache and build the reply.
        let (final_path, meta) = if let Some(handle) = handle {
            (
                handle.path.clone(),
                handle.file.metadata().map_err(io_errno)?,
            )
        } else {
            let final_path = path.as_deref().ok_or(EINVAL)?.to_owned();
            let meta = fs::symlink_metadata(&final_path).map_err(io_errno)?;
            (final_path, meta)
        };
        // A setattr may have written HVI_XATTR_LINUX_ATTR above (uid/gid/mode
        // branches); unconditionally invalidating is simpler than tracking
        // exactly which branch fired, and costs nothing but a HashMap write.
        self.invalidate_guest_attr(node);
        Ok(self.attr_out(node, &final_path, &meta))
    }

    fn require_writable(&self) -> Result<(), i32> {
        if self.writable {
            Ok(())
        } else {
            Err(EROFS)
        }
    }

    fn child_path(&self, parent: u64, name: &[u8]) -> Result<PathBuf, i32> {
        validate_mutation_name(name)?;
        let parent = self.node_path(parent)?;
        // FUSE path resolution follows directory symlinks.  Keep using
        // symlink_metadata for the node identity, but follow the parent here
        // so mutations below a symlinked directory (common in distro include
        // trees) are not rejected as ENOTDIR/ENOENT.
        //
        // There was a containment check here and in `lookup` that resolved
        // this path and refused it unless it stayed under the export root. It
        // is gone, and re-adding it in that shape is not the fix: resolving a
        // path string host-side asks the wrong question, because an absolute
        // symlink in a guest rootfs names the guest's filesystem and not
        // ours. `/usr/lib/ssl/certs -> /etc/ssl/certs` means the guest's
        // `/etc`; on the host it resolves to `/private/etc/ssl/certs`, which
        // is outside any export. Containment stays with the Seatbelt profile
        // until the path layer resolves relative to a descriptor instead
        // (NOFireAI/hvi-vmm#30), which makes it structural rather than a
        // check that can be asked the wrong question.
        if !fs::metadata(parent).map_err(io_errno)?.is_dir() {
            return Err(ENOTDIR);
        }
        Ok(parent.join(OsStr::from_bytes(name)))
    }

    fn new_entry(&mut self, path: PathBuf) -> Result<Vec<u8>, i32> {
        let meta = fs::symlink_metadata(&path).map_err(io_errno)?;
        let node = self.node_for(path.clone(), &meta);
        self.remember_lookup(node);
        Ok(self.entry_out(node, &path, &meta))
    }

    fn mknod(
        &mut self,
        parent: u64,
        input: &[u8],
        context: RequestContext,
    ) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let mode = get_u32(input, 0).ok_or(EINVAL)?;
        let name = nul_name(input, 16)?;
        let path = self.child_path(parent, name)?;
        match mode & S_IFMT {
            S_IFREG => {
                open_host_file(
                    &path,
                    LINUX_O_WRONLY | LINUX_O_EXCL,
                    true,
                    host_creation_mode(mode, false),
                )
                .map_err(io_errno)?;
            }
            S_IFIFO => host_mkfifo(&path, host_creation_mode(mode, false))?,
            // A socket is served from this device rather than created on the
            // host: see `VirtioFs::sockets`. `bind(2)` in the guest is what
            // lands here, and it expects the entry to exist afterwards.
            S_IFSOCK => return self.create_socket(path, mode, context),
            // Never create host device nodes from a guest.
            _ => return Err(EPERM),
        }
        initialize_guest_metadata(&path, mode, context)?;
        self.new_entry(path)
    }

    /// Records a socket at `path` and answers as if it had been created.
    fn create_socket(
        &mut self,
        path: PathBuf,
        mode: u32,
        context: RequestContext,
    ) -> Result<Vec<u8>, i32> {
        // A host entry at the same name wins: the guest asked to create
        // something that is already there, whatever its type.
        if fs::symlink_metadata(&path).is_ok() || self.sockets.contains_key(&path) {
            return Err(EEXIST);
        }
        let ino = self.next_socket_ino;
        self.next_socket_ino = self.next_socket_ino.saturating_add(1);
        let socket = SocketNode {
            mode: S_IFSOCK | (mode & 0o7777),
            uid: context.uid,
            gid: context.gid,
            ino,
            time: now_parts(),
        };
        self.sockets.insert(path.clone(), socket);
        let node = self.socket_node_id(&path, ino);
        self.remember_lookup(node);
        Ok(socket_entry_out(node, socket))
    }

    /// The node id for a socket, allocated once and then remembered, so a
    /// lookup after the guest dropped its cache lands on the same inode.
    fn socket_node_id(&mut self, path: &Path, ino: u64) -> u64 {
        let key = (SOCKET_DEV, ino);
        if let Some(node) = self.inode_ids.get(&key) {
            return *node;
        }
        let node = self.next_node;
        self.next_node = self.next_node.saturating_add(1);
        self.inode_ids.insert(key, node);
        self.nodes.insert(
            node,
            Node {
                key,
                paths: vec![path.to_owned()],
                lookups: 0,
                guest_attr: None,
            },
        );
        node
    }

    /// The socket at `node`, if that node is one.
    fn socket_at(&self, node: u64) -> Option<(PathBuf, SocketNode)> {
        let remembered = self.nodes.get(&node)?;
        if remembered.key.0 != SOCKET_DEV {
            return None;
        }
        let path = remembered.paths.first()?;
        self.sockets.get(path).map(|s| (path.clone(), *s))
    }

    fn mkdir(
        &mut self,
        parent: u64,
        input: &[u8],
        context: RequestContext,
    ) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let mode = get_u32(input, 0).ok_or(EINVAL)?;
        let name = nul_name(input, 8)?;
        let path = self.child_path(parent, name)?;
        let mut builder = fs::DirBuilder::new();
        builder
            .mode(host_creation_mode(mode, true))
            .create(&path)
            .map_err(io_errno)?;
        initialize_guest_metadata(&path, mode, context)?;
        self.new_entry(path)
    }

    fn symlink(
        &mut self,
        parent: u64,
        input: &[u8],
        context: RequestContext,
    ) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let (name, next) = nul_name_with_end(input, 0)?;
        let target = nul_name(input, next)?;
        let path = self.child_path(parent, name)?;
        std::os::unix::fs::symlink(OsStr::from_bytes(target), &path).map_err(io_errno)?;
        initialize_guest_metadata(&path, 0o777, context)?;
        self.new_entry(path)
    }

    fn link(&mut self, new_parent: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let old_node = get_u64(input, 0).ok_or(EINVAL)?;
        let name = nul_name(input, 8)?;
        let old_path = self.node_path(old_node)?.to_owned();
        let new_path = self.child_path(new_parent, name)?;
        host_link(&old_path, &new_path)?;
        self.new_entry(new_path)
    }

    fn remove(&mut self, parent: u64, input: &[u8], directory: bool) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let name = nul_name(input, 0)?;
        let path = self.child_path(parent, name)?;
        // Unlinking a socket takes it out of this device and leaves the host
        // alone, because putting it there was never part of creating it.
        if !directory && self.sockets.remove(&path).is_some() {
            let stale: Vec<u64> = self
                .nodes
                .iter()
                .filter(|(_, node)| node.key.0 == SOCKET_DEV && node.paths.contains(&path))
                .map(|(id, _)| *id)
                .collect();
            for id in stale {
                if let Some(node) = self.nodes.remove(&id) {
                    self.inode_ids.remove(&node.key);
                }
            }
            return Ok(Vec::new());
        }
        let meta = fs::symlink_metadata(&path).map_err(io_errno)?;
        if directory {
            fs::remove_dir(&path).map_err(io_errno)?;
        } else {
            fs::remove_file(&path).map_err(io_errno)?;
        }
        self.forget_node_path(&path, &meta);
        Ok(Vec::new())
    }

    fn rename(&mut self, old_parent: u64, input: &[u8], version2: bool) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let new_parent = get_u64(input, 0).ok_or(EINVAL)?;
        let (flags, names_at) = if version2 {
            (get_u32(input, 8).ok_or(EINVAL)?, 16)
        } else {
            (0, 8)
        };
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
            || flags & RENAME_WHITEOUT != 0
            || flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0
        {
            return Err(EOPNOTSUPP);
        }
        let (old_name, next) = nul_name_with_end(input, names_at)?;
        let new_name = nul_name(input, next)?;
        let old_path = self.child_path(old_parent, old_name)?;
        let new_path = self.child_path(new_parent, new_name)?;
        let old_meta = fs::symlink_metadata(&old_path).map_err(io_errno)?;
        let replaced = fs::symlink_metadata(&new_path).ok();
        host_rename(&old_path, &new_path, flags)?;
        if flags & RENAME_EXCHANGE != 0 {
            self.exchange_node_paths(&old_path, &new_path);
            return Ok(Vec::new());
        }
        if let Some(meta) = replaced {
            if (meta.dev(), meta.ino()) == (old_meta.dev(), old_meta.ino()) {
                return Ok(Vec::new());
            }
            self.forget_node_path(&new_path, &meta);
        }
        self.rewrite_node_paths(&old_path, &new_path);
        Ok(Vec::new())
    }

    fn rewrite_node_paths(&mut self, old: &Path, new: &Path) {
        for node in self.nodes.values_mut() {
            for path in &mut node.paths {
                let Ok(suffix) = path.strip_prefix(old) else {
                    continue;
                };
                *path = if suffix.as_os_str().is_empty() {
                    new.to_owned()
                } else {
                    new.join(suffix)
                };
            }
        }
    }

    fn exchange_node_paths(&mut self, left: &Path, right: &Path) {
        for node in self.nodes.values_mut() {
            for path in &mut node.paths {
                if let Ok(suffix) = path.strip_prefix(left) {
                    *path = if suffix.as_os_str().is_empty() {
                        right.to_owned()
                    } else {
                        right.join(suffix)
                    };
                } else if let Ok(suffix) = path.strip_prefix(right) {
                    *path = if suffix.as_os_str().is_empty() {
                        left.to_owned()
                    } else {
                        left.join(suffix)
                    };
                }
            }
        }
    }

    fn create(
        &mut self,
        parent: u64,
        input: &[u8],
        context: RequestContext,
    ) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let flags = get_u32(input, 0).ok_or(EINVAL)?;
        let mode = get_u32(input, 4).ok_or(EINVAL)?;
        let open_flags = get_u32(input, 12).ok_or(EINVAL)?;
        let name = nul_name(input, 16)?;
        let path = self.child_path(parent, name)?;
        let file = open_host_file(&path, flags, true, host_creation_mode(mode, false))
            .map_err(io_errno)?;
        initialize_guest_metadata(&path, mode, context)?;
        if open_flags & FUSE_OPEN_KILL_SUIDGID != 0 {
            clear_suid_sgid(&path, &file)?;
        }
        let meta = file.metadata().map_err(io_errno)?;
        let node = self.node_for(path.clone(), &meta);
        self.remember_lookup(node);
        let mut out = self.entry_out(node, &path, &meta);
        let fh = self.insert_handle(file, flags & LINUX_O_ACCMODE != 0, path);
        put_open_out(&mut out, fh, false, self.cache_policy != CachePolicy::None);
        Ok(out)
    }
    fn readlink(&self, node: u64) -> Result<Vec<u8>, i32> {
        let path = self.node_path(node)?;
        let meta = fs::symlink_metadata(path).map_err(io_errno)?;
        if !meta.file_type().is_symlink() {
            return Err(EINVAL);
        }
        Ok(fs::read_link(path)
            .map_err(io_errno)?
            .as_os_str()
            .as_bytes()
            .to_vec())
    }

    fn open(&mut self, node: u64, input: &[u8], directory: bool) -> Result<Vec<u8>, i32> {
        let flags = get_u32(input, 0).ok_or(EINVAL)?;
        let open_flags = get_u32(input, 4).ok_or(EINVAL)?;
        let wants_write = flags & LINUX_O_ACCMODE != 0
            || flags & LINUX_O_TRUNC != 0
            || open_flags & FUSE_OPEN_KILL_SUIDGID != 0;
        if wants_write && !self.writable {
            return Err(EROFS);
        }
        let path = self.node_path(node)?.to_owned();
        let meta = fs::symlink_metadata(&path).map_err(io_errno)?;
        if directory && !meta.is_dir() {
            return Err(ENOTDIR);
        }
        if !directory && meta.is_dir() {
            return Err(EISDIR);
        }
        // Only a regular file may be opened here. Opening a FIFO blocks until
        // the other end is opened, and this request holds the device mutex --
        // on the vCPU thread when the queue is shallow enough to be served
        // inline -- so the guest would stop the VM rather than just itself.
        // A guest kernel opens a FIFO, socket or device node on a FUSE mount
        // itself and never sends OPEN for one, so refusing costs it nothing.
        //
        // `meta` comes from `symlink_metadata`, so this refuses a symlink too.
        // That is deliberate rather than a side effect: `open_host_file`
        // already passes `O_NOFOLLOW`, so such an open never succeeded, and
        // the only change is that the guest now sees EPERM where it saw
        // ELOOP.
        if !directory && !meta.is_file() {
            return Err(EPERM);
        }
        let fh = if directory {
            self.insert_dir_handle(&path)?
        } else {
            let file = open_host_file(&path, flags, false, 0).map_err(io_errno)?;
            if open_flags & FUSE_OPEN_KILL_SUIDGID != 0 {
                clear_suid_sgid(&path, &file)?;
                self.invalidate_guest_attr(node);
            }
            self.insert_handle(file, wants_write, path)
        };
        let mut out = Vec::with_capacity(16);
        put_open_out(
            &mut out,
            fh,
            directory,
            self.cache_policy != CachePolicy::None,
        );
        Ok(out)
    }

    fn read(&self, node: u64, input: &[u8], capacity: usize) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        let offset = get_u64(input, 8).ok_or(EINVAL)?;
        let requested = get_u32(input, 16).ok_or(EINVAL)? as usize;
        let mut out = vec![0u8; requested.min(capacity).min(MAX_WRITE as usize)];
        let n = if let Some(handle) = self.handles.get(&fh) {
            handle.file.read_at(&mut out, offset).map_err(io_errno)?
        } else if fh == 0 {
            // A zero handle preserves compatibility with the earliest
            // stateless backend and is useful for pre-open protocol tests.
            let path = self.node_path(node)?;
            let meta = fs::symlink_metadata(path).map_err(io_errno)?;
            if !meta.is_file() {
                return Err(if meta.is_dir() { EISDIR } else { EINVAL });
            }
            let file = open_host_file(path, 0, false, 0).map_err(io_errno)?;
            file.read_at(&mut out, offset).map_err(io_errno)?
        } else {
            return Err(EBADF);
        };
        out.truncate(n);
        Ok(out)
    }

    fn write(&mut self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        let offset = get_u64(input, 8).ok_or(EINVAL)?;
        let size = get_u32(input, 16).ok_or(EINVAL)? as usize;
        let write_flags = get_u32(input, 20).ok_or(EINVAL)?;
        if size > MAX_WRITE as usize || input.len() < 40 + size {
            return Err(EINVAL);
        }
        let handle = self.handles.get(&fh).ok_or(EBADF)?;
        if !handle.writable {
            return Err(EBADF);
        }
        let n = handle
            .file
            .write_at(&input[40..40 + size], offset)
            .map_err(io_errno)?;
        if write_flags & FUSE_WRITE_KILL_SUIDGID != 0 {
            let handle = self.handles.get(&fh).ok_or(EBADF)?;
            clear_suid_sgid(&handle.path, &handle.file)?;
            self.invalidate_guest_attr(node);
        }
        let mut out = Vec::with_capacity(8);
        put_u32(&mut out, n as u32);
        put_u32(&mut out, 0);
        Ok(out)
    }

    /// The zero-copy READ path: `preadv` straight into the guest's output
    /// descriptors past the 16-byte out-header, instead of `read`'s
    /// allocate + `read_at` + `handle_chain`'s old scatter-copy.
    ///
    /// `None` means "take the buffered path instead" (via `read` above) --
    /// used for anything this shortcut does not handle, including the
    /// `fh == 0` stateless-read compatibility branch and a chain with more
    /// output descriptors than `IOV_MAX`, so as not to duplicate that
    /// handling here.
    fn read_direct(
        &self,
        mem: &GuestRam,
        unique: u64,
        declared: usize,
        input: &[(u64, u32)],
        output: &[(u64, u32)],
        max_out: usize,
    ) -> Option<Reply> {
        // fuse_read_in: fh(8) offset(8) size(4), the fields `read` uses.
        // `declared > total_in` mirrors `handle_fuse`'s own top-level check
        // (a guest cannot declare more than it physically supplied); without
        // it this shortcut would accept a malformed request the buffered
        // path has always rejected with EINVAL.
        let total_in: usize = input.iter().map(|(_, len)| *len as usize).sum();
        if declared < IN_HEADER_LEN + 20 || declared > total_in {
            return None;
        }
        let mut args = [0u8; 20];
        gather(mem, input, IN_HEADER_LEN, &mut args).ok()?;
        let fh = get_u64(&args, 0)?;
        if fh == 0 {
            return None;
        }
        let offset = get_u64(&args, 8)?;
        let requested = get_u32(&args, 16)? as usize;
        let handle = self.handles.get(&fh)?;

        let capacity = max_out.saturating_sub(OUT_HEADER_LEN);
        let want = requested.min(capacity).min(MAX_WRITE as usize);
        let (iov, _covered) = build_iov(mem, output, OUT_HEADER_LEN, want).ok()?;

        let n = match preadv_retry(&handle.file, &iov, offset) {
            Ok(n) => n,
            Err(e) => return Some(Reply::Buffered(error_response(unique, io_errno(e)))),
        };
        self.note_zero_copy_read();
        match write_direct_out_header(mem, output, unique, (OUT_HEADER_LEN + n) as u32) {
            Ok(()) => Some(Reply::Direct(OUT_HEADER_LEN + n)),
            Err(_) => Some(Reply::Buffered(error_response(unique, EIO))),
        }
    }

    /// The zero-copy WRITE path: `pwritev` straight out of the guest's input
    /// descriptors carrying the payload, instead of concatenating every
    /// input descriptor into one growing `Vec` before a single `write_at`.
    ///
    /// `None` falls back to the buffered `write` above, which re-validates
    /// independently -- this includes the security-relevant bound (`size`
    /// must not exceed what the guest actually declared/supplied), so a
    /// mismatch here is always safe to just defer rather than reject
    /// itself.
    fn write_direct(
        &mut self,
        mem: &GuestRam,
        node: u64,
        unique: u64,
        declared: usize,
        input: &[(u64, u32)],
    ) -> Option<Reply> {
        if !self.writable {
            return None;
        }
        let total_in: usize = input.iter().map(|(_, len)| *len as usize).sum();
        if declared < IN_HEADER_LEN || declared > total_in {
            return None;
        }
        // fuse_write_in: fh(8) offset(8) size(4) write_flags(4), matching
        // `write`'s own field offsets below.
        let mut args = [0u8; 24];
        gather(mem, input, IN_HEADER_LEN, &mut args).ok()?;
        let fh = get_u64(&args, 0)?;
        let offset = get_u64(&args, 8)?;
        let size = get_u32(&args, 16)? as usize;
        let write_flags = get_u32(&args, 20)?;

        // The security boundary: a guest must not make the daemon write from
        // outside the descriptors it actually offered. Mirrors `write`'s own
        // `size > MAX_WRITE || input.len() < 40 + size` bound exactly, using
        // `declared` (the guest's own claim) rather than the raw descriptor
        // byte count, since trailing descriptor slack past `declared` is not
        // part of the logical request either.
        if size > MAX_WRITE as usize || declared < IN_HEADER_LEN + 40 + size {
            return None;
        }

        let handle = self.handles.get(&fh)?;
        if !handle.writable {
            return None;
        }
        let (iov, covered) = build_iov(mem, input, IN_HEADER_LEN + 40, size).ok()?;
        if covered < size {
            return None;
        }
        let n = match pwritev_retry(&handle.file, &iov, offset) {
            Ok(n) => n,
            Err(e) => return Some(Reply::Buffered(error_response(unique, io_errno(e)))),
        };
        self.note_zero_copy_write();
        if write_flags & FUSE_WRITE_KILL_SUIDGID != 0 {
            if let Some(handle) = self.handles.get(&fh) {
                if let Err(errno) = clear_suid_sgid(&handle.path, &handle.file) {
                    return Some(Reply::Buffered(error_response(unique, errno)));
                }
            }
            self.invalidate_guest_attr(node);
        }
        let mut payload = Vec::with_capacity(8);
        put_u32(&mut payload, n as u32);
        put_u32(&mut payload, 0);
        Some(Reply::Buffered(success_response(unique, &payload)))
    }

    fn next_handle(&mut self) -> u64 {
        let fh = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1).max(1);
        fh
    }

    fn insert_handle(&mut self, file: File, writable: bool, path: PathBuf) -> u64 {
        let fh = self.next_handle();
        self.handles.insert(
            fh,
            FileHandle {
                file,
                writable,
                path,
                temporary_path: None,
            },
        );
        fh
    }

    fn insert_dir_handle(&mut self, path: &Path) -> Result<u64, i32> {
        let file = open_host_dir(path).map_err(io_errno)?;
        // `file_type()`/`ino()` are read straight off the dirent (`d_type`,
        // `d_ino`) on macOS and Linux, so capturing them here costs nothing
        // beyond the readdir(3) calls this loop already makes.
        let mut entries: Vec<DirEntryInfo> = fs::read_dir(path)
            .map_err(io_errno)?
            .filter_map(Result::ok)
            .map(|entry| DirEntryInfo {
                name: entry.file_name(),
                ino: entry.ino(),
                file_type: entry.file_type().ok(),
            })
            .collect();
        // Sockets this device holds are in no host directory, so they are
        // added here rather than found by `read_dir`. Doing it while the
        // handle is built means the listing is a snapshot like every other
        // entry's, and the pagination below needs to know nothing about them.
        for (socket_path, socket) in &self.sockets {
            if socket_path.parent() != Some(path) {
                continue;
            }
            if let Some(name) = socket_path.file_name() {
                entries.push(DirEntryInfo {
                    name: name.to_owned(),
                    ino: socket.ino,
                    file_type: None,
                });
            }
        }
        entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        entries.insert(
            0,
            DirEntryInfo {
                name: OsString::from_vec(b"..".to_vec()),
                ino: 0,
                file_type: None,
            },
        );
        entries.insert(
            0,
            DirEntryInfo {
                name: OsString::from_vec(b".".to_vec()),
                ino: 0,
                file_type: None,
            },
        );
        let fh = self.next_handle();
        self.dir_handles.insert(fh, DirHandle { file, entries });
        Ok(fh)
    }

    fn release(&mut self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        let flags = get_u32(input, 12).unwrap_or(0);
        let handle = self.handles.remove(&fh).ok_or(EBADF)?;
        if flags & FUSE_RELEASE_FLOCK_UNLOCK != 0 {
            let result = unsafe { libc::flock(handle.file.as_raw_fd(), libc::LOCK_UN) };
            if result != 0 {
                return Err(io_errno(io::Error::last_os_error()));
            }
        }
        if let Some(path) = handle.temporary_path {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(io_errno(err)),
            }
        }
        Ok(Vec::new())
    }

    fn release_dir(&mut self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        self.dir_handles.remove(&fh).ok_or(EBADF)?;
        Ok(Vec::new())
    }

    fn flush(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        if !self.handles.contains_key(&fh) {
            return Err(EBADF);
        }
        // FUSE_FLUSH is close(2) error propagation, not durability. Individual
        // writes are already reported synchronously; FSYNC does the host sync.
        Ok(Vec::new())
    }

    fn fsync(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        let flags = get_u32(input, 8).ok_or(EINVAL)?;
        let handle = self.handles.get(&fh).ok_or(EBADF)?;
        if flags & FUSE_FSYNC_FDATASYNC != 0 {
            handle.file.sync_data().map_err(io_errno)?;
        } else {
            handle.file.sync_all().map_err(io_errno)?;
        }
        Ok(Vec::new())
    }

    fn fsync_dir(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        let flags = get_u32(input, 8).ok_or(EINVAL)?;
        let handle = self.dir_handles.get(&fh).ok_or(EBADF)?;
        if flags & FUSE_FSYNC_FDATASYNC != 0 {
            handle.file.sync_data().map_err(io_errno)?;
        } else {
            handle.file.sync_all().map_err(io_errno)?;
        }
        Ok(Vec::new())
    }

    fn lock(&self, input: &[u8], opcode: u32) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        let start = get_u64(input, 16).ok_or(EINVAL)?;
        let end = get_u64(input, 24).ok_or(EINVAL)?;
        let lock_type = get_u32(input, 32).ok_or(EINVAL)?;
        let _pid = get_u32(input, 36).ok_or(EINVAL)?;
        let flags = get_u32(input, 40).ok_or(EINVAL)?;
        let handle = self.handles.get(&fh).ok_or(EBADF)?;

        if flags & FUSE_LK_FLOCK != 0 {
            if opcode == GETLK {
                let mut out = Vec::with_capacity(24);
                put_u64(&mut out, start);
                put_u64(&mut out, end);
                put_u32(&mut out, LINUX_F_UNLCK);
                put_u32(&mut out, 0);
                return Ok(out);
            }
            let mut operation = match lock_type {
                LINUX_F_RDLCK => libc::LOCK_SH,
                LINUX_F_WRLCK => libc::LOCK_EX,
                LINUX_F_UNLCK => libc::LOCK_UN,
                _ => return Err(EINVAL),
            };
            if opcode == SETLK {
                operation |= libc::LOCK_NB;
            }
            let result = unsafe { libc::flock(handle.file.as_raw_fd(), operation) };
            if result != 0 {
                return Err(io_errno(io::Error::last_os_error()));
            }
            return Ok(Vec::new());
        }

        let mut host_lock: libc::flock = unsafe { std::mem::zeroed() };
        host_lock.l_start = i64::try_from(start).map_err(|_| EFBIG)? as libc::off_t;
        // Linux FUSE encodes a lock through EOF with OFFSET_MAX (i64::MAX),
        // while host fcntl represents the same range with l_len=0. Adding one
        // to the inclusive Linux end would otherwise overflow and surface as
        // EFBIG to applications such as apt.
        host_lock.l_len = if end >= i64::MAX as u64 {
            0
        } else {
            i64::try_from(end.checked_sub(start).ok_or(EINVAL)?.saturating_add(1))
                .map_err(|_| EFBIG)? as libc::off_t
        };
        // OFD locking scopes the lock to this FUSE open handle. Both Linux and
        // macOS require l_pid=0 for F_OFD_* commands; the guest pid is not a
        // meaningful host pid and must not be forwarded.
        host_lock.l_pid = 0;
        host_lock.l_whence = libc::SEEK_SET as i16;
        host_lock.l_type = linux_lock_to_host(lock_type)?;
        let command = match opcode {
            GETLK => libc::F_OFD_GETLK,
            SETLK => libc::F_OFD_SETLK,
            SETLKW => libc::F_OFD_SETLKW,
            _ => return Err(EINVAL),
        };
        let result = unsafe { libc::fcntl(handle.file.as_raw_fd(), command, &mut host_lock) };
        if result != 0 {
            return Err(io_errno(io::Error::last_os_error()));
        }
        if opcode != GETLK {
            return Ok(Vec::new());
        }
        let returned_start = host_lock.l_start.max(0) as u64;
        let returned_end = if host_lock.l_len == 0 {
            u64::MAX
        } else {
            returned_start
                .saturating_add(host_lock.l_len as u64)
                .saturating_sub(1)
        };
        let mut out = Vec::with_capacity(24);
        put_u64(&mut out, returned_start);
        put_u64(&mut out, returned_end);
        put_u32(&mut out, host_lock_to_linux(host_lock.l_type)?);
        put_u32(&mut out, host_lock.l_pid.max(0) as u32);
        Ok(out)
    }

    fn poll(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        if !self.handles.contains_key(&fh) && !self.dir_handles.contains_key(&fh) {
            return Err(EBADF);
        }
        let events = get_u32(input, 20).ok_or(EINVAL)?;
        let mut out = Vec::with_capacity(8);
        put_u32(&mut out, events);
        put_u32(&mut out, 0);
        Ok(out)
    }

    fn fallocate(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        let offset = get_u64(input, 8).ok_or(EINVAL)?;
        let length = get_u64(input, 16).ok_or(EINVAL)?;
        let mode = get_u32(input, 24).ok_or(EINVAL)?;
        let handle = self.handles.get(&fh).ok_or(EBADF)?;
        if !handle.writable {
            return Err(EBADF);
        }
        host_fallocate(&handle.file, offset, length, mode)?;
        Ok(Vec::new())
    }

    fn lseek(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        let offset = get_u64(input, 8).ok_or(EINVAL)?;
        let whence = get_u32(input, 16).ok_or(EINVAL)?;
        let handle = self.handles.get(&fh).ok_or(EBADF)?;
        let host_whence = match whence {
            0 => libc::SEEK_SET,
            1 => libc::SEEK_CUR,
            2 => libc::SEEK_END,
            3 => libc::SEEK_DATA,
            4 => libc::SEEK_HOLE,
            _ => return Err(EINVAL),
        };
        let offset = i64::try_from(offset).map_err(|_| EFBIG)?;
        let result = unsafe { libc::lseek(handle.file.as_raw_fd(), offset, host_whence) };
        if result < 0 {
            return Err(io_errno(io::Error::last_os_error()));
        }
        let mut out = Vec::with_capacity(8);
        put_u64(&mut out, result as u64);
        Ok(out)
    }

    fn copy_file_range(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let source_fh = get_u64(input, 0).ok_or(EINVAL)?;
        let source_offset = get_u64(input, 8).ok_or(EINVAL)?;
        let target_fh = get_u64(input, 24).ok_or(EINVAL)?;
        let target_offset = get_u64(input, 32).ok_or(EINVAL)?;
        let requested = get_u64(input, 40).ok_or(EINVAL)?.min(u32::MAX as u64);
        let flags = get_u64(input, 48).ok_or(EINVAL)?;
        if flags != 0 {
            return Err(EINVAL);
        }
        let source = self.handles.get(&source_fh).ok_or(EBADF)?;
        let target = self.handles.get(&target_fh).ok_or(EBADF)?;
        if !target.writable {
            return Err(EBADF);
        }
        let source_meta = source.file.metadata().map_err(io_errno)?;
        let target_meta = target.file.metadata().map_err(io_errno)?;
        if source_meta.dev() == target_meta.dev()
            && source_meta.ino() == target_meta.ino()
            && ranges_overlap(source_offset, target_offset, requested)
        {
            return Err(EINVAL);
        }
        let mut copied = 0u64;
        let mut buffer = vec![0u8; MAX_WRITE as usize];
        while copied < requested {
            let want = (requested - copied).min(buffer.len() as u64) as usize;
            let read = source
                .file
                .read_at(&mut buffer[..want], source_offset.saturating_add(copied))
                .map_err(io_errno)?;
            if read == 0 {
                break;
            }
            let mut written = 0usize;
            while written < read {
                let n = target
                    .file
                    .write_at(
                        &buffer[written..read],
                        target_offset
                            .saturating_add(copied)
                            .saturating_add(written as u64),
                    )
                    .map_err(io_errno)?;
                if n == 0 {
                    return Err(EIO);
                }
                written += n;
            }
            copied += read as u64;
            if read < want {
                break;
            }
        }
        let mut out = Vec::with_capacity(8);
        put_u32(&mut out, copied as u32);
        put_u32(&mut out, 0);
        Ok(out)
    }

    fn syncfs(&self) -> Result<Vec<u8>, i32> {
        for handle in self.handles.values() {
            handle.file.sync_all().map_err(io_errno)?;
        }
        for handle in self.dir_handles.values() {
            handle.file.sync_all().map_err(io_errno)?;
        }
        Ok(Vec::new())
    }

    fn tmpfile(
        &mut self,
        parent: u64,
        input: &[u8],
        context: RequestContext,
    ) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let flags = get_u32(input, 0).ok_or(EINVAL)?;
        let mode = get_u32(input, 4).ok_or(EINVAL)?;
        let parent_path = self.node_path(parent)?.to_owned();
        let id = self.next_tmpfile;
        self.next_tmpfile = self.next_tmpfile.saturating_add(1).max(1);
        let path = parent_path.join(format!(".hvi-tmp-{}-{id}", std::process::id()));
        let file = open_host_file(
            &path,
            flags | LINUX_O_EXCL,
            true,
            host_creation_mode(mode, false),
        )
        .map_err(io_errno)?;
        initialize_guest_metadata(&path, mode, context)?;
        let meta = file.metadata().map_err(io_errno)?;
        let node = self.node_for(path.clone(), &meta);
        self.remember_lookup(node);
        let mut out = self.entry_out(node, &path, &meta);
        let fh = self.next_handle();
        self.handles.insert(
            fh,
            FileHandle {
                file,
                writable: true,
                path: path.clone(),
                temporary_path: Some(path),
            },
        );
        put_open_out(&mut out, fh, false, false);
        Ok(out)
    }

    fn statx(&mut self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        let flags = get_u32(input, 0).ok_or(EINVAL)?;
        let fh = get_u64(input, 8).ok_or(EINVAL)?;
        let (path, meta) = if flags & FUSE_GETATTR_FH != 0 {
            let handle = self.handles.get(&fh).ok_or(EBADF)?;
            let meta = handle.file.metadata().map_err(io_errno)?;
            (Some(handle.path.clone()), meta)
        } else {
            let path = self.node_path(node)?.to_owned();
            let meta = fs::symlink_metadata(&path).map_err(io_errno)?;
            (Some(path), meta)
        };
        let cache_seconds = self.cache_seconds();
        let guest = self.guest_attr(node, path.as_deref(), &meta);
        Ok(statx_out(node, &meta, cache_seconds, guest))
    }

    fn readdir(
        &mut self,
        node: u64,
        input: &[u8],
        capacity: usize,
        plus: bool,
    ) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        let offset = get_u64(input, 8).ok_or(EINVAL)? as usize;
        let requested = get_u32(input, 16).ok_or(EINVAL)? as usize;
        let limit = requested.min(capacity);
        let dir = self.node_path(node)?.to_owned();
        if !fs::metadata(&dir).map_err(io_errno)?.is_dir() {
            return Err(ENOTDIR);
        }

        let parent_path = if dir == self.root {
            self.root.clone()
        } else {
            dir.parent().unwrap_or(&self.root).to_owned()
        };
        let parent_meta = fs::symlink_metadata(&parent_path).map_err(io_errno)?;
        let parent_node = if plus {
            self.node_for(parent_path.clone(), &parent_meta)
        } else {
            parent_meta.ino()
        };

        // No reply can hold more than `limit / min_record_len` entries, so
        // that -- not the whole remaining tail of the directory -- bounds how
        // much of `entries` needs copying out from under the dir handle's
        // borrow. Cloning the full vector (or even the full tail) on every
        // call is what made a paginated listing of a large directory
        // quadratic: this makes each call's copy independent of directory
        // size.
        let min_record = align8((if plus { 128 } else { 0 }) + 24 + 1);
        let max_entries = limit / min_record + 1;
        let batch: Vec<(usize, DirEntryInfo)> = self
            .dir_handles
            .get(&fh)
            .ok_or(EBADF)?
            .entries
            .iter()
            .enumerate()
            .skip(offset)
            .take(max_entries)
            .map(|(idx, entry)| (idx, entry.clone()))
            .collect();

        let mut out = Vec::new();
        for (idx, entry) in batch {
            let path = if idx == 0 {
                dir.clone()
            } else if idx == 1 {
                parent_path.clone()
            } else {
                dir.join(&entry.name)
            };
            let name = entry.name.as_bytes();
            let record_len = align8((if plus { 128 } else { 0 }) + 24 + name.len());
            if out.len() + record_len > limit {
                break;
            }

            if plus {
                // A socket has no host entry behind it, so its attributes
                // come from this device rather than from a stat.
                if let Some(socket) = self.sockets.get(&path).copied() {
                    let entry_node = self.socket_node_id(&path, socket.ino);
                    self.remember_lookup(entry_node);
                    out.extend_from_slice(&socket_entry_out(entry_node, socket));
                    put_u64(&mut out, entry_node);
                    put_u64(&mut out, (idx + 1) as u64);
                    put_u32(&mut out, name.len() as u32);
                    put_u32(&mut out, DT_SOCK);
                    out.extend_from_slice(name);
                    out.resize(align8(out.len()), 0);
                    continue;
                }
                // READDIRPLUS always needs full attributes, so the d_type
                // fast path below does not apply here.
                let meta = match fs::symlink_metadata(&path) {
                    Ok(meta) => meta,
                    Err(_) => continue,
                };
                let entry_node = if idx == 0 {
                    node
                } else if idx == 1 {
                    parent_node
                } else {
                    self.node_for(path.clone(), &meta)
                };
                self.remember_lookup(entry_node);
                out.extend_from_slice(&self.entry_out(entry_node, &path, &meta));
                put_u64(&mut out, entry_node);
                put_u64(&mut out, (idx + 1) as u64);
                put_u32(&mut out, name.len() as u32);
                put_u32(&mut out, dirent_type(&meta));
            } else {
                // `.`/`..` are not from `fs::read_dir`, so they carry no
                // cached type; every other entry's d_type/ino came for free
                // off the directory at OPENDIR time and needs no stat here.
                let (entry_ino, dtype) = match entry.file_type {
                    Some(ft) if idx > 1 => (entry.ino, dirent_type_ft(&ft)),
                    // A socket carries no cached `d_type` -- it came from
                    // this device, not from a dirent -- and there is nothing
                    // to stat, so it is answered from the record.
                    _ => match self.sockets.get(&path) {
                        Some(socket) => (socket.ino, DT_SOCK),
                        None => match fs::symlink_metadata(&path) {
                            Ok(meta) => (meta.ino(), dirent_type(&meta)),
                            Err(_) => continue,
                        },
                    },
                };
                let entry_node = if idx == 0 {
                    node
                } else if idx == 1 {
                    parent_node
                } else {
                    entry_ino
                };
                put_u64(&mut out, entry_node);
                put_u64(&mut out, (idx + 1) as u64);
                put_u32(&mut out, name.len() as u32);
                put_u32(&mut out, dtype);
            }
            out.extend_from_slice(name);
            out.resize(align8(out.len()), 0);
        }
        Ok(out)
    }

    fn statfs(&self) -> Result<Vec<u8>, i32> {
        let path = path_cstring(&self.root)?;
        let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::statvfs(path.as_ptr(), &mut stats) };
        if result != 0 {
            return Err(io_errno(io::Error::last_os_error()));
        }
        let mut out = Vec::with_capacity(80);
        for value in [
            stats.f_blocks as u64,
            stats.f_bfree as u64,
            stats.f_bavail as u64,
            stats.f_files as u64,
            stats.f_ffree as u64,
        ] {
            put_u64(&mut out, value);
        }
        put_u32(&mut out, stats.f_bsize as u32);
        put_u32(&mut out, stats.f_namemax as u32);
        put_u32(&mut out, stats.f_frsize as u32);
        put_u32(&mut out, 0);
        out.resize(80, 0);
        Ok(out)
    }

    fn access(&self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        let mask = get_u32(input, 0).ok_or(EINVAL)?;
        fs::symlink_metadata(self.node_path(node)?).map_err(io_errno)?;
        if mask & 2 != 0 && !self.writable {
            Err(EROFS)
        } else {
            Ok(Vec::new())
        }
    }

    fn setxattr(&self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let size = get_u32(input, 0).ok_or(EINVAL)? as usize;
        let flags = get_u32(input, 4).ok_or(EINVAL)?;
        if flags & !(LINUX_XATTR_CREATE | LINUX_XATTR_REPLACE) != 0
            || flags == (LINUX_XATTR_CREATE | LINUX_XATTR_REPLACE)
        {
            return Err(EINVAL);
        }
        let (name, value_at) = nul_name_with_end(input, 16)?;
        if is_private_xattr(name) {
            return Err(EPERM);
        }
        let value = input
            .get(value_at..value_at.checked_add(size).ok_or(EINVAL)?)
            .ok_or(EINVAL)?;
        host_setxattr(self.node_path(node)?, name, value, flags)?;
        Ok(Vec::new())
    }

    fn getxattr(&self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        let size = get_u32(input, 0).ok_or(EINVAL)? as usize;
        let name = nul_name(input, 8)?;
        if is_private_xattr(name) {
            return Err(ENODATA);
        }
        let value = host_getxattr(self.node_path(node)?, name)?;
        xattr_response(size, value)
    }

    fn listxattr(&self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        let size = get_u32(input, 0).ok_or(EINVAL)?;
        let value = filter_private_xattrs(host_listxattr(self.node_path(node)?)?);
        xattr_response(size as usize, value)
    }

    fn removexattr(&self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let name = nul_name(input, 0)?;
        if is_private_xattr(name) {
            return Err(EPERM);
        }
        host_removexattr(self.node_path(node)?, name)?;
        Ok(Vec::new())
    }

    fn node_path(&self, node: u64) -> Result<&Path, i32> {
        let remembered = self.nodes.get(&node).ok_or(ENOENT)?;
        // With one alias there is nothing to disambiguate: a stale path still
        // fails at the caller's real syscall with the same errno, so skipping
        // the validating stat here does not change observable behaviour. Only
        // hard links / concurrent renames leave more than one path, and only
        // then is the scan below needed.
        if let [only] = remembered.paths.as_slice() {
            return Ok(only.as_path());
        }
        remembered
            .paths
            .iter()
            .find(|path| {
                fs::symlink_metadata(path)
                    .map(|meta| (meta.dev(), meta.ino()) == remembered.key)
                    .unwrap_or(false)
            })
            .map(PathBuf::as_path)
            .ok_or(ENOENT)
    }

    fn node_for(&mut self, path: PathBuf, meta: &Metadata) -> u64 {
        let key = (meta.dev(), meta.ino());
        if let Some(node) = self.inode_ids.get(&key) {
            if let Some(remembered) = self.nodes.get_mut(node) {
                if !remembered.paths.contains(&path) {
                    // A path we have not seen before resolving to an inode we
                    // already know is either a new alias or, after an unlink
                    // whose FORGET has not arrived yet, the host reusing the
                    // inode number for a different file. The cached xattr
                    // described the old occupant, so drop it: this is the one
                    // place a node can start referring to something the cache
                    // does not describe. A repeat lookup of an already-known
                    // path keeps its cache, which is the hot path.
                    remembered.paths.push(path);
                    remembered.guest_attr = None;
                }
            }
            return *node;
        }
        let node = self.next_node;
        self.next_node = self.next_node.saturating_add(1);
        self.nodes.insert(
            node,
            Node {
                key,
                paths: vec![path],
                lookups: 0,
                guest_attr: None,
            },
        );
        self.inode_ids.insert(key, node);
        node
    }

    fn remember_lookup(&mut self, node: u64) {
        if let Some(remembered) = self.nodes.get_mut(&node) {
            remembered.lookups = remembered.lookups.saturating_add(1);
        }
    }

    fn forget(&mut self, node: u64, input: &[u8]) {
        let count = get_u64(input, 0).unwrap_or(0);
        self.forget_count(node, count);
    }

    fn batch_forget(&mut self, input: &[u8]) {
        let count = get_u32(input, 0).unwrap_or(0) as usize;
        for index in 0..count {
            let Some(offset) = 8usize.checked_add(index.saturating_mul(16)) else {
                break;
            };
            let (Some(node), Some(lookups)) = (get_u64(input, offset), get_u64(input, offset + 8))
            else {
                break;
            };
            self.forget_count(node, lookups);
        }
    }

    fn forget_count(&mut self, node: u64, count: u64) {
        if node == FUSE_ROOT_ID {
            return;
        }
        let Some(remembered) = self.nodes.get_mut(&node) else {
            return;
        };
        remembered.lookups = remembered.lookups.saturating_sub(count);
        if remembered.lookups != 0 {
            return;
        }
        let key = remembered.key;
        self.nodes.remove(&node);
        self.inode_ids.remove(&key);
    }

    fn forget_node_path(&mut self, path: &Path, meta: &Metadata) {
        let key = (meta.dev(), meta.ino());
        let Some(node_id) = self.inode_ids.get(&key).copied() else {
            return;
        };
        let mut empty = false;
        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.paths.retain(|candidate| candidate != path);
            empty = node.paths.is_empty();
        }
        if empty && node_id != FUSE_ROOT_ID {
            self.nodes.remove(&node_id);
            self.inode_ids.remove(&key);
        }
    }

    fn cache_seconds(&self) -> u64 {
        if self.cache_policy == CachePolicy::None {
            0
        } else if !self.writable {
            // Read-only shares cannot go stale from the guest's own writes.
            60
        } else {
            1
        }
    }

    /// Every caller already resolved `path` (typically for the
    /// `symlink_metadata` that produced `meta`); taking it here instead of
    /// re-resolving via `node_path` saves a redundant stat and is strictly
    /// more correct, since it is the exact path `meta` was read from.
    fn attr_out(&mut self, node: u64, path: &Path, meta: &Metadata) -> Vec<u8> {
        let cache_seconds = self.cache_seconds();
        let guest = self.guest_attr(node, Some(path), meta);
        attr_out(node, meta, cache_seconds, guest)
    }

    fn entry_out(&mut self, node: u64, path: &Path, meta: &Metadata) -> Vec<u8> {
        let cache_seconds = self.cache_seconds();
        let guest = self.guest_attr(node, Some(path), meta);
        entry_out(node, meta, cache_seconds, guest)
    }

    /// Cached `com.nubificus.hvi.linux-attr` lookup. A getxattr call costs one
    /// syscall on a miss and two on a hit (size probe then read), and this is
    /// asked for on every attribute reply -- caching it on the `Node` turns
    /// that into at most one syscall for the node's whole cached lifetime.
    /// The mode's file-type bits still always come from the live `meta`, only
    /// the permission bits and uid/gid are cached.
    fn guest_attr(&mut self, node: u64, path: Option<&Path>, meta: &Metadata) -> GuestAttr {
        #[cfg(target_os = "macos")]
        if let Some(path) = path {
            let stored = match self.nodes.get(&node).map(|n| n.guest_attr) {
                Some(Some(cached)) => cached,
                _ => {
                    let stored = stored_guest_attr(path);
                    if let Some(n) = self.nodes.get_mut(&node) {
                        n.guest_attr = Some(stored);
                    }
                    stored
                }
            };
            if let Some(mut guest) = stored {
                guest.mode = (meta.mode() & S_IFMT) | (guest.mode & 0o7777);
                return guest;
            }
        }
        #[cfg(target_os = "linux")]
        let _ = (node, path);
        GuestAttr {
            mode: meta.mode(),
            uid: host_uid_to_guest(meta.uid()),
            gid: host_gid_to_guest(meta.gid()),
        }
    }

    /// Drops a node's cached guest attribute after this module writes
    /// `HVI_XATTR_LINUX_ATTR` or otherwise changes what it reports for that
    /// node, so the next attribute reply re-reads it instead of serving the
    /// value from before the change. A no-op on Linux, where the field is
    /// never populated.
    fn invalidate_guest_attr(&mut self, node: u64) {
        if let Some(n) = self.nodes.get_mut(&node) {
            n.guest_attr = None;
        }
    }
}

/// The attribute block for a socket this device holds rather than the host.
///
/// Everything a socket inode has is in `SocketNode`; there is no `Metadata` to
/// read because there is no file. Sizes and timestamps are zero, which is what
/// a freshly bound socket looks like anyway, and nothing consults them.
fn put_socket_attr(out: &mut Vec<u8>, node: u64, socket: SocketNode) {
    let (secs, nsecs) = socket.time;
    put_u64(out, node);
    put_u64(out, 0); // size
    put_u64(out, 0); // blocks
    put_u64(out, secs); // atime
    put_u64(out, secs); // mtime
    put_u64(out, secs); // ctime
    put_u32(out, nsecs);
    put_u32(out, nsecs);
    put_u32(out, nsecs);
    put_u32(out, socket.mode);
    put_u32(out, 1); // nlink
    put_u32(out, socket.uid);
    put_u32(out, socket.gid);
    put_u32(out, 0); // rdev
    put_u32(out, 4096); // blksize
    put_u32(out, 0);
}

fn socket_entry_out(node: u64, socket: SocketNode) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    put_u64(&mut out, node);
    put_u64(&mut out, 1); // generation
                          // No entry/attribute caching. The guest kernel is the only thing that can
                          // tell us a socket has gone, and it does that with UNLINK, so there is
                          // nothing to rediscover by expiring the entry -- but a zero timeout keeps
                          // the guest asking us rather than trusting a cached negative if a lookup
                          // and an unlink race.
    put_u64(&mut out, 0);
    put_u64(&mut out, 0);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_socket_attr(&mut out, node, socket);
    out
}

fn socket_attr_out(node: u64, socket: SocketNode) -> Vec<u8> {
    let mut out = Vec::with_capacity(104);
    put_u64(&mut out, 0);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_socket_attr(&mut out, node, socket);
    out
}

fn attr_out(node: u64, meta: &Metadata, cache_seconds: u64, guest: GuestAttr) -> Vec<u8> {
    let mut out = Vec::with_capacity(104);
    put_u64(&mut out, cache_seconds);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_attr(&mut out, node, meta, guest);
    out
}

fn entry_out(node: u64, meta: &Metadata, cache_seconds: u64, guest: GuestAttr) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    put_u64(&mut out, node);
    put_u64(&mut out, 1); // generation
    put_u64(&mut out, cache_seconds);
    put_u64(&mut out, cache_seconds);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_attr(&mut out, node, meta, guest);
    out
}

fn put_open_out(out: &mut Vec<u8>, fh: u64, directory: bool, cache: bool) {
    put_u64(out, fh);
    // Cache directory contents and regular-file pages. Attribute/entry
    // timeouts remain short, so host-side changes are still rediscovered.
    put_u32(
        out,
        if cache {
            if directory {
                1 << 3
            } else {
                1 << 1
            }
        } else {
            0
        },
    );
    put_u32(out, 0); // backing_id (signed on the wire, zero means none)
}

/// How many directory descriptors [`DirCache`] keeps open.
///
/// Descriptors are a budget this device already spends: it pins one per open
/// guest handle, and exhausting them reaches the guest as EMFILE
/// (NOFireAI/hvi-vmm#34). `fdlimit::raise_open_file_limit` lifts the soft
/// limit to the hard one at startup, so the ceiling is not macOS's bare 256 --
/// but "not 256" is not "unlimited", and a cache that grows with the guest's
/// directory count is a way to spend the whole budget on lookups. Bounded
/// instead, small enough to leave the handle budget alone and large enough
/// that a build's working set of directories stays resident.
// Unused on purpose: this is stage one of NOFireAI/hvi-vmm#30, landing the
// resolver and its tests before the call sites move onto it. The next stage
// removes this attribute along with the first path-based caller.
#[allow(dead_code)]
const DIR_CACHE_LIMIT: usize = 128;

/// Directory descriptors for the export, keyed by node.
///
/// This is the resolver Option B is built on (NOFireAI/hvi-vmm#30). Nothing
/// calls it yet: it lands first, with its tests, so the 120-odd call sites
/// that follow are mechanical against a primitive that has already been
/// argued about.
///
/// # Why descriptors rather than paths
///
/// Resolving a path string asks the host to interpret names that mean
/// something in the guest. An absolute symlink inside a container rootfs --
/// `/usr/lib/ssl/certs -> /etc/ssl/certs` -- names the guest's `/etc`, and
/// the host reads the same bytes as its own. Refusing what that resolves to
/// refuses ordinary guest paths, which is what broke booting a stock image
/// and what NOFireAI/hvi-vmm#40 removed.
///
/// Descending by descriptor asks no such question. Each component is opened
/// relative to the one before it with `O_NOFOLLOW`, so a symlink cannot
/// redirect the walk, and every descriptor here is reachable from the root by
/// a chain of non-following opens. Containment stops being a check that can be
/// wrong and becomes a property of how the descriptor was obtained.
///
/// It also closes a race the old check documented and could not fix: that one
/// resolved a path and then let the syscall resolve it again, so anything
/// host-side could swap a component in between.
#[allow(dead_code)]
struct DirCache {
    /// The export root. Pinned: never evicted, and the origin of every walk.
    root: OwnedFd,
    open: HashMap<u64, OwnedFd>,
    /// Least-recently-used first. Only node ids present in `open` appear here.
    lru: VecDeque<u64>,
    limit: usize,
}

#[allow(dead_code)]
impl DirCache {
    fn new(root: &Path, limit: usize) -> io::Result<Self> {
        let root = open_dir_nofollow_at(None, root.as_os_str().as_bytes())
            .map_err(io::Error::from_raw_os_error)?;
        Ok(Self {
            root,
            open: HashMap::new(),
            lru: VecDeque::new(),
            limit: limit.max(1),
        })
    }

    /// A descriptor for `node`, whose path relative to the export root is
    /// `relative`.
    ///
    /// The caller supplies the relative path because the node map is still the
    /// device's own business at this stage. Once the call sites move over, a
    /// hit costs no path work at all.
    ///
    /// The borrow is what makes this safe to hand out: it holds `&mut self`
    /// for as long as the descriptor is alive, so nothing can evict the entry
    /// underneath the caller.
    fn dir_fd(&mut self, node: u64, relative: &Path) -> Result<BorrowedFd<'_>, i32> {
        if node == FUSE_ROOT_ID || relative.as_os_str().is_empty() {
            return Ok(self.root.as_fd());
        }
        if self.open.contains_key(&node) {
            self.touch(node);
        } else {
            let fd = self.walk(relative)?;
            self.admit(node, fd);
        }
        Ok(self.open.get(&node).expect("just inserted").as_fd())
    }

    /// Opens each component in turn from the root, following nothing.
    fn walk(&self, relative: &Path) -> Result<OwnedFd, i32> {
        let mut current: Option<OwnedFd> = None;
        for component in relative.components() {
            let name = match component {
                Component::Normal(name) => name,
                // A relative path built from the node map should contain
                // neither. Refusing is not defensive dressing: `..` is exactly
                // the component that would climb out of the export, and the
                // walk is the only thing standing between it and the host.
                _ => return Err(EINVAL),
            };
            let parent = current
                .as_ref()
                .map(|fd| fd.as_raw_fd())
                .unwrap_or_else(|| self.root.as_raw_fd());
            current = Some(open_dir_nofollow_at(Some(parent), name.as_bytes())?);
        }
        current.ok_or(EINVAL)
    }

    fn touch(&mut self, node: u64) {
        if let Some(at) = self.lru.iter().position(|n| *n == node) {
            self.lru.remove(at);
        }
        self.lru.push_back(node);
    }

    fn admit(&mut self, node: u64, fd: OwnedFd) {
        while self.open.len() >= self.limit {
            match self.lru.pop_front() {
                // Dropping the descriptor closes it, which is the whole point
                // of the bound.
                Some(evicted) => drop(self.open.remove(&evicted)),
                None => break,
            }
        }
        self.open.insert(node, fd);
        self.lru.push_back(node);
    }

    /// Drops a node's descriptor, for FORGET and for the paths that invalidate
    /// a node (rename, unlink) once the call sites move over.
    fn forget(&mut self, node: u64) {
        if self.open.remove(&node).is_some() {
            if let Some(at) = self.lru.iter().position(|n| *n == node) {
                self.lru.remove(at);
            }
        }
    }

    #[cfg(test)]
    fn resident(&self) -> usize {
        self.open.len()
    }
}

/// Opens a directory without following a symlink in its final component.
///
/// `parent` selects the form: `Some(fd)` resolves `name` relative to that
/// descriptor, `None` treats it as a path from the host's root, which is only
/// used for the export root itself.
#[allow(dead_code)]
fn open_dir_nofollow_at(parent: Option<RawFd>, name: &[u8]) -> Result<OwnedFd, i32> {
    let name = CString::new(name).map_err(|_| EINVAL)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `name` is NUL-terminated and outlives the call; `parent`, when
    // given, is a descriptor this cache owns. The result is handed straight to
    // `OwnedFd`, which closes it.
    let fd = unsafe {
        match parent {
            Some(dirfd) => libc::openat(dirfd, name.as_ptr(), flags),
            None => libc::open(name.as_ptr(), flags),
        }
    };
    if fd < 0 {
        return Err(io_errno(io::Error::last_os_error()));
    }
    // SAFETY: a fresh descriptor this call owns and has not shared.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens a host file with the flags the guest asked for.
///
/// This translates by hand rather than going through `OpenOptions`, which
/// validates the access mode against what is reasonable for application code
/// and rejects `O_CREAT` or `O_TRUNC` without write access -- before issuing
/// any syscall, so the kernel never gets a say. The kernel accepts both, and
/// `O_CREAT|O_RDONLY` is exactly how a lock file is opened: `flock(1)`,
/// iptables' `xtables.lock` and Go's `gofrs/flock` all want the inode rather
/// than the bytes. Rejecting it surfaced in the guest as `flock: cannot open
/// lock file: Invalid argument`, which reads as missing lock support and is
/// not. A FUSE server has to be a faithful proxy for flags the guest kernel
/// has already validated.
///
/// Two properties `OpenOptions` was supplying implicitly are set here
/// deliberately: `O_CLOEXEC`, and refusing a path with an interior NUL rather
/// than letting `open(2)` see a truncated one.
fn open_host_file(path: &Path, flags: u32, create: bool, mode: u32) -> io::Result<File> {
    let mut host_flags = match flags & LINUX_O_ACCMODE {
        0 => libc::O_RDONLY,
        LINUX_O_WRONLY => libc::O_WRONLY,
        LINUX_O_RDWR => libc::O_RDWR,
        // Linux reserves the fourth O_ACCMODE value; a guest sending it did
        // not come through a working open(2).
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Linux O_ACCMODE value",
            ))
        }
    };
    if flags & LINUX_O_APPEND != 0 {
        host_flags |= libc::O_APPEND;
    }
    if flags & LINUX_O_TRUNC != 0 {
        host_flags |= libc::O_TRUNC;
    }
    if create {
        host_flags |= libc::O_CREAT;
        if flags & LINUX_O_EXCL != 0 {
            host_flags |= libc::O_EXCL;
        }
    }
    // The final component must be the inode the guest looked up, never a host
    // symlink followed behind the guest VFS's back.
    host_flags |= libc::O_NOFOLLOW;
    // A descriptor opened on the guest's behalf must not survive into any
    // process this one spawns. OpenOptions did this for us.
    host_flags |= libc::O_CLOEXEC;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    // SAFETY: c_path is NUL-terminated and outlives the call. The mode
    // argument is read by the kernel only when O_CREAT is set, and is passed
    // as the promoted type a variadic open(2) expects. The descriptor is
    // handed straight to File, which owns and closes it.
    let fd = unsafe { libc::open(c_path.as_ptr(), host_flags, (mode & 0o7777) as libc::c_uint) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor this call owns and has not shared.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_host_dir(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(target_os = "macos")]
fn host_creation_mode(mode: u32, directory: bool) -> u32 {
    (mode & 0o777) | if directory { 0o700 } else { 0o600 }
}

#[cfg(target_os = "linux")]
fn host_creation_mode(mode: u32, _directory: bool) -> u32 {
    mode & 0o7777
}

#[cfg(target_os = "macos")]
fn initialize_guest_metadata(path: &Path, mode: u32, context: RequestContext) -> Result<(), i32> {
    let meta = fs::symlink_metadata(path).map_err(io_errno)?;
    if !meta.file_type().is_symlink() {
        let host_mode = host_creation_mode(mode, meta.is_dir());
        fs::set_permissions(path, Permissions::from_mode(host_mode)).map_err(io_errno)?;
    }
    set_guest_attr(
        path,
        GuestAttr {
            mode: (meta.mode() & S_IFMT) | (mode & 0o7777),
            uid: context.uid,
            gid: context.gid,
        },
    )
}

#[cfg(target_os = "linux")]
fn initialize_guest_metadata(path: &Path, mode: u32, _context: RequestContext) -> Result<(), i32> {
    let meta = fs::symlink_metadata(path).map_err(io_errno)?;
    if !meta.file_type().is_symlink() {
        fs::set_permissions(path, Permissions::from_mode(mode & 0o7777)).map_err(io_errno)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn clear_suid_sgid(path: &Path, file: &File) -> Result<(), i32> {
    let meta = file.metadata().map_err(io_errno)?;
    let mut guest = guest_attr(Some(path), &meta);
    if guest.mode & 0o6000 != 0 {
        guest.mode &= !0o6000;
        set_guest_attr(path, guest)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_suid_sgid(_path: &Path, file: &File) -> Result<(), i32> {
    let mode = file.metadata().map_err(io_errno)?.mode() & 0o7777;
    if mode & 0o6000 != 0 {
        file.set_permissions(Permissions::from_mode(mode & !0o6000))
            .map_err(io_errno)?;
    }
    Ok(())
}

fn is_private_xattr(name: &[u8]) -> bool {
    name.starts_with(HVI_XATTR_PREFIX)
}

fn filter_private_xattrs(value: Vec<u8>) -> Vec<u8> {
    let mut filtered = Vec::with_capacity(value.len());
    for name in value.split(|byte| *byte == 0) {
        if name.is_empty() || is_private_xattr(name) {
            continue;
        }
        filtered.extend_from_slice(name);
        filtered.push(0);
    }
    filtered
}

#[cfg(target_os = "macos")]
fn set_guest_attr(path: &Path, guest: GuestAttr) -> Result<(), i32> {
    let mut value = [0u8; 12];
    value[0..4].copy_from_slice(&(guest.mode & 0o177777).to_le_bytes());
    value[4..8].copy_from_slice(&guest.uid.to_le_bytes());
    value[8..12].copy_from_slice(&guest.gid.to_le_bytes());
    host_setxattr(path, HVI_XATTR_LINUX_ATTR, &value, 0)
}

#[cfg(target_os = "macos")]
fn stored_guest_attr(path: &Path) -> Option<GuestAttr> {
    let value = host_getxattr(path, HVI_XATTR_LINUX_ATTR).ok()?;
    if value.len() != 12 {
        return None;
    }
    Some(GuestAttr {
        mode: u32::from_le_bytes(value[0..4].try_into().ok()?),
        uid: u32::from_le_bytes(value[4..8].try_into().ok()?),
        gid: u32::from_le_bytes(value[8..12].try_into().ok()?),
    })
}

fn guest_attr(path: Option<&Path>, meta: &Metadata) -> GuestAttr {
    #[cfg(target_os = "macos")]
    if let Some(path) = path {
        if let Some(mut guest) = stored_guest_attr(path) {
            guest.mode = (meta.mode() & S_IFMT) | (guest.mode & 0o7777);
            return guest;
        }
    }

    GuestAttr {
        mode: meta.mode(),
        uid: host_uid_to_guest(meta.uid()),
        gid: host_gid_to_guest(meta.gid()),
    }
}

fn path_cstring(path: &Path) -> Result<CString, i32> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| EINVAL)
}

#[cfg(target_os = "linux")]
fn guest_uid_to_host(uid: u32) -> libc::uid_t {
    if uid == guest_uid() {
        unsafe { libc::geteuid() }
    } else {
        uid
    }
}

#[cfg(target_os = "linux")]
fn guest_gid_to_host(gid: u32) -> libc::gid_t {
    if gid == guest_gid() {
        unsafe { libc::getegid() }
    } else {
        gid
    }
}

/// The guest-side identity the host user is presented as.
///
/// Everything the host user owns appears inside the guest as this uid/gid, and
/// the guest writing as it maps back. Zero -- the default -- makes the person
/// running hvi root in the guest, which is what a guest whose workload runs as
/// root needs.
///
/// It is configurable because that default silently locks out every guest that
/// does *not* run as root. Such a guest sees a home directory owned by a root
/// it is not, and the guest kernel refuses the write before the request ever
/// reaches this file server -- so the failure is a bare EACCES with nothing
/// pointing at the mapping that caused it. Point these at the uid the workload
/// runs as and the files belong to it.
static GUEST_UID: AtomicU32 = AtomicU32::new(0);
static GUEST_GID: AtomicU32 = AtomicU32::new(0);

/// Sets the identity above. Call once, before the device is served.
pub fn set_guest_ids(uid: u32, gid: u32) {
    GUEST_UID.store(uid, Ordering::Relaxed);
    GUEST_GID.store(gid, Ordering::Relaxed);
}

fn guest_uid() -> u32 {
    GUEST_UID.load(Ordering::Relaxed)
}

fn guest_gid() -> u32 {
    GUEST_GID.load(Ordering::Relaxed)
}

fn host_uid_to_guest(uid: u32) -> u32 {
    if uid == unsafe { libc::geteuid() } {
        guest_uid()
    } else {
        uid
    }
}

fn host_gid_to_guest(gid: u32) -> u32 {
    if gid == unsafe { libc::getegid() } {
        guest_gid()
    } else {
        gid
    }
}

#[cfg(target_os = "linux")]
fn host_fchown(file: &File, uid: Option<libc::uid_t>, gid: Option<libc::gid_t>) -> Result<(), i32> {
    let result = unsafe {
        libc::fchown(
            file.as_raw_fd(),
            uid.unwrap_or(!0 as libc::uid_t),
            gid.unwrap_or(!0 as libc::gid_t),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

#[cfg(target_os = "linux")]
fn host_lchown(path: &Path, uid: Option<libc::uid_t>, gid: Option<libc::gid_t>) -> Result<(), i32> {
    let path = path_cstring(path)?;
    let result = unsafe {
        libc::lchown(
            path.as_ptr(),
            uid.unwrap_or(!0 as libc::uid_t),
            gid.unwrap_or(!0 as libc::gid_t),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

fn host_lchmod(path: &Path, mode: u32) -> Result<(), i32> {
    let path = path_cstring(path)?;
    let result = unsafe {
        libc::fchmodat(
            libc::AT_FDCWD,
            path.as_ptr(),
            mode as libc::mode_t,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

fn fuse_times(
    valid: u32,
    atime: u64,
    atime_nsec: u32,
    mtime: u64,
    mtime_nsec: u32,
) -> Result<[libc::timespec; 2], i32> {
    fn one(valid: bool, now: bool, seconds: u64, nanos: u32) -> Result<libc::timespec, i32> {
        if now {
            return Ok(libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_NOW,
            });
        }
        if !valid {
            return Ok(libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            });
        }
        if nanos >= 1_000_000_000 || seconds > i64::MAX as u64 {
            return Err(EINVAL);
        }
        Ok(libc::timespec {
            tv_sec: seconds as libc::time_t,
            tv_nsec: nanos as libc::c_long,
        })
    }

    Ok([
        one(
            valid & FATTR_ATIME != 0,
            valid & FATTR_ATIME_NOW != 0,
            atime,
            atime_nsec,
        )?,
        one(
            valid & FATTR_MTIME != 0,
            valid & FATTR_MTIME_NOW != 0,
            mtime,
            mtime_nsec,
        )?,
    ])
}

fn host_futimens(file: &File, times: &[libc::timespec; 2]) -> Result<(), i32> {
    let result = unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

fn host_lutimens(path: &Path, times: &[libc::timespec; 2]) -> Result<(), i32> {
    let path = path_cstring(path)?;
    let result = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

fn xattr_name(name: &[u8]) -> Result<CString, i32> {
    if name.is_empty() || name.contains(&b'/') {
        return Err(EINVAL);
    }
    CString::new(name).map_err(|_| EINVAL)
}

fn xattr_response(requested: usize, value: Vec<u8>) -> Result<Vec<u8>, i32> {
    if requested == 0 {
        let len = u32::try_from(value.len()).map_err(|_| EFBIG)?;
        let mut out = Vec::with_capacity(8);
        put_u32(&mut out, len);
        put_u32(&mut out, 0);
        return Ok(out);
    }
    if requested < value.len() {
        return Err(ERANGE);
    }
    Ok(value)
}

#[cfg(target_os = "macos")]
fn host_getxattr(path: &Path, name: &[u8]) -> Result<Vec<u8>, i32> {
    let path = path_cstring(path)?;
    let name = xattr_name(name)?;
    let needed = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if needed < 0 {
        return Err(io_errno(io::Error::last_os_error()));
    }
    let mut value = vec![0u8; needed as usize];
    let got = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if got < 0 {
        return Err(io_errno(io::Error::last_os_error()));
    }
    value.truncate(got as usize);
    Ok(value)
}

#[cfg(target_os = "linux")]
fn host_getxattr(path: &Path, name: &[u8]) -> Result<Vec<u8>, i32> {
    let path = path_cstring(path)?;
    let name = xattr_name(name)?;
    let needed = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if needed < 0 {
        return Err(io_errno(io::Error::last_os_error()));
    }
    let mut value = vec![0u8; needed as usize];
    let got = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if got < 0 {
        return Err(io_errno(io::Error::last_os_error()));
    }
    value.truncate(got as usize);
    Ok(value)
}

#[cfg(target_os = "macos")]
fn host_setxattr(path: &Path, name: &[u8], value: &[u8], flags: u32) -> Result<(), i32> {
    let path = path_cstring(path)?;
    let name = xattr_name(name)?;
    let host_flags = libc::XATTR_NOFOLLOW
        | if flags & LINUX_XATTR_CREATE != 0 {
            libc::XATTR_CREATE
        } else if flags & LINUX_XATTR_REPLACE != 0 {
            libc::XATTR_REPLACE
        } else {
            0
        };
    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            host_flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

#[cfg(target_os = "linux")]
fn host_setxattr(path: &Path, name: &[u8], value: &[u8], flags: u32) -> Result<(), i32> {
    let path = path_cstring(path)?;
    let name = xattr_name(name)?;
    let result = unsafe {
        libc::lsetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            flags as i32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

#[cfg(target_os = "macos")]
fn host_listxattr(path: &Path) -> Result<Vec<u8>, i32> {
    let path = path_cstring(path)?;
    let needed =
        unsafe { libc::listxattr(path.as_ptr(), std::ptr::null_mut(), 0, libc::XATTR_NOFOLLOW) };
    if needed < 0 {
        return Err(io_errno(io::Error::last_os_error()));
    }
    let mut value = vec![0u8; needed as usize];
    let got = unsafe {
        libc::listxattr(
            path.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            libc::XATTR_NOFOLLOW,
        )
    };
    if got < 0 {
        return Err(io_errno(io::Error::last_os_error()));
    }
    value.truncate(got as usize);
    Ok(value)
}

#[cfg(target_os = "linux")]
fn host_listxattr(path: &Path) -> Result<Vec<u8>, i32> {
    let path = path_cstring(path)?;
    let needed = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if needed < 0 {
        return Err(io_errno(io::Error::last_os_error()));
    }
    let mut value = vec![0u8; needed as usize];
    let got = unsafe { libc::llistxattr(path.as_ptr(), value.as_mut_ptr().cast(), value.len()) };
    if got < 0 {
        return Err(io_errno(io::Error::last_os_error()));
    }
    value.truncate(got as usize);
    Ok(value)
}

#[cfg(target_os = "macos")]
fn host_removexattr(path: &Path, name: &[u8]) -> Result<(), i32> {
    let path = path_cstring(path)?;
    let name = xattr_name(name)?;
    let result = unsafe { libc::removexattr(path.as_ptr(), name.as_ptr(), libc::XATTR_NOFOLLOW) };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

fn linux_lock_to_host(lock_type: u32) -> Result<i16, i32> {
    match lock_type {
        LINUX_F_RDLCK => Ok(libc::F_RDLCK),
        LINUX_F_WRLCK => Ok(libc::F_WRLCK),
        LINUX_F_UNLCK => Ok(libc::F_UNLCK),
        _ => Err(EINVAL),
    }
}

fn host_lock_to_linux(lock_type: i16) -> Result<u32, i32> {
    if lock_type == libc::F_RDLCK {
        Ok(LINUX_F_RDLCK)
    } else if lock_type == libc::F_WRLCK {
        Ok(LINUX_F_WRLCK)
    } else if lock_type == libc::F_UNLCK {
        Ok(LINUX_F_UNLCK)
    } else {
        Err(EIO)
    }
}

fn ranges_overlap(left: u64, right: u64, length: u64) -> bool {
    if length == 0 {
        return false;
    }
    left < right.saturating_add(length) && right < left.saturating_add(length)
}

/// Hard links `old` to `new` without resolving `old` when it is a symlink.
///
/// `link(2)` on macOS follows the symlink and links whatever it names, so a
/// guest that pointed a symlink at a host file outside the export and then
/// hard linked it got a real directory entry inside the export sharing that
/// file's inode -- with no symlink left for anything downstream to notice.
/// `linkat` with no flags is defined not to follow, which is the behaviour
/// this device has always wanted.
fn host_link(old: &Path, new: &Path) -> Result<(), i32> {
    let old = path_cstring(old)?;
    let new = path_cstring(new)?;
    // SAFETY: both arguments are NUL-terminated C strings that outlive the
    // call, and `AT_FDCWD` resolves each path from the working directory
    // exactly as the `link(2)` this replaces did.
    let result = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            old.as_ptr(),
            libc::AT_FDCWD,
            new.as_ptr(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

fn host_mkfifo(path: &Path, mode: u32) -> Result<(), i32> {
    let path = path_cstring(path)?;
    let result = unsafe { libc::mkfifo(path.as_ptr(), mode as libc::mode_t) };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

#[cfg(target_os = "macos")]
fn host_rename(old: &Path, new: &Path, flags: u32) -> Result<(), i32> {
    if flags == 0 {
        return fs::rename(old, new).map_err(io_errno);
    }
    let old = path_cstring(old)?;
    let new = path_cstring(new)?;
    let host_flags = if flags & RENAME_EXCHANGE != 0 {
        0x2
    } else {
        0x4
    };
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            old.as_ptr(),
            libc::AT_FDCWD,
            new.as_ptr(),
            host_flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

#[cfg(target_os = "linux")]
fn host_rename(old: &Path, new: &Path, flags: u32) -> Result<(), i32> {
    if flags == 0 {
        return fs::rename(old, new).map_err(io_errno);
    }
    let old = path_cstring(old)?;
    let new = path_cstring(new)?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            old.as_ptr(),
            libc::AT_FDCWD,
            new.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

#[cfg(target_os = "macos")]
fn host_fallocate(file: &File, offset: u64, length: u64, mode: u32) -> Result<(), i32> {
    let unsupported = FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE | FALLOC_FL_UNSHARE_RANGE;
    if mode & unsupported != 0
        || mode & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE) != 0
    {
        return Err(EOPNOTSUPP);
    }
    if length == 0 {
        return Err(EINVAL);
    }
    let end = offset.checked_add(length).ok_or(EFBIG)?;
    let offset = i64::try_from(offset).map_err(|_| EFBIG)?;
    let length = i64::try_from(length).map_err(|_| EFBIG)?;

    if mode & FALLOC_FL_PUNCH_HOLE != 0 {
        if mode != (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE) {
            return Err(EOPNOTSUPP);
        }
        let mut punch = libc::fpunchhole_t {
            fp_flags: 0,
            reserved: 0,
            fp_offset: offset,
            fp_length: length,
        };
        let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &mut punch) };
        return if result == 0 {
            Ok(())
        } else {
            Err(io_errno(io::Error::last_os_error()))
        };
    }

    if mode & FALLOC_FL_ZERO_RANGE != 0 {
        if mode & !(FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE) != 0 {
            return Err(EOPNOTSUPP);
        }
        let old_size = file.metadata().map_err(io_errno)?.len();
        let zero_end = if mode & FALLOC_FL_KEEP_SIZE != 0 {
            end.min(old_size)
        } else {
            if end > old_size {
                file.set_len(end).map_err(io_errno)?;
            }
            end
        };
        let zeros = vec![0u8; MAX_WRITE as usize];
        let mut cursor = offset as u64;
        while cursor < zero_end {
            let count = (zero_end - cursor).min(zeros.len() as u64) as usize;
            let mut written = 0;
            while written < count {
                let n = file
                    .write_at(&zeros[written..count], cursor + written as u64)
                    .map_err(io_errno)?;
                if n == 0 {
                    return Err(EIO);
                }
                written += n;
            }
            cursor += count as u64;
        }
        return Ok(());
    }

    let mut store = libc::fstore_t {
        fst_flags: libc::F_ALLOCATECONTIG,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: offset,
        fst_length: length,
        fst_bytesalloc: 0,
    };
    let mut result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut store) };
    if result != 0 {
        store.fst_flags = libc::F_ALLOCATEALL;
        result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut store) };
    }
    if result != 0 {
        return Err(io_errno(io::Error::last_os_error()));
    }
    if mode & FALLOC_FL_KEEP_SIZE == 0 && end > file.metadata().map_err(io_errno)?.len() {
        file.set_len(end).map_err(io_errno)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn host_fallocate(file: &File, offset: u64, length: u64, mode: u32) -> Result<(), i32> {
    let offset = i64::try_from(offset).map_err(|_| EFBIG)?;
    let length = i64::try_from(length).map_err(|_| EFBIG)?;
    let result = unsafe { libc::fallocate(file.as_raw_fd(), mode as i32, offset, length) };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

const STATX_BASIC_STATS: u32 = 0x07ff;
const STATX_BTIME: u32 = 0x0800;

#[cfg(target_os = "macos")]
fn metadata_btime(meta: &Metadata) -> Option<(i64, u32)> {
    Some((meta.st_birthtime(), meta.st_birthtime_nsec().max(0) as u32))
}

#[cfg(target_os = "linux")]
fn metadata_btime(_meta: &Metadata) -> Option<(i64, u32)> {
    None
}

fn statx_out(node: u64, meta: &Metadata, cache_seconds: u64, guest: GuestAttr) -> Vec<u8> {
    let btime = metadata_btime(meta);
    let mut out = Vec::with_capacity(288);
    put_u64(&mut out, cache_seconds);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u64(&mut out, 0);
    put_u64(&mut out, 0);

    put_u32(
        &mut out,
        STATX_BASIC_STATS | if btime.is_some() { STATX_BTIME } else { 0 },
    );
    put_u32(&mut out, meta.blksize() as u32);
    put_u64(&mut out, 0);
    put_u32(&mut out, meta.nlink() as u32);
    put_u32(&mut out, guest.uid);
    put_u32(&mut out, guest.gid);
    put_u16(&mut out, guest.mode as u16);
    put_u16(&mut out, 0);
    put_u64(&mut out, node);
    put_u64(&mut out, meta.size());
    put_u64(&mut out, meta.blocks());
    put_u64(&mut out, 0);
    put_statx_time(&mut out, meta.atime(), meta.atime_nsec());
    let (birth_seconds, birth_nanos) = btime.unwrap_or((0, 0));
    put_statx_time(&mut out, birth_seconds, birth_nanos as i64);
    put_statx_time(&mut out, meta.ctime(), meta.ctime_nsec());
    put_statx_time(&mut out, meta.mtime(), meta.mtime_nsec());
    for _ in 0..4 {
        put_u32(&mut out, 0);
    }
    for _ in 0..14 {
        put_u64(&mut out, 0);
    }
    debug_assert_eq!(out.len(), 288);
    out
}

fn put_statx_time(out: &mut Vec<u8>, seconds: i64, nanos: i64) {
    put_i64(out, seconds);
    put_u32(out, nanos.max(0) as u32);
    put_i32(out, 0);
}

#[cfg(target_os = "linux")]
fn host_removexattr(path: &Path, name: &[u8]) -> Result<(), i32> {
    let path = path_cstring(path)?;
    let name = xattr_name(name)?;
    let result = unsafe { libc::lremovexattr(path.as_ptr(), name.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io_errno(io::Error::last_os_error()))
    }
}

fn nul_name(input: &[u8], offset: usize) -> Result<&[u8], i32> {
    nul_name_with_end(input, offset).map(|(name, _)| name)
}

fn nul_name_with_end(input: &[u8], offset: usize) -> Result<(&[u8], usize), i32> {
    let rest = input.get(offset..).ok_or(EINVAL)?;
    let len = rest.iter().position(|byte| *byte == 0).ok_or(EINVAL)?;
    let name = &rest[..len];
    if name.is_empty() {
        return Err(EINVAL);
    }
    Ok((name, offset + len + 1))
}

fn validate_mutation_name(name: &[u8]) -> Result<(), i32> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        Err(EINVAL)
    } else {
        Ok(())
    }
}

fn put_attr(out: &mut Vec<u8>, node: u64, meta: &Metadata, guest: GuestAttr) {
    put_u64(out, node);
    put_u64(out, meta.size());
    put_u64(out, meta.blocks());
    put_u64(out, nonnegative(meta.atime()));
    put_u64(out, nonnegative(meta.mtime()));
    put_u64(out, nonnegative(meta.ctime()));
    put_u32(out, meta.atime_nsec().max(0) as u32);
    put_u32(out, meta.mtime_nsec().max(0) as u32);
    put_u32(out, meta.ctime_nsec().max(0) as u32);
    put_u32(out, guest.mode);
    put_u32(out, meta.nlink() as u32);
    put_u32(out, guest.uid);
    put_u32(out, guest.gid);
    put_u32(out, 0); // macOS st_rdev encoding is not Linux-compatible
    put_u32(out, meta.blksize() as u32);
    put_u32(out, 0);
}

fn nonnegative(value: i64) -> u64 {
    value.max(0) as u64
}

fn dirent_type(meta: &Metadata) -> u32 {
    dirent_type_ft(&meta.file_type())
}

fn dirent_type_ft(ty: &std::fs::FileType) -> u32 {
    if ty.is_dir() {
        4
    } else if ty.is_file() {
        8
    } else if ty.is_symlink() {
        10
    } else {
        0
    }
}

fn io_errno(err: io::Error) -> i32 {
    match err.raw_os_error() {
        Some(code) if code == libc::EPERM => return EPERM,
        Some(code) if code == libc::EBADF => return EBADF,
        Some(code) if code == libc::EACCES => return EACCES,
        Some(code) if code == libc::ENOENT => return ENOENT,
        Some(code) if code == libc::EEXIST => return EEXIST,
        Some(code) if code == libc::EXDEV => return EXDEV,
        Some(code) if code == libc::ENOTDIR => return ENOTDIR,
        Some(code) if code == libc::EISDIR => return EISDIR,
        Some(code) if code == libc::EINVAL => return EINVAL,
        Some(code) if code == libc::ENXIO => return ENXIO,
        Some(code) if code == libc::EAGAIN => return EAGAIN,
        Some(code) if code == libc::EDEADLK => return EDEADLK,
        Some(code) if code == libc::ENOTTY => return ENOTTY,
        Some(code) if code == libc::EFBIG => return EFBIG,
        Some(code) if code == libc::ENOSPC => return ENOSPC,
        Some(code) if code == libc::EROFS => return EROFS,
        Some(code) if code == libc::ERANGE => return ERANGE,
        Some(code) if is_no_xattr(code) => return ENODATA,
        Some(code) if code == libc::EOPNOTSUPP => return EOPNOTSUPP,
        Some(code) if code == libc::ENOSYS => return ENOSYS,
        Some(code) if code == libc::ENOTEMPTY => return ENOTEMPTY,
        Some(code) if code == libc::ELOOP => return ELOOP,
        Some(code) if code == libc::EMFILE => return EMFILE,
        Some(code) if code == libc::ENFILE => return ENFILE,
        Some(code) if code == libc::ETXTBSY => return ETXTBSY,
        Some(code) if code == libc::ENAMETOOLONG => return ENAMETOOLONG,
        Some(code) if code == libc::EBUSY => return EBUSY,
        Some(code) if code == libc::ENOMEM => return ENOMEM,
        Some(code) if code == libc::EMLINK => return EMLINK,
        Some(code) if code == libc::ENOLCK => return ENOLCK,
        Some(code) if code == libc::EOVERFLOW => return EOVERFLOW,
        Some(code) if code == libc::ESTALE => return ESTALE,
        Some(code) if code == libc::EDQUOT => return EDQUOT,
        _ => {}
    }
    match err.kind() {
        io::ErrorKind::NotFound => ENOENT,
        io::ErrorKind::PermissionDenied => EACCES,
        io::ErrorKind::AlreadyExists => EEXIST,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => EINVAL,
        io::ErrorKind::NotADirectory => ENOTDIR,
        io::ErrorKind::IsADirectory => EISDIR,
        io::ErrorKind::Unsupported => ENOSYS,
        _ => EIO,
    }
}

#[cfg(target_os = "macos")]
fn is_no_xattr(code: i32) -> bool {
    code == libc::ENOATTR
}

#[cfg(target_os = "linux")]
fn is_no_xattr(code: i32) -> bool {
    code == libc::ENODATA
}

/// Reads `out.len()` bytes from the logical concatenation of `descs`,
/// starting `skip` bytes in. Errors if the descriptors do not carry that
/// many bytes past the skip -- the same "descriptors do not actually carry
/// what they claim" case a full reconstruction would also reject.
fn gather(mem: &GuestRam, descs: &[(u64, u32)], skip: usize, out: &mut [u8]) -> Result<(), ()> {
    let mut pos = 0usize; // position in the logical concatenation
    let mut filled = 0usize;
    for &(addr, len) in descs {
        if filled == out.len() {
            break;
        }
        let len = len as usize;
        let desc_end = pos + len;
        if desc_end > skip {
            let start_in_desc = skip.saturating_sub(pos);
            let avail = (len - start_in_desc).min(out.len() - filled);
            let base = addr.checked_add(start_in_desc as u64).ok_or(())?;
            mem.read(base, &mut out[filled..filled + avail])
                .map_err(|_| ())?;
            filled += avail;
        }
        pos = desc_end;
    }
    if filled < out.len() {
        Err(())
    } else {
        Ok(())
    }
}

/// Builds iovecs borrowing guest RAM directly for `descs`, skipping `skip`
/// bytes of the logical concatenation and capping the total at `cap` bytes.
/// Returns the iovecs and how many bytes they actually cover, which can be
/// less than `cap` if the descriptors run out first.
///
/// Errors (falling back to the buffered path) if there are more descriptors
/// than `IOV_MAX`, or if a descriptor's range is not in mapped guest RAM.
fn build_iov(
    mem: &GuestRam,
    descs: &[(u64, u32)],
    skip: usize,
    cap: usize,
) -> Result<(Vec<libc::iovec>, usize), ()> {
    if descs.len() > IOV_MAX {
        return Err(());
    }
    let mut iov = Vec::with_capacity(descs.len());
    let mut pos = 0usize;
    let mut total = 0usize;
    for &(addr, len) in descs {
        if total == cap {
            break;
        }
        let len = len as usize;
        let desc_end = pos + len;
        if desc_end > skip {
            let start_in_desc = skip.saturating_sub(pos);
            let avail = (len - start_in_desc).min(cap - total);
            if avail > 0 {
                let base = addr.checked_add(start_in_desc as u64).ok_or(())?;
                let ptr = mem.host_ptr(base, avail).map_err(|_| ())?;
                iov.push(libc::iovec {
                    iov_base: ptr.cast(),
                    iov_len: avail,
                });
                total += avail;
            }
        }
        pos = desc_end;
    }
    Ok((iov, total))
}

/// Writes a success `fuse_out_header` (`total_len`, error 0, `unique`)
/// scattered across `output`'s leading `OUT_HEADER_LEN` bytes -- the region
/// `build_iov(..., OUT_HEADER_LEN, ...)` deliberately excludes, so this never
/// overlaps the direct-path payload it is called after.
fn write_direct_out_header(
    mem: &GuestRam,
    output: &[(u64, u32)],
    unique: u64,
    total_len: u32,
) -> io::Result<()> {
    let mut header = [0u8; OUT_HEADER_LEN];
    header[0..4].copy_from_slice(&total_len.to_le_bytes());
    header[8..16].copy_from_slice(&unique.to_le_bytes());
    let mut copied = 0usize;
    for &(addr, len) in output {
        if copied == header.len() {
            break;
        }
        let n = (len as usize).min(header.len() - copied);
        mem.write(addr, &header[copied..copied + n])?;
        copied += n;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn raw_preadv(fd: i32, iov: &[libc::iovec], offset: u64) -> io::Result<usize> {
    let n = unsafe { libc::preadv(fd, iov.as_ptr(), iov.len() as i32, offset as libc::off_t) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(target_os = "linux")]
fn raw_preadv(fd: i32, iov: &[libc::iovec], offset: u64) -> io::Result<usize> {
    // glibc does not expose plain `preadv` (only `preadv64`/`preadv2`); on a
    // 64-bit target `off64_t` is the same width `off_t` would be anyway.
    let n = unsafe { libc::preadv64(fd, iov.as_ptr(), iov.len() as i32, offset as libc::off64_t) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(target_os = "macos")]
fn raw_pwritev(fd: i32, iov: &[libc::iovec], offset: u64) -> io::Result<usize> {
    let n = unsafe { libc::pwritev(fd, iov.as_ptr(), iov.len() as i32, offset as libc::off_t) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(target_os = "linux")]
fn raw_pwritev(fd: i32, iov: &[libc::iovec], offset: u64) -> io::Result<usize> {
    let n = unsafe { libc::pwritev64(fd, iov.as_ptr(), iov.len() as i32, offset as libc::off64_t) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// `preadv`, retried on `EINTR`. An empty `iov` is a legitimate zero-length
/// read (e.g. offset already at EOF with nothing requested) rather than a
/// syscall with a null iovec pointer.
fn preadv_retry(file: &File, iov: &[libc::iovec], offset: u64) -> io::Result<usize> {
    if iov.is_empty() {
        return Ok(0);
    }
    loop {
        match raw_preadv(file.as_raw_fd(), iov, offset) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// `pwritev`, retried on `EINTR`. See `preadv_retry` for the empty-`iov`
/// case.
fn pwritev_retry(file: &File, iov: &[libc::iovec], offset: u64) -> io::Result<usize> {
    if iov.is_empty() {
        return Ok(0);
    }
    loop {
        match raw_pwritev(file.as_raw_fd(), iov, offset) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn success_response(unique: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(OUT_HEADER_LEN + payload.len());
    put_u32(&mut out, (OUT_HEADER_LEN + payload.len()) as u32);
    put_i32(&mut out, 0);
    put_u64(&mut out, unique);
    out.extend_from_slice(payload);
    out
}

fn error_response(unique: u64, errno: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(OUT_HEADER_LEN);
    put_u32(&mut out, OUT_HEADER_LEN as u32);
    put_i32(&mut out, -errno.abs());
    put_u64(&mut out, unique);
    out
}

fn align8(value: usize) -> usize {
    (value + 7) & !7
}

fn get_u32(input: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        input.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn get_u64(input: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        input.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {

    /// Descriptor exhaustion must reach the guest as EMFILE, not EIO.
    ///
    /// This is the bug that cost a session of guessing. hvi pins one host fd
    /// per open guest handle; with the macOS default soft limit of 256, a
    /// build inside the guest exhausts them and every affected open failed
    /// with "Input/output error" on a random unrelated file. Confirmed by
    /// booting the same image at `ulimit -n 256` (guest fails all over, hvi
    /// peaks at 258 fds) and at 8192 (identical workload clean, peak 2134).
    ///
    /// The catch-all in io_errno is what turned a precise, actionable errno
    /// into the least informative one available.
    #[test]
    fn errnos_that_used_to_collapse_to_eio_are_named() {
        for (code, want, what) in [
            (libc::EMFILE, EMFILE, "per-process fd limit"),
            (libc::ENFILE, ENFILE, "system-wide fd limit"),
            (libc::ETXTBSY, ETXTBSY, "text file busy"),
            (libc::ENAMETOOLONG, ENAMETOOLONG, "name too long"),
            (libc::EBUSY, EBUSY, "busy"),
            (libc::ENOMEM, ENOMEM, "out of memory"),
            (libc::EMLINK, EMLINK, "too many links"),
            (libc::ENOLCK, ENOLCK, "no locks available"),
            (libc::EOVERFLOW, EOVERFLOW, "overflow"),
            (libc::ESTALE, ESTALE, "stale handle"),
            (libc::EDQUOT, EDQUOT, "quota exceeded"),
        ] {
            let got = io_errno(io::Error::from_raw_os_error(code));
            assert_eq!(
                got, want,
                "{what} (host errno {code}) reported to the guest as {got}, want {want}"
            );
            assert_ne!(
                got, EIO,
                "{what} is still collapsing to EIO, which tells the guest nothing"
            );
        }
    }

    /// The errnos that were already mapped stay mapped.
    #[test]
    fn the_existing_errno_mapping_is_unchanged() {
        for (code, want) in [
            (libc::ENOENT, ENOENT),
            (libc::EACCES, EACCES),
            (libc::EEXIST, EEXIST),
            (libc::ENOTDIR, ENOTDIR),
            (libc::EISDIR, EISDIR),
            (libc::ENOSPC, ENOSPC),
            (libc::ELOOP, ELOOP),
        ] {
            assert_eq!(io_errno(io::Error::from_raw_os_error(code)), want);
        }
    }

    /// An errno with no mapping still becomes EIO -- that fallback is correct,
    /// it was only ever the coverage that was wrong.
    #[test]
    fn an_unknown_errno_still_becomes_eio() {
        assert_eq!(io_errno(io::Error::from_raw_os_error(libc::EPROTO)), EIO);
    }

    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn request(opcode: u32, node: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, (IN_HEADER_LEN + payload.len()) as u32);
        put_u32(&mut out, opcode);
        put_u64(&mut out, 0x1234);
        put_u64(&mut out, node);
        out.resize(IN_HEADER_LEN, 0);
        out.extend_from_slice(payload);
        out
    }

    fn request_as(opcode: u32, node: u64, payload: &[u8], uid: u32, gid: u32) -> Vec<u8> {
        let mut out = request(opcode, node, payload);
        out[24..28].copy_from_slice(&uid.to_le_bytes());
        out[28..32].copy_from_slice(&gid.to_le_bytes());
        out
    }

    fn fixture_with_cache(writable: bool, cache: CachePolicy) -> (PathBuf, VirtioFs) {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("hvi-virtiofs-test-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/issue"), b"hello\n").unwrap();
        let fs = VirtioFs::new(fs::canonicalize(&dir).unwrap(), "rootfs", writable, cache).unwrap();
        (dir, fs)
    }

    fn fixture_with_access(writable: bool) -> (PathBuf, VirtioFs) {
        fixture_with_cache(writable, CachePolicy::Auto)
    }

    fn fixture() -> (PathBuf, VirtioFs) {
        fixture_with_access(false)
    }

    /// A guest binding a Unix socket sends MKNOD with S_IFSOCK. It has to
    /// succeed, and nothing may appear on the host: a socket needs the
    /// filesystem only for an inode of the right type, because the rendezvous
    /// and the data are the guest kernel's own business. Proven on Linux
    /// against a FUSE filesystem whose sockets were backed by nothing at all --
    /// bind, connect and a round trip between two processes all worked.
    #[test]
    fn a_guest_socket_is_served_without_touching_the_host() {
        let (dir, mut dev) = fixture_with_access(true);
        let mut payload = Vec::new();
        put_u32(&mut payload, S_IFSOCK | 0o700);
        put_u32(&mut payload, 0); // rdev
        put_u32(&mut payload, 0); // umask
        put_u32(&mut payload, 0); // padding
        payload.extend_from_slice(b"control.sock\0");

        let out = dev.handle_fuse(&request(MKNOD, FUSE_ROOT_ID, &payload), 4096);
        assert_eq!(
            i32::from_le_bytes(out[4..8].try_into().unwrap()),
            0,
            "MKNOD of a socket was refused"
        );

        // The host has nothing, which is the whole point.
        assert!(
            !dir.join("control.sock").exists(),
            "a socket reached the host filesystem"
        );

        // The guest sees it, with the type and mode it asked for.
        let node = lookup_node(&mut dev, FUSE_ROOT_ID, b"control.sock\0");
        let attrs = dev.handle_fuse(&request(GETATTR, node, &[0u8; 16]), 4096);
        let mode = u32::from_le_bytes(attrs[92..96].try_into().unwrap());
        assert_eq!(mode & S_IFMT, S_IFSOCK, "not reported as a socket");
        assert_eq!(mode & 0o7777, 0o700, "mode was not preserved");

        let _ = fs::remove_dir_all(dir);
    }

    /// A socket reported zero for atime, mtime and ctime when it was first
    /// served from here, which dates every one of them to 1 January 1970 in
    /// a listing -- visible in `ls -l`, and worse than cosmetic for anything
    /// that ages what it finds in a directory.
    #[test]
    fn a_socket_is_stamped_with_a_real_time() {
        let (dir, mut dev) = fixture_with_access(true);
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut payload = Vec::new();
        put_u32(&mut payload, S_IFSOCK | 0o700);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        payload.extend_from_slice(b"dated.sock\0");
        dev.handle_fuse(&request(MKNOD, FUSE_ROOT_ID, &payload), 4096);

        let node = lookup_node(&mut dev, FUSE_ROOT_ID, b"dated.sock\0");
        let attrs = dev.handle_fuse(&request(GETATTR, node, &[0u8; 16]), 4096);
        // put_attr's layout: the out header is 16 bytes, attr_out adds 16,
        // then ino/size/blocks precede the three timestamps.
        let atime = u64::from_le_bytes(attrs[56..64].try_into().unwrap());
        let mtime = u64::from_le_bytes(attrs[64..72].try_into().unwrap());
        let ctime = u64::from_le_bytes(attrs[72..80].try_into().unwrap());

        assert!(atime >= before, "atime is not a real time: {atime}");
        assert_eq!(mtime, atime, "mtime should match");
        assert_eq!(ctime, atime, "ctime should match");

        let _ = fs::remove_dir_all(dir);
    }

    /// The identity requirement. A guest that drops its cache and looks the
    /// path up again must arrive at the same inode, or the socket its server
    /// is bound to becomes unreachable. Verified on Linux by dropping the
    /// kernel's dentry cache under a live bind and reconnecting.
    #[test]
    fn a_socket_keeps_its_identity_across_lookups() {
        let (dir, mut dev) = fixture_with_access(true);
        let mut payload = Vec::new();
        put_u32(&mut payload, S_IFSOCK | 0o700);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        payload.extend_from_slice(b"keep.sock\0");
        dev.handle_fuse(&request(MKNOD, FUSE_ROOT_ID, &payload), 4096);

        let first = lookup_node(&mut dev, FUSE_ROOT_ID, b"keep.sock\0");
        let second = lookup_node(&mut dev, FUSE_ROOT_ID, b"keep.sock\0");
        assert_eq!(first, second, "the same socket resolved to two nodes");

        let _ = fs::remove_dir_all(dir);
    }

    /// Unlinking takes the socket out of the device, and the host -- which
    /// never had it -- is left alone.
    #[test]
    fn unlinking_a_socket_removes_it() {
        let (dir, mut dev) = fixture_with_access(true);
        let mut payload = Vec::new();
        put_u32(&mut payload, S_IFSOCK | 0o700);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, 0);
        payload.extend_from_slice(b"gone.sock\0");
        dev.handle_fuse(&request(MKNOD, FUSE_ROOT_ID, &payload), 4096);

        let out = dev.handle_fuse(&request(UNLINK, FUSE_ROOT_ID, b"gone.sock\0"), 4096);
        assert_eq!(i32::from_le_bytes(out[4..8].try_into().unwrap()), 0);

        let out = dev.handle_fuse(&request(LOOKUP, FUSE_ROOT_ID, b"gone.sock\0"), 4096);
        assert_eq!(
            i32::from_le_bytes(out[4..8].try_into().unwrap()),
            -ENOENT,
            "the socket outlived its unlink"
        );

        let _ = fs::remove_dir_all(dir);
    }

    fn lookup_node(dev: &mut VirtioFs, parent: u64, name: &[u8]) -> u64 {
        let mut payload = name.to_vec();
        payload.push(0);
        let out = dev.handle_fuse(&request(LOOKUP, parent, &payload), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        get_u64(&out, OUT_HEADER_LEN).unwrap()
    }

    fn open_rw(dev: &mut VirtioFs, node: u64) -> u64 {
        let mut input = vec![0u8; 8];
        input[0..4].copy_from_slice(&LINUX_O_RDWR.to_le_bytes());
        let out = dev.handle_fuse(&request(OPEN, node, &input), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        get_u64(&out, OUT_HEADER_LEN).unwrap()
    }

    /// Daemon-side cost of the metadata path, the one real workloads (a build
    /// tree, `ls -R`, a source checkout) spend their time in. Drives the device
    /// directly, so it measures host-side work only: no guest kernel, and so no
    /// benefit from the attribute/entry timeouts, which cut the number of
    /// requests that ever arrive rather than the cost of serving one.
    ///
    /// Run with:
    ///   cargo test --release -- --ignored --nocapture bench_metadata_workload
    #[test]
    #[ignore]
    fn bench_metadata_workload() {
        const FILES: usize = 200;
        const ROUNDS: usize = 20;

        let (dir, mut dev) = fixture_with_access(true);
        let tree = dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        for i in 0..FILES {
            fs::write(tree.join(format!("file-{i:04}")), b"x").unwrap();
        }
        let tree_node = lookup_node(&mut dev, FUSE_ROOT_ID, b"tree");

        // Warm the host's own metadata caches so this measures our syscall
        // count, not cold I/O.
        for i in 0..FILES {
            let mut name = format!("file-{i:04}").into_bytes();
            name.push(0);
            let _ = dev.handle_fuse(&request(LOOKUP, tree_node, &name), 4096);
        }

        let start = std::time::Instant::now();
        let mut ops = 0u64;
        for _ in 0..ROUNDS {
            // A directory listing, the way the guest does it.
            let out = dev.handle_fuse(&request(OPENDIR, tree_node, &[0u8; 8]), 4096);
            let fh = get_u64(&out, OUT_HEADER_LEN).unwrap();
            let mut offset = 0u64;
            loop {
                let mut input = vec![0u8; 40];
                input[0..8].copy_from_slice(&fh.to_le_bytes());
                input[8..16].copy_from_slice(&offset.to_le_bytes());
                input[16..20].copy_from_slice(&4096u32.to_le_bytes());
                let out = dev.handle_fuse(&request(READDIRPLUS, tree_node, &input), 4096 + 16);
                ops += 1;
                if out.len() <= OUT_HEADER_LEN {
                    break;
                }
                // Last dirent's offset field is the next starting point.
                let mut pos = OUT_HEADER_LEN;
                let mut last = offset;
                while pos + 152 <= out.len() {
                    last = get_u64(&out, pos + 128 + 8).unwrap();
                    let namelen = get_u32(&out, pos + 128 + 16).unwrap() as usize;
                    pos += align8(128 + 24 + namelen);
                }
                if last == offset {
                    break;
                }
                offset = last;
            }
            let mut input = vec![0u8; 8];
            input[0..8].copy_from_slice(&fh.to_le_bytes());
            dev.handle_fuse(&request(RELEASEDIR, tree_node, &input), 4096);

            // Then stat every entry, which is what a build actually does.
            for i in 0..FILES {
                let mut name = format!("file-{i:04}").into_bytes();
                name.push(0);
                let out = dev.handle_fuse(&request(LOOKUP, tree_node, &name), 4096);
                let node = get_u64(&out, OUT_HEADER_LEN).unwrap();
                dev.handle_fuse(&request(GETATTR, node, &[0u8; 16]), 4096);
                ops += 2;
            }
        }
        let elapsed = start.elapsed();
        println!(
            "BENCH metadata: {} ops in {:.3} ms => {:.2} us/op",
            ops,
            elapsed.as_secs_f64() * 1e3,
            elapsed.as_secs_f64() * 1e6 / ops as f64
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn init_negotiates_without_dax() {
        let (dir, mut dev) = fixture();
        let mut payload = Vec::new();
        put_u32(&mut payload, 7);
        put_u32(&mut payload, 39);
        put_u32(&mut payload, 128 << 10);
        put_u32(&mut payload, u32::MAX);
        let out = dev.handle_fuse(&request(INIT, 0, &payload), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(get_u32(&out, 16), Some(7));
        assert_eq!(get_u32(&out, 20), Some(39));
        assert_eq!(get_u32(&out, 40), Some(1)); // time_gran
        let _ = fs::remove_dir_all(dir);
    }

    fn init_payload_offering_everything() -> Vec<u8> {
        let mut payload = Vec::new();
        put_u32(&mut payload, 7);
        put_u32(&mut payload, 39);
        put_u32(&mut payload, 0);
        put_u32(&mut payload, u32::MAX);
        payload
    }

    #[test]
    fn init_writable_always_negotiates_writeback_cache() {
        const WRITEBACK_CACHE: u32 = 1 << 16;
        let (dir, mut dev) = fixture_with_cache(true, CachePolicy::Always);
        let out = dev.handle_fuse(&request(INIT, 0, &init_payload_offering_everything()), 4096);
        let flags = get_u32(&out, OUT_HEADER_LEN + 12).unwrap();
        assert_ne!(
            flags & WRITEBACK_CACHE,
            0,
            "Always + writable negotiates it"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn init_writable_auto_does_not_negotiate_writeback_cache() {
        const WRITEBACK_CACHE: u32 = 1 << 16;
        let (dir, mut dev) = fixture_with_cache(true, CachePolicy::Auto);
        let out = dev.handle_fuse(&request(INIT, 0, &init_payload_offering_everything()), 4096);
        let flags = get_u32(&out, OUT_HEADER_LEN + 12).unwrap();
        assert_eq!(
            flags & WRITEBACK_CACHE,
            0,
            "handing over mtime/size ownership needs an explicit Always"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn init_always_negotiates_parallel_diroops() {
        const PARALLEL_DIROPS: u32 = 1 << 18;
        for (writable, cache) in [
            (false, CachePolicy::Auto),
            (true, CachePolicy::None),
            (true, CachePolicy::Always),
        ] {
            let (dir, mut dev) = fixture_with_cache(writable, cache);
            let out = dev.handle_fuse(&request(INIT, 0, &init_payload_offering_everything()), 4096);
            let flags = get_u32(&out, OUT_HEADER_LEN + 12).unwrap();
            assert_ne!(flags & PARALLEL_DIROPS, 0, "{writable:?}/{cache:?}");
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn writable_auto_cache_returns_nonzero_timeouts_and_none_returns_zero() {
        let (dir, mut dev) = fixture_with_cache(true, CachePolicy::Auto);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let lookup = dev.handle_fuse(&request(LOOKUP, etc, b"issue\0"), 4096);
        assert_ne!(
            get_u64(&lookup, OUT_HEADER_LEN + 16),
            Some(0),
            "entry_valid"
        );
        assert_ne!(get_u64(&lookup, OUT_HEADER_LEN + 24), Some(0), "attr_valid");
        let issue = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let getattr = dev.handle_fuse(&request(GETATTR, issue, &[]), 4096);
        assert_ne!(
            get_u64(&getattr, OUT_HEADER_LEN),
            Some(0),
            "attr_out attr_valid"
        );
        let _ = fs::remove_dir_all(dir);

        let (dir, mut dev) = fixture_with_cache(true, CachePolicy::None);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let lookup = dev.handle_fuse(&request(LOOKUP, etc, b"issue\0"), 4096);
        assert_eq!(get_u64(&lookup, OUT_HEADER_LEN + 16), Some(0));
        assert_eq!(get_u64(&lookup, OUT_HEADER_LEN + 24), Some(0));
        let issue = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let getattr = dev.handle_fuse(&request(GETATTR, issue, &[]), 4096);
        assert_eq!(get_u64(&getattr, OUT_HEADER_LEN), Some(0));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn open_keep_cache_flag_follows_cache_policy() {
        const FOPEN_KEEP_CACHE: u32 = 1 << 1;
        let mut open = vec![0u8; 8];
        open[0..4].copy_from_slice(&LINUX_O_RDWR.to_le_bytes());

        let (dir, mut dev) = fixture_with_cache(true, CachePolicy::Auto);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let issue = lookup_node(&mut dev, etc, b"issue");
        let opened = dev.handle_fuse(&request(OPEN, issue, &open), 4096);
        assert_eq!(get_u32(&opened, OUT_HEADER_LEN + 8), Some(FOPEN_KEEP_CACHE));
        let _ = fs::remove_dir_all(dir);

        let (dir, mut dev) = fixture_with_cache(true, CachePolicy::None);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let issue = lookup_node(&mut dev, etc, b"issue");
        let opened = dev.handle_fuse(&request(OPEN, issue, &open), 4096);
        assert_eq!(get_u32(&opened, OUT_HEADER_LEN + 8), Some(0));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn lookup_and_read_regular_file() {
        let (dir, mut dev) = fixture();
        let lookup = dev.handle_fuse(&request(LOOKUP, FUSE_ROOT_ID, b"etc\0"), 4096);
        let etc_node = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let lookup = dev.handle_fuse(&request(LOOKUP, etc_node, b"issue\0"), 4096);
        let issue_node = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let mut read_in = vec![0u8; 40];
        read_in[16..20].copy_from_slice(&32u32.to_le_bytes());
        let out = dev.handle_fuse(&request(READ, issue_node, &read_in), 4096);
        assert_eq!(&out[OUT_HEADER_LEN..], b"hello\n");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn mutation_is_read_only() {
        let (dir, mut dev) = fixture();
        let out = dev.handle_fuse(&request(9, FUSE_ROOT_ID, b"bad\0"), 4096);
        assert_eq!(i32::from_le_bytes(out[4..8].try_into().unwrap()), -EROFS);
        assert!(!dir.join("bad").exists());

        let lookup = dev.handle_fuse(&request(LOOKUP, FUSE_ROOT_ID, b"etc\0"), 4096);
        let etc_node = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let lookup = dev.handle_fuse(&request(LOOKUP, etc_node, b"issue\0"), 4096);
        let issue_node = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let mut open = vec![0u8; 8];
        open[0..4].copy_from_slice(&LINUX_O_RDWR.to_le_bytes());
        let out = dev.handle_fuse(&request(OPEN, issue_node, &open), 4096);
        assert_eq!(i32::from_le_bytes(out[4..8].try_into().unwrap()), -EROFS);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn create_write_sync_and_release() {
        let (dir, mut dev) = fixture_with_access(true);
        let mut create = vec![0u8; 16];
        create[0..4].copy_from_slice(&(LINUX_O_RDWR | LINUX_O_EXCL).to_le_bytes());
        create[4..8].copy_from_slice(&(S_IFREG | 0o640).to_le_bytes());
        create.extend_from_slice(b"created\0");
        let out = dev.handle_fuse(&request(CREATE, FUSE_ROOT_ID, &create), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        let node = get_u64(&out, OUT_HEADER_LEN).unwrap();
        let fh = get_u64(&out, OUT_HEADER_LEN + 128).unwrap();

        let mut write = vec![0u8; 40];
        write[0..8].copy_from_slice(&fh.to_le_bytes());
        write[8..16].copy_from_slice(&3u64.to_le_bytes());
        write[16..20].copy_from_slice(&5u32.to_le_bytes());
        write.extend_from_slice(b"hello");
        let out = dev.handle_fuse(&request(WRITE, node, &write), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(get_u32(&out, OUT_HEADER_LEN), Some(5));

        let mut fsync = vec![0u8; 16];
        fsync[0..8].copy_from_slice(&fh.to_le_bytes());
        let out = dev.handle_fuse(&request(FSYNC, node, &fsync), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));

        let mut release = vec![0u8; 24];
        release[0..8].copy_from_slice(&fh.to_le_bytes());
        let out = dev.handle_fuse(&request(RELEASE, node, &release), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(fs::read(dir.join("created")).unwrap(), b"\0\0\0hello");
        let mode = fs::metadata(dir.join("created")).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o640);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn writable_namespace_operations_update_node_paths() {
        let (dir, mut dev) = fixture_with_access(true);
        let mut mkdir = vec![0u8; 8];
        mkdir[0..4].copy_from_slice(&0o750u32.to_le_bytes());
        mkdir.extend_from_slice(b"work\0");
        let out = dev.handle_fuse(&request(MKDIR, FUSE_ROOT_ID, &mkdir), 4096);
        let work_node = get_u64(&out, OUT_HEADER_LEN).unwrap();

        let mut create = vec![0u8; 16];
        create[0..4].copy_from_slice(&(LINUX_O_RDWR | LINUX_O_EXCL).to_le_bytes());
        create[4..8].copy_from_slice(&(S_IFREG | 0o600).to_le_bytes());
        create.extend_from_slice(b"old\0");
        let out = dev.handle_fuse(&request(CREATE, work_node, &create), 4096);
        let file_node = get_u64(&out, OUT_HEADER_LEN).unwrap();

        let mut rename = Vec::new();
        put_u64(&mut rename, work_node);
        rename.extend_from_slice(b"old\0new\0");
        let out = dev.handle_fuse(&request(RENAME, work_node, &rename), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(
            dev.node_path(file_node).unwrap(),
            fs::canonicalize(&dir).unwrap().join("work/new")
        );

        let out = dev.handle_fuse(&request(UNLINK, work_node, b"new\0"), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        let out = dev.handle_fuse(&request(RMDIR, FUSE_ROOT_ID, b"work\0"), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert!(!dir.join("work").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn writable_operations_follow_directory_symlinks() {
        let (dir, mut dev) = fixture_with_access(true);
        #[cfg(unix)]
        std::os::unix::fs::symlink("etc", dir.join("include")).expect("create directory symlink");

        let lookup = dev.handle_fuse(&request(LOOKUP, FUSE_ROOT_ID, b"include\0"), 4096);
        assert_eq!(get_u32(&lookup, 4), Some(0));
        let include_node = get_u64(&lookup, OUT_HEADER_LEN).unwrap();

        let mut create = vec![0u8; 16];
        create[0..4].copy_from_slice(&(LINUX_O_RDWR | LINUX_O_EXCL).to_le_bytes());
        create[4..8].copy_from_slice(&(S_IFREG | 0o600).to_le_bytes());
        create.extend_from_slice(b"from-link\0");
        let out = dev.handle_fuse(&request(CREATE, include_node, &create), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert!(dir.join("etc/from-link").exists());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn writable_symlink_and_hardlink() {
        let (dir, mut dev) = fixture_with_access(true);
        let lookup = dev.handle_fuse(&request(LOOKUP, FUSE_ROOT_ID, b"etc\0"), 4096);
        let etc_node = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let lookup = dev.handle_fuse(&request(LOOKUP, etc_node, b"issue\0"), 4096);
        let issue_node = get_u64(&lookup, OUT_HEADER_LEN).unwrap();

        let out = dev.handle_fuse(&request(SYMLINK, etc_node, b"current\0issue\0"), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(
            fs::read_link(dir.join("etc/current")).unwrap(),
            Path::new("issue")
        );

        let mut link = Vec::new();
        put_u64(&mut link, issue_node);
        link.extend_from_slice(b"banner\0");
        let out = dev.handle_fuse(&request(LINK, etc_node, &link), 4096);
        assert_eq!(get_u64(&out, OUT_HEADER_LEN), Some(issue_node));
        assert_eq!(fs::read(dir.join("etc/banner")).unwrap(), b"hello\n");
        let _ = fs::remove_dir_all(dir);
    }

    /// Attaching a previously unseen path to an inode we already know must
    /// drop that node's cached guest attribute.
    ///
    /// That happens for a new hard link, and -- the case that actually
    /// corrupts -- when the host reuses an inode number for a freshly created
    /// file while the guest still holds a lookup reference to the unlinked
    /// one. Before the cache every attribute reply re-read the xattr, so a
    /// stale value was not representable; the cache makes it possible, and
    /// this pins the invalidation that prevents it.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_new_path_for_a_known_inode_drops_the_cached_guest_attribute() {
        let (dir, mut dev) = fixture_with_access(true);
        let etc_node = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let issue_node = lookup_node(&mut dev, etc_node, b"issue");

        // Populate the cache. The fixture's files are host-created, so this
        // caches "no xattr present".
        let out = dev.handle_fuse(&request(GETATTR, issue_node, &[0u8; 16]), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(get_u32(&out, OUT_HEADER_LEN + 16 + 68), Some(0));

        // Write the xattr behind the device's back, standing in for what a
        // creation into a reused inode would leave on disk.
        set_guest_attr(
            &dir.join("etc/issue"),
            GuestAttr {
                mode: S_IFREG | 0o600,
                uid: 4242,
                gid: 4243,
            },
        )
        .unwrap();

        // Still the cached answer: serving the memoised miss is the whole
        // point, and nothing has told us the inode changed identity yet.
        let out = dev.handle_fuse(&request(GETATTR, issue_node, &[0u8; 16]), 4096);
        assert_eq!(get_u32(&out, OUT_HEADER_LEN + 16 + 68), Some(0));

        // A second name for the same inode is that signal.
        let mut link = Vec::new();
        put_u64(&mut link, issue_node);
        link.extend_from_slice(b"alias\0");
        let out = dev.handle_fuse(&request(LINK, etc_node, &link), 4096);
        assert_eq!(get_u64(&out, OUT_HEADER_LEN), Some(issue_node));

        let out = dev.handle_fuse(&request(GETATTR, issue_node, &[0u8; 16]), 4096);
        assert_eq!(
            get_u32(&out, OUT_HEADER_LEN + 16 + 68),
            Some(4242),
            "stale uid served from the cache after the inode gained a new path"
        );
        assert_eq!(get_u32(&out, OUT_HEADER_LEN + 16 + 72), Some(4243));
        assert_eq!(
            get_u32(&out, OUT_HEADER_LEN + 16 + 60).unwrap() & 0o7777,
            0o600
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn open_handle_survives_unlink_and_supports_setattr() {
        let (dir, mut dev) = fixture_with_access(true);
        let lookup = dev.handle_fuse(&request(LOOKUP, FUSE_ROOT_ID, b"etc\0"), 4096);
        let etc_node = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let lookup = dev.handle_fuse(&request(LOOKUP, etc_node, b"issue\0"), 4096);
        let issue_node = get_u64(&lookup, OUT_HEADER_LEN).unwrap();

        let mut open = vec![0u8; 8];
        open[0..4].copy_from_slice(&LINUX_O_RDWR.to_le_bytes());
        let out = dev.handle_fuse(&request(OPEN, issue_node, &open), 4096);
        let fh = get_u64(&out, OUT_HEADER_LEN).unwrap();

        let out = dev.handle_fuse(&request(UNLINK, etc_node, b"issue\0"), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert!(!dir.join("etc/issue").exists());

        let mut write = vec![0u8; 40];
        write[0..8].copy_from_slice(&fh.to_le_bytes());
        write[16..20].copy_from_slice(&4u32.to_le_bytes());
        write.extend_from_slice(b"kept");
        let out = dev.handle_fuse(&request(WRITE, issue_node, &write), 4096);
        assert_eq!(get_u32(&out, OUT_HEADER_LEN), Some(4));

        let mut setattr = vec![0u8; 88];
        setattr[0..4].copy_from_slice(&(FATTR_SIZE | FATTR_FH).to_le_bytes());
        setattr[8..16].copy_from_slice(&fh.to_le_bytes());
        setattr[16..24].copy_from_slice(&2u64.to_le_bytes());
        let out = dev.handle_fuse(&request(SETATTR, issue_node, &setattr), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        // attr_out starts after the response header; size follows nodeid.
        assert_eq!(get_u64(&out, OUT_HEADER_LEN + 16 + 8), Some(2));

        let mut release = vec![0u8; 24];
        release[0..8].copy_from_slice(&fh.to_le_bytes());
        dev.handle_fuse(&request(RELEASE, issue_node, &release), 4096);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn writable_names_cannot_escape_the_export() {
        let (dir, mut dev) = fixture_with_access(true);
        let mut mkdir = vec![0u8; 8];
        mkdir[0..4].copy_from_slice(&0o755u32.to_le_bytes());
        mkdir.extend_from_slice(b"..\0");
        let out = dev.handle_fuse(&request(MKDIR, FUSE_ROOT_ID, &mkdir), 4096);
        assert_eq!(i32::from_le_bytes(out[4..8].try_into().unwrap()), -EINVAL);

        let mut rename = Vec::new();
        put_u64(&mut rename, FUSE_ROOT_ID);
        rename.extend_from_slice(b"etc\0../outside\0");
        let out = dev.handle_fuse(&request(RENAME, FUSE_ROOT_ID, &rename), 4096);
        assert_eq!(i32::from_le_bytes(out[4..8].try_into().unwrap()), -EINVAL);
        assert!(dir.join("etc").is_dir());
        let _ = fs::remove_dir_all(dir);
    }

    /// Opening a FIFO blocks until the other end is opened, and the device
    /// serves a request holding its own mutex, on the vCPU thread for a
    /// shallow queue. A guest that made a FIFO and opened it therefore stopped
    /// the whole VM, not just its own request.
    #[test]
    fn opening_a_fifo_is_refused_rather_than_blocking() {
        let (dir, mut dev) = fixture_with_access(true);
        let mut mknod = vec![0u8; 16];
        mknod[0..4].copy_from_slice(&(S_IFIFO | 0o644).to_le_bytes());
        mknod.extend_from_slice(b"pipe\0");
        let out = dev.handle_fuse(&request(MKNOD, FUSE_ROOT_ID, &mknod), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        let node = get_u64(&out, OUT_HEADER_LEN).unwrap();

        // Served on another thread so a regression fails this test instead of
        // hanging the suite the way it would hang a guest.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = dev.handle_fuse(&request(OPEN, node, &[0u8; 8]), 4096);
            let _ = tx.send(i32::from_le_bytes(out[4..8].try_into().unwrap()));
        });
        let errno = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("opening a FIFO blocked the device");
        assert_eq!(errno, -EPERM);
        let _ = fs::remove_dir_all(dir);
    }

    /// A path outside any export, for the escape tests below.
    fn outside_path(what: &str) -> PathBuf {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "hvi-virtiofs-outside-{what}-{}-{id}",
            std::process::id()
        ))
    }

    /// A tree to walk, returned with its own resolved root so the assertions
    /// compare like with like on a macOS `/var` -> `/private/var` temp dir.
    fn dircache_fixture() -> (PathBuf, DirCache) {
        let dir = outside_path("dircache");
        fs::create_dir_all(dir.join("usr/lib/ssl")).unwrap();
        fs::create_dir_all(dir.join("etc")).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let cache = DirCache::new(&dir, DIR_CACHE_LIMIT).unwrap();
        (dir, cache)
    }

    /// The root is the origin of every walk and is never keyed or evicted.
    #[test]
    fn dircache_serves_the_root_without_walking() {
        let (dir, mut cache) = dircache_fixture();
        let fd = cache.dir_fd(FUSE_ROOT_ID, Path::new("")).unwrap();
        assert!(fd.as_raw_fd() >= 0);
        assert_eq!(cache.resident(), 0, "the root is pinned, not cached");
        let _ = fs::remove_dir_all(dir);
    }

    /// A descriptor for a nested directory, and the second ask is a hit.
    #[test]
    fn dircache_walks_then_reuses() {
        let (dir, mut cache) = dircache_fixture();
        let first = cache
            .dir_fd(2, Path::new("usr/lib/ssl"))
            .unwrap()
            .as_raw_fd();
        assert_eq!(cache.resident(), 1);
        let second = cache
            .dir_fd(2, Path::new("usr/lib/ssl"))
            .unwrap()
            .as_raw_fd();
        assert_eq!(
            first, second,
            "a hit must hand back the descriptor already open, not walk again"
        );
        assert_eq!(cache.resident(), 1);
        let _ = fs::remove_dir_all(dir);
    }

    /// The point of the whole design: a directory symlink pointing outside the
    /// export cannot be walked through, because every component is opened with
    /// O_NOFOLLOW. This is the case the removed containment check tried to
    /// catch by resolving a path, and got wrong for ordinary guest paths.
    #[test]
    fn dircache_cannot_walk_through_a_symlink_out_of_the_export() {
        let (dir, mut cache) = dircache_fixture();
        let outside = outside_path("escape-target");
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("out")).unwrap();

        // ENOTDIR rather than ELOOP, which is worth knowing: O_NOFOLLOW means
        // the open lands on the symlink itself, and O_DIRECTORY then refuses
        // it because a symlink is not a directory. The refusal is what this
        // test is for; the errno is recorded so a later change to it is a
        // deliberate one rather than a surprise.
        let err = cache.dir_fd(3, Path::new("out")).unwrap_err();
        assert_eq!(err, ENOTDIR, "a symlinked component must refuse the walk");
        assert_eq!(cache.resident(), 0, "nothing may be admitted on failure");

        // And the same holds for a component in the middle of a path.
        fs::create_dir_all(outside.join("deeper")).unwrap();
        let err = cache.dir_fd(4, Path::new("out/deeper")).unwrap_err();
        assert_eq!(err, ENOTDIR);

        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(dir);
    }

    /// `..` is the component that would climb out of the export, so the walk
    /// refuses it rather than trusting whoever built the path.
    #[test]
    fn dircache_refuses_a_parent_component() {
        let (dir, mut cache) = dircache_fixture();
        assert_eq!(
            cache.dir_fd(5, Path::new("usr/../etc")).unwrap_err(),
            EINVAL
        );
        assert_eq!(cache.dir_fd(6, Path::new("/etc")).unwrap_err(), EINVAL);
        assert_eq!(cache.resident(), 0);
        let _ = fs::remove_dir_all(dir);
    }

    /// The bound is the reason this cannot spend the descriptor budget the
    /// device already shares with open guest handles (#34).
    #[test]
    fn dircache_holds_no_more_than_its_limit() {
        let dir = outside_path("dircache-bound");
        for i in 0..8 {
            fs::create_dir_all(dir.join(format!("d{i}"))).unwrap();
        }
        let dir = fs::canonicalize(&dir).unwrap();
        let mut cache = DirCache::new(&dir, 3).unwrap();
        for i in 0..8u64 {
            cache.dir_fd(10 + i, Path::new(&format!("d{i}"))).unwrap();
            assert!(
                cache.resident() <= 3,
                "cache grew past its limit at {i}: {}",
                cache.resident()
            );
        }
        assert_eq!(cache.resident(), 3);
        let _ = fs::remove_dir_all(dir);
    }

    /// Eviction is least-recently-used, so a directory kept warm survives a
    /// sweep through colder ones.
    #[test]
    fn dircache_evicts_the_least_recently_used() {
        let dir = outside_path("dircache-lru");
        for name in ["hot", "a", "b", "c"] {
            fs::create_dir_all(dir.join(name)).unwrap();
        }
        let dir = fs::canonicalize(&dir).unwrap();
        let mut cache = DirCache::new(&dir, 2).unwrap();

        let hot = cache.dir_fd(20, Path::new("hot")).unwrap().as_raw_fd();
        for (node, name) in [(21u64, "a"), (22, "b"), (23, "c")] {
            cache.dir_fd(node, Path::new(name)).unwrap();
            // Keep `hot` warm across each admission.
            let again = cache.dir_fd(20, Path::new("hot")).unwrap().as_raw_fd();
            assert_eq!(again, hot, "the warm entry was evicted after {name}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    /// FORGET and the invalidating mutations need a way to drop a descriptor.
    #[test]
    fn dircache_forget_releases_the_descriptor() {
        let (dir, mut cache) = dircache_fixture();
        cache.dir_fd(7, Path::new("etc")).unwrap();
        assert_eq!(cache.resident(), 1);
        cache.forget(7);
        assert_eq!(cache.resident(), 0);
        cache.forget(7); // idempotent
        assert_eq!(cache.resident(), 0);
        let _ = fs::remove_dir_all(dir);
    }

    /// Hard linking a symlink must link the symlink, never the file it names.
    /// macOS `link(2)` follows symlinks, so a guest that pointed a symlink at
    /// a host file and then hard linked it got a real directory entry inside
    /// the export sharing that file's inode.
    #[test]
    fn hard_linking_a_symlink_does_not_capture_its_target() {
        let (dir, mut dev) = fixture_with_access(true);
        let outside = outside_path("file");
        fs::write(&outside, b"host only\n").unwrap();

        let mut symlink = Vec::new();
        symlink.extend_from_slice(b"escape\0");
        symlink.extend_from_slice(outside.as_os_str().as_bytes());
        symlink.push(0);
        let out = dev.handle_fuse(&request(SYMLINK, FUSE_ROOT_ID, &symlink), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        let escape = get_u64(&out, OUT_HEADER_LEN).unwrap();

        let mut link = Vec::new();
        put_u64(&mut link, escape);
        link.extend_from_slice(b"captured\0");
        let out = dev.handle_fuse(&request(LINK, FUSE_ROOT_ID, &link), 4096);

        assert_eq!(get_u32(&out, 4), Some(0));

        // The link is to the symlink inode, so the new name is itself a
        // symlink and shares nothing with the file outside the export.
        let captured = fs::symlink_metadata(dir.join("captured")).unwrap();
        assert!(
            captured.file_type().is_symlink(),
            "hard link resolved the symlink instead of linking it"
        );
        assert_ne!(
            captured.ino(),
            fs::metadata(&outside).unwrap().ino(),
            "the file outside the export is reachable from inside it"
        );
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(dir);
    }

    /// A mutation whose parent resolves through a symlink must not land
    /// outside the export. `child_path` follows the parent on purpose, so the
    /// joined path can sit under the root as a string while the syscall
    /// resolves somewhere else entirely.
    ///
    /// Ignored rather than deleted, because the property is still one we want.
    /// The device-side check that satisfied it resolved the parent host-side,
    /// which refused ordinary guest paths as well -- an absolute symlink in a
    /// container rootfs names the guest's filesystem, not ours -- and broke
    /// booting a stock image. Containment is the Seatbelt profile's alone
    /// again, as it was before that check, and the sandbox does refuse this
    /// escape at the syscall. What is missing is the device's own answer,
    /// which returns with fd-relative resolution (NOFireAI/hvi-vmm#30). Turn
    /// this back on with that change; it is the test for it.
    #[test]
    #[ignore = "device-side containment returns with fd-relative resolution (#30)"]
    fn a_symlinked_directory_cannot_take_a_mutation_outside_the_export() {
        let (dir, mut dev) = fixture_with_access(true);
        let outside = outside_path("dir");
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("out")).unwrap();

        let node = lookup_node(&mut dev, FUSE_ROOT_ID, b"out");
        let mut mkdir = vec![0u8; 8];
        mkdir[0..4].copy_from_slice(&0o755u32.to_le_bytes());
        mkdir.extend_from_slice(b"planted\0");
        dev.handle_fuse(&request(MKDIR, node, &mkdir), 4096);

        assert!(
            !outside.join("planted").exists(),
            "mutation escaped the export through a symlinked directory"
        );
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn hard_links_share_one_fuse_node() {
        let (dir, mut dev) = fixture();
        fs::hard_link(dir.join("etc/issue"), dir.join("etc/banner")).unwrap();
        let lookup = dev.handle_fuse(&request(LOOKUP, FUSE_ROOT_ID, b"etc\0"), 4096);
        let etc_node = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let issue = dev.handle_fuse(&request(LOOKUP, etc_node, b"issue\0"), 4096);
        let banner = dev.handle_fuse(&request(LOOKUP, etc_node, b"banner\0"), 4096);
        assert_eq!(
            get_u64(&issue, OUT_HEADER_LEN),
            get_u64(&banner, OUT_HEADER_LEN)
        );
        let _ = fs::remove_dir_all(dir);
    }

    // Renamed from `writable_exports_disable_host_incoherent_caches`: Task 1
    // made `Auto` (the default) hand out non-zero timeouts and
    // FOPEN_KEEP_CACHE on writable shares, which is the whole point of that
    // task. `None` is the policy that keeps the old fully-incoherent
    // behaviour, so that is what this test now exercises.
    #[test]
    fn writable_none_cache_disables_host_incoherent_caches() {
        let (dir, mut dev) = fixture_with_cache(true, CachePolicy::None);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        // fuse_entry_out.entry_valid and attr_valid are both zero.
        let lookup = dev.handle_fuse(&request(LOOKUP, etc, b"issue\0"), 4096);
        assert_eq!(get_u64(&lookup, OUT_HEADER_LEN + 16), Some(0));
        assert_eq!(get_u64(&lookup, OUT_HEADER_LEN + 24), Some(0));
        let issue = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let mut open = vec![0u8; 8];
        open[0..4].copy_from_slice(&LINUX_O_RDWR.to_le_bytes());
        let opened = dev.handle_fuse(&request(OPEN, issue, &open), 4096);
        // No FOPEN_KEEP_CACHE on a writable share.
        assert_eq!(get_u32(&opened, OUT_HEADER_LEN + 8), Some(0));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn setattr_updates_mode_times_and_reports_squashed_owner() {
        let (dir, mut dev) = fixture_with_access(true);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let issue = lookup_node(&mut dev, etc, b"issue");
        let mut input = vec![0u8; 88];
        input[0..4].copy_from_slice(&(FATTR_MODE | FATTR_ATIME | FATTR_MTIME).to_le_bytes());
        input[32..40].copy_from_slice(&1_700_000_001u64.to_le_bytes());
        input[40..48].copy_from_slice(&1_700_000_002u64.to_le_bytes());
        input[56..60].copy_from_slice(&123u32.to_le_bytes());
        input[60..64].copy_from_slice(&456u32.to_le_bytes());
        input[68..72].copy_from_slice(&0o640u32.to_le_bytes());
        let out = dev.handle_fuse(&request(SETATTR, issue, &input), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        let meta = fs::metadata(dir.join("etc/issue")).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o640);
        assert_eq!(meta.atime(), 1_700_000_001);
        assert_eq!(meta.mtime(), 1_700_000_002);
        assert_eq!(get_u32(&out, OUT_HEADER_LEN + 16 + 68), Some(0));
        assert_eq!(get_u32(&out, OUT_HEADER_LEN + 16 + 72), Some(0));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn restrictive_modes_and_linux_owners_persist_without_locking_out_host() {
        let (dir, mut dev) = fixture_with_access(true);
        let mut mkdir = vec![0u8; 8];
        mkdir[0..4].copy_from_slice(&0u32.to_le_bytes());
        mkdir.extend_from_slice(b"locked\0");
        let out = dev.handle_fuse(&request_as(MKDIR, FUSE_ROOT_ID, &mkdir, 42, 43), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(get_u32(&out, OUT_HEADER_LEN + 40 + 60).unwrap() & 0o7777, 0);
        assert_eq!(get_u32(&out, OUT_HEADER_LEN + 40 + 68), Some(42));
        assert_eq!(get_u32(&out, OUT_HEADER_LEN + 40 + 72), Some(43));

        let host_meta = fs::metadata(dir.join("locked")).unwrap();
        assert_eq!(host_meta.mode() & 0o700, 0o700);
        fs::write(dir.join("locked/host-still-has-access"), b"ok").unwrap();

        let mut reopened = VirtioFs::new(
            fs::canonicalize(&dir).unwrap(),
            "rootfs",
            true,
            CachePolicy::Auto,
        )
        .unwrap();
        let lookup = reopened.handle_fuse(&request(LOOKUP, FUSE_ROOT_ID, b"locked\0"), 4096);
        assert_eq!(
            get_u32(&lookup, OUT_HEADER_LEN + 40 + 60).unwrap() & 0o7777,
            0
        );
        assert_eq!(get_u32(&lookup, OUT_HEADER_LEN + 40 + 68), Some(42));
        assert_eq!(get_u32(&lookup, OUT_HEADER_LEN + 40 + 72), Some(43));

        let locked = get_u64(&lookup, OUT_HEADER_LEN).unwrap();
        let mut list = vec![0u8; 8];
        list[0..4].copy_from_slice(&4096u32.to_le_bytes());
        let listed = reopened.handle_fuse(&request(LISTXATTR, locked, &list), 8192);
        assert!(!listed[OUT_HEADER_LEN..]
            .windows(HVI_XATTR_PREFIX.len())
            .any(|window| window == HVI_XATTR_PREFIX));
        let private = reopened.handle_fuse(
            &request(
                GETXATTR,
                locked,
                b"\x04\0\0\0\0\0\0\0com.nubificus.hvi.mode\0",
            ),
            4096,
        );
        assert_eq!(
            i32::from_le_bytes(private[4..8].try_into().unwrap()),
            -ENODATA
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn extended_attributes_round_trip() {
        let (dir, mut dev) = fixture_with_access(true);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let issue = lookup_node(&mut dev, etc, b"issue");
        let mut set = vec![0u8; 16];
        set[0..4].copy_from_slice(&5u32.to_le_bytes());
        set.extend_from_slice(b"user.hvi\0value");
        let out = dev.handle_fuse(&request(SETXATTR, issue, &set), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));

        let mut get = vec![0u8; 8];
        get[0..4].copy_from_slice(&16u32.to_le_bytes());
        get.extend_from_slice(b"user.hvi\0");
        let out = dev.handle_fuse(&request(GETXATTR, issue, &get), 4096);
        assert_eq!(&out[OUT_HEADER_LEN..], b"value");

        let mut list = vec![0u8; 8];
        list[0..4].copy_from_slice(&4096u32.to_le_bytes());
        let out = dev.handle_fuse(&request(LISTXATTR, issue, &list), 8192);
        assert!(out[OUT_HEADER_LEN..]
            .split(|byte| *byte == 0)
            .any(|name| name == b"user.hvi"));

        let out = dev.handle_fuse(&request(REMOVEXATTR, issue, b"user.hvi\0"), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        let out = dev.handle_fuse(&request(GETXATTR, issue, &get), 4096);
        assert_eq!(i32::from_le_bytes(out[4..8].try_into().unwrap()), -ENODATA);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn allocation_seek_and_copy_work_on_host_files() {
        let (dir, mut dev) = fixture_with_access(true);
        fs::write(dir.join("source"), b"abcdefgh").unwrap();
        fs::write(dir.join("target"), b"--------").unwrap();
        let source = lookup_node(&mut dev, FUSE_ROOT_ID, b"source");
        let target = lookup_node(&mut dev, FUSE_ROOT_ID, b"target");
        let source_fh = open_rw(&mut dev, source);
        let target_fh = open_rw(&mut dev, target);

        let mut zero = vec![0u8; 32];
        zero[0..8].copy_from_slice(&source_fh.to_le_bytes());
        zero[8..16].copy_from_slice(&2u64.to_le_bytes());
        zero[16..24].copy_from_slice(&3u64.to_le_bytes());
        zero[24..28].copy_from_slice(&(FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE).to_le_bytes());
        let out = dev.handle_fuse(&request(FALLOCATE, source, &zero), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(fs::read(dir.join("source")).unwrap(), b"ab\0\0\0fgh");

        let mut copy = vec![0u8; 56];
        copy[0..8].copy_from_slice(&source_fh.to_le_bytes());
        copy[8..16].copy_from_slice(&5u64.to_le_bytes());
        copy[16..24].copy_from_slice(&target.to_le_bytes());
        copy[24..32].copy_from_slice(&target_fh.to_le_bytes());
        copy[32..40].copy_from_slice(&1u64.to_le_bytes());
        copy[40..48].copy_from_slice(&3u64.to_le_bytes());
        let out = dev.handle_fuse(&request(COPY_FILE_RANGE, source, &copy), 4096);
        assert_eq!(get_u32(&out, OUT_HEADER_LEN), Some(3));
        assert_eq!(fs::read(dir.join("target")).unwrap(), b"-fgh----");

        let mut seek = vec![0u8; 24];
        seek[0..8].copy_from_slice(&target_fh.to_le_bytes());
        seek[16..20].copy_from_slice(&2u32.to_le_bytes());
        let out = dev.handle_fuse(&request(LSEEK, target, &seek), 4096);
        assert_eq!(get_u64(&out, OUT_HEADER_LEN), Some(8));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn readdirplus_uses_a_real_directory_handle() {
        let (dir, mut dev) = fixture_with_access(true);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let opened = dev.handle_fuse(&request(OPENDIR, etc, &[0; 8]), 4096);
        let fh = get_u64(&opened, OUT_HEADER_LEN).unwrap();
        let mut read = vec![0u8; 40];
        read[0..8].copy_from_slice(&fh.to_le_bytes());
        read[16..20].copy_from_slice(&4096u32.to_le_bytes());
        let out = dev.handle_fuse(&request(READDIRPLUS, etc, &read), 8192);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert!(out.len() > OUT_HEADER_LEN + 128 + 24);
        assert_eq!(get_u64(&out, OUT_HEADER_LEN), Some(etc));
        let mut release = vec![0u8; 24];
        release[0..8].copy_from_slice(&fh.to_le_bytes());
        let out = dev.handle_fuse(&request(RELEASEDIR, etc, &release), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        let _ = fs::remove_dir_all(dir);
    }

    /// Parses a READDIR(PLUS) payload (the reply past `OUT_HEADER_LEN`) into
    /// (reported ino/node, next offset, d_type, name, plus-mode mode bits).
    fn parse_readdir_entries(payload: &[u8], plus: bool) -> Vec<(u64, u64, u32, String, u32)> {
        let mut entries = Vec::new();
        let mut pos = 0;
        while pos < payload.len() {
            let (node, mode) = if plus {
                let node = get_u64(payload, pos).unwrap();
                let mode = get_u32(payload, pos + 100).unwrap();
                pos += 128;
                (node, mode)
            } else {
                (0, 0)
            };
            let ino = get_u64(payload, pos).unwrap();
            let off = get_u64(payload, pos + 8).unwrap();
            let namelen = get_u32(payload, pos + 16).unwrap() as usize;
            let dtype = get_u32(payload, pos + 20).unwrap();
            let name = String::from_utf8(payload[pos + 24..pos + 24 + namelen].to_vec()).unwrap();
            pos += align8(24 + namelen);
            entries.push((if plus { node } else { ino }, off, dtype, name, mode));
        }
        entries
    }

    fn host_listing(dir: &Path) -> Vec<String> {
        let mut names = vec![".".to_string(), "..".to_string()];
        let mut host: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        host.sort();
        names.extend(host);
        names
    }

    #[test]
    fn readdir_matches_host_directory_names_types_and_order() {
        let (dir, mut dev) = fixture_with_access(true);
        fs::create_dir(dir.join("etc/sub")).unwrap();
        std::os::unix::fs::symlink("issue", dir.join("etc/issue-link")).unwrap();
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let opened = dev.handle_fuse(&request(OPENDIR, etc, &[0; 8]), 4096);
        let fh = get_u64(&opened, OUT_HEADER_LEN).unwrap();
        let mut read = vec![0u8; 40];
        read[0..8].copy_from_slice(&fh.to_le_bytes());
        read[16..20].copy_from_slice(&65536u32.to_le_bytes());
        let out = dev.handle_fuse(&request(READDIR, etc, &read), 65536 + OUT_HEADER_LEN);
        let entries = parse_readdir_entries(&out[OUT_HEADER_LEN..], false);
        let names: Vec<String> = entries.iter().map(|(_, _, _, n, _)| n.clone()).collect();
        assert_eq!(names, host_listing(&dir.join("etc")));
        let type_of = |n: &str| entries.iter().find(|e| e.3 == n).unwrap().2;
        assert_eq!(type_of("sub"), 4, "directory");
        assert_eq!(type_of("issue"), 8, "regular file");
        assert_eq!(type_of("issue-link"), 10, "symlink");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn paginated_readdir_yields_each_entry_exactly_once() {
        let (dir, mut dev) = fixture_with_access(true);
        for i in 0..40 {
            fs::write(dir.join("etc").join(format!("f{i:02}")), b"x").unwrap();
        }
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let opened = dev.handle_fuse(&request(OPENDIR, etc, &[0; 8]), 4096);
        let fh = get_u64(&opened, OUT_HEADER_LEN).unwrap();

        let mut seen: Vec<String> = Vec::new();
        let mut offset = 0u64;
        let mut rounds = 0;
        loop {
            let mut read = vec![0u8; 40];
            read[0..8].copy_from_slice(&fh.to_le_bytes());
            read[8..16].copy_from_slice(&offset.to_le_bytes());
            // Small enough to force several rounds over 40+2 entries.
            read[16..20].copy_from_slice(&256u32.to_le_bytes());
            let out = dev.handle_fuse(&request(READDIR, etc, &read), 256 + OUT_HEADER_LEN);
            let entries = parse_readdir_entries(&out[OUT_HEADER_LEN..], false);
            if entries.is_empty() {
                break;
            }
            for (_, off, _, name, _) in &entries {
                seen.push(name.clone());
                offset = *off;
            }
            rounds += 1;
            assert!(rounds < 100, "runaway pagination");
        }
        assert!(rounds > 1, "the small max_out should force multiple rounds");
        assert_eq!(seen, host_listing(&dir.join("etc")));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn readdirplus_reports_correct_attributes_for_each_type() {
        let (dir, mut dev) = fixture_with_access(true);
        fs::create_dir(dir.join("etc/sub")).unwrap();
        std::os::unix::fs::symlink("issue", dir.join("etc/issue-link")).unwrap();
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let opened = dev.handle_fuse(&request(OPENDIR, etc, &[0; 8]), 4096);
        let fh = get_u64(&opened, OUT_HEADER_LEN).unwrap();
        let mut read = vec![0u8; 40];
        read[0..8].copy_from_slice(&fh.to_le_bytes());
        read[16..20].copy_from_slice(&65536u32.to_le_bytes());
        let out = dev.handle_fuse(&request(READDIRPLUS, etc, &read), 65536 + OUT_HEADER_LEN);
        let entries = parse_readdir_entries(&out[OUT_HEADER_LEN..], true);
        let find = |n: &str| entries.iter().find(|e| e.3 == n).unwrap().clone();

        let (_, _, dtype, _, mode) = find("sub");
        assert_eq!(dtype, 4);
        assert_eq!(mode & S_IFMT, libc::S_IFDIR as u32);

        let (_, _, dtype, _, mode) = find("issue");
        assert_eq!(dtype, 8);
        assert_eq!(mode & S_IFMT, S_IFREG);

        let (_, _, dtype, _, mode) = find("issue-link");
        assert_eq!(dtype, 10);
        assert_eq!(mode & S_IFMT, libc::S_IFLNK as u32);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn hard_link_removal_leaves_the_remaining_alias_addressable() {
        let (dir, mut dev) = fixture_with_access(true);
        fs::write(dir.join("primary"), b"data").unwrap();
        fs::hard_link(dir.join("primary"), dir.join("secondary")).unwrap();
        let primary = lookup_node(&mut dev, FUSE_ROOT_ID, b"primary");
        let secondary = lookup_node(&mut dev, FUSE_ROOT_ID, b"secondary");
        assert_eq!(primary, secondary);

        let out = dev.handle_fuse(&request(UNLINK, FUSE_ROOT_ID, b"primary\0"), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));

        // Exercises the multi-alias validating scan in node_path: the
        // single-alias fast path (2a) must not be taken while `primary` is
        // still a (now stale) entry in this node's path list.
        assert_eq!(
            dev.node_path(secondary).unwrap(),
            dev.root().join("secondary")
        );
        let getattr = dev.handle_fuse(&request(GETATTR, secondary, &[]), 4096);
        assert_eq!(get_u32(&getattr, 4), Some(0));
        assert_eq!(get_u64(&getattr, OUT_HEADER_LEN + 24), Some(4)); // size
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rename_exchange_and_hardlink_aliases_remain_addressable() {
        let (dir, mut dev) = fixture_with_access(true);
        fs::write(dir.join("left"), b"left").unwrap();
        fs::write(dir.join("right"), b"right").unwrap();
        let left = lookup_node(&mut dev, FUSE_ROOT_ID, b"left");
        let right = lookup_node(&mut dev, FUSE_ROOT_ID, b"right");
        let mut rename = Vec::new();
        put_u64(&mut rename, FUSE_ROOT_ID);
        put_u32(&mut rename, RENAME_EXCHANGE);
        put_u32(&mut rename, 0);
        rename.extend_from_slice(b"left\0right\0");
        let out = dev.handle_fuse(&request(RENAME2, FUSE_ROOT_ID, &rename), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(fs::read(dir.join("left")).unwrap(), b"right");
        assert_eq!(fs::read(dir.join("right")).unwrap(), b"left");
        assert_eq!(dev.node_path(left).unwrap(), dev.root().join("right"));
        assert_eq!(dev.node_path(right).unwrap(), dev.root().join("left"));

        fs::hard_link(dir.join("right"), dir.join("alias")).unwrap();
        assert_eq!(lookup_node(&mut dev, FUSE_ROOT_ID, b"alias"), left);
        let out = dev.handle_fuse(&request(UNLINK, FUSE_ROOT_ID, b"right\0"), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(dev.node_path(left).unwrap(), dev.root().join("alias"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn statx_and_statfs_return_real_data() {
        let (dir, mut dev) = fixture_with_access(true);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let issue = lookup_node(&mut dev, etc, b"issue");
        let out = dev.handle_fuse(&request(STATX, issue, &[0; 24]), 4096);
        assert_eq!(out.len(), OUT_HEADER_LEN + 288);
        assert_eq!(get_u64(&out, OUT_HEADER_LEN + 32 + 32), Some(issue));
        let out = dev.handle_fuse(&request(STATFS, FUSE_ROOT_ID, &[]), 4096);
        assert_eq!(out.len(), OUT_HEADER_LEN + 80);
        assert!(get_u64(&out, OUT_HEADER_LEN).unwrap() > 0);
        assert!(get_u32(&out, OUT_HEADER_LEN + 40).unwrap() > 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn locks_conflict_between_open_file_descriptions() {
        let (dir, mut dev) = fixture_with_access(true);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let issue = lookup_node(&mut dev, etc, b"issue");
        let first = open_rw(&mut dev, issue);
        let second = open_rw(&mut dev, issue);
        let mut lock = vec![0u8; 48];
        lock[0..8].copy_from_slice(&first.to_le_bytes());
        lock[24..32].copy_from_slice(&(i64::MAX as u64).to_le_bytes());
        lock[32..36].copy_from_slice(&LINUX_F_WRLCK.to_le_bytes());

        let mut probe = lock.clone();
        probe[0..8].copy_from_slice(&second.to_le_bytes());
        let out = dev.handle_fuse(&request(GETLK, issue, &probe), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(get_u32(&out, OUT_HEADER_LEN + 16), Some(LINUX_F_UNLCK));

        let out = dev.handle_fuse(&request(SETLK, issue, &lock), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));

        let out = dev.handle_fuse(&request(GETLK, issue, &probe), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert_eq!(get_u32(&out, OUT_HEADER_LEN + 16), Some(LINUX_F_WRLCK));

        lock[0..8].copy_from_slice(&second.to_le_bytes());
        let out = dev.handle_fuse(&request(SETLK, issue, &lock), 4096);
        let errno = i32::from_le_bytes(out[4..8].try_into().unwrap());
        assert!(errno == -EAGAIN || errno == -EACCES);

        lock[0..8].copy_from_slice(&first.to_le_bytes());
        lock[32..36].copy_from_slice(&LINUX_F_UNLCK.to_le_bytes());
        let out = dev.handle_fuse(&request(SETLK, issue, &lock), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        let _ = fs::remove_dir_all(dir);
    }

    /// A lock file is opened `O_CREAT|O_RDONLY`: the caller wants an inode to
    /// lock, not the bytes. `flock(1)`, iptables' `xtables.lock` and Go's
    /// `gofrs/flock` all do exactly this. Routing it through `OpenOptions`
    /// rejected the combination before any syscall, and the tools reported it
    /// as `cannot open lock file: Invalid argument` -- which reads as absent
    /// lock support but is nothing of the kind, because the lock is never
    /// reached.
    #[test]
    fn a_read_only_create_can_take_a_lock() {
        let (dir, mut dev) = fixture_with_access(true);
        let mut create = vec![0u8; 16];
        // Access mode O_RDONLY, which is what those callers send.
        create[0..4].copy_from_slice(&0u32.to_le_bytes());
        create[4..8].copy_from_slice(&(S_IFREG | 0o600).to_le_bytes());
        create.extend_from_slice(b"xtables.lock\0");
        let out = dev.handle_fuse(&request(CREATE, FUSE_ROOT_ID, &create), 4096);
        assert_eq!(
            get_u32(&out, 4),
            Some(0),
            "O_CREAT|O_RDONLY has to reach the kernel"
        );
        let node = get_u64(&out, OUT_HEADER_LEN).unwrap();
        let fh = get_u64(&out, OUT_HEADER_LEN + 128).unwrap();
        assert!(dir.join("xtables.lock").exists());

        // flock(2) is indifferent to the access mode, which is the reason
        // lock files can be opened read-only in the first place.
        let mut lock = vec![0u8; 48];
        lock[0..8].copy_from_slice(&fh.to_le_bytes());
        lock[24..32].copy_from_slice(&(i64::MAX as u64).to_le_bytes());
        lock[32..36].copy_from_slice(&LINUX_F_WRLCK.to_le_bytes());
        lock[40..44].copy_from_slice(&FUSE_LK_FLOCK.to_le_bytes());
        let out = dev.handle_fuse(&request(SETLK, node, &lock), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        let _ = fs::remove_dir_all(dir);
    }

    /// `OpenOptions` set O_CLOEXEC for us. Opening by hand makes it ours to
    /// remember, so it needs a test that fails if anyone forgets: a host
    /// descriptor opened on the guest's behalf must not survive into a child.
    #[test]
    fn guest_descriptors_are_close_on_exec() {
        let (dir, _dev) = fixture_with_access(true);
        let file = open_host_file(&dir.join("cloexec-probe"), 0, true, 0o600).unwrap();
        // SAFETY: querying descriptor flags on a descriptor we own.
        let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert!(descriptor_flags >= 0);
        assert_ne!(
            descriptor_flags & libc::FD_CLOEXEC,
            0,
            "a guest descriptor would leak into any process hvi spawns"
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// O_NOFOLLOW was explicit before this change and stays explicit after it.
    #[test]
    fn the_final_component_is_never_a_followed_symlink() {
        let (dir, _dev) = fixture_with_access(true);
        fs::write(dir.join("target"), b"host-side").unwrap();
        std::os::unix::fs::symlink("target", dir.join("link")).unwrap();
        let err = open_host_file(&dir.join("link"), 0, false, 0).unwrap_err();
        assert_eq!(io_errno(err), ELOOP);
        let _ = fs::remove_dir_all(dir);
    }

    /// `CString::new` is what refuses this now; before, `OpenOptions` did. An
    /// interior NUL must not reach open(2), where it would silently name a
    /// shorter path than the one asked for.
    #[test]
    fn a_path_with_an_interior_nul_is_refused() {
        let (dir, _dev) = fixture_with_access(true);
        let mut raw = dir.join("lock").into_os_string().into_vec();
        raw.extend_from_slice(b"\0.ignored");
        let path = PathBuf::from(OsString::from_vec(raw));
        let err = open_host_file(&path, 0, true, 0o600).unwrap_err();
        assert_eq!(io_errno(err), EINVAL);
        assert!(
            !dir.join("lock").exists(),
            "the truncated path must not have been created"
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// Linux reserves the fourth O_ACCMODE value; it was refused before the
    /// hand translation and is refused by it.
    #[test]
    fn a_reserved_access_mode_is_refused() {
        let (dir, _dev) = fixture_with_access(true);
        let err = open_host_file(&dir.join("bad"), LINUX_O_ACCMODE, true, 0o600).unwrap_err();
        assert_eq!(io_errno(err), EINVAL);
        assert!(!dir.join("bad").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tmpfile_can_be_linked_before_release() {
        let (dir, mut dev) = fixture_with_access(true);
        let mut input = vec![0u8; 16];
        input[0..4].copy_from_slice(&LINUX_O_RDWR.to_le_bytes());
        input[4..8].copy_from_slice(&(S_IFREG | 0o600).to_le_bytes());
        let out = dev.handle_fuse(&request(TMPFILE, FUSE_ROOT_ID, &input), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        let node = get_u64(&out, OUT_HEADER_LEN).unwrap();
        let fh = get_u64(&out, OUT_HEADER_LEN + 128).unwrap();
        let temporary = dev
            .handles
            .get(&fh)
            .unwrap()
            .temporary_path
            .clone()
            .unwrap();

        let mut link = Vec::new();
        put_u64(&mut link, node);
        link.extend_from_slice(b"linked-temp\0");
        let out = dev.handle_fuse(&request(LINK, FUSE_ROOT_ID, &link), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));

        let mut release = vec![0u8; 24];
        release[0..8].copy_from_slice(&fh.to_le_bytes());
        let out = dev.handle_fuse(&request(RELEASE, node, &release), 4096);
        assert_eq!(get_u32(&out, 4), Some(0));
        assert!(!temporary.exists());
        assert!(dir.join("linked-temp").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn forget_releases_inode_state_and_a_new_lookup_gets_a_fresh_node() {
        let (dir, mut dev) = fixture_with_access(true);
        let etc = lookup_node(&mut dev, FUSE_ROOT_ID, b"etc");
        let issue = lookup_node(&mut dev, etc, b"issue");
        let mut forget = Vec::new();
        put_u64(&mut forget, 1);
        assert!(dev
            .handle_fuse(&request(FORGET, issue, &forget), 4096)
            .is_empty());
        assert!(!dev.nodes.contains_key(&issue));
        let replacement = lookup_node(&mut dev, etc, b"issue");
        assert_ne!(replacement, issue);
        let _ = fs::remove_dir_all(dir);
    }

    // --- Task 3: the direct-path tests below drive a real virtqueue over a
    // `GuestRam` backed by a plain `Vec<u8>`, the same pattern virtio_net.rs
    // uses. Everything above this point exercises `handle_fuse` with no
    // guest memory at all, which is the buffered path; these instead go
    // through `mmio`/`process_queue`/`handle_chain` so the READ/WRITE direct
    // path in `handle_fuse_desc` is what actually runs.

    const REQ_QUEUE: u32 = 0;

    /// Programs a queue the way the Linux virtio-mmio driver does: select,
    /// size, the three ring addresses, then READY last.
    fn program_queue(
        dev: &mut VirtioFs,
        mem: &GuestRam,
        size: u32,
        desc: u64,
        avail: u64,
        used: u64,
    ) {
        dev.mmio(mem, reg::QUEUE_SEL, true, u64::from(REQ_QUEUE));
        dev.mmio(mem, reg::QUEUE_NUM, true, u64::from(size));
        dev.mmio(mem, reg::QUEUE_DESC_LOW, true, desc & 0xffff_ffff);
        dev.mmio(mem, reg::QUEUE_DESC_HIGH, true, desc >> 32);
        dev.mmio(mem, reg::QUEUE_DRIVER_LOW, true, avail & 0xffff_ffff);
        dev.mmio(mem, reg::QUEUE_DRIVER_HIGH, true, avail >> 32);
        dev.mmio(mem, reg::QUEUE_DEVICE_LOW, true, used & 0xffff_ffff);
        dev.mmio(mem, reg::QUEUE_DEVICE_HIGH, true, used >> 32);
        dev.mmio(mem, reg::QUEUE_READY, true, 1);
    }

    fn write_desc(
        mem: &GuestRam,
        table: u64,
        idx: u16,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let da = table + u64::from(idx) * 16;
        mem.write_u64(da, addr).unwrap();
        mem.write_u32(da + 8, len).unwrap();
        mem.write_u16(da + 12, flags).unwrap();
        mem.write_u16(da + 14, next).unwrap();
    }

    /// Publishes `head` as the one available buffer, notifies the device,
    /// then drains it -- standing in for the worker thread that does the
    /// draining in production (Stage A moved that off `mmio` itself; see
    /// `queue_notify_only_records_the_index_and_does_no_io` below for a test
    /// of `mmio`'s half of that split in isolation).
    fn notify_head(dev: &mut VirtioFs, mem: &GuestRam, avail: u64, head: u16) {
        mem.write_u16(avail + 2, 1).unwrap(); // avail.idx
        mem.write_u16(avail + 4, head).unwrap(); // avail.ring[0]
        dev.mmio(mem, reg::QUEUE_NOTIFY, true, u64::from(REQ_QUEUE));
        dev.drain_notified(mem);
    }

    /// The `len` the device reported for the one chain `notify_head` submits.
    fn used_len(mem: &GuestRam, used: u64) -> u32 {
        mem.read_u32(used + 4 + 4).unwrap()
    }

    fn fuse_in_header(len: u32, opcode: u32, unique: u64, nodeid: u64) -> Vec<u8> {
        let mut h = vec![0u8; IN_HEADER_LEN];
        h[0..4].copy_from_slice(&len.to_le_bytes());
        h[4..8].copy_from_slice(&opcode.to_le_bytes());
        h[8..16].copy_from_slice(&unique.to_le_bytes());
        h[16..24].copy_from_slice(&nodeid.to_le_bytes());
        h
    }

    #[test]
    fn direct_read_spans_two_output_descriptors() {
        let (dir, mut dev) = fixture_with_access(true);
        let content: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        fs::write(dir.join("big"), &content).unwrap();
        let node = lookup_node(&mut dev, FUSE_ROOT_ID, b"big");
        let fh = open_rw(&mut dev, node);

        let mut backing = vec![0u8; 0x10000];
        let base = 0x4000_0000u64;
        let mem = GuestRam::new(backing.as_mut_ptr(), base, backing.len());
        let (desc, avail, used, in_buf, out1, out2) = (
            base,
            base + 0x100,
            base + 0x200,
            base + 0x1000,
            base + 0x2000,
            base + 0x3000,
        );
        program_queue(&mut dev, &mem, 8, desc, avail, used);

        let mut req = fuse_in_header(80, READ, 0xabcd, node);
        let mut args = vec![0u8; 40];
        args[0..8].copy_from_slice(&fh.to_le_bytes());
        args[16..20].copy_from_slice(&1000u32.to_le_bytes());
        req.extend_from_slice(&args);
        mem.write(in_buf, &req).unwrap();

        write_desc(&mem, desc, 0, in_buf, req.len() as u32, DESC_NEXT, 1);
        // Header (16) + the first 400 payload bytes in one descriptor, the
        // remaining 600 payload bytes in a second -- the payload spans both.
        write_desc(&mem, desc, 1, out1, 416, DESC_WRITE | DESC_NEXT, 2);
        write_desc(&mem, desc, 2, out2, 600, DESC_WRITE, 0);
        notify_head(&mut dev, &mem, avail, 0);

        let mut got = vec![0u8; 1000];
        mem.read(out1 + OUT_HEADER_LEN as u64, &mut got[0..400])
            .unwrap();
        mem.read(out2, &mut got[400..1000]).unwrap();
        assert_eq!(got, content);
        assert_eq!(mem.read_u32(out1).unwrap(), (OUT_HEADER_LEN + 1000) as u32);
        assert_eq!(mem.read_u64(out1 + 8).unwrap(), 0xabcd);
        assert_eq!(used_len(&mem, used), (OUT_HEADER_LEN + 1000) as u32);
        // The buffered fallback would produce byte-identical output, so assert
        // the fast path was the one that ran.
        assert_eq!(
            dev.zero_copy_counts().0,
            1,
            "READ did not take the zero-copy path"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn direct_read_reports_true_length_on_short_read_at_eof() {
        let (dir, mut dev) = fixture_with_access(true);
        fs::write(dir.join("short"), b"0123456789").unwrap();
        let node = lookup_node(&mut dev, FUSE_ROOT_ID, b"short");
        let fh = open_rw(&mut dev, node);

        let mut backing = vec![0u8; 0x10000];
        let base = 0x4000_0000u64;
        let mem = GuestRam::new(backing.as_mut_ptr(), base, backing.len());
        let (desc, avail, used, in_buf, out) = (
            base,
            base + 0x100,
            base + 0x200,
            base + 0x1000,
            base + 0x2000,
        );
        program_queue(&mut dev, &mem, 8, desc, avail, used);

        let mut req = fuse_in_header(80, READ, 0x55, node);
        let mut args = vec![0u8; 40];
        args[0..8].copy_from_slice(&fh.to_le_bytes());
        args[16..20].copy_from_slice(&100u32.to_le_bytes()); // more than the file has
        req.extend_from_slice(&args);
        mem.write(in_buf, &req).unwrap();

        write_desc(&mem, desc, 0, in_buf, req.len() as u32, DESC_NEXT, 1);
        write_desc(
            &mem,
            desc,
            1,
            out,
            OUT_HEADER_LEN as u32 + 100,
            DESC_WRITE,
            0,
        );
        notify_head(&mut dev, &mem, avail, 0);

        let mut got = [0u8; 10];
        mem.read(out + OUT_HEADER_LEN as u64, &mut got).unwrap();
        assert_eq!(&got, b"0123456789");
        assert_eq!(mem.read_u32(out).unwrap(), (OUT_HEADER_LEN + 10) as u32);
        assert_eq!(used_len(&mem, used), (OUT_HEADER_LEN + 10) as u32);
        assert_eq!(
            dev.zero_copy_counts().0,
            1,
            "READ did not take the zero-copy path"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn direct_write_spans_two_input_descriptors() {
        let (dir, mut dev) = fixture_with_access(true);
        fs::write(dir.join("target"), vec![0u8; 1000]).unwrap();
        let node = lookup_node(&mut dev, FUSE_ROOT_ID, b"target");
        let fh = open_rw(&mut dev, node);

        let mut backing = vec![0u8; 0x10000];
        let base = 0x4000_0000u64;
        let mem = GuestRam::new(backing.as_mut_ptr(), base, backing.len());
        let (desc, avail, used, hdr_buf, payload1, payload2, out) = (
            base,
            base + 0x100,
            base + 0x200,
            base + 0x1000,
            base + 0x2000,
            base + 0x3000,
            base + 0x4000,
        );
        program_queue(&mut dev, &mem, 8, desc, avail, used);

        let size = 1000u32;
        let mut hdr = fuse_in_header(40 + 40 + size, WRITE, 0x99, node);
        let mut args = vec![0u8; 40];
        args[0..8].copy_from_slice(&fh.to_le_bytes());
        args[16..20].copy_from_slice(&size.to_le_bytes());
        hdr.extend_from_slice(&args);
        mem.write(hdr_buf, &hdr).unwrap();

        let part1: Vec<u8> = (0..400u32).map(|i| (i % 251) as u8).collect();
        let part2: Vec<u8> = (0..600u32).map(|i| ((i + 7) % 251) as u8).collect();
        mem.write(payload1, &part1).unwrap();
        mem.write(payload2, &part2).unwrap();

        write_desc(&mem, desc, 0, hdr_buf, hdr.len() as u32, DESC_NEXT, 1);
        write_desc(&mem, desc, 1, payload1, part1.len() as u32, DESC_NEXT, 2);
        write_desc(&mem, desc, 2, payload2, part2.len() as u32, DESC_NEXT, 3);
        write_desc(&mem, desc, 3, out, 64, DESC_WRITE, 0);
        notify_head(&mut dev, &mem, avail, 0);

        let mut expected = part1;
        expected.extend_from_slice(&part2);
        assert_eq!(fs::read(dir.join("target")).unwrap(), expected);
        assert_eq!(
            mem.read_u32(out + OUT_HEADER_LEN as u64).unwrap(),
            size,
            "fuse_write_out.size"
        );
        assert_eq!(mem.read_u32(out).unwrap(), (OUT_HEADER_LEN + 8) as u32);
        assert_eq!(
            dev.zero_copy_counts().1,
            1,
            "WRITE did not take the zero-copy path"
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// A guest must not be able to make the daemon write from outside the
    /// descriptors it actually offered: `fuse_write_in.size` claims 1000
    /// bytes, but only 100 payload bytes (and a `declared` consistent with
    /// only those 100) are actually in the chain.
    #[test]
    fn direct_write_with_declared_size_exceeding_descriptors_is_rejected() {
        let (dir, mut dev) = fixture_with_access(true);
        fs::write(dir.join("target"), b"before").unwrap();
        let node = lookup_node(&mut dev, FUSE_ROOT_ID, b"target");
        let fh = open_rw(&mut dev, node);

        let mut backing = vec![0u8; 0x10000];
        let base = 0x4000_0000u64;
        let mem = GuestRam::new(backing.as_mut_ptr(), base, backing.len());
        let (desc, avail, used, hdr_buf, payload, out) = (
            base,
            base + 0x100,
            base + 0x200,
            base + 0x1000,
            base + 0x2000,
            base + 0x3000,
        );
        program_queue(&mut dev, &mem, 8, desc, avail, used);

        let claimed_size = 1000u32;
        let actual_payload = 100u32;
        let mut hdr = fuse_in_header(40 + 40 + actual_payload, WRITE, 0x77, node);
        let mut args = vec![0u8; 40];
        args[0..8].copy_from_slice(&fh.to_le_bytes());
        args[16..20].copy_from_slice(&claimed_size.to_le_bytes());
        hdr.extend_from_slice(&args);
        mem.write(hdr_buf, &hdr).unwrap();
        mem.write(payload, &vec![0xaau8; actual_payload as usize])
            .unwrap();

        write_desc(&mem, desc, 0, hdr_buf, hdr.len() as u32, DESC_NEXT, 1);
        write_desc(&mem, desc, 1, payload, actual_payload, DESC_NEXT, 2);
        write_desc(&mem, desc, 2, out, 64, DESC_WRITE, 0);
        notify_head(&mut dev, &mem, avail, 0);

        assert_eq!(mem.read_u32(out).unwrap(), OUT_HEADER_LEN as u32);
        assert_eq!(mem.read_u32(out + 4).unwrap() as i32, -EINVAL);
        assert_eq!(fs::read(dir.join("target")).unwrap(), b"before");
        // The oversized claim must be refused before any `pwritev`, not merely
        // produce an error after one: no zero-copy write may have happened.
        assert_eq!(
            dev.zero_copy_counts().1,
            0,
            "an over-declared WRITE reached the zero-copy path"
        );
        let _ = fs::remove_dir_all(dir);
    }

    // --- Stage A: `QUEUE_NOTIFY` no longer runs the request inline; it just
    // records the queue index for a worker thread (`spawn_fs_worker` in
    // `machine_macos.rs`) to drain. The two tests below cover the part of
    // that split this module can exercise without a live VM: that `mmio`
    // itself does no I/O, and that the notified-bitmask/`process_queue`
    // hand-off it feeds is race-free under concurrent access.

    /// `mmio`'s `QUEUE_NOTIFY` arm must return having done nothing but flag
    /// the queue: no guest-memory access, no FUSE dispatch, no interrupt.
    /// `drain_notified` -- the worker's call, never the vCPU's -- is what
    /// actually runs the request.
    #[test]
    fn queue_notify_only_records_the_index_and_does_no_io() {
        let (dir, mut dev) = fixture_with_access(true);
        fs::write(dir.join("f"), b"hello").unwrap();
        let node = lookup_node(&mut dev, FUSE_ROOT_ID, b"f");
        let fh = open_rw(&mut dev, node);

        let mut backing = vec![0u8; 0x10000];
        let base = 0x4000_0000u64;
        let mem = GuestRam::new(backing.as_mut_ptr(), base, backing.len());
        let (desc, avail, used, in_buf, out) = (
            base,
            base + 0x100,
            base + 0x200,
            base + 0x1000,
            base + 0x2000,
        );
        program_queue(&mut dev, &mem, 8, desc, avail, used);

        let mut req = fuse_in_header(80, READ, 0x1234, node);
        let mut args = vec![0u8; 40];
        args[0..8].copy_from_slice(&fh.to_le_bytes());
        args[16..20].copy_from_slice(&5u32.to_le_bytes());
        req.extend_from_slice(&args);
        mem.write(in_buf, &req).unwrap();
        write_desc(&mem, desc, 0, in_buf, req.len() as u32, DESC_NEXT, 1);
        write_desc(&mem, desc, 1, out, OUT_HEADER_LEN as u32 + 5, DESC_WRITE, 0);
        mem.write_u16(avail + 2, 1).unwrap(); // avail.idx
        mem.write_u16(avail + 4, 0).unwrap(); // avail.ring[0] = head 0

        dev.mmio(&mem, reg::QUEUE_NOTIFY, true, u64::from(REQ_QUEUE));

        assert_eq!(
            mem.read_u16(used + 2).unwrap(),
            0,
            "QUEUE_NOTIFY must not touch the used ring synchronously"
        );
        assert!(
            !dev.irq_level(),
            "QUEUE_NOTIFY must not raise an interrupt synchronously -- no \
             request has run yet"
        );

        // The worker's side of the split: draining now must service exactly
        // the request the vCPU thread queued.
        dev.drain_notified(&mem);
        assert_eq!(
            mem.read_u16(used + 2).unwrap(),
            1,
            "drain_notified must service the request the notify flagged"
        );
        let mut got = [0u8; 5];
        mem.read(out + OUT_HEADER_LEN as u64, &mut got).unwrap();
        assert_eq!(&got, b"hello");
        assert!(dev.irq_level());
        let _ = fs::remove_dir_all(dir);
    }

    /// A vCPU services a shallow queue inline and hands a deep one to the
    /// worker. The budget is what splits the two, so it must service exactly
    /// that many chains, report that work is left, and re-flag the queue --
    /// otherwise the remainder is stranded until the guest happens to notify
    /// again, which for a blocking FUSE call it never will.
    #[test]
    fn a_bounded_drain_services_its_budget_and_strands_nothing() {
        let (dir, mut dev) = fixture_with_access(true);
        fs::write(dir.join("f"), b"hello").unwrap();
        let node = lookup_node(&mut dev, FUSE_ROOT_ID, b"f");
        let fh = open_rw(&mut dev, node);

        let mut backing = vec![0u8; 0x20000];
        let base = 0x4000_0000u64;
        let mem = GuestRam::new(backing.as_mut_ptr(), base, backing.len());
        let (desc, avail, used) = (base, base + 0x100, base + 0x200);
        program_queue(&mut dev, &mem, 8, desc, avail, used);

        // Four independent READ chains, each a request descriptor followed by
        // a writable reply descriptor.
        const CHAINS: u16 = 4;
        for i in 0..CHAINS {
            let in_buf = base + 0x1000 + u64::from(i) * 0x200;
            let out = base + 0x8000 + u64::from(i) * 0x200;
            let mut req = fuse_in_header(80, READ, 0x100 + u64::from(i), node);
            let mut args = vec![0u8; 40];
            args[0..8].copy_from_slice(&fh.to_le_bytes());
            args[16..20].copy_from_slice(&5u32.to_le_bytes());
            req.extend_from_slice(&args);
            mem.write(in_buf, &req).unwrap();
            write_desc(
                &mem,
                desc,
                i * 2,
                in_buf,
                req.len() as u32,
                DESC_NEXT,
                i * 2 + 1,
            );
            write_desc(
                &mem,
                desc,
                i * 2 + 1,
                out,
                OUT_HEADER_LEN as u32 + 5,
                DESC_WRITE,
                0,
            );
            mem.write_u16(avail + 4 + u64::from(i) * 2, i * 2).unwrap();
        }
        mem.write_u16(avail + 2, CHAINS).unwrap();

        dev.mmio(&mem, reg::QUEUE_NOTIFY, true, u64::from(REQ_QUEUE));

        let remaining = dev.drain_notified_bounded(&mem, 2);
        assert!(
            remaining,
            "a budget below the queue depth must report work left"
        );
        assert_eq!(
            mem.read_u16(used + 2).unwrap(),
            2,
            "a bounded drain must service exactly its budget"
        );

        // Re-flagged, so the worker picks the rest up without a fresh notify.
        let remaining = dev.drain_notified_bounded(&mem, u16::MAX);
        assert!(!remaining, "the second pass should exhaust the queue");
        assert_eq!(
            mem.read_u16(used + 2).unwrap(),
            CHAINS,
            "every queued chain must be serviced, none stranded"
        );
        for i in 0..CHAINS {
            let out = base + 0x8000 + u64::from(i) * 0x200;
            let mut got = [0u8; 5];
            mem.read(out + OUT_HEADER_LEN as u64, &mut got).unwrap();
            assert_eq!(&got, b"hello", "chain {i} did not get its reply");
        }
        let _ = fs::remove_dir_all(dir);
    }

    /// The failure mode Stage A must rule out is notify-during-drain: a
    /// `QUEUE_NOTIFY` landing on the vCPU thread while the worker thread is
    /// mid-`drain_notified` must never leave a published request stranded.
    ///
    /// This drives `mmio`/`drain_notified` from two real threads sharing an
    /// `Arc<Mutex<VirtioFs>>`, the same sharing `spawn_fs_worker` uses in
    /// production: one thread publishes `REQS` independent single-request
    /// notifies back to back (racing however the scheduler interleaves it
    /// with the other thread's drains), the other drains in a tight loop.
    /// After the producer has fully joined -- so every one of its `mmio`
    /// calls has completed and is visible to whichever thread next takes the
    /// lock -- one guaranteed final `drain_notified` call is what a real
    /// worker's post-drain-recheck-before-park does; skipping it is exactly
    /// the classic lost-wakeup bug this test exists to catch. Every request
    /// must show up in the used ring exactly once: none stranded, none
    /// double-serviced.
    #[test]
    fn concurrent_notifies_during_a_drain_leave_nothing_stranded() {
        const REQS: u16 = 64;
        const QUEUE_SIZE: u32 = 128;
        // Spaced generously so a GETATTR response (well under 0x200 bytes)
        // can never reach into the next request's input buffer.
        const STRIDE: u64 = 0x400;

        let (dir, dev) = fixture();
        let dev = Arc::new(Mutex::new(dev));

        let mut backing = vec![0u8; 0x20000];
        let base = 0x4000_0000u64;
        let mem = Arc::new(GuestRam::new(backing.as_mut_ptr(), base, backing.len()));
        let (desc, avail, used) = (base, base + 0x1000, base + 0x2000);
        let bufs = base + 0x4000;

        {
            let mut d = dev.lock().unwrap();
            program_queue(&mut d, &mem, QUEUE_SIZE, desc, avail, used);
        }

        // Lay out REQS independent 2-descriptor chains up front -- guest
        // descriptor tables are static, only avail/used move as requests are
        // published and serviced.
        for i in 0..REQS {
            let head = i * 2;
            let in_buf = bufs + u64::from(i) * STRIDE;
            let out_buf = in_buf + STRIDE / 2;
            let req = request(GETATTR, FUSE_ROOT_ID, &[]);
            mem.write(in_buf, &req).unwrap();
            write_desc(
                &mem,
                desc,
                head,
                in_buf,
                req.len() as u32,
                DESC_NEXT,
                head + 1,
            );
            write_desc(
                &mem,
                desc,
                head + 1,
                out_buf,
                (STRIDE / 2) as u32,
                DESC_WRITE,
                0,
            );
        }

        let stop = Arc::new(AtomicBool::new(false));

        // Stands in for the vCPU thread: publishes one request at a time and
        // rings the doorbell after each.
        let producer = {
            let dev = Arc::clone(&dev);
            let mem = Arc::clone(&mem);
            std::thread::spawn(move || {
                for i in 0..REQS {
                    mem.write_u16(avail + 4 + u64::from(i) * 2, i * 2).unwrap();
                    mem.write_u16(avail + 2, i + 1).unwrap(); // avail.idx
                    dev.lock()
                        .unwrap()
                        .mmio(&mem, reg::QUEUE_NOTIFY, true, u64::from(REQ_QUEUE));
                    std::thread::yield_now();
                }
            })
        };

        // Stands in for the worker thread's drain loop.
        let drainer = {
            let dev = Arc::clone(&dev);
            let mem = Arc::clone(&mem);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    dev.lock().unwrap().drain_notified(&mem);
                    std::thread::yield_now();
                }
                // The post-drain recheck a real worker does right before
                // parking again -- guaranteed to observe every notify the
                // producer made, since `producer.join()` happened-before
                // `stop.store`, below.
                dev.lock().unwrap().drain_notified(&mem);
            })
        };

        producer.join().unwrap();
        stop.store(true, Ordering::Relaxed);
        drainer.join().unwrap();

        assert_eq!(
            mem.read_u16(used + 2).unwrap(),
            REQS,
            "every published request must be serviced exactly once -- none \
             stranded, none double-serviced"
        );
        let _ = fs::remove_dir_all(dir);
    }
}

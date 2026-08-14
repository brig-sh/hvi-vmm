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
//! descriptors. Each device is independently read-only or read-write; the OCI
//! rootfs stays protected while explicitly writable volumes can be exported
//! without block images.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

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
const GETXATTR: u32 = 22;
const LISTXATTR: u32 = 23;
const FLUSH: u32 = 25;
const INIT: u32 = 26;
const OPENDIR: u32 = 27;
const READDIR: u32 = 28;
const RELEASEDIR: u32 = 29;
const FSYNCDIR: u32 = 30;
const ACCESS: u32 = 34;
const CREATE: u32 = 35;
const DESTROY: u32 = 38;
const BATCH_FORGET: u32 = 42;
const RENAME2: u32 = 45;

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
const RENAME_NOREPLACE: u32 = 1;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

// Linux errno values. Host errno numbers are not portable from macOS to the
// Linux guest, so errors are translated explicitly.
const ENOENT: i32 = 2;
const EPERM: i32 = 1;
const EIO: i32 = 5;
const EBADF: i32 = 9;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const EXDEV: i32 = 18;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;
const EROFS: i32 = 30;
const ENOSYS: i32 = 38;
const ENOTEMPTY: i32 = 39;
const ELOOP: i32 = 40;
const ENODATA: i32 = 61;
const EOPNOTSUPP: i32 = 95;

struct FileHandle {
    file: File,
    writable: bool,
}

/// A virtio-fs device exporting exactly one canonical host directory.
pub struct VirtioFs {
    root: PathBuf,
    writable: bool,
    tag: [u8; TAG_LEN],
    status: u32,
    dev_feat_sel: u32,
    queue_sel: u32,
    queues: [Queue; NUM_QUEUES],
    interrupt_status: u32,
    nodes: HashMap<u64, PathBuf>,
    inode_ids: HashMap<(u64, u64), u64>,
    next_node: u64,
    handles: HashMap<u64, FileHandle>,
    next_handle: u64,
}

impl VirtioFs {
    /// Creates an export. `root` must already be canonical so the same exact
    /// path and access mode can be granted by Seatbelt.
    pub fn new(root: PathBuf, tag: &str, writable: bool) -> io::Result<Self> {
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
        let mut nodes = HashMap::new();
        nodes.insert(FUSE_ROOT_ID, root.clone());
        let root_meta = fs::symlink_metadata(&root)?;
        let mut inode_ids = HashMap::new();
        inode_ids.insert((root_meta.dev(), root_meta.ino()), FUSE_ROOT_ID);
        Ok(Self {
            root,
            writable,
            tag: tag_buf,
            status: 0,
            dev_feat_sel: 0,
            queue_sel: 0,
            queues: std::array::from_fn(|_| Queue::default()),
            interrupt_status: 0,
            nodes,
            inode_ids,
            next_node: FUSE_ROOT_ID + 1,
            handles: HashMap::new(),
            next_handle: 1,
        })
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

    /// Services a virtio-mmio register access. Queue notifications are drained
    /// in one batch, avoiding an exit/interrupt round trip per request.
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
                    self.process_queue(mem, v as usize);
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

    fn process_queue(&mut self, mem: &GuestRam, queue_idx: usize) {
        if !self.queues[queue_idx].is_ready() {
            return;
        }
        let Some(pending) = self.queues[queue_idx].pending(mem) else {
            return;
        };
        let mut last = self.queues[queue_idx].last_avail();
        let mut serviced = false;
        for _ in 0..pending {
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
    }

    fn handle_chain(&mut self, mem: &GuestRam, queue_idx: usize, head: u16) -> u32 {
        let q = &self.queues[queue_idx];
        let mut request = Vec::new();
        let mut output = Vec::new();
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
                let Some(total) = request.len().checked_add(len as usize) else {
                    return 0;
                };
                if total > MAX_REQUEST {
                    return 0;
                }
                let start = request.len();
                request.resize(total, 0);
                if mem.read(addr, &mut request[start..]).is_err() {
                    return 0;
                }
            }
            if flags & DESC_NEXT == 0 {
                break;
            }
            desc = next;
        }
        if request.len() < IN_HEADER_LEN || output.is_empty() {
            return 0;
        }
        let max_out: usize = output.iter().map(|(_, len)| *len as usize).sum();
        let response = self.handle_fuse(&request, max_out);
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

    fn handle_fuse(&mut self, raw: &[u8], max_out: usize) -> Vec<u8> {
        let declared = get_u32(raw, 0).unwrap_or(0) as usize;
        let opcode = get_u32(raw, 4).unwrap_or(0);
        let unique = get_u64(raw, 8).unwrap_or(0);
        let nodeid = get_u64(raw, 16).unwrap_or(0);
        if declared < IN_HEADER_LEN || declared > raw.len() {
            return error_response(unique, EINVAL);
        }
        let payload = &raw[IN_HEADER_LEN..declared];
        let result = match opcode {
            FORGET | BATCH_FORGET | DESTROY => return Vec::new(),
            INIT => self.init(payload),
            LOOKUP => self.lookup(nodeid, payload),
            GETATTR => self.getattr(nodeid, payload),
            SETATTR => self.setattr(nodeid, payload),
            READLINK => self.readlink(nodeid),
            SYMLINK => self.symlink(nodeid, payload),
            MKNOD => self.mknod(nodeid, payload),
            MKDIR => self.mkdir(nodeid, payload),
            UNLINK => self.remove(nodeid, payload, false),
            RMDIR => self.remove(nodeid, payload, true),
            RENAME => self.rename(nodeid, payload, false),
            RENAME2 => self.rename(nodeid, payload, true),
            LINK => self.link(nodeid, payload),
            OPEN => self.open(nodeid, payload, false),
            OPENDIR => self.open(nodeid, payload, true),
            READ => self.read(nodeid, payload, max_out.saturating_sub(OUT_HEADER_LEN)),
            WRITE => self.write(payload),
            READDIR => self.readdir(nodeid, payload, max_out.saturating_sub(OUT_HEADER_LEN)),
            STATFS => self.statfs(),
            ACCESS => self.access(nodeid, payload),
            CREATE => self.create(nodeid, payload),
            GETXATTR => Err(ENODATA),
            LISTXATTR => self.listxattr(payload),
            RELEASE => self.release(payload),
            RELEASEDIR => Ok(Vec::new()),
            FLUSH => self.flush(payload),
            FSYNC => self.fsync(payload),
            FSYNCDIR => Ok(Vec::new()),
            // Extended mutations that are not implemented yet still preserve
            // a read-only export's stronger EROFS contract.
            21 | 24 | 43 | 47..=51 if !self.writable => Err(EROFS),
            21 | 24 | 43 | 47..=51 => Err(EOPNOTSUPP),
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
        const BIG_WRITES: u32 = 1 << 5;
        const AUTO_INVAL_DATA: u32 = 1 << 12;
        const MAX_PAGES: u32 = 1 << 22;
        const CACHE_SYMLINKS: u32 = 1 << 23;
        let supported = ASYNC_READ | BIG_WRITES | AUTO_INVAL_DATA | MAX_PAGES | CACHE_SYMLINKS;
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
        let meta = fs::symlink_metadata(&path).map_err(io_errno)?;
        let node = self.node_for(path, &meta);
        Ok(entry_out(node, &meta))
    }

    fn getattr(&self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        let flags = get_u32(input, 0).unwrap_or(0);
        let fh = get_u64(input, 8).unwrap_or(0);
        let meta = if flags & FUSE_GETATTR_FH != 0 {
            self.handles
                .get(&fh)
                .ok_or(EBADF)?
                .file
                .metadata()
                .map_err(io_errno)?
        } else {
            fs::symlink_metadata(self.node_path(node)?).map_err(io_errno)?
        };
        Ok(attr_out(node, &meta))
    }

    fn setattr(&mut self, node: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let valid = get_u32(input, 0).ok_or(EINVAL)?;
        let fh = get_u64(input, 8).ok_or(EINVAL)?;
        let size = get_u64(input, 16).ok_or(EINVAL)?;
        let mode = get_u32(input, 68).ok_or(EINVAL)?;

        // Ownership and timestamp translation need explicit guest/host ID and
        // clock semantics. Refuse those bits rather than silently applying the
        // wrong identity or following a symlink during a timestamp update.
        let unsupported = FATTR_UID
            | FATTR_GID
            | FATTR_ATIME
            | FATTR_MTIME
            | FATTR_ATIME_NOW
            | FATTR_MTIME_NOW
            | FATTR_CTIME;
        if valid & unsupported != 0 {
            return Err(EOPNOTSUPP);
        }
        let known =
            FATTR_MODE | FATTR_SIZE | FATTR_FH | FATTR_LOCKOWNER | FATTR_KILL_SUIDGID | unsupported;
        if valid & !known != 0 {
            return Err(EINVAL);
        }

        if valid & FATTR_SIZE != 0 {
            if valid & FATTR_FH != 0 {
                let handle = self.handles.get(&fh).ok_or(EBADF)?;
                if !handle.writable {
                    return Err(EBADF);
                }
                handle.file.set_len(size).map_err(io_errno)?;
            } else {
                let file = open_host_file(self.node_path(node)?, LINUX_O_WRONLY, false, 0)
                    .map_err(io_errno)?;
                file.set_len(size).map_err(io_errno)?;
            }
        }
        if valid & FATTR_MODE != 0 {
            fs::set_permissions(self.node_path(node)?, Permissions::from_mode(mode & 0o7777))
                .map_err(io_errno)?;
        }

        let meta = if valid & FATTR_FH != 0 {
            self.handles
                .get(&fh)
                .ok_or(EBADF)?
                .file
                .metadata()
                .map_err(io_errno)?
        } else {
            fs::symlink_metadata(self.node_path(node)?).map_err(io_errno)?
        };
        Ok(attr_out(node, &meta))
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
        if !fs::symlink_metadata(parent).map_err(io_errno)?.is_dir() {
            return Err(ENOTDIR);
        }
        Ok(parent.join(OsStr::from_bytes(name)))
    }

    fn new_entry(&mut self, path: PathBuf) -> Result<Vec<u8>, i32> {
        let meta = fs::symlink_metadata(&path).map_err(io_errno)?;
        let node = self.node_for(path, &meta);
        Ok(entry_out(node, &meta))
    }

    fn mknod(&mut self, parent: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let mode = get_u32(input, 0).ok_or(EINVAL)?;
        if mode & S_IFMT != S_IFREG {
            // Never create host device nodes from a guest. CREATE normally
            // handles regular files; this path is its older-kernel fallback.
            return Err(EPERM);
        }
        let name = nul_name(input, 16)?;
        let path = self.child_path(parent, name)?;
        let file =
            open_host_file(&path, LINUX_O_WRONLY | LINUX_O_EXCL, true, mode).map_err(io_errno)?;
        file.set_permissions(Permissions::from_mode(mode & 0o7777))
            .map_err(io_errno)?;
        drop(file);
        self.new_entry(path)
    }

    fn mkdir(&mut self, parent: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let mode = get_u32(input, 0).ok_or(EINVAL)?;
        let name = nul_name(input, 8)?;
        let path = self.child_path(parent, name)?;
        let mut builder = fs::DirBuilder::new();
        builder
            .mode(mode & 0o7777)
            .create(&path)
            .map_err(io_errno)?;
        fs::set_permissions(&path, Permissions::from_mode(mode & 0o7777)).map_err(io_errno)?;
        self.new_entry(path)
    }

    fn symlink(&mut self, parent: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let (name, next) = nul_name_with_end(input, 0)?;
        let target = nul_name(input, next)?;
        let path = self.child_path(parent, name)?;
        std::os::unix::fs::symlink(OsStr::from_bytes(target), &path).map_err(io_errno)?;
        self.new_entry(path)
    }

    fn link(&mut self, new_parent: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let old_node = get_u64(input, 0).ok_or(EINVAL)?;
        let name = nul_name(input, 8)?;
        let old_path = self.node_path(old_node)?.to_owned();
        let new_path = self.child_path(new_parent, name)?;
        fs::hard_link(&old_path, &new_path).map_err(io_errno)?;
        self.new_entry(new_path)
    }

    fn remove(&mut self, parent: u64, input: &[u8], directory: bool) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let name = nul_name(input, 0)?;
        let path = self.child_path(parent, name)?;
        let meta = fs::symlink_metadata(&path).map_err(io_errno)?;
        if directory {
            fs::remove_dir(&path).map_err(io_errno)?;
        } else {
            fs::remove_file(&path).map_err(io_errno)?;
        }
        self.inode_ids.remove(&(meta.dev(), meta.ino()));
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
        if flags & !RENAME_NOREPLACE != 0 {
            return Err(EOPNOTSUPP);
        }
        let (old_name, next) = nul_name_with_end(input, names_at)?;
        let new_name = nul_name(input, next)?;
        let old_path = self.child_path(old_parent, old_name)?;
        let new_path = self.child_path(new_parent, new_name)?;
        if flags & RENAME_NOREPLACE != 0 && fs::symlink_metadata(&new_path).is_ok() {
            return Err(EEXIST);
        }

        let replaced = fs::symlink_metadata(&new_path).ok();
        fs::rename(&old_path, &new_path).map_err(io_errno)?;
        if let Some(meta) = replaced {
            self.inode_ids.remove(&(meta.dev(), meta.ino()));
        }
        self.rewrite_node_paths(&old_path, &new_path);
        Ok(Vec::new())
    }

    fn rewrite_node_paths(&mut self, old: &Path, new: &Path) {
        for path in self.nodes.values_mut() {
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

    fn create(&mut self, parent: u64, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let flags = get_u32(input, 0).ok_or(EINVAL)?;
        let mode = get_u32(input, 4).ok_or(EINVAL)?;
        let name = nul_name(input, 16)?;
        let path = self.child_path(parent, name)?;
        let file = open_host_file(&path, flags, true, mode).map_err(io_errno)?;
        file.set_permissions(Permissions::from_mode(mode & 0o7777))
            .map_err(io_errno)?;
        let meta = file.metadata().map_err(io_errno)?;
        let node = self.node_for(path, &meta);
        let fh = self.insert_handle(file, flags & LINUX_O_ACCMODE != 0);
        let mut out = entry_out(node, &meta);
        put_open_out(&mut out, fh, false);
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
        let wants_write = flags & LINUX_O_ACCMODE != 0 || flags & LINUX_O_TRUNC != 0;
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
        let fh = if directory {
            node // directory traversal remains stateless
        } else {
            let file = open_host_file(&path, flags, false, 0).map_err(io_errno)?;
            self.insert_handle(file, wants_write)
        };
        let mut out = Vec::with_capacity(16);
        put_open_out(&mut out, fh, directory);
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

    fn write(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        self.require_writable()?;
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        let offset = get_u64(input, 8).ok_or(EINVAL)?;
        let size = get_u32(input, 16).ok_or(EINVAL)? as usize;
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
        let mut out = Vec::with_capacity(8);
        put_u32(&mut out, n as u32);
        put_u32(&mut out, 0);
        Ok(out)
    }

    fn insert_handle(&mut self, file: File, writable: bool) -> u64 {
        let fh = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1).max(1);
        self.handles.insert(fh, FileHandle { file, writable });
        fh
    }

    fn release(&mut self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let fh = get_u64(input, 0).ok_or(EINVAL)?;
        self.handles.remove(&fh);
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

    fn readdir(&mut self, node: u64, input: &[u8], capacity: usize) -> Result<Vec<u8>, i32> {
        let offset = get_u64(input, 8).ok_or(EINVAL)? as usize;
        let requested = get_u32(input, 16).ok_or(EINVAL)? as usize;
        let limit = requested.min(capacity);
        let dir = self.node_path(node)?.to_owned();
        if !fs::symlink_metadata(&dir).map_err(io_errno)?.is_dir() {
            return Err(ENOTDIR);
        }

        let parent_path = if dir == self.root {
            self.root.clone()
        } else {
            dir.parent().unwrap_or(&self.root).to_owned()
        };
        let parent_meta = fs::symlink_metadata(&parent_path).map_err(io_errno)?;
        let parent_node = self.node_for(parent_path, &parent_meta);
        let mut entries: Vec<(OsString, PathBuf)> = fs::read_dir(&dir)
            .map_err(io_errno)?
            .filter_map(Result::ok)
            .map(|entry| (entry.file_name(), entry.path()))
            .collect();
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        entries.insert(
            0,
            (
                OsString::from_vec(b"..".to_vec()),
                self.node_path(parent_node)?.to_owned(),
            ),
        );
        entries.insert(0, (OsString::from_vec(b".".to_vec()), dir));

        let mut out = Vec::new();
        for (idx, (name, path)) in entries.into_iter().enumerate().skip(offset) {
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            let entry_node = if idx == 0 {
                node
            } else if idx == 1 {
                parent_node
            } else {
                self.node_for(path, &meta)
            };
            let name = name.as_bytes();
            let record_len = align8(24 + name.len());
            if out.len() + record_len > limit {
                break;
            }
            put_u64(&mut out, entry_node);
            put_u64(&mut out, (idx + 1) as u64);
            put_u32(&mut out, name.len() as u32);
            put_u32(&mut out, dirent_type(&meta));
            out.extend_from_slice(name);
            out.resize(align8(out.len()), 0);
        }
        Ok(out)
    }

    fn statfs(&self) -> Result<Vec<u8>, i32> {
        let mut out = Vec::with_capacity(80);
        for value in [0u64; 5] {
            put_u64(&mut out, value);
        }
        put_u32(&mut out, 4096);
        put_u32(&mut out, 255);
        put_u32(&mut out, 4096);
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

    fn listxattr(&self, input: &[u8]) -> Result<Vec<u8>, i32> {
        let size = get_u32(input, 0).ok_or(EINVAL)?;
        if size == 0 {
            let mut out = Vec::with_capacity(8);
            put_u32(&mut out, 0);
            put_u32(&mut out, 0);
            Ok(out)
        } else {
            Ok(Vec::new())
        }
    }

    fn node_path(&self, node: u64) -> Result<&Path, i32> {
        self.nodes.get(&node).map(PathBuf::as_path).ok_or(ENOENT)
    }

    fn node_for(&mut self, path: PathBuf, meta: &Metadata) -> u64 {
        let key = (meta.dev(), meta.ino());
        if let Some(node) = self.inode_ids.get(&key) {
            // Hard links intentionally share a node. Prefer a live spelling if
            // the original link was removed while another remains.
            if self
                .nodes
                .get(node)
                .is_some_and(|remembered| fs::symlink_metadata(remembered).is_err())
            {
                self.nodes.insert(*node, path);
            }
            return *node;
        }
        let node = self.next_node;
        self.next_node = self.next_node.saturating_add(1);
        self.nodes.insert(node, path.clone());
        self.inode_ids.insert(key, node);
        node
    }
}

fn attr_out(node: u64, meta: &Metadata) -> Vec<u8> {
    let mut out = Vec::with_capacity(104);
    put_u64(&mut out, 60);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_attr(&mut out, node, meta);
    out
}

fn entry_out(node: u64, meta: &Metadata) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    put_u64(&mut out, node);
    put_u64(&mut out, 1); // generation
    put_u64(&mut out, 60);
    put_u64(&mut out, 60);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_attr(&mut out, node, meta);
    out
}

fn put_open_out(out: &mut Vec<u8>, fh: u64, directory: bool) {
    put_u64(out, fh);
    // Cache directory contents and regular-file pages. Attribute/entry
    // timeouts remain short, so host-side changes are still rediscovered.
    put_u32(out, if directory { 1 << 3 } else { 1 << 1 });
    put_u32(out, 0); // backing_id (signed on the wire, zero means none)
}

fn open_host_file(path: &Path, flags: u32, create: bool, mode: u32) -> io::Result<File> {
    let access = flags & LINUX_O_ACCMODE;
    if access == LINUX_O_ACCMODE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Linux O_ACCMODE value",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(access == 0 || access == LINUX_O_RDWR);
    options.write(access == LINUX_O_WRONLY || access == LINUX_O_RDWR);
    options.append(flags & LINUX_O_APPEND != 0 && access != 0);
    options.truncate(flags & LINUX_O_TRUNC != 0);
    if create {
        options.create(true);
        options.create_new(flags & LINUX_O_EXCL != 0);
        options.mode(mode & 0o7777);
    }
    // The final component must be the inode the guest looked up, never a host
    // symlink followed behind the guest VFS's back.
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(path)
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

fn put_attr(out: &mut Vec<u8>, node: u64, meta: &Metadata) {
    put_u64(out, node);
    put_u64(out, meta.size());
    put_u64(out, meta.blocks());
    put_u64(out, nonnegative(meta.atime()));
    put_u64(out, nonnegative(meta.mtime()));
    put_u64(out, nonnegative(meta.ctime()));
    put_u32(out, meta.atime_nsec().max(0) as u32);
    put_u32(out, meta.mtime_nsec().max(0) as u32);
    put_u32(out, meta.ctime_nsec().max(0) as u32);
    put_u32(out, meta.mode());
    put_u32(out, meta.nlink() as u32);
    put_u32(out, meta.uid());
    put_u32(out, meta.gid());
    put_u32(out, 0); // macOS st_rdev encoding is not Linux-compatible
    put_u32(out, meta.blksize() as u32);
    put_u32(out, 0);
}

fn nonnegative(value: i64) -> u64 {
    value.max(0) as u64
}

fn dirent_type(meta: &Metadata) -> u32 {
    let ty = meta.file_type();
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
        Some(code) if code == libc::ENOSPC => return ENOSPC,
        Some(code) if code == libc::ENOTEMPTY => return ENOTEMPTY,
        Some(code) if code == libc::ELOOP => return ELOOP,
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

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

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

    fn fixture_with_access(writable: bool) -> (PathBuf, VirtioFs) {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("hvi-virtiofs-test-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/issue"), b"hello\n").unwrap();
        let fs = VirtioFs::new(fs::canonicalize(&dir).unwrap(), "rootfs", writable).unwrap();
        (dir, fs)
    }

    fn fixture() -> (PathBuf, VirtioFs) {
        fixture_with_access(false)
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
}

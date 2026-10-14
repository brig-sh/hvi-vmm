// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Backend-independent boot configuration and result types, shared by every
//! hypervisor backend.

use std::fmt;
use std::path::PathBuf;

/// Access granted to a host directory exported through virtio-fs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    ReadOnly,
    ReadWrite,
}

impl ShareMode {
    #[must_use]
    pub fn writable(self) -> bool {
        self == Self::ReadWrite
    }
}

/// How long the guest may keep metadata and page-cache contents without
/// re-checking the host.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CachePolicy {
    /// Metadata cached for five seconds on a writable share, and for a minute
    /// on a read-only one, which cannot go stale from the guest's own writes.
    /// The page cache is retained across opens either way, with the guest
    /// revalidating on a size or mtime change. See `WRITABLE_CACHE_SECS` in
    /// `devices::virtio::fs::server` for where the five comes from.
    #[default]
    Auto,
    /// On a writable share, additionally lets the guest own the page cache for
    /// writes, batching them into large aligned WRITEs. Only correct when the
    /// guest is the sole writer. On a read-only share it negotiates no
    /// writeback cache and behaves as [`CachePolicy::Auto`].
    ///
    /// A trade, not a straight win, and which way it goes depends entirely on
    /// how the workload writes. Measured with `tools/fsbench` writing 256 MiB:
    /// at `dd bs=4k` it batched 65536 requests down to a few hundred and ran
    /// 2.4x faster, while at `bs=1M` it ran 3.7x slower, because the guest's
    /// writeback path then costs more than the requests it saves. Worth it for
    /// many small writes to the same file, not for bulk sequential ones.
    Always,
    /// Every lookup and read goes to the host. Correct under concurrent host
    /// mutation, and slow.
    None,
}

/// One host directory exported to the guest through virtio-fs, which hvi
/// serves itself. Only the macOS backend serves these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsShare {
    /// The host directory the export serves.
    pub path: PathBuf,
    /// The tag the guest mounts the export by, 1 to 36 bytes.
    pub tag: String,
    /// Whether the guest may write the export.
    pub mode: ShareMode,
    /// How long the guest may cache what the export answers.
    pub cache: CachePolicy,
    /// The guest uid the host user's files carry in this export.
    pub uid: u32,
    /// The guest gid the host user's files carry in this export.
    pub gid: u32,
}

/// A virtio-fs export served by a vhost-user daemon the caller runs.
///
/// The daemon serves the directory it was started with, and it decides whether
/// the guest may write it. The VMM sees only the socket. Only the Linux
/// backends serve these. The fields and their defaults are Cloud Hypervisor's
/// `--fs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsConfig {
    /// The tag the guest mounts the export by, 1 to 36 bytes.
    pub tag: String,
    /// The socket the daemon listens on.
    pub socket: PathBuf,
    /// The number of request queues, beside the hiprio queue. At most one per
    /// vCPU.
    pub num_queues: usize,
    /// The size of each queue, a power of two up to 32768.
    pub queue_size: u16,
}

impl FsConfig {
    /// The request queues an export gets when `num_queues` is not given.
    pub const DEFAULT_NUM_QUEUES: usize = 1;
    /// The queue size an export gets when `queue_size` is not given.
    pub const DEFAULT_QUEUE_SIZE: u16 = 1024;
    /// The largest queue size, which is the largest split virtqueue.
    pub const MAX_QUEUE_SIZE: u16 = 32768;

    /// Refuses an export no guest could use.
    ///
    /// [`FsSpec::parse`] runs it on what it reads, and [`check_fs`] on every
    /// export a backend is given, so a library caller that builds an
    /// `FsConfig` itself gets the same checks as the command line.
    ///
    /// # Errors
    ///
    /// Returns why on a tag that is empty, longer than 36 bytes or holds a
    /// NUL, on no request queue, and on a queue size that is not a power of
    /// two up to [`Self::MAX_QUEUE_SIZE`].
    pub fn validate(&self) -> Result<(), String> {
        if self.tag.is_empty() || self.tag.len() > FsSpec::MAX_TAG_LEN || self.tag.contains('\0') {
            return Err(format!(
                "the tag must be 1 to {} bytes with no NUL",
                FsSpec::MAX_TAG_LEN
            ));
        }
        if self.num_queues == 0 {
            return Err("num_queues=0 is not a count of 1 or more".into());
        }
        if !self.queue_size.is_power_of_two() || self.queue_size > Self::MAX_QUEUE_SIZE {
            return Err(format!(
                "queue_size={} is not a power of two up to {}",
                self.queue_size,
                Self::MAX_QUEUE_SIZE
            ));
        }
        Ok(())
    }
}

/// One `--fs` export: a directory hvi serves, or a vhost-user daemon's socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsSpec {
    /// `path=`: hvi serves the directory itself, on macOS.
    Share(FsShare),
    /// `socket=`: the caller's daemon serves it, on Linux.
    Socket(FsConfig),
}

/// Returns the `key=value` fields of `spec`, in order, when every key is one of
/// `allowed` and none repeats.
///
/// `bad` wraps the reason into the caller's error, so the two `--fs` and
/// `--disk` parsers report the same shapes the same way.
fn key_values<'a>(
    spec: &'a str,
    allowed: &[&str],
    bad: impl Fn(String) -> String,
) -> Result<Vec<(&'a str, &'a str)>, String> {
    let mut fields: Vec<(&str, &str)> = Vec::new();
    for field in spec.split(',') {
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| bad(format!("{field:?} is not key=value")))?;
        if !allowed.contains(&key) {
            return Err(bad(format!("unknown key {key:?}")));
        }
        if fields.iter().any(|(seen, _)| *seen == key) {
            return Err(bad(format!("{key} given twice")));
        }
        fields.push((key, value));
    }
    Ok(fields)
}

impl FsSpec {
    /// The syntax [`parse`](Self::parse) takes, for an error to quote.
    pub const SYNTAX: &'static str =
        "tag=<tag>,socket=<socket>[,num_queues=<n>][,queue_size=<size>] \
         or tag=<tag>,path=<dir>[,readonly=on|off][,cache=auto|always|none][,uid=<n>][,gid=<n>]";
    /// The longest tag, which is the length of the config-space field.
    pub const MAX_TAG_LEN: usize = 36;

    /// Returns the export `spec` describes, in the syntax of
    /// [`SYNTAX`](Self::SYNTAX).
    ///
    /// The `socket=` form is Cloud Hypervisor's `--fs`, with its defaults.
    /// The `path=` form takes what only hvi's own server can honor. A
    /// `path=` is returned as given; resolving it is the caller's.
    ///
    /// # Errors
    ///
    /// Errors on a missing tag, on neither or both of `path` and `socket`, on
    /// a key that is unknown, repeated or belongs to the other form, on a tag
    /// that is empty, longer than 36 bytes or holds a NUL, and on a value a
    /// key cannot take.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let bad = |why: String| format!("--fs {spec:?}: {why}; expected {}", Self::SYNTAX);
        let fields = key_values(
            spec,
            &[
                "tag",
                "socket",
                "num_queues",
                "queue_size",
                "path",
                "readonly",
                "cache",
                "uid",
                "gid",
            ],
            bad,
        )?;
        let get = |key: &str| fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);

        let tag = get("tag").ok_or_else(|| bad("no tag".into()))?;
        if tag.is_empty() || tag.len() > Self::MAX_TAG_LEN || tag.contains('\0') {
            return Err(bad(format!(
                "the tag must be 1 to {} bytes with no NUL",
                Self::MAX_TAG_LEN
            )));
        }
        let (path, socket) = (
            get("path").filter(|v| !v.is_empty()),
            get("socket").filter(|v| !v.is_empty()),
        );
        // A key of the other form says the caller expects hvi to do something
        // the form cannot do, so it is refused rather than ignored.
        let other = |keys: &[&str], form: &str, why: &str| -> Result<(), String> {
            match keys.iter().find(|key| get(key).is_some()) {
                Some(key) => Err(bad(format!(
                    "{key} does not apply to a {form} export: {why}"
                ))),
                None => Ok(()),
            }
        };
        match (path, socket) {
            (Some(_), Some(_)) => Err(bad("path and socket are two kinds of export".into())),
            (None, None) => Err(bad("no path or socket".into())),
            (None, Some(socket)) => {
                other(
                    &["readonly", "cache", "uid", "gid"],
                    "socket",
                    "the daemon decides the mode, the cache and the ownership \
                     (for virtiofsd: --readonly, --cache, --translate-uid, --translate-gid)",
                )?;
                let num_queues = match get("num_queues") {
                    None => FsConfig::DEFAULT_NUM_QUEUES,
                    Some(n) => n
                        .parse()
                        .map_err(|_| bad(format!("num_queues {n:?} is not a count")))?,
                };
                let queue_size = match get("queue_size") {
                    None => FsConfig::DEFAULT_QUEUE_SIZE,
                    Some(n) => n.parse().map_err(|_| {
                        bad(format!(
                            "queue_size {n:?} is not a power of two up to {}",
                            FsConfig::MAX_QUEUE_SIZE
                        ))
                    })?,
                };
                let fs = FsConfig {
                    tag: tag.to_string(),
                    socket: PathBuf::from(socket),
                    num_queues,
                    queue_size,
                };
                fs.validate().map_err(bad)?;
                Ok(Self::Socket(fs))
            }
            (Some(path), None) => {
                other(
                    &["num_queues", "queue_size"],
                    "path",
                    "hvi serves it on one request queue of its own size",
                )?;
                let mode = match get("readonly") {
                    None | Some("off") => ShareMode::ReadWrite,
                    Some("on") => ShareMode::ReadOnly,
                    Some(v) => return Err(bad(format!("readonly {v:?} is not on or off"))),
                };
                let cache = match get("cache") {
                    None | Some("auto") => CachePolicy::Auto,
                    Some("always") => CachePolicy::Always,
                    Some("none") => CachePolicy::None,
                    Some(v) => return Err(bad(format!("cache {v:?} is not auto, always or none"))),
                };
                let id = |key: &str| -> Result<u32, String> {
                    get(key).map_or(Ok(0), |v| {
                        v.parse()
                            .map_err(|_| bad(format!("{key} {v:?} is not a numeric id")))
                    })
                };
                Ok(Self::Share(FsShare {
                    path: PathBuf::from(path),
                    tag: tag.to_string(),
                    mode,
                    cache,
                    uid: id("uid")?,
                    gid: id("gid")?,
                }))
            }
        }
    }
}

/// Refuses exports the guest could not tell apart or use.
///
/// The tag is the whole of what a guest has to name an export by, so a
/// duplicate makes one of the two unreachable, and which one depends on the
/// order the guest probes its devices in. A request queue beyond the guest's
/// `vcpus` has no vCPU to submit on it, which Cloud Hypervisor refuses too.
///
/// # Errors
///
/// Returns the tag when an export fails [`FsConfig::validate`], when two
/// exports carry it, or when an export asks for more request queues than the
/// guest has vCPUs.
pub fn check_fs(exports: &[FsConfig], vcpus: u32) -> Result<(), String> {
    let mut seen = std::collections::HashSet::with_capacity(exports.len());
    for export in exports {
        export
            .validate()
            .map_err(|e| format!("virtio-fs {:?}: {e}", export.tag))?;
        if !seen.insert(export.tag.as_str()) {
            return Err(format!("duplicate virtio-fs tag {:?}", export.tag));
        }
        if export.num_queues > vcpus as usize {
            return Err(format!(
                "virtio-fs {:?}: num_queues={} is more than the guest's {vcpus} vCPU(s)",
                export.tag, export.num_queues
            ));
        }
    }
    Ok(())
}

/// Refuses two exports of the same host subtree that disagree on whether the
/// guest may write it.
///
/// A read-only export is a statement about the host directory, not about the
/// tag: a guest that mounts both tags reaches the same inodes either way, and
/// through the writable one it writes them. Read-only then means nothing,
/// which is worse than not offering it, so a boot that asks for both does not
/// start. On macOS the Seatbelt profile says the same thing out loud -- a
/// writable grant on a parent subsumes the read-only grant on its child.
///
/// Nesting with the same mode is left alone: two writable views of one tree,
/// or two read-only ones, promise the guest nothing they do not deliver.
///
/// Paths are canonicalized first, so two spellings of one directory compare
/// equal, and then compared component-wise, so `/srv/ab` is not inside
/// `/srv/a`.
///
/// # Errors
///
/// Returns the pair and their modes when one export is the same directory as
/// another, or sits underneath it, and the two disagree on write permission.
pub fn check_export_overlap(shares: &[FsShare]) -> Result<(), String> {
    // A path that does not resolve is not this check's to report: the backend
    // opens it a moment later and fails with the real reason. Compare what was
    // asked for instead.
    // Export roots, resolved once before any guest runs; see clippy.toml.
    #[allow(clippy::disallowed_methods)]
    let roots: Vec<PathBuf> = shares
        .iter()
        .map(|share| std::fs::canonicalize(&share.path).unwrap_or_else(|_| share.path.clone()))
        .collect();
    let name = |m: ShareMode| if m.writable() { "rw" } else { "ro" };
    for (i, a) in shares.iter().enumerate() {
        for (j, b) in shares.iter().enumerate().skip(i + 1) {
            if a.mode == b.mode {
                continue;
            }
            // `starts_with` is true for equal paths, which would otherwise
            // read as a directory nested inside itself.
            if roots[i] == roots[j] {
                return Err(format!(
                    "exports {} (tag {:?}, {}) and {} (tag {:?}, {}) are the \
                     same host directory and disagree on write permission",
                    a.path.display(),
                    a.tag,
                    name(a.mode),
                    b.path.display(),
                    b.tag,
                    name(b.mode),
                ));
            }
            let nested = if roots[i].starts_with(&roots[j]) {
                Some((a, b))
            } else if roots[j].starts_with(&roots[i]) {
                Some((b, a))
            } else {
                None
            };
            if let Some((inner, outer)) = nested {
                return Err(format!(
                    "export {} (tag {:?}, {}) is nested inside export {} (tag \
                     {:?}, {}): overlapping exports with conflicting write \
                     permission are refused",
                    inner.path.display(),
                    inner.tag,
                    name(inner.mode),
                    outer.path.display(),
                    outer.tag,
                    name(outer.mode),
                ));
            }
        }
    }
    Ok(())
}

/// Most virtio-blk disks one guest can have.
///
/// Each disk is its own virtio-mmio device with its own window and interrupt,
/// and every backend reserves exactly this many slots for them (see
/// `virtio_blk_base` in each architecture's layout module).
pub const MAX_DISKS: usize = 4;

/// One host file or block device backing a virtio-blk disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskConfig {
    /// Host path of the image file or block device.
    pub path: String,
    /// Whether the disk is read-only.
    ///
    /// A read-only disk is opened `O_RDONLY` and advertised to the guest with
    /// `VIRTIO_BLK_F_RO`. A write the guest sends anyway fails with an I/O
    /// error.
    pub read_only: bool,
    /// The serial the disk answers `GET_ID` with, or `None` for [`disk_serial`]
    /// of its position.
    ///
    /// The guest reads it from `/sys/block/vdX/serial`, so an initrd finds a
    /// disk by a name the caller chose.
    pub serial: Option<String>,
}

impl DiskConfig {
    /// The syntax [`parse`](Self::parse) takes, for an error to quote.
    pub const SYNTAX: &'static str = "<path> or path=<path>[,readonly=on|off][,serial=<id>]";
    /// The longest serial, which is the length of the `GET_ID` field.
    pub const MAX_SERIAL_LEN: usize = crate::devices::virtio::block::SERIAL_LEN;

    /// Returns a writable disk backed by `path`, with the default serial.
    #[must_use]
    pub fn rw(path: impl Into<String>) -> Self {
        DiskConfig {
            path: path.into(),
            read_only: false,
            serial: None,
        }
    }

    /// Returns a read-only disk backed by `path`, with the default serial.
    #[must_use]
    pub fn ro(path: impl Into<String>) -> Self {
        DiskConfig {
            path: path.into(),
            read_only: true,
            serial: None,
        }
    }

    /// Returns the disk `spec` describes, in the syntax of
    /// [`SYNTAX`](Self::SYNTAX).
    ///
    /// A spec that does not start with `path=` is a bare path, so a file whose
    /// name holds `=` or `,` still attaches. The `path=` form is Cloud
    /// Hypervisor's `--disk`.
    ///
    /// # Errors
    ///
    /// Errors on an empty path, on a key that is unknown or repeated, on a
    /// `readonly` that is not `on` or `off`, and on a serial that is empty,
    /// longer than 20 bytes, or holds a byte outside printable ASCII.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let bad = |why: String| format!("--disk {spec:?}: {why}; expected {}", Self::SYNTAX);
        if !spec.starts_with("path=") {
            if spec.is_empty() {
                return Err(bad("no path".into()));
            }
            return Ok(Self::rw(spec));
        }
        let fields = key_values(spec, &["path", "readonly", "serial"], bad)?;
        let get = |key: &str| fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
        let path = get("path").filter(|v| !v.is_empty());
        let path = path.ok_or_else(|| bad("no path".into()))?;
        let read_only = match get("readonly") {
            None | Some("off") => false,
            Some("on") => true,
            Some(other) => return Err(bad(format!("readonly {other:?} is not on or off"))),
        };
        let serial = match get("serial") {
            None => None,
            Some(serial) => {
                check_serial(serial).map_err(bad)?;
                Some(serial.to_string())
            }
        };
        Ok(DiskConfig {
            path: path.to_string(),
            read_only,
            serial,
        })
    }

    /// Returns the serial of this disk at position `index` in
    /// [`BootConfig::disks`]: the one the caller set, or [`disk_serial`].
    #[must_use]
    pub fn serial_at(&self, index: usize) -> String {
        self.serial.clone().unwrap_or_else(|| disk_serial(index))
    }
}

/// Returns the virtio-blk serial of the disk at `index` in
/// [`BootConfig::disks`] when the caller set none.
///
/// The guest reads it from `/sys/block/vdX/serial`. The `vdX` letter follows
/// probe order, so the serial is the stable way to find a disk in the guest.
#[must_use]
pub fn disk_serial(index: usize) -> String {
    format!("disk{index}")
}

/// Refuses a serial the `GET_ID` field cannot carry or a guest cannot read back
/// as given.
fn check_serial(serial: &str) -> Result<(), String> {
    if serial.is_empty() || serial.len() > DiskConfig::MAX_SERIAL_LEN {
        return Err(format!(
            "the serial must be 1 to {} bytes",
            DiskConfig::MAX_SERIAL_LEN
        ));
    }
    if !serial.bytes().all(|b| (b' '..=b'~').contains(&b)) {
        return Err("the serial must be printable ASCII".into());
    }
    Ok(())
}

/// Refuses a disk list no backend can attach.
///
/// Every caller's list passes here, the CLI's after it parsed the arguments and
/// a library caller's in `open_disks`, so a serial set without
/// [`DiskConfig::parse`] is checked too.
///
/// # Errors
///
/// Returns a message naming the limit when there are more than [`MAX_DISKS`],
/// the disk whose serial the `GET_ID` field cannot carry, and the serial when
/// two disks would answer `GET_ID` the same way, which is what the serial is
/// for.
pub fn check_disks(disks: &[DiskConfig]) -> Result<(), String> {
    if disks.len() > MAX_DISKS {
        return Err(format!(
            "{} disks given; at most {MAX_DISKS} fit",
            disks.len()
        ));
    }
    for (index, disk) in disks.iter().enumerate() {
        if let Some(serial) = &disk.serial {
            check_serial(serial).map_err(|why| format!("disk {index} ({}): {why}", disk.path))?;
        }
    }
    let serials: Vec<String> = disks
        .iter()
        .enumerate()
        .map(|(index, disk)| disk.serial_at(index))
        .collect();
    for (index, serial) in serials.iter().enumerate() {
        if serials[..index].contains(serial) {
            return Err(format!(
                "two disks carry the serial {serial:?}; give one a serial= of its own"
            ));
        }
    }
    Ok(())
}

/// Inputs for a boot, which [`boot`](crate::boot) takes.
pub struct BootConfig {
    pub kernel: Vec<u8>,
    pub initramfs: Option<Vec<u8>>,
    pub mem_bytes: u64,
    pub cmdline: String,
    /// virtio-blk disks, at most [`MAX_DISKS`], in the order the guest sees
    /// them. The disk at index `N` answers `GET_ID` with its serial, or
    /// [`disk_serial`]`(N)` when it has none.
    pub disks: Vec<DiskConfig>,
    /// Unpacked directories shared with the guest through independent
    /// virtio-fs devices. The Linux guest mounts each by `tag`; no block images
    /// are involved. Access is enforced independently for every export.
    pub fs_shares: Vec<FsShare>,
    /// virtio-fs exports served by vhost-user daemons the caller runs, one
    /// device each. Only the Linux backends serve these, and only these.
    pub fs: Vec<FsConfig>,
    pub net: bool,
    /// When set, virtio-net relays frames to this gvisor-tap-vsock gateway QEMU
    /// stream socket (real egress) instead of the built-in user-space stack.
    pub net_gateway: Option<String>,
    /// Existing tap device to attach to (Linux). urunc creates it in the
    /// container netns and redirects the veth to it, so the guest gets the
    /// container's own network identity rather than a private stack.
    pub net_tap: Option<String>,
    /// MAC the guest NIC presents, on whichever backend the run selects.
    ///
    /// A tap needs it because a tc mirred redirect carries the veth's
    /// destination MAC, so the guest must answer to that address. A gateway
    /// needs it to tell two guests apart, since it keys DHCP leases by MAC.
    /// The built-in stub frames its synthesized replies to it.
    pub net_mac: Option<[u8; 6]>,
    /// The path of the `RawEvent` ledger, or `None` for no ledger.
    ///
    /// A file already at the path must be a regular file that no other ledger
    /// is writing. The last component of the path cannot be a symbolic link.
    pub events: Option<String>,
    pub sandbox_id: String,
    /// Number of vCPUs (>= 1).
    pub vcpus: u32,
    /// Host Unix-socket path bridged to the guest agent's vsock port (exec).
    pub agent_sock: Option<String>,
    /// Path the machine profile is written to, as one line of canonical JSON
    /// (see [`crate::checkpoint::profile`]).
    ///
    /// The file is created before confinement, which forbids creating one
    /// later, and written once the profile is complete: before the guest starts
    /// on KVM, and on hvf by the boot vCPU before the guest's first
    /// instruction, since only a vCPU's own thread can read `MIDR_EL1` there.
    /// A reader that finds the file empty waits, or asks the control socket.
    pub profile_out: Option<String>,
    /// Host Unix-socket path of the control socket, which pauses, resumes,
    /// reports and stops the VM (see [`crate::checkpoint::control`]).
    ///
    /// It is bound before confinement, as the agent socket is.
    pub control_sock: Option<String>,
    /// The directory a `checkpoint` on the control socket may write its
    /// bundle under, or `None` to refuse every `checkpoint`.
    ///
    /// It must exist, and should be private to this sandbox: mode 0700, never
    /// shared, since a bundle holds guest RAM in clear. It is resolved before
    /// confinement. On macOS a Seatbelt subtree rule holds every write to it
    /// and the writable shares. On Linux the control socket's thread gets a
    /// seccomp filter of its own with the file calls a bundle needs, but
    /// seccomp cannot filter paths: that thread can write wherever the uid
    /// can, and only hvi's own path check keeps bundles below the root. It
    /// needs `control_sock`.
    pub checkpoint_root: Option<String>,
    /// A plugin attached to this guest, or `None` to run it with none.
    ///
    /// This is the whole of the VMM's observation surface: see
    /// [`crate::plugin`]. The `hvi` binary sets it only for `--dump-memory`
    /// and `--trace-io`, which it chains into a single plugin; with neither
    /// flag it stays `None`. Any other plugin comes from a caller that links
    /// this crate as a library.
    pub plugin: Option<std::sync::Arc<dyn crate::plugin::Plugin>>,
    /// Whether the VMM process is confined before it services any guest I/O, by
    /// a Seatbelt profile on macOS (`sandbox::seatbelt`) or seccomp-bpf
    /// allowlists on Linux (`sandbox::seccomp`).
    ///
    /// Neither module is an intra-doc link, because each is compiled only on
    /// its own OS and the link would dangle on every other target. It is on by
    /// default, and `--no-sandbox` clears it, for debugging a run the
    /// confinement breaks. Once the sandbox is on in the process, it stays on,
    /// and [`boot`](crate::boot) refuses a run with it off and, on macOS, any
    /// later run. The backend logs which one it installed, so this is never a
    /// silent "sandboxed" claim on a host that is not.
    pub sandbox: bool,
    /// The registration of the [`StopHandle`](crate::run::StopHandle) that asks
    /// this run to stop from outside the guest, or `None` when the caller keeps
    /// no handle.
    ///
    /// See [`crate::run`].
    pub stop: Option<crate::run::StopRegistration>,
}

impl BootConfig {
    /// Takes the run's stop out of [`stop`](Self::stop) as a handle, or returns
    /// a new handle when it is `None`.
    ///
    /// # Errors
    ///
    /// Errors if a new handle cannot be created.
    pub(crate) fn take_stop_handle(&mut self) -> std::io::Result<crate::run::StopHandle> {
        match self.stop.take() {
            Some(registration) => Ok(registration.into_handle()),
            None => Ok(crate::run::StopHandle::new_pair()?.0),
        }
    }
}

/// Inputs for a restore: `hvi restore`, which resumes a checkpoint bundle in
/// this process instead of booting a kernel. Populated by
/// `main::restore_guest` and handed to the active backend's `restore()`.
///
/// The machine comes from the bundle: its RAM, vCPUs, devices and their
/// state. What it needs from this host comes from here, and must agree with
/// the bundle: a disk of the size the guest was given when it had one, a
/// network of the mode it ran on when it had one, and an agent socket when it
/// had a vsock device.
pub struct RestoreConfig {
    /// The bundle directory.
    pub from: String,
    /// The control socket, bound before confinement. The guest waits
    /// restored-paused until a client sends `resume` on it.
    pub control_sock: String,
    /// The directory a later `checkpoint` may write under; see
    /// [`BootConfig::checkpoint_root`].
    pub checkpoint_root: Option<String>,
    /// The disk image to reopen for the guest's virtio-blk device, in
    /// `--disk`'s syntax. A checkpoint carries one writable disk, and the
    /// restored disk answers `GET_ID` with the serial the bundle records, so
    /// a `serial` here must be that one, and `read_only` is refused.
    pub disk: Option<DiskConfig>,
    /// The built-in network stack, for a guest that ran on it.
    pub net: bool,
    /// The gateway stream socket, for a guest that ran on a gateway.
    pub net_gateway: Option<String>,
    /// The MAC the guest was given. Optional, since the bundle holds it; a
    /// MAC given here must be that one.
    pub net_mac: Option<[u8; 6]>,
    /// The agent socket, for a guest that had a vsock device.
    pub agent_sock: Option<String>,
    /// The sandbox id, or `None` for the one the bundle was captured under.
    pub sandbox_id: Option<String>,
    /// The event ledger path.
    pub events: Option<String>,
    /// Where to write this machine's profile; see [`BootConfig::profile_out`].
    pub profile_out: Option<String>,
    /// Confine the process, as [`BootConfig::sandbox`].
    pub sandbox: bool,
}

/// Why the run stopped.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Stop {
    /// A power-off by the guest.
    SystemOff,
    /// A reset by the guest, which is not restarted.
    SystemReset,
    /// The host asked the run to stop, through a
    /// [`StopHandle`](crate::run::StopHandle), or the control socket's `stop`
    /// op ended it.
    Requested,
}

/// The error [`boot`](crate::boot) returns.
///
/// It carries the error that failed the run, which says what failed, such as a
/// vCPU or a thread and how it failed. Its message is that error's, and it
/// names any thread the run left running. [`get_ref`](Self::get_ref) returns
/// the carried error, which a caller can downcast to the type it expects, and
/// [`source`](std::error::Error::source) returns what caused it, when anything
/// did.
#[derive(Debug)]
pub struct BootError {
    /// The error that failed the run.
    error: Box<dyn std::error::Error + Send + Sync>,
    /// The thread the run left running, when the error does not name it.
    left_running: Option<String>,
}

impl BootError {
    /// Returns a `BootError` that carries `error`.
    ///
    /// The error of a run that left a thread running is taken apart, so the
    /// error that failed the run is the one carried.
    pub(crate) fn new(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        match error.downcast::<crate::run::LeftRunning>() {
            Ok(left) => BootError {
                error: left.error,
                left_running: left.left.map(|left| left.to_string()),
            },
            Err(error) => BootError {
                error,
                left_running: None,
            },
        }
    }

    /// Returns the error this one carries.
    #[must_use]
    pub fn get_ref(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        &*self.error
    }

    /// Returns the error this one carries, consuming it.
    #[must_use]
    pub fn into_inner(self) -> Box<dyn std::error::Error + Send + Sync> {
        self.error
    }
}

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.left_running {
            Some(left) => write!(f, "{}, and {left}", self.error),
            None => fmt::Display::fmt(&self.error, f),
        }
    }
}

impl std::error::Error for BootError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::{
        check_disks, check_export_overlap, check_fs, disk_serial, BootError, CachePolicy,
        DiskConfig, FsConfig, FsShare, FsSpec, ShareMode, MAX_DISKS,
    };
    use crate::hypervisor::vcpus::Outcome;
    use std::path::{Path, PathBuf};

    fn shares(pairs: &[(&str, ShareMode)]) -> Vec<FsShare> {
        pairs
            .iter()
            .enumerate()
            .map(|(i, (path, mode))| FsShare {
                path: PathBuf::from(path),
                tag: format!("tag{i}"),
                mode: *mode,
                cache: CachePolicy::Auto,
                uid: 0,
                gid: 0,
            })
            .collect()
    }

    #[test]
    fn read_only_export_inside_a_writable_one_is_refused() {
        let err = check_export_overlap(&shares(&[
            ("/srv/root", ShareMode::ReadWrite),
            ("/srv/root/etc", ShareMode::ReadOnly),
        ]))
        .unwrap_err();
        assert!(
            err.contains("/srv/root/etc (tag \"tag1\", ro) is nested inside"),
            "{err}"
        );
        assert!(err.contains("/srv/root (tag \"tag0\", rw)"), "{err}");
    }

    #[test]
    fn writable_export_inside_a_read_only_one_is_refused() {
        let err = check_export_overlap(&shares(&[
            ("/srv/root", ShareMode::ReadOnly),
            ("/srv/root/var", ShareMode::ReadWrite),
        ]))
        .unwrap_err();
        assert!(
            err.contains("/srv/root/var (tag \"tag1\", rw) is nested inside"),
            "{err}"
        );
        assert!(err.contains("/srv/root (tag \"tag0\", ro)"), "{err}");
    }

    /// `Path::starts_with` is true of a path and itself, so the nesting arm
    /// would describe a directory as sitting inside itself. Equal paths get
    /// their own sentence.
    #[test]
    fn one_directory_exported_twice_with_different_modes_is_refused() {
        let err = check_export_overlap(&shares(&[
            ("/srv/root", ShareMode::ReadWrite),
            ("/srv/root", ShareMode::ReadOnly),
        ]))
        .unwrap_err();
        assert!(err.contains("are the same host directory"), "{err}");
        assert!(!err.contains("nested inside"), "{err}");
    }

    /// An embedder reaches `boot` without going through the argument parser,
    /// so the two exports need not be spelled the same way. Canonicalizing
    /// first is what makes a symlink and its target one directory here.
    #[test]
    fn two_spellings_of_one_directory_are_refused() {
        let dir = std::env::temp_dir().join(format!("hvi-overlap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();

        let err = check_export_overlap(&[
            FsShare {
                path: dir.join("real"),
                tag: "real".into(),
                mode: ShareMode::ReadWrite,
                cache: CachePolicy::Auto,
                uid: 0,
                gid: 0,
            },
            FsShare {
                path: dir.join("link"),
                tag: "link".into(),
                mode: ShareMode::ReadOnly,
                cache: CachePolicy::Auto,
                uid: 0,
                gid: 0,
            },
        ])
        .unwrap_err();
        assert!(err.contains("are the same host directory"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nesting_with_the_same_mode_is_allowed() {
        check_export_overlap(&shares(&[
            ("/srv/root", ShareMode::ReadWrite),
            ("/srv/root/var", ShareMode::ReadWrite),
        ]))
        .expect("two writable views of one tree stay allowed");
        check_export_overlap(&shares(&[
            ("/srv/root", ShareMode::ReadOnly),
            ("/srv/root/var", ShareMode::ReadOnly),
        ]))
        .expect("two read-only views of one tree stay allowed");
    }

    #[test]
    fn exports_that_share_no_subtree_are_allowed() {
        check_export_overlap(&shares(&[
            ("/srv/root", ShareMode::ReadWrite),
            ("/srv/other", ShareMode::ReadOnly),
            ("/tmp/payload", ShareMode::ReadWrite),
        ]))
        .expect("exports that share no subtree are unrelated");
    }

    /// Component-wise, not textually: `/srv/ab` is a sibling of `/srv/a`.
    #[test]
    fn shared_name_prefix_is_not_nesting() {
        check_export_overlap(&shares(&[
            ("/srv/ab", ShareMode::ReadWrite),
            ("/srv/a", ShareMode::ReadOnly),
        ]))
        .expect("/srv/ab is a sibling of /srv/a, not a child");
        assert!(!Path::new("/srv/ab").starts_with("/srv/a"));
    }

    #[test]
    fn five_disks_are_refused() {
        let mut disks: Vec<DiskConfig> = (0..MAX_DISKS)
            .map(|i| DiskConfig::rw(format!("d{i}.img")))
            .collect();
        check_disks(&disks).expect("four disks fit");
        disks.push(DiskConfig::ro("e.img"));
        let err = check_disks(&disks).unwrap_err();
        assert!(err.contains("at most 4"), "{err}");
    }

    #[test]
    fn default_serials_fit_the_virtio_blk_id_field() {
        assert_eq!(disk_serial(0), "disk0");
        assert_eq!(disk_serial(3), "disk3");
        // VIRTIO_BLK_ID_BYTES.
        assert!(disk_serial(MAX_DISKS - 1).len() <= DiskConfig::MAX_SERIAL_LEN);
        assert_eq!(DiskConfig::rw("a.img").serial_at(2), "disk2");
        let named = DiskConfig::parse("path=a.img,serial=lower").unwrap();
        assert_eq!(named.serial_at(2), "lower");
    }

    #[test]
    fn disk_specs_take_a_bare_path_or_cloud_hypervisor_keys() {
        assert_eq!(
            DiskConfig::parse("up.img").unwrap(),
            DiskConfig::rw("up.img")
        );
        // A bare path keeps every byte, even ones the keyed form would split.
        assert_eq!(
            DiskConfig::parse("a=b,c.img").unwrap(),
            DiskConfig::rw("a=b,c.img")
        );
        assert_eq!(
            DiskConfig::parse("path=lo.img,readonly=on,serial=lower").unwrap(),
            DiskConfig {
                path: "lo.img".into(),
                read_only: true,
                serial: Some("lower".into()),
            }
        );
        assert_eq!(
            DiskConfig::parse("path=up.img,readonly=off").unwrap(),
            DiskConfig::rw("up.img")
        );
        for (spec, why) in [
            ("", "no path"),
            ("path=", "no path"),
            ("path=a.img,ro=on", "unknown key"),
            ("path=a.img,path=b.img", "given twice"),
            ("path=a.img,readonly=yes", "not on or off"),
            ("path=a.img,serial=", "1 to 20 bytes"),
            ("path=a.img,serial=abcdefghijklmnopqrstu", "1 to 20 bytes"),
            ("path=a.img,serial=\u{2603}", "printable ASCII"),
        ] {
            let err = DiskConfig::parse(spec).unwrap_err();
            assert!(err.contains(why), "{spec:?}: {err}");
            assert!(err.contains(DiskConfig::SYNTAX), "{spec:?}: {err}");
        }
    }

    // The serial is how the guest tells the disks apart, so two alike are
    // refused whether the caller set them or a default collided with one.
    #[test]
    fn two_disks_may_not_share_a_serial() {
        let disks = [
            DiskConfig::parse("path=a.img,serial=lower").unwrap(),
            DiskConfig::parse("path=b.img,serial=lower").unwrap(),
        ];
        let err = check_disks(&disks).unwrap_err();
        assert!(err.contains("\"lower\""), "{err}");
        let disks = [
            DiskConfig::rw("a.img"),
            DiskConfig::parse("path=b.img,serial=disk0").unwrap(),
        ];
        let err = check_disks(&disks).unwrap_err();
        assert!(err.contains("\"disk0\""), "{err}");
        let disks = [
            DiskConfig::parse("path=a.img,serial=lower").unwrap(),
            DiskConfig::rw("b.img"),
        ];
        check_disks(&disks).expect("lower and disk1 differ");
    }

    // A library caller builds the struct without `parse`, so the list check is
    // where a serial it set is checked.
    #[test]
    fn check_disks_checks_a_serial_set_without_parse() {
        for serial in ["", "lower\0a", "abcdefghijklmnopqrstu"] {
            let disks = [DiskConfig {
                path: "a.img".into(),
                read_only: false,
                serial: Some(serial.into()),
            }];
            let err = check_disks(&disks).unwrap_err();
            assert!(
                err.starts_with("disk 0 (a.img): the serial"),
                "{serial:?}: {err}"
            );
        }
    }

    #[test]
    fn single_export_never_conflicts_with_itself() {
        check_export_overlap(&shares(&[("/srv/root", ShareMode::ReadWrite)]))
            .expect("one export is fine");
        check_export_overlap(&[]).expect("no exports at all is fine");
    }

    #[test]
    fn boot_error_reads_as_the_failure_it_carries() {
        let failure = Outcome::Failed("vcpu1: KVM internal error".to_string())
            .into_result()
            .unwrap_err();
        let error = BootError::new(failure);
        assert_eq!(error.to_string(), "vcpu1: KVM internal error");
        assert!(std::error::Error::source(&error).is_none());
    }

    /// A failure with a cause, as an error from a step `boot` takes.
    #[derive(Debug)]
    struct Setup(std::io::Error);

    impl std::fmt::Display for Setup {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "opening /dev/kvm: {}", self.0)
        }
    }

    impl std::error::Error for Setup {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn boot_error_hands_back_the_error_it_carries() {
        let cause = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let error = BootError::new(Box::new(Setup(cause)));
        let source = std::error::Error::source(&error).expect("the carried error's cause");
        let cause = source
            .downcast_ref::<std::io::Error>()
            .expect("an io::Error");
        assert_eq!(cause.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.get_ref().downcast_ref::<Setup>().is_some());
        assert!(error.into_inner().downcast::<Setup>().is_ok());
    }

    #[test]
    fn boot_error_keeps_the_failure_typed_beside_a_thread_left_running() {
        let failure = std::io::Error::from(std::io::ErrorKind::WouldBlock);
        let left = std::io::Error::other("vcpu1 did not stop within 1s");
        let error = BootError::new(Box::new(crate::run::LeftRunning {
            error: Box::new(failure),
            left: Some(left),
        }));
        assert!(error
            .to_string()
            .ends_with(", and vcpu1 did not stop within 1s"));
        let failure = error
            .get_ref()
            .downcast_ref::<std::io::Error>()
            .expect("an io::Error");
        assert_eq!(failure.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn boot_error_converts_and_crosses_threads() {
        fn caller() -> Result<(), Box<dyn std::error::Error>> {
            let failed: Result<(), BootError> = Err(BootError::new("vcpu0: failed".into()));
            failed?;
            Ok(())
        }
        assert_eq!(caller().unwrap_err().to_string(), "vcpu0: failed");
        let error = std::thread::spawn(|| BootError::new("vcpu0: failed".into()))
            .join()
            .unwrap();
        assert_eq!(error.to_string(), "vcpu0: failed");
    }

    /// Returns the socket export `spec` parses to.
    fn socket(spec: &str) -> FsConfig {
        match FsSpec::parse(spec).unwrap() {
            FsSpec::Socket(fs) => fs,
            other => panic!("{spec}: {other:?}"),
        }
    }

    /// Returns the directory export `spec` parses to.
    fn share(spec: &str) -> FsShare {
        match FsSpec::parse(spec).unwrap() {
            FsSpec::Share(fs) => fs,
            other => panic!("{spec}: {other:?}"),
        }
    }

    #[test]
    fn fs_socket_takes_cloud_hypervisors_syntax_and_defaults() {
        assert_eq!(
            socket("tag=fs0,socket=/run/fs0.sock"),
            FsConfig {
                tag: "fs0".into(),
                socket: PathBuf::from("/run/fs0.sock"),
                num_queues: 1,
                queue_size: 1024,
            }
        );
        let fs = socket("socket=/s,queue_size=256,tag=t,num_queues=2");
        assert_eq!((fs.num_queues, fs.queue_size), (2, 256));
        assert_eq!(socket("tag=t,socket=/s,queue_size=32768").queue_size, 32768);
    }

    #[test]
    fn fs_path_takes_mode_cache_and_ids() {
        assert_eq!(
            share("tag=src,path=/srv/src"),
            FsShare {
                path: PathBuf::from("/srv/src"),
                tag: "src".into(),
                mode: ShareMode::ReadWrite,
                cache: CachePolicy::Auto,
                uid: 0,
                gid: 0,
            }
        );
        let fs = share("tag=t,path=/p,readonly=on,cache=none,uid=1000,gid=100");
        assert_eq!(fs.mode, ShareMode::ReadOnly);
        assert_eq!(fs.cache, CachePolicy::None);
        assert_eq!((fs.uid, fs.gid), (1000, 100));
        assert_eq!(
            share("tag=t,path=/p,readonly=off").mode,
            ShareMode::ReadWrite
        );
        assert_eq!(
            share("tag=t,path=/p,cache=always").cache,
            CachePolicy::Always
        );
    }

    #[test]
    fn fs_spec_refuses_what_it_cannot_serve() {
        let tag37 = format!("tag={},path=/p", "t".repeat(37));
        for (spec, why) in [
            ("path=/p", "no tag"),
            ("tag=t", "no path"),
            ("tag=t,path=", "no path"),
            ("tag=t,socket=", "no path or socket"),
            (
                "tag=t,path=/p,socket=/s",
                "path and socket are two kinds of export",
            ),
            ("tag=,path=/p", "the tag must be"),
            (tag37.as_str(), "the tag must be"),
            ("tag=t,path=/p,ro=on", "unknown key \"ro\""),
            ("tag=t,tag=u,path=/p", "tag given twice"),
            ("tag=t,socket=/s,num_queues=0", "num_queues=0"),
            ("tag=t,socket=/s,num_queues=x", "num_queues \"x\""),
            ("tag=t,socket=/s,queue_size=1000", "queue_size=1000"),
            ("tag=t,socket=/s,queue_size=65536", "queue_size \"65536\""),
            (
                "tag=t,socket=/s,uid=1000",
                "uid does not apply to a socket export",
            ),
            (
                "tag=t,socket=/s,readonly=on",
                "readonly does not apply to a socket export",
            ),
            (
                "tag=t,path=/p,num_queues=2",
                "num_queues does not apply to a path export",
            ),
            (
                "tag=t,path=/p,readonly=yes",
                "readonly \"yes\" is not on or off",
            ),
            ("tag=t,path=/p,cache=sometimes", "cache \"sometimes\""),
            ("tag=t,path=/p,uid=-1", "uid \"-1\" is not a numeric id"),
            ("tag=t,path=/p,ro", "\"ro\" is not key=value"),
        ] {
            let err = FsSpec::parse(spec).expect_err(spec);
            assert!(err.contains(why), "{spec}: {err}");
            assert!(err.contains(FsSpec::SYNTAX), "{spec}: {err}");
        }
    }

    #[test]
    fn two_exports_may_not_share_a_tag() {
        let export = |tag: &str| socket(&format!("tag={tag},socket=/s"));
        check_fs(&[export("a"), export("b")], 1).expect("distinct tags");
        let err = check_fs(&[export("a"), export("a")], 1).expect_err("a duplicate tag");
        assert!(err.contains("\"a\""), "{err}");
    }

    #[test]
    fn an_export_may_not_have_more_queues_than_vcpus() {
        let export = socket("tag=t,socket=/s,num_queues=4");
        check_fs(std::slice::from_ref(&export), 4).expect("one queue per vCPU");
        let err = check_fs(&[export], 2).expect_err("four queues on two vCPUs");
        assert!(err.contains("num_queues=4"), "{err}");
    }

    // A library caller builds FsConfig without the parser. Two 40-byte tags
    // that share their first 36 bytes would reach the guest as one tag twice.
    #[test]
    fn check_fs_refuses_what_the_parser_refuses() {
        let good = socket("tag=t,socket=/s");
        for (export, why) in [
            (
                FsConfig {
                    tag: "t".repeat(40),
                    ..good.clone()
                },
                "the tag must be",
            ),
            (
                FsConfig {
                    tag: "a\0b".into(),
                    ..good.clone()
                },
                "the tag must be",
            ),
            (
                FsConfig {
                    num_queues: 0,
                    ..good.clone()
                },
                "num_queues=0",
            ),
            (
                FsConfig {
                    queue_size: 1000,
                    ..good.clone()
                },
                "queue_size=1000",
            ),
        ] {
            let err = check_fs(&[export], 4).expect_err(why);
            assert!(err.contains(why), "{err}");
        }
    }
}

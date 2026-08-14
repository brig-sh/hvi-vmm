//! Backend-independent boot configuration and result types, shared by the
//! macOS (Hypervisor.framework) and Linux (KVM) machine backends.

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
    /// Metadata cached for a second and page cache retained across opens, with
    /// the guest revalidating on size/mtime change. Matches virtiofsd's
    /// default.
    #[default]
    Auto,
    /// Additionally lets the guest own the page cache for writes, batching them
    /// into large aligned WRITEs. Only correct when the guest is the sole
    /// writer.
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

/// One host directory exported to the guest through virtio-fs.
#[derive(Debug, Clone)]
pub struct FsShare {
    pub path: PathBuf,
    pub tag: String,
    pub mode: ShareMode,
    pub cache: CachePolicy,
}

/// Inputs for a boot. Populated by `main::boot_guest` from the CLI and handed
/// to the active backend's `boot()`.
pub struct BootConfig {
    pub kernel: Vec<u8>,
    pub initramfs: Option<Vec<u8>>,
    pub mem_bytes: u64,
    pub cmdline: String,
    pub disk: Option<String>,
    /// Unpacked directories shared with the guest through independent
    /// virtio-fs devices. The Linux guest mounts each by `tag`; no block images
    /// are involved. Access is enforced independently for every export.
    pub fs_shares: Vec<FsShare>,
    pub net: bool,
    /// When set, virtio-net relays frames to this gvisor-tap-vsock gateway QEMU
    /// stream socket (real egress) instead of the built-in user-space stack.
    pub net_gateway: Option<String>,
    /// Existing tap device to attach to (Linux). urunc creates it in the
    /// container netns and redirects the veth to it, so the guest gets the
    /// container's own network identity rather than a private stack.
    pub net_tap: Option<String>,
    /// MAC the guest NIC presents. With urunc's tc mirred redirect the inbound
    /// frames carry the veth's destination MAC, so the guest has to answer to
    /// that address or every reply is dropped as not-for-us.
    pub net_mac: Option<String>,
    pub events: Option<String>,
    pub sandbox_id: String,
    /// Number of vCPUs (>= 1).
    pub vcpus: u32,
    /// Host Unix-socket path bridged to the guest agent's vsock port (exec).
    pub agent_sock: Option<String>,
    /// A plugin attached to this guest, or `None` to run it with none.
    ///
    /// This is the whole of the VMM's observation surface: see
    /// [`crate::plugin`]. The `hvi` binary never sets it — a plugin comes
    /// from a caller that links this crate as a library.
    pub plugin: Option<std::sync::Arc<dyn crate::plugin::Plugin>>,
    /// Confine the VMM process before it services any guest I/O: a Seatbelt
    /// profile on macOS (the `sandbox` module), seccomp-bpf allowlists on
    /// Linux (the `seccomp` module). Neither is an intra-doc link, because
    /// each module is compiled only on its own OS and the link would dangle
    /// on every other target. On by default; `--no-sandbox` clears it, for
    /// debugging a run the confinement breaks. Both are per-process and
    /// irreversible, and the backend logs which one it installed, so this is
    /// never a silent "sandboxed" claim on a host that is not.
    pub sandbox: bool,
}

/// Why the run stopped.
#[derive(Debug, Clone, Copy)]
pub enum Stop {
    SystemOff,
    SystemReset,
}

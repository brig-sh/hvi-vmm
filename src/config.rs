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
    /// Metadata cached for five seconds on a writable share, and for a minute
    /// on a read-only one, which cannot go stale from the guest's own writes.
    /// The page cache is retained across opens either way, with the guest
    /// revalidating on a size or mtime change. See `WRITABLE_CACHE_SECS` in
    /// `virtio_fs` for where the five comes from.
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

/// One host directory exported to the guest through virtio-fs.
#[derive(Debug, Clone)]
pub struct FsShare {
    pub path: PathBuf,
    pub tag: String,
    pub mode: ShareMode,
    pub cache: CachePolicy,
    /// A vhost-user socket someone else is already serving this export on,
    /// or `None` to start a daemon for it.
    ///
    /// Only the Linux backends read this. The macOS backend serves every
    /// export itself, so a socket there is a configuration error, and the
    /// machine says so before the guest runs.
    pub socket: Option<PathBuf>,
}

/// Refuses two exports that share a mount tag.
///
/// The tag is the whole of what a guest has to name an export by, so a
/// duplicate makes one of the two unreachable, and which one depends on the
/// order the guest probes its devices in.
///
/// # Errors
///
/// Returns the tag when two exports carry it.
pub fn check_unique_tags(shares: &[FsShare]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::with_capacity(shares.len());
    for share in shares {
        if !seen.insert(share.tag.as_str()) {
            return Err(format!("duplicate virtio-fs tag {:?}", share.tag));
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
    /// The `virtiofsd` binary the Linux backends start for an export that
    /// brings no socket of its own, or `None` to look for one.
    ///
    /// The search order is the `virtiofsd` module's, which is compiled only
    /// on Linux, so this is not an intra-doc link.
    pub virtiofsd: Option<PathBuf>,
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
    pub events: Option<String>,
    pub sandbox_id: String,
    /// Number of vCPUs (>= 1).
    pub vcpus: u32,
    /// Host Unix-socket path bridged to the guest agent's vsock port (exec).
    pub agent_sock: Option<String>,
    /// A plugin attached to this guest, or `None` to run it with none.
    ///
    /// This is the whole of the VMM's observation surface: see
    /// [`crate::plugin`]. The `hvi` binary sets it only for `--dump-memory`
    /// and `--trace-io`, which it chains into a single plugin; with neither
    /// flag it stays `None`. Any other plugin comes from a caller that links
    /// this crate as a library.
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

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::{check_export_overlap, check_unique_tags, CachePolicy, FsShare, ShareMode};
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
                socket: None,
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
                socket: None,
            },
            FsShare {
                path: dir.join("link"),
                tag: "link".into(),
                mode: ShareMode::ReadOnly,
                cache: CachePolicy::Auto,
                socket: None,
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
    fn single_export_never_conflicts_with_itself() {
        check_export_overlap(&shares(&[("/srv/root", ShareMode::ReadWrite)]))
            .expect("one export is fine");
        check_export_overlap(&[]).expect("no exports at all is fine");
    }

    #[test]
    fn two_exports_may_not_share_a_tag() {
        let mut shares = shares(&[
            ("/srv/a", ShareMode::ReadOnly),
            ("/srv/b", ShareMode::ReadOnly),
        ]);
        check_unique_tags(&shares).expect("distinct tags");
        shares[1].tag = shares[0].tag.clone();
        let err = check_unique_tags(&shares).expect_err("a duplicate tag");
        assert!(err.contains(&shares[0].tag), "{err}");
    }
}

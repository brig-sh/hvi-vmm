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

/// One host directory exported to the guest through virtio-fs.
#[derive(Debug, Clone)]
pub struct FsShare {
    pub path: PathBuf,
    pub tag: String,
    pub mode: ShareMode,
    pub cache: CachePolicy,
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

/// The machine a guest is given.
///
/// `Native` is the host's own machine: on macOS the in-kernel GICv3 of
/// Hypervisor.framework and the host CPU's feature registers. A portable
/// profile is one machine on every host that implements it, so a guest can
/// move between them; see `docs/portable-profile.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MachineProfileKind {
    /// The host's own machine.
    #[default]
    Native,
    /// `portable-arm64-v1`: a GICv2, a Cortex-A76 identity with a reduced
    /// feature set, PSCI 1.1 and SMCCC 1.1 as KVM on a Pi 5 answers them.
    PortableArm64V1,
}

impl MachineProfileKind {
    /// Returns the profile's name, as `--profile` takes it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::PortableArm64V1 => "portable-arm64-v1",
        }
    }

    /// Returns the profile called `name`.
    ///
    /// # Errors
    ///
    /// Errors when no profile has that name.
    pub fn from_name(name: &str) -> Result<Self, String> {
        [Self::Native, Self::PortableArm64V1]
            .into_iter()
            .find(|p| p.name() == name)
            .ok_or_else(|| {
                format!("unknown machine profile {name:?}; expected native or portable-arm64-v1")
            })
    }
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
    /// Confine the VMM process before it services any guest I/O: a Seatbelt
    /// profile on macOS (`sandbox::seatbelt`), seccomp-bpf allowlists on Linux
    /// (`sandbox::seccomp`). Neither is an intra-doc link, because each module
    /// is compiled only on its own OS and the link would dangle on every other
    /// target. On by default; `--no-sandbox` clears it, for debugging a run the
    /// confinement breaks. Both are per-process and irreversible, and the
    /// backend logs which one it installed, so this is never a silent
    /// "sandboxed" claim on a host that is not.
    pub sandbox: bool,
    /// The machine the guest is given.
    pub profile: MachineProfileKind,
    /// Whether the devicetree gives the architected timer its interrupts, or
    /// `None` for the profile's default.
    ///
    /// The native profile always does. The portable profile does not: its
    /// `/timer` node carries a fixed `clock-frequency` and no interrupts, so
    /// the guest's arch-timer driver takes its rate from the node and
    /// registers no clock event, and the guest's clock and timers come from
    /// `hvi-time`. `Some(true)` there is a debugging aid: the node gets its
    /// four PPIs back, so a guest kernel without the `hvi-time` driver still
    /// ticks. It changes the devicetree, and with it the profile's
    /// `dtb_sha256`.
    pub arch_timer_irq: Option<bool>,
}

impl BootConfig {
    /// Refuses a combination of fields that no backend boots, whichever
    /// one runs. Every backend's `boot` calls it first, so a library
    /// caller gets the same answer as the CLI.
    ///
    /// # Errors
    ///
    /// Errors when `arch_timer_irq` is set on the native profile, or when a
    /// portable profile is given virtio-fs shares.
    pub fn validate(&self) -> Result<(), String> {
        if self.arch_timer_irq.is_some() && self.profile == MachineProfileKind::Native {
            return Err("--arch-timer-irq needs --profile portable-arm64-v1".into());
        }
        if self.profile != MachineProfileKind::Native && !self.fs_shares.is_empty() {
            return Err(format!(
                "--share-ro/--share-rw are not part of --profile {}: a portable guest keeps its storage on virtio-blk",
                self.profile.name()
            ));
        }
        Ok(())
    }

    /// Returns whether the devicetree gives the architected timer its
    /// interrupts: `arch_timer_irq`, or the profile's default.
    #[must_use]
    pub fn arch_timer_irq(&self) -> bool {
        self.arch_timer_irq
            .unwrap_or(self.profile == MachineProfileKind::Native)
    }

    /// Refuses a portable profile on a backend that does not implement one
    /// yet.
    ///
    /// # Errors
    ///
    /// Errors naming `backend` when the profile is not native.
    pub fn require_native_profile(&self, backend: &str) -> Result<(), String> {
        if self.profile == MachineProfileKind::Native {
            return Ok(());
        }
        Err(format!(
            "--profile {} is not implemented on the {backend} backend yet",
            self.profile.name()
        ))
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
    /// The bundle directory, or for a stream a name for it in messages.
    pub from: String,
    /// The streamed bundle to read instead of a directory: `-` for stdin,
    /// or the path of a Unix socket hvi connects to before confinement.
    pub from_stream: Option<String>,
    /// A new directory the stream's documents and manifest are kept in,
    /// without RAM.
    pub stream_keep: Option<String>,
    /// The control socket, bound before confinement. The guest waits
    /// restored-paused until a client sends `resume` on it.
    pub control_sock: String,
    /// The directory a later `checkpoint` may write under; see
    /// [`BootConfig::checkpoint_root`].
    pub checkpoint_root: Option<String>,
    /// The disk image to reopen for the guest's virtio-blk device.
    pub disk: Option<String>,
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
pub enum Stop {
    SystemOff,
    SystemReset,
    /// The control socket's `stop` op ended the run.
    Requested,
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::{
        check_export_overlap, BootConfig, CachePolicy, FsShare, MachineProfileKind, ShareMode,
    };
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
            },
            FsShare {
                path: dir.join("link"),
                tag: "link".into(),
                mode: ShareMode::ReadOnly,
                cache: CachePolicy::Auto,
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

    fn boot_config(profile: MachineProfileKind, arch_timer_irq: Option<bool>) -> BootConfig {
        BootConfig {
            kernel: Vec::new(),
            initramfs: None,
            mem_bytes: 0,
            cmdline: String::new(),
            disk: None,
            fs_shares: Vec::new(),
            net: false,
            net_gateway: None,
            net_tap: None,
            net_mac: None,
            events: None,
            sandbox_id: String::new(),
            vcpus: 1,
            agent_sock: None,
            profile_out: None,
            control_sock: None,
            checkpoint_root: None,
            plugin: None,
            sandbox: false,
            profile,
            arch_timer_irq,
        }
    }

    #[test]
    fn validate_refuses_what_no_backend_boots() {
        use MachineProfileKind::{Native, PortableArm64V1};
        assert_eq!(boot_config(Native, None).validate(), Ok(()));
        assert_eq!(boot_config(PortableArm64V1, None).validate(), Ok(()));
        assert_eq!(boot_config(PortableArm64V1, Some(true)).validate(), Ok(()));
        assert_eq!(boot_config(PortableArm64V1, Some(false)).validate(), Ok(()));
        for timer in [Some(true), Some(false)] {
            assert_eq!(
                boot_config(Native, timer).validate(),
                Err("--arch-timer-irq needs --profile portable-arm64-v1".into())
            );
        }
        let mut cfg = boot_config(PortableArm64V1, None);
        cfg.fs_shares = shares(&[("/srv/a", ShareMode::ReadOnly)]);
        assert!(cfg
            .validate()
            .unwrap_err()
            .contains("--share-ro/--share-rw"));
        let mut cfg = boot_config(Native, None);
        cfg.fs_shares = shares(&[("/srv/a", ShareMode::ReadOnly)]);
        assert_eq!(cfg.validate(), Ok(()));
    }

    /// The portable profile's arch timer has no interrupts unless asked;
    /// the native one always has them.
    #[test]
    fn the_arch_timer_interrupts_follow_the_profile() {
        use MachineProfileKind::{Native, PortableArm64V1};
        assert!(boot_config(Native, None).arch_timer_irq());
        assert!(!boot_config(PortableArm64V1, None).arch_timer_irq());
        assert!(boot_config(PortableArm64V1, Some(true)).arch_timer_irq());
        assert!(!boot_config(PortableArm64V1, Some(false)).arch_timer_irq());
    }

    #[test]
    fn a_backend_without_the_profile_names_the_profile() {
        let cfg = boot_config(MachineProfileKind::PortableArm64V1, None);
        assert_eq!(
            cfg.require_native_profile("KVM"),
            Err("--profile portable-arm64-v1 is not implemented on the KVM backend yet".into())
        );
        assert_eq!(
            boot_config(MachineProfileKind::Native, None).require_native_profile("KVM"),
            Ok(())
        );
    }

    #[test]
    fn profiles_are_found_by_their_names() {
        for p in [
            MachineProfileKind::Native,
            MachineProfileKind::PortableArm64V1,
        ] {
            assert_eq!(MachineProfileKind::from_name(p.name()), Ok(p));
        }
        assert_eq!(MachineProfileKind::default(), MachineProfileKind::Native);
        assert!(MachineProfileKind::from_name("portable").is_err());
    }

    #[test]
    fn single_export_never_conflicts_with_itself() {
        check_export_overlap(&shares(&[("/srv/root", ShareMode::ReadWrite)]))
            .expect("one export is fine");
        check_export_overlap(&[]).expect("no exports at all is fine");
    }
}

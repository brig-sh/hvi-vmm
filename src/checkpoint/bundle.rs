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

//! The checkpoint bundle: a directory of named components and the manifest
//! that seals them.
//!
//! | file | holds |
//! |---|---|
//! | `profile.json` | the source's [`MachineProfile`] |
//! | `ram.bin`, `ram.map` | guest RAM, see [`ram`] |
//! | `cpu.json` | every vCPU, see [`CpuState`] |
//! | `platform.json` | the interrupt controller and counter, see [`PlatformState`] |
//! | `devices.json` | [`DeviceStates`] and the interrupt line levels, see [`DevicesDoc`] |
//! | `disk.json` | the disk the guest had, when it had one, see [`DiskState`] |
//! | `session.json` | who captured it and when, see [`Session`] |
//! | `manifest.json` | every other file's size and SHA-256, written last |
//!
//! The writer, [`BundleWriter`], syncs the parent of a directory it creates,
//! writes each component to a new file and syncs it, then writes the
//! manifest to a temporary name, syncs it, renames it into place and syncs
//! the directory. The bundle is sealed once that last sync returns. A
//! directory without `manifest.json` is therefore not a bundle, whatever
//! else is in it, and a writer that fails or is dropped before
//! [`BundleWriter::seal`] succeeds removes what it wrote, the manifest
//! included.
//!
//! The reader, [`Bundle::open`], trusts nothing in the directory. It reads the
//! manifest within a size limit, checks every count, name and size in it
//! against the limits below before it allocates anything by them, and then
//! hashes every component and compares its size and SHA-256 with the
//! manifest's before it returns. A mismatch is refused with the component's
//! name, never repaired or skipped. Each accessor reads its component again
//! and checks the hash again, so a file changed after the open is refused
//! too.

// The bundle directory is the operator's, named on the control socket or the
// command line, not a guest's share, so it is resolved and opened by path.
// See clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::checkpoint::cpu::CpuState;
use crate::checkpoint::platform::PlatformState;
use crate::checkpoint::profile::{
    this_build, HviBuild, MachineProfile, CHECKPOINT_FORMAT, MAX_PROFILE_BYTES,
};
use crate::checkpoint::ram::{self, RamImage, RegionImage, PAGE_SIZE};
use crate::devices::state::DeviceStates;
use crate::memory::{GuestRam, GuestRamView};

/// The manifest's file name.
pub const MANIFEST: &str = "manifest.json";

/// The name the manifest is written under before the rename seals it.
const MANIFEST_TMP: &str = "manifest.json.tmp";

/// The most components a manifest may list.
pub const MAX_COMPONENTS: usize = 16;

/// The largest component, `ram.bin` of a 64 GiB guest.
pub const MAX_COMPONENT_BYTES: u64 = 64 << 30;

/// The largest manifest the reader reads.
pub const MAX_MANIFEST_BYTES: u64 = 1 << 20;

/// The format of the small documents beside the RAM image.
pub const DOC_VERSION: u32 = 1;

/// One file of a bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    /// `profile.json`.
    Profile,
    /// `ram.map`.
    RamMap,
    /// `ram.bin`.
    RamBin,
    /// `cpu.json`.
    Cpu,
    /// `platform.json`.
    Platform,
    /// `devices.json`.
    Devices,
    /// `disk.json`, present only when the guest has a disk.
    Disk,
    /// `session.json`.
    Session,
}

impl Component {
    /// Every component, in the order the writer writes them.
    pub const ALL: [Component; 8] = [
        Component::Profile,
        Component::RamBin,
        Component::RamMap,
        Component::Cpu,
        Component::Platform,
        Component::Devices,
        Component::Disk,
        Component::Session,
    ];

    /// Returns the name the manifest gives the component.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Component::Profile => "profile",
            Component::RamMap => "ram_map",
            Component::RamBin => "ram_bin",
            Component::Cpu => "cpu",
            Component::Platform => "platform",
            Component::Devices => "devices",
            Component::Disk => "disk",
            Component::Session => "session",
        }
    }

    /// Returns the component's file name in the bundle directory.
    #[must_use]
    pub fn file(self) -> &'static str {
        match self {
            Component::Profile => "profile.json",
            Component::RamMap => "ram.map",
            Component::RamBin => "ram.bin",
            Component::Cpu => "cpu.json",
            Component::Platform => "platform.json",
            Component::Devices => "devices.json",
            Component::Disk => "disk.json",
            Component::Session => "session.json",
        }
    }

    /// Returns the largest size the reader accepts for the component.
    ///
    /// `devices.json` is the largest document: the vsock device can hold up
    /// to 16 MiB of waiting packets, which JSON writes as a list of numbers.
    #[must_use]
    pub fn limit(self) -> u64 {
        match self {
            Component::Profile => MAX_PROFILE_BYTES as u64,
            Component::RamMap => 64 << 20,
            Component::RamBin => MAX_COMPONENT_BYTES,
            Component::Cpu | Component::Platform => 16 << 20,
            Component::Devices => 256 << 20,
            Component::Disk | Component::Session => 64 << 10,
        }
    }

    /// Returns whether every bundle has the component.
    #[must_use]
    pub fn required(self) -> bool {
        self != Component::Disk
    }

    /// Returns the component the manifest names `name`.
    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }
}

/// One component as the manifest lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentEntry {
    /// [`Component::name`].
    pub name: String,
    /// The file name in the bundle directory, [`Component::file`].
    pub path: String,
    /// The file's length in bytes.
    pub size: u64,
    /// The SHA-256 of the file, lowercase hex.
    pub sha256: String,
}

/// The RAM image as the manifest describes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RamSummary {
    /// The page size of `ram.map`, [`PAGE_SIZE`].
    pub page_size: u64,
    /// Every region, in address order.
    pub regions: Vec<RegionImage>,
    /// The length of `ram.bin`.
    pub present_bytes: u64,
}

/// The whole of `manifest.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// [`CHECKPOINT_FORMAT`] when written by this build.
    pub checkpoint_format: u32,
    /// The hvi that wrote the bundle.
    pub hvi_build: HviBuild,
    /// Every other file of the bundle.
    pub components: Vec<ComponentEntry>,
    /// The RAM image.
    pub ram: RamSummary,
    /// The SHA-256 of `profile.json`, so a destination can compare profiles
    /// before it reads anything else.
    pub profile_sha256: String,
    /// What a restore must be able to load, such as `hvf-gic-state-v1`.
    /// Empty while the bundle carries no backend blob.
    pub capabilities: Vec<String>,
    /// When the manifest was written, in milliseconds since the Unix epoch.
    pub sealed_at_unix_ms: u64,
}

/// The interrupt line each device drove at capture, so a restore can drive
/// the lines again.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IrqLevels {
    /// virtio-blk.
    pub blk: bool,
    /// virtio-net.
    pub net: bool,
    /// virtio-vsock.
    pub vsock: bool,
    /// The console UART, a PL011 or a 16550.
    pub uart: bool,
}

/// The whole of `devices.json`: the [`DeviceStates`] document with an
/// `irq_levels` key beside the devices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevicesDoc {
    /// Every device's state.
    pub states: DeviceStates,
    /// The line levels at capture.
    pub irq_levels: IrqLevels,
}

impl DevicesDoc {
    /// Encodes the document.
    ///
    /// # Errors
    ///
    /// Errors as `serde_json` does, which for these types it does not.
    pub fn to_json(&self) -> io::Result<Vec<u8>> {
        let mut doc = serde_json::to_value(&self.states).map_err(io::Error::other)?;
        let levels = serde_json::to_value(self.irq_levels).map_err(io::Error::other)?;
        doc.as_object_mut()
            .ok_or_else(|| io::Error::other("device states are not a JSON object"))?
            .insert("irq_levels".to_string(), levels);
        serde_json::to_vec(&doc).map_err(io::Error::other)
    }

    /// Decodes the document, refusing one without `irq_levels` and every
    /// device-state document [`DeviceStates::from_json`] refuses.
    ///
    /// # Errors
    ///
    /// Errors, as `InvalidData`, on any of those.
    pub fn from_json(json: &[u8]) -> io::Result<Self> {
        let invalid = |what: String| io::Error::new(io::ErrorKind::InvalidData, what);
        let mut doc: serde_json::Value =
            serde_json::from_slice(json).map_err(|e| invalid(e.to_string()))?;
        let levels = doc
            .as_object_mut()
            .and_then(|fields| fields.remove("irq_levels"))
            .ok_or_else(|| invalid("no irq_levels".to_string()))?;
        let irq_levels = serde_json::from_value(levels).map_err(|e| invalid(e.to_string()))?;
        let states = DeviceStates::from_json(&serde_json::to_vec(&doc).map_err(io::Error::other)?)?;
        Ok(Self { states, irq_levels })
    }
}

/// The whole of `disk.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskState {
    /// [`DOC_VERSION`] when written by this build.
    pub version: u32,
    /// The path the source opened the disk at. A hint: the destination
    /// names its own copy.
    pub path_hint: String,
    /// The disk's size in bytes.
    pub size_bytes: u64,
    /// The SHA-256 of the whole image, when whoever moves the disk computed
    /// it; hvi writes `null`.
    pub sha256_sparse: Option<String>,
    /// The writes and flushes the guest made since boot, so two captures of
    /// one run can tell whether the disk changed between them.
    pub generation: u64,
    /// Whether the disk was synced to stable storage before the capture.
    pub synced: bool,
}

/// The whole of `session.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    /// [`DOC_VERSION`] when written by this build.
    pub version: u32,
    /// The sandbox id the VM ran under.
    pub sandbox_id: String,
    /// The caller's epoch for the sandbox, 0 when it gave none.
    pub epoch: u64,
    /// The caller's transaction id, when it gave one.
    pub txid: Option<String>,
    /// When the guest was captured, in milliseconds since the Unix epoch.
    pub captured_at_unix_ms: u64,
    /// `continue` or `fence`: what the source did after the capture.
    pub then: String,
}

/// Returns the milliseconds since the Unix epoch.
#[must_use]
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Returns an `InvalidData` error naming `what`.
fn bad(what: &str, why: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{what}: {why}"))
}

/// A writer that hashes and counts what passes through it.
struct Hashing<W> {
    inner: W,
    hasher: Sha256,
    len: u64,
}

impl<W> Hashing<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            len: 0,
        }
    }

    fn finish(self) -> (W, String, u64) {
        (self.inner, hex(&self.hasher.finalize()), self.len)
    }
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }
}

/// Returns `digest` as lowercase hex.
fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// What [`BundleWriter::seal`] reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The SHA-256 of `manifest.json`.
    pub manifest_sha256: String,
    /// The size of every file of the bundle, the manifest included.
    pub bundle_bytes: u64,
    /// The bytes of guest RAM `ram.bin` holds.
    pub ram_present_bytes: u64,
    /// The size of guest RAM.
    pub ram_total_bytes: u64,
}

/// Writes a bundle, component by component, and seals it.
///
/// Dropping it before [`seal`](Self::seal) succeeds removes every file it
/// wrote, the manifest included, and the directory when it created it.
pub struct BundleWriter {
    /// The bundle directory.
    dir: PathBuf,
    /// Whether [`create`](Self::create) made the directory.
    created_dir: bool,
    /// The components written so far.
    written: Vec<(Component, ComponentEntry)>,
    /// The RAM image, once written.
    ram: Option<RamImage>,
    /// Whether the manifest is in place.
    sealed: bool,
}

impl BundleWriter {
    /// Starts a bundle in `dir`, which must be an absolute path and either
    /// not exist, in which case its parent must, or be an empty directory.
    ///
    /// An existing bundle is never written over: an old manifest beside new
    /// components would seal a mix of two captures.
    ///
    /// # Errors
    ///
    /// Errors when `dir` is relative, is not a directory, is not empty, or
    /// cannot be created.
    pub fn create(dir: &Path) -> io::Result<Self> {
        if !dir.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{}: a bundle directory must be an absolute path",
                    dir.display()
                ),
            ));
        }
        let created_dir = match std::fs::symlink_metadata(dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(dir).map_err(|e| {
                    io::Error::new(e.kind(), format!("{}: cannot create: {e}", dir.display()))
                })?;
                true
            }
            Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {e}", dir.display()))),
            Ok(meta) if !meta.file_type().is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{}: exists and is not a directory", dir.display()),
                ))
            }
            Ok(_) => {
                if std::fs::read_dir(dir)?.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("{}: the directory is not empty", dir.display()),
                    ));
                }
                false
            }
        };
        let writer = Self {
            dir: dir.to_path_buf(),
            created_dir,
            written: Vec::new(),
            ram: None,
            sealed: false,
        };
        // The new directory's entry is in its parent. Without this sync a
        // host crash can lose a bundle that was reported sealed, and with it
        // the only copy of a fenced guest. A failure drops the writer, which
        // removes the directory.
        if created_dir {
            if let Some(parent) = dir.parent() {
                File::open(parent)
                    .and_then(|parent| parent.sync_all())
                    .map_err(|e| {
                        io::Error::new(e.kind(), format!("{}: cannot sync: {e}", parent.display()))
                    })?;
            }
        }
        Ok(writer)
    }

    /// Returns the bundle directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Writes `doc` as the JSON of `component`.
    ///
    /// # Errors
    ///
    /// Errors when the component was written already, is larger than
    /// [`Component::limit`], or the file fails.
    pub fn write_json<T: Serialize>(&mut self, component: Component, doc: &T) -> io::Result<()> {
        let bytes = serde_json::to_vec(doc).map_err(io::Error::other)?;
        self.write_bytes(component, &bytes)
    }

    /// Writes `bytes` as `component`.
    ///
    /// # Errors
    ///
    /// Errors when the component was written already, is larger than
    /// [`Component::limit`], or the file fails.
    pub fn write_bytes(&mut self, component: Component, bytes: &[u8]) -> io::Result<()> {
        check_size(component, bytes.len() as u64)?;
        self.write_with(component, |out| out.write_all(bytes))
    }

    /// Writes guest RAM as `ram.bin` and `ram.map`, and returns the image.
    ///
    /// `stopping` is asked between reads of guest RAM, see
    /// [`ram::write_ram`].
    ///
    /// # Errors
    ///
    /// Errors when RAM was written already, `stopping` returns true, or a
    /// file fails.
    pub fn write_ram(
        &mut self,
        ram: &GuestRamView,
        stopping: &dyn Fn() -> bool,
    ) -> io::Result<&RamImage> {
        let mut image = None;
        self.write_with(Component::RamBin, |out| {
            image = Some(ram::write_ram(ram, out, stopping)?);
            Ok(())
        })?;
        let image = image.ok_or_else(|| io::Error::other("no RAM image"))?;
        self.write_bytes(Component::RamMap, &image.map)?;
        Ok(self.ram.insert(image))
    }

    /// Writes `component` through `fill`, syncs it and records its size and
    /// hash. A component larger than the reader takes is refused, and
    /// removed with the rest when the writer is dropped.
    fn write_with(
        &mut self,
        component: Component,
        fill: impl FnOnce(&mut dyn Write) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.written.iter().any(|(c, _)| *c == component) {
            return Err(io::Error::other(format!(
                "{} was written already",
                component.file()
            )));
        }
        let path = self.dir.join(component.file());
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        // Recorded before the first byte, so a failure part way removes it.
        self.written.push((
            component,
            ComponentEntry {
                name: component.name().to_string(),
                path: component.file().to_string(),
                size: 0,
                sha256: String::new(),
            },
        ));
        let mut out = Hashing::new(BufWriter::with_capacity(1 << 20, file));
        fill(&mut out)?;
        out.flush()?;
        let (buffered, sha256, size) = out.finish();
        check_size(component, size)?;
        let file = buffered
            .into_inner()
            .map_err(io::IntoInnerError::into_error)?;
        file.sync_all()?;
        if let Some((_, entry)) = self.written.last_mut() {
            entry.size = size;
            entry.sha256 = sha256;
        }
        Ok(())
    }

    /// Writes the manifest last and renames it into place, which makes the
    /// directory a bundle.
    ///
    /// `capabilities` names what a restore must be able to load.
    ///
    /// # Errors
    ///
    /// Errors when a required component or the RAM image is missing, the
    /// manifest is one [`Bundle::open`] would refuse, or a file or the
    /// directory sync fails. The bundle is then removed.
    pub fn seal(mut self, capabilities: Vec<String>) -> io::Result<Sealed> {
        for component in Component::ALL {
            if component.required() && !self.written.iter().any(|(c, _)| *c == component) {
                return Err(io::Error::other(format!(
                    "{} was not written",
                    component.file()
                )));
            }
        }
        let image = self
            .ram
            .clone()
            .ok_or_else(|| io::Error::other("no RAM image"))?;
        let profile_sha256 = self
            .written
            .iter()
            .find(|(c, _)| *c == Component::Profile)
            .map(|(_, e)| e.sha256.clone())
            .unwrap_or_default();
        let manifest = Manifest {
            checkpoint_format: CHECKPOINT_FORMAT,
            hvi_build: this_build(),
            components: self.written.iter().map(|(_, e)| e.clone()).collect(),
            ram: RamSummary {
                page_size: PAGE_SIZE,
                present_bytes: image.present_bytes(),
                regions: image.regions.clone(),
            },
            profile_sha256,
            capabilities,
            sealed_at_unix_ms: unix_ms(),
        };
        // The reader's own checks, run before the manifest exists: a bundle
        // its reader refuses is lost the moment it is sealed, since a fenced
        // source never runs again. Failing here leaves the VM free to run on.
        check_manifest(&manifest)
            .map_err(|e| io::Error::new(e.kind(), format!("the reader would refuse it: {e}")))?;
        let bytes = serde_json::to_vec_pretty(&manifest).map_err(io::Error::other)?;
        check_size_of(MANIFEST, bytes.len() as u64, MAX_MANIFEST_BYTES)?;
        let tmp = self.dir.join(MANIFEST_TMP);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, self.dir.join(MANIFEST))?;
        // The rename is durable once the directory is. Until then the bundle
        // is not sealed: a failure drops the writer, which removes the
        // manifest with the rest, so a capture that replies capture_failed
        // and resumes the source leaves no bundle a later restore could run
        // beside it.
        File::open(&self.dir)?.sync_all()?;
        self.sealed = true;
        let bundle_bytes =
            self.written.iter().map(|(_, e)| e.size).sum::<u64>() + bytes.len() as u64;
        Ok(Sealed {
            manifest_sha256: hex(&Sha256::digest(&bytes)),
            bundle_bytes,
            ram_present_bytes: image.present_bytes(),
            ram_total_bytes: image.total_bytes(),
        })
    }
}

impl Drop for BundleWriter {
    fn drop(&mut self) {
        if self.sealed {
            return;
        }
        for (component, _) in &self.written {
            let _ = std::fs::remove_file(self.dir.join(component.file()));
        }
        let _ = std::fs::remove_file(self.dir.join(MANIFEST_TMP));
        // Only this writer can have put a manifest here: create refuses a
        // directory that is not empty.
        let _ = std::fs::remove_file(self.dir.join(MANIFEST));
        if self.created_dir {
            let _ = std::fs::remove_dir(&self.dir);
        }
    }
}

/// Refuses `component` at `size` bytes when the reader would refuse it, so
/// the capture fails before the seal rather than seal a bundle that no
/// reader opens.
fn check_size(component: Component, size: u64) -> io::Result<()> {
    check_size_of(component.file(), size, component.limit())
}

/// Refuses the file `name` at `size` bytes when it is over `limit`.
fn check_size_of(name: &str, size: u64, limit: u64) -> io::Result<()> {
    if size > limit {
        return Err(bad(
            name,
            format!("would be {size} bytes, the reader takes at most {limit}"),
        ));
    }
    Ok(())
}

/// Opens `name` in `dir` for reading: a regular file, not through a link,
/// and no longer than `limit`.
fn open_component(dir: &Path, name: &str, limit: u64) -> io::Result<(File, u64)> {
    let path = dir.join(name);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("{name}: {e}")))?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(bad(name, "is not a regular file"));
    }
    if meta.len() > limit {
        return Err(bad(
            name,
            format!("is {} bytes, the limit is {limit}", meta.len()),
        ));
    }
    Ok((file, meta.len()))
}

/// Reads the component `entry` lists whole, checking its size and hash
/// again.
fn read_component(dir: &Path, entry: &ComponentEntry) -> io::Result<Vec<u8>> {
    let (mut file, len) = open_component(dir, &entry.path, entry.size.max(1))?;
    let mut bytes = Vec::with_capacity(len as usize);
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != entry.size || hex(&Sha256::digest(&bytes)) != entry.sha256 {
        return Err(bad(&entry.path, "changed since the bundle was opened"));
    }
    Ok(bytes)
}

/// Returns whether `name` is a plain file name: no directory part, not `.`
/// or `..`, not empty, no NUL.
fn is_bare(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

/// A bundle whose manifest and components have been checked.
#[derive(Debug)]
pub struct Bundle {
    /// The bundle directory.
    dir: PathBuf,
    /// The manifest.
    manifest: Manifest,
    /// The SHA-256 of `manifest.json`.
    manifest_sha256: String,
    /// The source's profile.
    profile: MachineProfile,
}

impl Bundle {
    /// Opens the bundle in `dir` and checks it whole: the manifest against
    /// the limits, then every component's size and SHA-256, then the profile
    /// against the manifest's RAM regions.
    ///
    /// # Errors
    ///
    /// Errors, naming the file, on the first thing that does not hold.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let (mut file, len) = open_component(dir, MANIFEST, MAX_MANIFEST_BYTES)?;
        let mut bytes = Vec::with_capacity(len as usize);
        file.read_to_end(&mut bytes)?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| bad(MANIFEST, e))?;
        check_manifest(&manifest)?;
        for entry in &manifest.components {
            let (file, len) = open_component(dir, &entry.path, entry.size.max(1))?;
            if len != entry.size {
                return Err(bad(
                    &entry.path,
                    format!("is {len} bytes, the manifest says {}", entry.size),
                ));
            }
            let mut hashing = Hashing::new(BufReader::with_capacity(1 << 20, file));
            io::copy(&mut hashing, &mut io::sink())?;
            let (_, sha256, read) = hashing.finish();
            if read != entry.size {
                return Err(bad(&entry.path, "changed while it was read"));
            }
            if sha256 != entry.sha256 {
                return Err(bad(&entry.path, "SHA-256 does not match the manifest"));
            }
        }
        let profile = manifest
            .components
            .iter()
            .find(|e| e.name == Component::Profile.name())
            .ok_or_else(|| bad("profile.json", "is not in this bundle"))?;
        let profile = read_component(dir, profile)?;
        let profile = std::str::from_utf8(&profile).map_err(|e| bad("profile.json", e))?;
        let profile = MachineProfile::from_json(profile).map_err(|e| bad("profile.json", e))?;
        if profile.checkpoint_format != CHECKPOINT_FORMAT {
            return Err(bad(
                "profile.json",
                format!(
                    "checkpoint_format {}, this build reads {CHECKPOINT_FORMAT}",
                    profile.checkpoint_format
                ),
            ));
        }
        let regions = &manifest.ram.regions;
        let same = profile.ram_regions.len() == regions.len()
            && profile
                .ram_regions
                .iter()
                .zip(regions)
                .all(|(p, r)| p.gpa == r.gpa && p.size == r.size);
        if !same {
            return Err(bad(MANIFEST, "the RAM regions are not the profile's"));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            manifest_sha256: hex(&Sha256::digest(&bytes)),
            manifest,
            profile,
        })
    }

    /// Returns the manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Returns the SHA-256 of `manifest.json`.
    #[must_use]
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    /// Returns the source's profile.
    #[must_use]
    pub fn profile(&self) -> &MachineProfile {
        &self.profile
    }

    /// Returns the manifest's entry for `component`.
    #[must_use]
    pub fn entry(&self, component: Component) -> Option<&ComponentEntry> {
        self.manifest
            .components
            .iter()
            .find(|e| e.name == component.name())
    }

    /// Reads `component` whole, checking its size and hash again.
    ///
    /// # Errors
    ///
    /// Errors when the bundle has no such component, it is `ram.bin`, which
    /// is too large to read whole, or it no longer matches the manifest.
    pub fn read(&self, component: Component) -> io::Result<Vec<u8>> {
        if component == Component::RamBin {
            return Err(io::Error::other(
                "ram.bin is streamed by load_ram, not read whole",
            ));
        }
        let entry = self
            .entry(component)
            .ok_or_else(|| bad(component.file(), "is not in this bundle"))?;
        read_component(&self.dir, entry)
    }

    /// Returns `cpu.json`.
    ///
    /// # Errors
    ///
    /// Errors when it cannot be read or is not the document.
    pub fn cpu(&self) -> io::Result<CpuState> {
        CpuState::from_json(&self.read(Component::Cpu)?).map_err(|e| bad("cpu.json", e))
    }

    /// Returns `platform.json`.
    ///
    /// # Errors
    ///
    /// Errors when it cannot be read or is not the document.
    pub fn platform(&self) -> io::Result<PlatformState> {
        PlatformState::from_json(&self.read(Component::Platform)?)
            .map_err(|e| bad("platform.json", e))
    }

    /// Returns `devices.json`.
    ///
    /// # Errors
    ///
    /// Errors when it cannot be read or is not the document.
    pub fn devices(&self) -> io::Result<DevicesDoc> {
        DevicesDoc::from_json(&self.read(Component::Devices)?).map_err(|e| bad("devices.json", e))
    }

    /// Returns `disk.json`, when the bundle has one.
    ///
    /// # Errors
    ///
    /// Errors when it cannot be read or is not the document.
    pub fn disk(&self) -> io::Result<Option<DiskState>> {
        if self.entry(Component::Disk).is_none() {
            return Ok(None);
        }
        let disk: DiskState = serde_json::from_slice(&self.read(Component::Disk)?)
            .map_err(|e| bad("disk.json", e))?;
        if disk.version != DOC_VERSION {
            return Err(bad("disk.json", format!("version {}", disk.version)));
        }
        Ok(Some(disk))
    }

    /// Returns `session.json`.
    ///
    /// # Errors
    ///
    /// Errors when it cannot be read or is not the document.
    pub fn session(&self) -> io::Result<Session> {
        let session: Session = serde_json::from_slice(&self.read(Component::Session)?)
            .map_err(|e| bad("session.json", e))?;
        if session.version != DOC_VERSION {
            return Err(bad("session.json", format!("version {}", session.version)));
        }
        if session.then != "continue" && session.then != "fence" {
            return Err(bad("session.json", format!("then {:?}", session.then)));
        }
        Ok(session)
    }

    /// Copies the RAM image into `ram`, which must be fresh RAM of the
    /// bundle's regions, hashing `ram.bin` again as it goes.
    ///
    /// # Errors
    ///
    /// Errors as [`ram::load_ram`] does, or when `ram.bin` no longer matches
    /// the manifest. Pages copied before the error stay copied, so the caller
    /// discards `ram`.
    pub fn load_ram(&self, ram: &GuestRam) -> io::Result<()> {
        let map = self.read(Component::RamMap)?;
        let entry = self
            .entry(Component::RamBin)
            .ok_or_else(|| bad("ram.bin", "is not in this bundle"))?;
        let (file, _) = open_component(&self.dir, &entry.path, entry.size.max(1))?;
        let mut bin = Hashing::new(BufReader::with_capacity(1 << 20, file));
        ram::load_ram(&map, &self.manifest.ram.regions, &mut bin, ram)?;
        let (_, sha256, _) = bin.finish();
        if sha256 != entry.sha256 {
            return Err(bad("ram.bin", "changed since the bundle was opened"));
        }
        Ok(())
    }
}

/// Checks the manifest against the format and the limits, before anything is
/// read or allocated by what it says.
fn check_manifest(manifest: &Manifest) -> io::Result<()> {
    if manifest.checkpoint_format != CHECKPOINT_FORMAT {
        return Err(bad(
            MANIFEST,
            format!(
                "checkpoint_format {}, this build reads {CHECKPOINT_FORMAT}",
                manifest.checkpoint_format
            ),
        ));
    }
    if manifest.components.len() > MAX_COMPONENTS {
        return Err(bad(
            MANIFEST,
            format!(
                "{} components, at most {MAX_COMPONENTS}",
                manifest.components.len()
            ),
        ));
    }
    let mut seen = Vec::new();
    for entry in &manifest.components {
        if !is_bare(&entry.path) {
            return Err(bad(
                MANIFEST,
                format!("component path {:?} is not a bare file name", entry.path),
            ));
        }
        let component = Component::from_name(&entry.name)
            .ok_or_else(|| bad(MANIFEST, format!("unknown component {:?}", entry.name)))?;
        if entry.path != component.file() {
            return Err(bad(
                MANIFEST,
                format!(
                    "component {} must be at {}, not {:?}",
                    entry.name,
                    component.file(),
                    entry.path
                ),
            ));
        }
        if seen.contains(&component) {
            return Err(bad(
                MANIFEST,
                format!("component {} is listed twice", entry.name),
            ));
        }
        seen.push(component);
        if entry.size > MAX_COMPONENT_BYTES || entry.size > component.limit() {
            return Err(bad(
                MANIFEST,
                format!(
                    "{} is {} bytes, the limit is {}",
                    entry.path,
                    entry.size,
                    component.limit()
                ),
            ));
        }
        let hex_ok = entry.sha256.len() == 64
            && entry
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex_ok {
            return Err(bad(
                MANIFEST,
                format!("{} has no lowercase hex SHA-256", entry.path),
            ));
        }
    }
    for component in Component::ALL {
        if component.required() && !seen.contains(&component) {
            return Err(bad(MANIFEST, format!("{} is not listed", component.file())));
        }
    }
    let ram = &manifest.ram;
    if ram.page_size != PAGE_SIZE {
        return Err(bad(
            MANIFEST,
            format!("page size {}, this build reads {PAGE_SIZE}", ram.page_size),
        ));
    }
    if ram.regions.is_empty() || ram.regions.len() > ram::MAX_REGIONS {
        return Err(bad(
            MANIFEST,
            format!(
                "{} RAM regions, 1 to {}",
                ram.regions.len(),
                ram::MAX_REGIONS
            ),
        ));
    }
    let mut present = 0u64;
    let mut map_len = ram::HEADER_LEN as u64;
    for region in &ram.regions {
        if region.size == 0 || region.size % PAGE_SIZE != 0 || region.size > MAX_COMPONENT_BYTES {
            return Err(bad(
                MANIFEST,
                format!("the RAM region at {:#x} has a bad size", region.gpa),
            ));
        }
        if region.present_pages > region.pages() {
            return Err(bad(
                MANIFEST,
                format!(
                    "the RAM region at {:#x} has {} present pages in {} pages",
                    region.gpa,
                    region.present_pages,
                    region.pages()
                ),
            ));
        }
        present += region.present_pages * PAGE_SIZE;
        map_len += region.bitmap_len() as u64;
    }
    if present != ram.present_bytes {
        return Err(bad(
            MANIFEST,
            format!(
                "present_bytes is {}, the regions add up to {present}",
                ram.present_bytes
            ),
        ));
    }
    let size_of = |component: Component| {
        manifest
            .components
            .iter()
            .find(|e| e.name == component.name())
            .map_or(0, |e| e.size)
    };
    if size_of(Component::RamBin) != present {
        return Err(bad(
            "ram.bin",
            format!(
                "the manifest lists {} bytes, the RAM image holds {present}",
                size_of(Component::RamBin)
            ),
        ));
    }
    if size_of(Component::RamMap) != map_len {
        return Err(bad(
            "ram.map",
            format!(
                "the manifest lists {} bytes, the regions need {map_len}",
                size_of(Component::RamMap)
            ),
        ));
    }
    let profile_sha = manifest
        .components
        .iter()
        .find(|e| e.name == Component::Profile.name())
        .map(|e| e.sha256.as_str());
    if profile_sha != Some(manifest.profile_sha256.as_str()) {
        return Err(bad(MANIFEST, "profile_sha256 is not the profile's"));
    }
    Ok(())
}

/// What [`verify`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The SHA-256 of `manifest.json`.
    pub manifest_sha256: String,
    /// The hvi that wrote the bundle.
    pub hvi_build: HviBuild,
    /// The source's architecture and backend.
    pub arch: String,
    /// `hvf` or `kvm`.
    pub backend: String,
    /// Every file, the manifest included, with its size.
    pub files: Vec<(String, u64)>,
    /// The bytes of guest RAM the image holds.
    pub ram_present_bytes: u64,
    /// The size of guest RAM.
    pub ram_total_bytes: u64,
    /// The vCPUs.
    pub vcpus: usize,
    /// The parts a restore would need more of.
    pub partial: Vec<&'static str>,
}

impl std::fmt::Display for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "bundle ok: manifest sha256 {}", self.manifest_sha256)?;
        writeln!(
            f,
            "written by hvi {} ({}), {} on {}",
            self.hvi_build.version, self.hvi_build.git_sha, self.arch, self.backend
        )?;
        for (name, size) in &self.files {
            writeln!(f, "  {name:<14} {size:>14} bytes")?;
        }
        writeln!(
            f,
            "RAM: {} of {} bytes present; {} vCPU(s)",
            self.ram_present_bytes, self.ram_total_bytes, self.vcpus
        )?;
        if self.partial.is_empty() {
            write!(f, "complete: every part a restore needs is captured")
        } else {
            write!(
                f,
                "partial: {} not captured, so no restore can resume this bundle",
                self.partial.join(", ")
            )
        }
    }
}

/// Checks the bundle in `dir` whole, as `hvi checkpoint-verify` does: what
/// [`Bundle::open`] checks, then every document parsed and checked against
/// the profile, and `ram.map` against the manifest.
///
/// # Errors
///
/// Errors, naming the file, on the first thing that does not hold.
pub fn verify(dir: &Path) -> io::Result<Verified> {
    let bundle = Bundle::open(dir)?;
    let profile = bundle.profile();
    ram::check_map(
        &bundle.read(Component::RamMap)?,
        &bundle.manifest.ram.regions,
    )?;
    let cpu = bundle.cpu()?;
    if cpu.arch != profile.arch || cpu.vcpus.len() != profile.vcpus as usize {
        return Err(bad(
            "cpu.json",
            format!(
                "{} {} vCPU(s), the profile has {} {}",
                cpu.vcpus.len(),
                cpu.arch,
                profile.vcpus,
                profile.arch
            ),
        ));
    }
    let platform = bundle.platform()?;
    if platform.arch != profile.arch || platform.backend != profile.backend {
        return Err(bad(
            "platform.json",
            "is not of the profile's arch and backend",
        ));
    }
    let devices = bundle.devices()?;
    let disk = bundle.disk()?;
    if devices.states.blk.is_some() != disk.is_some() {
        return Err(bad(
            "disk.json",
            "must be present exactly when devices.json has a virtio-blk device",
        ));
    }
    bundle.session()?;
    let mut partial = Vec::new();
    if cpu.is_partial() {
        partial.push("vCPU registers");
    }
    if platform.is_partial() {
        partial.push("interrupt controller and timer");
    }
    let mut files: Vec<(String, u64)> = bundle
        .manifest
        .components
        .iter()
        .map(|e| (e.path.clone(), e.size))
        .collect();
    let manifest_len = std::fs::symlink_metadata(dir.join(MANIFEST))?.len();
    files.push((MANIFEST.to_string(), manifest_len));
    Ok(Verified {
        manifest_sha256: bundle.manifest_sha256.clone(),
        hvi_build: bundle.manifest.hvi_build.clone(),
        arch: profile.arch.clone(),
        backend: profile.backend.clone(),
        files,
        ram_present_bytes: bundle.manifest.ram.present_bytes,
        ram_total_bytes: bundle.manifest.ram.regions.iter().map(|r| r.size).sum(),
        vcpus: cpu.vcpus.len(),
        partial,
    })
}

/// Returns the bundle directory `dir` names, which must be below `root`, the
/// resolved checkpoint root.
///
/// `dir` must be absolute, name a directory strictly below `root`, and have
/// no `..` in it. Every directory between the root and the bundle must
/// exist and be a directory, not a link, so no link on the way can take the
/// bundle outside the root; the writer opens the last component without
/// following a link.
///
/// # Errors
///
/// Errors, as `InvalidInput`, on any of those, or as looking at a directory
/// on the way does.
pub fn resolve_in_root(root: &Path, dir: &str) -> io::Result<PathBuf> {
    use std::path::Component as Part;
    let refuse = |why: String| io::Error::new(io::ErrorKind::InvalidInput, why);
    let path = Path::new(dir);
    if !path.is_absolute() {
        return Err(refuse(format!(
            "{dir}: a bundle directory must be an absolute path"
        )));
    }
    if path
        .components()
        .any(|part| matches!(part, Part::ParentDir))
    {
        return Err(refuse(format!("{dir}: a bundle directory has no .. in it")));
    }
    let clean: PathBuf = path.components().collect();
    let below = clean.strip_prefix(root).map_err(|_| {
        refuse(format!(
            "{dir}: not below the checkpoint root {}",
            root.display()
        ))
    })?;
    if below.as_os_str().is_empty() {
        return Err(refuse(format!(
            "{dir}: is the checkpoint root itself; name a directory below it"
        )));
    }
    // Each directory between the root and the bundle must be a directory,
    // not a link. They are looked at one by one with lstat rather than
    // resolved: under Seatbelt only paths below the root may be looked at,
    // and resolving a path looks at every directory above it.
    let mut walked = root.to_path_buf();
    let parts: Vec<_> = below.components().collect();
    for part in &parts[..parts.len() - 1] {
        walked.push(part);
        let meta = std::fs::symlink_metadata(&walked)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", walked.display())))?;
        if !meta.file_type().is_dir() {
            return Err(refuse(format!(
                "{dir}: {} is a link or not a directory",
                walked.display()
            )));
        }
    }
    Ok(clean)
}

/// Writes a bundle of `ram`, with no vCPU and no device, to `name` below
/// `root`, checks it with [`verify`] and removes it. `profile` is the one the
/// bundle records, made before confinement, since reading the host's facts
/// needs calls the confinement refuses; its RAM regions and vCPU count are
/// set here.
///
/// The sandbox selftests run it under the production confinement, so they
/// prove that the writer and the reader need no right the confinement of the
/// control socket's thread does not grant.
///
/// # Errors
///
/// Errors as resolving the directory, the writer, the reader or the removal
/// does.
pub fn selftest_round_trip(
    root: &Path,
    name: &str,
    ram: &GuestRamView,
    profile: &MachineProfile,
) -> io::Result<()> {
    let dir = resolve_in_root(root, &root.join(name).to_string_lossy())?;
    let dir = dir.as_path();
    let mut profile = profile.clone();
    profile.arch = "aarch64".into();
    profile.backend = "selftest".into();
    profile.ram_regions = ram.regions().into_iter().map(Into::into).collect();
    profile.vcpus = 0;
    let mut w = BundleWriter::create(dir)?;
    w.write_bytes(Component::Profile, profile.to_json().as_bytes())?;
    w.write_ram(ram, &|| false)?;
    w.write_json(
        Component::Cpu,
        &CpuState::new(crate::plugin::GuestArch::Aarch64, Vec::new()),
    )?;
    w.write_json(
        Component::Platform,
        &PlatformState::not_captured(crate::plugin::GuestArch::Aarch64, "selftest"),
    )?;
    let devices = DevicesDoc {
        states: DeviceStates::default(),
        irq_levels: IrqLevels::default(),
    };
    w.write_bytes(Component::Devices, &devices.to_json()?)?;
    w.write_json(
        Component::Session,
        &Session {
            version: DOC_VERSION,
            sandbox_id: "selftest".into(),
            epoch: 0,
            txid: None,
            captured_at_unix_ms: unix_ms(),
            then: "continue".into(),
        },
    )?;
    w.seal(Vec::new())?;
    let verified = verify(dir);
    std::fs::remove_dir_all(dir)?;
    verified.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::cpu::VcpuState;
    use crate::checkpoint::profile::RamRegion;
    use crate::plugin::{GuestArch, RegsView};

    const MIB: usize = 1 << 20;
    const GPA: u64 = 0x4000_0000;

    /// A directory under the temp dir, removed with everything in it when
    /// dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("hvi-bundle-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn bundle(&self) -> PathBuf {
            self.0.join("ck")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn guest() -> GuestRam {
        let ram = GuestRam::from_ranges(&[(GPA, MIB)]);
        ram.write(GPA + 0x1000, b"kernel text").unwrap();
        ram.write(GPA + 0x8_0000, b"page cache").unwrap();
        ram
    }

    fn profile() -> MachineProfile {
        let mut profile = MachineProfile::for_this_host("aarch64", "hvf");
        profile.ram_regions = vec![RamRegion {
            gpa: GPA,
            size: MIB as u64,
            file_offset: 0,
        }];
        profile.vcpus = 1;
        profile
    }

    /// Writes a whole bundle of [`guest`] to `dir`, with a disk when `disk`.
    fn write(dir: &Path, disk: bool) -> Sealed {
        let ram = guest();
        let mut w = BundleWriter::create(dir).unwrap();
        w.write_bytes(Component::Profile, profile().to_json().as_bytes())
            .unwrap();
        w.write_ram(&ram, &|| false).unwrap();
        let vcpu = VcpuState::from_regs_view(GuestArch::Aarch64, "hvf", 0, &RegsView::default());
        w.write_json(
            Component::Cpu,
            &CpuState::new(GuestArch::Aarch64, vec![vcpu]),
        )
        .unwrap();
        w.write_json(
            Component::Platform,
            &PlatformState::not_captured(GuestArch::Aarch64, "hvf"),
        )
        .unwrap();
        let devices = DevicesDoc {
            states: DeviceStates::default(),
            irq_levels: IrqLevels::default(),
        };
        w.write_bytes(Component::Devices, &devices.to_json().unwrap())
            .unwrap();
        if disk {
            w.write_json(
                Component::Disk,
                &DiskState {
                    version: DOC_VERSION,
                    path_hint: "/disk.img".into(),
                    size_bytes: 1 << 30,
                    sha256_sparse: None,
                    generation: 7,
                    synced: true,
                },
            )
            .unwrap();
        }
        w.write_json(
            Component::Session,
            &Session {
                version: DOC_VERSION,
                sandbox_id: "sb".into(),
                epoch: 3,
                txid: Some("tx".into()),
                captured_at_unix_ms: unix_ms(),
                then: "continue".into(),
            },
        )
        .unwrap();
        w.seal(Vec::new()).unwrap()
    }

    fn refused(dir: &Path) -> String {
        let err = Bundle::open(dir).unwrap_err();
        err.to_string()
    }

    /// Rewrites the manifest through `edit`.
    fn edit_manifest(dir: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
        let path = dir.join(MANIFEST);
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        edit(&mut doc);
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
    }

    fn component<'a>(doc: &'a mut serde_json::Value, name: &str) -> &'a mut serde_json::Value {
        doc["components"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|c| c["name"] == name)
            .unwrap()
    }

    #[test]
    fn a_bundle_round_trips() {
        let scratch = Scratch::new("round-trip");
        let dir = scratch.bundle();
        let sealed = write(&dir, false);
        assert_eq!(sealed.ram_present_bytes, 2 * PAGE_SIZE);
        assert_eq!(sealed.ram_total_bytes, MIB as u64);
        let on_disk: u64 = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum();
        assert_eq!(sealed.bundle_bytes, on_disk);

        let bundle = Bundle::open(&dir).unwrap();
        assert_eq!(bundle.manifest_sha256(), sealed.manifest_sha256);
        assert_eq!(bundle.profile(), &profile());
        assert_eq!(bundle.manifest().hvi_build, this_build());
        assert_eq!(bundle.cpu().unwrap().vcpus.len(), 1);
        assert!(bundle.platform().unwrap().is_partial());
        assert_eq!(bundle.devices().unwrap().states, DeviceStates::default());
        assert_eq!(bundle.disk().unwrap(), None);
        assert_eq!(bundle.session().unwrap().epoch, 3);
        let fresh = GuestRam::from_ranges(&[(GPA, MIB)]);
        bundle.load_ram(&fresh).unwrap();
        let (mut a, mut b) = (vec![0u8; MIB], vec![1u8; MIB]);
        guest().read(GPA, &mut a).unwrap();
        fresh.read(GPA, &mut b).unwrap();
        assert!(a == b, "the loaded RAM differs");

        let verified = verify(&dir).unwrap();
        assert_eq!(
            verified.partial,
            ["vCPU registers", "interrupt controller and timer"]
        );
        assert_eq!(verified.files.len(), 8);
        assert!(verified
            .to_string()
            .starts_with("bundle ok: manifest sha256 "));
    }

    // The image loads into RAM made the way a restore makes it, from a
    // shareable object, not only into the anonymous test mappings.
    #[test]
    fn ram_loads_into_a_fresh_shared_object() {
        let scratch = Scratch::new("shared");
        let dir = scratch.bundle();
        write(&dir, true);
        let bundle = Bundle::open(&dir).unwrap();
        assert_eq!(bundle.disk().unwrap().unwrap().generation, 7);
        let shared = crate::memory::SharedRam::new(MIB).unwrap();
        let fresh = GuestRam::new(&shared, &[shared.region_at(GPA)]).unwrap();
        bundle.load_ram(&fresh).unwrap();
        let mut text = [0u8; 11];
        fresh.read(GPA + 0x1000, &mut text).unwrap();
        assert_eq!(&text, b"kernel text");
    }

    #[test]
    fn a_changed_byte_is_refused_by_name() {
        let scratch = Scratch::new("flip");
        let dir = scratch.bundle();
        write(&dir, false);
        let path = dir.join("ram.bin");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[100] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(
            refused(&dir),
            "ram.bin: SHA-256 does not match the manifest"
        );
        assert!(verify(&dir).is_err());
    }

    #[test]
    fn a_short_or_missing_component_is_refused_by_name() {
        let scratch = Scratch::new("short");
        let dir = scratch.bundle();
        write(&dir, false);
        let path = dir.join("cpu.json");
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(
            refused(&dir).starts_with("cpu.json: is "),
            "{}",
            refused(&dir)
        );
        std::fs::remove_file(&path).unwrap();
        assert!(refused(&dir).starts_with("cpu.json: "), "{}", refused(&dir));
    }

    #[test]
    fn a_directory_without_a_manifest_is_not_a_bundle() {
        let scratch = Scratch::new("unsealed");
        let dir = scratch.bundle();
        write(&dir, false);
        std::fs::remove_file(dir.join(MANIFEST)).unwrap();
        assert!(refused(&dir).starts_with("manifest.json: "));
    }

    // A component that is a link could point the reader at any file the
    // reader can open.
    #[test]
    fn a_component_behind_a_link_is_refused() {
        let scratch = Scratch::new("link");
        let dir = scratch.bundle();
        write(&dir, false);
        let real = scratch.0.join("session.json");
        std::fs::rename(dir.join("session.json"), &real).unwrap();
        std::os::unix::fs::symlink(&real, dir.join("session.json")).unwrap();
        assert!(
            refused(&dir).starts_with("session.json: "),
            "{}",
            refused(&dir)
        );
    }

    #[test]
    fn an_oversized_manifest_is_refused_before_it_is_parsed() {
        let scratch = Scratch::new("big");
        let dir = scratch.bundle();
        write(&dir, false);
        std::fs::write(
            dir.join(MANIFEST),
            vec![b' '; MAX_MANIFEST_BYTES as usize + 1],
        )
        .unwrap();
        assert!(
            refused(&dir).contains("the limit is 1048576"),
            "{}",
            refused(&dir)
        );
    }

    #[test]
    fn manifest_limits_and_cross_checks_are_enforced() {
        type Edit = Box<dyn Fn(&mut serde_json::Value)>;
        let cases: Vec<(&str, Edit)> = vec![
            (
                "checkpoint_format 2",
                Box::new(|m| m["checkpoint_format"] = 2.into()),
            ),
            ("unknown field", Box::new(|m| m["extra"] = 1.into())),
            (
                "17 components",
                Box::new(|m| {
                    let first = m["components"][0].clone();
                    let list = m["components"].as_array_mut().unwrap();
                    while list.len() <= MAX_COMPONENTS {
                        list.push(first.clone());
                    }
                }),
            ),
            (
                "not a bare file name",
                Box::new(|m| component(m, "cpu")["path"] = "../cpu.json".into()),
            ),
            (
                "must be at cpu.json",
                Box::new(|m| component(m, "cpu")["path"] = "session.json".into()),
            ),
            (
                "unknown component",
                Box::new(|m| component(m, "cpu")["name"] = "gpu".into()),
            ),
            (
                "listed twice",
                Box::new(|m| {
                    let cpu = component(m, "cpu").clone();
                    m["components"].as_array_mut().unwrap().push(cpu);
                }),
            ),
            (
                "the limit is",
                Box::new(|m| component(m, "session")["size"] = (1u64 << 20).into()),
            ),
            (
                "the limit is",
                Box::new(|m| component(m, "ram_bin")["size"] = (MAX_COMPONENT_BYTES + 1).into()),
            ),
            (
                "no lowercase hex",
                Box::new(|m| component(m, "cpu")["sha256"] = "ABC".into()),
            ),
            (
                "platform.json is not listed",
                Box::new(|m| {
                    m["components"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|c| c["name"] != "platform");
                }),
            ),
            (
                "page size",
                Box::new(|m| m["ram"]["page_size"] = 16384.into()),
            ),
            (
                "RAM regions, 1 to 8",
                Box::new(|m| {
                    let region = m["ram"]["regions"][0].clone();
                    m["ram"]["regions"] = vec![region; 9].into();
                }),
            ),
            (
                "present pages in 256 pages",
                Box::new(|m| m["ram"]["regions"][0]["present_pages"] = 257.into()),
            ),
            (
                "the regions add up to",
                Box::new(|m| m["ram"]["present_bytes"] = 4096.into()),
            ),
            (
                "ram.bin: the manifest lists",
                Box::new(|m| {
                    m["ram"]["regions"][0]["present_pages"] = 3.into();
                    m["ram"]["present_bytes"] = (3 * PAGE_SIZE).into();
                }),
            ),
            (
                "ram.map: the manifest lists",
                Box::new(|m| component(m, "ram_map")["size"] = 17.into()),
            ),
            (
                "profile_sha256 is not",
                Box::new(|m| m["profile_sha256"] = "0".repeat(64).into()),
            ),
            (
                "not the profile's",
                Box::new(|m| {
                    m["ram"]["regions"][0]["gpa"] = 0x8000_0000u64.into();
                }),
            ),
        ];
        let scratch = Scratch::new("limits");
        let dir = scratch.bundle();
        write(&dir, false);
        let good = std::fs::read(dir.join(MANIFEST)).unwrap();
        for (want, edit) in cases {
            std::fs::write(dir.join(MANIFEST), &good).unwrap();
            edit_manifest(&dir, edit);
            let got = refused(&dir);
            assert!(got.contains(want), "want {want:?}, got {got:?}");
        }
    }

    #[test]
    fn verify_checks_the_documents_against_the_profile() {
        let scratch = Scratch::new("docs");
        let dir = scratch.bundle();
        write(&dir, false);
        // A disk.json for a guest without a disk.
        let disk = br#"{"version":1,"path_hint":"/d","size_bytes":1,"sha256_sparse":null,"generation":0,"synced":true}"#;
        std::fs::write(dir.join("disk.json"), disk).unwrap();
        edit_manifest(&dir, |m| {
            m["components"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "name": "disk", "path": "disk.json", "size": disk.len(),
                    "sha256": hex(&Sha256::digest(disk)),
                }));
        });
        Bundle::open(&dir).unwrap();
        let err = verify(&dir).unwrap_err().to_string();
        assert!(
            err.starts_with("disk.json: must be present exactly"),
            "{err}"
        );
    }

    #[test]
    fn the_writer_refuses_a_relative_or_used_directory() {
        let scratch = Scratch::new("writer");
        let relative = BundleWriter::create(Path::new("ck")).err().unwrap();
        assert_eq!(relative.kind(), io::ErrorKind::InvalidInput);
        std::fs::write(scratch.0.join("note"), b"x").unwrap();
        let used = BundleWriter::create(&scratch.0).err().unwrap();
        assert!(used.to_string().contains("not empty"), "{used}");
        let file = BundleWriter::create(&scratch.0.join("note")).err().unwrap();
        assert!(file.to_string().contains("not a directory"), "{file}");
        let orphan = BundleWriter::create(&scratch.0.join("no/such"))
            .err()
            .unwrap();
        assert_eq!(orphan.kind(), io::ErrorKind::NotFound);
        // An empty directory someone made for it is fine.
        std::fs::create_dir(scratch.bundle()).unwrap();
        write(&scratch.bundle(), false);
        Bundle::open(&scratch.bundle()).unwrap();
    }

    // A capture that fails part way must not leave files a later reader, or
    // a later capture into the same directory, would trip on.
    #[test]
    fn an_unsealed_writer_removes_what_it_wrote() {
        let scratch = Scratch::new("abandon");
        let dir = scratch.bundle();
        let mut w = BundleWriter::create(&dir).unwrap();
        w.write_bytes(Component::Profile, b"{}").unwrap();
        w.write_ram(&guest(), &|| false).unwrap();
        assert!(w.write_bytes(Component::Profile, b"{}").is_err());
        let err = w.seal(Vec::new()).unwrap_err();
        assert_eq!(err.to_string(), "cpu.json was not written");
        assert!(
            std::fs::symlink_metadata(&dir).is_err(),
            "the directory it created is still there"
        );

        std::fs::create_dir(&dir).unwrap();
        let mut w = BundleWriter::create(&dir).unwrap();
        w.write_bytes(Component::Profile, b"{}").unwrap();
        // As a seal whose directory sync failed after the rename leaves it.
        std::fs::write(dir.join(MANIFEST), b"{}").unwrap();
        drop(w);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "the drop left a file"
        );
        assert!(
            std::fs::symlink_metadata(&dir).is_ok(),
            "the drop removed a directory it did not create"
        );
    }

    // The writer must refuse what the reader would, before the seal: a
    // sealed bundle the reader refuses is a lost session once the source is
    // fenced.
    #[test]
    fn the_writer_refuses_what_the_reader_would() {
        let scratch = Scratch::new("writer-limits");
        let dir = scratch.bundle();
        let mut w = BundleWriter::create(&dir).unwrap();
        let big = vec![b' '; Component::Session.limit() as usize + 1];
        let err = w.write_bytes(Component::Session, &big).unwrap_err();
        assert!(err.to_string().contains("session.json: would be"), "{err}");
        // A component written through a stream is refused once it is over.
        let err = w
            .write_with(Component::Disk, |out| out.write_all(&big))
            .unwrap_err();
        assert!(err.to_string().contains("disk.json: would be"), "{err}");
        drop(w);
        assert!(
            std::fs::symlink_metadata(&dir).is_err(),
            "the refused writer left its directory"
        );

        // The seal runs the reader's manifest checks, so a writer that drifts
        // from the reader fails the capture instead of sealing. The drift is
        // made by hand here: a hash the reader would not take.
        let mut w = BundleWriter::create(&dir).unwrap();
        w.write_bytes(Component::Profile, profile().to_json().as_bytes())
            .unwrap();
        w.write_ram(&guest(), &|| false).unwrap();
        for component in [
            Component::Cpu,
            Component::Platform,
            Component::Devices,
            Component::Session,
        ] {
            w.write_bytes(component, b"{}").unwrap();
        }
        w.written[3].1.sha256 = "not hex".into();
        let err = w.seal(Vec::new()).unwrap_err();
        assert!(
            err.to_string().contains("the reader would refuse it"),
            "{err}"
        );
        assert!(
            std::fs::symlink_metadata(&dir).is_err(),
            "the refused seal left its directory"
        );
    }

    #[test]
    fn a_bundle_directory_must_be_below_the_root() {
        let scratch = Scratch::new("resolve");
        let root = scratch.0.canonicalize().unwrap();
        std::fs::create_dir(root.join("sb")).unwrap();
        let ok = |dir: &str| resolve_in_root(&root, dir).unwrap();
        let refused = |dir: &str| resolve_in_root(&root, dir).unwrap_err().to_string();
        let r = root.display();
        assert_eq!(ok(&format!("{r}/ck")), root.join("ck"));
        assert_eq!(ok(&format!("{r}/sb/tx1/")), root.join("sb/tx1"));
        assert!(refused("ck").contains("absolute"));
        assert!(refused(&format!("{r}/../ck")).contains("no .. in it"));
        // A `.` inside the path names the same directory, and goes.
        assert_eq!(ok(&format!("{r}/./ck")), root.join("ck"));
        assert!(refused("/etc/ck").contains("not below the checkpoint root"));
        assert!(refused(&format!("{r}")).contains("the checkpoint root itself"));
        assert!(refused(&format!("{r}-other/ck")).contains("not below"));
        // A link inside the root can point anywhere.
        std::os::unix::fs::symlink("/tmp", root.join("out")).unwrap();
        assert!(
            refused(&format!("{r}/out/ck")).contains("is a link"),
            "{}",
            refused(&format!("{r}/out/ck"))
        );
        assert!(resolve_in_root(&root, &format!("{r}/none/ck")).is_err());
    }

    #[test]
    fn devices_json_needs_its_irq_levels() {
        let doc = DevicesDoc {
            states: DeviceStates::default(),
            irq_levels: IrqLevels {
                blk: true,
                ..IrqLevels::default()
            },
        };
        let json = doc.to_json().unwrap();
        assert_eq!(
            String::from_utf8(json.clone()).unwrap(),
            r#"{"blk":null,"irq_levels":{"blk":true,"net":false,"uart":false,"vsock":false},"net":null,"pl011":null,"rtc":null,"uart":null,"version":1,"vsock":null}"#
        );
        assert_eq!(DevicesDoc::from_json(&json).unwrap(), doc);
        let without = br#"{"version":1,"blk":null,"net":null,"vsock":null,"pl011":null,"uart":null,"rtc":null}"#;
        assert!(DevicesDoc::from_json(without).is_err());
        let extra = String::from_utf8(json)
            .unwrap()
            .replace("\"uart\":false", "\"uart\":false,\"fs\":true");
        assert!(DevicesDoc::from_json(extra.as_bytes()).is_err());
    }
}

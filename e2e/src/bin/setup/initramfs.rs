// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

//! The guest initramfs, a newc cpio archive of the root filesystem tarball with
//! the suite's init and agent added.
//!
//! The archive is written directly, so no `cpio` program and no root are
//! needed. Device nodes are archive entries, and the kernel creates them as it
//! unpacks the archive. Every entry is owned by root and dated 0, so the
//! archive depends only on its inputs.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;

use flate2::read::GzDecoder;
use tar::{Archive, EntryType};

use crate::Result;

/// The type bits of a regular file.
const S_IFREG: u32 = 0o100_000;
/// The type bits of a directory.
const S_IFDIR: u32 = 0o040_000;
/// The type bits of a symbolic link.
const S_IFLNK: u32 = 0o120_000;
/// The type bits of a character device.
const S_IFCHR: u32 = 0o020_000;

/// Writes the initramfs built from `rootfs`, `init` and `agent` to `out`.
///
/// The archive holds the entries of the gzipped tarball `rootfs`, then `init`
/// as `/init`, `agent` as `/sbin/hvi-e2e-agent` and the console device. The
/// console node is there because the kernel opens `/dev/console` for init's
/// output before init has mounted anything.
pub(crate) fn build(rootfs: &Path, init: &Path, agent: &Path, out: &Path) -> Result<()> {
    let file = File::create(out).map_err(|e| format!("creating {}: {e}", out.display()))?;
    let mut cpio = Cpio::new(BufWriter::new(file));
    let tarball = File::open(rootfs).map_err(|e| format!("opening {}: {e}", rootfs.display()))?;
    add_tarball(&mut cpio, tarball).map_err(|e| format!("reading {}: {e}", rootfs.display()))?;
    let read =
        |path: &Path| std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()));
    cpio.entry("init", S_IFREG | 0o755, (0, 0), &read(init)?)?;
    cpio.entry("sbin/hvi-e2e-agent", S_IFREG | 0o755, (0, 0), &read(agent)?)?;
    cpio.entry("dev/console", S_IFCHR | 0o600, (5, 1), &[])?;
    cpio.finish()
        .map_err(|e| format!("writing {}: {e}", out.display()).into())
}

/// Adds every entry of the gzipped tarball `tarball` to `cpio`.
///
/// A hard link becomes a copy of the file it links to, since the kernel unpacks
/// a newc hard link only from entries that share an inode number.
fn add_tarball(cpio: &mut Cpio<impl Write>, tarball: File) -> Result<()> {
    let mut archive = Archive::new(GzDecoder::new(tarball));
    let mut files: HashMap<String, (u32, Vec<u8>)> = HashMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry_name(&entry.path()?.to_string_lossy());
        if name.is_empty() {
            continue;
        }
        let mode = entry.header().mode()? & 0o7777;
        match entry.header().entry_type() {
            EntryType::Directory => cpio.entry(&name, S_IFDIR | mode, (0, 0), &[])?,
            EntryType::Regular => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                cpio.entry(&name, S_IFREG | mode, (0, 0), &data)?;
                files.insert(name, (mode, data));
            }
            EntryType::Symlink => {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| format!("{name}: the symlink has no target"))?;
                let target = target.to_string_lossy().into_owned();
                cpio.entry(&name, S_IFLNK | 0o777, (0, 0), target.as_bytes())?;
            }
            EntryType::Link => {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| format!("{name}: the hard link has no target"))?;
                let target = entry_name(&target.to_string_lossy());
                let (mode, data) = files
                    .get(&target)
                    .ok_or_else(|| format!("{name} links to {target}, which comes later"))?;
                cpio.entry(&name, S_IFREG | mode, (0, 0), data)?;
            }
            other => return Err(format!("{name}: unsupported tar entry {other:?}").into()),
        }
    }
    Ok(())
}

/// Returns a tar path as an archive name: relative, with no leading `./` and no
/// trailing slash.
fn entry_name(path: &str) -> String {
    path.trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

/// A newc ("070701") cpio archive being written.
struct Cpio<W: Write> {
    /// The writer the archive goes to.
    out: W,
    /// The inode number the next entry gets.
    next_inode: u32,
}

impl<W: Write> Cpio<W> {
    /// Starts an archive written to `out`.
    fn new(out: W) -> Cpio<W> {
        Cpio { out, next_inode: 1 }
    }

    /// Adds an entry named `name` with `mode`, the device numbers `rdev` and
    /// the contents `data`.
    fn entry(&mut self, name: &str, mode: u32, rdev: (u32, u32), data: &[u8]) -> Result<()> {
        let inode = self.next_inode;
        self.next_inode += 1;
        let nlink = if mode & S_IFDIR == S_IFDIR { 2 } else { 1 };
        let size = u32::try_from(data.len()).map_err(|_| format!("{name} is too large"))?;
        // The name size counts the terminating NUL.
        let name_size = u32::try_from(name.len() + 1).map_err(|_| "a name is too long")?;
        let fields = [
            inode, mode, 0, 0, nlink, 0, size, 0, 0, rdev.0, rdev.1, name_size, 0,
        ];
        let mut header = String::from("070701");
        for field in fields {
            header.push_str(&format!("{field:08x}"));
        }
        self.out.write_all(header.as_bytes())?;
        self.out.write_all(name.as_bytes())?;
        self.out.write_all(&[0])?;
        // The header and name are padded to a multiple of four, and so is the
        // data.
        self.pad(header.len() + name.len() + 1)?;
        self.out.write_all(data)?;
        self.pad(data.len())?;
        Ok(())
    }

    /// Writes the zeros that round `len` up to a multiple of four.
    fn pad(&mut self, len: usize) -> Result<()> {
        self.out.write_all(&[0; 3][..(4 - len % 4) % 4])?;
        Ok(())
    }

    /// Ends the archive with its trailer entry and flushes it.
    fn finish(mut self) -> std::io::Result<()> {
        self.entry("TRAILER!!!", 0, (0, 0), &[])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.out.flush()
    }
}

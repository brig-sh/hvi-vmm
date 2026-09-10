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

//! Guest RAM in a form another process can map.
//!
//! Guest RAM is allocated as an object another process can open, so a
//! plugin that only reads guest memory can run outside the VMM process; a
//! private anonymous mapping could not be shared that way.
//!
//! - **Linux** uses a `memfd`, which is passed to the plugin over the control
//!   socket with `SCM_RIGHTS`. KVM only requires that `userspace_addr` be a
//!   valid host address in the creating process, so backing it with a
//!   `MAP_SHARED` memfd instead of anonymous memory changes nothing about how
//!   the guest sees it. vhost-user VMMs back guest RAM the same way.
//! - **macOS** has no `memfd`, so it uses a POSIX shared-memory object. The
//!   guest mapping is then established by calling `hv_vm_map` on the region's
//!   host pointer, rather than letting `applevisor` allocate. `hvi smoke --shm`
//!   proves that path end to end.
//!
//! The object is unlinked from the namespace as soon as it is created. It
//! stays alive through the open descriptor, so the RAM cannot outlive the VMM
//! or be opened by name by a process that was not given the descriptor.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;

use crate::guestmem::MemRegion;

/// A shareable guest-RAM allocation, the descriptor of an unlinked object
/// sized to hold the guest. The object lives as long as any mapping of it or
/// this value does.
pub struct SharedRam {
    /// The unlinked object, shared with every mapping of it.
    file: Arc<File>,
    /// Object length in bytes.
    len: usize,
}

impl SharedRam {
    /// Allocates `len` bytes of shareable memory.
    ///
    /// The backing object is unlinked immediately, so it is reachable only
    /// through the returned descriptor.
    pub fn new(len: usize) -> io::Result<Self> {
        let file = Self::create_object(len)?;
        Ok(Self {
            file: Arc::new(file),
            len,
        })
    }

    /// Creates the (already unlinked) backing object, sized to `len`.
    ///
    /// The returned `File` owns the descriptor from creation, so an early
    /// error closes it.
    fn create_object(len: usize) -> io::Result<File> {
        #[cfg(target_os = "linux")]
        {
            let name = c"hvi-guest-ram";
            // SAFETY: a valid NUL-terminated name; MFD_CLOEXEC keeps the
            // descriptor out of child processes.
            let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` is a descriptor this function created and owns.
            let file = unsafe { File::from_raw_fd(fd) };
            // SAFETY: sizing a descriptor we just created.
            if unsafe { libc::ftruncate(file.as_raw_fd(), len as libc::off_t) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(file)
        }
        #[cfg(target_os = "macos")]
        {
            // macOS caps the name at 31 characters including the slash, and the
            // object must be sized before it is mapped. O_EXCL so a stale
            // object is an error rather than a silently reused
            // mapping.
            //
            // The name carries a per-allocation counter as well as the pid,
            // because the pid alone is not unique within a process: between
            // shm_open and the shm_unlink below, a second allocation in the
            // same process would collide.
            static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let name = std::ffi::CString::new(format!("/hvi-ram-{}-{seq}", std::process::id()))
                .map_err(|_| io::Error::other("shm name"))?;
            // SAFETY: valid NUL-terminated name.
            let fd = unsafe {
                libc::shm_open(
                    name.as_ptr(),
                    libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
                    0o600 as libc::c_uint,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` is a descriptor this function created and owns.
            let file = unsafe { File::from_raw_fd(fd) };
            // Unlink now: the descriptor keeps it alive, and nothing can reach
            // it by name afterwards.
            // SAFETY: unlinking a name we just created.
            unsafe { libc::shm_unlink(name.as_ptr()) };
            // SAFETY: sizing a descriptor we just created.
            if unsafe { libc::ftruncate(file.as_raw_fd(), len as libc::off_t) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(file)
        }
    }

    /// Returns the region that maps the whole object at `gpa`.
    #[must_use]
    pub fn region_at(&self, gpa: u64) -> MemRegion {
        MemRegion {
            gpa,
            size: self.len as u64,
            file_offset: 0,
        }
    }

    /// Returns the backing object, shared with every region mapped from it.
    #[must_use]
    pub fn file(&self) -> &Arc<File> {
        &self.file
    }

    /// Returns the object length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the object is empty.
    ///
    /// Never true after `new`; it pairs with `len` for the
    /// `len_without_is_empty` lint.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the backing descriptor, which stays owned here and must not be
    /// closed.
    #[must_use]
    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guestmem::GuestRam;

    const BASE: u64 = 0x4000_0000;
    // The smallest object one region can map.
    const LEN: usize = MemRegion::ALIGN as usize;

    /// Maps the whole object as one region at `BASE`.
    fn view(ram: &SharedRam) -> GuestRam {
        GuestRam::new(ram, &[ram.region_at(BASE)]).expect("map")
    }

    #[test]
    fn allocates_and_reads_back() {
        let ram = SharedRam::new(LEN).expect("allocate");
        assert_eq!(ram.len(), LEN);
        assert!(!ram.is_empty());
        let mem = view(&ram);
        mem.write_u8(BASE, 0xab).expect("write");
        assert_eq!(mem.read_u32(BASE).expect("read") & 0xff, 0xab);
    }

    // The read-only plugin view depends on this.
    #[test]
    fn guest_ram_writes_are_visible_to_a_second_mapping() {
        let ram = SharedRam::new(LEN).expect("allocate");
        view(&ram)
            .write(BASE + 128, b"HVI-SHARED")
            .expect("write guest RAM");

        // SAFETY: a second, read-only view of the same object.
        let other = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ram.len(),
                libc::PROT_READ,
                libc::MAP_SHARED,
                ram.fd(),
                0,
            )
        };
        assert_ne!(other, libc::MAP_FAILED);
        // SAFETY: reading 10 bytes at offset 128, inside both mappings.
        let seen = unsafe { std::slice::from_raw_parts(other.cast::<u8>().add(128), 10) };
        assert_eq!(seen, b"HVI-SHARED", "the plugin's view is stale");
        // SAFETY: unmapping the view we just made.
        unsafe { libc::munmap(other, ram.len()) };
    }

    // The two platforms give the guarantee differently. On macOS the object is
    // a named POSIX shared-memory segment whose name derives from the pid, so
    // every name this process could have used is probed and must be gone. On
    // Linux a memfd has no filesystem name; its /proc link must be a memfd,
    // not an openable path.
    //
    // The macOS half reconstructs the name format, so a change to that format
    // must change this test too.
    #[test]
    fn the_backing_object_is_not_reachable_by_name() {
        let ram = SharedRam::new(LEN).expect("allocate");

        #[cfg(target_os = "macos")]
        {
            let pid = std::process::id();
            let open_by_name = |name: &std::ffi::CStr| -> i32 {
                // SAFETY: a valid NUL-terminated name; no O_CREAT, so this
                // only ever opens something that already exists.
                unsafe { libc::shm_open(name.as_ptr(), libc::O_RDONLY, 0 as libc::c_uint) }
            };

            // Positive control first. Without it a change to the name format
            // would leave the probe below passing on names nothing ever used.
            let control = std::ffi::CString::new(format!("/hvi-ram-{pid}-ctl")).unwrap();
            // SAFETY: a valid NUL-terminated name we own.
            let made = unsafe {
                libc::shm_open(
                    control.as_ptr(),
                    libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
                    0o600 as libc::c_uint,
                )
            };
            assert!(made >= 0, "the control object could not be created");
            let found = open_by_name(&control);
            assert!(found >= 0, "shm_open cannot see a linked object");
            // SAFETY: descriptors and a name this test created.
            unsafe {
                libc::close(found);
                libc::shm_unlink(control.as_ptr());
            }
            assert!(
                open_by_name(&control) < 0,
                "an unlinked object is still reachable, so the probe proves nothing"
            );
            // SAFETY: a descriptor this test created.
            unsafe { libc::close(made) };

            // The probe itself. The sequence number is process-wide and
            // every allocation increments it once, so this range covers every
            // name the test binary can have produced.
            for seq in 0..1024 {
                let name = std::ffi::CString::new(format!("/hvi-ram-{pid}-{seq}")).unwrap();
                let fd = open_by_name(&name);
                assert!(
                    fd < 0,
                    "guest RAM is reachable by name as {name:?}, which defeats the whole point"
                );
            }
        }

        #[cfg(target_os = "linux")]
        {
            // A memfd has no filesystem name. Its /proc link records the
            // creation name for diagnostics and is not a path: opening it
            // fails, which is what "unreachable by name" means here.
            let link = std::fs::read_link(format!("/proc/self/fd/{}", ram.fd()))
                .expect("the descriptor has a /proc link");
            let link = link.to_string_lossy().into_owned();
            assert!(
                link.starts_with("/memfd:"),
                "guest RAM is backed by {link}, not an anonymous memfd"
            );
            assert!(
                std::fs::File::open(&link).is_err(),
                "the memfd link {link} opens, so guest RAM has a reachable name"
            );
        }
        // Alive through the probes above, on both platforms.
        drop(ram);
    }

    // On macOS the object name is unique only per process; two allocations
    // inside the shm_open/shm_unlink window would collide.
    #[test]
    fn concurrent_allocations_do_not_collide() {
        // Collected before any join, so the allocations overlap.
        let handles: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| SharedRam::new(LEN)))
            .collect();
        let rams: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread").expect("allocate"))
            .collect();
        // Distinct objects: a write through one must not appear in another.
        let views: Vec<_> = rams.iter().map(view).collect();
        for (i, mem) in views.iter().enumerate() {
            mem.write_u8(BASE, i as u8 + 1).expect("write");
        }
        for (i, mem) in views.iter().enumerate() {
            assert_eq!(
                mem.read_u32(BASE).expect("read") & 0xff,
                u32::from(i as u8 + 1),
                "allocation {i} shares storage with another"
            );
        }
    }
}

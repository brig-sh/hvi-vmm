//! Guest RAM in a form another process can map.
//!
//! A plugin only reads guest memory, and reading it does not need
//! the hypervisor -- so it does not need to live in the VMM process at all.
//! That is only true if the RAM is backed by something *nameable*, though: a
//! private anonymous mapping cannot be handed to anyone. This module allocates
//! it from a shareable object instead, so an out-of-process plugin can
//! map the same pages read-only.
//!
//! - **Linux** uses a `memfd`, which is passed to the plugin over the control
//!   socket with `SCM_RIGHTS`. KVM only requires that `userspace_addr` be a
//!   valid host address in the creating process, so backing it with a
//!   `MAP_SHARED` memfd instead of anonymous memory changes nothing about how
//!   the guest sees it. This is what vhost-user VMMs do anyway.
//! - **macOS** has no `memfd`, so it uses a POSIX shared-memory object. The
//!   guest mapping is then established by calling `hv_vm_map` on our own
//!   pointer, rather than letting `applevisor` allocate. `hvi smoke --shm`
//!   proves that path end to end.
//!
//! The object is unlinked from the namespace as soon as it is mapped. It stays
//! alive through the open descriptor, so the RAM cannot outlive the VMM or be
//! opened by name by anything that was not handed the descriptor.

use std::io;

/// Page size the guest mapping must be aligned to. Apple silicon uses 16 KiB,
/// which `hv_vm_map` enforces on the address, the IPA and the length.
#[cfg(target_os = "macos")]
pub const PAGE: usize = 0x4000;
/// Page size the guest mapping must be aligned to.
#[cfg(not(target_os = "macos"))]
pub const PAGE: usize = 0x1000;

/// A shareable guest-RAM allocation: a descriptor plus the mapping we made from
/// it. Dropping it unmaps the region and closes the descriptor.
pub struct SharedRam {
    host: *mut u8,
    len: usize,
    fd: i32,
}

// SAFETY: `SharedRam` is just an owned mapping; the pointer is valid for `len`
// bytes for as long as the value lives, and the vCPU threads already coordinate
// their access to guest RAM through `GuestRam`.
unsafe impl Send for SharedRam {}
unsafe impl Sync for SharedRam {}

impl SharedRam {
    /// Allocates `len` bytes of shareable memory, rounded up to [`PAGE`].
    ///
    /// The backing object is unlinked immediately, so it is reachable only
    /// through the returned descriptor.
    pub fn new(len: usize) -> io::Result<Self> {
        let len = len.next_multiple_of(PAGE);
        let fd = Self::create_object(len)?;

        // SAFETY: `fd` is a descriptor sized to exactly `len` bytes.
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if host == libc::MAP_FAILED {
            let e = io::Error::last_os_error();
            // SAFETY: closing a descriptor we own and have not handed out.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(Self {
            host: host.cast::<u8>(),
            len,
            fd,
        })
    }

    /// Creates the (already unlinked) backing object, sized to `len`.
    fn create_object(len: usize) -> io::Result<i32> {
        #[cfg(target_os = "linux")]
        {
            let name = c"hvi-guest-ram";
            // SAFETY: a valid NUL-terminated name; MFD_CLOEXEC keeps the
            // descriptor out of anything we spawn that has no business with it.
            let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: sizing a descriptor we just created.
            if unsafe { libc::ftruncate(fd, len as libc::off_t) } != 0 {
                let e = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(e);
            }
            Ok(fd)
        }
        #[cfg(target_os = "macos")]
        {
            // macOS caps the name at 31 characters including the slash, and the
            // object must be sized before it is mapped. O_EXCL so a stale
            // object is an error rather than a silently reused
            // mapping.
            //
            // The name carries a per-allocation counter as well as the pid,
            // because the pid alone is not unique within a process: the window
            // between shm_open and the shm_unlink below is open to any other
            // allocation in flight, which is a live collision whenever one
            // process holds two guest-RAM objects (and is what made the unit
            // tests, which allocate on several threads, flake).
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
            // Unlink now: the descriptor keeps it alive, and nothing can reach
            // it by name afterwards.
            // SAFETY: unlinking a name we just created.
            unsafe { libc::shm_unlink(name.as_ptr()) };
            // SAFETY: sizing a descriptor we just created.
            if unsafe { libc::ftruncate(fd, len as libc::off_t) } != 0 {
                let e = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(e);
            }
            Ok(fd)
        }
    }

    /// Host pointer to the mapping.
    #[must_use]
    pub fn as_ptr(&self) -> *mut u8 {
        self.host
    }

    /// Length of the mapping, rounded up to [`PAGE`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the mapping is empty (never true in practice; present so `len`
    /// does not read as a lint violation).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The backing descriptor, to be sent to a plugin with `SCM_RIGHTS`.
    /// Borrowed, not owned: the caller must not close it.
    #[must_use]
    pub fn fd(&self) -> i32 {
        self.fd
    }
}

impl Drop for SharedRam {
    fn drop(&mut self) {
        // SAFETY: unmapping and closing exactly what we created in `new`.
        unsafe {
            libc::munmap(self.host.cast::<libc::c_void>(), self.len);
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The allocation is usable memory of at least the requested size.
    #[test]
    fn allocates_and_reads_back() {
        let ram = SharedRam::new(PAGE).expect("allocate");
        assert!(ram.len() >= PAGE);
        assert!(!ram.is_empty());
        // SAFETY: writing inside a mapping we own.
        unsafe {
            ram.as_ptr().write(0xab);
            assert_eq!(ram.as_ptr().read(), 0xab);
        }
    }

    /// A short request is rounded up to a whole page, since the guest mapping
    /// APIs require it.
    #[test]
    fn rounds_up_to_a_page() {
        let ram = SharedRam::new(1).expect("allocate");
        assert_eq!(ram.len(), PAGE);
    }

    /// End to end: what a VMM writes through `GuestRam` is what a tool reads
    /// from its own mapping of the same object -- the property a read-only
    /// view depends on.
    #[test]
    fn guest_ram_writes_are_visible_to_a_second_mapping() {
        const BASE: u64 = 0x4000_0000;
        let ram = SharedRam::new(PAGE).expect("allocate");
        // The mapping is live and covers `len` bytes from `as_ptr`.
        let view = crate::guestmem::GuestRam::new(ram.as_ptr(), BASE, ram.len());
        view.write(BASE + 128, b"HVI-SHARED")
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

    /// The point of the type: the same pages are reachable through a second
    /// mapping of the descriptor, which is what a plugin does.
    #[test]
    fn is_visible_through_a_second_mapping() {
        let ram = SharedRam::new(PAGE).expect("allocate");
        // SAFETY: mapping the same descriptor again, read-only, as a separate
        // view of the same object.
        let second = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ram.len(),
                libc::PROT_READ,
                libc::MAP_SHARED,
                ram.fd(),
                0,
            )
        };
        assert_ne!(second, libc::MAP_FAILED, "second mapping failed");
        // SAFETY: both mappings are live and cover the same object.
        unsafe {
            ram.as_ptr().add(64).write(0x5a);
            assert_eq!(
                second.cast::<u8>().add(64).read(),
                0x5a,
                "a write through the owner was not visible in the second mapping"
            );
            libc::munmap(second, ram.len());
        }
    }

    /// Two objects can be alive in one process at once, and they are distinct.
    ///
    /// On macOS the backing object is named, and a name that is unique only per
    /// process collides with any allocation still inside the window between its
    /// shm_open and its shm_unlink. Allocating from several threads at once is
    /// the shape that hit it.
    #[test]
    fn concurrent_allocations_do_not_collide() {
        // Collected before any join, so the allocations really do overlap.
        let handles: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| SharedRam::new(PAGE)))
            .collect();
        let rams: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread").expect("allocate"))
            .collect();
        // Distinct objects: a write through one must not appear in another.
        // SAFETY: every mapping is live and at least PAGE long.
        unsafe {
            for (i, ram) in rams.iter().enumerate() {
                ram.as_ptr().write(i as u8 + 1);
            }
            for (i, ram) in rams.iter().enumerate() {
                assert_eq!(
                    ram.as_ptr().read(),
                    i as u8 + 1,
                    "allocation {i} shares storage with another"
                );
            }
        }
    }
}

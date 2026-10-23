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

//! Reading guest physical memory through `/dev/mem`, as busybox's `devmem`
//! does.

use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

/// Returns the 32 bits at the physical address `address`.
///
/// # Errors
///
/// Errors if `address` is not 4-byte aligned, or `/dev/mem` cannot be opened
/// or mapped there.
pub(crate) fn read_u32(address: u64) -> io::Result<u32> {
    // SAFETY: `map` passes a readable, aligned pointer to a `u32`.
    map(address, |word: *const u32| unsafe {
        std::ptr::read_volatile(word)
    })
}

/// Returns the two 32-bit words at the physical address `address`, read with
/// one `ldp`.
///
/// The data abort of a load pair carries no instruction syndrome, so a
/// hypervisor that traps it cannot tell from the abort which registers to fill.
///
/// # Errors
///
/// Errors if `address` is not 8-byte aligned, or `/dev/mem` cannot be opened
/// or mapped there.
#[cfg(target_arch = "aarch64")]
pub(crate) fn load_pair(address: u64) -> io::Result<(u32, u32)> {
    map(address, |pair: *const u64| {
        // A load that a hypervisor skips leaves both as they are.
        let (mut first, mut second) = (0xdead_beef_u32, 0xdead_beef_u32);
        // SAFETY: `map` passes a readable, aligned pointer to the 8 bytes the
        // load reads, and the load writes only the two registers.
        unsafe {
            std::arch::asm!(
                "ldp {first:w}, {second:w}, [{pair}]",
                pair = in(reg) pair,
                first = inout(reg) first,
                second = inout(reg) second,
                options(nostack, readonly),
            );
        }
        (first, second)
    })
}

/// Maps the page around the physical address `address` from `/dev/mem` and
/// returns what `read` makes of the `W` there.
///
/// `address` must be aligned to the size of `W`, so the `W` stays inside the
/// page. The page is mapped since the kernel refuses a `read` of `/dev/mem`
/// outside RAM.
fn map<W, T>(address: u64, read: impl FnOnce(*const W) -> T) -> io::Result<T> {
    let width = size_of::<W>() as u64;
    if !address.is_multiple_of(width) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the address is not {width}-byte aligned"),
        ));
    }
    // SAFETY: sysconf takes a plain name and reads no memory.
    let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .map_err(|_| io::Error::last_os_error())?;
    let page = address & !(page_size - 1);
    let offset = libc::off_t::try_from(page)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the address is too large"))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_SYNC)
        .open("/dev/mem")?;
    // SAFETY: a new read-only mapping of one page of the open file, which no
    // other code refers to.
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size as usize,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            offset,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `address - page` is below the page size and aligned to `W`'s
    // size, which divides the page size, so the `W` stays inside the mapped
    // page.
    let word = unsafe {
        mapped
            .cast::<u8>()
            .add((address - page) as usize)
            .cast::<W>()
    };
    let value = read(word);
    // SAFETY: unmaps the page mapped above, which nothing else uses.
    unsafe { libc::munmap(mapped, page_size as usize) };
    Ok(value)
}

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

//! A `Send + Sync` view of guest physical RAM over the raw host mapping.
//!
//! applevisor's `Memory` is `!Send` (it holds a raw pointer with no `Send`
//! impl), so it cannot be shared across the per-vCPU threads that SMP needs.
//! The guest RAM is a single process-global region (`hv_vm_map`) that outlives
//! every vCPU, so we take its `host_addr()` once and access it directly here.
//!
//! Access is through `&self` (the pointer gives interior mutability), so device
//! backends and a plugin take a shared `&GuestRam` — no `&mut`
//! threading. Reads/writes are inherently racy against the running guest, which
//! is intrinsic to observing a live VM; they stay in-bounds and byte-safe.

use std::io;

/// A guest-physical-memory accessor over the host mapping at `[ram_base,
/// ram_base+len)`.
pub struct GuestRam {
    host: *mut u8,
    ram_base: u64,
    len: usize,
    /// Bytes mapped *below* the MMIO hole. Equal to `len` when the guest is
    /// small enough that no hole is needed.
    low_len: usize,
    /// Guest-physical address at which the remainder resumes above the hole.
    /// `u64::MAX` when there is no hole, so the split branch never fires.
    high_base: u64,
}

// SAFETY: `host` points at a single process-global mapping created with
// `hv_vm_map` that outlives all vCPU threads (the owning `applevisor::Memory`
// is held on the main thread for the VM's lifetime). Every access is
// bounds-checked against `[0, len)`. Concurrent access races the guest's own
// writes, which is inherent to observing a live guest and byte-safe for plain
// memory.
unsafe impl Send for GuestRam {}
unsafe impl Sync for GuestRam {}

impl GuestRam {
    /// Wraps the host mapping. `host` must be the `host_addr()` of an
    /// `applevisor::Memory` mapped at `ram_base` with at least `len` bytes,
    /// kept alive for as long as any `GuestRam` is in use.
    #[must_use]
    pub fn new(host: *mut u8, ram_base: u64, len: usize) -> Self {
        GuestRam {
            host,
            ram_base,
            len,
            low_len: len,
            high_base: u64::MAX,
        }
    }

    /// Wraps a mapping whose guest-physical view is split by an MMIO hole.
    ///
    /// A guest bigger than the device window cannot be one contiguous span of
    /// guest-physical memory: RAM laid over the virtio-mmio registers shadows
    /// them (the devices stop responding, silently), and RAM laid over the
    /// in-kernel LAPIC page at `0xfee00000` makes KVM refuse the memory region
    /// outright. So the low `low_len` bytes stay at `ram_base` and the
    /// remainder resumes at `high_base`, conventionally 4 GiB.
    ///
    /// The *host* mapping stays contiguous: the high half is simply the bytes
    /// after the low half, which is what lets one memfd back both KVM slots and
    /// one pointer serve both halves here.
    #[must_use]
    pub fn new_split(
        host: *mut u8,
        ram_base: u64,
        low_len: usize,
        high_base: u64,
        high_len: usize,
    ) -> Self {
        GuestRam {
            host,
            ram_base,
            len: low_len + high_len,
            low_len,
            high_base,
        }
    }

    /// Host pointer (for zero-copy scans).
    #[must_use]
    pub fn host_addr(&self) -> *mut u8 {
        self.host
    }

    /// Scans all of guest RAM for `needle`, returning the guest-physical
    /// addresses of the matches (capped at 64). Reads race the running guest,
    /// which is intrinsic to reading a live VM's memory.
    #[must_use]
    pub fn scan(&self, needle: &[u8]) -> Vec<u64> {
        let mut out = Vec::new();
        if needle.is_empty() || needle.len() > self.len {
            return out;
        }
        // SAFETY: `host` points at `len` valid bytes for the VM's lifetime; we
        // only read, and bound every index to `[0, len)`.
        let hay = unsafe { std::slice::from_raw_parts(self.host, self.len) };
        let first = needle[0];
        let mut i = 0;
        while i + needle.len() <= self.len {
            if hay[i] == first && &hay[i..i + needle.len()] == needle {
                // Host offsets are contiguous; guest-physical addresses are
                // not.
                out.push(if i < self.low_len {
                    self.ram_base + i as u64
                } else {
                    self.high_base + (i - self.low_len) as u64
                });
                if out.len() >= 64 {
                    break;
                }
                i += needle.len();
            } else {
                i += 1;
            }
        }
        out
    }

    /// True if `[gpa, gpa+len)` lies entirely inside mapped guest RAM.
    ///
    /// Devices use this to reject a virtqueue whose rings the driver placed
    /// outside RAM, before any access rather than one failed read at a time.
    /// Goes through the same translation as a read, so a split guest answers
    /// consistently: an address in the hole is not RAM, and a range above the
    /// hole is validated against the high half rather than folded into it.
    #[must_use]
    pub fn contains(&self, gpa: u64, len: u64) -> bool {
        usize::try_from(len).is_ok_and(|n| self.offset(gpa, n).is_ok())
    }

    /// Translates a guest-physical address + access length to a bounds-checked
    /// host offset.
    fn offset(&self, gpa: u64, n: usize) -> io::Result<usize> {
        let oob = || io::Error::new(io::ErrorKind::UnexpectedEof, "gpa out of guest RAM");
        let off = if gpa >= self.high_base {
            // Above the hole: the remainder sits directly after the low half in
            // the host mapping.
            self.low_len
                .checked_add((gpa - self.high_base) as usize)
                .ok_or_else(oob)?
        } else {
            let below = gpa
                .checked_sub(self.ram_base)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "gpa below RAM base"))?
                as usize;
            // An address inside the hole is a device, not RAM. Without this it
            // would fold into the high half and read the wrong bytes.
            if below >= self.low_len {
                return Err(oob());
            }
            below
        };
        if off.checked_add(n).map_or(true, |end| end > self.len) {
            return Err(oob());
        }
        // The halves are contiguous in the host mapping but not in the guest's
        // address space, so an access must not straddle the seam.
        if off < self.low_len && off + n > self.low_len {
            return Err(oob());
        }
        Ok(off)
    }

    /// Reads `buf.len()` bytes at guest-physical `gpa`.
    ///
    /// # Errors
    ///
    /// Errors if the range is outside mapped guest RAM.
    pub fn read(&self, gpa: u64, buf: &mut [u8]) -> io::Result<()> {
        let off = self.offset(gpa, buf.len())?;
        // SAFETY: `off..off+len` is in-bounds; src and dst do not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(self.host.add(off), buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    }

    /// Writes `data` at guest-physical `gpa`.
    ///
    /// # Errors
    ///
    /// Errors if the range is outside mapped guest RAM.
    pub fn write(&self, gpa: u64, data: &[u8]) -> io::Result<()> {
        let off = self.offset(gpa, data.len())?;
        // SAFETY: `off..off+len` is in-bounds; src and dst do not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.host.add(off), data.len());
        }
        Ok(())
    }

    /// Addresses `[gpa, gpa+len)` in the host mapping, for a caller that hands
    /// the bytes to a syscall (`preadv`/`pwritev`-style) rather than copying
    /// them through an intermediate buffer.
    ///
    /// # Errors
    ///
    /// Errors if the range is outside mapped guest RAM or straddles the MMIO
    /// hole.
    ///
    /// # Safety contract
    ///
    /// Returns a raw pointer, not a slice, on purpose. A `&[u8]` or
    /// `&mut [u8]` would tell the compiler something untrue about these
    /// bytes: the guest runs while the syscall is in flight, and a guest may
    /// point two descriptors of one chain at one address, so a caller
    /// assembling an iovec array would hold overlapping borrows of the same
    /// memory. Handing back a pointer keeps the bounds check and drops the
    /// aliasing claim, which is the part that was never true.
    ///
    /// The caller owes the usual raw-pointer duties: stay within `len`, and
    /// expect the bytes to race the running guest as `read`/`write` do.
    pub fn host_ptr(&self, gpa: u64, len: usize) -> io::Result<*mut u8> {
        let off = self.offset(gpa, len)?;
        // SAFETY: `off..off+len` is in-bounds, checked above by `offset`.
        Ok(unsafe { self.host.add(off) })
    }

    pub fn read_u16(&self, gpa: u64) -> io::Result<u16> {
        let mut b = [0u8; 2];
        self.read(gpa, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }
    pub fn read_u32(&self, gpa: u64) -> io::Result<u32> {
        let mut b = [0u8; 4];
        self.read(gpa, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    pub fn read_u64(&self, gpa: u64) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.read(gpa, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    pub fn write_u8(&self, gpa: u64, v: u8) -> io::Result<()> {
        self.write(gpa, &[v])
    }
    pub fn write_u16(&self, gpa: u64, v: u16) -> io::Result<()> {
        self.write(gpa, &v.to_le_bytes())
    }
    pub fn write_u32(&self, gpa: u64, v: u32) -> io::Result<()> {
        self.write(gpa, &v.to_le_bytes())
    }
    pub fn write_u64(&self, gpa: u64, v: u64) -> io::Result<()> {
        self.write(gpa, &v.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip_and_bounds() {
        let mut backing = vec![0u8; 0x1000];
        let base = 0x4000_0000;
        let ram = GuestRam::new(backing.as_mut_ptr(), base, backing.len());
        ram.write_u32(base + 0x10, 0xdead_beef).unwrap();
        assert_eq!(ram.read_u32(base + 0x10).unwrap(), 0xdead_beef);
        // below base and past the end both error.
        assert!(ram.read_u32(base - 4).is_err());
        assert!(ram.read_u32(base + 0x0ffe).is_err());
    }

    #[test]
    fn scan_finds_guest_physical_addresses() {
        let mut backing = vec![0u8; 0x1000];
        backing[0x100..0x109].copy_from_slice(b"needle-xy");
        backing[0x800..0x809].copy_from_slice(b"needle-xy");
        let base = 0x4000_0000;
        let ram = GuestRam::new(backing.as_mut_ptr(), base, backing.len());
        let hits = ram.scan(b"needle-xy");
        assert_eq!(hits, vec![base + 0x100, base + 0x800]);
        assert!(ram.scan(b"not-present").is_empty());
    }

    #[test]
    fn host_ptr_in_bounds_addresses_the_mapping() {
        let mut backing = vec![0u8; 0x1000];
        let base = 0x4000_0000;
        let ram = GuestRam::new(backing.as_mut_ptr(), base, backing.len());
        let ptr = ram.host_ptr(base + 0x10, 4).unwrap();
        // SAFETY: `host_ptr` bounds-checked these four bytes.
        unsafe { std::ptr::copy_nonoverlapping(0xdead_beefu32.to_le_bytes().as_ptr(), ptr, 4) };
        let mut got = [0u8; 4];
        ram.read(base + 0x10, &mut got).unwrap();
        assert_eq!(u32::from_le_bytes(got), 0xdead_beef);
    }

    #[test]
    fn host_ptr_out_of_bounds_errors() {
        let mut backing = vec![0u8; 0x1000];
        let base = 0x4000_0000;
        let ram = GuestRam::new(backing.as_mut_ptr(), base, backing.len());
        assert!(ram.host_ptr(base - 4, 4).is_err());
        assert!(ram.host_ptr(base + 0x0ffe, 4).is_err());
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;

    const LOW: usize = 0x1000; // stand-in for the MMIO gap base
    const HIGH_BASE: u64 = 0x1_0000; // stand-in for 4 GiB
    const HIGH: usize = 0x800;

    fn split() -> (Vec<u8>, GuestRam) {
        let mut backing = vec![0u8; LOW + HIGH];
        // Mark the first byte of each half so a mistranslation is visible
        // rather than merely out of range.
        backing[0] = 0xa1;
        backing[LOW] = 0xb2;
        let ram = GuestRam::new_split(backing.as_mut_ptr(), 0, LOW, HIGH_BASE, HIGH);
        (backing, ram)
    }

    #[test]
    fn the_low_half_translates_identically() {
        let (_b, ram) = split();
        let mut b = [0u8; 1];
        ram.read(0, &mut b).expect("low base");
        assert_eq!(b[0], 0xa1);
    }

    /// The high half is contiguous with the low half in the *host* mapping but
    /// starts at HIGH_BASE in the guest, so this is where a naive
    /// `gpa - ram_base` gets the wrong bytes rather than an error.
    #[test]
    fn the_high_half_translates_across_the_hole() {
        let (_b, ram) = split();
        let mut b = [0u8; 1];
        ram.read(HIGH_BASE, &mut b).expect("high base");
        assert_eq!(b[0], 0xb2);
    }

    /// Addresses inside the hole are devices, not RAM. Folding them into the
    /// high half is exactly the bug that makes RAM shadow the virtio registers.
    #[test]
    fn the_hole_itself_is_not_ram() {
        let (_b, ram) = split();
        let mut b = [0u8; 1];
        for gpa in [LOW as u64, LOW as u64 + 1, HIGH_BASE - 1] {
            assert!(
                ram.read(gpa, &mut b).is_err(),
                "gpa {gpa:#x} should not be RAM"
            );
            assert!(!ram.contains(gpa, 1), "gpa {gpa:#x} should not be RAM");
        }
    }

    /// The halves are adjacent in the host mapping, so a read that runs off the
    /// end of the low half would silently continue into the high half's bytes.
    #[test]
    fn a_read_may_not_straddle_the_seam() {
        let (_b, ram) = split();
        let mut buf = [0u8; 8];
        assert!(ram.read(LOW as u64 - 4, &mut buf).is_err());
        // But a read that ends exactly at the seam is fine.
        assert!(ram.read(LOW as u64 - 8, &mut buf).is_ok());
    }

    /// `host_ptr` shares `offset()` with `read`/`write`, so it must refuse the
    /// same straddling range rather than silently handing back a pointer to
    /// bytes that jump from the low half into the high half.
    #[test]
    fn host_ptr_may_not_straddle_the_seam() {
        let (_b, ram) = split();
        assert!(ram.host_ptr(LOW as u64 - 4, 8).is_err());
        assert!(ram.host_ptr(LOW as u64 - 8, 8).is_ok());
    }

    #[test]
    fn reads_past_the_end_of_the_high_half_fail() {
        let (_b, ram) = split();
        let mut b = [0u8; 1];
        assert!(ram.read(HIGH_BASE + HIGH as u64, &mut b).is_err());
        assert!(ram.contains(HIGH_BASE + HIGH as u64 - 1, 1));
    }

    /// scan() walks the contiguous host buffer, so it has to map the index back
    /// through the same hole or every hit above the seam is reported at an
    /// address that does not exist in the guest.
    #[test]
    fn scan_reports_guest_addresses_on_both_sides() {
        let mut backing = vec![0u8; LOW + HIGH];
        backing[0x40..0x44].copy_from_slice(b"MARK");
        backing[LOW + 0x20..LOW + 0x24].copy_from_slice(b"MARK");
        let ram = GuestRam::new_split(backing.as_mut_ptr(), 0, LOW, HIGH_BASE, HIGH);
        assert_eq!(ram.scan(b"MARK"), vec![0x40, HIGH_BASE + 0x20]);
    }

    /// An unsplit guest must behave exactly as before.
    #[test]
    fn an_unsplit_guest_is_unaffected() {
        let mut backing = vec![0u8; 0x2000];
        backing[0x1fff] = 0xcc;
        let ram = GuestRam::new(backing.as_mut_ptr(), 0, backing.len());
        let mut b = [0u8; 1];
        ram.read(0x1fff, &mut b).expect("last byte");
        assert_eq!(b[0], 0xcc);
        assert!(ram.read(0x2000, &mut b).is_err());
    }
}

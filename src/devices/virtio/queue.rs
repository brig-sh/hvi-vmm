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

//! The split virtqueue the virtio devices share.
//!
//! A [`QueueConfig`] holds what the driver programs into one queue and checks
//! it against guest RAM. A [`Queue`] is what the device serves once the driver
//! made the queue ready: it hands out the available chains as
//! [`DescriptorChain`]s and publishes completed ones to the used ring.

use virtio_queue::desc::split::Descriptor;
use virtio_queue::QueueT;
use vm_memory::{GuestAddress, GuestMemoryMmap};

use crate::memory::GuestRam;

/// Descriptor flags.
pub(super) const VIRTQ_DESC_F_NEXT: u16 = virtio_bindings::virtio_ring::VRING_DESC_F_NEXT as u16;
pub(super) const VIRTQ_DESC_F_WRITE: u16 = virtio_bindings::virtio_ring::VRING_DESC_F_WRITE as u16;
#[cfg(test)]
pub(super) const VIRTQ_DESC_F_INDIRECT: u16 =
    virtio_bindings::virtio_ring::VRING_DESC_F_INDIRECT as u16;

/// The largest queue size the in-process devices offer in the `QUEUE_NUM_MAX`
/// register.
pub(super) const QUEUE_MAX_SIZE: u16 = 256;

/// One virtqueue's driver-programmed state, and the largest size it takes.
///
/// Every field but `max_size` is driver-controlled, so the fields are private
/// and the setters check what the driver writes. `num` is stored only if it is
/// a non-zero power of two no greater than `max_size`, so [`QueueConfig::size`]
/// is a valid `u16` queue size. The check runs on the `u32` the driver wrote,
/// since `0x10000` is non-zero as a `u32` and zero as a `u16`.
pub(crate) struct QueueConfig {
    /// The largest size the driver may program.
    max_size: u16,
    /// The queue size, or 0 until the driver programs a valid one.
    num: u32,
    /// The queue the device serves, or `None` unless the driver set READY on
    /// the current programming and it passed the checks.
    queue: Option<virtio_queue::Queue>,
    /// The guest address of the descriptor table.
    desc: u64,
    /// The guest address of the avail ring.
    avail: u64,
    /// The guest address of the used ring.
    used: u64,
    /// The avail ring index of the next chain the device serves.
    last_avail: u16,
}

impl QueueConfig {
    /// Returns an unprogrammed queue that takes sizes up to `max_size`.
    pub(crate) fn new(max_size: u16) -> Self {
        Self {
            max_size,
            num: 0,
            queue: None,
            desc: 0,
            avail: 0,
            used: 0,
            last_avail: 0,
        }
    }

    /// Records the driver's queue size, ignoring anything the spec does not
    /// allow. A rejected size leaves the queue unusable rather than trusted.
    pub(crate) fn set_num(&mut self, v: u32) {
        self.num = if v != 0 && v <= u32::from(self.max_size) && v.is_power_of_two() {
            v
        } else {
            0
        };
        self.queue = None; // resizing invalidates the ring bounds we checked
    }

    /// Returns the validated ring size, or 0 when the driver has not programmed
    /// a valid one.
    pub(crate) fn size(&self) -> u16 {
        self.num as u16 // <= max_size by construction in `set_num`
    }

    /// Marks the queue ready when `v` sets READY, the size is valid, and the
    /// three rings fit inside guest RAM at the addresses the driver gave.
    ///
    /// Each ring must also sit at its virtio 1.2 (2.7) alignment: 16 bytes for
    /// the descriptor table, 2 for the avail ring and 4 for the used ring. An
    /// avail ring at address 0 is refused too, because the crate takes it for
    /// an unprogrammed queue and never serves it.
    pub(crate) fn set_ready(&mut self, v: u32, mem: &GuestRam) {
        self.queue = (v & 1 == 1 && self.avail != 0 && self.rings_fit(mem))
            .then(|| self.build())
            .flatten();
    }

    /// Returns the crate's queue for this programming, or `None` when the crate
    /// refuses the size or a ring address.
    fn build(&self) -> Option<virtio_queue::Queue> {
        let mut queue = virtio_queue::Queue::new(self.max_size).ok()?;
        queue.try_set_size(self.size()).ok()?;
        queue
            .try_set_desc_table_address(GuestAddress(self.desc))
            .ok()?;
        queue
            .try_set_avail_ring_address(GuestAddress(self.avail))
            .ok()?;
        queue
            .try_set_used_ring_address(GuestAddress(self.used))
            .ok()?;
        queue.set_ready(true);
        Some(queue)
    }

    /// Returns whether the driver made the queue ready.
    pub(crate) fn is_ready(&self) -> bool {
        self.queue.is_some()
    }

    /// Returns the address and the length in bytes of the descriptor table, the
    /// avail ring and the used ring, in that order.
    ///
    /// The lengths are those of a split virtqueue of `n` entries, the
    /// programmed size: `16*n` for the descriptor table, `6+2*n` for the avail
    /// ring and `6+8*n` for the used ring, each ring with its 2-byte event
    /// suffix.
    pub(crate) fn ring_extents(&self) -> [(u64, u64); 3] {
        let n = u64::from(self.num);
        [
            (self.desc, 16 * n),
            (self.avail, 6 + 2 * n),
            (self.used, 6 + 8 * n),
        ]
    }

    /// Returns whether the queue has a size and its three rings are in guest
    /// RAM.
    fn rings_fit(&self, mem: &GuestRam) -> bool {
        self.num != 0
            && self
                .ring_extents()
                .iter()
                .all(|&(address, len)| mem.contains(address, len))
    }

    /// Address of descriptor `d`, or `None` if the driver referenced an index
    /// outside the ring it programmed.
    pub(crate) fn desc_addr(&self, d: u16) -> Option<u64> {
        (u32::from(d) < self.num).then(|| self.desc + u64::from(d) * 16)
    }

    /// Address of the avail ring's `idx`-th slot, wrapped into the ring.
    pub(crate) fn avail_slot(&self, idx: u16) -> Option<u64> {
        let n = self.size();
        (n != 0).then(|| self.avail + 4 + u64::from(idx % n) * 2)
    }

    /// How many buffers the driver has published since `last_avail`.
    ///
    /// `None` if `avail.idx` is unreadable, or if it claims more than a ring's
    /// worth -- which no conforming driver can do, and which would otherwise
    /// let a single notify drive up to 65535 descriptor-chain walks.
    pub(crate) fn pending(&self, mem: &GuestRam) -> Option<u16> {
        let idx = mem.read_u16(self.avail + 2).ok()?;
        // Acquire against the guest's `virtio_wmb()`: the driver fills the
        // avail ring slot and the descriptor table before it bumps
        // `avail.idx`, and the ring slot is an unrelated address, so without
        // this the host may read the slot before it reads the index and get
        // the previous wrap's head. Free on x86, a `dmb ishld` on arm64, and
        // only once per drain pass rather than per chain.
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        let n = idx.wrapping_sub(self.last_avail);
        (n <= self.size()).then_some(n)
    }

    pub(crate) fn last_avail(&self) -> u16 {
        self.last_avail
    }
    pub(crate) fn set_last_avail(&mut self, v: u16) {
        self.last_avail = v;
    }

    pub(crate) fn set_desc_lo(&mut self, v: u32) {
        self.desc = set_lo(self.desc, v);
        self.queue = None;
    }
    pub(crate) fn set_desc_hi(&mut self, v: u32) {
        self.desc = set_hi(self.desc, v);
        self.queue = None;
    }
    pub(crate) fn set_avail_lo(&mut self, v: u32) {
        self.avail = set_lo(self.avail, v);
        self.queue = None;
    }
    pub(crate) fn set_avail_hi(&mut self, v: u32) {
        self.avail = set_hi(self.avail, v);
        self.queue = None;
    }
    pub(crate) fn set_used_lo(&mut self, v: u32) {
        self.used = set_lo(self.used, v);
        self.queue = None;
    }
    pub(crate) fn set_used_hi(&mut self, v: u32) {
        self.used = set_hi(self.used, v);
        self.queue = None;
    }

    /// Appends a completed buffer to the used ring and advances its index.
    pub(crate) fn push_used(&self, mem: &GuestRam, head: u16, len: u32) {
        let Some(n) = Some(self.size()).filter(|&n| n != 0) else {
            return;
        };
        let Ok(used_idx) = mem.read_u16(self.used + 2) else {
            return;
        };
        let entry = self.used + 4 + u64::from(used_idx % n) * 8;
        let _ = mem.write_u32(entry, u32::from(head));
        let _ = mem.write_u32(entry + 4, len);
        // Release against the guest's `virtio_rmb()` in
        // `virtqueue_get_buf_ctx_split`. The element and `used.idx` are
        // separate addresses with no dependency between them, so on arm64
        // the guest -- running on another core the whole time a host worker
        // thread is completing requests -- may observe the bumped index
        // while the element still holds the previous wrap's contents. It
        // then takes a descriptor id it has already freed, prints
        // "id %u is not a head!", sets `vq->broken` and fails every later
        // enqueue with -EIO.
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        let _ = mem.write_u16(self.used + 2, used_idx.wrapping_add(1));
    }

    /// Returns the queue a device serves from this programming, or `None` when
    /// the driver did not make the queue ready.
    pub(crate) fn into_queue(self) -> Option<Queue> {
        self.queue.map(|inner| Queue { inner })
    }
}

/// A queue the driver made ready, as its device serves it.
///
/// The device keeps its own place in both rings: the next avail entry to take
/// and the next used entry to fill. Neither is read back from guest RAM, where
/// the guest could rewrite it.
pub(crate) struct Queue {
    /// The split virtqueue.
    inner: virtio_queue::Queue,
}

impl Queue {
    /// Returns the number of entries in each ring.
    pub(crate) fn size(&self) -> u16 {
        self.inner.size()
    }

    /// Puts each chain the driver made available on the used ring, with the
    /// device-written length `f` returns for it, at most a queue's worth per
    /// call.
    ///
    /// Returns whether it put a chain on the used ring. The bound means a
    /// driver that adds chains during the call cannot hold the caller here.
    pub(crate) fn serve<'r>(
        &mut self,
        ram: &'r GuestRam,
        mut f: impl FnMut(DescriptorChain<'r>) -> u32,
    ) -> bool {
        let mut served = false;
        for _ in 0..self.size() {
            let Some(chain) = self.pop(ram) else {
                break;
            };
            let head = chain.head_index();
            let len = f(chain);
            served |= self.add_used(ram, head, len);
        }
        served
    }

    /// Returns the next chain the driver made available, or `None` when there
    /// is none or the avail ring claims more than the queue holds.
    pub(crate) fn pop<'r>(&mut self, ram: &'r GuestRam) -> Option<DescriptorChain<'r>> {
        let inner = self.inner.pop_descriptor_chain(ram.memory())?;
        Some(DescriptorChain {
            inner,
            left: self.inner.size(),
            complete: false,
        })
    }

    /// Puts chain `head` on the used ring with `len` device-written bytes, and
    /// returns whether it did.
    ///
    /// A head outside the ring gets no used entry. Only a driver that wrote an
    /// index outside the ring produces one.
    ///
    /// The used entry is written before the used index, which is stored with
    /// release ordering, so a guest that sees the index also sees the entry.
    pub(crate) fn add_used(&mut self, ram: &GuestRam, head: u16, len: u32) -> bool {
        self.inner.add_used(ram.memory(), head, len).is_ok()
    }
}

/// The descriptors of one chain, at most as many as the queue has entries.
///
/// Virtio 1.2 (2.7.5.3.1) bounds a chain at the queue size, counting the
/// descriptors of an indirect table too. The crate follows an indirect table
/// whether or not the driver negotiated it and then allows the table's own
/// length, up to 65535, so the bound is kept here instead.
///
/// No device that walks its chains through this type offers
/// `VIRTIO_RING_F_INDIRECT_DESC`, which the same section requires of a driver
/// before it sets the flag. A chain that sets it anyway is followed, within the
/// bound, rather than refused.
pub(crate) struct DescriptorChain<'r> {
    /// The crate's walk of the chain.
    inner: virtio_queue::DescriptorChain<&'r GuestMemoryMmap>,
    /// How many more descriptors the chain may yield.
    left: u16,
    /// Whether the last descriptor yielded ended the chain.
    complete: bool,
}

impl DescriptorChain<'_> {
    /// Returns the index of the chain's first descriptor, which the used ring
    /// names.
    pub(crate) fn head_index(&self) -> u16 {
        self.inner.head_index()
    }

    /// Returns whether the walk ended at a descriptor without NEXT.
    ///
    /// A chain is incomplete when it is longer than the queue, loops, names a
    /// descriptor outside its table or guest RAM, or has an indirect table the
    /// crate refuses.
    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }
}

impl Iterator for DescriptorChain<'_> {
    type Item = Descriptor;

    fn next(&mut self) -> Option<Descriptor> {
        self.left = self.left.checked_sub(1)?;
        let descriptor = self.inner.next()?;
        self.complete = !descriptor.has_next();
        Some(descriptor)
    }
}

fn set_lo(v: u64, lo: u32) -> u64 {
    (v & 0xffff_ffff_0000_0000) | u64::from(lo)
}
fn set_hi(v: u64, hi: u32) -> u64 {
    (v & 0x0000_0000_ffff_ffff) | (u64::from(hi) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x4000_0000;

    #[test]
    fn queue_rejects_zero_non_power_of_two_and_over_max() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x4000)]);
        // 0x1_0001 is 1, a valid size, when it is cut to 16 bits.
        for bad in [
            0,
            3,
            100,
            u32::from(QUEUE_MAX_SIZE) + 1,
            0x1_0000,
            0x1_0001,
            u32::MAX,
        ] {
            let mut q = QueueConfig::new(QUEUE_MAX_SIZE);
            q.set_num(bad);
            assert_eq!(q.size(), 0, "{bad} should be refused");
            q.set_ready(1, &mem);
            assert!(!q.is_ready(), "{bad} must not become ready");
        }
        for good in [1, 2, 4, 128, u32::from(QUEUE_MAX_SIZE)] {
            let mut q = QueueConfig::new(QUEUE_MAX_SIZE);
            q.set_num(good);
            assert_eq!(u32::from(q.size()), good, "{good} should be accepted");
        }
    }

    #[test]
    fn descriptor_index_outside_the_ring_is_refused() {
        let mut q = QueueConfig::new(QUEUE_MAX_SIZE);
        q.set_num(8);
        q.set_desc_lo(0x1000);
        assert_eq!(q.desc_addr(0), Some(0x1000));
        assert_eq!(q.desc_addr(7), Some(0x1000 + 7 * 16));
        assert_eq!(q.desc_addr(8), None, "index == size is out of the ring");
        assert_eq!(q.desc_addr(u16::MAX), None);
    }

    /// `avail.idx` claiming more than a ring's worth is a bogus ring, not
    /// 65535 chain walks.
    #[test]
    fn avail_idx_beyond_the_ring_is_refused() {
        let mem = GuestRam::from_ranges(&[(BASE, 0x4000)]);
        let mut q = QueueConfig::new(QUEUE_MAX_SIZE);
        q.set_num(8);
        q.set_avail_lo((BASE + 0x1000) as u32);
        q.set_avail_hi(((BASE + 0x1000) >> 32) as u32);

        mem.write_u16(BASE + 0x1000 + 2, 8).unwrap();
        assert_eq!(q.pending(&mem), Some(8), "a full ring is fine");
        mem.write_u16(BASE + 0x1000 + 2, 9).unwrap();
        assert_eq!(q.pending(&mem), None, "one past the ring is refused");
        mem.write_u16(BASE + 0x1000 + 2, 0xffff).unwrap();
        assert_eq!(q.pending(&mem), None);
    }

    const DESC: u64 = BASE;
    const AVAIL: u64 = BASE + 0x1000;
    const USED: u64 = BASE + 0x2000;

    /// Returns guest RAM large enough for the rings and a 300-entry indirect
    /// table at `BASE + 0x3000`.
    fn ram() -> GuestRam {
        GuestRam::from_ranges(&[(BASE, 0x8000)])
    }

    /// Returns the config of a queue of `size` entries with its rings at
    /// `DESC`, `AVAIL` and `USED`.
    fn config(size: u32) -> QueueConfig {
        let mut config = QueueConfig::new(QUEUE_MAX_SIZE);
        config.set_num(size);
        config.set_desc_lo(DESC as u32);
        config.set_desc_hi((DESC >> 32) as u32);
        config.set_avail_lo(AVAIL as u32);
        config.set_avail_hi((AVAIL >> 32) as u32);
        config.set_used_lo(USED as u32);
        config.set_used_hi((USED >> 32) as u32);
        config
    }

    /// Returns the queue a device serves from [`config`], made ready.
    fn ready(mem: &GuestRam, size: u32) -> Queue {
        let mut config = config(size);
        config.set_ready(1, mem);
        config.into_queue().expect("the queue should be ready")
    }

    /// Writes entry `index` of the descriptor table at `table`.
    fn write_descriptor(
        mem: &GuestRam,
        table: u64,
        index: u64,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let at = table + index * 16;
        mem.write_u64(at, addr).unwrap();
        mem.write_u32(at + 8, len).unwrap();
        mem.write_u16(at + 12, flags).unwrap();
        mem.write_u16(at + 14, next).unwrap();
    }

    /// Makes chain `head` available as the next entry of the avail ring of a
    /// queue of `size` entries.
    fn make_available(mem: &GuestRam, size: u16, head: u16) {
        let idx = mem.read_u16(AVAIL + 2).unwrap();
        mem.write_u16(AVAIL + 4 + u64::from(idx % size) * 2, head)
            .unwrap();
        mem.write_u16(AVAIL + 2, idx.wrapping_add(1)).unwrap();
    }

    /// Returns how many descriptors the next available chain yields, and
    /// whether it is complete.
    fn walk(queue: &mut Queue, mem: &GuestRam) -> (usize, bool) {
        let mut chain = queue.pop(mem).expect("a chain should be available");
        let count = chain.by_ref().count();
        (count, chain.is_complete())
    }

    #[test]
    fn misaligned_ring_is_not_ready() {
        let mem = ram();
        let mut aligned = config(8);
        aligned.set_ready(1, &mem);
        assert!(aligned.is_ready(), "the aligned rings are ready");

        let mut desc = config(8);
        desc.set_desc_lo((DESC + 8) as u32);
        let mut avail = config(8);
        avail.set_avail_lo((AVAIL + 1) as u32);
        let mut used = config(8);
        used.set_used_lo((USED + 2) as u32);
        for (ring, mut config) in [("desc", desc), ("avail", avail), ("used", used)] {
            config.set_ready(1, &mem);
            assert!(!config.is_ready(), "a misaligned {ring} ring is not ready");
            assert!(config.into_queue().is_none());
        }
    }

    // On x86 guest RAM starts at address 0, so a driver can place the avail
    // ring there.
    #[test]
    fn avail_ring_at_address_zero_is_not_ready() {
        let mem = GuestRam::from_ranges(&[(0, 0x4000)]);
        let mut config = QueueConfig::new(QUEUE_MAX_SIZE);
        config.set_num(8);
        config.set_desc_lo(0x1000);
        config.set_used_lo(0x2000);
        config.set_ready(1, &mem);
        assert!(!config.is_ready(), "an avail ring at 0 is refused");

        config.set_avail_lo(0x3000);
        config.set_ready(1, &mem);
        assert!(config.is_ready(), "the same queue elsewhere is ready");
    }

    // A driver on another vCPU can make chains available while they are served.
    // Here each served chain makes another available, up to 20 more.
    #[test]
    fn serve_takes_at_most_the_queue_size() {
        let mem = ram();
        let mut queue = ready(&mem, 8);
        write_descriptor(&mem, DESC, 0, BASE + 0x3000, 16, 0, 0);
        make_available(&mem, 8, 0);
        let mut refills = 20;

        let served = queue.serve(&mem, |_| {
            if refills > 0 {
                refills -= 1;
                make_available(&mem, 8, 0);
            }
            0
        });

        assert!(served);
        assert_eq!(mem.read_u16(USED + 2).unwrap(), 8);
    }

    #[test]
    fn chain_without_next_is_complete() {
        let mem = ram();
        let mut queue = ready(&mem, 8);
        write_descriptor(&mem, DESC, 0, BASE + 0x3000, 16, VIRTQ_DESC_F_NEXT, 1);
        write_descriptor(&mem, DESC, 1, BASE + 0x3100, 16, VIRTQ_DESC_F_WRITE, 0);
        make_available(&mem, 8, 0);

        assert_eq!(walk(&mut queue, &mem), (2, true));
    }

    #[test]
    fn direct_loop_ends_incomplete_at_the_queue_size() {
        let mem = ram();
        let mut queue = ready(&mem, 8);
        write_descriptor(&mem, DESC, 0, BASE + 0x3000, 16, VIRTQ_DESC_F_NEXT, 0);
        make_available(&mem, 8, 0);

        assert_eq!(walk(&mut queue, &mem), (8, false));
    }

    // The crate allows an indirect table its own length, up to 65535 entries.
    // Zero-length entries add no bytes, so the queue size is the only bound.
    #[test]
    fn indirect_table_longer_than_the_queue_ends_incomplete_at_the_queue_size() {
        let mem = ram();
        let mut queue = ready(&mem, 8);
        let table = BASE + 0x3000;
        for index in 0..300u16 {
            let flags = if index < 299 { VIRTQ_DESC_F_NEXT } else { 0 };
            write_descriptor(
                &mem,
                table,
                u64::from(index),
                BASE + 0x7000,
                0,
                flags,
                index + 1,
            );
        }
        write_descriptor(&mem, DESC, 0, table, 300 * 16, VIRTQ_DESC_F_INDIRECT, 0);
        make_available(&mem, 8, 0);

        assert_eq!(walk(&mut queue, &mem), (8, false));
    }

    // Virtio 1.2 (2.7.5.3.2) lets direct descriptors come before the one that
    // refers to an indirect table.
    #[test]
    fn indirect_table_after_direct_descriptors_is_followed() {
        let mem = ram();
        let mut queue = ready(&mem, 8);
        let table = BASE + 0x3000;
        write_descriptor(&mem, table, 0, BASE + 0x7000, 16, VIRTQ_DESC_F_NEXT, 1);
        write_descriptor(&mem, table, 1, BASE + 0x7100, 16, VIRTQ_DESC_F_WRITE, 0);
        write_descriptor(&mem, DESC, 0, BASE + 0x7200, 16, VIRTQ_DESC_F_NEXT, 1);
        write_descriptor(&mem, DESC, 1, BASE + 0x7300, 16, VIRTQ_DESC_F_NEXT, 2);
        write_descriptor(&mem, DESC, 2, table, 2 * 16, VIRTQ_DESC_F_INDIRECT, 0);
        make_available(&mem, 8, 0);

        assert_eq!(walk(&mut queue, &mem), (4, true));
    }

    #[test]
    fn indirect_table_inside_a_table_ends_incomplete() {
        let mem = ram();
        let mut queue = ready(&mem, 8);
        let table = BASE + 0x3000;
        write_descriptor(&mem, table, 0, table, 16, VIRTQ_DESC_F_INDIRECT, 0);
        write_descriptor(&mem, DESC, 0, table, 16, VIRTQ_DESC_F_INDIRECT, 0);
        make_available(&mem, 8, 0);

        assert_eq!(walk(&mut queue, &mem), (0, false));
    }

    #[test]
    fn indirect_table_of_a_partial_entry_ends_incomplete() {
        let mem = ram();
        let mut queue = ready(&mem, 8);
        let table = BASE + 0x3000;
        write_descriptor(&mem, table, 0, BASE + 0x7000, 16, 0, 0);
        write_descriptor(&mem, DESC, 0, table, 24, VIRTQ_DESC_F_INDIRECT, 0);
        make_available(&mem, 8, 0);

        assert_eq!(walk(&mut queue, &mem), (0, false));
    }

    #[test]
    fn head_outside_the_ring_gets_no_used_entry() {
        let mem = ram();
        let mut queue = ready(&mem, 8);
        make_available(&mem, 8, 8);

        let mut chain = queue.pop(&mem).expect("a chain should be available");
        let head = chain.head_index();
        assert_eq!(chain.by_ref().count(), 0);
        assert!(!chain.is_complete());

        assert!(!queue.add_used(&mem, head, 0));
        assert_eq!(mem.read_u16(USED + 2).unwrap(), 0);
    }

    #[test]
    fn serve_of_a_head_outside_the_ring_puts_nothing_on_the_used_ring() {
        let mem = ram();
        let mut queue = ready(&mem, 8);
        make_available(&mem, 8, 8);

        assert!(!queue.serve(&mem, |_| 0));
        assert_eq!(mem.read_u16(USED + 2).unwrap(), 0);
    }

    // The guest can write `used.idx`. The device keeps its own place in the
    // used ring, so the next entry goes in slot 1, not after the index the
    // guest wrote.
    #[test]
    fn used_index_written_by_the_guest_does_not_move_the_next_entry() {
        let mem = ram();
        let mut queue = ready(&mem, 8);
        queue.add_used(&mem, 3, 10);
        mem.write_u16(USED + 2, 5).unwrap();

        queue.add_used(&mem, 4, 20);

        assert_eq!(
            mem.read_u32(USED + 4 + 8).unwrap(),
            4,
            "slot 1 holds the head"
        );
        assert_eq!(mem.read_u32(USED + 4 + 8 + 4).unwrap(), 20);
        assert_eq!(mem.read_u16(USED + 2).unwrap(), 2);
    }
}

// A litmus test for the used-ring publish in `QueueConfig::push_used`. It
// models what `run_fs_worker` does on macOS: a host thread that is not the vCPU
// thread appends completions to the used ring while the guest is running and
// consuming that same ring.
#[cfg(test)]
mod ordering_tests {
    use super::QueueConfig;
    use crate::memory::GuestRam;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering as AOrd};

    const BASE: u64 = 0x4000_0000;
    const N: u32 = 256;
    const ITERS: u32 = 4_000_000;

    /// How long each arm may run for. The iteration count is the ceiling; this
    /// is what actually ends the run anywhere the two threads cannot spin
    /// freely.
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

    /// Back off while waiting on the other thread.
    ///
    /// A bare `spin_loop` assumes the other thread is running on another core
    /// right now. On a runner with fewer cores than that it is a way to hold a
    /// core doing nothing until the scheduler takes it away, which is how this
    /// test went from half a second to tens of minutes on a hosted macOS
    /// runner. Spin briefly for the common case, then yield so progress never
    /// depends on there being a spare core.
    fn wait(idle: &mut u32) {
        *idle += 1;
        if *idle < 64 {
            std::hint::spin_loop();
        } else {
            *idle = 0;
            std::thread::yield_now();
        }
    }

    /// The head descriptor id the device hands back for completion `i`. A real
    /// guest allocates heads from a free list, so the id in a given used slot
    /// differs from one wrap of the ring to the next; making it `slot` would
    /// make a stale id indistinguishable from a fresh one.
    fn expected_head(i: u32) -> u32 {
        (i % N + i / N) % N
    }

    /// The real thing. This is what the test guards: if the release in
    /// `QueueConfig::push_used` is ever removed, this arm starts tearing on any
    /// weakly ordered host.
    fn publish_real(q: &QueueConfig, mem: &GuestRam, _used: u64, head: u16, len: u32) {
        q.push_used(mem, head, len);
    }

    /// The publish as it was before the fence: element stores, then the index
    /// store, with nothing in between.
    ///
    /// This is the harness's positive control, and it is deliberately a local
    /// copy rather than a call into `QueueConfig`. Pointing it at `push_used`
    /// would make it track whatever `push_used` does, so the moment the
    /// fence landed the control would stop tearing and the test would be
    /// asserting against itself.
    fn publish_unfenced(_q: &QueueConfig, mem: &GuestRam, used: u64, head: u16, len: u32) {
        let n = N as u16;
        let Ok(used_idx) = mem.read_u16(used + 2) else {
            return;
        };
        let entry = used + 4 + u64::from(used_idx % n) * 8;
        let _ = mem.write_u32(entry, u32::from(head));
        let _ = mem.write_u32(entry + 4, len);
        let _ = mem.write_u16(used + 2, used_idx.wrapping_add(1));
    }

    /// Runs the device thread against a guest thread that consumes the used
    /// ring the way `virtqueue_get_buf_ctx_split` does: an acquire on
    /// `used.idx` (the guest's `virtio_rmb`), then a read of the element it
    /// claims to describe. Returns how many elements the guest observed stale
    /// (i.e. how many times it would have printed "is not a head!"), how many
    /// of those were a bogus descriptor id, and how many completions it got
    /// through. That last count is below `ITERS` when the time budget ended the
    /// run first.
    fn run(publish: fn(&QueueConfig, &GuestRam, u64, u16, u32)) -> (u32, u32, u32) {
        let start = std::time::Instant::now();
        let mem = GuestRam::from_ranges(&[(BASE, 0x8000)]);
        let used = BASE + 0x1000;

        let mut q = QueueConfig::new(N as u16);
        q.set_num(N);
        q.set_used_lo(used as u32);
        q.set_used_hi((used >> 32) as u32);

        // Pre-stamp every slot with a generation the guest recognises as stale.
        for s in 0..N {
            let e = used + 4 + u64::from(s) * 8;
            mem.write_u32(e, 0xdead_beef).unwrap();
            mem.write_u32(e + 4, u32::MAX).unwrap();
        }
        mem.write_u16(used + 2, 0).unwrap();

        let done = AtomicBool::new(false);
        let stale = AtomicU32::new(0);
        // A real device can never publish more than a ring's worth ahead of the
        // guest: the descriptors are not free again until the guest consumes
        // the used element. Without this the guest simply laps and every read
        // is stale for reasons that have nothing to do with ordering.
        let consumed = AtomicU32::new(0);
        let bad_head = AtomicU32::new(0);
        // used.idx as the guest sees it: an acquire load, not a plain read.
        let idx_addr = mem.host_ptr(used + 2, 2).unwrap() as usize;

        std::thread::scope(|s| {
            let start = &start;
            let q = &q;
            let mem = &mem;
            let done = &done;
            let stale = &stale;
            let consumed = &consumed;
            let bad_head = &bad_head;

            // The guest driver: poll used.idx, consume every new element.
            s.spawn(move || {
                let atomic_idx = unsafe { &*(idx_addr as *const AtomicU16) };
                let mut seen: u32 = 0;
                let mut idle = 0u32;
                loop {
                    let cur = atomic_idx.load(AOrd::Acquire);
                    // How far ahead the device claims to be, as a count rather
                    // than by chasing equality. Chasing it deadlocks: the
                    // control arm exists to make `used.idx` observable stale,
                    // so `cur` can appear *behind* `seen`, and "consume until
                    // they are equal" then walks 65535 phantom entries.
                    // `consumed` overshoots the device, its `i - consumed`
                    // underflows to a huge number, and it waits for a guest
                    // that has already run away. That is a real deadlock. It
                    // needs a torn read to trigger, so it happens only on
                    // arm64, which is where this test is meant to run.
                    let avail = cur.wrapping_sub(seen as u16);
                    // A real device is held to a ring's depth by the flow
                    // control below, so anything beyond that is a stale index
                    // rather than work. Re-read instead of chasing it.
                    if u32::from(avail) > N {
                        wait(&mut idle);
                        continue;
                    }
                    for _ in 0..avail {
                        let e = used + 4 + u64::from(seen % N) * 8;
                        let id = mem.read_u32(e).unwrap();
                        let len = mem.read_u32(e + 4).unwrap();
                        let want_id = expected_head(seen);
                        if len != seen || id != want_id {
                            stale.fetch_add(1, AOrd::Relaxed);
                        }
                        if id != want_id {
                            // The guest just read a descriptor id it was not
                            // given for this slot: BAD_RING "id %u is not a
                            // head!" and vq->broken = true.
                            bad_head.fetch_add(1, AOrd::Relaxed);
                        }
                        seen = seen.wrapping_add(1);
                        consumed.store(seen, AOrd::Release);
                    }
                    if done.load(AOrd::Acquire) && (seen as u16) == atomic_idx.load(AOrd::Acquire) {
                        break;
                    }
                    // Independent of the device's own budget. A deadlock is a
                    // state neither thread can end on its own, so each carries
                    // its own way out.
                    if start.elapsed() > BUDGET {
                        break;
                    }
                    wait(&mut idle);
                }
            });

            // The device: what the fs worker's drain does, one completion per
            // iteration, with `len` carrying the generation.
            s.spawn(move || {
                let mut idle = 0u32;
                for i in 0..ITERS {
                    // Wall clock, not just an iteration count. These two
                    // threads are tightly coupled, because the device may not
                    // run more than a ring ahead. On a small virtualized runner
                    // that costs a context switch per batch rather than a few
                    // nanoseconds. Left unbounded it turned a 0.5-second test
                    // into a CI job still going 47 minutes later. Whatever it
                    // manages in the budget is enough: the assertion is that
                    // the guarded arm never tears, and the control reports
                    // whether it tore at all.
                    if i % 4096 == 0 && start.elapsed() > BUDGET {
                        break;
                    }
                    while i.wrapping_sub(consumed.load(AOrd::Acquire)) >= N - 1 {
                        // The budget has to be inside this loop, not only at
                        // the top of the iteration: this is where the device
                        // blocks, so a check it never reaches is not a bound at
                        // all.
                        if start.elapsed() > BUDGET {
                            done.store(true, AOrd::Release);
                            return;
                        }
                        wait(&mut idle);
                    }
                    publish(q, mem, used, expected_head(i) as u16, i);
                }
                done.store(true, AOrd::Release);
            });
        });

        (
            stale.load(AOrd::Relaxed),
            bad_head.load(AOrd::Relaxed),
            consumed.load(AOrd::Relaxed),
        )
    }

    /// Not part of the default suite. Run it with:
    ///
    /// ```text
    /// cargo test --release ordering_tests -- --ignored --nocapture
    /// ```
    ///
    /// It is a stress test, and it is kept out of CI on purpose. Two reasons,
    /// both learned the hard way:
    ///
    /// It is low-signal. On an M-series Mac the unfenced control is observed
    /// torn 0 to 3 times in 4,000,000 completions, so a green run mostly means
    /// the race did not happen to land, not that the ordering is right. An
    /// earlier version of this test appeared to be far more sensitive, with
    /// hundreds of tearings per run, but that was the harness miscounting: it
    /// chased `used.idx` by equality, so one stale index sent it walking 65535
    /// phantom slots and it flagged every one.
    ///
    /// And a stress test that spins two coupled threads is a bad CI citizen.
    /// That same phantom walk deadlocked against the device's flow control and
    /// left a hosted macOS job running for 47 minutes on a step that takes 36
    /// seconds.
    ///
    /// What it is good for is what it was written for: showing the defect
    /// exists, and showing a fix removes it. Remove the `fence(Release)` from
    /// `QueueConfig::push_used` and this fails.
    #[ignore = "timing-dependent stress test; run explicitly with --ignored"]
    #[test]
    fn push_used_is_never_observed_torn() {
        let (torn, bad, n) = run(publish_real);
        eprintln!(
            "push_used        : {torn} torn elements, {bad} bogus descriptor ids, in {n} completions"
        );
        let (ctl_torn, ctl_bad, ctl_n) = run(publish_unfenced);
        eprintln!(
            "unfenced control : {ctl_torn} torn elements, {ctl_bad} bogus descriptor ids, in {ctl_n} completions"
        );

        // The guard. A bogus id is the fatal one: the guest takes a descriptor
        // it has already freed, prints "id %u is not a head!", sets vq->broken,
        // and every later enqueue returns -EIO for the life of the guest.
        assert_eq!(
            bad, 0,
            "push_used handed the guest a descriptor id it had already freed"
        );
        assert_eq!(torn, 0, "push_used was observed torn");

        // The control says whether this host can detect the race at all. A
        // strongly ordered one (x86) will not tear even unfenced, and then the
        // assertions above have not been exercised -- say so rather than let a
        // green result imply more than it does.
        if ctl_torn == 0 {
            eprintln!(
                "note: the unfenced control did not tear on this host, so the check \
                 above did not exercise the ordering it is guarding. Run it on arm64."
            );
        }
    }
}

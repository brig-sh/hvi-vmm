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

//! The guest's writes to its RAM on KVM, from KVM's own dirty log.
//!
//! [`KvmWriteLog`] registers every RAM slot again with
//! `KVM_MEM_LOG_DIRTY_PAGES` when a move starts. KVM takes a flags-only
//! change to a slot in place while the vCPUs run, and starts the slot's log
//! clean. Each collect is one `KVM_GET_DIRTY_LOG` per slot, which returns the
//! pages written since the last one and write-protects them again in the
//! same step, under KVM's own lock. The log counts host pages, 16 KiB on a
//! Raspberry Pi 5's kernel, and each one written adds its four 4 KiB pages.
//! The stop registers the slots again without the flag. Slots past the RAM
//! regions, such as the hvi-time page's read-only one, are not touched.

use std::io;
use std::sync::Arc;

use kvm_ioctls::VmFd;

use crate::memory::{DirtyPages, GuestRam, GuestWriteLog};

/// KVM's dirty log over guest RAM; see the module documentation.
pub(crate) struct KvmWriteLog {
    /// The VM whose slots log.
    vm: Arc<VmFd>,
    /// Guest RAM, whose regions are slots `0..n`.
    ram: Arc<GuestRam>,
    /// The host page, the bytes each bit of KVM's log covers.
    page: u64,
}

impl KvmWriteLog {
    /// Returns the log of `vm`'s RAM slots, not yet logging.
    #[must_use]
    pub(crate) fn new(vm: Arc<VmFd>, ram: Arc<GuestRam>) -> Self {
        // SAFETY: sysconf has no preconditions.
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
        Self { vm, ram, page }
    }
}

impl GuestWriteLog for KvmWriteLog {
    fn start(&self) -> io::Result<()> {
        if let Err(e) = self.ram.set_kvm_dirty_log(&self.vm, true) {
            let _ = self.ram.set_kvm_dirty_log(&self.vm, false);
            return Err(io::Error::new(
                e.kind(),
                format!("turning on KVM's dirty log: {e}"),
            ));
        }
        Ok(())
    }

    fn collect(&self, into: &mut DirtyPages) -> io::Result<()> {
        for index in 0..into.region_count() {
            let bitmap = self.ram.kvm_dirty_log(&self.vm, index).map_err(|e| {
                io::Error::new(e.kind(), format!("KVM_GET_DIRTY_LOG of slot {index}: {e}"))
            })?;
            into.or_granules(index, &bitmap, self.page)?;
        }
        Ok(())
    }

    fn stop(&self) {
        if let Err(e) = self.ram.set_kvm_dirty_log(&self.vm, false) {
            eprintln!("{} turning off KVM's dirty log: {e}", crate::LOG_PREFIX);
        }
    }

    fn granule(&self) -> u64 {
        self.page
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;
    use crate::memory::SharedRam;
    use kvm_bindings::{kvm_vcpu_init, KVM_ARM_VCPU_PSCI_0_2};
    use kvm_ioctls::{Kvm, VcpuExit};

    const BASE: u64 = 0x4000_0000;
    /// An address no slot covers, where a store exits as MMIO.
    const MMIO: u64 = 0x0900_0000;
    /// `str x0, [x1]; add x1, x1, x2; subs x3, x3, #1; b.ne .-12;
    /// str x0, [x4]; b .-20`: stores x0 at x1, x1 + x2, ... x3 times, then
    /// exits on a store to x4. KVM moves the PC past that store on the next
    /// run, which then branches back to the start.
    const STRIDE_STUB: [u32; 6] = [
        0xf900_0020,
        0x8b02_0021,
        0xf100_0463,
        0x54ff_ffa1,
        0xf900_0080,
        0x17ff_fffb,
    ];

    fn x(n: u64) -> u64 {
        0x6030_0000_0010_0000 + 2 * n
    }

    // A flags-only update of a slot the guest runs from takes, the next
    // KVM_GET_DIRTY_LOG reports each host page the guest wrote and only
    // those, and the one after it is clean. Needs /dev/kvm on an arm64 host.
    #[test]
    #[ignore = "needs /dev/kvm on an arm64 host"]
    fn a_flags_only_update_logs_the_guests_writes() {
        let kvm = Kvm::new().unwrap();
        let vm = Arc::new(kvm.create_vm().unwrap());
        let shared = SharedRam::new(16 << 20).unwrap();
        let ram = Arc::new(GuestRam::new(&shared, &[shared.region_at(BASE)]).unwrap());
        ram.register_kvm_slots(&vm).unwrap();
        for (i, insn) in STRIDE_STUB.iter().enumerate() {
            ram.write_u32(BASE + 4 * i as u64, *insn).unwrap();
        }
        let mut vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        vcpu.vcpu_init(&kvi).unwrap();
        let log = KvmWriteLog::new(Arc::clone(&vm), Arc::clone(&ram));
        let page = log.granule();
        println!("host page {page} bytes");
        const COUNT: u64 = 64;
        let set = |vcpu: &kvm_ioctls::VcpuFd, id: u64, v: u64| {
            vcpu.set_one_reg(id, &v.to_le_bytes()).unwrap();
        };
        set(&vcpu, 0x6030_0000_0010_0040, BASE); // PC
        set(&vcpu, 0x6030_0000_0010_0042, 0x3c5); // PSTATE: EL1h, DAIF masked
        let mut run = |value: u64| {
            let set = |id: u64, v: u64| set(&vcpu, id, v);
            set(x(0), value);
            set(x(1), BASE + page);
            set(x(2), page);
            set(x(3), COUNT);
            set(x(4), MMIO);
            match vcpu.run().unwrap() {
                VcpuExit::MmioWrite(addr, _) => assert_eq!(addr, MMIO),
                other => panic!("unexpected exit {other:?}"),
            }
        };
        run(1);
        log.start().unwrap();
        let mut set = DirtyPages::new(&ram.regions());
        log.collect(&mut set).unwrap();
        assert!(set.is_empty(), "the log starts clean: {:?}", set.runs(64));
        run(0x5a5a);
        log.collect(&mut set).unwrap();
        let per = page / 4096;
        assert_eq!(set.count(), COUNT * per, "{:?}", set.runs(64));
        assert!(!set.contains(0, 0), "the code page was only read");
        assert!(set.contains(0, per) && set.contains(0, COUNT * per + per - 1));
        let mut again = DirtyPages::new(&ram.regions());
        log.collect(&mut again).unwrap();
        assert!(again.is_empty(), "the collect cleared the log");
        log.stop();
        run(2);
        assert_eq!(ram.read_u64(BASE + page).unwrap(), 2);
    }
}

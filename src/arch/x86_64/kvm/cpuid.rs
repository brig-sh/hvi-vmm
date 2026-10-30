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

//! The CPUID an x86-64 guest on KVM gets.

use kvm_bindings::CpuId;

/// The CPUID leaf 1 ECX bit that says the local APIC timer has a TSC-deadline
/// mode.
const CPUID_1_ECX_TSC_DEADLINE_TIMER: u32 = 1 << 24;
/// The CPUID leaf 1 ECX bit that says the CPU runs under a hypervisor.
const CPUID_1_ECX_HYPERVISOR: u32 = 1 << 31;

/// Returns `supported`, the CPUID KVM supports, with the bits added that the
/// guest needs.
///
/// RDRAND and RDSEED are not added. KVM reports them when the host has them,
/// and a guest told it has them on a host without them takes #UD on first use.
/// Without RDRAND, the decompressor's KASLR `rdrand` triple-faults, since its
/// boot IDT has no #UD vector. Without RDSEED, the kernel oopses in
/// `random_init_early` and hangs.
///
/// The hypervisor bit tells the guest it runs under KVM, so it reads KVM's
/// leaves from `0x4000_0000` and uses the paravirtual features they list. The
/// TSC-deadline bit offers the local APIC timer mode that KVM's in-kernel local
/// APIC emulates. Every KVM that hvi runs on reports
/// `KVM_CAP_TSC_DEADLINE_TIMER`, so the bit is set without a check. Newer KVMs
/// report the hypervisor and TSC-deadline bits themselves.
pub(super) fn guest_cpuid(mut supported: CpuId) -> CpuId {
    for entry in supported.as_mut_slice() {
        if entry.function == 1 {
            entry.ecx |= CPUID_1_ECX_TSC_DEADLINE_TIMER | CPUID_1_ECX_HYPERVISOR;
        }
    }
    supported
}

#[cfg(test)]
mod tests {
    use kvm_bindings::{kvm_cpuid_entry2, CpuId};

    use super::{guest_cpuid, CPUID_1_ECX_HYPERVISOR, CPUID_1_ECX_TSC_DEADLINE_TIMER};

    /// Leaf 1 ECX as an older KVM, such as Linux 6.8's, reports it, with SSE3
    /// and x2APIC set and neither the hypervisor bit nor the TSC-deadline bit.
    const LEAF_1_ECX: u32 = 1 | 1 << 21;
    /// Leaf 7 subleaf 0 EBX as KVM reports it, with FSGSBASE set and RDSEED
    /// clear.
    const LEAF_7_EBX: u32 = 1;
    /// The leaf 1 ECX bit for RDRAND.
    const RDRAND: u32 = 1 << 30;
    /// The leaf 7 subleaf 0 EBX bit for RDSEED.
    const RDSEED: u32 = 1 << 18;

    /// Returns a CPUID entry with the given leaf, subleaf and registers.
    fn entry(function: u32, index: u32, ebx: u32, ecx: u32, edx: u32) -> kvm_cpuid_entry2 {
        kvm_cpuid_entry2 {
            function,
            index,
            ebx,
            ecx,
            edx,
            ..Default::default()
        }
    }

    #[test]
    fn guest_cpuid_adds_its_bits_and_keeps_other_leaves() {
        // Both subleaves of leaf 7 and KVM's signature leaf, "KVMKVMKVM", which
        // `guest_cpuid` must leave alone.
        let untouched = [
            entry(7, 0, LEAF_7_EBX, 0, 0),
            entry(7, 1, 0, 0, 0),
            entry(0x4000_0000, 0, 0x4b4d_564b, 0x564b_4d56, 0x4d),
        ];
        let mut entries = vec![entry(1, 0, 0, LEAF_1_ECX, 0)];
        entries.extend(untouched);
        let cpuid = guest_cpuid(CpuId::from_entries(&entries).unwrap());

        let entries = cpuid.as_slice();
        assert_eq!(
            entries[0].ecx,
            LEAF_1_ECX | CPUID_1_ECX_TSC_DEADLINE_TIMER | CPUID_1_ECX_HYPERVISOR
        );
        assert_eq!(entries[1..], untouched);
    }

    #[test]
    fn guest_cpuid_passes_rdrand_and_rdseed_through() {
        // A host without them, as under `-cpu kvm64`. A guest told it has them
        // there triple-faults on its first `rdrand`.
        let entries = [entry(1, 0, 0, LEAF_1_ECX, 0), entry(7, 0, LEAF_7_EBX, 0, 0)];
        let cpuid = guest_cpuid(CpuId::from_entries(&entries).unwrap());
        assert_eq!(cpuid.as_slice()[0].ecx & RDRAND, 0);
        assert_eq!(cpuid.as_slice()[1].ebx & RDSEED, 0);

        // A host with them keeps them.
        let entries = [
            entry(1, 0, 0, LEAF_1_ECX | RDRAND, 0),
            entry(7, 0, LEAF_7_EBX | RDSEED, 0, 0),
        ];
        let cpuid = guest_cpuid(CpuId::from_entries(&entries).unwrap());
        assert_eq!(cpuid.as_slice()[0].ecx & RDRAND, RDRAND);
        assert_eq!(cpuid.as_slice()[1].ebx & RDSEED, RDSEED);
    }
}

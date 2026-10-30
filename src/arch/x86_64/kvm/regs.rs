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

//! The long-mode state the boot vCPU of an x86-64 guest enters with: the
//! identity page tables, the boot GDT, and the segment and control registers
//! that point at them.

use kvm_bindings::{kvm_dtable, kvm_segment};
use kvm_ioctls::VcpuFd;

use crate::arch::x86_64::layout::{BOOT_STACK, GDT_ADDR, PDPT_ADDR, PML4_ADDR};
use crate::memory::GuestRam;

// Long-mode control-register values and page-table entry bits.
const CR0_PE_PG: u64 = 0x8005_0033; // PE|MP|ET|NE|WP|AM|PG
const CR4_PAE: u64 = 0x0000_0020; // PAE
const EFER_LME_LMA: u64 = 0x0000_0500; // LME|LMA
const PDE64_PRESENT_RW_PS: u64 = 0x83; // present | writable | page-size (1 GiB)
const PDE64_PRESENT_RW: u64 = 0x03; // present | writable (table)

/// Returns a flat segment for `KVM_SET_SREGS`, with base 0 and a 4 GiB limit.
fn seg(selector: u16, code: bool) -> kvm_segment {
    kvm_segment {
        base: 0,
        limit: 0xf_ffff,
        selector,
        type_: if code { 0b1011 } else { 0b0011 }, // exec/read vs read/write, accessed
        present: 1,
        dpl: 0,
        db: u8::from(!code), // data=1, 64-bit code=0
        s: 1,
        l: u8::from(code), // 64-bit code segment
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

/// Sets the BSP into 64-bit long mode with `rip=entry`, `rsi=zero_page`.
pub(super) fn setup_long_mode(
    vcpu: &VcpuFd,
    entry: u64,
    zero_page: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut sregs = vcpu.get_sregs()?;
    let cs = seg(0x08, true);
    let ds = seg(0x10, false);
    sregs.cs = cs;
    sregs.ds = ds;
    sregs.es = ds;
    sregs.fs = ds;
    sregs.gs = ds;
    sregs.ss = ds;
    sregs.gdt = kvm_dtable {
        base: GDT_ADDR,
        limit: 3 * 8 - 1,
        padding: [0; 3],
    };
    sregs.cr3 = PML4_ADDR;
    sregs.cr0 = CR0_PE_PG;
    sregs.cr4 = CR4_PAE;
    sregs.efer = EFER_LME_LMA;
    vcpu.set_sregs(&sregs)?;

    let mut regs = vcpu.get_regs()?;
    regs.rip = entry;
    regs.rsi = zero_page; // boot_params
    regs.rsp = BOOT_STACK;
    regs.rbp = BOOT_STACK;
    regs.rflags = 0x2; // reserved bit set
    vcpu.set_regs(&regs)?;
    Ok(())
}

/// Identity-maps the first 4 GiB with 1 GiB pages.
///
/// `PML4[0]` points at the PDPT, and `PDPT[0..4]` are the pages. They cover
/// RAM, the virtio MMIO hole and the APIC region.
pub(super) fn write_boot_page_tables(
    ram: &GuestRam,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ram.write_u64(PML4_ADDR, PDPT_ADDR | PDE64_PRESENT_RW)?;
    for i in 0..4u64 {
        ram.write_u64(PDPT_ADDR + i * 8, (i << 30) | PDE64_PRESENT_RW_PS)?;
    }
    Ok(())
}

/// Writes the boot GDT, with a null entry and code and data entries that match
/// [`seg`].
pub(super) fn write_boot_gdt(
    ram: &GuestRam,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let code: u64 = 0x00af_9b00_0000_ffff; // present, code, long-mode, g
    let data: u64 = 0x00cf_9300_0000_ffff; // present, data, 32-bit, g
    ram.write_u64(GDT_ADDR, 0)?;
    ram.write_u64(GDT_ADDR + 8, code)?;
    ram.write_u64(GDT_ADDR + 16, data)?;
    Ok(())
}

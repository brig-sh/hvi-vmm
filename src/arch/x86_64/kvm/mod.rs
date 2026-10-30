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

//! The x86-64 guest on KVM, SMP-capable.
//!
//! The x86 counterpart of `aarch64::kvm`. KVM runs the LAPIC, the IOAPIC and
//! the PIT in the kernel (`create_irq_chip`, `create_pit2`), and the guest
//! brings up its APs with INIT-SIPI-SIPI, which the kernel handles. The VMM
//! enters the BSP in long mode and runs every vCPU thread. It builds the
//! initial long-mode state (identity page tables, flat 64-bit segments,
//! CR0/CR3/CR4/EFER), loads the bzImage or vmlinux, writes `boot_params` (see
//! `super::loader`), and enters at the 64-bit entry with RSI pointing at the
//! zero page.
//!
//! Devices are the shared virtio-mmio blk/net/vsock (serviced on
//! `KVM_EXIT_MMIO`) plus a 16550 serial on port I/O (`KVM_EXIT_IO`). The guest
//! powers off and resets through the ACPI PM1 control and reset registers,
//! which the exit loop serves as ports. A guest without ACPI resets through the
//! i8042's CPU-reset command. A plugin, if the caller supplied one, sees CR3 as
//! the walk root.
//!
//! A long-mode entry needs KVM's `set_tss_address` and identity map, which
//! Intel VMX requires. It also needs `set_cpuid2`, since the guest reads CPUID
//! for feature detection and early boot triple-faults without it. Set
//! `HVI_X86_TRACE=1` for exit and register tracing.
//!
//! `boot` builds the VM, its RAM, devices and vCPUs, and runs it. `vcpu` runs
//! each vCPU thread and routes its exits to the devices. `regs` holds the
//! long-mode state the boot vCPU enters with, and `cpuid` the CPUID every vCPU
//! gets.

mod boot;
mod cpuid;
mod regs;
mod vcpu;

pub(crate) use boot::boot;

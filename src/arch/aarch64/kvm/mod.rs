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

//! The arm64 guest on KVM, SMP-capable.
//!
//! The Linux counterpart of `hvf`. KVM runs the GIC and PSCI in the kernel.
//! Secondaries are created powered off, and the guest brings them up with PSCI
//! `CPU_ON`, which the kernel serves. A device sets its interrupt line with
//! `KVM_IRQ_LINE`, which also wakes a vCPU in WFI. A kick sets the vCPU's
//! `immediate_exit` byte and signals its thread, as `hypervisor::kvm`
//! describes.
//!
//! The image and layout, the DTB, the virtio devices, the PL011 and the PL031,
//! the `RawEvent` ledger and the plugin interface are the same code the macOS
//! backend uses.
//!
//! `boot` builds the VM, its RAM, devices and vCPUs, and runs it. `vcpu` runs
//! each vCPU thread and routes its MMIO exits to the devices. `gic` sets up the
//! vGIC and encodes its interrupt lines. `regs` names the vCPU registers the
//! backend reads and writes, and sets the boot vCPU's.

mod boot;
mod gic;
mod regs;
mod vcpu;

pub(crate) use boot::boot;

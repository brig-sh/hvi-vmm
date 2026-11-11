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

//! The in-kernel IOAPIC of an x86-64 guest on KVM, and the interrupt lines on
//! its pins.

use std::sync::Arc;

use kvm_ioctls::VmFd;

use crate::devices::irq;
use crate::hypervisor::kvm;

/// The in-kernel IOAPIC of an x86-64 guest on KVM, whose lines are its pins.
pub(super) struct KernelIoApic {
    /// The VM whose IOAPIC has the lines.
    pub(super) vm: Arc<VmFd>,
}

impl irq::Chip for KernelIoApic {
    fn line(&self, gsi: u32) -> Arc<dyn irq::Line> {
        Arc::new(kvm::IrqLine::new(Arc::clone(&self.vm), gsi))
    }
}

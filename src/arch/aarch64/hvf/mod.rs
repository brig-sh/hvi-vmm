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

//! The arm64 guest on Hypervisor.framework, SMP-capable.
//!
//! One thread per vCPU (an `applevisor::Vcpu` is thread-bound). vcpu0 boots at
//! the kernel entry; secondaries park until the guest brings them up via PSCI
//! `CPU_ON`. Guest RAM is a `GuestRam` shared by every vCPU thread. Devices and
//! the vCPU-handle list are shared behind locks, and the event ledger is shared
//! as an `Arc<Ledger>`. A plugin, if the caller supplied one, is called on
//! vcpu0 between guest entries. See [`crate::plugin`].
//!
//! `boot` builds the VM, its RAM and devices, confines the process and runs the
//! vCPU threads. `vcpu` runs one of them: it creates and starts its vCPU, runs
//! the exit loop, and serves the MMIO, PSCI and system-register exits. `kick`
//! holds the vCPU handles a kick goes through and the secondaries' `CPU_ON`
//! mailboxes. `gic` holds the in-kernel GIC's interrupt lines and works out its
//! placement.

mod boot;
mod gic;
mod kick;
mod vcpu;

pub(crate) use boot::boot;

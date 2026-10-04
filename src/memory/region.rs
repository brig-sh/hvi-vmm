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

//! The placement of one guest RAM region, in the guest and in its backing
//! object.

/// A guest-physical span of the VM's RAM and where it sits in the object that
/// backs it, so a process that maps the same object sees the same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamRegion {
    /// Guest-physical address this span starts at.
    pub gpa: u64,
    /// Length in bytes.
    pub size: u64,
    /// Offset of `gpa` within the object that backs this region.
    pub file_offset: u64,
}

impl RamRegion {
    /// Alignment of `gpa`, `size` and `file_offset`, 1 MiB.
    ///
    /// Every host page size divides it, so a region's mapping offset and its
    /// hypervisor slot are page-aligned on any host.
    pub const ALIGN: u64 = 1 << 20;
}

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

//! The confinement hvi enters before it serves guest I/O.
//!
//! The virtio devices parse guest-controlled data in the same process as the
//! vCPU threads, so hvi confines that process. `seccomp` installs seccomp-bpf
//! allowlists on Linux, one per thread, and `seatbelt` enters a Seatbelt
//! profile on macOS. Each has a selftest that checks the confinement holds, run
//! as `hvi seccomp-selftest` and `hvi sandbox-selftest`.

#[cfg(target_os = "macos")]
pub mod seatbelt;
#[cfg(target_os = "linux")]
pub mod seccomp;

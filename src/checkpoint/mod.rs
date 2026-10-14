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

//! Checkpoint support: the machine profile a guest was built against, the
//! control socket that pauses and resumes it, and the bundle a capture writes.
//!
//! [`profile`] describes the machine in a form two hosts can compare before a
//! guest moves between them. [`control`] is the line protocol of the
//! `--control-sock` socket, and `server` the I/O thread that serves it.
//! [`bundle`] is the directory a capture writes and a restore reads, with
//! guest RAM in [`ram`], the vCPUs in [`cpu`] and the interrupt controller and
//! counter in [`platform`]. `restore` holds what every backend's `hvi restore`
//! shares.

pub mod bundle;
pub(crate) mod capture;
pub mod control;
pub mod cpu;
pub mod kvm_regs;
pub mod platform;
pub mod profile;
pub mod ram;
pub(crate) mod restore;
pub(crate) mod server;
pub mod stream;

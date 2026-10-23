// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

//! The harness the e2e tests boot guests with.
//!
//! A test builds a [`Vm`] with [`Vm::builder`] and boots it, which starts the
//! `hvi` binary the setup binary built. The run's event ledger goes in a
//! directory of the test's own, and its agent socket in a temporary directory.
//! The guest's init starts the agent, and the harness drives the guest through
//! it with an [`Agent`].
//!
//! A test ends the run with [`Vm::power_off`] or [`Vm::reset`], which check how
//! it stopped. A test that ends it with [`Vm::wait`] or [`Vm::kill`] checks the
//! [`RunOutput`] they return.
//!
//! The setup binary (`src/bin/setup`) prepares everything a test needs and
//! hands it over in `HVI_E2E_*` environment variables, which [`Suite`] reads.

mod agent;
mod daemon;
mod data;
mod export;
mod ledger;
mod net;
mod sockets;
mod stream;
mod suite;
mod vm;

pub use agent::{Agent, GuestOutput};
pub use data::{pattern, sha256};
pub use export::{export_dir, FsExport, PendingSocket, Virtiofsd};
pub use ledger::Ledger;
pub use net::{Gateway, Tap};
pub use suite::{vars, Suite};
pub use vm::{scratch_dir, sparse_file, RunOutput, Stop, Vm, VmBuilder};

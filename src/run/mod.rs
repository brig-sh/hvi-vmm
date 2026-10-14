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

//! A run of a guest: starting it, asking it to stop, and the loop that owns its
//! stop.
//!
//! [`boot`](crate::boot) runs a guest on the calling thread.
//! [`spawn`](crate::spawn) runs it on a thread of its own and returns a
//! [`Run`](crate::Run), which asks the run to stop and waits for it. A caller
//! of `boot` stops the run through a [`StopHandle`]: it creates the handle and
//! its [`StopRegistration`] with [`StopHandle::new_pair`] before the run, keeps
//! the handle and passes the registration in
//! [`BootConfig::stop`](crate::config::BootConfig::stop). The run takes the
//! registration by value, so it serves one run. A request on the handle stops
//! the run, and `boot` or [`Run::wait`](crate::Run::wait) returns
//! [`Stop::Requested`](crate::config::Stop::Requested) once it is torn down.
//! The two halves own both ends of the pipe for as long as either exists, so a
//! request after the run has ended still writes to that pipe, where nothing
//! reads it.
//!
//! [`stop_on_signals`](crate::signal::stop_on_signals) makes the stop signals
//! request a stop on a handle.

pub(crate) mod spawn;
mod stop;
mod supervisor;

pub use stop::{StopHandle, StopRegistration};
pub(crate) use supervisor::{record_start, run_to_stop, LeftRunning, RUN_SLOT};

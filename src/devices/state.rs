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

//! The device state a checkpoint carries, and the checks every restore shares.
//!
//! Each device's state is a plain serde struct beside the device, in a form
//! that names no host and no backend: integers of a fixed width, bytes as byte
//! lists, enums by name. What only the host holds (files, sockets, the
//! interrupt line, the event ledger) stays out, and a restore reattaches it.
//! Every struct refuses fields it does not know, so a newer format fails to
//! load instead of losing what it added.

use std::io;

/// Returns the error a restore refuses a corrupt or foreign state with.
pub(crate) fn invalid(what: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("device state: {what}"))
}

/// Refuses a state whose `version` this build does not read.
///
/// # Errors
///
/// Errors when `version` is not `want`.
pub(crate) fn check_version(device: &str, version: u32, want: u32) -> io::Result<()> {
    if version == want {
        Ok(())
    } else {
        Err(invalid(format_args!(
            "{device} state version {version}, this build reads {want}"
        )))
    }
}

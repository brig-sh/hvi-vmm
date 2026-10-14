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

//! `platform.json`: the interrupt controller and the guest counter.
//!
//! Neither is captured yet. The interrupt controller lives in the hypervisor
//! (HVF's `hv_gic`, KVM's vGIC, KVM's x86 irqchip and PIT), and each has its
//! own way out; the guest counter is an offset from the host's. Until those
//! exports exist, each section is a `{"kind":"not-captured"}` marker with the
//! reason, so a bundle says what it lacks instead of holding a default a
//! restore could mistake for the real thing. A restore refuses a marker.

use std::io;

use serde::{Deserialize, Serialize};

use crate::checkpoint::cpu::arch_name;
use crate::plugin::GuestArch;

/// The [`PlatformState`] format this build writes and reads.
pub const PLATFORM_STATE_VERSION: u32 = 1;

/// The interrupt controller's state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum IrqState {
    /// This build does not read the controller.
    NotCaptured {
        /// Why, for a person.
        reason: String,
    },
}

/// The guest counter's state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TimerState {
    /// This build does not read the counter.
    NotCaptured {
        /// Why, for a person.
        reason: String,
    },
}

/// An opaque blob a backend keeps beside the canonical state, such as HVF's
/// `hv_gic_state`, which only the same macOS build can load.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adjunct {
    /// What the blob is, such as `hvf_gic_state`.
    pub kind: String,
    /// The blob, base64.
    pub data_b64: String,
    /// The SHA-256 of the blob's bytes, hex.
    pub sha256: String,
}

/// The whole of `platform.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformState {
    /// [`PLATFORM_STATE_VERSION`] when written by this build.
    pub version: u32,
    /// `aarch64` or `x86_64`.
    pub arch: String,
    /// `hvf` or `kvm`.
    pub backend: String,
    /// The interrupt controller.
    pub irq: IrqState,
    /// The guest counter.
    pub timer: TimerState,
    /// The backend's own blob, when it has one.
    pub backend_adjunct: Option<Adjunct>,
}

impl PlatformState {
    /// Returns the document this build writes: both sections marked as not
    /// captured.
    #[must_use]
    pub fn not_captured(arch: GuestArch, backend: &str) -> Self {
        Self {
            version: PLATFORM_STATE_VERSION,
            arch: arch_name(arch).to_string(),
            backend: backend.to_string(),
            irq: IrqState::NotCaptured {
                reason: format!("this hvi does not read the {backend} interrupt controller yet"),
            },
            timer: TimerState::NotCaptured {
                reason: format!("this hvi does not read the {backend} guest counter yet"),
            },
            backend_adjunct: None,
        }
    }

    /// Returns whether a restore would need more than this.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        matches!(self.irq, IrqState::NotCaptured { .. })
            || matches!(self.timer, TimerState::NotCaptured { .. })
    }

    /// Parses `platform.json`, refusing another version.
    ///
    /// # Errors
    ///
    /// Errors, as `InvalidData`, when the JSON is not this document or is of
    /// another version.
    pub fn from_json(json: &[u8]) -> io::Result<Self> {
        let state: Self = serde_json::from_slice(json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if state.version != PLATFORM_STATE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "version {}, this build reads {PLATFORM_STATE_VERSION}",
                    state.version
                ),
            ));
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_markers_are_pinned_and_read_back() {
        let state = PlatformState::not_captured(GuestArch::Aarch64, "hvf");
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            json,
            concat!(
                r#"{"version":1,"arch":"aarch64","backend":"hvf","#,
                r#""irq":{"kind":"not-captured","reason":"this hvi does not read the hvf interrupt controller yet"},"#,
                r#""timer":{"kind":"not-captured","reason":"this hvi does not read the hvf guest counter yet"},"#,
                r#""backend_adjunct":null}"#
            )
        );
        assert!(state.is_partial());
        assert_eq!(PlatformState::from_json(json.as_bytes()).unwrap(), state);
        let other = json.replace(r#""version":1"#, r#""version":2"#);
        assert!(PlatformState::from_json(other.as_bytes()).is_err());
        let unknown = json.replace("not-captured", "gic-v9");
        assert!(PlatformState::from_json(unknown.as_bytes()).is_err());
    }
}

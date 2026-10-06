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

//! The interrupt line a device drives.
//!
//! A device sets its own line from the methods that change its interrupt level,
//! so the line is set under the lock that decided the level. Two threads that
//! change one device's level, a vCPU that acknowledges the interrupt and a
//! helper thread that delivers a packet, then cannot leave the line at a level
//! the device no longer has. Each backend supplies the line, since how it
//! reaches the guest's interrupt controller is the hypervisor's.

use std::sync::Arc;

/// A device's interrupt line, as the backend wires it to the guest.
pub(crate) trait IrqLine: Send + Sync {
    /// Sets the line to `level`.
    fn set_level(&self, level: bool);
}

/// A device's interrupt, which it drives through the line its backend connects.
#[derive(Default)]
pub(crate) struct Irq {
    /// The line, once the backend has connected one.
    line: Option<Arc<dyn IrqLine>>,
}

impl Irq {
    /// Connects the device to `line`.
    pub(crate) fn connect(&mut self, line: Arc<dyn IrqLine>) {
        self.line = Some(line);
    }

    /// Sets the line to `level`, when the device is connected to one.
    pub(crate) fn set(&self, level: bool) {
        if let Some(line) = &self.line {
            line.set_level(level);
        }
    }
}

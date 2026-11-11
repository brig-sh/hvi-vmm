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

//! The in-kernel IOAPIC of an x86-64 guest on KVM, and the interrupt lines and
//! triggers on its pins.

use std::sync::{Arc, Mutex};

use kvm_ioctls::VmFd;

use crate::devices::irq;
use crate::hypervisor::kvm;

/// The in-kernel IOAPIC of an x86-64 guest on KVM, whose lines and triggers are
/// its pins.
pub(super) struct KernelIoApic {
    /// The VM whose IOAPIC has the lines.
    pub(super) vm: Arc<VmFd>,
}

impl irq::Chip for KernelIoApic {
    fn line(&self, gsi: u32) -> Arc<dyn irq::Line> {
        Arc::new(kvm::IrqLine::new(Arc::clone(&self.vm), gsi))
    }

    fn trigger(&self, gsi: u32) -> Arc<dyn irq::Trigger> {
        Arc::new(Pulsed::new(kvm::IrqLine::new(Arc::clone(&self.vm), gsi)))
    }
}

/// The trigger of an edge-triggered IOAPIC pin, which raises the pin's line and
/// lowers it again.
///
/// The IOAPIC takes an edge only on a 0 to 1 transition. The line is locked
/// across the raise and the lower, so two calls cannot both raise it before
/// either lowers it, which the IOAPIC would take as one edge. The lock covers
/// the pin because the pin has one trigger, as each virtio device has a pin of
/// its own.
struct Pulsed<L> {
    /// The pin's line.
    line: Mutex<L>,
}

impl<L> Pulsed<L> {
    /// Returns the trigger that pulses `line`.
    fn new(line: L) -> Self {
        Self {
            line: Mutex::new(line),
        }
    }
}

impl<L: irq::Line> irq::Trigger for Pulsed<L> {
    fn trigger(&self) -> std::io::Result<()> {
        let line = self.line.lock().unwrap();
        line.set_level(true)?;
        line.set_level(false)
    }
}

#[cfg(test)]
mod tests {
    use irq::Trigger as _;

    use super::*;

    /// A line that records each level it is set to, in order.
    #[derive(Default)]
    struct RecordingLine {
        /// The levels, in the order they were set.
        levels: Mutex<Vec<bool>>,
    }

    impl irq::Line for RecordingLine {
        fn set_level(&self, level: bool) -> std::io::Result<()> {
            self.levels.lock().unwrap().push(level);
            Ok(())
        }
    }

    impl Pulsed<RecordingLine> {
        /// Returns the levels the line was set to, in order.
        fn levels(&self) -> Vec<bool> {
            self.line.lock().unwrap().levels.lock().unwrap().clone()
        }
    }

    #[test]
    fn pulse_raises_the_line_then_lowers_it() {
        let pulse = Pulsed::new(RecordingLine::default());
        pulse.trigger().unwrap();
        assert_eq!(pulse.levels(), [true, false]);
    }

    #[test]
    fn concurrent_pulses_do_not_interleave() {
        let pulse = Pulsed::new(RecordingLine::default());
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..1000 {
                        pulse.trigger().unwrap();
                    }
                });
            }
        });
        let levels = pulse.levels();
        assert_eq!(levels.len(), 8000);
        assert!(levels.chunks(2).all(|pair| pair == [true, false]));
    }
}

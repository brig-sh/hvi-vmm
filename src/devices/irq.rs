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

//! The interrupt line a device drives, and the controller it is on.
//!
//! The line is set under the lock that decided the level, and only when the
//! level changes. Two threads that change one device's level then cannot leave
//! the line at a level the device no longer has. A virtio device's level is
//! held by its [`Interrupt`](crate::devices::virtio::mmio::Interrupt). Each
//! backend supplies the lines through its [`Chip`], since how a line reaches
//! the guest's interrupt controller is the hypervisor's.

use std::sync::Arc;

/// A guest's interrupt controller, which gives each device its line.
pub(crate) trait Chip {
    /// Returns the line of interrupt `irq`, numbered as in
    /// [`Slot::irq`](crate::devices::manager::Slot::irq).
    fn line(&self, irq: u32) -> Arc<dyn Line>;
}

impl<C: Chip + ?Sized> Chip for &C {
    fn line(&self, irq: u32) -> Arc<dyn Line> {
        (**self).line(irq)
    }
}

/// A device's interrupt line on the guest's interrupt controller.
pub(crate) trait Line: Send + Sync {
    /// Sets the line to `level`.
    ///
    /// # Errors
    ///
    /// Errors if the hypervisor does not set the line.
    fn set_level(&self, level: bool) -> std::io::Result<()>;
}

/// A device's interrupt line, with the level it was last set to.
#[derive(Default)]
pub(crate) struct Irq {
    /// The line, once the backend has connected one.
    line: Option<Arc<dyn Line>>,
    /// The level the line was last set to. The line starts low.
    high: bool,
}

impl Irq {
    /// Connects the backend's `line`.
    pub(crate) fn connect(&mut self, line: Arc<dyn Line>) {
        self.line = Some(line);
    }

    /// Sets the line to `level` when the device is connected to one and the
    /// line is at the other level.
    ///
    /// The level is recorded only if the line was set, so the next call tries
    /// again after a failure.
    pub(crate) fn set(&mut self, level: bool) {
        if level == self.high {
            return;
        }
        let Some(line) = &self.line else { return };
        if line.set_level(level).is_ok() {
            self.high = level;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// A line that counts the times it is set.
    #[derive(Default)]
    struct CountingLine {
        /// The number of times the line was set.
        sets: AtomicU32,
    }

    impl Line for CountingLine {
        fn set_level(&self, _level: bool) -> std::io::Result<()> {
            self.sets.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A line that refuses the first time it is set, and counts the times it is
    /// set after that.
    #[derive(Default)]
    struct RefusesFirst {
        /// Whether the line has already refused once.
        refused: AtomicBool,
        /// The number of times the line was set.
        sets: AtomicU32,
    }

    impl Line for RefusesFirst {
        fn set_level(&self, _level: bool) -> std::io::Result<()> {
            if !self.refused.swap(true, Ordering::SeqCst) {
                return Err(std::io::Error::other("refused"));
            }
            self.sets.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn line_is_set_only_when_the_level_changes() {
        let line = Arc::new(CountingLine::default());
        let mut irq = Irq::default();
        irq.connect(Arc::clone(&line) as Arc<dyn Line>);
        for level in [false, true, true, true, false, false, true] {
            irq.set(level);
        }
        assert_eq!(line.sets.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn refused_set_is_tried_again() {
        let line = Arc::new(RefusesFirst::default());
        let mut irq = Irq::default();
        irq.connect(Arc::clone(&line) as Arc<dyn Line>);
        irq.set(true);
        irq.set(true);
        assert_eq!(line.sets.load(Ordering::SeqCst), 1);
    }
}

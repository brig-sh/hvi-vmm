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

//! The address spaces a guest reaches its devices through.
//!
//! A [`Bus`] maps ranges of one address space to the devices behind them. A
//! backend decodes a VM exit into an address and the bytes of the access and
//! hands them to the bus, which finds the range and calls the device with the
//! offset. What an access to no range does is the caller's choice, since it
//! differs between MMIO and port I/O.
//!
//! The entries are fixed before the first vCPU runs, so a lookup takes no lock.
//! It scans them in the order they were inserted, so its cost grows with their
//! number.

use std::ops::Range;
use std::sync::Arc;

use crate::config::Stop;

/// A device behind a range of a [`Bus`].
///
/// A device takes its own lock, so it can do work once the lock is released.
pub(crate) trait Device: Send + Sync {
    /// Fills `data` with what an access of `data.len()` bytes at `offset` into
    /// the range reads.
    fn read(&self, offset: u64, data: &mut [u8]);

    /// Applies a write of `data` at `offset` into the range.
    ///
    /// Returns the stop the write asks for, or `None` when it asks for none.
    fn write(&self, offset: u64, data: &[u8]) -> Option<Stop>;
}

/// The error of an access to an address in no range.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UnclaimedError;

/// A device on a [`Bus`] and the addresses it answers on.
struct Entry {
    /// The addresses.
    range: Range<u64>,
    /// The device.
    device: Arc<dyn Device>,
}

/// The devices of one address space, by the ranges they answer on.
#[derive(Default)]
pub(crate) struct Bus {
    /// The entries, whose ranges do not overlap.
    entries: Vec<Entry>,
}

impl Bus {
    /// Returns a bus with no ranges.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Puts `device` behind the `size` addresses from `base`.
    ///
    /// # Errors
    ///
    /// Errors if the range is empty, runs past the end of the address space or
    /// overlaps a range already inserted.
    pub(crate) fn insert(
        &mut self,
        base: u64,
        size: u64,
        device: Arc<dyn Device>,
    ) -> Result<(), String> {
        let end = base
            .checked_add(size)
            .filter(|_| size > 0)
            .ok_or_else(|| format!("adding a device at {base:#x}: invalid size {size:#x}"))?;
        if let Some(other) = self
            .entries
            .iter()
            .find(|other| base < other.range.end && other.range.start < end)
        {
            return Err(format!(
                "adding a device at {base:#x}..{end:#x}: overlaps the one at {:#x}..{:#x}",
                other.range.start, other.range.end
            ));
        }
        self.entries.push(Entry {
            range: base..end,
            device,
        });
        Ok(())
    }

    /// Fills `data` from the device whose range holds `address`.
    ///
    /// # Errors
    ///
    /// Errors with [`UnclaimedError`] when no range holds `address`, and leaves
    /// `data` as it is.
    pub(crate) fn read(&self, address: u64, data: &mut [u8]) -> Result<(), UnclaimedError> {
        let (device, offset) = self.device_at(address)?;
        device.read(offset, data);
        Ok(())
    }

    /// Writes `data` to the device whose range holds `address`.
    ///
    /// Returns the stop the write asks for, or `None` when it asks for none.
    ///
    /// # Errors
    ///
    /// Errors with [`UnclaimedError`] when no range holds `address`.
    pub(crate) fn write(&self, address: u64, data: &[u8]) -> Result<Option<Stop>, UnclaimedError> {
        let (device, offset) = self.device_at(address)?;
        Ok(device.write(offset, data))
    }

    /// Returns the device whose range holds `address`, and the offset of
    /// `address` in that range.
    fn device_at(&self, address: u64) -> Result<(&dyn Device, u64), UnclaimedError> {
        self.entries
            .iter()
            .find(|entry| entry.range.contains(&address))
            .map(|entry| (entry.device.as_ref(), address - entry.range.start))
            .ok_or(UnclaimedError)
    }
}

/// Returns the value of a little-endian access of at most 8 bytes.
pub(crate) fn u64_from_le_bytes(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    let len = data.len().min(8);
    bytes[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(bytes)
}

/// Fills `data` with the low bytes of `value`, little-endian.
pub(crate) fn fill_le_bytes(data: &mut [u8], value: u64) {
    let len = data.len().min(8);
    data[..len].copy_from_slice(&value.to_le_bytes()[..len]);
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A device that records the offsets it is called with, reads its offset
    /// back, and asks for a stop on a write of `[0xfe]`.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<u64>>);

    impl Device for Recorder {
        fn read(&self, offset: u64, data: &mut [u8]) {
            self.0.lock().unwrap().push(offset);
            fill_le_bytes(data, offset);
        }

        fn write(&self, offset: u64, data: &[u8]) -> Option<Stop> {
            self.0.lock().unwrap().push(offset);
            (data == [0xfe]).then_some(Stop::SystemReset)
        }
    }

    #[test]
    fn access_reaches_the_device_whose_range_holds_it_with_the_offset() {
        let (first, second) = (Arc::new(Recorder::default()), Arc::new(Recorder::default()));
        let mut bus = Bus::new();
        bus.insert(0x1000, 0x100, Arc::clone(&first) as Arc<dyn Device>)
            .unwrap();
        bus.insert(0x1100, 0x100, Arc::clone(&second) as Arc<dyn Device>)
            .unwrap();

        let mut data = [0u8; 2];
        bus.read(0x10ff, &mut data).unwrap();
        assert_eq!(data, [0xff, 0x00]);
        assert!(bus.write(0x1100, &[0]).unwrap().is_none());
        assert_eq!(*first.0.lock().unwrap(), [0xff]);
        assert_eq!(*second.0.lock().unwrap(), [0]);
    }

    #[test]
    fn access_outside_every_range_is_unclaimed_and_leaves_the_data() {
        let mut bus = Bus::new();
        bus.insert(0x1000, 0x100, Arc::new(Recorder::default()))
            .unwrap();
        let mut data = [0xaa];
        for address in [0xfff, 0x1100] {
            assert_eq!(bus.read(address, &mut data), Err(UnclaimedError));
            assert!(bus.write(address, &[0xfe]).is_err());
        }
        assert_eq!(data, [0xaa]);
    }

    #[test]
    fn write_returns_the_stop_the_device_asks_for() {
        let mut bus = Bus::new();
        bus.insert(0x64, 1, Arc::new(Recorder::default())).unwrap();
        assert!(matches!(
            bus.write(0x64, &[0xfe]),
            Ok(Some(Stop::SystemReset))
        ));
    }

    #[test]
    fn overlapping_range_is_refused_and_an_adjacent_one_is_not() {
        let device = || Arc::new(Recorder::default()) as Arc<dyn Device>;
        let mut bus = Bus::new();
        bus.insert(0x1000, 0x100, device()).unwrap();
        for (base, size) in [(0x1000, 1), (0x10ff, 2), (0xfff, 2), (0xf00, 0x300)] {
            let error = bus.insert(base, size, device()).unwrap_err();
            assert!(
                error.contains("overlaps the one at 0x1000..0x1100"),
                "{error}"
            );
        }
        bus.insert(0xf00, 0x100, device()).unwrap();
        bus.insert(0x1100, 0x100, device()).unwrap();
    }

    #[test]
    fn range_with_no_addresses_or_past_the_end_is_refused() {
        let device = || Arc::new(Recorder::default()) as Arc<dyn Device>;
        let mut bus = Bus::new();
        assert!(bus.insert(0x1000, 0, device()).is_err());
        assert!(bus.insert(u64::MAX, 2, device()).is_err());
    }

    #[test]
    fn access_values_convert_at_their_width() {
        assert_eq!(u64_from_le_bytes(&[0x34, 0x12]), 0x1234);
        let mut data = [0u8; 2];
        fill_le_bytes(&mut data, 0xabcd_1234);
        assert_eq!(data, [0x34, 0x12]);
    }
}

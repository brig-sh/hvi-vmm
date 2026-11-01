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

//! The command port of an i8042 keyboard controller, enough for a guest to
//! reset through it.

use crate::config::Stop;
use crate::devices::bus;

/// The controller's CPU-reset command.
const RESET_CPU: u8 = 0xfe;

/// The status the guest reads.
///
/// The input buffer reads empty, so the kernel's reset path sends its command
/// at once. The other bits read set, as on a port with nothing behind it, so a
/// guest that probes for the controller finds none at its first flush.
const STATUS: u8 = !0x02;

/// The command port, which reads a fixed status and takes the reset command.
pub(crate) struct I8042;

impl bus::Device for I8042 {
    fn read(&self, _offset: u64, data: &mut [u8]) {
        data.fill(STATUS);
    }

    fn write(&self, _offset: u64, data: &[u8]) -> Option<Stop> {
        (*data == [RESET_CPU]).then_some(Stop::SystemReset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::bus::Device as _;

    // The kernel's i8042 reset waits for the input buffer to empty before each
    // command. A full one costs the whole poll before every try.
    #[test]
    fn reset_command_is_taken_at_once() {
        let mut status = [0];
        I8042.read(0, &mut status);
        assert_eq!(status[0] & 0x02, 0, "input buffer empty");
        assert_eq!(status[0] & 0x01, 0x01, "a probe's first flush still fails");
        assert!(matches!(
            I8042.write(0, &[RESET_CPU]),
            Some(Stop::SystemReset)
        ));
    }

    #[test]
    fn other_writes_are_not_the_reset_command() {
        assert!(I8042.write(0, &[0xaa]).is_none());
        // A wider access is not the command, whatever its bytes.
        assert!(I8042.write(0, &[0x00, RESET_CPU]).is_none());
    }
}

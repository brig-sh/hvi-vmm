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

//! Pseudo-random test data and its digests.

use sha2::{Digest, Sha256};

/// Returns `len` pseudo-random bytes from `seed`.
///
/// Every 8-byte word differs from its neighbors, so a transfer that drops,
/// repeats or reorders a chunk changes the digest. Each seed gives different
/// bytes, so two transfers cannot be mistaken for each other.
pub fn pattern(len: usize, seed: u64) -> Vec<u8> {
    // The generator is xorshift64, which never yields zero from a nonzero
    // state. Its start state is the seed passed through splitmix64's finalizer,
    // so seeds next to each other start far apart.
    let mut state = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    state = (state ^ (state >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    state = (state ^ (state >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    state = (state ^ (state >> 31)) | 1;
    let mut bytes = Vec::with_capacity(len + 8);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

/// Returns the sha256 of `bytes` as lowercase hex, as `sha256sum` prints it.
pub fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

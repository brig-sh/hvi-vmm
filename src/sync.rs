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

//! Taking a lock whose last holder panicked.
//!
//! Rust poisons a `Mutex` when a thread panics while holding it, and
//! `.lock().unwrap()` turns that into a second panic in every thread that
//! locks it next. For a VMM that is the wrong default twice over.
//!
//! It is wrong about what poison means. A poisoned device mutex says a thread
//! panicked, not that guest RAM is inconsistent -- guest memory is a shared
//! mapping the guest itself writes, and no host panic makes it less valid than
//! the guest already made it. The device state behind the lock is the VMM's
//! own bookkeeping, and dropping the VM is a decision for the panic handler,
//! not for whoever happens to lock next.
//!
//! It is wrong about how it fails. One panic under a device lock kills every
//! thread that touches that device afterwards, one at a time, each with a
//! different message and none naming the original cause. The VM stops
//! answering, and the operator gets a cascade to read backwards instead of one
//! report (#35).
//!
//! So take the lock and carry on. The panic that poisoned it is reported where
//! it happened.

use std::sync::{Mutex, MutexGuard};

/// Locks `m`, taking the guard even if the previous holder panicked.
///
/// Blocks like [`Mutex::lock`]; the only difference is that poison is
/// recovered from rather than propagated.
pub fn lock_or_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The whole point: a lock whose holder panicked is still usable, and the
    /// data behind it is whatever that thread left there.
    #[test]
    fn a_poisoned_lock_is_still_taken() {
        let m = Arc::new(Mutex::new(0u32));
        let poisoner = Arc::clone(&m);
        let panicked = std::thread::spawn(move || {
            let mut guard = poisoner.lock().unwrap();
            *guard = 7;
            panic!("while holding the lock");
        })
        .join();
        assert!(panicked.is_err(), "the thread panicked as intended");
        assert!(m.lock().is_err(), "which poisoned the mutex");

        assert_eq!(*lock_or_recover(&m), 7, "the write before the panic stands");
        *lock_or_recover(&m) += 1;
        assert_eq!(*lock_or_recover(&m), 8, "and the lock still works after");
    }

    /// An unpoisoned lock behaves exactly like `lock().unwrap()`.
    #[test]
    fn an_ordinary_lock_is_unaffected() {
        let m = Mutex::new(vec![1u8, 2, 3]);
        lock_or_recover(&m).push(4);
        assert_eq!(*lock_or_recover(&m), vec![1, 2, 3, 4]);
    }
}

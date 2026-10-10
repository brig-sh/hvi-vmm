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

//! Recovery of a lock whose last holder panicked.
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

use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

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

/// Locks `m` if it is free by `deadline`, taking the guard even if the previous
/// holder panicked.
///
/// Returns `None` when the lock is still held at `deadline`. It tries the lock
/// each millisecond until then.
pub fn try_lock_until<T>(m: &Mutex<T>, deadline: Instant) -> Option<MutexGuard<'_, T>> {
    loop {
        match m.try_lock() {
            Ok(guard) => return Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::WouldBlock) => return None,
        }
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

    #[test]
    fn lock_held_past_the_deadline_is_not_taken() {
        let m = Mutex::new(0u32);
        let guard = m.lock().unwrap();
        let start = Instant::now();
        assert!(try_lock_until(&m, start + Duration::from_millis(20)).is_none());
        assert!(start.elapsed() >= Duration::from_millis(20));
        drop(guard);
        assert!(try_lock_until(&m, Instant::now()).is_some());
    }

    /// An unpoisoned lock behaves exactly like `lock().unwrap()`.
    #[test]
    fn an_ordinary_lock_is_unaffected() {
        let m = Mutex::new(vec![1u8, 2, 3]);
        lock_or_recover(&m).push(4);
        assert_eq!(*lock_or_recover(&m), vec![1, 2, 3, 4]);
    }
}

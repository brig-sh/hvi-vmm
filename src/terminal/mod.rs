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

//! The operator's terminal, as the guest's serial console reaches it.
//!
//! The guest's console output goes to stdout through a [`ConsoleFilter`], which
//! drops the escape sequences that would change host state. Its input is stdin,
//! which `RawTerm` puts in raw mode for the run and `input` reads on a thread
//! of its own.

mod filter;
pub(crate) mod input;
mod raw;

pub use filter::ConsoleFilter;
pub(crate) use raw::RawTerm;

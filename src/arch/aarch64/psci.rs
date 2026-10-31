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

//! The PSCI function IDs hvi recognizes, in their SMC32 form except for
//! `CPU_ON_64`, and the return codes it answers with.

pub const VERSION: u64 = 0x8400_0000;
pub const CPU_OFF: u64 = 0x8400_0002;
pub const SYSTEM_OFF: u64 = 0x8400_0008;
pub const SYSTEM_RESET: u64 = 0x8400_0009;
pub const FEATURES: u64 = 0x8400_000a;
pub const CPU_ON_64: u64 = 0xc400_0003;
pub const SUCCESS: u64 = 0;
pub const NOT_SUPPORTED: u64 = (-1i64) as u64;

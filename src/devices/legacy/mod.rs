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

//! The devices a guest finds without virtio: the PL011 and 16550 UARTs that
//! carry its serial console, and the MC146818 CMOS RTC an x86-64 guest reads
//! for the wall clock at boot.

pub mod pl011;
pub mod rtc_cmos;
pub mod uart16550;

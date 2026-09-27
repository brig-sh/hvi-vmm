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

//! What this host lets a guest do, asked without booting one: `hvi caps`.
//!
//! A caller such as hull asks here before it starts a guest with
//! `--nested-virt`, because a boot refused only once the VMM runs looks, from
//! outside, like a guest that never became ready. The JSON shape is a
//! contract with those callers: keys are only added, and `schemaVersion`
//! changes if one is removed or changes meaning.

use serde::Serialize;

/// The document `hvi caps --json` prints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Caps {
    pub schema_version: u32,
    pub nested_virt: NestedVirt,
}

/// Whether `boot --nested-virt` can work here, and why not when it cannot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NestedVirt {
    pub supported: bool,
    pub detail: String,
}

/// Why a host without the macOS backend says no.
pub const NOT_MACOS: &str = "--nested-virt is currently implemented by the macOS HVI backend only";

/// Asks the host. A host that answers "no" is not an error.
///
/// # Errors
///
/// Errors only when Hypervisor.framework cannot say whether it supports EL2.
pub fn probe() -> Result<Caps, Box<dyn std::error::Error>> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let (supported, detail) = if applevisor::prelude::VirtualMachineConfig::get_el2_supported()? {
        (true, "Hypervisor.framework reports EL2")
    } else {
        (false, "Hypervisor.framework reports no EL2")
    };
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let (supported, detail) = (false, NOT_MACOS);
    Ok(Caps {
        schema_version: 1,
        nested_virt: NestedVirt {
            supported,
            detail: detail.to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hull parses these keys. Renaming one breaks every hull that reads it
    /// without failing anything in this crate, so the spelling is pinned here.
    #[test]
    fn json_keys_match_the_contract() {
        let caps = Caps {
            schema_version: 1,
            nested_virt: NestedVirt {
                supported: false,
                detail: NOT_MACOS.into(),
            },
        };
        assert_eq!(
            serde_json::to_string(&caps).unwrap(),
            format!(
                r#"{{"schemaVersion":1,"nestedVirt":{{"supported":false,"detail":"{NOT_MACOS}"}}}}"#
            )
        );
    }
}

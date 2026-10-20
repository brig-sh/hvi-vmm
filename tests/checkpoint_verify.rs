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

//! `hvi checkpoint-verify` on a bundle, and on the same bundle with one byte
//! of guest RAM changed: the binary, run as a person or hull would run it.

// The test's bundle lives in a scratch directory of its own. See clippy.toml.
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::Command;

use hvi::checkpoint::bundle::{BundleWriter, Component, DevicesDoc, IrqLevels, Session};
use hvi::checkpoint::cpu::{CpuState, VcpuState};
use hvi::checkpoint::platform::PlatformState;
use hvi::checkpoint::profile::{MachineProfile, RamRegion};
use hvi::devices::state::DeviceStates;
use hvi::memory::{GuestRam, SharedRam};
use hvi::plugin::{GuestArch, RegsView};

const GPA: u64 = 0x4000_0000;

/// Writes a one-vCPU, 2 MiB bundle into `dir`.
fn write_bundle(dir: &Path) {
    let shared = SharedRam::new(2 << 20).unwrap();
    let ram = GuestRam::new(&shared, &[shared.region_at(GPA)]).unwrap();
    ram.write(GPA + 0x2000, b"guest data").unwrap();
    let mut profile = MachineProfile::for_this_host("aarch64", "kvm");
    profile.ram_regions = vec![RamRegion {
        gpa: GPA,
        size: 2 << 20,
        file_offset: 0,
    }];
    profile.vcpus = 1;
    let mut w = BundleWriter::create(dir).unwrap();
    w.write_bytes(Component::Profile, profile.to_json().as_bytes())
        .unwrap();
    w.write_ram(&ram, &|| false).unwrap();
    let vcpu = VcpuState::from_regs_view(GuestArch::Aarch64, "kvm", 0, &RegsView::default());
    w.write_json(
        Component::Cpu,
        &CpuState::new(GuestArch::Aarch64, vec![vcpu]),
    )
    .unwrap();
    w.write_json(
        Component::Platform,
        &PlatformState::not_captured(GuestArch::Aarch64, "kvm"),
    )
    .unwrap();
    let devices = DevicesDoc {
        states: DeviceStates::default(),
        irq_levels: IrqLevels::default(),
    };
    w.write_bytes(Component::Devices, &devices.to_json().unwrap())
        .unwrap();
    w.write_json(
        Component::Session,
        &Session {
            version: 1,
            sandbox_id: "it".into(),
            epoch: 0,
            txid: None,
            captured_at_unix_ms: 0,
            then: "fence".into(),
        },
    )
    .unwrap();
    w.seal(Vec::new()).unwrap();
}

fn verify(dir: &Path) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hvi"))
        .arg("checkpoint-verify")
        .arg(dir)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn checkpoint_verify_passes_a_bundle_and_refuses_a_changed_one() {
    let scratch: PathBuf =
        std::env::temp_dir().join(format!("hvi-verify-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    let dir = scratch.join("ck");
    write_bundle(&dir);

    let (ok, stdout, stderr) = verify(&dir);
    assert!(ok, "{stdout}{stderr}");
    assert!(
        stdout.starts_with("bundle ok: manifest sha256 "),
        "{stdout}"
    );
    assert!(
        stdout.contains("RAM: 4096 of 2097152 bytes present; 1 vCPU(s)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("partial: vCPU registers, interrupt controller and timer"),
        "{stdout}"
    );

    let ram_bin = dir.join("ram.bin");
    let mut bytes = std::fs::read(&ram_bin).unwrap();
    bytes[0] ^= 0x80;
    std::fs::write(&ram_bin, bytes).unwrap();
    let (ok, stdout, stderr) = verify(&dir);
    assert!(!ok, "a changed byte passed: {stdout}");
    assert!(
        stderr.contains("ram.bin: SHA-256 does not match the manifest"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&scratch);
}

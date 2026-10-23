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

//! The builds of the `hvi` binary under test and of the guest agent.
//!
//! Both are built on every setup. Cargo does nothing when the sources have not
//! changed, and building here means a test can never run an `hvi` older than
//! the tree.

use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::Result;

/// Returns the `hvi` binary to test, built in release mode.
///
/// On Linux it is built for the static musl target on `arch`, whose seccomp
/// allowlists differ from a glibc build's. On macOS the binary is copied into
/// `artifacts` and signed there with `hvi.entitlements`, since an unsigned
/// binary cannot create a VM.
pub(crate) fn build_hvi(repo: &Path, artifacts: &Path, arch: &str) -> Result<PathBuf> {
    let mut build = cargo();
    build
        .arg("--manifest-path")
        .arg(repo.join("Cargo.toml"))
        .args(["--bin", "hvi"]);
    if !cfg!(target_os = "macos") {
        let target = format!("{arch}-unknown-linux-musl");
        build.args(["--target", &target]);
        return build_one(build, "hvi");
    }
    let built = build_one(build, "hvi")?;
    let dir = artifacts.join("bin");
    std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let signed = dir.join("hvi");
    std::fs::copy(&built, &signed)
        .map_err(|e| format!("copying {} to {}: {e}", built.display(), signed.display()))?;
    let status = Command::new("codesign")
        .args([
            "--sign",
            "-",
            "--force",
            "--options",
            "runtime",
            "--entitlements",
        ])
        .arg(repo.join("hvi.entitlements"))
        .arg(&signed)
        .status()
        .map_err(|e| format!("running codesign: {e}"))?;
    if !status.success() {
        return Err(format!(
            "signing {}: codesign exited with {status}",
            signed.display()
        )
        .into());
    }
    Ok(signed)
}

/// Returns the guest agent binary, built for the guest's musl target on `arch`.
///
/// It links with `rust-lld`, which ships with the toolchain, so no host needs a
/// cross toolchain. A `CARGO_TARGET_<TARGET>_LINKER` variable overrides the
/// linker. The target itself has to be installed with `rustup target add`.
pub(crate) fn build_agent(e2e: &Path, arch: &str) -> Result<PathBuf> {
    let target = format!("{arch}-unknown-linux-musl");
    let linker = format!(
        "CARGO_TARGET_{}_LINKER",
        target.to_uppercase().replace('-', "_")
    );
    let mut build = cargo();
    build
        .arg("--manifest-path")
        .arg(e2e.join("Cargo.toml"))
        .args(["--package", "hvi-e2e-agent", "--target", &target]);
    if std::env::var_os(&linker).is_none() {
        build.env(linker, "rust-lld");
    }
    build_one(build, "hvi-e2e-agent")
}

/// Returns a `cargo build --release` command that reports its artifacts as JSON
/// on stdout.
fn cargo() -> Command {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command.args([
        "build",
        "--release",
        "--message-format=json-render-diagnostics",
    ]);
    command
}

/// Returns the executable `build` builds for the target `name`.
///
/// Cargo's progress and diagnostics go to stderr, which is passed through.
fn build_one(mut build: Command, name: &str) -> Result<PathBuf> {
    let mut child = build
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("building {name}: {e}"))?;
    let stdout = child.stdout.take().expect("stdout should be piped");
    let mut executable = None;
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| format!("building {name}: reading cargo's output: {e}"))?;
        let Ok(message) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if message["reason"] == "compiler-artifact" && message["target"]["name"] == name {
            if let Some(path) = message["executable"].as_str() {
                executable = Some(PathBuf::from(path));
            }
        }
    }
    let status = child.wait().map_err(|e| format!("building {name}: {e}"))?;
    if !status.success() {
        return Err(format!("building {name}: cargo exited with {status}").into());
    }
    executable.ok_or_else(|| format!("building {name}: cargo reported no executable").into())
}

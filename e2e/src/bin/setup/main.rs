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

//! The nextest setup script that prepares an e2e run.
//!
//! It builds the `hvi` binary under test and the guest agent, fetches the
//! pinned guest kernel, root filesystem and gateway, assembles the initramfs,
//! and finds the host's optional capabilities. It hands the results to the
//! tests as `HVI_E2E_*` variables, through the file nextest names in
//! `NEXTEST_ENV`. Run outside nextest, it prints them as `KEY=value` lines
//! instead.
//!
//! It runs as the user the tests run as and writes only to the cache, the
//! artifacts directory and cargo's target directories. What needs privileges is
//! done once per boot by `e2e/tools/provision.sh`.

mod assets;
mod binaries;
mod initramfs;

use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use assets::Assets;
use hvi_e2e::vars;

/// The result of a setup step, whose error ends the setup.
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hvi-e2e setup: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Prepares the run for the tests.
fn run() -> Result<()> {
    let e2e = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    let repo = e2e
        .parent()
        .expect("e2e/ should sit in the repository")
        .to_path_buf();
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let artifacts = artifacts_dir(&e2e);
    std::fs::create_dir_all(&artifacts)
        .map_err(|e| format!("creating {}: {e}", artifacts.display()))?;

    check_hypervisor()?;
    let hvi = binaries::build_hvi(&repo, &artifacts, arch)?;
    let agent = binaries::build_agent(&e2e, arch)?;
    let assets = Assets::load(&e2e.join("assets.toml"), cache_dir()?)?;
    let kernel = assets.fetch("kernel", arch)?;
    let rootfs = assets.fetch("rootfs", arch)?;
    let gvproxy = assets.fetch_executable("gvproxy", &format!("{os}-{arch}"))?;
    let initramfs = artifacts.join(format!("initramfs-{arch}.cpio"));
    initramfs::build(&rootfs, &e2e.join("guest/init"), &agent, &initramfs)?;

    let mut prepared = vec![
        (vars::HVI, hvi),
        (vars::KERNEL, kernel),
        (vars::INITRAMFS, initramfs),
        (vars::GVPROXY, gvproxy),
        (vars::ARTIFACTS, artifacts),
    ];
    let tap = tap_name(&e2e)?;
    if let Some(address) = tap_address(&tap) {
        prepared.push((vars::TAP, PathBuf::from(tap)));
        prepared.push((vars::TAP_ADDRESS, PathBuf::from(address)));
    }
    if let Some(virtiofsd) = find_virtiofsd() {
        // The version goes in the run's log, since hosts can differ in it.
        let version = Command::new(&virtiofsd)
            .arg("--version")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|e| format!("unknown version ({e})"));
        eprintln!("hvi-e2e setup: {} is {version}", virtiofsd.display());
        prepared.push((vars::VIRTIOFSD, virtiofsd));
    }
    hand_over(&prepared)
}

/// Returns the directory the tests write their files under, `HVI_E2E_ARTIFACTS`
/// or else `hvi-e2e` in the cargo target directory.
fn artifacts_dir(e2e: &Path) -> PathBuf {
    if let Some(dir) = std::env::var_os(vars::ARTIFACTS) {
        return PathBuf::from(dir);
    }
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| e2e.join("target"));
    target.join("hvi-e2e")
}

/// Returns the download cache, `HVI_E2E_CACHE` or else `hvi-e2e` in the user's
/// cache directory.
fn cache_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(vars::CACHE) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(dir).join("hvi-e2e"));
    }
    let home = std::env::var_os("HOME").ok_or("finding the cache directory: HOME is not set")?;
    Ok(PathBuf::from(home).join(".cache/hvi-e2e"))
}

/// Checks that this user can open `/dev/kvm`, on Linux.
///
/// Every test boots a guest, so a host without access fails here once rather
/// than in every test.
fn check_hypervisor() -> Result<()> {
    if cfg!(target_os = "linux") {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .map_err(|e| format!("opening /dev/kvm: {e}"))?;
    }
    Ok(())
}

/// Returns the name of the tap device `e2e/tools/provision.sh` creates, from
/// the script's `TAP=` line, so the script is the one place it is set.
fn tap_name(e2e: &Path) -> Result<String> {
    let script = e2e.join("tools/provision.sh");
    let text = std::fs::read_to_string(&script)
        .map_err(|e| format!("reading {}: {e}", script.display()))?;
    text.lines()
        .find_map(|line| line.strip_prefix("TAP="))
        .map(String::from)
        .ok_or_else(|| {
            format!(
                "reading the tap name from {}: no TAP= line",
                script.display()
            )
            .into()
        })
}

/// Returns the host's address on the provisioned tap, as `<ip>/<prefix
/// length>`, if the tap exists, has an IPv4 address, and this user may attach
/// to it.
fn tap_address(tap: &str) -> Option<String> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let owner = std::fs::read_to_string(format!("/sys/class/net/{tap}/owner")).ok()?;
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let owner: i64 = owner.trim().parse().ok()?;
    if owner != i64::from(uid) && uid != 0 {
        return None;
    }
    let output = Command::new("ip")
        .args(["-4", "-o", "address", "show", "dev", tap])
        .output()
        .ok()?;
    // A line reads `5: hvi-e2e0 inet <ip>/<prefix> scope global ...`.
    let text = String::from_utf8_lossy(&output.stdout);
    let mut words = text.split_whitespace();
    words.find(|word| *word == "inet")?;
    words.next().map(String::from)
}

/// Returns the path of the vhost-user virtio-fs daemon on Linux,
/// `HVI_E2E_VIRTIOFSD` or else `virtiofsd` on `PATH` or where distributions
/// install it.
fn find_virtiofsd() -> Option<PathBuf> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    if let Some(path) = std::env::var_os(vars::VIRTIOFSD) {
        return Some(PathBuf::from(path));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(["/usr/libexec", "/usr/lib", "/usr/lib/qemu"].map(PathBuf::from))
        .map(|dir| dir.join("virtiofsd"))
        .find(|candidate| candidate.is_file())
}

/// Writes `vars` to the file `NEXTEST_ENV` names, or prints them when it is not
/// set.
fn hand_over(vars: &[(&str, PathBuf)]) -> Result<()> {
    let mut lines = String::new();
    for (key, value) in vars {
        let value = value
            .to_str()
            .ok_or_else(|| format!("handing over {key}: {} is not UTF-8", value.display()))?;
        lines.push_str(&format!("{key}={value}\n"));
    }
    match std::env::var_os("NEXTEST_ENV") {
        Some(path) => {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&path)
                .map_err(|e| format!("opening {}: {e}", Path::new(&path).display()))?;
            file.write_all(lines.as_bytes())
                .map_err(|e| format!("writing {}: {e}", Path::new(&path).display()))?;
        }
        None => print!("{lines}"),
    }
    Ok(())
}

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

//! What the setup binary prepared, read from the environment.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use crate::net::Tap;

/// The names of the environment variables that configure the suite.
pub mod vars {
    /// The `hvi` binary under test.
    pub const HVI: &str = "HVI_E2E_HVI";
    /// The guest kernel.
    pub const KERNEL: &str = "HVI_E2E_KERNEL";
    /// The guest initramfs.
    pub const INITRAMFS: &str = "HVI_E2E_INITRAMFS";
    /// The gvisor-tap-vsock gateway.
    pub const GVPROXY: &str = "HVI_E2E_GVPROXY";
    /// The directory each test writes its files under.
    pub const ARTIFACTS: &str = "HVI_E2E_ARTIFACTS";
    /// The download cache.
    pub const CACHE: &str = "HVI_E2E_CACHE";
    /// The name of the provisioned tap device.
    pub const TAP: &str = "HVI_E2E_TAP";
    /// The host's address on the tap, as `<ip>/<prefix length>`.
    pub const TAP_ADDRESS: &str = "HVI_E2E_TAP_ADDRESS";
    /// The vhost-user virtio-fs daemon.
    pub const VIRTIOFSD: &str = "HVI_E2E_VIRTIOFSD";
    /// The factor every timeout is multiplied by.
    pub const TIMEOUT_SCALE: &str = "HVI_E2E_TIMEOUT_SCALE";
    /// The vGIC an arm64 KVM host offers, `v2` or `v3`.
    pub const VGIC: &str = "HVI_E2E_VGIC";
}

/// The binaries, guest images and host capabilities the setup binary prepared
/// for this run.
#[derive(Debug)]
pub struct Suite {
    /// The `hvi` binary under test.
    pub hvi: PathBuf,
    /// The guest kernel.
    pub kernel: PathBuf,
    /// The guest initramfs, with the suite's init and agent.
    pub initramfs: PathBuf,
    /// The gvisor-tap-vsock gateway.
    pub gvproxy: PathBuf,
    /// The directory each test writes its files under.
    pub artifacts: PathBuf,
    /// The tap device provisioned for the tests, if this host has one.
    tap: Option<Tap>,
    /// The vhost-user virtio-fs daemon, if this host has one.
    virtiofsd: Option<PathBuf>,
    /// The factor every timeout is multiplied by, from `HVI_E2E_TIMEOUT_SCALE`.
    timeout_scale: f64,
    /// The vGIC this arm64 KVM host offers, `v2` or `v3`, when the runner
    /// states it.
    pub vgic: Option<String>,
}

impl Suite {
    /// Returns the suite, read from the environment on the first call.
    ///
    /// # Panics
    ///
    /// Panics if the setup binary's variables are not set, which means the test
    /// was not started by `cargo nextest run` in `e2e/`. Also panics if
    /// `HVI_E2E_TIMEOUT_SCALE` or `HVI_E2E_TAP_ADDRESS` does not parse.
    pub fn get() -> &'static Suite {
        static SUITE: OnceLock<Suite> = OnceLock::new();
        SUITE.get_or_init(Suite::from_env)
    }

    /// Reads the suite from the `HVI_E2E_*` variables.
    fn from_env() -> Suite {
        let path = |name: &str| {
            PathBuf::from(std::env::var_os(name).unwrap_or_else(|| {
                panic!("{name} should be set: run the suite with `cargo nextest run` in e2e/")
            }))
        };
        let timeout_scale = match std::env::var(vars::TIMEOUT_SCALE) {
            Ok(value) => value
                .parse()
                .unwrap_or_else(|e| panic!("{}={value}: {e}", vars::TIMEOUT_SCALE)),
            Err(_) => 1.0,
        };
        Suite {
            hvi: path(vars::HVI),
            kernel: path(vars::KERNEL),
            initramfs: path(vars::INITRAMFS),
            gvproxy: path(vars::GVPROXY),
            artifacts: path(vars::ARTIFACTS),
            tap: std::env::var(vars::TAP).ok().map(|name| {
                let address = std::env::var(vars::TAP_ADDRESS).unwrap_or_default();
                Tap::parse(name, &address).unwrap_or_else(|| {
                    panic!("{}={address:?} is not an ip/prefix", vars::TAP_ADDRESS)
                })
            }),
            virtiofsd: std::env::var_os(vars::VIRTIOFSD).map(PathBuf::from),
            timeout_scale,
            vgic: std::env::var(vars::VGIC)
                .ok()
                .filter(|vgic| !vgic.is_empty()),
        }
    }

    /// Returns `base` scaled for this host, by `HVI_E2E_TIMEOUT_SCALE`.
    pub fn timeout(&self, base: Duration) -> Duration {
        base.mul_f64(self.timeout_scale)
    }

    /// Returns the tap device provisioned for the tests.
    ///
    /// # Panics
    ///
    /// Panics if the host has no tap.
    pub fn tap(&self) -> &Tap {
        self.tap.as_ref().unwrap_or_else(|| {
            panic!(
                "this host has no tap: run e2e/tools/provision.sh, or leave the tap tests \
                 out with -E 'not test(/(^|::)tap::/)'"
            )
        })
    }

    /// Returns the path of the vhost-user virtio-fs daemon.
    ///
    /// # Panics
    ///
    /// Panics if the host has no daemon.
    pub fn virtiofsd(&self) -> &Path {
        self.virtiofsd.as_deref().unwrap_or_else(|| {
            panic!(
                "this host has no virtiofsd: install it, or leave the export tests out with \
                 -E 'not binary(fs)'"
            )
        })
    }
}

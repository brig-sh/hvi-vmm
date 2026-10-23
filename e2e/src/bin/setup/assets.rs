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

//! The pinned downloads in `e2e/assets.toml`, fetched into a cache keyed by
//! digest.
//!
//! An entry is a plain download pinned by its sha256, or an OCI image pinned by
//! the digest of its manifest or index. An image is resolved through its
//! registry by digest alone: an index to the Linux manifest for this host's
//! architecture, and a manifest to the layer that holds the file. Every object
//! is checked against its digest and kept in the cache under it, so a run whose
//! objects are all cached needs no network. A plain download is reused only for
//! the URL it came from, so a pin whose URL moves while its sha256 stays the
//! same fails on every host rather than passing on a stale copy. Concurrent
//! setups on one host serialize on a lock file in the cache.

use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::Result;

/// The media types a manifest request accepts, indexes included.
const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json,\
    application/vnd.oci.image.manifest.v1+json,\
    application/vnd.docker.distribution.manifest.list.v2+json,\
    application/vnd.docker.distribution.manifest.v2+json";

/// The key of an entry that serves every platform.
const ANY_PLATFORM: &str = "any";

/// One pinned file.
#[derive(Debug, Deserialize)]
#[serde(try_from = "RawEntry")]
enum Entry {
    /// A download pinned by its sha256.
    Download {
        /// A URL to download the file from.
        url: String,
        /// The downloaded file's sha256, as lowercase hex.
        sha256: String,
    },
    /// A file in an OCI image.
    Image {
        /// The image, as `registry/name:tag@sha256:digest`.
        image: String,
        /// The title annotation of the image layer that holds the file, for an
        /// image with more than one layer.
        layer: Option<String>,
    },
}

/// An entry as `assets.toml` spells it, before its keys are checked against
/// each other.
///
/// A wrong combination fails when the file is read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    url: Option<String>,
    sha256: Option<String>,
    image: Option<String>,
    layer: Option<String>,
}

impl TryFrom<RawEntry> for Entry {
    type Error = String;

    fn try_from(raw: RawEntry) -> std::result::Result<Entry, String> {
        match raw {
            RawEntry {
                url: Some(url),
                sha256: Some(sha256),
                image: None,
                layer: None,
            } => Ok(Entry::Download { url, sha256 }),
            RawEntry {
                url: None,
                sha256: None,
                image: Some(image),
                layer,
            } => Ok(Entry::Image { image, layer }),
            _ => Err("an entry needs url and sha256, or image and an optional layer".into()),
        }
    }
}

/// The entries of `assets.toml`, by kind and then by platform.
pub(crate) struct Assets {
    /// Each table of the file, such as `kernel`, keyed by platform or `any`.
    entries: BTreeMap<String, BTreeMap<String, Entry>>,
    /// The cache directory.
    cache: PathBuf,
}

impl Assets {
    /// Reads the asset list at `path`, creating the download cache `cache`.
    pub(crate) fn load(path: &Path, cache: PathBuf) -> Result<Assets> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let entries =
            toml::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
        std::fs::create_dir_all(&cache)
            .map_err(|e| format!("creating {}: {e}", cache.display()))?;
        Ok(Assets { entries, cache })
    }

    /// Returns the cached file for `kind` on `platform`, fetching what the
    /// cache does not hold.
    pub(crate) fn fetch(&self, kind: &str, platform: &str) -> Result<PathBuf> {
        let entry = self
            .entries
            .get(kind)
            .and_then(|table| table.get(platform).or_else(|| table.get(ANY_PLATFORM)))
            .ok_or_else(|| format!("assets.toml has no {kind}.{platform}"))?;
        let lock_path = self.cache.join(".lock");
        // The lock is held until the fetch returns and the file is closed.
        let _lock = File::create(&lock_path)
            .and_then(|lock| lock.lock().map(|()| lock))
            .map_err(|e| format!("locking {}: {e}", lock_path.display()))?;
        let fetched = match entry {
            Entry::Download { url, sha256 } => self.fetch_object(sha256, url, None, None),
            Entry::Image { image, layer } => self.fetch_image(image, layer.as_deref()),
        };
        fetched.map_err(|e| format!("fetching {kind}.{platform}: {e}").into())
    }

    /// Returns the cached file for `kind` on `platform`, as [`Assets::fetch`]
    /// does, with its mode set to 0755.
    pub(crate) fn fetch_executable(&self, kind: &str, platform: &str) -> Result<PathBuf> {
        let path = self.fetch(kind, platform)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("making {} executable: {e}", path.display()))?;
        Ok(path)
    }

    /// Returns the file the image `reference` holds in its layer titled
    /// `layer`, or in its only layer.
    fn fetch_image(&self, reference: &str, layer: Option<&str>) -> Result<PathBuf> {
        let image = Image::parse(reference)?;
        let mut token = None;
        let mut digest = image.digest.clone();
        loop {
            let path = self.registry_object(&image, "manifests", &digest, &mut token)?;
            let bytes =
                std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            let manifest: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("reading the manifest sha256:{digest}: {e}"))?;
            if let Some(manifests) = manifest["manifests"].as_array() {
                digest = platform_manifest(manifests)?;
                continue;
            }
            let layers = manifest["layers"]
                .as_array()
                .ok_or_else(|| format!("the manifest sha256:{digest} has no layers"))?;
            let chosen = match layer {
                Some(title) => layers
                    .iter()
                    .find(|candidate| {
                        candidate["annotations"]["org.opencontainers.image.title"] == title
                    })
                    .ok_or_else(|| format!("the image has no layer titled {title:?}"))?,
                None if layers.len() == 1 => &layers[0],
                None => return Err("the image has several layers and the entry names none".into()),
            };
            let blob = chosen["digest"]
                .as_str()
                .and_then(|digest| digest.strip_prefix("sha256:"))
                .ok_or("a layer has no sha256 digest")?;
            return self.registry_object(&image, "blobs", blob, &mut token);
        }
    }

    /// Returns the cached manifest or blob whose sha256 is `digest`, fetching
    /// it from `image`'s registry if the cache does not hold it.
    ///
    /// `token` is `None` until the first download asks the registry for a pull
    /// token, and then holds the answer.
    fn registry_object(
        &self,
        image: &Image,
        kind: &str,
        digest: &str,
        token: &mut Option<Option<String>>,
    ) -> Result<PathBuf> {
        let cached = self.cache.join(digest);
        if cached.is_file() && sha256_file(&cached)? == digest {
            return Ok(cached);
        }
        let url = format!(
            "https://{}/v2/{}/{kind}/sha256:{digest}",
            image.host, image.name
        );
        if token.is_none() {
            *token = Some(registry_token(&url)?);
        }
        let accept = (kind == "manifests").then_some(MANIFEST_TYPES);
        let auth = token.as_ref().and_then(Option::as_deref);
        self.fetch_object(digest, &url, accept, auth)
    }

    /// Returns the cached object whose sha256 is `digest`, downloading it from
    /// `url` first if the cache does not hold it as fetched from `url`.
    fn fetch_object(
        &self,
        digest: &str,
        url: &str,
        accept: Option<&str>,
        token: Option<&str>,
    ) -> Result<PathBuf> {
        let path = self.cache.join(digest);
        let source = self.cache.join(format!("{digest}.url"));
        let from_url = std::fs::read_to_string(&source).is_ok_and(|cached| cached == url);
        if from_url && path.is_file() && sha256_file(&path)? == digest {
            return Ok(path);
        }
        eprintln!("hvi-e2e setup: fetching {url}");
        let partial = self.cache.join(format!("{digest}.part"));
        let mut curl = curl();
        curl.arg("--fail").arg("--output").arg(&partial);
        if let Some(accept) = accept {
            curl.arg("--header").arg(format!("Accept: {accept}"));
        }
        if let Some(token) = token {
            curl.arg("--header")
                .arg(format!("Authorization: Bearer {token}"));
        }
        let status = curl
            .arg(url)
            .status()
            .map_err(|e| format!("running curl: {e}"))?;
        if !status.success() {
            return Err(format!("downloading {url}: curl exited with {status}").into());
        }
        let actual = sha256_file(&partial)?;
        if actual != digest {
            let _ = std::fs::remove_file(&partial);
            return Err(format!("downloading {url}: sha256 is {actual}, expected {digest}").into());
        }
        std::fs::rename(&partial, &path)
            .map_err(|e| format!("renaming {}: {e}", partial.display()))?;
        std::fs::write(&source, url).map_err(|e| format!("writing {}: {e}", source.display()))?;
        Ok(path)
    }
}

/// An image reference, `registry/name:tag@sha256:digest`.
///
/// The image is fetched by its digest alone. The tag is for the reader and for
/// Renovate.
struct Image {
    /// The registry's API host.
    host: String,
    /// The repository's name on the registry.
    name: String,
    /// The pinned digest, as lowercase hex.
    digest: String,
}

impl Image {
    /// Parses `reference`.
    fn parse(reference: &str) -> Result<Image> {
        let bad = || format!("{reference} is not registry/name:tag@sha256:digest");
        let (named, digest) = reference.split_once("@sha256:").ok_or_else(bad)?;
        let (repository, _tag) = named.rsplit_once(':').ok_or_else(bad)?;
        let (registry, name) = repository.split_once('/').ok_or_else(bad)?;
        // Docker Hub serves its API from a host of its own.
        let host = match registry {
            "docker.io" => "registry-1.docker.io",
            other => other,
        };
        Ok(Image {
            host: host.to_string(),
            name: name.to_string(),
            digest: digest.to_string(),
        })
    }
}

/// Returns the hex digest of the Linux manifest for this host's architecture in
/// an index's `manifests` list.
fn platform_manifest(manifests: &[serde_json::Value]) -> Result<String> {
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => return Err(format!("no OCI platform for {other}").into()),
    };
    manifests
        .iter()
        .find(|manifest| {
            manifest["platform"]["os"] == "linux"
                && manifest["platform"]["architecture"] == architecture
        })
        .and_then(|manifest| manifest["digest"].as_str())
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .map(String::from)
        .ok_or_else(|| format!("the index has no linux/{architecture} manifest").into())
}

/// Returns a pull token for the registry object at `url`, or `None` when the
/// registry asks for none.
///
/// The registry's answer to an unauthenticated request names the token endpoint
/// in its `WWW-Authenticate` challenge, which is how both ghcr.io and Docker
/// Hub hand out anonymous tokens.
fn registry_token(url: &str) -> Result<Option<String>> {
    // No --fail here, since the challenge answer is a 401.
    let output = curl()
        .args(["--head", "--header"])
        .arg(format!("Accept: {MANIFEST_TYPES}"))
        .arg(url)
        .output()
        .map_err(|e| format!("running curl: {e}"))?;
    let headers = String::from_utf8_lossy(&output.stdout);
    let Some(challenge) = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("www-authenticate")
            .then(|| value.trim().to_string())
    }) else {
        return Ok(None);
    };
    let field = |key: &str| {
        challenge
            .split(',')
            .find_map(|part| part.trim().trim_start_matches("Bearer ").strip_prefix(key))
            .and_then(|rest| rest.strip_prefix('='))
            .map(|value| value.trim_matches('"').to_string())
    };
    let realm = field("realm")
        .ok_or_else(|| format!("requesting a token for {url}: the challenge has no realm"))?;
    let mut query = Vec::new();
    for key in ["service", "scope"] {
        if let Some(value) = field(key) {
            query.push(format!("{key}={value}"));
        }
    }
    let token_url = format!("{realm}?{}", query.join("&"));
    let output = curl()
        .arg("--fail")
        .arg(&token_url)
        .output()
        .map_err(|e| format!("running curl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "requesting a token from {token_url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let body: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("requesting a token from {token_url}: {e}"))?;
    body["token"]
        .as_str()
        .or_else(|| body["access_token"].as_str())
        .map(|token| Some(token.to_string()))
        .ok_or_else(|| {
            format!("requesting a token from {token_url}: no token in the answer").into()
        })
}

/// Returns a `curl` command that follows redirects and retries, and gives up on
/// a transfer that stalls below 1000 bytes a second for a minute.
fn curl() -> Command {
    let mut curl = Command::new("curl");
    curl.args(["--silent", "--show-error", "--location"]).args([
        "--retry",
        "3",
        "--connect-timeout",
        "30",
        "--speed-limit",
        "1000",
        "--speed-time",
        "60",
    ]);
    curl
}

/// Returns the sha256 of the file at `path`, as lowercase hex.
fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    Ok(hvi_e2e::sha256(&bytes))
}

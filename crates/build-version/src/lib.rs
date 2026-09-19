//! Derives the version string a build script embeds in a binary.
//!
//! A build takes its version from git: the release tag it was built from, or
//! that tag plus how far past it the build is. A build with no release tag in
//! its history reports the commit alone.
//!
//! Call [`emit`] from a build script and read the value back with
//! `env!("HVI_VERSION")`.
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this
// repository's own git directory, read at build time.
#![allow(clippy::disallowed_methods)]

use std::env;
use std::path::Path;
use std::process::Command;

/// Version reported when neither the environment nor git names one, which is
/// what a build from a source archive without the history gets.
const UNKNOWN: &str = "0.0.0+unknown";

/// Emits `HVI_VERSION` for the crate whose build script calls this.
///
/// `HVI_VERSION` in the environment wins. That is how a release names its
/// version once for every binary it builds, and how a build from a checkout
/// without tags still reports the version it is part of.
pub fn emit() {
    let version = env::var("HVI_VERSION")
        .ok()
        .filter(|version| !version.is_empty())
        .unwrap_or_else(from_git);
    println!("cargo::rustc-env=HVI_VERSION={version}");
    println!("cargo::rerun-if-env-changed=HVI_VERSION");
    // Naming anything at all replaces cargo's own rule, which reruns when the
    // package changes, so what the version is derived from has to be named here
    // too. A commit leaves `HEAD` pointing where it did and appends to the
    // reflog, and a checkout onto another branch rewrites `HEAD`, so the two
    // together cover every move the derived string follows.
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo::rerun-if-changed={git_dir}/HEAD");
        println!("cargo::rerun-if-changed={git_dir}/logs/HEAD");
    }
    // A tag laid on the commit already built rewrites neither of those, and it
    // changes the version this derives. The refs a tag lands in are watched as
    // well: a new tag is a file under `refs/tags`, and `git gc` moves it into
    // `packed-refs`. Both are shared by every worktree, so they are read from
    // the common directory rather than from the one above, which in a worktree
    // holds that worktree's `HEAD` and no refs.
    //
    // Each is named only where it exists, since cargo counts a path that is
    // absent as changed and would rerun this on every build.
    if let Some(common_dir) = git(&["rev-parse", "--path-format=absolute", "--git-common-dir"]) {
        for name in ["refs/tags", "packed-refs"] {
            let path = format!("{common_dir}/{name}");
            if Path::new(&path).exists() {
                println!("cargo::rerun-if-changed={path}");
            }
        }
    }
}

/// Derives the version from the git history this build sits in.
fn from_git() -> String {
    // Release tags only, so none of the other tags a working repository
    // accumulates can become a version.
    let described = git(&["describe", "--tags", "--match", "v[0-9]*", "--always"]);
    described.map_or_else(|| UNKNOWN.to_owned(), |described| to_semver(&described))
}

/// Rewrites what `git describe` printed as a SemVer version.
///
/// A build on a release tag is that version. A build past one carries the
/// distance and the commit as build metadata, which SemVer ignores when it
/// orders versions: the string says which build this is rather than where it
/// sits between two releases.
fn to_semver(described: &str) -> String {
    let Some(version) = described.strip_prefix('v') else {
        // No release tag in this history, so `git describe` printed the commit
        // on its own.
        return format!("0.0.0+g{described}");
    };
    // The distance and the commit are appended to whatever tag was found, and a
    // tag carries hyphens of its own once it names a prerelease, so the two
    // appended fields are the last two rather than the second and the third.
    let mut fields = version.rsplitn(3, '-');
    match (fields.next(), fields.next(), fields.next()) {
        (Some(commit), Some(distance), Some(tag))
            if commit.starts_with('g') && distance.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            format!("{tag}+{distance}.{commit}")
        }
        _ => version.to_owned(),
    }
}

/// Runs git and returns its output, or `None` when git is missing or the
/// command failed.
///
/// Cargo runs a build script in the directory of the crate being built, so this
/// reads the checkout that crate is part of.
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::to_semver;

    #[test]
    fn release_tag_becomes_the_version() {
        assert_eq!(to_semver("v0.1.0"), "0.1.0");
    }

    #[test]
    fn commits_past_a_release_become_build_metadata() {
        assert_eq!(to_semver("v0.1.0-15-gabc1234"), "0.1.0+15.gabc1234");
    }

    #[test]
    fn prerelease_tag_keeps_the_hyphen_it_carries() {
        assert_eq!(to_semver("v0.2.0-rc.1-3-gdeadbee"), "0.2.0-rc.1+3.gdeadbee");
    }

    #[test]
    fn history_without_a_release_reports_the_commit() {
        assert_eq!(to_semver("abc1234"), "0.0.0+gabc1234");
    }
}

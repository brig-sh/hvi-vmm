//! Derives the version string a build script embeds in a binary.
//!
//! A build takes its version from git: the release tag it was built from, or
//! that tag plus how far past it the build is. A build with no release tag in
//! its history reports the commit alone. A build whose sources differ from that
//! commit says so with a `dirty` field in the build metadata.
//!
//! Call [`emit`] from a build script and read the value back with
//! `env!("HVI_VERSION")`.
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this
// repository's own git directory, read at build time.
#![allow(clippy::disallowed_methods)]

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Version reported when neither the environment nor git names one, which is
/// what a build from a source archive without the history gets.
const UNKNOWN: &str = "0.0.0+unknown";

/// Paths, relative to the crate, that the binary is built from. A change under
/// any of them makes the build differ from the commit it names, and reruns the
/// derivation so the version says so.
const INPUTS: [&str; 7] = [
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "rust-toolchain.toml",
    "crates",
    "resources",
    "src",
];

/// Emits `HVI_VERSION` for the crate whose build script calls this.
///
/// `HVI_VERSION` in the environment wins. That is how a release names its
/// version once for every binary it builds, and how a build from a checkout
/// without tags still reports the version it is part of.
pub fn emit() {
    let own_checkout = in_own_checkout();
    let version = env::var("HVI_VERSION")
        .ok()
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| {
            if own_checkout {
                from_git(Path::new("."))
            } else {
                UNKNOWN.to_owned()
            }
        });
    println!("cargo::rustc-env=HVI_VERSION={version}");
    println!("cargo::rerun-if-env-changed=HVI_VERSION");
    if !own_checkout {
        return;
    }
    // Naming anything at all replaces cargo's own rule, which reruns when the
    // package changes, so what the version is derived from has to be named here
    // too. A commit leaves `HEAD` pointing where it did and appends to the
    // reflog, and a checkout onto another branch rewrites `HEAD`, so the two
    // together cover every move the derived string follows.
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo::rerun-if-changed={git_dir}/HEAD");
        println!("cargo::rerun-if-changed={git_dir}/logs/HEAD");
    }
    // An edit to the sources makes the tree dirty, or clean again, without
    // touching either. Watching the inputs costs no extra build, since a change
    // under them rebuilds the crate anyway.
    for input in INPUTS {
        if Path::new(input).exists() {
            println!("cargo::rerun-if-changed={input}");
        }
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

/// Returns whether the crate being built is the top of the git checkout
/// around it.
///
/// git searches the parent directories for a repository. A copy of hvi with
/// no history of its own, such as a vendored tree or an unpacked archive,
/// would otherwise report the tag of whichever repository holds it, and
/// rebuild on that repository's commits.
fn in_own_checkout() -> bool {
    let Some(top) = git(&["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR") else {
        return false;
    };
    match (fs::canonicalize(top), fs::canonicalize(manifest_dir)) {
        (Ok(top), Ok(manifest_dir)) => top == manifest_dir,
        _ => false,
    }
}

/// Derives the version from the git history of the checkout at `dir`.
fn from_git(dir: &Path) -> String {
    // Release tags only, so none of the other tags a working repository
    // accumulates can become a version.
    let Some(described) = git_in(
        dir,
        &["describe", "--tags", "--match", "v[0-9]*", "--always"],
    ) else {
        return UNKNOWN.to_owned();
    };
    let version = to_semver(&described);
    if sources_modified(dir) {
        mark_dirty(&version)
    } else {
        version
    }
}

/// Returns whether a tracked file under [`INPUTS`] in the checkout at `dir`
/// differs from the commit checked out.
///
/// Files git does not track are left out, since a build never reads one it was
/// not told about. A failed status counts as clean, the way a failed describe
/// counts as no version: the version names what git could say.
fn sources_modified(dir: &Path) -> bool {
    let mut args = vec!["status", "--porcelain", "--untracked-files=no", "--"];
    args.extend(INPUTS);
    git_in(dir, &args).is_some()
}

/// Adds the `dirty` field to the build metadata of `version`, so a binary
/// built from uncommitted changes never reports the release or the commit it
/// sits on as if it were built from them.
fn mark_dirty(version: &str) -> String {
    if version.contains('+') {
        format!("{version}.dirty")
    } else {
        format!("{version}+dirty")
    }
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

/// Runs git in the current directory and returns its output, or `None` when
/// git is missing or the command failed.
///
/// Cargo runs a build script in the directory of the crate being built, so this
/// reads the checkout that crate is part of.
fn git(args: &[&str]) -> Option<String> {
    git_in(Path::new("."), args)
}

/// Runs git in `dir` and returns its output, or `None` when git is missing or
/// the command failed.
///
/// Optional locks are off, so a status refreshes the index in memory rather
/// than writing it back while a build runs.
fn git_in(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::{from_git, mark_dirty, to_semver};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

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

    #[test]
    fn modified_release_build_is_not_the_release() {
        assert_eq!(mark_dirty(&to_semver("v0.1.0")), "0.1.0+dirty");
        assert_eq!(mark_dirty(&to_semver("v0.2.0-rc.1")), "0.2.0-rc.1+dirty");
    }

    #[test]
    fn modified_build_past_a_release_extends_the_metadata() {
        assert_eq!(
            mark_dirty(&to_semver("v0.1.0-15-gabc1234")),
            "0.1.0+15.gabc1234.dirty"
        );
        assert_eq!(mark_dirty(&to_semver("abc1234")), "0.0.0+gabc1234.dirty");
    }

    // A scratch repository holding one source file and one document, tagged
    // as a release. Removed when dropped.
    struct Checkout {
        // The top of the scratch repository.
        dir: PathBuf,
    }

    impl Checkout {
        // Creates the repository under the system temporary directory, named
        // after the test so parallel tests never share one.
        fn tagged(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("build-version-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("src")).unwrap();
            fs::write(dir.join("src/lib.rs"), "// v1\n").unwrap();
            fs::write(dir.join("README.md"), "v1\n").unwrap();
            let checkout = Self { dir };
            checkout.git(&["init", "-q"]);
            checkout.git(&["add", "."]);
            checkout.git(&["commit", "-q", "-m", "first"]);
            checkout.git(&["tag", "-a", "v0.1.0", "-m", "v0.1.0"]);
            checkout
        }

        // Runs git in the repository with no user or system configuration, so
        // a signing or hook setting on the host cannot fail the test.
        fn git(&self, args: &[&str]) {
            let status = Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(args)
                .current_dir(&self.dir)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?}");
        }

        // Returns the path of `name` inside the repository.
        fn path(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }

        // Returns the repository's top directory.
        fn dir(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for Checkout {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn clean_tag_reports_the_release() {
        let checkout = Checkout::tagged("clean");
        assert_eq!(from_git(checkout.dir()), "0.1.0");
    }

    #[test]
    fn edited_source_marks_the_tag_build_dirty() {
        let checkout = Checkout::tagged("edited");
        fs::write(checkout.path("src/lib.rs"), "// v2\n").unwrap();
        assert_eq!(from_git(checkout.dir()), "0.1.0+dirty");
    }

    #[test]
    fn edits_outside_the_sources_leave_the_version_clean() {
        let checkout = Checkout::tagged("outside");
        fs::write(checkout.path("README.md"), "v2\n").unwrap();
        fs::write(checkout.path("src/untracked.rs"), "// new\n").unwrap();
        assert_eq!(from_git(checkout.dir()), "0.1.0");
    }
}

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

//! Records the commit the build came from, as `HVI_GIT_SHA`.
//!
//! The machine profile carries it, and a checkpoint is refused on an hvi built
//! from another commit, since the device state it holds is only defined by the
//! code that wrote it. A tree with uncommitted changes gets a `-dirty` suffix,
//! which no profile check accepts either, since it does not say which changes.
//! A build with no git, such as one from a source tarball, reads
//! `HVI_GIT_SHA` from the environment or records `unknown`, which no profile
//! check accepts. Whoever sets `HVI_GIT_SHA` vouches that it names the code.

use std::process::Command;

/// Runs git with `args` in the package directory and returns its trimmed
/// output, or `None` when git is missing or fails.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn main() {
    println!("cargo:rerun-if-env-changed=HVI_GIT_SHA");
    // Naming any path turns off cargo's default of rerunning on every package
    // file, so the files that make up the build are named here as well.
    for path in ["src", "resources", "build.rs", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={path}");
    }
    let sha = std::env::var("HVI_GIT_SHA")
        .ok()
        .filter(|sha| !sha.is_empty())
        .or_else(|| {
            // A commit that changes no file moves HEAD and its log alone, and
            // `git add` moves the index. In a worktree these live under the
            // worktree's own git directory, which `--git-path` resolves.
            for name in ["HEAD", "logs/HEAD", "index"] {
                if let Some(path) = git(&["rev-parse", "--git-path", name]) {
                    println!("cargo:rerun-if-changed={path}");
                }
            }
            let sha = git(&["rev-parse", "HEAD"])?;
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_some();
            Some(if dirty { format!("{sha}-dirty") } else { sha })
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=HVI_GIT_SHA={sha}");
}

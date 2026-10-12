//! Emits the version string `hvi --version` and `hvi::CORE_VERSION` report.
//!
//! A release is a git tag, and the version a build reports is derived from
//! the history it was built in, so a build between two releases says which
//! one it sits past. The version in `Cargo.toml` is the `0.0.0` cargo insists
//! on and names nothing. See the `build-version` crate for the derivation.

fn main() {
    build_version::emit();
}

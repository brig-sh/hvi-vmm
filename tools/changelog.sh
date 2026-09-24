#!/usr/bin/env bash
#
# Print the changelog for a release, or a preview of the one the next release
# would carry, from the Conventional-Commits history with git-cliff
# (cliff.toml).
#
#   tools/changelog.sh                  # preview: what is unreleased so far
#   tools/changelog.sh --notes vX.Y.Z   # one release's notes
#
# Nothing is written to the tree. The repository keeps no CHANGELOG.md: a
# release is a git tag, and its notes are generated from the commits since the
# tag before it, so the releases page is the changelog. Preview before tagging
# to see what a release would say.
#
# git-cliff is pinned in pins.env. An installed binary of any version is used
# with a warning when it disagrees with the pin; with none installed, the
# pinned version runs in a container.
#
# Written for the bash 3.2 that ships with macOS.

set -euo pipefail

cd "$(dirname "$0")/.."

# shellcheck disable=SC1091 # pins.env is a committed sibling, sourced at runtime
. ./pins.env

IMAGE="orhunp/git-cliff:$GIT_CLIFF_VERSION"

cliff() {
  if command -v git-cliff >/dev/null 2>&1; then
    local installed
    installed=$(git-cliff --version | awk '{print $2}')
    if [ "$installed" != "$GIT_CLIFF_VERSION" ]; then
      echo "changelog: git-cliff $installed installed, pins.env says" \
        "$GIT_CLIFF_VERSION; the output may differ from CI" >&2
    fi
    git-cliff "$@"
    return
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "changelog: install git-cliff $GIT_CLIFF_VERSION (cargo install" \
      "git-cliff, or brew install git-cliff), or run docker" >&2
    exit 1
  fi
  # This reads the history through the mount, so it needs a checkout that
  # carries its own .git directory. In a git worktree that is a file pointing
  # outside the mount, and the container sees no history: install the binary
  # to work in one.
  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$PWD:/app" -w /app --entrypoint git-cliff "$IMAGE" "$@"
}

usage() {
  echo "usage: tools/changelog.sh [--notes <tag>]" >&2
  exit 2
}

case "${1:-}" in
  --notes)
    [ $# -ge 2 ] || usage
    # A release has the tag, and HEAD is its commit, so --current names that
    # tag's section. A preview of a tag that does not exist yet folds the
    # unreleased commits into it instead.
    #
    # Which branch to take is decided by whether the tag exists rather than by
    # what --current returns: with no tags at all it succeeds and returns the
    # unreleased section, so a caller falling back on its status would publish
    # notes headed "unreleased" and never know.
    if git rev-parse -q --verify "refs/tags/$2" >/dev/null; then
      cliff --config cliff.toml --current --strip header
    else
      cliff --config cliff.toml --unreleased --tag "$2" --strip header
    fi
    ;;
  "")
    cliff --config cliff.toml --unreleased --strip header
    ;;
  *)
    usage
    ;;
esac

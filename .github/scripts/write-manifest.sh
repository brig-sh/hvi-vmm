#!/usr/bin/env bash
# Write the manifest.json a published artifact carries beside its files.
#
# Every artifact carries one, so the fields common to all of them are written
# here rather than once per publisher: the commit the build ran on and a digest
# per file. A consumer can then tell what it pulled from the bytes alone.
#
# Component-specific fields are passed as name=value arguments and merged in. A
# name:=value pair takes its value as JSON, which is what a boolean or a number
# needs: the string "false" reads as true to a consumer that tests it.
#
#   write-manifest.sh <directory> [name=value | name:=value ...]
set -euo pipefail

# GNU coreutils names it sha256sum and macOS ships shasum, and the release
# builds run on both.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

# Merge the name=value and name:=value arguments into one JSON object.
merge_fields() {
  local pair object='{}'
  for pair in "$@"; do
    # Anchored on the name, so a value holding the separator stays a string: a
    # ref and a URL both carry a colon.
    if [[ $pair =~ ^[^=:]+:= ]]; then
      object=$(jq --arg name "${pair%%:=*}" --argjson value "${pair#*:=}" \
        '. + {($name): $value}' <<<"$object")
    else
      object=$(jq --arg name "${pair%%=*}" --arg value "${pair#*=}" \
        '. + {($name): $value}' <<<"$object")
    fi
  done
  printf '%s' "$object"
}

main() {
  local directory=$1
  shift

  # The commit that was built, read from the checkout rather than from
  # GITHUB_SHA: that names the ref the run was triggered on, and a release
  # dispatched on a branch builds a tag which is not that ref.
  local revision
  revision=$(git rev-parse HEAD 2>/dev/null) || revision=${GITHUB_SHA:-unknown}

  # A manifest from an earlier run would otherwise be digested as one of the
  # files this one describes.
  rm -f "$directory/manifest.json"

  # Taken before the manifest lands, so it describes the files beside it.
  local digests
  digests=$(
    (cd "$directory" && sha256 -- *) |
      jq -Rn '[inputs | split("  ") | {(.[1]): .[0]}] | add'
  )

  local fields
  fields=$(merge_fields "$@")

  jq -n \
    --argjson fields "$fields" \
    --arg revision "$revision" \
    --argjson files "$digests" \
    '$fields + {$revision, $files}' \
    >"$directory/manifest.json"
}

main "$@"

#!/usr/bin/env bash
# Sign each published artifact that carries no signature yet.
#
# A push and its signature are two registry operations, so a run that stops
# between them leaves a tag no consumer can verify. Signing takes the ref
# alone, so a publisher passes every tag it names whether or not this run
# pushed: nothing is rebuilt and nothing is downloaded. A tag with nothing
# under it is an error, since a publisher pushes before it calls this.
#
# The question goes to cosign rather than to a signature tag, so the answer
# holds whichever way cosign stores what it writes. A signature is written on
# the one status that says there is none. Any other failure leaves the question
# open, since cosign fetches its trust root over the network on every call, so
# signing then could add a second signature to something already signed.
#
# The identity is this repository's publish workflow, at any ref, so a
# signature from another workflow of the organization does not count. Matched
# without case, since the certificate spells the repository as GitHub records
# it.
#
#   GITHUB_REPOSITORY=<owner>/<repo> sign-artifacts.sh <ref> [<ref> ...]
set -euo pipefail

ISSUER=https://token.actions.githubusercontent.com
IDENTITY="(?i)^https://github\.com/${GITHUB_REPOSITORY}/\.github/workflows/publish-binaries\.yml@"

# The status cosign returns for an artifact that carries no signature.
UNSIGNED=10

# Sign one artifact, unless it carries a signature already. Returns nonzero
# when it could not be signed.
sign() {
  local ref=$1 status=0 message
  if ! oras manifest fetch "$ref" >/dev/null 2>&1; then
    echo "::error::$ref was not published"
    return 1
  fi
  message=$(cosign verify --certificate-oidc-issuer "$ISSUER" \
    --certificate-identity-regexp "$IDENTITY" "$ref" 2>&1) || status=$?
  case $status in
    0) echo "$ref is signed" ;;
    "$UNSIGNED") cosign sign "$ref" ;;
    *)
      # cosign prints a message for an unsigned artifact too, so its output
      # is shown only where it says something the caller does not expect.
      printf '%s\n' "$message" >&2
      echo "::error::could not tell whether $ref is signed"
      return 1
      ;;
  esac
}

main() {
  # A caller whose ref list came out empty would otherwise report success
  # having signed nothing.
  if [[ $# -eq 0 ]]; then
    echo "::error::no refs to sign"
    exit 1
  fi

  # Every ref is tried, so one that cannot be signed leaves the rest signed.
  local ref failures=0
  for ref in "$@"; do
    sign "$ref" || failures=$((failures + 1))
  done
  [[ $failures -eq 0 ]] || exit 1
}

main "$@"

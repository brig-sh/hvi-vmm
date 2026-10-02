#!/usr/bin/env bash
# Sign a macOS binary with the organization's Developer ID and notarize it.
#
# A release binary is downloaded, and Gatekeeper runs a downloaded binary only
# when it is signed with a Developer ID and notarized. An ad-hoc signature
# carries the hypervisor entitlement as well, so a binary built locally needs
# none of this.
#
# The certificate is imported into a keychain created for this run and deleted
# when the script returns, so nothing is left in the runner's login keychain.
# Two signing jobs at once on one Mac race over the user search list, whichever
# repository they come from, so the keychain's whole life is spent holding the
# Mac's keychain lock (keychain-lock.sh), which hull's signing jobs take too.
#
#   MACOS_CERT_P12=... MACOS_CERT_PASSWORD=... NOTARY_KEY_P8=... \
#   NOTARY_KEY_ID=... NOTARY_ISSUER_ID=... sign-macos.sh <binary> <entitlements>
set -euo pipefail

BINARY=$1
ENTITLEMENTS=$2
LOCK="$(dirname "$0")/keychain-lock.sh"

WORK=$(mktemp -d)
KEYCHAIN="$WORK/sign.keychain-db"

# The wait sits below the job's timeout with the notarization's 30 minutes on
# top, so a job stuck behind another reports who holds the lock rather than
# being killed while it waits.
export HULL_KEYCHAIN_LOCK_WAIT=${HULL_KEYCHAIN_LOCK_WAIT:-1200}
"$LOCK" acquire

# The search list as this job found it, read under the lock so it holds no
# other job's keychain.
saved=()
while IFS= read -r keychain; do
  keychain=${keychain#"${keychain%%[![:space:]]*}"}
  keychain=${keychain#\"}
  keychain=${keychain%\"}
  if [[ -n $keychain ]]; then
    saved+=("$keychain")
  fi
done < <(security list-keychains -d user)
if [[ ${#saved[@]} -eq 0 ]]; then
  saved=(login.keychain-db)
fi

# The import replaces the user search list wholesale, so the list goes back
# whatever happened above it, and the lock is let go only after that.
cleanup() {
  security delete-keychain "$KEYCHAIN" 2>/dev/null || true
  security list-keychains -d user -s "${saved[@]}"
  rm -rf "$WORK"
  "$LOCK" release
}
trap cleanup EXIT
# A cancelled job is signalled, and the shell runs no EXIT trap on a signal it
# leaves at the default, so the lock would wait out its stale age.
trap 'exit 1' INT TERM HUP

keychain_password=$(uuidgen)
security create-keychain -p "$keychain_password" "$KEYCHAIN"
security set-keychain-settings -lut 3600 "$KEYCHAIN"
security unlock-keychain -p "$keychain_password" "$KEYCHAIN"
printf '%s' "$MACOS_CERT_P12" | base64 -d >"$WORK/cert.p12"
security import "$WORK/cert.p12" -k "$KEYCHAIN" \
  -P "$MACOS_CERT_PASSWORD" -T /usr/bin/codesign
rm "$WORK/cert.p12"
security set-key-partition-list -S apple-tool:,apple: \
  -k "$keychain_password" "$KEYCHAIN" >/dev/null
security list-keychains -d user -s "$KEYCHAIN" "${saved[@]}"

# `|| true`, so a certificate with no such identity reaches the error below
# instead of ending the script on the failed grep.
identity=$(security find-identity -v -p codesigning "$KEYCHAIN" |
  grep -o '"Developer ID Application: [^"]*"' | head -1 | tr -d '"') || true
if [[ -z $identity ]]; then
  echo "::error::no Developer ID identity in the imported certificate"
  exit 1
fi

# --timestamp, because a signature without one stops verifying the day the
# certificate expires. --options runtime, because notarization requires the
# hardened runtime.
codesign --force --options runtime --timestamp \
  --keychain "$KEYCHAIN" --sign "$identity" \
  --entitlements "$ENTITLEMENTS" "$BINARY"
codesign --verify --strict "$BINARY"
codesign -d --entitlements - --xml "$BINARY" |
  grep -q com.apple.security.hypervisor || {
  echo "::error::$BINARY lost its hypervisor entitlement"
  exit 1
}

# A bare binary cannot have a ticket stapled to it, so it is notarized in a zip
# and Gatekeeper resolves the ticket online. The timeout sits below the job's,
# so a stuck submission fails here and the trap above still runs.
printf '%s' "$NOTARY_KEY_P8" >"$WORK/notary-key.p8"
ditto -c -k "$BINARY" "$WORK/binary.zip"
submission=$(xcrun notarytool submit "$WORK/binary.zip" \
  --key "$WORK/notary-key.p8" \
  --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID" \
  --wait --timeout 30m --output-format json)
echo "$submission"
submission_id=$(printf '%s' "$submission" |
  sed -n 's/.*"id" *: *"\([^"]*\)".*/\1/p' | head -1)
if [[ -z $submission_id ]]; then
  echo "::error::notarytool returned no submission id"
  exit 1
fi

# What Apple returns is the authority on whether this binary is notarized. The
# ticket names the cdhash it covers, so comparing that to the binary about to
# ship proves the artifact is the notarized one. A Gatekeeper probe answers the
# same question over the network, hours later and unreliably.
xcrun notarytool log "$submission_id" \
  --key "$WORK/notary-key.p8" \
  --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID" \
  >"$WORK/notary-log.json"
rm "$WORK/notary-key.p8"
cat "$WORK/notary-log.json"

grep -q '"status" *: *"Accepted"' "$WORK/notary-log.json" || {
  echo "::error::Apple did not accept $BINARY"
  exit 1
}
ticket=$(sed -n 's/.*"cdhash" *: *"\([^"]*\)".*/\1/p' "$WORK/notary-log.json" |
  head -1)
actual=$(codesign -dvvv "$BINARY" 2>&1 | sed -n 's/^CDHash=//p')
if [[ -z $ticket || $ticket != "$actual" ]]; then
  echo "::error::notarized cdhash $ticket does not match shipped cdhash $actual"
  exit 1
fi
echo "$BINARY is Developer ID signed and notarized; ticket covers $actual"

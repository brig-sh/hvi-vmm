#!/usr/bin/env bash
# Creates what the e2e tests need root for, once per Linux host: the tap device
# the --net-tap tests attach to. The tests themselves run unprivileged.
#
#   sudo e2e/tools/provision.sh [user]
#
# The tap belongs to the user, by default the one sudo was run by, so that
# user's hvi can attach to it. The host side takes 172.30.0.1/24, and the guest
# uses the next address. The setup binary reads the name from the TAP= line
# below and the address from the device, so this script is the one place either
# is set. Running it again changes nothing.
set -euo pipefail

TAP=hvi-e2e0
ADDRESS=172.30.0.1/24

user=${1:-${SUDO_USER:-$(id -un)}}
if ! ip link show "$TAP" >/dev/null 2>&1; then
  ip tuntap add dev "$TAP" mode tap user "$user"
fi
ip address replace "$ADDRESS" dev "$TAP"
ip link set "$TAP" up
echo "provision: $TAP is up with $ADDRESS for $user"

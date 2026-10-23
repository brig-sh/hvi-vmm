#!/usr/bin/env bash
# Creates what the e2e tests need root for, once per boot of a Linux host:
# access to /dev/kvm, and the tap device the --net-tap tests attach to. Neither
# outlasts a reboot. The tests themselves run unprivileged.
#
#   sudo e2e/tools/provision.sh [user]
#   sudo e2e/tools/provision.sh --remove
#
# The tap belongs to the user, by default the one sudo was run by, so that
# user's hvi can attach to it. The host side takes 172.30.1.1/24, and the guest
# uses the next address. The setup binary reads the name from the TAP= line
# below and the address from the device, so this script is the one place either
# is set. Running it again changes nothing.
#
# --remove deletes the tap and the /dev/kvm entries this script added, and
# leaves any entry it found already there.
set -euo pipefail

TAP=hvi-e2e0
ADDRESS=172.30.1.1/24
# Holds one file per user this script gave /dev/kvm access. /run is emptied at
# boot, as /dev/kvm's entries are.
STATE=/run/hvi-e2e

# The /dev/kvm entries are read and set with getfacl and setfacl, which the acl
# package installs, so a host without them stops before anything changes.
for tool in getfacl setfacl; do
  if ! command -v "$tool" >/dev/null; then
    echo "provision: $tool is missing; install the acl package" >&2
    exit 1
  fi
done

# Returns whether user $1, a name or a number, has an entry of its own on
# /dev/kvm.
has_entry() {
  uid=$(id -u "$1" 2>/dev/null || echo "$1")
  getfacl -cpn /dev/kvm 2>/dev/null | grep -q "^user:$uid:"
}

if [ "${1:-}" = "--remove" ]; then
  for record in "$STATE"/kvm-acl.*; do
    [ -e "$record" ] || continue
    user=${record##*/kvm-acl.}
    if has_entry "$user"; then
      setfacl -x "u:$user" /dev/kvm
      echo "provision: $user may no longer open /dev/kvm"
    fi
    rm -f "$record"
  done
  rmdir "$STATE" 2>/dev/null || true
  if ip link show "$TAP" >/dev/null 2>&1; then
    ip link delete "$TAP"
    echo "provision: $TAP is removed"
  fi
  exit 0
fi

user=${1:-${SUDO_USER:-$(id -un)}}

# A tap's owner cannot change, and a host can serve more than one user. A tap
# another user owns therefore stops the script before it changes anything, since
# that user's run may be using it.
uid=$(id -u "$user" 2>/dev/null || echo "$user")
if ip link show "$TAP" >/dev/null 2>&1; then
  owner=$(cat "/sys/class/net/$TAP/owner")
  if [ "$owner" != "$uid" ]; then
    echo "provision: $TAP belongs to uid $owner, whose runs may be using it;" \
      "run the suite as that user" >&2
    exit 1
  fi
fi

# /dev/kvm belongs to root and the kvm group. A user without an entry of their
# own gets one, which lasts until the device node is recreated at the next boot.
# The group alone is not enough: a process started before the user joined it,
# such as a runner service, does not hold it.
if ! has_entry "$user"; then
  mkdir -p "$STATE"
  setfacl -m "u:$user:rw" /dev/kvm
  touch "$STATE/kvm-acl.$user"
  echo "provision: $user may open /dev/kvm"
fi

# Another device with an address in the subnet would take the guest's packets,
# so a clash stops here rather than as a lost packet in a test.
clash=$(ip -4 -o address show to "$ADDRESS" | awk -v tap="$TAP" '$2 != tap { print $2 }')
if [ -n "$clash" ]; then
  echo "provision: $clash already has an address in the subnet of $ADDRESS; change ADDRESS" >&2
  exit 1
fi

if ! ip link show "$TAP" >/dev/null 2>&1; then
  ip tuntap add dev "$TAP" mode tap user "$user"
fi
ip address flush dev "$TAP"
ip address add "$ADDRESS" dev "$TAP"
ip link set "$TAP" up
echo "provision: $TAP is up with $ADDRESS for $user"

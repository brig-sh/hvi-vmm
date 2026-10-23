# The e2e suite

The suite's tests boot real guests under the release `hvi` binary and check each
run from outside the process.
[docs/testing.md](../docs/testing.md#the-e2e-suite) says what the suite proves,
its tiers, and where it runs in CI.

## Running it

```sh
sudo e2e/tools/provision.sh           # Linux, once per boot
rustup target add "$(uname -m | sed s/arm64/aarch64/)-unknown-linux-musl"
cargo nextest run --manifest-path e2e/Cargo.toml
```

`e2e/tools/provision.sh` is the only part that needs root, and it needs `ip`
from iproute2 and `setfacl` from acl. It lets the user open `/dev/kvm` and
creates the tap device `hvi-e2e0` with `172.30.1.1/24`, neither of which
outlasts a reboot. It stops if another user owns the tap, or another device
already has an address in that /24. With `--remove` the script deletes the tap
and the `/dev/kvm` access it gave, and keeps any access the user had before. The
tests themselves run as the user.

The musl target is that of the host's architecture, which is the guest's. The
guest agent builds for it, and on Linux `hvi` does too.

On Linux the export tests need virtiofsd. The setup takes the one
`HVI_E2E_VIRTIOFSD` names, or else finds one on `PATH` or where distributions
install it. CI builds the version `.github/actions/run-e2e/action.yml` pins,
which needs the libseccomp and libcap-ng headers, such as Debian's
`libseccomp-dev` and `libcap-ng-dev`:

```sh
cargo install --locked virtiofsd@<version>
```

## Layout

| Crate | What it holds |
| --- | --- |
| `e2e` (`hvi-e2e`) | The suite library, the setup binary, and one test binary per subsystem in `tests/`. |
| `e2e/protocol` (`hvi-e2e-protocol`) | The messages the harness and the agent exchange. |
| `e2e/guest/agent` (`hvi-e2e-agent`) | The program the guest's init starts. It listens on vsock port 1024 behind `--agent-sock`, and runs programs, moves bytes and powers the guest off. |

Before the tests, nextest runs the setup binary in `e2e/src/bin/setup`. It
builds `hvi`, against musl on Linux, and the guest agent. It fetches the guest
kernel, the Alpine root filesystem and gvproxy, and assembles the initramfs. It
finds virtiofsd, prints its version, and finds the tap. Every download is pinned
in `e2e/assets.toml`, an image by the digest of its manifest and any other file
by its sha256, and is cached under `~/.cache/hvi-e2e`. The guest kernel is the
one `brig-sh/community-images` publishes as `ghcr.io/brig-sh/kernel`, and the
root filesystem is the `alpine` image's. Renovate keeps the pins current.

On macOS the setup binary signs `hvi` with `hvi.entitlements`. Exports there use
hvi's own server rather than virtiofsd, and the tap tests are Linux only.

## A run's files

A test checks a run three ways: hvi's exit status, its `guest stopped:` line,
and the event ledger. The ledger's `vmm.start` must report the confinement the
run was started with, and its `vmm.stop` must give the expected reason with no
record dropped. Each run writes its command line, console, stderr and ledger
under `e2e/target/hvi-e2e/tests/hvi-e2e/<binary>/<test>/`, and a retry under
`<test>.attempt<N>/` beside it.

## Missing capabilities and slow hosts

A test that needs the tap or virtiofsd fails when the host lacks it, and names
the filter that leaves it out. A Linux host that is meant to run without them
passes the filter, and nextest then reports those tests as skipped:

```sh
cargo nextest run --manifest-path e2e/Cargo.toml \
  -E 'not test(/(^|::)tap::/) and not binary(fs)'
```

| Variable | Set by | Meaning |
| --- | --- | --- |
| `HVI_E2E_TIMEOUT_SCALE` | the runner | A factor for every timeout, 1 by default, for a slow host. |
| `HVI_E2E_CACHE` | the runner | The download cache. |
| `HVI_E2E_ARTIFACTS` | the runner | Where runs write their files. |
| `HVI_E2E_VIRTIOFSD` | the runner | The virtiofsd to use, instead of the one found. |
| `HVI_E2E_VGIC` | the runner | The vGIC an arm64 KVM host offers, `v2` or `v3`. The 32-vCPU test then expects that vGIC's limit rather than reading it from hvi's stderr. |
| `HVI_E2E_HVI`, `HVI_E2E_KERNEL`, `HVI_E2E_INITRAMFS`, `HVI_E2E_GVPROXY`, `HVI_E2E_TAP`, `HVI_E2E_TAP_ADDRESS` | the setup binary | What it prepared, for the tests. |

## Adding a test

Every new test goes on the probation list in `e2e/.config/nextest.toml` by its
exact name, and so does a flaky one. It stays there until it has passed seven
nightly runs in a row on every backend that builds it. After each nightly run,
an issue labeled `e2e-probation` names the tests that may leave, with the runs
each one failed. A test that fails rarely can still pass seven runs in a row, so
check those before removing one.

A test too slow to run on every pull request goes on the nightly list beside it
instead, such as the one that waits out the 60 s hvi gives a vhost-user daemon
to start, and runs only nightly. One that leaves the nightly list goes on
probation, like a new test. A test that loads the whole host, such as one with
32 vCPUs or gibibytes of RAM, also goes in the override that puts it in the
`heavy` test group, whose tests run one at a time.

`e2e/tools/check-probation.sh <base>` fails a change that adds a test without
putting it on either list, or that takes one off the nightly list without
putting it on probation. It goes by name, so a renamed or moved test counts as
new, as does one whose `#[ignore]` is removed. nextest ignores an exact name
that matches no test, so `e2e/tools/check-filters.sh` fails on any such name in
the filters.

A test that pins a bug not fixed yet carries `#[ignore]` with the reason, and
the issue number where there is one. Until its ignore is removed it needs no
probation, since only the nightly report of pinned tests runs it.

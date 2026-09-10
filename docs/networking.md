# Networking

hvi gives a guest one virtio-net device, or none. There is no second NIC and
no hotplug.

Three modes back that device. They are selected by flag, and the first one
given wins: `--net-tap`, then `--net-gateway`, then `--net`. Passing more than
one is not an error, so pass one.

## Mode comparison

| | `--net` | `--net-gateway <sock>` | `--net-tap <dev>` |
| --- | --- | --- | --- |
| Platforms | all three | all three | Linux only |
| Real egress | no | yes | yes |
| Guest address | 10.0.2.15 | from the gateway (10.87.0.2) | whoever configures it |
| Gateway | 10.0.2.2 | 10.87.0.1 | the other end of the tap |
| DNS server | 10.0.2.3 | 10.87.0.1 | external |
| Who runs it | hvi | an external gvisor-tap process | whoever owns the netns |
| TLS SNI recorded | no | yes | yes |
| `--net-mac` honoured | no | no | yes |

## The built-in stack: `--net`

`--net` runs a small user-space network stack inside the VMM. It needs no
privileges, no entitlement and no host configuration, which makes it the right
choice for a first boot and for tests. It is not a way onto the network.

It answers four things, and each is narrower than "supports the protocol":

- **ARP**, but only requests (opcode 1) for `10.0.2.2` and `10.0.2.3`. Any
  other target gets no reply.
- **ICMP**, but only echo request (type 8).
- **DHCP**, but only DISCOVER and REQUEST. The reply carries a 24-hour lease,
  netmask `255.255.255.0`, router `10.0.2.2` and DNS `10.0.2.3`.
- **DNS**, over UDP to `10.0.2.3:53`, and with the limits below.

TCP is seen and recorded, and it is not forwarded. A guest that opens a TCP
connection gets nothing back.

### DNS

The stack parses the question, records the name, and asks the host to resolve
it. It refuses a question that uses a compression pointer, and one whose name
runs past the end of the message without room for the type and class.

**Name resolution does not work while confined.** Resolving needs a socket,
and neither the macOS Seatbelt profile nor the Linux seccomp allowlists grant
one. The query is still parsed and recorded, so the reply reaches the guest
with no addresses in it:

```text
$ nslookup example.com 10.0.2.3
Server:		10.0.2.3
Address:	10.0.2.3:53

Non-authoritative answer:
```

With `--no-sandbox` the same command answers:

```text
Non-authoritative answer:
Name:	example.com
Address: 104.20.23.154
```

Do not run a workload under `--no-sandbox` to obtain name resolution. Use
`--net-gateway` or `--net-tap`, which resolve through something outside the
VMM and keep confinement on.

## An external gateway: `--net-gateway <socket>`

This relays raw frames over a Unix stream socket to a gvisor-tap-vsock
process, which owns the DHCP, DNS and NAT. The wire format is the QEMU stream
protocol: each frame carries a 4-byte big-endian length prefix.

hvi is the client here. The gateway must already be listening.

```sh
hvi boot --kernel <Image> --net-gateway /run/hvi/gateway.qemu
```

If the socket cannot be reached, hvi does not fail. It warns and falls back to
the built-in stack, so a guest can come up with no egress and no error.

The warning text differs by backend. On macOS:

```text
[hvi] WARNING: cannot reach gateway /run/hvi/gateway.qemu (No such file or
directory (os error 2)); falling back to built-in stack
```

On Linux, from `[hvi/kvm]` on arm64 and `[hvi/x86]` on x86-64:

```text
[hvi/kvm] WARNING: gateway /run/hvi/gateway.qemu unreachable (No such file or
directory (os error 2)); built-in stack
```

Read that line. To detect this in a log pipeline across platforms, match the
substring `built-in stack`, which all three carry, rather than either full
sentence.

A socket path is also subject to the platform's `sockaddr_un` length limit,
and an over-long path fails the same way.

CAUTION: The gateway enforces whatever egress policy it enforces. hvi does not
filter egress in this mode. Do not describe traffic through an external
gateway as filtered by hvi.

## A Linux tap: `--net-tap <dev>`

hvi attaches to a tap device that already exists. It does not create one, does
not configure addresses, and does not bring it up. Whoever owns the network
namespace does that.

The device is opened through `/dev/net/tun` with `IFF_TAP`, `IFF_NO_PI` and
`IFF_VNET_HDR`, and the vnet header size is set to the `virtio_net_hdr_v1`
length rather than tun's legacy default. No offloads are negotiated.

An interface name must be 1 to 15 bytes. A tap that cannot be opened fails the
boot and names the interface, which is the opposite of the gateway's silent
fallback.

On macOS the flag is refused after the backend starts:

```text
hvi: --net-tap tap0: no /dev/net/tun on macOS; use --net-gateway
```

### `--net-mac`

`--net-mac` sets the MAC the guest NIC presents, and **only under
`--net-tap`**. It is read in the tap branch of the two Linux backends and
nowhere else.

It exists because a `tc mirred` redirect hands hvi the veth's frames
unchanged, so the guest has to answer to the veth's address or every reply is
dropped as not addressed to it.

Two consequences that are easy to miss:

- Under `--net`, `--net-gateway`, or on macOS, the value is accepted and
  discarded. There is no message.
- A value that does not parse warns and keeps the default, but only in the tap
  branch that reads it. Elsewhere a malformed value is silent too.
- Omitting it under `--net-tap` is accepted. The guest keeps the default MAC,
  which under a redirect usually means it receives nothing.

## What the ledger records

With `--events <path>`, hvi writes a `net` record for observed traffic. Two
properties decide what those records can be used for:

- **They are per packet, not per flow.** There is no flow table and no
  aggregation. One DNS lookup that retransmits produces two identical records.
- **They are egress only.** The `direction` and `guest_initiated` fields are
  constants in the code, not observations. Inbound frames produce no record.

A record looks like this:

```json
{"sandbox_id":"hvi","ts":1788992154919811000,"provenance":"boundary","source":"net","payload":{"five_tuple":{"proto":17,"src_ip":"10.0.2.15","src_port":43098,"dst_ip":"10.0.2.3","dst_port":53},"direction":"egress","guest_initiated":true,"bytes":37,"dns":"example.com"}}
```

`bytes` is the length of the layer-4 slice, not the IP total length.

## What TLS SNI observation establishes

Under `--net-tap` and `--net-gateway`, hvi parses the server name out of a TLS
ClientHello and puts it in the record. The built-in `--net` stack does not do
this at all.

An SNI value tells you one thing: **this guest sent a packet that claimed to
be starting a TLS session with that name.** It is a useful signal. It is not
any of the following:

- Proof that the connection was established, or that anything was sent.
- The identity of the application that sent it.
- Authorization. Observing a name is not permitting or denying it.
- Complete. A ClientHello split across segments, a resumed session, encrypted
  ClientHello, QUIC, and any non-TLS protocol all yield no name.

Do not build an allowlist on this field. It is an observation of what a
hostile guest chose to put on the wire.

## See also

- [observability.md](observability.md) for the ledger and the I/O trace.
- [security.md](security.md) for why the confinement denies the resolver.
- [cli.md](cli.md) for the flags.

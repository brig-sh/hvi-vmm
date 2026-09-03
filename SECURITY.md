# Security

hvi is a microVMM. It runs a Linux guest that we assume is hostile, and it is
the thing standing between that guest and the host. So the boundary we care
about is the one between the guest and everything outside its VM.

## Reporting a vulnerability

Please report privately, through GitHub: open the **Security** tab of this
repository and choose **Report a vulnerability**. That opens a private advisory
that only the maintainers can see, and it keeps the report, the fix and the
disclosure in one place.

Do not open a public issue for something you believe is exploitable. If you
cannot use GitHub for some reason, mail <ananos@nofire.ai> instead.

What to expect:

- We aim to acknowledge a report within three working days.
- We will tell you whether we consider it in scope, and why, rather than going
  quiet.
- If it is a real vulnerability we fix it on `main` first, publish a GitHub
  Security Advisory, and request a CVE through GitHub as the numbering
  authority.
- We are happy to credit you in the advisory. Tell us how you want to be named.

There is no bounty programme. We are a small team and we would rather be honest
about that than imply otherwise.

## What is in scope

Anything that lets a guest reach past its own VM. For instance:

- a guest escaping into the VMM process, or executing code on the host;
- a guest reaching host resources the confinement layer is supposed to deny,
  whether that is the Seatbelt profile on macOS or the seccomp filters on Linux
  (see [Confinement](README.md#confinement));
- one sandbox reading or influencing another, or the host, through a device
  backend, a share or the network stack;
- the VMM mishandling host paths or host state in a way a guest can steer, for
  example through a writable directory share.

Reports against the shipped confinement profiles are welcome, including a
syscall or an operation that we allow and should not.

## What is out of scope

- A guest that degrades or hangs **its own VM**. The guest owns the resources
  we gave it, and a guest wasting them is not a boundary crossing.
- Resource exhaustion on the host that follows from limits the operator chose,
  for example running many VMs without any bound on memory.
- Anything under `--no-sandbox`, which exists to debug the profile and the
  filters and deliberately turns confinement off.
- Side channels that depend on shared microarchitecture, such as speculative
  execution and cache timing. They are real, and they are the platform's to
  mitigate, not a small VMM's.
- Reports from a version that is not current `main`. See below.

## Supported versions

There is no released version yet. `main` is what we support, and a fix lands
there. Once tags exist, this section says which ones we still fix.

## Maturity

hvi is young. It has not had an external security audit, and no part of it has
been through formal verification. It is exercised by CI on every backend, and
the confinement layer has negative tests that check what a confined thread must
lose as well as what it must keep, but that is testing, not assurance. Please
weigh that when you decide what to run on it.

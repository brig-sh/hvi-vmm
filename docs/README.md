# hvi documentation

Four journeys. Start at the one that matches what you are doing.

## Boot a guest

| Page | What it covers |
| --- | --- |
| [first-boot.md](first-boot.md) | Prerequisites, signing on macOS, and one guest booted to a shell on each platform. |
| [guest-images.md](guest-images.md) | Where a kernel and an initramfs come from, how to build them, and the kernel options a guest needs. |
| [cli.md](cli.md) | Every subcommand, flag, default and environment variable, and what each platform ignores. |

## Give the guest something to work with

| Page | What it covers |
| --- | --- |
| [storage-and-sharing.md](storage-and-sharing.md) | virtio-blk disks, and virtio-fs directory shares on macOS: access modes, cache policy, ownership, and the limits that matter before you share real data. |
| [networking.md](networking.md) | The built-in stack, an external gateway, and a Linux tap. What each mode forwards, and what it cannot. |
| [observability.md](observability.md) | The event ledger, memory dumps, I/O traces, and the tracing environment variables. What each artefact contains, and how to handle it. |

## Understand or extend it

| Page | What it covers |
| --- | --- |
| [architecture.md](architecture.md) | Backends, boot protocols, the device model, guest memory, and concurrency. |
| [embedding.md](embedding.md) | Linking hvi as a library: `BootConfig`, `machine::boot`, and the process-global configuration outside it. |
| [plugins.md](plugins.md) | The `Plugin` / `VmHandle` / `CpuHandle` / `IoSink` contract, hook ordering, and the two rules that fail quietly. |
| [security.md](security.md) | The threat model, what confinement does and does not do, and the residual risks. |
| [limitations.md](limitations.md) | Every known limit in one place, with its consequence and whether it is a defect or a design choice. |

## Change it

| Page | What it covers |
| --- | --- |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Branches, commits, pull requests, and the gates to run before you push. |
| [testing.md](testing.md) | What runs where: the unit suite, the confinement selftests, the live boots, and the gaps. |
| [benchmarking.md](benchmarking.md) | The virtio-fs benchmarks, the performance gate, and how to compare two builds honestly. Tool usage is in [`tools/fsbench/README.md`](../tools/fsbench/README.md). |
| [../resources/seccomp/README.md](../resources/seccomp/README.md) | Changing a seccomp allowlist safely. |

## Reference tables

- [architecture.md](architecture.md#guest-memory-maps) has the guest memory
  map and interrupt numbers for both guest architectures.
- [cli.md](cli.md#flag-reference) has every flag with its default.
- [networking.md](networking.md#mode-comparison) compares the three
  networking modes.

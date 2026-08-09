---
name: Bug report
about: Report a defect or incorrect behavior
title: ''
labels: bug
assignees: ''
---

<!--
Write a specific, imperative title, e.g. "x86 guest hangs before mounting the
rootfs on the azure kernel". Search open and closed issues first to avoid
duplicates.
-->

## Describe the bug

<!-- A clear description of what is wrong. -->

## To reproduce

<!--
The exact steps. Include the full `hvi boot` command line and any relevant
flags (--kernel, --disk, --net, --cpus, --events).
-->

1.
2.

## Expected behavior

<!-- What you expected to happen. -->

## Actual behavior

<!-- What happened instead. Paste the error verbatim if there is one. -->

## Environment

<!-- Fill in what applies; delete the rest. -->

- Component / scope: <!-- machine, x86, virtio, boot, layout, ... -->
- Host backend: <!-- macOS/hvf | Linux/KVM aarch64 | Linux/KVM x86-64 -->
- Host OS and kernel: <!-- e.g. macOS 15, or Ubuntu 24.04 / 6.8.0 -->
- Guest kernel: <!-- arm64 Image or x86 bzImage, and version if relevant -->
- Commit / build: <!-- git rev-parse HEAD -->

## Logs and additional context

<!--
Relevant log output (fenced), and anything else that helps. The
HVI_X86_TRACE / HVI_BLK_TRACE env flags add detail.
Strip ANSI before pasting log lines. Link related issues inline with #NN.
-->

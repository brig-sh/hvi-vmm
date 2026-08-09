<!--
Title: use a conventional-commit subject, e.g. feat(x86): Add virtio-net gateway.
Example scopes: machine, x86, virtio, boot, layout, fdt, mptable,
uart, ci, docs.

Every commit in the pull request is linted too: 72-column header, capitalized
subject with no trailing period, body wrapped at 72, and a Signed-off-by
trailer. See CONTRIBUTING.md.
-->

## Summary

<!-- What this changes and why. Lead with the problem, then the approach. -->

## Related issues

<!-- Closes #NN, Refs #MM. Delete if none. -->

## Changes

<!-- The notable changes, one bullet each. -->

-

## Checklist

<!--
Check items as you complete them; strike through (~~like this~~) any that do
not apply, rather than deleting or rewording them. Keep the reasoning in
Summary or Changes, not here.

`tools/tidy.sh --check` is what the validate-code jobs run (fmt, comment
reflow, clippy, rustdoc); the live x86/KVM job (boot-x86) needs
a runner with /dev/kvm; the macOS jobs need macOS 15. See CONTRIBUTING.md.
-->

- [ ] `tools/tidy.sh` is clean (fmt, reflow, clippy, rustdoc)
- [ ] `cargo test` passes
- [ ] I have added or updated unit or integration tests covering the change
- [ ] For x86/KVM changes: the live boot ran on a /dev/kvm host (or CI)
- [ ] For macOS/hvf changes: it builds on macOS 15 and ad-hoc signs with the entitlement
- [ ] I have updated the affected docs (`README.md`, `docs/architecture.md`)

## LLM usage

<!--
For transparency: note any AI assistance used in this change, e.g.
"Authored with assistance from Claude Code; I have reviewed every line and am
accountable for the change."
-->

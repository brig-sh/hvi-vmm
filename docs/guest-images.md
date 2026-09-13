# Kernels and root filesystems

hvi boots an unmodified Linux kernel. It supplies no firmware and no
bootloader: it parses the kernel image itself, places it in guest RAM, and
enters it directly. A Unikraft unikernel boots the same way, because Unikraft
links its arm64 images with the same 64-byte Linux boot header.

That means the image format has to match the guest architecture exactly, and
the guest needs a root filesystem from somewhere.

## What image format

| Guest | Format | What hvi checks |
| --- | --- | --- |
| aarch64 | Uncompressed `Image` | The magic `0x644d5241` at offset 0x38, then `text_offset` and `image_size` from the 64-byte header. |
| x86-64 | `bzImage` | `0xAA55` at offset 0x1fe, `HdrS` at 0x202, a boot protocol of 2.00 or later and `LOADED_HIGH`, then the setup header. |
| x86-64 | Uncompressed `vmlinux` | The ELF magic at offset 0. Each segment loads at its physical address and the kernel is entered at `e_entry`. It skips the decompressor, so it boots without KASLR. |

A compressed `Image.gz` does not work on arm64. Decompress it first.

`hvi dump-fdt --kernel <Image>` parses the header and prints what it found
without needing a hypervisor, which is the quickest way to check an arm64
image is the right shape.

## Getting a kernel

### The one CI uses (arm64)

```sh
oras pull ghcr.io/nofireai/urunc-kernel:minimal -o target
```

That writes `target/Image`, a 6.12.95 arm64 kernel. The registry allows
anonymous pulls, so `curl` works too. See
[first-boot.md](first-boot.md#3-get-a-kernel).

### A distribution kernel (x86-64)

```sh
sudo apt-get install -y --no-install-recommends linux-image-virtual
ls /boot/vmlinuz-*
```

Debian and Ubuntu ship a `bzImage` at `/boot/vmlinuz-*`. Pass it directly. The
`vmlinux` from a kernel build tree also boots.

### Building your own

A guest kernel needs the drivers for the devices hvi presents. Build them in,
not as modules, unless your initramfs carries the modules and loads them.

```text
CONFIG_VIRTIO=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_BLK=y                 # --disk
CONFIG_VIRTIO_NET=y                 # --net, --net-gateway, --net-tap
CONFIG_VSOCKETS=y                   # --agent-sock
CONFIG_VIRTIO_VSOCKETS=y
CONFIG_FUSE_FS=y                    # --share-ro, --share-rw
CONFIG_VIRTIO_FS=y
CONFIG_BLK_DEV_INITRD=y             # --initramfs
```

Per architecture:

```text
# aarch64
CONFIG_SERIAL_AMBA_PL011=y
CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
CONFIG_ARM_PSCI_FW=y                # power off, and SMP bring-up
CONFIG_ARM_GIC_V3=y                 # or CONFIG_ARM_GIC for a GICv2 host
CONFIG_OF=y                         # hvi passes a devicetree

# x86-64
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_RTC_DRV_CMOS=y               # not optional, see below
CONFIG_X86_MPPARSE=y                # hvi supplies an MP table, not ACPI
```

hvi implements the CMOS real-time clock on x86-64 because a guest that reads
it cannot proceed without one. `read_persistent_clock64()` polls the
update-in-progress bit with interrupts disabled, and an unimplemented port
reads back `0xff`, so that bit never clears and the guest spins there forever,
before the console is up. hvi supplies the device, so this is a reason the
device exists rather than something you configure.

There is no PCI at all. A kernel that expects to find its devices on a PCI bus
finds nothing.

## Unikernel guests (Unikraft)

A Unikraft/arm64 image is an arm64 `Image` as far as the loader is concerned,
so `--kernel` takes it unchanged. Two build options are not optional, and
neither is discoverable from a failure -- both kill the guest before it has a
console to complain with.

**GICv3.** Apple's `hv_gic` is GICv3 only. The stock `qemu-arm64` defconfig
sets `CONFIG_LIBUKINTCTLR_GICV2=y` and leaves v3 off, because
`plat/kvm/Config.uk` has `KVM_VMM_QEMU imply GICV2`. The two drivers are
independent bools and `uk_intctlr_probe()` matches on the devicetree
`compatible`, so building both is fine and the image still boots under QEMU.

**No PCI.** hvi has no PCI bus and emits no PCI node. Unikraft's arm64 PCI
driver probes a hardcoded ECAM window anyway, and the data abort lands in
`arch_pci_probe` before the banner:

```text
CRIT: [libkvmplat] <traps_arm64.c @ 210> EL1 sync trap caught
CRIT: [libkvmplat] <traps_arm64.c @ 176>  FAR_EL1  : 0x0000000000008000
```

So, on top of a stock `defconfigs/qemu-arm64`:

```text
CONFIG_LIBUKINTCTLR_GICV3=y         # Apple's hv_gic is GICv3-only
# CONFIG_LIBVIRTIO_PCI is not set   # hvi is virtio-mmio only
# CONFIG_LIBUKBUS_PCI is not set
CONFIG_LWIP_DHCP=y                  # --net answers DHCP
```

Then:

```bash
hvi boot --kernel httpreply_qemu-arm64 --mem-mib 256 --net
```

There is one more constraint on the hvi side, and it is why the device windows
sit where they do. Unikraft/arm64 enables the MMU from a page table fixed at
link time, which maps exactly `0x0800_0000`-`0x4000_0000` as device memory.
Linux builds its early map from the devicetree and accepts MMIO anywhere;
Unikraft does not. Every hvi device window is inside that range, so this costs
a Linux guest nothing (see `DEVICE_WINDOW_BASE` in `src/layout.rs`).

## The kernel command line

The default is `earlycon console=ttyAMA0 panic=-1`, which names the arm64
console.

hvi appends what its own devices need, and only on x86-64:
`console=ttyS0`, plus one `virtio_mmio.device=<size>@<addr>:<irq>` for each
backed device, because that guest has no devicetree and no PCI bus to discover
them on. On arm64 the devicetree describes the devices, so nothing is
appended.

Because hvi appends `console=ttyS0` itself, an x86-64 guest gets console
output even with the default. The default's `console=ttyAMA0` is simply inert
there. Pass `--cmdline "console=ttyS0 panic=-1"` anyway, so the line says what
it means and `earlycon` is not left pointing at a console that does not exist.

The append is spliced in **before** a bare `--` separator, so arguments meant
for `init` stay with `init` rather than being read by the kernel.

`panic=-1` makes the guest reboot immediately on panic. hvi does not reboot a
guest, so the run stops instead. Without it, a panicking guest sits there
until you kill it.

## Root filesystems

A guest needs one of three things, or it panics at `Unable to mount root fs`.

### An initramfs

The simplest. `tools/mk-initramfs.py` transcodes an Alpine aarch64 minirootfs
tarball straight into a newc cpio archive in memory. It needs no root and no
`cpio` command, because macOS cannot create device nodes without root and the
cpio format carries them as metadata anyway.

```sh
tools/mk-initramfs.py --out target/initramfs.cpio
```

It injects an `/init` that mounts the pseudo-filesystems, configures `eth0`
for the built-in network stack when there is one, prints a banner and drops to
a shell. When the shell exits, it powers off through PSCI.

| Flag | Effect |
| --- | --- |
| `--out <path>` | Output, default `target/initramfs.cpio`. |
| `--alpine-version <v>` | Default 3.20.10. |
| `--cache <dir>` | Where the tarball is cached. Defaults beside `--out`. |
| `--keep-alive <secs>` | Replace the shell with a `HVI-INITRAMFS-UP` line, a sleep, and a power off. For an unattended run. |
| `--net-static ADDR/PLEN,GW` | Replace the `eth0` block with a static address, a default route and three pings of the gateway. For a tap boot. |

CI uses `--keep-alive`, because a shell on a console with no input blocks
forever.

**It builds an arm64 initramfs only.** For x86-64, supply your own.

### A disk image

```sh
hvi boot --kernel <bzImage> --disk rootfs.img \
         --cmdline "console=ttyS0 root=/dev/vda rw panic=-1"
```

The guest sees the disk as `/dev/vda`. One disk, no partition table required,
no hotplug.

### A virtio-fs share, on macOS

A share can carry a root filesystem, but the guest still needs an initramfs to
mount it, because the kernel cannot mount virtiofs as its own root without
help. Use a share for working data and an initramfs or a disk for root.

## Checking what the guest will be told, on arm64

`dump-fdt` runs the whole pre-boot pipeline and writes the devicetree hvi
would hand the kernel:

```sh
hvi dump-fdt --kernel target/Image --mem-mib 1024 --out target/fdt.dtb
dtc -I dtb -O dts target/fdt.dtb | head -40
```

`--initramfs`, `--mem-mib` and `--cmdline` all change the layout it describes,
so pass the same ones you would boot with.

It always builds a one-vCPU tree with no virtio devices, using the fixed QEMU
virt GIC layout. It shows you the placement arithmetic, not the device set a
real boot would describe.

## See also

- [first-boot.md](first-boot.md) for the whole sequence.
- [storage-and-sharing.md](storage-and-sharing.md) for disks and shares.
- [cli.md](cli.md) for the flags.

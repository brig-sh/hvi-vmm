// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The arm64 guest on KVM, SMP-capable.
//!
//! The Linux counterpart of `hvf`. KVM runs the GIC and PSCI in the kernel.
//! Secondaries are created powered off, and the guest brings them up with PSCI
//! `CPU_ON`, which the kernel serves. A device sets its interrupt line with
//! `KVM_IRQ_LINE`, which also wakes a vCPU in WFI. A kick sets the vCPU's
//! `immediate_exit` byte and signals its thread, as `hypervisor::kvm`
//! describes.
//!
//! The image and layout, the DTB, the virtio devices, the PL011, the `RawEvent`
//! ledger and the plugin interface are the same code the macOS backend uses.
//!
//! KVM's vGIC uses the host's CPU interface, so a GICv3 host serves vGICv3 and
//! a GIC-400 host serves only vGICv2. The backend asks for v3, falls back to
//! v2, and lays out the DTB to match.
//!
//! The portable profile (`--profile portable-arm64-v1`, see
//! `docs/portable-profile.md`) gives the guest the machine a Mac gives it:
//! a vGICv2, the profile's CPU baseline written with `KVM_SET_ONE_REG` and
//! read back, the firmware bitmaps lowered so PSCI and SMCCC answer as the
//! Mac's hvi does, and [`crate::devices::hvitime`] for the clock: its page
//! is a read-only memory slot, its timer window is served here, and its
//! timer thread raises PPI 20 with `KVM_IRQ_LINE`. The counter offset is
//! set with `KVM_ARM_SET_COUNTER_OFFSET`, so hvi knows the guest's counter
//! exactly: the host's `CNTVCT_EL0` less that offset.
// The host-path ban in clippy.toml is aimed at the virtio-fs device, where
// every component of a path comes from the guest. The paths here are this
// VMM's own.
#![allow(clippy::disallowed_methods)]

use std::ops::ControlFlow;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    kvm_arm_counter_offset, kvm_create_device, kvm_device_attr,
    kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
    kvm_userspace_memory_region, kvm_vcpu_init, KVM_ARM_IRQ_TYPE_PPI, KVM_ARM_IRQ_TYPE_SHIFT,
    KVM_ARM_IRQ_TYPE_SPI, KVM_ARM_IRQ_VCPU_SHIFT, KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2,
    KVM_ARM_VCPU_PTRAUTH_ADDRESS, KVM_ARM_VCPU_PTRAUTH_GENERIC, KVM_DEV_ARM_VGIC_CPUID_SHIFT,
    KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CPU_REGS,
    KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
    KVM_MEM_READONLY, KVM_VGIC_V2_ADDR_TYPE_CPU, KVM_VGIC_V2_ADDR_TYPE_DIST,
    KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST,
};
use kvm_ioctls::{Cap, DeviceFd, Kvm, VcpuExit, VcpuFd, VmFd};

use crate::arch::aarch64::fdt;
use crate::arch::aarch64::kvm_state;
use crate::arch::aarch64::layout::{
    GicLayout, GicVersion, HVI_TIME_PAGE_BASE, HVI_TIME_TIMERS_BASE, RAM_BASE, UART_BASE,
    UART_SIZE, UART_SPI, VIRTIO_BASE, VIRTIO_NET_BASE, VIRTIO_NET_SPI, VIRTIO_SIZE, VIRTIO_SPI,
    VIRTIO_VSOCK_BASE, VIRTIO_VSOCK_SPI,
};
use crate::arch::aarch64::loader;
use crate::arch::aarch64::portable::{self, KvmHost};
use crate::arch::aarch64::profile::{self as arm64_profile, Arm64Machine};
use crate::arch::aarch64::rebuild;
use crate::arch::aarch64::vgicv2::{self, Bank, Lines, VgicV2};
use crate::checkpoint::capture::Console;
use crate::checkpoint::cpu::Power;
use crate::checkpoint::cpu::{Output, VcpuState, Work};
use crate::checkpoint::platform::{IrqState, PlatformState, TimerState, PLATFORM_STATE_VERSION};
use crate::checkpoint::profile::{hex, host_page_size, MachineProfile, ProfileCell, UNKNOWN};
use crate::checkpoint::restore::{self, Refused, Restorer};
use crate::config::{BootConfig, MachineProfileKind, RestoreConfig, Stop};
use crate::devices::hvitime::{self, trace, GuestCounter, HviTime, PendingPublish, TimerLine};
use crate::devices::legacy::pl011::Pl011;
use crate::devices::virtio::block::VirtioBlk;
use crate::devices::virtio::net::{self, VirtioNet};
use crate::devices::virtio::tap;
use crate::devices::virtio::vsock::VirtioVsock;
use crate::events::Emitter;
use crate::hypervisor::guest::{Guest, PluginThreads, SafepointVcpu};
use crate::hypervisor::kvm::{
    kick_handle, run_guest, run_vcpu, start_io_threads, unhandled_exit, IoConfig, Kicker,
    KvmIrqLine,
};
use crate::hypervisor::kvm_dirty::KvmWriteLog;
use crate::hypervisor::vcpus::{Outcome, Vcpus};
use crate::io_threads::{IoThreads, NetSource};
use crate::memory::{GuestRam, GuestWriteLog, SharedRam};
use crate::plugin::{GuestArch, Plugin, RegsView};
use crate::run::StopHandle;
use crate::sandbox::seccomp;
use crate::signal::install_kick_handler;
use crate::sync::lock_or_recover;
use crate::teardown::STOP_TIMEOUT;
use crate::LOG_PREFIX;

// --- ONE_REG ids (architectural KVM ABI, aarch64). ---------------
// Core regs: KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE |
// (byte_off/4).
const REG_X0: u64 = 0x6030_0000_0010_0000;
const REG_PC: u64 = 0x6030_0000_0010_0040;
const REG_PSTATE: u64 = 0x6030_0000_0010_0042;
const REG_SP_EL1: u64 = 0x6030_0000_0010_0044;
// System regs: KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG | enc.
const REG_SCTLR_EL1: u64 = 0x6030_0000_0013_c080;
const REG_TTBR0_EL1: u64 = 0x6030_0000_0013_c100;
const REG_TTBR1_EL1: u64 = 0x6030_0000_0013_c101;
const REG_TCR_EL1: u64 = 0x6030_0000_0013_c102;
// SP_EL0 is a core register (user_pt_regs.sp), not a sysreg: Linux keeps
// `current` there while running in the kernel.
const REG_SP_EL0: u64 = 0x6030_0000_0010_003e;

/// PSTATE = EL1h + DAIF masked (the arm64 Linux boot-protocol entry state).
const PSTATE_EL1H_DAIF: u64 = 0x3c5;

/// KVM GSI for SPI `spi` (our layout SPI number; INTID = 32 + spi).
fn spi_gsi(spi: u32) -> u32 {
    const KVM_ARM_IRQ_TYPE_SPI: u32 = 1;
    const KVM_ARM_IRQ_TYPE_SHIFT: u32 = 24;
    (KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) | (32 + spi)
}

fn set_u64(vcpu: &VcpuFd, id: u64, val: u64) {
    let _ = vcpu.set_one_reg(id, &val.to_le_bytes());
}
fn get_u64(vcpu: &VcpuFd, id: u64) -> u64 {
    let mut b = [0u8; 8];
    vcpu.get_one_reg(id, &mut b)
        .map(|_| u64::from_le_bytes(b))
        .unwrap_or(0)
}

/// Returns the `KVM_GET_ONE_REG` id of the 64-bit system register with
/// encoding `op0, op1, CRn, CRm, op2`, as the kernel's `ARM64_SYS_REG` builds
/// it. bindgen does not expand that macro, so it is spelled out here.
const fn sys_reg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    0x6030_0000_0013_0000 | (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}

/// `MIDR_EL1`, the CPU's identity.
const REG_MIDR_EL1: u64 = sys_reg(3, 0, 0, 0, 0);

/// The PSCI version firmware register, `KVM_REG_ARM_FW_REG(0)`.
const REG_PSCI_VERSION: u64 = 0x6030_0000_0014_0000;

/// The firmware feature bitmaps, `KVM_REG_ARM_FW_FEAT_BMAP_REG(0..=2)`:
/// the standard services (TRNG), the standard hypervisor services
/// (PV_TIME) and the vendor hypervisor services (PTP). The portable profile
/// lowers all three to 0, as the Mac's firmware offers none of them.
const FW_FEATURE_BITMAPS: [(&str, u64); 3] = [
    ("KVM_REG_ARM_STD_BMAP", 0x6030_0000_0016_0000),
    ("KVM_REG_ARM_STD_HYP_BMAP", 0x6030_0000_0016_0001),
    ("KVM_REG_ARM_VENDOR_HYP_BMAP", 0x6030_0000_0016_0002),
];

/// `MPIDR_EL1`, which KVM sets from the vCPU index and the portable profile
/// checks.
const REG_MPIDR_EL1: u64 = sys_reg(3, 0, 0, 0, 5);

/// `ID_AA64ISAR2_EL1`, which the baseline holds at 0 and which KVM, unlike
/// Hypervisor.framework, can write.
const REG_ID_AA64ISAR2_EL1: u64 = sys_reg(3, 0, 0, 6, 2);

/// The guest's virtual counter, `KVM_REG_ARM_TIMER_CNT`. Its UAPI id is
/// the swapped encoding (3, 3, 14, 3, 2) that `asm/kvm.h` documents.
const REG_TIMER_CNT: u64 = 0x6030_0000_0013_df1a;

/// The portable baseline's registers, in [`portable::BASELINE`]'s order.
const BASELINE_REGS: [u64; 12] = [
    sys_reg(3, 0, 0, 0, 0), // MIDR_EL1
    sys_reg(3, 0, 0, 4, 0), // ID_AA64PFR0_EL1
    sys_reg(3, 0, 0, 4, 1), // ID_AA64PFR1_EL1
    sys_reg(3, 0, 0, 4, 4), // ID_AA64ZFR0_EL1
    sys_reg(3, 0, 0, 4, 5), // ID_AA64SMFR0_EL1
    sys_reg(3, 0, 0, 6, 0), // ID_AA64ISAR0_EL1
    sys_reg(3, 0, 0, 6, 1), // ID_AA64ISAR1_EL1
    sys_reg(3, 0, 0, 7, 0), // ID_AA64MMFR0_EL1
    sys_reg(3, 0, 0, 7, 1), // ID_AA64MMFR1_EL1
    sys_reg(3, 0, 0, 7, 2), // ID_AA64MMFR2_EL1
    sys_reg(3, 0, 0, 5, 0), // ID_AA64DFR0_EL1
    sys_reg(3, 0, 0, 5, 1), // ID_AA64DFR1_EL1
];

/// `KVM_ARM_SET_COUNTER_OFFSET`, `_IOW(KVMIO, 0xb5, struct
/// kvm_arm_counter_offset)`, 0x4010aeb5: the struct is two `u64`s.
/// kvm-ioctls has no wrapper. Built with `libc::_IOW`, so the request has
/// the type `ioctl` takes on glibc and on musl alike.
const KVM_ARM_SET_COUNTER_OFFSET: libc::Ioctl = libc::_IOW::<[u64; 2]>(0xae, 0xb5);

/// `KVM_ARM_GET_REG_WRITABLE_MASKS`, `_IOR(KVMIO, 0xb6, struct
/// reg_mask_range)`, 0x8040aeb6: the struct is 64 bytes.
const KVM_ARM_GET_REG_WRITABLE_MASKS: libc::Ioctl = libc::_IOR::<[u64; 8]>(0xae, 0xb6);

/// `KVM_CAP_ARM_SUPPORTED_REG_MASK_RANGES`: a bitmap of the ranges
/// `KVM_ARM_GET_REG_WRITABLE_MASKS` reports; bit 0 is the feature ID range.
const KVM_CAP_ARM_SUPPORTED_REG_MASK_RANGES: libc::c_ulong = 230;

/// `struct reg_mask_range` of `asm/kvm.h`.
#[repr(C)]
struct RegMaskRange {
    addr: u64,
    range: u32,
    reserved: [u32; 13],
}

/// The number of registers in the feature ID range: op0 3, op1 0-7 folded
/// into 3 slots, CRn 0, CRm 0-7, op2 0-7.
const FEATURE_ID_RANGE_SIZE: usize = 3 * 8 * 8;

/// The index of ID register `(3, op1, 0, crm, op2)` in the feature ID range,
/// as `KVM_ARM_FEATURE_ID_RANGE_IDX` computes it.
const fn feature_id_index(op1: u64, crm: u64, op2: u64) -> usize {
    let mut op1 = op1 & 3;
    if op1 == 3 {
        op1 -= 1;
    }
    ((op1 << 6) | ((crm & 7) << 3) | op2) as usize
}

/// The ID registers the profile records, by the name it records them under.
/// The guest reads these values, and KVM serves the host's unless told
/// otherwise, so two hosts must agree on each.
const ID_REGS: [(&str, u64); 13] = [
    ("ID_AA64DFR0_EL1", sys_reg(3, 0, 0, 5, 0)),
    ("ID_AA64DFR1_EL1", sys_reg(3, 0, 0, 5, 1)),
    ("ID_AA64ISAR0_EL1", sys_reg(3, 0, 0, 6, 0)),
    ("ID_AA64ISAR1_EL1", sys_reg(3, 0, 0, 6, 1)),
    ("ID_AA64ISAR2_EL1", sys_reg(3, 0, 0, 6, 2)),
    ("ID_AA64MMFR0_EL1", sys_reg(3, 0, 0, 7, 0)),
    ("ID_AA64MMFR1_EL1", sys_reg(3, 0, 0, 7, 1)),
    ("ID_AA64MMFR2_EL1", sys_reg(3, 0, 0, 7, 2)),
    ("ID_AA64PFR0_EL1", sys_reg(3, 0, 0, 4, 0)),
    ("ID_AA64PFR1_EL1", sys_reg(3, 0, 0, 4, 1)),
    ("CTR_EL0", sys_reg(3, 3, 0, 0, 1)),
    ("CLIDR_EL1", sys_reg(3, 1, 0, 0, 1)),
    ("DCZID_EL0", sys_reg(3, 3, 0, 0, 7)),
];

/// Returns the 64-bit register `id` of `vcpu`, or `None` when KVM does not
/// serve it.
fn read_u64(vcpu: &VcpuFd, id: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    vcpu.get_one_reg(id, &mut b).ok()?;
    Some(u64::from_le_bytes(b))
}

/// Returns `DCZID_EL0` as this thread reads it.
///
/// Older kernels do not serve it through `KVM_GET_ONE_REG`. The guest reads
/// the hardware's value, since KVM does not trap it, and EL0 may read it too:
/// the block size is the hardware's, and Linux lets userspace and KVM lets a
/// guest kernel use `DC ZVA`, so the prohibit bit is clear for both.
fn host_dczid_el0() -> u64 {
    let value: u64;
    // SAFETY: reads a system register EL0 may read; no memory is touched.
    unsafe {
        std::arch::asm!("mrs {}, dczid_el0", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Returns the machine profile of this boot, read from the boot vCPU.
fn boot_profile(cfg: &BootConfig, machine: &Arm64Machine<'_>, boot: &VcpuFd) -> MachineProfile {
    let mut p = arm64_profile::profile("kvm", machine);
    p.cpu.ident = read_u64(boot, REG_MIDR_EL1).map(hex);
    for (name, id) in ID_REGS {
        let value = match read_u64(boot, id) {
            Some(value) => Some(value),
            None if name == "DCZID_EL0" => Some(host_dczid_el0()),
            None => None,
        };
        // A register KVM does not serve is recorded as unread, which the
        // compatibility check refuses on either side.
        let value = value.map_or_else(|| UNKNOWN.to_string(), hex);
        p.cpu.id_regs.insert(name.to_string(), value);
    }
    p.firmware.psci_version =
        read_u64(boot, REG_PSCI_VERSION).map(|v| format!("{}.{}", v >> 16, v & 0xffff));
    p.agent_sock = cfg.agent_sock.is_some();
    p.disk_base_sha256.clone_from(&cfg.disk_base_sha256);
    p
}

/// State shared across the vCPU threads.
#[derive(Clone)]
struct Shared {
    /// The guest's RAM, virtio devices and vCPUs.
    guest: Arc<Guest<Kicker>>,
    pl011: Arc<Mutex<Pl011>>,
    /// Whoever is watching this guest, if anyone.
    plugin: Option<Arc<dyn Plugin>>,
    /// The portable guest's `hvi-time`, or `None` on the native machine.
    hvitime: Option<Arc<HviTime>>,
    /// The VM, for the vGIC's lines.
    vm: Arc<VmFd>,
    /// The in-kernel vGIC, whose state a portable checkpoint reads.
    gic: Arc<DeviceFd>,
    /// The `hvi-time` state a restore publishes at the guest's resume,
    /// when this VM is one.
    restoring: Option<Arc<PendingPublish>>,
}

/// The portable guest's counter: the host's virtual counter less the VM's
/// counter offset, which hvi set.
///
/// On a VHE host, and on any host while no guest runs on the reading CPU,
/// `CNTVCT_EL0` at EL0 is the physical counter, and KVM gives the guest the
/// physical counter less the offset, so the two agree to the tick. The boot
/// checks that against `KVM_REG_ARM_TIMER_CNT` once.
struct KvmCounter {
    offset: u64,
}

impl GuestCounter for KvmCounter {
    fn now(&self) -> u64 {
        host_counter().wrapping_sub(self.offset)
    }
}

/// Returns the host's `CNTVCT_EL0`.
fn host_counter() -> u64 {
    let cnt: u64;
    // SAFETY: an EL0-readable system register; `isb` orders the read after
    // what came before it, as the guest driver's read is ordered.
    unsafe {
        std::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) cnt, options(nomem, nostack, preserves_flags));
    }
    cnt
}

/// Returns the host's `DCZID_EL0`, which KVM gives the guest as it is.
fn host_dczid() -> u64 {
    let v: u64;
    // SAFETY: an EL0-readable system register.
    unsafe {
        std::arch::asm!("mrs {}, dczid_el0", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// The `hvi-time` lines: PPI 20 of each vCPU, through `KVM_IRQ_LINE`. The
/// in-kernel vGIC wakes a vCPU in WFI itself, so nothing is left to wake.
struct KvmTimerLine {
    vm: Arc<VmFd>,
}

impl TimerLine for KvmTimerLine {
    fn set(&self, cpu: usize, level: bool) -> u8 {
        let irq = (KVM_ARM_IRQ_TYPE_PPI << KVM_ARM_IRQ_TYPE_SHIFT)
            | ((cpu as u32) << KVM_ARM_IRQ_VCPU_SHIFT)
            | hvitime::INTID;
        if let Err(e) = self.vm.set_irq_line(irq, level) {
            eprintln!(
                "{LOG_PREFIX} hvi-time: KVM_IRQ_LINE cpu{cpu} PPI {} -> {level}: {e}",
                hvitime::INTID
            );
        }
        0
    }
}

/// A vGICv2 as [`vgicv2`] reaches it: its register views through the
/// device's attributes, and its lines through `KVM_IRQ_LINE`.
struct KvmVgic<'a> {
    gic: &'a DeviceFd,
    vm: &'a VmFd,
    ncpu: usize,
}

impl KvmVgic<'_> {
    /// The attribute of register `offset` of `bank` as vCPU `cpu` sees it,
    /// moving the 32 bits at `addr`.
    fn attr(bank: Bank, cpu: usize, offset: u64, addr: u64) -> kvm_device_attr {
        kvm_device_attr {
            flags: 0,
            group: match bank {
                Bank::Dist => KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
                Bank::Cpu => KVM_DEV_ARM_VGIC_GRP_CPU_REGS,
            },
            attr: ((cpu as u64) << KVM_DEV_ARM_VGIC_CPUID_SHIFT) | offset,
            addr,
        }
    }
}

impl VgicV2 for KvmVgic<'_> {
    fn ncpu(&self) -> usize {
        self.ncpu
    }

    fn read(&self, bank: Bank, cpu: usize, offset: u64) -> Result<u32, String> {
        let mut value = 0u32;
        let mut attr = Self::attr(bank, cpu, offset, std::ptr::addr_of_mut!(value) as u64);
        // SAFETY: `addr` is `value`, a u32 that outlives the call, and a
        // vGICv2 register access moves 32 bits.
        unsafe { self.gic.get_device_attr(&mut attr) }.map_err(|e| e.to_string())?;
        Ok(value)
    }

    fn write(&self, bank: Bank, cpu: usize, offset: u64, value: u32) -> Result<(), String> {
        let attr = Self::attr(bank, cpu, offset, std::ptr::addr_of!(value) as u64);
        self.gic.set_device_attr(&attr).map_err(|e| e.to_string())
    }

    fn set_line(&self, cpu: usize, intid: u32, level: bool) -> Result<(), String> {
        let irq = if intid >= 32 {
            (KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) | intid
        } else {
            (KVM_ARM_IRQ_TYPE_PPI << KVM_ARM_IRQ_TYPE_SHIFT)
                | ((cpu as u32) << KVM_ARM_IRQ_VCPU_SHIFT)
                | intid
        };
        self.vm.set_irq_line(irq, level).map_err(|e| e.to_string())
    }
}

/// The line levels hvi's devices hold, which KVM's vGICv2 view cannot
/// give back.
fn device_lines(sh: &Shared, ncpu: usize) -> Lines {
    let mut spis = vec![0u32; crate::devices::gicv2::WORDS];
    let mut set = |spi: u32, high: bool| {
        let intid = 32 + spi as usize;
        if high {
            spis[intid / 32] |= 1 << (intid % 32);
        }
    };
    set(UART_SPI, lock_or_recover(&sh.pl011).irq_level());
    if let Some(d) = &sh.guest.block {
        set(VIRTIO_SPI, lock_or_recover(d).irq_level());
    }
    if let Some(d) = &sh.guest.net {
        set(VIRTIO_NET_SPI, lock_or_recover(d).irq_level());
    }
    if let Some(d) = &sh.guest.vsock {
        set(VIRTIO_VSOCK_SPI, lock_or_recover(d).irq_level());
    }
    let mut ppis = vec![0u32; ncpu];
    if let Some(device) = &sh.hvitime {
        // A restored guest that has not run since: its lines are the
        // restored state's, which the device gets only at the resume.
        let lines = match sh
            .restoring
            .as_deref()
            .and_then(PendingPublish::unpublished)
        {
            Some(state) => state.lines(),
            None => device.lines(),
        };
        for (cpu, high) in lines.into_iter().enumerate().take(ncpu) {
            if high {
                ppis[cpu] |= vgicv2::OWNED_PPIS;
            }
        }
    }
    Lines { spis, ppis }
}

/// Exports the vGIC of a held guest, imports the export back, and exports
/// again, for `HVI_TIME_TEST_RESTORE`: the capture and restore a
/// checkpoint will make, on the live guest's interrupt state.
fn vgic_round_trip(gic: &DeviceFd, vm: &VmFd, ncpu: usize, sh: &Shared) {
    let vgic = KvmVgic { gic, vm, ncpu };
    let lines = device_lines(sh, ncpu);
    let result = vgicv2::export(&vgic, &lines).and_then(|state| {
        let checked = vgicv2::import(&vgic, &state)?;
        let again = vgicv2::export(&vgic, &lines)?;
        if again != state {
            return Err(format!(
                "the second export differs from the first: {again:?} against {state:?}"
            ));
        }
        let active: u32 = state
            .cpus
            .iter()
            .map(|c| c.isactiver0.count_ones())
            .sum::<u32>()
            + state
                .dist
                .isactiver
                .iter()
                .map(|w| w.count_ones())
                .sum::<u32>();
        let pending: u32 = state
            .cpus
            .iter()
            .map(|c| c.latch0.count_ones())
            .sum::<u32>()
            + state.dist.latch.iter().map(|w| w.count_ones()).sum::<u32>();
        Ok(format!(
            "{checked} registers read back as written; {active} active, {pending} latched, \
             GICC_APR0 {:x?}, PPI 20 lines {:x?}",
            state.cpus.iter().map(|c| c.apr[0]).collect::<Vec<_>>(),
            lines.ppis
        ))
    });
    match result {
        Ok(summary) => eprintln!("{LOG_PREFIX} vGICv2 round trip while held: {summary}"),
        Err(e) => eprintln!("{LOG_PREFIX} vGICv2 round trip while held FAILED: {e}"),
    }
}

/// Boots `cfg` on KVM (arm64), as [`crate::boot`] describes.
pub(crate) fn boot(mut cfg: BootConfig) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    cfg.validate()?;
    let is_portable = cfg.profile == MachineProfileKind::PortableArm64V1;
    if !cfg.fs_shares.is_empty() {
        return Err(
            "--share-ro/--share-rw are currently implemented by the macOS HVI backend only".into(),
        );
    }
    install_kick_handler();
    // Refuse a kernel that is not a flat Image before the VM, its RAM, the
    // devices and the event ledger exist.
    loader::LoadedKernel::from_header(&cfg.kernel)?;

    let num_cpus = cfg.vcpus.max(1);

    let kvm = Kvm::new()?;
    // A kick relies on `kvm_run.immediate_exit`. Without it, one that lands
    // just before `KVM_RUN` is lost, and a stop with it.
    if !kvm.check_extension(Cap::ImmediateExit) {
        return Err("hvi needs KVM_CAP_IMMEDIATE_EXIT, which Linux 4.11 added".into());
    }
    if is_portable && !kvm.check_extension(Cap::ReadonlyMem) {
        return Err(
            "--profile portable-arm64-v1 needs KVM_CAP_READONLY_MEM for the hvi-time page".into(),
        );
    }
    let vm = Arc::new(kvm.create_vm()?);

    // The guest GIC has to be created before the DTB is built, because which
    // version we get decides what the DTB must describe — and we do not get to
    // choose. KVM's vGIC borrows the host's CPU interface, so a GICv3 host
    // serves vGICv3 while a GIC-400 host (Raspberry Pi 5 and most Cortex-A72/
    // A76 SoCs) serves vGICv2 only. Ask for v3 and fall back on failure: a
    // rejected KVM_CREATE_DEVICE creates nothing, so this costs one ioctl.
    // The portable profile's GIC is a GICv2 on every host, so it asks for v2
    // alone and refuses a host that cannot give one.
    //
    // Deliberately *not* KVM_CREATE_DEVICE_TEST: with that flag the kernel
    // leaves `fd` at 0, and kvm-ioctls would wrap descriptor 0 in a `DeviceFd`
    // that closes stdin when dropped.
    let create_v2 = || {
        vm.create_device(&mut kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
            fd: 0,
            flags: 0,
        })
    };
    let (gicfd, version) = if is_portable {
        match create_v2() {
            Ok(fd) => (fd, GicVersion::V2),
            Err(e) => {
                return Err(format!(
                    "--profile portable-arm64-v1 needs a vGICv2, and KVM offers none on this \
                     host ({e}): a GICv3-only host serves vGICv3 alone, which the portable \
                     machine does not use yet"
                )
                .into())
            }
        }
    } else {
        match vm.create_device(&mut kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        }) {
            Ok(fd) => (fd, GicVersion::V3),
            Err(e) => {
                eprintln!("{LOG_PREFIX} vGICv3 unavailable ({e}); falling back to vGICv2");
                (create_v2()?, GicVersion::V2)
            }
        }
    };

    // Placement (QEMU virt values; the DTB and KVM must agree). Sizing and the
    // v2 vCPU cap both live in `for_vcpus`, so they are unit-testable on a host
    // with no KVM at all.
    let gic = GicLayout::for_vcpus(version, num_cpus)?;
    eprintln!(
        "{LOG_PREFIX} {num_cpus} vCPU(s)  {:?}  GICD {:#x}+{:#x}  {} {:#x}+{:#x}{}",
        version,
        gic.gicd_base,
        gic.gicd_size,
        match version {
            GicVersion::V3 => "GICR",
            GicVersion::V2 => "GICC",
        },
        gic.gicr_base,
        gic.gicr_size,
        if is_portable {
            format!("  profile {}", cfg.profile.name())
        } else {
            String::new()
        }
    );

    // Guest RAM: one region at RAM_BASE, backed by a shareable object (a
    // memfd) so an out-of-process plugin can map the same pages. KVM only
    // needs a valid host address, so the guest is unaffected.
    let shared_ram = SharedRam::new(cfg.mem_bytes as usize)?;
    let ram = Arc::new(GuestRam::new(
        &shared_ram,
        &[shared_ram.region_at(RAM_BASE)],
    )?);
    ram.register_kvm_slots(&vm)?;

    // Devices (same modules as the macOS backend).
    let virtio = match &cfg.disk {
        Some(path) => {
            eprintln!("{LOG_PREFIX} virtio-blk: {path}");
            Some(Arc::new(Mutex::new(VirtioBlk::open_with_base(
                path,
                cfg.disk_base_sha256.is_some(),
                cfg.disk_written.as_deref(),
            )?)))
        }
        None => None,
    };
    let mut net_source: Option<NetSource> = None;
    let net_dev = if let Some(ifname) = &cfg.net_tap {
        // urunc already created the tap and redirected the veth to it, so all
        // that is left is to attach -- that is what brings carrier up. An
        // unusable tap fails the boot: falling back to the built-in stack
        // would put the guest on the wrong network, which from the outside is
        // indistinguishable from success.
        let file = tap::open(ifname).map_err(|e| format!("--net-tap {ifname}: {e}"))?;
        let reader = file
            .try_clone()
            .map_err(|e| format!("--net-tap {ifname}: cloning the tap fd: {e}"))?;
        eprintln!("{LOG_PREFIX} virtio-net: tap {ifname}");
        net_source = Some(NetSource::Tap(reader));
        Some(VirtioNet::with_tap(file))
    } else if let Some(sock) = &cfg.net_gateway {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(stream) => match stream.try_clone() {
                Ok(reader) => {
                    eprintln!("{LOG_PREFIX} virtio-net: gvisor-tap gateway relay via {sock}");
                    net_source = Some(NetSource::Gateway(reader));
                    Some(VirtioNet::with_gateway(stream))
                }
                Err(e) => {
                    eprintln!(
                        "{LOG_PREFIX} WARNING: cannot clone gateway socket ({e}); net disabled"
                    );
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "{LOG_PREFIX} WARNING: gateway {sock} unreachable ({e}); falling back to the {}",
                    net::stub_stack_line()
                );
                Some(VirtioNet::new())
            }
        }
    } else if cfg.net {
        eprintln!("{LOG_PREFIX} virtio-net: {}", net::stub_stack_line());
        Some(VirtioNet::new())
    } else {
        None
    };

    let net = net::share(net_dev, cfg.net_mac);

    let vsock = cfg
        .agent_sock
        .as_ref()
        .map(|_| Arc::new(Mutex::new(VirtioVsock::new())));
    let has_blk = virtio.is_some();
    let has_net = net.is_some();
    let has_vsock = vsock.is_some();
    // The portable guest's devicetree comes from the same inputs on every
    // backend; see `portable::devicetree`.
    let (cmdline, fdt_devices) = if is_portable {
        let dt = portable::devicetree(&cfg, num_cpus, has_blk, has_net, has_vsock)?;
        debug_assert_eq!(dt.gic.gicr_base, gic.gicr_base);
        (dt.cmdline, dt.devices)
    } else {
        let devices = fdt::VirtioDevices {
            blk: has_blk,
            net: has_net,
            vsock: has_vsock,
            fs_count: 0,
            timer: fdt::ArchTimer::Interrupts,
            hvi_time: false,
        };
        (cfg.cmdline.clone(), devices)
    };

    let emitter = Emitter::new(cfg.events.as_deref(), &cfg.sandbox_id)?;
    let layout = loader::Payload {
        kernel: &cfg.kernel,
        initramfs: cfg.initramfs.as_deref(),
        cmdline: &cmdline,
    }
    .load(ram.memory(), cfg.mem_bytes, &gic, num_cpus, fdt_devices)?;

    // Place the GIC regions (the device itself was created above, before the
    // DTB). The address-type constants differ per version, and v2 takes a CPU
    // interface where v3 takes a redistributor. NR_IRQS + INIT follow the
    // vCPUs.
    match version {
        GicVersion::V3 => {
            set_gic_addr(&gicfd, KVM_VGIC_V3_ADDR_TYPE_DIST, gic.gicd_base)?;
            set_gic_addr(&gicfd, KVM_VGIC_V3_ADDR_TYPE_REDIST, gic.gicr_base)?;
        }
        GicVersion::V2 => {
            set_gic_addr(&gicfd, KVM_VGIC_V2_ADDR_TYPE_DIST, gic.gicd_base)?;
            set_gic_addr(&gicfd, KVM_VGIC_V2_ADDR_TYPE_CPU, gic.gicr_base)?;
        }
    }

    // Create + init all vCPUs. Secondaries start powered off; the guest's PSCI
    // CPU_ON (in-kernel) wakes them.
    let mut kvi = kvm_vcpu_init::default();
    vm.get_preferred_target(&mut kvi)?;
    kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
    // KVM hides pointer authentication from the guest unless asked for it, and
    // refuses a request for one of its two kinds without the other. The
    // portable baseline has none, and KVM fixes the ID_AA64ISAR1_EL1 fields of
    // a vCPU that has it, so a portable vCPU does not ask.
    if !is_portable
        && vm.check_extension(Cap::ArmPtrAuthAddress)
        && vm.check_extension(Cap::ArmPtrAuthGeneric)
    {
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS | 1 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
    }
    let mut vcpus = Vec::with_capacity(num_cpus as usize);
    let mut kick_handles = Vec::with_capacity(num_cpus as usize);
    for id in 0..num_cpus {
        let vcpu = vm.create_vcpu(u64::from(id))?;
        let mut kvi_cpu = kvi;
        if id != 0 {
            kvi_cpu.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
        }
        vcpu.vcpu_init(&kvi_cpu)?;
        kick_handles.push(kick_handle(&vm, &vcpu)?);
        vcpus.push(vcpu);
    }

    // The portable machine, before any vCPU runs: KVM takes ID registers,
    // firmware registers and the counter offset only until then.
    let hvitime = if is_portable {
        let host = kvm_host(&kvm, &vm, &vcpus[0]);
        let problems = portable::kvm_host_problems(&host);
        if !problems.is_empty() {
            return Err(format!(
                "this host cannot present --profile portable-arm64-v1: {}",
                problems.join("; ")
            )
            .into());
        }
        // Without the masks the readback below is the only check that a
        // lowered field took, so the log says which one ran.
        eprintln!(
            "{LOG_PREFIX} portable-arm64-v1 host check: vGICv2, {}-byte pages, {}-bit IPA, {} ID registers read, writable masks {}",
            host.page_size,
            host.ipa_bits,
            host.id_regs.len(),
            match &host.writable {
                Some(masks) => format!("reported for {} registers", masks.len()),
                None => "not reported".to_string(),
            }
        );
        set_baseline(&vcpus)?;
        let offset = set_counter_offset(&kvm, &vm, &vcpus[0], 0)?;
        let device = Arc::new(HviTime::new(
            num_cpus as usize,
            crate::checkpoint::profile::counter_freq_hz(),
            Box::new(KvmCounter { offset }),
            Box::new(KvmTimerLine {
                vm: Arc::clone(&vm),
            }),
        )?);
        // The page is a read-only slot: the guest reads it without an exit,
        // and a write exits as MMIO, which is dropped.
        let slot = kvm_userspace_memory_region {
            slot: u32::try_from(ram.regions().len()).unwrap_or(u32::MAX),
            flags: KVM_MEM_READONLY,
            guest_phys_addr: HVI_TIME_PAGE_BASE,
            memory_size: hvitime::PAGE_SIZE,
            userspace_addr: device.page().host_ptr() as u64,
        };
        // SAFETY: the page is a live mapping of `PAGE_SIZE` bytes that lives
        // as long as `device`, which outlives the VM.
        unsafe { vm.set_user_memory_region(slot) }
            .map_err(|e| format!("the hvi-time page's read-only memory slot: {e}"))?;
        eprintln!(
            "{LOG_PREFIX} hvi-time: page {HVI_TIME_PAGE_BASE:#x}+{:#x} (read-only slot), timers {HVI_TIME_TIMERS_BASE:#x}+{:#x}, PPI {} (INTID {}), counter {} Hz, counter offset {offset:#x}",
            hvitime::PAGE_SIZE,
            hvitime::TIMERS_SIZE,
            hvitime::PPI,
            hvitime::INTID,
            device.counter_freq_hz()
        );
        if trace::enable_from_env() {
            eprintln!("{LOG_PREFIX} hvi-time: HVI_TIME_TRACE on, exits to hvi counted");
        }
        Some(device)
    } else {
        cfg.require_native_profile("KVM")?;
        None
    };

    // Number of SPIs (multiple of 32), then finalize the GIC.
    let nr_irqs: u32 = 256;
    set_gic_attr_u32(&gicfd, KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &nr_irqs)?;
    let init_attr = kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
        addr: 0,
    };
    gicfd.set_device_attr(&init_attr)?;
    let gicfd = Arc::new(gicfd);

    // The profile is complete now, so its file is written before any filter
    // goes in.
    let machine = Arm64Machine {
        gic: &gic,
        layout: &layout,
        vcpus: num_cpus,
        cmdline: &cmdline,
        devices: fdt_devices,
        net_mode: match (&net, &net_source) {
            (Some(_), Some(NetSource::Tap(_))) => Some("tap"),
            (Some(_), Some(NetSource::Gateway(_))) => Some("gateway"),
            (Some(_), None) => Some("stub"),
            (None, _) => None,
        },
        ram_regions: ram.regions(),
        profile: cfg.profile,
    };
    let profile = Arc::new(ProfileCell::new(
        boot_profile(&cfg, &machine, &vcpus[0]),
        cfg.profile_out.as_deref(),
    )?);
    profile.complete(|_| {})?;

    // Primary vCPU boot state: PC = kernel entry, X0 = DTB, PSTATE = EL1h/DAIF.
    set_u64(&vcpus[0], REG_PC, layout.kernel_addr);
    set_u64(&vcpus[0], REG_X0, layout.dtb_addr);
    set_u64(&vcpus[0], REG_PSTATE, PSTATE_EL1H_DAIF);

    // A live move reads KVM's dirty log of the RAM slots.
    let write_log: Arc<dyn GuestWriteLog> =
        Arc::new(KvmWriteLog::new(Arc::clone(&vm), Arc::clone(&ram)));
    let shared = Shared {
        guest: Arc::new(Guest {
            arch: GuestArch::Aarch64,
            sandbox_id: cfg.sandbox_id.clone(),
            ram,
            shared_ram,
            ledger: Arc::new(Mutex::new(emitter)),
            block: virtio,
            net,
            vsock,
            vcpus: Arc::new(Vcpus::new(
                num_cpus,
                Kicker::new(num_cpus),
                cfg.take_stop_handle()?,
            )),
            plugin_threads: PluginThreads::new(),
            write_log: Some(write_log),
        }),
        pl011: Arc::new(Mutex::new(Pl011::new())),
        plugin: cfg.plugin.clone(),
        hvitime,
        vm: Arc::clone(&vm),
        gic: Arc::clone(&gicfd),
        restoring: None,
    };

    // Each device sets its own interrupt line, from the methods that change its
    // level and so under the lock that decides it.
    let line = |spi| Arc::new(KvmIrqLine::new(Arc::clone(&vm), spi_gsi(spi)));
    lock_or_recover(&shared.pl011).connect_irq(line(UART_SPI));
    shared.guest.connect_irqs(
        line(VIRTIO_SPI),
        line(VIRTIO_NET_SPI),
        line(VIRTIO_VSOCK_SPI),
    );

    // The plugin attach, the seccomp arm and the I/O threads, in the order the
    // filters need. Each polls its stop token beside its own descriptor and is
    // joined after the vCPUs; `teardown` describes the stop.
    let (filters, mut io_threads) = start_io_threads(
        &(&cfg).into(),
        &shared.guest,
        {
            let pl011 = Arc::clone(&shared.pl011);
            move |byte| lock_or_recover(&pl011).push_rx(byte)
        },
        net_source,
        profile,
        Console::Pl011(Arc::clone(&shared.pl011)),
    )?;

    // The hvi-time timer thread. It lowers its timer slack before it
    // filters itself, since neither allowlist has `prctl`, and the main
    // thread, which it inherits from, is not filtered yet.
    if let Some(device) = &shared.hvitime {
        spawn_timer(&mut io_threads, device);
        if let Some(test) = hvitime::TestRestore::from_env() {
            let hold = {
                let (gicfd, vm, sh) = (Arc::clone(&gicfd), Arc::clone(&vm), shared.clone());
                move || vgic_round_trip(&gicfd, &vm, num_cpus as usize, &sh)
            };
            let (device, vcpus) = (Arc::clone(device), Arc::clone(&shared.guest.vcpus));
            io_threads.spawn("hvi-time test restore", move |_| {
                test.run(&device, &vcpus, hold);
            });
        }
    }

    run_guest(
        &shared.guest,
        &shared,
        vcpus,
        kick_handles,
        run_cpu,
        filters,
        io_threads,
    )
}

/// What the KVM restore loads: a portable guest, from either backend.
const RESTORER: Restorer = restore::portable("kvm");

/// Resumes the checkpoint bundle `cfg` names in this process, and runs it
/// until the guest powers off or a client stops it.
///
/// Only the portable profile restores on KVM: its interrupt controller is
/// a vGICv2 here, loaded from the canonical state, and its clock is
/// `hvi-time`. The native machine's vGICv3 is not captured, and its bundle
/// is refused with that reason.
///
/// It refuses with every reason it finds before it creates anything: a
/// bundle that does not hold all a restore loads, flags that do not match
/// the guest's devices, and a machine profile this host does not match.
/// It then builds the VM as a portable boot does: the vGICv2, guest RAM
/// copied from the bundle, the devices from their state, every vCPU
/// created and initialised in index order (one that was off powered off),
/// the CPU baseline and firmware, and the counter offset set so the guest's
/// counter reads no less than at the capture, scaled to this host's rate.
/// The host check of a portable boot runs first. Then, before any vCPU has
/// run, each vCPU loads its state by name (`kvm_state::import`), the vGIC
/// loads the canonical state and each device's line is driven to its level.
/// The guest waits restored-paused on the control socket, and the first
/// vCPU to enter it after `resume` publishes `hvi-time`'s page.
///
/// # Errors
///
/// Errors on any refusal, on a host resource that cannot be opened, and on
/// a state KVM does not take, after stopping whatever had started.
// One function so the order of the steps, which KVM and the seccomp
// filters constrain, reads top to bottom.
#[allow(clippy::too_many_lines)]
pub(crate) fn restore(
    cfg: RestoreConfig,
) -> Result<Stop, Box<dyn std::error::Error + Send + Sync>> {
    let mut opened = restore::open_config(&cfg).map_err(|e| format!("{}: {e}", cfg.from))?;
    let source_profile = opened.profile().clone();
    let source = &source_profile;
    let mut why = restore::refusals(&opened, &cfg, &RESTORER);
    if !RESTORER.profiles.contains(&source.profile.as_str()) {
        why.push(
            "the KVM restore rebuilds the portable machine only; the native machine's vGICv3 \
             is not captured"
                .to_string(),
        );
        return Err(Box::new(Refused(why)));
    }
    let ram_size = match source.ram_regions.as_slice() {
        [region] if region.gpa == RAM_BASE => Some(region.size),
        _ => {
            why.push(format!(
                "profile.json: the guest has one RAM region at {RAM_BASE:#x}, not {:?}",
                source.ram_regions
            ));
            None
        }
    };
    let num_cpus = source.vcpus;
    let gic = match GicLayout::for_vcpus(GicVersion::V2, num_cpus.max(1)) {
        Ok(gic) => gic,
        Err(e) => {
            why.push(format!("profile.json: {e}"));
            return Err(Box::new(Refused(why)));
        }
    };
    let present = fdt::VirtioDevices {
        blk: cfg.disk.is_some(),
        net: cfg.net || cfg.net_gateway.is_some(),
        vsock: cfg.agent_sock.is_some(),
        fs_count: 0,
        timer: fdt::ArchTimer::NoInterrupts {
            clock_frequency: fdt::ArchTimer::PORTABLE_HZ,
        },
        hvi_time: true,
    };
    let net_mode = if cfg.net_gateway.is_some() {
        Some("gateway")
    } else if cfg.net {
        Some("stub")
    } else {
        None
    };
    let mut local = arm64_profile::restored(
        "kvm",
        &gic,
        present,
        net_mode,
        source,
        MachineProfileKind::PortableArm64V1,
    );
    local.agent_sock = cfg.agent_sock.is_some();
    // set_baseline gives the guest PSCI 1.1, as a portable boot does.
    local.firmware.psci_version = Some("1.1".to_string());
    local.cpu.ident.clone_from(&source.cpu.ident);
    why.extend(restore::profile_refusals(source, &local));
    // Held apart from `opened`, which hands over guest RAM below.
    let plan = Arc::clone(&opened.plan);
    let TimerState::HviTime(clock) = &plan.platform.timer else {
        why.push("platform.json: the counter is not hvi-time".to_string());
        return Err(Box::new(Refused(why)));
    };
    let IrqState::Gicv2(gic_state) = &plan.platform.irq else {
        why.push("platform.json: the interrupt controller is not a GICv2".to_string());
        return Err(Box::new(Refused(why)));
    };
    let Some(ram_size) = ram_size.filter(|_| why.is_empty()) else {
        return Err(Box::new(Refused(why)));
    };
    eprintln!(
        "{LOG_PREFIX} restoring {} ({num_cpus} vCPU(s), {} MiB, captured by {} on {} at epoch {})",
        cfg.from,
        ram_size >> 20,
        opened.session.sandbox_id,
        source.backend,
        opened.session.epoch
    );
    install_kick_handler();

    let kvm = Kvm::new()?;
    if !kvm.check_extension(Cap::ImmediateExit) {
        return Err("hvi needs KVM_CAP_IMMEDIATE_EXIT, which Linux 4.11 added".into());
    }
    if !kvm.check_extension(Cap::ReadonlyMem) {
        return Err("a portable guest needs KVM_CAP_READONLY_MEM for the hvi-time page".into());
    }
    let vm = Arc::new(kvm.create_vm()?);
    let gicfd = vm
        .create_device(&mut kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
            fd: 0,
            flags: 0,
        })
        .map_err(|e| {
            format!(
                "the portable guest needs a vGICv2, and KVM offers none on this host ({e}): \
                 a GICv3-only host serves vGICv3 alone"
            )
        })?;
    eprintln!(
        "{LOG_PREFIX} {num_cpus} vCPU(s)  V2  GICD {:#x}+{:#x}  GICC {:#x}+{:#x}  profile {}",
        gic.gicd_base, gic.gicd_size, gic.gicr_base, gic.gicr_size, source.profile
    );

    set_gic_addr(&gicfd, KVM_VGIC_V2_ADDR_TYPE_DIST, gic.gicd_base)?;
    set_gic_addr(&gicfd, KVM_VGIC_V2_ADDR_TYPE_CPU, gic.gicr_base)?;

    // Every vCPU, in index order, as the boot creates them; one that was
    // off powered off, as it was.
    let mut kvi = kvm_vcpu_init::default();
    vm.get_preferred_target(&mut kvi)?;
    kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
    let mut vcpus = Vec::with_capacity(num_cpus as usize);
    let mut kick_handles = Vec::with_capacity(num_cpus as usize);
    for (id, state) in (0..num_cpus).zip(&opened.plan.vcpus) {
        let vcpu = vm.create_vcpu(u64::from(id))?;
        let mut kvi_cpu = kvi;
        if matches!(state, VcpuState::Aarch64(v) if v.power == Power::Off) {
            kvi_cpu.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
        }
        vcpu.vcpu_init(&kvi_cpu)?;
        kick_handles.push(kick_handle(&vm, &vcpu)?);
        vcpus.push(vcpu);
    }

    // The host check of a portable boot, before guest RAM is copied and the
    // disk is opened, and the baseline and firmware, before any vCPU runs.
    let host = kvm_host(&kvm, &vm, &vcpus[0]);
    let problems = portable::kvm_host_problems(&host);
    if !problems.is_empty() {
        return Err(Box::new(Refused(
            problems.into_iter().map(|p| format!("host: {p}")).collect(),
        )));
    }
    set_baseline(&vcpus)?;

    // A bundle directory's ram.bin is hashed here, as it is copied, and
    // refused like the open refuses a component: named with the bundle. A
    // stream's RAM was filled and checked as it was read.
    let (shared_ram, ram) = opened
        .guest_ram()
        .map_err(|e| format!("{}: {e}", cfg.from))?;
    ram.register_kvm_slots(&vm)?;
    let rebuild::Devices {
        block,
        net,
        net_reader,
        vsock,
        pl011,
    } = rebuild::devices(&opened, &cfg, &ram)?;

    // The counter, which KVM takes only before a vCPU has run.
    let start = clock.counter_target(crate::checkpoint::profile::counter_freq_hz());
    let offset = set_counter_offset(&kvm, &vm, &vcpus[0], start)?;
    let device = Arc::new(HviTime::new(
        num_cpus as usize,
        crate::checkpoint::profile::counter_freq_hz(),
        Box::new(KvmCounter { offset }),
        Box::new(KvmTimerLine {
            vm: Arc::clone(&vm),
        }),
    )?);
    let slot = kvm_userspace_memory_region {
        slot: u32::try_from(ram.regions().len()).unwrap_or(u32::MAX),
        flags: KVM_MEM_READONLY,
        guest_phys_addr: HVI_TIME_PAGE_BASE,
        memory_size: hvitime::PAGE_SIZE,
        userspace_addr: device.page().host_ptr() as u64,
    };
    // SAFETY: the page is a live mapping of `PAGE_SIZE` bytes that lives as
    // long as `device`, which outlives the VM.
    unsafe { vm.set_user_memory_region(slot) }
        .map_err(|e| format!("the hvi-time page's read-only memory slot: {e}"))?;
    eprintln!(
        "{LOG_PREFIX} hvi-time: page {HVI_TIME_PAGE_BASE:#x}+{:#x} (read-only slot), counter {} Hz \
         (the capture's {} Hz), guest counter from {start}, offset {offset:#x}",
        hvitime::PAGE_SIZE,
        device.counter_freq_hz(),
        clock.page.counter_freq_hz
    );
    let nr_irqs: u32 = 256;
    set_gic_attr_u32(&gicfd, KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &nr_irqs)?;
    gicfd.set_device_attr(&kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
        addr: 0,
    })?;
    let gicfd = Arc::new(gicfd);

    // The state, before any vCPU has run, then the lines: loading the vGIC
    // set every line to its captured level behind the devices' backs, so
    // each device's line goes to the device's level once it is connected,
    // and the device's record of it with it.
    let pl011 = Arc::new(Mutex::new(pl011));
    let line = |spi| Arc::new(KvmIrqLine::new(Arc::clone(&vm), spi_gsi(spi)));
    let checked = kvm_state::load_portable(
        &vcpus,
        &opened.plan.vcpus,
        &KvmVgic {
            gic: &gicfd,
            vm: &vm,
            ncpu: num_cpus as usize,
        },
        gic_state,
        || {
            let mut uart = lock_or_recover(&pl011);
            uart.connect_irq(line(UART_SPI));
            uart.redrive_irq();
            drop(uart);
            if let Some(dev) = &block {
                let mut dev = lock_or_recover(dev);
                dev.connect_irq(line(VIRTIO_SPI));
                dev.redrive_irq();
            }
            if let Some(dev) = &net {
                let mut dev = lock_or_recover(dev);
                dev.connect_irq(line(VIRTIO_NET_SPI));
                dev.redrive_irq();
            }
            if let Some(dev) = &vsock {
                let mut dev = lock_or_recover(dev);
                dev.connect_irq(line(VIRTIO_VSOCK_SPI));
                dev.redrive_irq();
            }
        },
    )?;
    eprintln!("{LOG_PREFIX} vGICv2: {checked} registers loaded and read back");
    let midr = read_u64(&vcpus[0], REG_MIDR_EL1);

    let stop_source_profile = Arc::new(ProfileCell::new(local, cfg.profile_out.as_deref())?);
    stop_source_profile.complete(|p| p.cpu.ident = midr.map(hex))?;
    let sandbox_id = cfg
        .sandbox_id
        .clone()
        .unwrap_or_else(|| opened.session.sandbox_id.clone());
    let emitter = Emitter::new(cfg.events.as_deref(), &sandbox_id)?;
    // A live move reads KVM's dirty log of the RAM slots.
    let write_log: Arc<dyn GuestWriteLog> =
        Arc::new(KvmWriteLog::new(Arc::clone(&vm), Arc::clone(&ram)));
    let shared = Shared {
        guest: Arc::new(Guest {
            arch: GuestArch::Aarch64,
            sandbox_id,
            ram,
            shared_ram,
            ledger: Arc::new(Mutex::new(emitter)),
            block,
            net,
            vsock,
            vcpus: Arc::new(Vcpus::new(
                num_cpus,
                Kicker::new(num_cpus),
                StopHandle::new_pair()?.0,
            )),
            write_log: Some(write_log),
            plugin_threads: PluginThreads::new(),
        }),
        pl011,
        plugin: None,
        hvitime: Some(Arc::clone(&device)),
        vm: Arc::clone(&vm),
        gic: Arc::clone(&gicfd),
        restoring: Some(Arc::new(PendingPublish::new((**clock).clone()))),
    };

    // Held from the control socket before any vCPU thread exists, so each
    // parks before its first entry until a client resumes the guest.
    shared
        .guest
        .vcpus
        .pause_from_control(std::time::Duration::ZERO)
        .map_err(|e| format!("holding the vCPUs for the restore: {e}"))?;
    let io = IoConfig {
        plugin: None,
        sandbox: cfg.sandbox,
        agent_sock: cfg.agent_sock.as_deref(),
        control_sock: Some(&cfg.control_sock),
        checkpoint_root: cfg.checkpoint_root.as_deref(),
        disk: cfg.disk.clone(),
        restored: true,
    };
    let (filters, mut io_threads) = start_io_threads(
        &io,
        &shared.guest,
        {
            let pl011 = Arc::clone(&shared.pl011);
            move |byte| lock_or_recover(&pl011).push_rx(byte)
        },
        net_reader.map(NetSource::Gateway),
        stop_source_profile,
        Console::Pl011(Arc::clone(&shared.pl011)),
    )?;
    spawn_timer(&mut io_threads, &device);

    // `boot` keeps the run's claim when it sees a `LeftRunning` error, so the
    // error goes back as `run_guest` returned it.
    run_guest(
        &shared.guest,
        &shared,
        vcpus,
        kick_handles,
        run_cpu,
        filters,
        io_threads,
    )
}

/// Starts `device`'s timer thread with the I/O threads, which the stop ends
/// through the device.
///
/// The thread lowers its timer slack before it filters itself, since neither
/// allowlist has `prctl`, so it confines itself rather than at its start.
fn spawn_timer(io_threads: &mut IoThreads<Kicker>, device: &Arc<HviTime>) {
    let timer = Arc::clone(device);
    io_threads.spawn_with(
        "hvi-time timer",
        STOP_TIMEOUT,
        || {},
        move |_| {
            let how = hvitime::timer_thread_setup();
            seccomp::install_thread(seccomp::Thread::Vmm);
            eprintln!("{LOG_PREFIX} hvi-time: timer thread on {how}");
            timer.run_timer();
        },
    );
    let timer = Arc::clone(device);
    io_threads.on_stop(move || timer.stop());
}

/// Reads what this host's KVM offers a portable guest. `vcpu` is a vCPU
/// that has not run and whose ID registers are still KVM's defaults.
fn kvm_host(kvm: &Kvm, vm: &VmFd, vcpu: &VcpuFd) -> KvmHost {
    let id_regs = portable::BASELINE
        .iter()
        .zip(BASELINE_REGS)
        .filter_map(|((name, _), id)| read_u64(vcpu, id).map(|v| (*name, v)))
        .collect();
    KvmHost {
        // The caller created one already.
        vgic_v2: true,
        page_size: host_page_size(),
        ipa_bits: u32::try_from(kvm.get_host_ipa_limit()).unwrap_or(0),
        id_regs,
        writable: writable_masks(kvm, vm),
    }
}

/// Returns the writable mask of each baseline register, or `None` when this
/// KVM does not report them.
fn writable_masks(kvm: &Kvm, vm: &VmFd) -> Option<Vec<(&'static str, u64)>> {
    if kvm.check_extension_raw(KVM_CAP_ARM_SUPPORTED_REG_MASK_RANGES) & 1 == 0 {
        return None;
    }
    let mut masks = vec![0u64; FEATURE_ID_RANGE_SIZE];
    let mut range = RegMaskRange {
        addr: masks.as_mut_ptr() as u64,
        range: 0,
        reserved: [0; 13],
    };
    // SAFETY: a VM ioctl that writes FEATURE_ID_RANGE_SIZE u64s to `addr`,
    // which `masks` holds, and reads `range`.
    let ret = unsafe {
        libc::ioctl(
            vm.as_raw_fd(),
            KVM_ARM_GET_REG_WRITABLE_MASKS,
            std::ptr::addr_of_mut!(range),
        )
    };
    if ret != 0 {
        return None;
    }
    Some(
        portable::BASELINE
            .iter()
            .zip(BASELINE_REGS)
            .map(|((name, _), id)| {
                let (op1, crm, op2) = ((id >> 11) & 7, (id >> 3) & 0xf, id & 7);
                (*name, masks[feature_id_index(op1, crm, op2)])
            })
            .collect(),
    )
}

/// Gives the VM the portable CPU baseline and firmware, through vCPU 0
/// (KVM keeps them per VM), and reads them back on every vCPU.
///
/// # Errors
///
/// Errors naming every register KVM refused or that reads back otherwise,
/// a vCPU whose `MPIDR_EL1` is not `0x80000000 | index`, and a host
/// `DCZID_EL0` other than the profile's.
fn set_baseline(vcpus: &[VcpuFd]) -> Result<(), String> {
    let mut wrong = Vec::new();
    let mut wanted: Vec<(String, u64, u64)> = portable::BASELINE
        .iter()
        .zip(BASELINE_REGS)
        .map(|((name, value), id)| ((*name).to_string(), id, *value))
        .collect();
    wanted.push(("ID_AA64ISAR2_EL1".into(), REG_ID_AA64ISAR2_EL1, 0));
    for (name, id) in FW_FEATURE_BITMAPS {
        wanted.push((name.into(), id, 0));
    }
    wanted.push((
        "KVM_REG_ARM_PSCI_VERSION".into(),
        REG_PSCI_VERSION,
        portable::fw::VERSION_1_1,
    ));
    for (name, id, value) in &wanted {
        if let Err(e) = vcpus[0].set_one_reg(*id, &value.to_le_bytes()) {
            wrong.push(format!("{name} cannot be set to {value:#x} ({e})"));
        }
    }
    for (cpu, vcpu) in vcpus.iter().enumerate() {
        let mpidr = 0x8000_0000 | cpu as u64;
        let reads = wanted
            .iter()
            .map(|(name, id, value)| (name.as_str(), *id, *value))
            .chain([("MPIDR_EL1", REG_MPIDR_EL1, mpidr)]);
        for (name, id, value) in reads {
            match read_u64(vcpu, id) {
                Some(back) if back == value => {}
                Some(back) => {
                    wrong.push(format!("cpu{cpu} {name} reads {back:#x}, not {value:#x}"))
                }
                None => wrong.push(format!("cpu{cpu} {name} does not read back")),
            }
        }
    }
    let dczid = host_dczid();
    if dczid != portable::DCZID_EL0 {
        wrong.push(format!(
            "DCZID_EL0 is {dczid:#x} here, not {:#x}",
            portable::DCZID_EL0
        ));
    }
    if !wrong.is_empty() {
        return Err(format!(
            "the portable-arm64-v1 CPU baseline does not hold on this host: {}",
            wrong.join("; ")
        ));
    }
    let regs: Vec<String> = portable::BASELINE
        .iter()
        .map(|(name, value)| format!("{name}={value:#x}"))
        .collect();
    let ctr = read_u64(&vcpus[0], sys_reg(3, 3, 0, 0, 1)).unwrap_or(0);
    eprintln!(
        "{LOG_PREFIX} portable-arm64-v1 CPU baseline: {} ID_AA64ISAR2_EL1=0x0 (host CTR_EL0={ctr:#x} DCZID_EL0={dczid:#x}, not lowered); firmware bitmaps 0, PSCI 1.1",
        regs.join(" ")
    );
    Ok(())
}

/// Sets the guest's counter so that it starts near `start` (0 at a boot,
/// and at a restore the captured counter scaled to this host's rate), and
/// returns the offset hvi subtracts from the host's counter to read it.
///
/// With `KVM_CAP_COUNTER_OFFSET` the offset is set exactly, VM-wide, and
/// moves the guest's physical counter with the virtual one, as on the Mac,
/// where the physical counter traps and reads the virtual one. Without it,
/// `KVM_REG_ARM_TIMER_CNT` is written and the offset is measured around a
/// read of it, to within the ioctl's time. Either way the result is checked
/// against `KVM_REG_ARM_TIMER_CNT` once, and the boot refused when they
/// disagree: every deadline, `NOW_NS` and the page's `base_counter` would
/// then be wrong.
///
/// # Errors
///
/// Errors when KVM refuses the offset or the counter, and when the guest's
/// counter is not where hvi computes it.
fn set_counter_offset(kvm: &Kvm, vm: &VmFd, vcpu: &VcpuFd, start: u64) -> Result<u64, String> {
    let (offset, how) = if kvm.check_extension(Cap::CounterOffset) {
        let offset = host_counter().wrapping_sub(start);
        let arg = kvm_arm_counter_offset {
            counter_offset: offset,
            reserved: 0,
        };
        // SAFETY: a VM ioctl that reads one `kvm_arm_counter_offset`.
        let ret = unsafe {
            libc::ioctl(
                vm.as_raw_fd(),
                KVM_ARM_SET_COUNTER_OFFSET,
                std::ptr::addr_of!(arg),
            )
        };
        if ret != 0 {
            return Err(format!(
                "KVM_ARM_SET_COUNTER_OFFSET: {}",
                std::io::Error::last_os_error()
            ));
        }
        (offset, "KVM_ARM_SET_COUNTER_OFFSET")
    } else {
        vcpu.set_one_reg(REG_TIMER_CNT, &start.to_le_bytes())
            .map_err(|e| format!("KVM_REG_ARM_TIMER_CNT cannot be set: {e}"))?;
        let before = host_counter();
        let guest = read_u64(vcpu, REG_TIMER_CNT).ok_or("KVM_REG_ARM_TIMER_CNT does not read")?;
        let after = host_counter();
        (
            before
                .wrapping_add(after.wrapping_sub(before) / 2)
                .wrapping_sub(guest),
            "KVM_REG_ARM_TIMER_CNT",
        )
    };
    let before = host_counter().wrapping_sub(offset);
    let guest = read_u64(vcpu, REG_TIMER_CNT).ok_or("KVM_REG_ARM_TIMER_CNT does not read")?;
    let after = host_counter().wrapping_sub(offset);
    let slack = crate::checkpoint::profile::counter_freq_hz() / 1_000_000;
    portable::check_guest_counter(guest, before, after, slack)
        .map_err(|e| format!("the guest counter set with {how} is wrong: {e}"))?;
    eprintln!(
        "{LOG_PREFIX} hvi-time: guest counter set with {how}; check: KVM_REG_ARM_TIMER_CNT {guest} within hvi's [{before}, {after}]: yes"
    );
    Ok(offset)
}

/// Runs one vCPU until the VM stops, servicing its MMIO exits.
fn run_cpu(cpu_id: u32, vcpu: VcpuFd, kick_handle: VcpuFd, sh: Shared) {
    let read_platform = std::cell::Cell::new(false);
    if cpu_id == 0 && sh.restoring.is_none() {
        // Guest nanoseconds start at 0 at the boot vCPU's first entry.
        if let Some(device) = &sh.hvitime {
            device.publish_boot();
        }
    }
    // A restored guest's clock is published before its first entry after
    // `resume`, which is the first call of the run below.
    let mut published = sh.restoring.is_none();
    run_vcpu(
        cpu_id,
        vcpu,
        kick_handle,
        &sh.guest,
        sh.plugin.as_deref(),
        |vcpu, work| {
            read_platform.set(read_platform.get() || matches!(work, Work::ExportPlatform));
            serve(&sh, cpu_id, vcpu, work)
        },
        || {
            // A capture froze hvi-time to read it. A guest that goes on
            // after it, as `then: "continue"` has it, gets its timers back.
            if read_platform.replace(false) {
                if let Some(device) = &sh.hvitime {
                    device.thaw();
                }
            }
            if !published {
                if let (Some(pending), Some(device)) = (&sh.restoring, &sh.hvitime) {
                    if let Err(e) = pending.publish(device) {
                        return ControlFlow::Break(Outcome::Failed(format!("vcpu{cpu_id}: {e}")));
                    }
                }
                published = true;
            }
            ControlFlow::Continue(())
        },
        |exit| {
            match exit {
                VcpuExit::MmioRead(addr, data) => on_mmio(&sh, addr, true, data),
                VcpuExit::MmioWrite(addr, data) => {
                    // Copy out first: `data` borrows the run struct.
                    let mut buf = [0u8; 8];
                    let n = data.len().min(8);
                    buf[..n].copy_from_slice(&data[..n]);
                    on_mmio_write(&sh, addr, &buf[..n]);
                }
                // Kicked for a snapshot or a stop; the loop checks which.
                VcpuExit::Intr => trace::exit(trace::Exit::Kicked),
                other => return unhandled_exit(cpu_id, &other),
            }
            ControlFlow::Continue(())
        },
    );
}

/// Carries out the control socket's `work` for vCPU `cpu`, parked on its
/// own thread: its whole state by name (see `kvm_state`), and on vCPU 0 of
/// a portable guest the platform, once every vCPU has exported.
///
/// The portable platform is the vGICv2, read in the canonical form with
/// the line levels hvi's devices hold, and `hvi-time`, read frozen so no
/// timer fires between the two; the caller thaws it if the guest goes on.
/// The native machine's vGICv3 is not read, and its platform is written as
/// not captured. A KVM restore loads every vCPU before any thread runs, so
/// there is no import here.
fn serve(sh: &Shared, cpu: u32, vcpu: &VcpuFd, work: Work<'_>) -> std::io::Result<Option<Output>> {
    match work {
        Work::Export => Ok(Some(Output::Vcpu {
            state: VcpuState::Aarch64(kvm_state::export(cpu, vcpu)?),
            irq: None,
        })),
        Work::ExportPlatform if cpu == 0 => {
            let Some(device) = &sh.hvitime else {
                return Ok(None);
            };
            // A restored guest that has not run since holds the restored
            // state, which the device gets only at the resume.
            let timer = match sh
                .restoring
                .as_deref()
                .and_then(PendingPublish::unpublished)
            {
                Some(state) => state.clone(),
                None => {
                    device.freeze();
                    device.state()
                }
            };
            let ncpu = device.vcpus();
            let vgic = KvmVgic {
                gic: &sh.gic,
                vm: &sh.vm,
                ncpu,
            };
            let irq = vgicv2::export(&vgic, &device_lines(sh, ncpu))
                .map_err(|e| std::io::Error::other(format!("the vGICv2: {e}")))?;
            Ok(Some(Output::Platform {
                platform: PlatformState {
                    version: PLATFORM_STATE_VERSION,
                    arch: "aarch64".to_string(),
                    backend: "kvm".to_string(),
                    irq: IrqState::Gicv2(Box::new(irq)),
                    timer: TimerState::HviTime(Box::new(timer)),
                    backend_adjunct: None,
                },
                capabilities: Vec::new(),
            }))
        }
        Work::ExportPlatform => Ok(None),
        Work::Import(..) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("vCPU {cpu}: a KVM restore loads the vCPUs before they run"),
        )),
    }
}

impl SafepointVcpu for VcpuFd {
    fn regs(&self) -> RegsView {
        let ttbr1 = get_u64(self, REG_TTBR1_EL1);
        RegsView {
            // arm64's kernel-half page-table base is the walk root.
            root: ttbr1,
            pc: get_u64(self, REG_PC),
            cpsr: get_u64(self, REG_PSTATE),
            ttbr0: get_u64(self, REG_TTBR0_EL1),
            ttbr1,
            sctlr: get_u64(self, REG_SCTLR_EL1),
            sp_el1: get_u64(self, REG_SP_EL1),
            tcr: get_u64(self, REG_TCR_EL1),
            current_task: get_u64(self, REG_SP_EL0),
        }
    }
}

/// Services an MMIO **read**: fills `data` with the addressed device's value.
fn on_mmio(sh: &Shared, addr: u64, _read: bool, data: &mut [u8]) {
    let width = data.len();
    let val = read_device(sh, addr, width);
    let bytes = val.to_le_bytes();
    let n = width.min(8);
    data[..n].copy_from_slice(&bytes[..n]);
}

/// Returns `sh`'s `hvi-time` and the offset of `addr` in its timer window,
/// when `addr` is there.
fn hvitime_at(sh: &Shared, addr: u64) -> Option<(&HviTime, u64)> {
    let device = sh.hvitime.as_deref()?;
    (HVI_TIME_TIMERS_BASE..HVI_TIME_TIMERS_BASE + hvitime::TIMERS_SIZE)
        .contains(&addr)
        .then_some((device, addr - HVI_TIME_TIMERS_BASE))
}

/// Reads the device register at `addr`.
fn read_device(sh: &Shared, addr: u64, width: usize) -> u64 {
    if let Some((device, offset)) = hvitime_at(sh, addr) {
        trace::exit(trace::Exit::Timer);
        return device.mmio_read(offset, width as u8);
    }
    trace::exit(trace::Exit::Mmio);
    if (UART_BASE..UART_BASE + UART_SIZE).contains(&addr) {
        sh.pl011.lock().unwrap().mmio(addr - UART_BASE, false, 0)
    } else if (VIRTIO_BASE..VIRTIO_BASE + VIRTIO_SIZE).contains(&addr) {
        dev_read(sh, sh.guest.block.as_ref(), addr - VIRTIO_BASE)
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        dev_read(sh, sh.guest.net.as_ref(), addr - VIRTIO_NET_BASE)
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        vsock_read(sh, addr - VIRTIO_VSOCK_BASE)
    } else {
        0
    }
}

/// Services an MMIO **write** to the addressed device.
fn on_mmio_write(sh: &Shared, addr: u64, data: &[u8]) {
    let mut b = [0u8; 8];
    b[..data.len()].copy_from_slice(data);
    let val = u64::from_le_bytes(b);
    if let Some((device, offset)) = hvitime_at(sh, addr) {
        trace::exit(trace::Exit::Timer);
        device.mmio_write(offset, data.len() as u8, val);
        return;
    }
    // A write to the hvi-time page, a read-only slot, arrives here and is
    // dropped with the other writes no device claims.
    trace::exit(trace::Exit::Mmio);
    if (UART_BASE..UART_BASE + UART_SIZE).contains(&addr) {
        sh.pl011.lock().unwrap().mmio(addr - UART_BASE, true, val);
    } else if (VIRTIO_BASE..VIRTIO_BASE + VIRTIO_SIZE).contains(&addr) {
        dev_write(sh, sh.guest.block.as_ref(), addr - VIRTIO_BASE, val);
    } else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_SIZE).contains(&addr) {
        dev_write(sh, sh.guest.net.as_ref(), addr - VIRTIO_NET_BASE, val);
    } else if (VIRTIO_VSOCK_BASE..VIRTIO_VSOCK_BASE + VIRTIO_SIZE).contains(&addr) {
        vsock_write(sh, addr - VIRTIO_VSOCK_BASE, val);
    }
}

/// Services a read of register `off` of a virtio-blk or virtio-net device.
///
/// The device's captured events then go to the ledger.
fn dev_read<D: VirtioMmio>(sh: &Shared, dev: Option<&Arc<Mutex<D>>>, off: u64) -> u64 {
    let Some(dev) = dev else { return 0 };
    let (v, events) = {
        let mut d = dev.lock().unwrap();
        let v = d.mmio(&sh.guest.ram, off, false, 0);
        (v, d.take_events())
    };
    drain(sh, &events);
    v
}

/// Services a write of `val` to register `off` of a virtio-blk or virtio-net
/// device.
///
/// The device's captured events then go to the ledger.
fn dev_write<D: VirtioMmio>(sh: &Shared, dev: Option<&Arc<Mutex<D>>>, off: u64, val: u64) {
    let Some(dev) = dev else { return };
    let events = {
        let mut d = dev.lock().unwrap();
        d.mmio(&sh.guest.ram, off, true, val);
        d.take_events()
    };
    drain(sh, &events);
}

/// Services a read of virtio-vsock register `off`.
fn vsock_read(sh: &Shared, off: u64) -> u64 {
    let Some(dev) = sh.guest.vsock.as_ref() else {
        return 0;
    };
    dev.lock().unwrap().mmio(&sh.guest.ram, off, false, 0)
}

/// Services a write of `val` to virtio-vsock register `off`.
fn vsock_write(sh: &Shared, off: u64, val: u64) {
    let Some(dev) = sh.guest.vsock.as_ref() else {
        return;
    };
    dev.lock().unwrap().mmio(&sh.guest.ram, off, true, val);
}

/// Moves a device's captured `events` into the ledger.
fn drain(sh: &Shared, events: &[crate::events::CapturedEvent]) {
    if events.is_empty() {
        return;
    }
    let mut e = sh.guest.ledger.lock().unwrap();
    for ev in events {
        e.captured(ev);
    }
}

/// The virtio-mmio surface `dev_read`/`dev_write` need (blk and net share it).
trait VirtioMmio {
    fn mmio(&mut self, mem: &GuestRam, offset: u64, is_write: bool, value: u64) -> u64;
    fn take_events(&mut self) -> Vec<crate::events::CapturedEvent>;
}
impl VirtioMmio for VirtioBlk {
    fn mmio(&mut self, m: &GuestRam, o: u64, w: bool, v: u64) -> u64 {
        VirtioBlk::mmio(self, m, o, w, v)
    }
    fn take_events(&mut self) -> Vec<crate::events::CapturedEvent> {
        VirtioBlk::take_events(self)
    }
}
impl VirtioMmio for VirtioNet {
    fn mmio(&mut self, m: &GuestRam, o: u64, w: bool, v: u64) -> u64 {
        VirtioNet::mmio(self, m, o, w, v)
    }
    fn take_events(&mut self) -> Vec<crate::events::CapturedEvent> {
        VirtioNet::take_events(self)
    }
}

fn set_gic_addr(
    gic: &kvm_ioctls::DeviceFd,
    addr_type: u32,
    gpa: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let val: u64 = gpa;
    let attr = kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(addr_type),
        addr: std::ptr::addr_of!(val) as u64,
    };
    gic.set_device_attr(&attr)?;
    Ok(())
}

fn set_gic_attr_u32(
    gic: &kvm_ioctls::DeviceFd,
    group: u32,
    attr: u64,
    val: &u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let a = kvm_device_attr {
        flags: 0,
        group,
        attr,
        addr: std::ptr::addr_of!(*val) as u64,
    };
    gic.set_device_attr(&a)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::aarch64::vgicv2::tests::busy_state;

    /// The two raw requests are the numbers the kernel's headers give.
    #[test]
    fn the_raw_ioctl_requests_are_the_kernels() {
        assert_eq!(u64::from(KVM_ARM_SET_COUNTER_OFFSET as u32), 0x4010_aeb5);
        assert_eq!(
            u64::from(KVM_ARM_GET_REG_WRITABLE_MASKS as u32),
            0x8040_aeb6
        );
    }

    /// A VM with a vGICv2 and `ncpu` vCPUs, set up as the boot sets them up
    /// and never run.
    fn vgic_vm(ncpu: u32) -> (VmFd, DeviceFd, Vec<VcpuFd>) {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = vm
            .create_device(&mut kvm_create_device {
                type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
                fd: 0,
                flags: 0,
            })
            .unwrap();
        let layout = GicLayout::for_vcpus(GicVersion::V2, ncpu).unwrap();
        set_gic_addr(&gic, KVM_VGIC_V2_ADDR_TYPE_DIST, layout.gicd_base).unwrap();
        set_gic_addr(&gic, KVM_VGIC_V2_ADDR_TYPE_CPU, layout.gicr_base).unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        let vcpus = (0..ncpu)
            .map(|id| {
                let vcpu = vm.create_vcpu(u64::from(id)).unwrap();
                vcpu.vcpu_init(&kvi).unwrap();
                vcpu
            })
            .collect();
        set_gic_attr_u32(&gic, KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &256).unwrap();
        gic.set_device_attr(&kvm_device_attr {
            flags: 0,
            group: KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
            addr: 0,
        })
        .unwrap();
        (vm, gic, vcpus)
    }

    /// Prints `KVM_GET_REG_LIST` of a vCPU set up as the boot sets it up,
    /// with each register's value: `native` as it is, `portable` once the
    /// portable baseline and firmware are written. The output is the
    /// fixture the classification test reads
    /// (`src/checkpoint/testdata/kvm-reg-list-rp2-*.txt`). Needs /dev/kvm
    /// on a Pi 5.
    #[test]
    #[ignore]
    fn print_the_register_lists() {
        for portable in [false, true] {
            let (_vm, _gic, vcpus) = vgic_vm(1);
            if portable {
                set_baseline(&vcpus).unwrap();
            }
            let mut list = kvm_bindings::RegList::new(500).unwrap();
            vcpus[0].get_reg_list(&mut list).unwrap();
            let name = if portable { "portable" } else { "native" };
            println!("# {name}: {} registers", list.as_slice().len());
            for id in list.as_slice() {
                let size = 1usize << ((id >> 52) & 0xf);
                let mut buf = vec![0u8; size];
                let value = match vcpus[0].get_one_reg(*id, &mut buf) {
                    Ok(_) => buf
                        .iter()
                        .rev()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                    Err(e) => format!("error:{}", e.errno()),
                };
                println!("{name} {id:#018x} {value}");
            }
        }
    }

    /// The software model's state, with pending, active, SGI-source and
    /// line state on both CPUs, goes into KVM's vGICv2, reads back register
    /// for register, and comes out as it went in. Needs /dev/kvm on a host
    /// with a vGICv2 (a Pi 5).
    #[test]
    #[ignore]
    fn a_gicv2_state_round_trips_through_kvm() {
        let (vm, gic, _vcpus) = vgic_vm(2);
        let vgic = KvmVgic {
            gic: &gic,
            vm: &vm,
            ncpu: 2,
        };
        let quiet = Lines {
            spis: vec![0; crate::devices::gicv2::WORDS],
            ppis: vec![0; 2],
        };
        let fresh = vgicv2::export(&vgic, &quiet).unwrap();
        let c = &fresh.cpus[0];
        // KVM reads 0 for both binary points of a fresh vCPU; the guest
        // reads the minimums, which the export gives.
        assert_eq!(
            vgic.read(Bank::Cpu, 0, crate::devices::gicv2::gicc::BPR),
            Ok(0)
        );
        assert_eq!((c.bpr, c.abpr), (2, 3));
        eprintln!(
            "fresh vGICv2: GICD_CTLR {:#x}, cpu0 GICC_CTLR {:#x} PMR {:#x} BPR {} ABPR {} \
             APR {:x?}, ISENABLER0 {:#x}, IGROUPR0 {:#x}, ICFGR2 {:#x}, IPRIORITYR32 {:#x}, \
             ITARGETSR32 {:#x}",
            fresh.dist.ctlr,
            c.ctlr,
            c.pmr,
            c.bpr,
            c.abpr,
            c.apr,
            c.isenabler0,
            fresh.dist.igroupr[0],
            fresh.dist.icfgr[2],
            fresh.dist.ipriorityr[32],
            fresh.dist.itargetsr[32]
        );

        let s = busy_state();
        let checked = vgicv2::import(&vgic, &s).unwrap();
        let back = vgicv2::export(&vgic, &Lines::of(&s)).unwrap();
        assert_eq!(back, s);
        eprintln!("{checked} registers read back as written; the export equals the state");

        // A second import over a vGIC that holds state is exact too: the
        // latches, sources and lines the first one set are gone.
        let mut calm = s.clone();
        calm.dist.latch[1] = 0;
        calm.dist.line_level[1] = 0;
        calm.cpus[1].line0 = 0;
        calm.cpus[1].sgi_sources = vec![0; 16];
        calm.cpus[1].latch0 &= !0xffff;
        calm.cpus[0].isactiver0 = 0;
        calm.dist.isactiver[1] = 0;
        calm.cpus[0].apr[0] = 0;
        vgicv2::import(&vgic, &calm).unwrap();
        assert_eq!(vgicv2::export(&vgic, &Lines::of(&calm)).unwrap(), calm);

        // What KVM cannot hold is refused.
        let mut apr = s.clone();
        apr.cpus[0].apr[1] = 1;
        assert!(vgicv2::import(&vgic, &apr)
            .unwrap_err()
            .contains("GICC_APR1-3"));
    }
}

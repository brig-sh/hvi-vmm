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

//! KVM's vGICv2 state in the canonical checkpoint form, [`Gicv2State`].
//!
//! The portable machine's interrupt controller is the software model on the
//! Mac and KVM's in-kernel vGICv2 on the Pi, and a checkpoint of either has
//! the one form the model defines. [`export`] reads the vGIC into it and
//! [`import`] writes it back, through the `KVM_DEV_ARM_VGIC_GRP_DIST_REGS`
//! and `KVM_DEV_ARM_VGIC_GRP_CPU_REGS` register views (behind [`VgicV2`],
//! so the conversion is tested without KVM).
//!
//! KVM's userspace view of a GICv2 differs from the model's state in ways
//! the conversion has to undo (Linux 6.12, `arch/arm64/kvm/vgic/`):
//!
//! - `GICD_IGROUPR` writes are dropped until userspace has written `GICD_IIDR`
//!   (`v2_groups_user_writable`), so `GICD_IIDR` goes first.
//! - `GICD_ISPENDR` reads `latch || line_level` for a level interrupt, and the
//!   v2 view has no separate line level. hvi's devices know their lines, so
//!   [`export`] takes them, and an interrupt's latch is the pending bit with
//!   the line high taken out. A level interrupt whose line is high and whose
//!   latch is also set exports without the latch: the one loss.
//! - A `GICD_ISPENDR` write to an SGI makes the writing vCPU its only source,
//!   so SGIs are written through `GICD_SPENDSGIR` with their sources, and the
//!   SGI bits of `GICD_ISPENDR0` are left out.
//! - The line levels are set with `KVM_IRQ_LINE` after the registers. KVM
//!   ignores a line it does not own, so only the lines hvi drives are set: the
//!   level SPIs, and PPI 20 (`hvi-time`) of each vCPU. A state with another
//!   PPI's line high is refused.
//! - `GICC_PMR` is the five-bit `VMPriMask`, the register's value shifted right
//!   by 3.
//! - A GICv2 host has `GICC_APR0` only: `GICC_APR1-3` read 0 and ignore writes.
//!   A state with any of them set is refused.
//! - `GICC_BPR` and `GICC_ABPR` read 0 from a vCPU nothing has written, where
//!   the guest reads 2 and 3, the minimums, as the model does. The export gives
//!   the guest's view.
//!
//! [`import`] clears every enable, active and pending bit before it sets the
//! state's, so it is exact on a vGIC that has run, then reads every register
//! back and refuses when one differs. Every vCPU must be out of `KVM_RUN`
//! for the whole of either call: KVM refuses a register access with `EBUSY`
//! otherwise.

use crate::devices::gicv2::{
    gicc, gicd, CpuState, DistState, Gicv2State, ABPR_MIN, BPR_MIN, CFG_EDGE_BITS, GICC_CTLR_MASK,
    GICD_IIDR, NR_IRQS, PRIO_MASK, WORDS,
};
use crate::devices::hvitime;

/// Which register view of the vGIC an access goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bank {
    /// The distributor, `KVM_DEV_ARM_VGIC_GRP_DIST_REGS`.
    Dist,
    /// A CPU interface, `KVM_DEV_ARM_VGIC_GRP_CPU_REGS`.
    Cpu,
}

/// A vGICv2's registers as userspace reaches them, and its lines.
pub(crate) trait VgicV2 {
    /// Returns the number of vCPUs.
    fn ncpu(&self) -> usize;
    /// Reads the 32-bit register at `offset` of `bank`, as vCPU `cpu` sees
    /// it.
    ///
    /// # Errors
    ///
    /// Errors when the hypervisor refuses the access.
    fn read(&self, bank: Bank, cpu: usize, offset: u64) -> Result<u32, String>;
    /// Writes `value` to the 32-bit register at `offset` of `bank`, as vCPU
    /// `cpu`.
    ///
    /// # Errors
    ///
    /// Errors when the hypervisor refuses the access.
    fn write(&self, bank: Bank, cpu: usize, offset: u64, value: u32) -> Result<(), String>;
    /// Sets the line of interrupt `intid` to `level`: an SPI, or for an
    /// `intid` below 32, the PPI of vCPU `cpu`.
    ///
    /// # Errors
    ///
    /// Errors when the hypervisor refuses it.
    fn set_line(&self, cpu: usize, intid: u32, level: bool) -> Result<(), String>;
}

/// The PPIs whose lines hvi drives on KVM: `hvi-time`'s. The others belong
/// to the in-kernel timers and PMU.
pub(crate) const OWNED_PPIS: u32 = 1 << hvitime::INTID;

/// `GICC_APR0`..`GICC_APR3`.
const APR_COUNT: u64 = 4;

/// The line levels hvi's devices hold, in the canonical form's layout:
/// `spis` one bit per interrupt in 8 words (word 0 unused), `ppis` one
/// word per vCPU with the PPIs in bits 16-31.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lines {
    pub spis: Vec<u32>,
    pub ppis: Vec<u32>,
}

impl Lines {
    /// Returns the lines of `state`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn of(state: &Gicv2State) -> Self {
        Self {
            spis: state.dist.line_level.clone(),
            ppis: state.cpus.iter().map(|c| c.line0).collect(),
        }
    }
}

/// The level-triggered interrupts of bit word `word` (32 interrupts) under
/// the configuration `icfgr`: those whose edge bit is clear.
fn level_mask(icfgr: &[u32], word: usize) -> u32 {
    let mut mask = 0;
    for bit in 0..32 {
        let irq = word * 32 + bit;
        let cfg = icfgr[irq / 16] >> ((irq % 16) * 2);
        if cfg & 2 == 0 {
            mask |= 1 << bit;
        }
    }
    mask
}

/// Packs four bytes of `bytes` from `at`, the first in the low byte.
fn word_of(bytes: &[u8], at: usize, mask: u8) -> u32 {
    (0..4).fold(0, |acc, i| {
        acc | (u32::from(bytes[at + i] & mask) << (i * 8))
    })
}

/// Unpacks `word` into four bytes of `bytes` from `at`.
fn put_word(bytes: &mut [u8], at: usize, word: u32) {
    for i in 0..4 {
        bytes[at + i] = (word >> (i * 8)) as u8;
    }
}

/// One bit per SGI of `sources` with any source CPU set.
fn sgi_pending(sources: &[u8], cpu_mask: u8) -> u32 {
    (0..16).fold(0, |acc, i| {
        if sources[i] & cpu_mask != 0 {
            acc | (1 << i)
        } else {
            acc
        }
    })
}

/// One register write and the value it must read back.
struct Reg {
    name: String,
    bank: Bank,
    cpu: usize,
    offset: u64,
    /// What [`import`] writes, or `None` for a register it only checks.
    write: Option<u32>,
    /// What the register reads once [`import`] is done.
    expect: u32,
}

/// The register writes that load `s` into a vGIC of `ncpu` vCPUs, in the
/// order KVM needs them, each with the value it must then read back.
fn plan(s: &Gicv2State, ncpu: usize) -> Vec<Reg> {
    let d: &DistState = &s.dist;
    let cpu_mask = ((1u32 << ncpu) - 1) as u8;
    let mut regs = Vec::new();
    let mut push = |name: String, bank, cpu, offset, write: Option<u32>, expect| {
        regs.push(Reg {
            name,
            bank,
            cpu,
            offset,
            write,
            expect,
        });
    };
    let dist = |name: &str, offset: u64, value: u32| (format!("GICD_{name}"), offset, value);

    // GICD_IIDR first: it makes GICD_IGROUPR writable.
    let (n, o, v) = dist("IIDR", gicd::IIDR, GICD_IIDR);
    push(n, Bank::Dist, 0, o, Some(v), v);
    let (n, o, v) = dist("CTLR", gicd::CTLR, d.ctlr & 1);
    push(n, Bank::Dist, 0, o, Some(v), v);

    // Group, configuration, priority and targets.
    for (cpu, _) in s.cpus.iter().enumerate() {
        let v = d.igroupr[0];
        push(
            format!("cpu{cpu} GICD_IGROUPR0"),
            Bank::Dist,
            cpu,
            gicd::IGROUPR,
            Some(v),
            v,
        );
    }
    for w in 1..WORDS {
        let v = d.igroupr[w];
        let off = gicd::IGROUPR + 4 * w as u64;
        push(format!("GICD_IGROUPR{w}"), Bank::Dist, 0, off, Some(v), v);
    }
    for w in 2..NR_IRQS / 16 {
        let v = d.icfgr[w] & CFG_EDGE_BITS;
        let off = gicd::ICFGR + 4 * w as u64;
        push(format!("GICD_ICFGR{w}"), Bank::Dist, 0, off, Some(v), v);
    }
    for (cpu, c) in s.cpus.iter().enumerate() {
        for w in 0..8 {
            let v = word_of(&c.ipriorityr0, w * 4, PRIO_MASK);
            let off = gicd::IPRIORITYR + 4 * w as u64;
            push(
                format!("cpu{cpu} GICD_IPRIORITYR{w}"),
                Bank::Dist,
                cpu,
                off,
                Some(v),
                v,
            );
        }
    }
    for w in 8..NR_IRQS / 4 {
        let v = word_of(&d.ipriorityr, w * 4, PRIO_MASK);
        let off = gicd::IPRIORITYR + 4 * w as u64;
        push(
            format!("GICD_IPRIORITYR{w}"),
            Bank::Dist,
            0,
            off,
            Some(v),
            v,
        );
    }
    for w in 8..NR_IRQS / 4 {
        let v = word_of(&d.itargetsr, w * 4, cpu_mask);
        let off = gicd::ITARGETSR + 4 * w as u64;
        push(format!("GICD_ITARGETSR{w}"), Bank::Dist, 0, off, Some(v), v);
    }

    // Enable, active and pending: each cleared, then set.
    let pairs: [(&str, u64, u64); 3] = [
        ("ENABLER", gicd::ICENABLER, gicd::ISENABLER),
        ("ACTIVER", gicd::ICACTIVER, gicd::ISACTIVER),
        ("PENDR", gicd::ICPENDR, gicd::ISPENDR),
    ];
    for (name, clear, set) in pairs {
        for (cpu, c) in s.cpus.iter().enumerate() {
            let (write, expect) = match name {
                "ENABLER" => (c.isenabler0, c.isenabler0),
                "ACTIVER" => (c.isactiver0, c.isactiver0),
                // The SGIs come from GICD_SPENDSGIR below; a PPI reads
                // pending while hvi holds its line high.
                _ => {
                    let ppis = c.latch0 & 0xffff_0000;
                    let lines = c.line0 & OWNED_PPIS;
                    (ppis, ppis | lines | sgi_pending(&c.sgi_sources, cpu_mask))
                }
            };
            push(
                format!("cpu{cpu} GICD_IC{name}0"),
                Bank::Dist,
                cpu,
                clear,
                Some(u32::MAX),
                expect,
            );
            push(
                format!("cpu{cpu} GICD_IS{name}0"),
                Bank::Dist,
                cpu,
                set,
                Some(write),
                expect,
            );
        }
        for w in 1..WORDS {
            let (write, expect) = match name {
                "ENABLER" => (d.isenabler[w], d.isenabler[w]),
                "ACTIVER" => (d.isactiver[w], d.isactiver[w]),
                _ => (
                    d.latch[w],
                    d.latch[w] | (d.line_level[w] & level_mask(&d.icfgr, w)),
                ),
            };
            let off = 4 * w as u64;
            push(
                format!("GICD_IC{name}{w}"),
                Bank::Dist,
                0,
                clear + off,
                Some(u32::MAX),
                expect,
            );
            push(
                format!("GICD_IS{name}{w}"),
                Bank::Dist,
                0,
                set + off,
                Some(write),
                expect,
            );
        }
    }
    for (cpu, c) in s.cpus.iter().enumerate() {
        for w in 0..4 {
            let v = word_of(&c.sgi_sources, w * 4, cpu_mask);
            let off = gicd::SPENDSGIR + 4 * w as u64;
            push(
                format!("cpu{cpu} GICD_SPENDSGIR{w}"),
                Bank::Dist,
                cpu,
                off,
                Some(v),
                v,
            );
        }
    }

    // The CPU interfaces.
    for (cpu, c) in s.cpus.iter().enumerate() {
        let regs = [
            ("CTLR", gicc::CTLR, c.ctlr & GICC_CTLR_MASK),
            ("PMR", gicc::PMR, (c.pmr & u32::from(PRIO_MASK)) >> 3),
            ("BPR", gicc::BPR, c.bpr & 7),
            ("ABPR", gicc::ABPR, c.abpr & 7),
        ];
        for (name, off, v) in regs {
            push(
                format!("cpu{cpu} GICC_{name}"),
                Bank::Cpu,
                cpu,
                off,
                Some(v),
                v,
            );
        }
        for n in 0..APR_COUNT {
            let v = c.apr[n as usize];
            push(
                format!("cpu{cpu} GICC_APR{n}"),
                Bank::Cpu,
                cpu,
                gicc::APR + 4 * n,
                Some(v),
                v,
            );
        }
    }
    regs
}

/// Why KVM's vGICv2 cannot hold `s`, or nothing when it can.
fn refusals(s: &Gicv2State) -> Vec<String> {
    let mut why = Vec::new();
    for (cpu, c) in s.cpus.iter().enumerate() {
        if c.apr[1..].iter().any(|&a| a != 0) {
            why.push(format!(
                "cpu{cpu} has GICC_APR1-3 {:#x?}, which a GICv2 host does not have",
                &c.apr[1..]
            ));
        }
        let foreign = c.line0 & 0xffff_0000 & !OWNED_PPIS;
        if foreign != 0 {
            why.push(format!(
                "cpu{cpu} has PPI lines {foreign:#010x} high, and on KVM only the in-kernel \
                 timers and PMU drive PPIs other than {}",
                hvitime::INTID
            ));
        }
    }
    why
}

/// Loads `s` into the vGIC, sets the lines hvi drives, and reads every
/// register back. Returns how many registers it checked.
///
/// # Errors
///
/// Errors when `s` does not fit the vGIC, when KVM refuses an access, and
/// when a register reads back otherwise than `s` says, naming each.
pub(crate) fn import(gic: &impl VgicV2, s: &Gicv2State) -> Result<usize, String> {
    let ncpu = gic.ncpu();
    s.check_shape(ncpu)?;
    let why = refusals(s);
    if !why.is_empty() {
        return Err(format!(
            "the vGICv2 cannot hold this state: {}",
            why.join("; ")
        ));
    }
    let regs = plan(s, ncpu);
    for r in &regs {
        if let Some(v) = r.write {
            gic.write(r.bank, r.cpu, r.offset, v)
                .map_err(|e| format!("writing {} = {v:#x}: {e}", r.name))?;
        }
    }
    // The lines, after the registers: a level line set before its
    // configuration would latch an edge.
    let d = &s.dist;
    for w in 1..WORDS {
        let level = level_mask(&d.icfgr, w);
        for bit in (0..32).filter(|b| level & (1 << b) != 0) {
            let intid = (w * 32 + bit) as u32;
            gic.set_line(0, intid, d.line_level[w] & (1 << bit) != 0)
                .map_err(|e| format!("setting the line of SPI {intid}: {e}"))?;
        }
    }
    for (cpu, c) in s.cpus.iter().enumerate() {
        gic.set_line(cpu, hvitime::INTID, c.line0 & OWNED_PPIS != 0)
            .map_err(|e| format!("setting cpu{cpu}'s PPI {} line: {e}", hvitime::INTID))?;
    }
    let mut wrong = Vec::new();
    for r in &regs {
        match gic.read(r.bank, r.cpu, r.offset) {
            Ok(v) if v == r.expect => {}
            Ok(v) => wrong.push(format!("{} reads {v:#x}, not {:#x}", r.name, r.expect)),
            Err(e) => wrong.push(format!("{} does not read back: {e}", r.name)),
        }
    }
    if !wrong.is_empty() {
        return Err(format!(
            "the vGICv2 does not hold the state written to it: {}",
            wrong.join("; ")
        ));
    }
    Ok(regs.len())
}

/// Reads the vGIC's state, with `lines` the levels hvi's devices hold.
///
/// # Errors
///
/// Errors when KVM refuses an access, when `lines` does not fit the vGIC,
/// and when the vCPUs' banked `GICD_IGROUPR0` differ, which the canonical
/// form cannot hold.
pub(crate) fn export(gic: &impl VgicV2, lines: &Lines) -> Result<Gicv2State, String> {
    let ncpu = gic.ncpu();
    if lines.spis.len() != WORDS || lines.ppis.len() != ncpu {
        return Err(format!(
            "the line levels have {} SPI words and {} vCPUs, not {WORDS} and {ncpu}",
            lines.spis.len(),
            lines.ppis.len()
        ));
    }
    let rd = |bank, cpu: usize, offset: u64, name: &str| {
        gic.read(bank, cpu, offset)
            .map_err(|e| format!("reading cpu{cpu} {name}: {e}"))
    };
    let words = |base: u64, name: &str| -> Result<Vec<u32>, String> {
        let mut v = vec![0; WORDS];
        for (w, slot) in v.iter_mut().enumerate().skip(1) {
            *slot = rd(Bank::Dist, 0, base + 4 * w as u64, name)?;
        }
        Ok(v)
    };
    let bytes = |base: u64, name: &str| -> Result<Vec<u8>, String> {
        let mut v = vec![0u8; NR_IRQS];
        for w in 8..NR_IRQS / 4 {
            put_word(&mut v, w * 4, rd(Bank::Dist, 0, base + 4 * w as u64, name)?);
        }
        Ok(v)
    };

    let mut icfgr = vec![0; NR_IRQS / 16];
    for (w, slot) in icfgr.iter_mut().enumerate().skip(2) {
        *slot = rd(Bank::Dist, 0, gicd::ICFGR + 4 * w as u64, "GICD_ICFGR")?;
    }
    let mut igroupr = words(gicd::IGROUPR, "GICD_IGROUPR")?;
    igroupr[0] = rd(Bank::Dist, 0, gicd::IGROUPR, "GICD_IGROUPR0")?;
    for cpu in 1..ncpu {
        let g = rd(Bank::Dist, cpu, gicd::IGROUPR, "GICD_IGROUPR0")?;
        if g != igroupr[0] {
            return Err(format!(
                "cpu{cpu}'s GICD_IGROUPR0 is {g:#x} and cpu0's {:#x}; the canonical form \
                 holds one",
                igroupr[0]
            ));
        }
    }
    let pending = words(gicd::ISPENDR, "GICD_ISPENDR")?;
    let mut line_level = lines.spis.clone();
    line_level[0] = 0;
    let latch = (0..WORDS)
        .map(|w| {
            if w == 0 {
                0
            } else {
                pending[w] & !(line_level[w] & level_mask(&icfgr, w))
            }
        })
        .collect();
    let dist = DistState {
        ctlr: rd(Bank::Dist, 0, gicd::CTLR, "GICD_CTLR")? & 1,
        igroupr,
        isenabler: words(gicd::ISENABLER, "GICD_ISENABLER")?,
        latch,
        line_level,
        isactiver: words(gicd::ISACTIVER, "GICD_ISACTIVER")?,
        ipriorityr: bytes(gicd::IPRIORITYR, "GICD_IPRIORITYR")?,
        itargetsr: bytes(gicd::ITARGETSR, "GICD_ITARGETSR")?,
        icfgr,
    };

    let mut cpus = Vec::with_capacity(ncpu);
    for cpu in 0..ncpu {
        let mut ipriorityr0 = vec![0u8; 32];
        for w in 0..8 {
            let off = gicd::IPRIORITYR + 4 * w as u64;
            put_word(
                &mut ipriorityr0,
                w * 4,
                rd(Bank::Dist, cpu, off, "GICD_IPRIORITYR")?,
            );
        }
        let mut sgi_sources = vec![0u8; 16];
        for w in 0..4 {
            let off = gicd::SPENDSGIR + 4 * w as u64;
            put_word(
                &mut sgi_sources,
                w * 4,
                rd(Bank::Dist, cpu, off, "GICD_SPENDSGIR")?,
            );
        }
        let mut apr = Vec::with_capacity(APR_COUNT as usize);
        for n in 0..APR_COUNT {
            apr.push(rd(Bank::Cpu, cpu, gicc::APR + 4 * n, "GICC_APR")?);
        }
        let line0 = lines.ppis[cpu] & 0xffff_0000;
        let pending0 = rd(Bank::Dist, cpu, gicd::ISPENDR, "GICD_ISPENDR0")?;
        cpus.push(CpuState {
            ctlr: rd(Bank::Cpu, cpu, gicc::CTLR, "GICC_CTLR")? & GICC_CTLR_MASK,
            pmr: (rd(Bank::Cpu, cpu, gicc::PMR, "GICC_PMR")? << 3) & u32::from(PRIO_MASK),
            bpr: (rd(Bank::Cpu, cpu, gicc::BPR, "GICC_BPR")? & 7).max(BPR_MIN),
            abpr: (rd(Bank::Cpu, cpu, gicc::ABPR, "GICC_ABPR")? & 7).max(ABPR_MIN),
            apr,
            isenabler0: rd(Bank::Dist, cpu, gicd::ISENABLER, "GICD_ISENABLER0")?,
            // PPIs are level: a pending bit with the line high is the line.
            latch0: pending0 & !line0,
            line0,
            isactiver0: rd(Bank::Dist, cpu, gicd::ISACTIVER, "GICD_ISACTIVER0")?,
            ipriorityr0,
            sgi_sources,
        });
    }
    Ok(Gicv2State { dist, cpus })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::devices::gicv2::Gicv2;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// A vGICv2 with the userspace semantics [`import`] relies on: banked
    /// interrupts 0-31, set and clear register pairs, `GICD_ISPENDR`
    /// reading the latch or a level line, SGI sources, `GICC_PMR` shifted
    /// and `GICC_APR1-3` reading 0.
    #[derive(Default)]
    pub(crate) struct Fake {
        ncpu: usize,
        regs: RefCell<HashMap<(usize, u64), u32>>,
        cpu_regs: RefCell<HashMap<(usize, u64), u32>>,
        /// (cpu, intid) -> level, cpu 0 for SPIs.
        lines: RefCell<HashMap<(usize, u32), bool>>,
        /// A register that drops writes, to show the readback catches it.
        drops: Option<(Bank, u64)>,
        groups_writable: RefCell<bool>,
    }

    impl Fake {
        pub(crate) fn new(ncpu: usize) -> Self {
            let f = Self {
                ncpu,
                ..Self::default()
            };
            for cpu in 0..ncpu {
                // SGIs enabled at reset, as KVM does.
                f.regs.borrow_mut().insert((cpu, gicd::ISENABLER), 0xffff);
            }
            f
        }

        /// The key of a distributor register: banked for the first word
        /// of each bit array and the first 8 words of each byte array.
        fn key(&self, cpu: usize, offset: u64) -> (usize, u64) {
            let banked = match offset {
                0x080..=0x3ff => offset % 0x80 == 0,
                0x400..=0xbff => offset % 0x400 < 0x20,
                0xf10..=0xf2f => true,
                _ => false,
            };
            (if banked { cpu } else { 0 }, offset)
        }

        fn bits(&self, cpu: usize, offset: u64) -> u32 {
            *self.regs.borrow().get(&self.key(cpu, offset)).unwrap_or(&0)
        }

        fn line_word(&self, cpu: usize, word: u64) -> u32 {
            let lines = self.lines.borrow();
            (0..32).fold(0, |acc, b| {
                let intid = (word * 32 + b) as u32;
                let who = if intid < 32 { cpu } else { 0 };
                if lines.get(&(who, intid)) == Some(&true) {
                    acc | (1 << b)
                } else {
                    acc
                }
            })
        }
    }

    impl VgicV2 for Fake {
        fn ncpu(&self) -> usize {
            self.ncpu
        }

        fn read(&self, bank: Bank, cpu: usize, offset: u64) -> Result<u32, String> {
            if bank == Bank::Cpu {
                if (gicc::APR + 4..gicc::APR + 16).contains(&offset) {
                    return Ok(0);
                }
                return Ok(*self.cpu_regs.borrow().get(&(cpu, offset)).unwrap_or(&0));
            }
            Ok(match offset {
                gicd::IIDR => GICD_IIDR,
                0x180..=0x1ff => self.bits(cpu, offset - 0x80),
                0x280..=0x2ff => self.read(bank, cpu, offset - 0x80)?,
                0x380..=0x3ff => self.bits(cpu, offset - 0x80),
                0x200..=0x27f => {
                    let w = (offset - 0x200) / 4;
                    let cfg: Vec<u32> = (0..16u64)
                        .map(|i| {
                            if i == 0 {
                                CFG_EDGE_BITS
                            } else {
                                self.bits(cpu, gicd::ICFGR + 4 * i)
                            }
                        })
                        .collect();
                    let level = if w == 0 {
                        0xffff_0000
                    } else {
                        level_mask(&cfg, w as usize)
                    };
                    let sgis = if w == 0 {
                        let mut v = 0;
                        for k in 0..4u64 {
                            let src = self.bits(cpu, gicd::SPENDSGIR + 4 * k);
                            for i in 0..4 {
                                if (src >> (i * 8)) & 0xff != 0 {
                                    v |= 1 << (k * 4 + i);
                                }
                            }
                        }
                        v
                    } else {
                        0
                    };
                    self.bits(cpu, offset) | (self.line_word(cpu, w) & level) | sgis
                }
                gicd::CPENDSGIR..=0xf1f => self.bits(cpu, offset + 0x10),
                _ => self.bits(cpu, offset),
            })
        }

        fn write(&self, bank: Bank, cpu: usize, offset: u64, value: u32) -> Result<(), String> {
            if self.drops == Some((bank, offset)) {
                return Ok(());
            }
            if bank == Bank::Cpu {
                self.cpu_regs.borrow_mut().insert((cpu, offset), value);
                return Ok(());
            }
            let mut regs = self.regs.borrow_mut();
            let key = self.key(cpu, offset);
            match offset {
                gicd::IIDR => {
                    if value != GICD_IIDR {
                        return Err("EINVAL".into());
                    }
                    *self.groups_writable.borrow_mut() = true;
                }
                0x080..=0x0ff if !*self.groups_writable.borrow() => {}
                // Set registers OR in, clear registers clear their pair.
                0x100..=0x17f | 0x200..=0x27f | 0x300..=0x37f => {
                    *regs.entry(key).or_default() |= value;
                }
                0x180..=0x1ff | 0x280..=0x2ff | 0x380..=0x3ff => {
                    let pair = self.key(cpu, offset - 0x80);
                    *regs.entry(pair).or_default() &= !value;
                    if offset == gicd::ICPENDR {
                        for k in 0..4u64 {
                            regs.remove(&(cpu, gicd::SPENDSGIR + 4 * k));
                        }
                    }
                }
                gicd::SPENDSGIR..=0xf2f => {
                    *regs.entry(key).or_default() |= value;
                }
                _ => {
                    regs.insert(key, value);
                }
            }
            Ok(())
        }

        fn set_line(&self, cpu: usize, intid: u32, level: bool) -> Result<(), String> {
            let who = if intid < 32 { cpu } else { 0 };
            self.lines.borrow_mut().insert((who, intid), level);
            Ok(())
        }
    }

    /// A 2-CPU software GIC programmed as Linux programs it, with an edge
    /// SPI latched, a level SPI's line high, another level SPI latched, an
    /// SGI pending from both CPUs, an active interrupt and cpu1's hvi-time
    /// line high.
    pub(crate) fn busy_state() -> Gicv2State {
        let mut g = Gicv2::new(2);
        for cpu in 0..2 {
            g.dist_write(cpu, gicd::ICENABLER, 4, 0xffff_0000);
            g.dist_write(cpu, gicd::ISENABLER, 4, 0x0010_ffff);
            for w in 0..8 {
                g.dist_write(cpu, gicd::IPRIORITYR + w * 4, 4, 0xa0a0_a0a0);
            }
            g.cpu_write(cpu, gicc::PMR, 4, 0xf0);
            g.cpu_write(cpu, gicc::CTLR, 4, 1);
        }
        for w in 2..16 {
            g.dist_write(0, gicd::ICFGR + w * 4, 4, 0);
        }
        // SPI 40 edge.
        g.dist_write(0, gicd::ICFGR + 8, 4, 2 << 16);
        for w in 8..64 {
            g.dist_write(0, gicd::IPRIORITYR + w * 4, 4, 0x8080_8080);
            g.dist_write(0, gicd::ITARGETSR + w * 4, 4, 0x0101_0101);
        }
        g.dist_write(0, gicd::ITARGETSR + 48, 4, 0x0202_0202);
        g.dist_write(0, gicd::ISENABLER + 4, 4, 0xffff_ffff);
        g.dist_write(0, gicd::CTLR, 4, 1);
        g.dist_write(0, gicd::ISPENDR + 4, 4, 1 << 8); // SPI 40, edge
        g.dist_write(0, gicd::ISPENDR + 4, 4, 1 << 3); // SPI 35, level, latched
        g.set_spi_line(33, true);
        g.set_ppi_line(1, hvitime::INTID, true);
        // SGI 1 from cpu0 to cpu1, SGI 1 from cpu1 to itself.
        g.dist_write(0, gicd::SGIR, 4, (2 << 16) | 1);
        g.dist_write(1, gicd::SGIR, 4, (2 << 24) | 1);
        // cpu0 takes SPI 33: active, and its priority in APR0.
        assert_eq!(g.cpu_read(0, gicc::IAR, 4), 33);
        g.state()
    }

    #[test]
    fn a_state_round_trips_through_the_register_views() {
        let s = busy_state();
        assert_eq!(s.cpus[0].apr[0], 1 << (0x80 >> 3));
        assert_ne!(s.cpus[1].sgi_sources[1], 0);
        let gic = Fake::new(2);
        let checked = import(&gic, &s).unwrap();
        assert!(checked > 200, "{checked}");
        // The lines hvi drives followed the state.
        assert_eq!(gic.lines.borrow().get(&(0, 33)), Some(&true));
        assert_eq!(gic.lines.borrow().get(&(1, hvitime::INTID)), Some(&true));
        assert_eq!(gic.lines.borrow().get(&(0, hvitime::INTID)), Some(&false));
        // The edge SPI's line is not driven.
        assert_eq!(gic.lines.borrow().get(&(0, 40)), None);
        let back = export(&gic, &Lines::of(&s)).unwrap();
        assert_eq!(back, s);
        // A second import over the first is exact too.
        let mut quiet = s.clone();
        quiet.dist.latch[1] = 0;
        quiet.dist.line_level[1] = 0;
        quiet.cpus[1].line0 = 0;
        quiet.cpus[1].sgi_sources = vec![0; 16];
        quiet.cpus[1].latch0 &= !0xffff;
        import(&gic, &quiet).unwrap();
        assert_eq!(export(&gic, &Lines::of(&quiet)).unwrap(), quiet);
    }

    #[test]
    fn a_fresh_cpu_interface_exports_the_binary_points_the_guest_reads() {
        let gic = Fake::new(1);
        let lines = Lines {
            spis: vec![0; WORDS],
            ppis: vec![0],
        };
        let c = &export(&gic, &lines).unwrap().cpus[0];
        assert_eq!((c.bpr, c.abpr), (BPR_MIN, ABPR_MIN));
        assert_eq!(Gicv2::new(1).state().cpus[0].bpr, c.bpr);
    }

    #[test]
    fn a_register_that_does_not_take_its_value_refuses_the_import() {
        let s = busy_state();
        let gic = Fake {
            drops: Some((Bank::Cpu, gicc::PMR)),
            ..Fake::new(2)
        };
        let e = import(&gic, &s).unwrap_err();
        assert!(e.contains("cpu0 GICC_PMR reads 0x0, not 0x1e"), "{e}");
        assert!(e.contains("cpu1 GICC_PMR"), "{e}");
    }

    #[test]
    fn a_state_kvm_cannot_hold_is_refused_before_any_write() {
        let mut s = busy_state();
        s.cpus[0].apr[2] = 1;
        s.cpus[1].line0 |= 1 << 27;
        let gic = Fake::new(2);
        let e = import(&gic, &s).unwrap_err();
        assert!(e.contains("cpu0 has GICC_APR1-3"), "{e}");
        assert!(e.contains("cpu1 has PPI lines 0x08000000"), "{e}");
        assert!(gic.regs.borrow().len() == 2, "only the reset values");
        assert!(import(&Fake::new(1), &busy_state())
            .unwrap_err()
            .contains("2 CPUs, this machine 1"));
    }

    #[test]
    fn a_latched_level_interrupt_with_its_line_high_exports_as_the_line() {
        // The one loss the v2 view forces: KVM reads latch || line.
        let mut s = busy_state();
        s.dist.latch[1] |= 1 << 1; // SPI 33, whose line is high
        let gic = Fake::new(2);
        import(&gic, &s).unwrap();
        let back = export(&gic, &Lines::of(&s)).unwrap();
        assert_eq!(back.dist.latch[1] & 2, 0);
        s.dist.latch[1] &= !2;
        assert_eq!(back, s);
    }
}

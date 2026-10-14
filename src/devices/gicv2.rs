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

//! A software GICv2: distributor and CPU interface, for a backend without an
//! in-kernel interrupt controller.
//!
//! The portable machine profile (`docs/portable-profile.md`) gives the guest
//! one GICv2 on every host. KVM on the Raspberry Pi 5 has a vGICv2 in the
//! kernel; Hypervisor.framework without `hv_gic` has none, so hvi models it
//! here. The model mirrors what a guest on the Pi reads, so a checkpoint of
//! either is the same device:
//!
//! - `GICD_TYPER` = ((ncpu - 1) << 5) | 7 (256 interrupts), `GICD_IIDR`
//!   0x4b00343b, `GICC_IIDR` 0x0202143b.
//! - Five priority bits: writes keep bits 7:3. `GICC_PMR` reads 0xf8 after a
//!   0xff write. `GICC_BPR` resets to 2 and never reads below it, `GICC_ABPR`
//!   resets to 3.
//! - SGIs are enabled at reset and edge-triggered, `GICD_ICFGR0` reads
//!   0xaaaaaaaa and `GICD_ICFGR1` reads 0 (PPIs level), both read-only. SPIs
//!   reset to edge and their configuration is writable.
//! - `GICD_ITARGETSR0-7` are banked and read-only, one bit for the reading CPU
//!   in every byte.
//!
//! Each interrupt keeps its enable, line level, software latch and active
//! state apart. An interrupt is pending when it is enabled and, for an edge
//! interrupt, its latch is set, or, for a level interrupt, its line is high
//! or its latch is set. The latch is set by a `GICD_ISPENDR` write, by a
//! rising edge on an edge-configured line and, for an SGI, by `GICD_SGIR` or
//! `GICD_SPENDSGIR`. `GICD_ICPENDR` clears it, as does acknowledging an edge
//! interrupt. A level interrupt's latch is cleared when the guest
//! deactivates it, as KVM's vGICv2 does (`vgic_v2_fold_lr_state`, "Clear
//! soft pending state when level irqs have been acked"), so the two hosts
//! agree on what an acknowledged, latched level interrupt does next.
//!
//! Only EOImode 0 is modelled: `GICC_EOIR` drops the priority and
//! deactivates. There is no `GICC_DIR`, no virtualisation extension and no
//! security extension; every interrupt is signalled as an IRQ.
//!
//! The model knows nothing of the hypervisor. The backend routes guest MMIO
//! here, drives device and timer lines, and asks [`Gicv2::irq_pending`]
//! before each guest entry. A change that may give another vCPU an interrupt
//! returns that vCPU in [`Outcome::wake`], and an end of interrupt returns
//! the interrupt in [`Outcome::eoi`].

use serde::{Deserialize, Serialize};

/// The number of interrupts the distributor implements, SGIs and PPIs
/// included.
pub const NR_IRQS: usize = 256;
/// The most CPU interfaces a GICv2 addresses.
pub const MAX_CPUS: usize = 8;
/// The interrupt ID `GICC_IAR` returns when nothing can be acknowledged.
pub const SPURIOUS: u32 = 1023;
/// `GICD_IIDR` as a guest on the Pi reads it.
pub const GICD_IIDR: u32 = 0x4b00_343b;
/// `GICC_IIDR` as a guest on the Pi reads it.
pub const GICC_IIDR: u32 = 0x0202_143b;
/// The part of the CPU interface window that holds registers. The rest of
/// the 64 KiB window reads as zero and ignores writes.
pub const GICC_DECODED: u64 = 0x1000;

/// Number of 32-interrupt words in a bit-per-interrupt register.
const WORDS: usize = NR_IRQS / 32;
/// The priority bits the model implements.
const PRIO_MASK: u8 = 0xf8;
/// The configuration bits a guest can set: one edge bit per interrupt, the
/// odd bit of each pair.
const CFG_EDGE_BITS: u32 = 0xaaaa_aaaa;
/// The reset value of `GICC_BPR`, also its minimum.
const BPR_MIN: u32 = 2;
/// The reset value of `GICC_ABPR`, also its minimum.
const ABPR_MIN: u32 = 3;
/// The `GICC_CTLR` bits that hold what is written: EnableGrp0, EnableGrp1
/// and the four bypass-disable bits (5-8). AckCtl, FIQEn, CBPR and EOImode
/// read as zero.
const GICC_CTLR_MASK: u32 = 0x1e3;
/// The running priority of a CPU interface with nothing active.
const IDLE_PRIORITY: u32 = 0xff;

/// Distributor register offsets.
mod gicd {
    pub const CTLR: u64 = 0x000;
    pub const TYPER: u64 = 0x004;
    pub const IIDR: u64 = 0x008;
    pub const IGROUPR: u64 = 0x080;
    pub const ISENABLER: u64 = 0x100;
    pub const ICENABLER: u64 = 0x180;
    pub const ISPENDR: u64 = 0x200;
    pub const ICPENDR: u64 = 0x280;
    pub const ISACTIVER: u64 = 0x300;
    pub const ICACTIVER: u64 = 0x380;
    pub const IPRIORITYR: u64 = 0x400;
    pub const ITARGETSR: u64 = 0x800;
    pub const ICFGR: u64 = 0xc00;
    pub const SGIR: u64 = 0xf00;
    pub const CPENDSGIR: u64 = 0xf10;
    pub const SPENDSGIR: u64 = 0xf20;
}

/// CPU interface register offsets.
mod gicc {
    pub const CTLR: u64 = 0x00;
    pub const PMR: u64 = 0x04;
    pub const BPR: u64 = 0x08;
    pub const IAR: u64 = 0x0c;
    pub const EOIR: u64 = 0x10;
    pub const RPR: u64 = 0x14;
    pub const HPPIR: u64 = 0x18;
    pub const ABPR: u64 = 0x1c;
    pub const AIAR: u64 = 0x20;
    pub const AHPPIR: u64 = 0x28;
    pub const APR: u64 = 0xd0;
    pub const IIDR: u64 = 0xfc;
}

/// What a guest access or a line change asks of the backend.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// The CPUs, one bit each, that now have an interrupt to take. The
    /// backend wakes each of them that is not the calling vCPU.
    pub wake: u8,
    /// The interrupt a `GICC_EOIR` write just ended, if it ended one.
    pub eoi: Option<u32>,
}

/// The distributor's state for the shared interrupts. Word 0 of each bit
/// array and bytes 0-31 of the byte arrays are unused: SGIs and PPIs are
/// banked in [`CpuIf`].
#[derive(Debug, Clone)]
struct Dist {
    ctlr: u32,
    igroupr: [u32; WORDS],
    enabled: [u32; WORDS],
    latch: [u32; WORDS],
    line: [u32; WORDS],
    active: [u32; WORDS],
    priority: [u8; NR_IRQS],
    targets: [u8; NR_IRQS],
    icfgr: [u32; NR_IRQS / 16],
}

/// One CPU interface and the banked distributor state of interrupts 0-31.
#[derive(Debug, Clone)]
struct CpuIf {
    ctlr: u32,
    pmr: u32,
    bpr: u32,
    abpr: u32,
    apr: [u32; 4],
    enabled0: u32,
    /// The software latch of the PPIs. An SGI's latch is its source mask.
    latch0: u32,
    line0: u32,
    active0: u32,
    priority0: [u8; 32],
    /// For each SGI, the CPUs that sent it and whose request is pending.
    sgi_sources: [u8; 16],
}

impl CpuIf {
    fn new() -> Self {
        Self {
            ctlr: 0,
            pmr: 0,
            bpr: BPR_MIN,
            abpr: ABPR_MIN,
            apr: [0; 4],
            enabled0: 0x0000_ffff,
            latch0: 0,
            line0: 0,
            active0: 0,
            priority0: [0; 32],
            sgi_sources: [0; 16],
        }
    }

    /// The pending bits of interrupts 0-31, before enable and active.
    fn pending0(&self) -> u32 {
        let mut sgi = 0u32;
        for (id, sources) in self.sgi_sources.iter().enumerate() {
            if *sources != 0 {
                sgi |= 1 << id;
            }
        }
        // PPIs are level-sensitive.
        sgi | ((self.line0 | self.latch0) & 0xffff_0000)
    }

    /// The running priority: that of the highest active priority group, or
    /// [`IDLE_PRIORITY`].
    fn running_priority(&self) -> u32 {
        // Five priority bits give 32 groups, all in APR0.
        if self.apr[0] == 0 {
            IDLE_PRIORITY
        } else {
            self.apr[0].trailing_zeros() << 3
        }
    }
}

/// The software GICv2.
#[derive(Debug, Clone)]
pub struct Gicv2 {
    dist: Dist,
    cpus: Vec<CpuIf>,
}

/// A bit test in a word array.
fn bit(words: &[u32], irq: usize) -> bool {
    words[irq / 32] & (1 << (irq % 32)) != 0
}

/// Sets or clears one bit in a word array.
fn put(words: &mut [u32], irq: usize, on: bool) {
    if on {
        words[irq / 32] |= 1 << (irq % 32);
    } else {
        words[irq / 32] &= !(1 << (irq % 32));
    }
}

impl Gicv2 {
    /// Returns a GICv2 in its reset state with `ncpu` CPU interfaces.
    ///
    /// # Panics
    ///
    /// Panics when `ncpu` is 0 or above [`MAX_CPUS`]. The backend checks the
    /// vCPU count before it builds the machine.
    #[must_use]
    pub fn new(ncpu: u32) -> Self {
        let ncpu = ncpu as usize;
        assert!((1..=MAX_CPUS).contains(&ncpu), "a GICv2 has 1-8 CPUs");
        let mut icfgr = [CFG_EDGE_BITS; NR_IRQS / 16];
        // Fixed: SGIs edge (word 0), PPIs level (word 1).
        icfgr[1] = 0;
        Self {
            dist: Dist {
                ctlr: 0,
                igroupr: [0; WORDS],
                enabled: [0; WORDS],
                latch: [0; WORDS],
                line: [0; WORDS],
                active: [0; WORDS],
                priority: [0; NR_IRQS],
                targets: [0; NR_IRQS],
                icfgr,
            },
            cpus: (0..ncpu).map(|_| CpuIf::new()).collect(),
        }
    }

    /// Returns the number of CPU interfaces.
    #[must_use]
    pub fn ncpu(&self) -> usize {
        self.cpus.len()
    }

    /// The CPUs that exist, one bit each.
    fn cpu_mask(&self) -> u8 {
        ((1u16 << self.cpus.len()) - 1) as u8
    }

    fn is_edge(&self, irq: usize) -> bool {
        // SGIs are edge, PPIs level; both fixed.
        match irq {
            0..=15 => true,
            16..=31 => false,
            _ => self.dist.icfgr[irq / 16] & (2 << ((irq % 16) * 2)) != 0,
        }
    }

    fn priority(&self, cpu: usize, irq: usize) -> u8 {
        if irq < 32 {
            self.cpus[cpu].priority0[irq]
        } else {
            self.dist.priority[irq]
        }
    }

    fn group(&self, irq: usize) -> u32 {
        // IGROUPR0 is shared here; see `Gicv2State`.
        u32::from(bit(&self.dist.igroupr, irq))
    }

    /// The group priority of `prio` for `irq` under `cpu`'s binary point.
    fn group_priority(&self, cpu: usize, irq: usize, prio: u8) -> u32 {
        let c = &self.cpus[cpu];
        let bpr = if self.group(irq) == 0 { c.bpr } else { c.abpr };
        u32::from(prio) & (0xff << (bpr + 1)) & 0xff
    }

    /// The pending bits of word `w` that target `cpu`: pending (latch or
    /// line), enabled and not active.
    fn candidates(&self, cpu: usize, w: usize) -> u32 {
        if w == 0 {
            let c = &self.cpus[cpu];
            return c.pending0() & c.enabled0 & !c.active0;
        }
        let d = &self.dist;
        let level = !self.edge_word(w);
        let pending = d.latch[w] | (d.line[w] & level);
        let mut bits = pending & d.enabled[w] & !d.active[w];
        let mut out = 0;
        while bits != 0 {
            let b = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            if d.targets[w * 32 + b] & (1 << cpu) != 0 {
                out |= 1 << b;
            }
        }
        out
    }

    /// The edge bits of word `w`, one per interrupt.
    fn edge_word(&self, w: usize) -> u32 {
        let mut out = 0;
        for half in 0..2 {
            let cfg = self.dist.icfgr[w * 2 + half];
            for i in 0..16 {
                if cfg & (2 << (i * 2)) != 0 {
                    out |= 1 << (half * 16 + i);
                }
            }
        }
        out
    }

    /// The highest-priority pending interrupt for `cpu` with its priority,
    /// ignoring the priority mask and the running priority. Ties go to the
    /// lowest ID.
    fn highest_pending(&self, cpu: usize) -> Option<(usize, u8)> {
        let mut best: Option<(usize, u8)> = None;
        for w in 0..WORDS {
            let mut bits = self.candidates(cpu, w);
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let irq = w * 32 + b;
                let prio = self.priority(cpu, irq);
                if best.map_or(true, |(_, p)| prio < p) {
                    best = Some((irq, prio));
                }
            }
        }
        best
    }

    /// The interrupt `cpu` would acknowledge now: the highest pending one,
    /// when the distributor and the interface forward it and its priority
    /// beats the priority mask and the running priority.
    fn deliverable(&self, cpu: usize) -> Option<usize> {
        if self.dist.ctlr & 1 == 0 {
            return None;
        }
        let (irq, prio) = self.highest_pending(cpu)?;
        let c = &self.cpus[cpu];
        let group_enable = 1 << self.group(irq);
        if c.ctlr & group_enable == 0 {
            return None;
        }
        if u32::from(prio) >= c.pmr {
            return None;
        }
        if self.group_priority(cpu, irq, prio) >= c.running_priority() {
            return None;
        }
        Some(irq)
    }

    /// Returns whether `cpu` has an interrupt to take, which the backend
    /// signals as the vCPU's IRQ line.
    #[must_use]
    pub fn irq_pending(&self, cpu: usize) -> bool {
        cpu < self.cpus.len() && self.deliverable(cpu).is_some()
    }

    /// The CPUs in `mask` that have an interrupt to take.
    fn wake_of(&self, mask: u8) -> u8 {
        (0..self.cpus.len())
            .filter(|cpu| mask & (1 << cpu) != 0 && self.irq_pending(*cpu))
            .fold(0, |acc, cpu| acc | (1 << cpu))
    }

    /// Sets the line of shared interrupt `intid` (32-255) to `level`.
    ///
    /// A rising edge on an edge-configured line sets its latch. Returns the
    /// CPUs to wake. An ID outside the SPI range is ignored.
    pub fn set_spi_line(&mut self, intid: u32, level: bool) -> Outcome {
        let irq = intid as usize;
        if !(32..NR_IRQS).contains(&irq) {
            return Outcome::default();
        }
        let was = bit(&self.dist.line, irq);
        put(&mut self.dist.line, irq, level);
        if level && !was && self.is_edge(irq) {
            put(&mut self.dist.latch, irq, true);
        }
        if !level {
            return Outcome::default();
        }
        Outcome {
            wake: self.wake_of(self.dist.targets[irq]),
            eoi: None,
        }
    }

    /// Sets `cpu`'s line of private interrupt `intid` (16-31) to `level`.
    ///
    /// PPIs are level-sensitive. Returns the CPU to wake. An ID outside the
    /// PPI range, or a CPU that does not exist, is ignored.
    pub fn set_ppi_line(&mut self, cpu: usize, intid: u32, level: bool) -> Outcome {
        if !(16..32).contains(&intid) || cpu >= self.cpus.len() {
            return Outcome::default();
        }
        put(
            std::slice::from_mut(&mut self.cpus[cpu].line0),
            intid as usize,
            level,
        );
        if !level {
            return Outcome::default();
        }
        Outcome {
            wake: self.wake_of(1 << cpu),
            eoi: None,
        }
    }

    // ----- Distributor -----------------------------------------------------

    /// Reads `width` bytes at `offset` of the distributor, as `cpu`.
    #[must_use]
    pub fn dist_read(&self, cpu: usize, offset: u64, width: u8) -> u32 {
        let word = self.dist_read_word(cpu, offset & !3);
        sub_word(word, offset, width)
    }

    fn dist_read_word(&self, cpu: usize, offset: u64) -> u32 {
        let Some(c) = self.cpus.get(cpu) else {
            return 0;
        };
        let d = &self.dist;
        let n = ((offset & 0x7f) / 4) as usize;
        match offset {
            gicd::CTLR => d.ctlr,
            gicd::TYPER => ((self.cpus.len() as u32 - 1) << 5) | (WORDS as u32 - 1),
            gicd::IIDR => GICD_IIDR,
            o if (gicd::IGROUPR..gicd::IGROUPR + 0x80).contains(&o) => {
                d.igroupr.get(n).copied().unwrap_or(0)
            }
            o if (gicd::ISENABLER..gicd::ICENABLER + 0x80).contains(&o) => match n {
                0 => c.enabled0,
                n if n < WORDS => d.enabled[n],
                _ => 0,
            },
            o if (gicd::ISPENDR..gicd::ICPENDR + 0x80).contains(&o) => match n {
                0 => c.pending0(),
                n if n < WORDS => d.latch[n] | (d.line[n] & !self.edge_word(n)),
                _ => 0,
            },
            o if (gicd::ISACTIVER..gicd::ICACTIVER + 0x80).contains(&o) => match n {
                0 => c.active0,
                n if n < WORDS => d.active[n],
                _ => 0,
            },
            o if (gicd::IPRIORITYR..gicd::IPRIORITYR + NR_IRQS as u64).contains(&o) => {
                let base = (o - gicd::IPRIORITYR) as usize;
                bytes_le(|i| self.priority(cpu, base + i))
            }
            o if (gicd::ITARGETSR..gicd::ITARGETSR + NR_IRQS as u64).contains(&o) => {
                let base = (o - gicd::ITARGETSR) as usize;
                bytes_le(|i| {
                    if base + i < 32 {
                        1 << cpu
                    } else {
                        d.targets[base + i]
                    }
                })
            }
            o if (gicd::ICFGR..gicd::ICFGR + (NR_IRQS / 4) as u64).contains(&o) => {
                d.icfgr[((o - gicd::ICFGR) / 4) as usize]
            }
            o if (gicd::CPENDSGIR..gicd::SPENDSGIR + 0x10).contains(&o) => {
                let base = ((o - gicd::CPENDSGIR) % 0x10) as usize;
                bytes_le(|i| c.sgi_sources[base + i])
            }
            _ => 0,
        }
    }

    /// Writes the low `width` bytes of `value` at `offset` of the
    /// distributor, as `cpu`.
    ///
    /// The priority, target and SGI pending registers take byte accesses;
    /// the others take whole words, and a narrower write to them is
    /// ignored.
    pub fn dist_write(&mut self, cpu: usize, offset: u64, width: u8, value: u32) -> Outcome {
        if cpu >= self.cpus.len() {
            return Outcome::default();
        }
        let byte_reg = (gicd::IPRIORITYR..gicd::ICFGR).contains(&offset)
            || (gicd::CPENDSGIR..gicd::SPENDSGIR + 0x10).contains(&offset);
        if byte_reg && width < 4 {
            for i in 0..u64::from(width) {
                let byte = (value >> (i * 8)) as u8;
                self.dist_write_byte(cpu, offset + i, byte);
            }
            return self.after_dist_write(cpu, offset);
        }
        if width < 4 {
            return Outcome::default();
        }
        let offset = offset & !3;
        if byte_reg {
            for i in 0..4 {
                self.dist_write_byte(cpu, offset + i, (value >> (i * 8)) as u8);
            }
            return self.after_dist_write(cpu, offset);
        }
        self.dist_write_word(cpu, offset, value)
    }

    fn dist_write_byte(&mut self, cpu: usize, offset: u64, byte: u8) {
        let cpu_mask = self.cpu_mask();
        match offset {
            o if (gicd::IPRIORITYR..gicd::IPRIORITYR + NR_IRQS as u64).contains(&o) => {
                let irq = (o - gicd::IPRIORITYR) as usize;
                if irq < 32 {
                    self.cpus[cpu].priority0[irq] = byte & PRIO_MASK;
                } else {
                    self.dist.priority[irq] = byte & PRIO_MASK;
                }
            }
            o if (gicd::ITARGETSR..gicd::ITARGETSR + NR_IRQS as u64).contains(&o) => {
                let irq = (o - gicd::ITARGETSR) as usize;
                // Bytes 0-31 are read-only.
                if irq >= 32 {
                    self.dist.targets[irq] = byte & cpu_mask;
                }
            }
            o if (gicd::CPENDSGIR..gicd::CPENDSGIR + 0x10).contains(&o) => {
                let sgi = (o - gicd::CPENDSGIR) as usize;
                self.cpus[cpu].sgi_sources[sgi] &= !byte;
            }
            o if (gicd::SPENDSGIR..gicd::SPENDSGIR + 0x10).contains(&o) => {
                let sgi = (o - gicd::SPENDSGIR) as usize;
                self.cpus[cpu].sgi_sources[sgi] |= byte & cpu_mask;
            }
            _ => {}
        }
    }

    /// The CPUs to wake after a write to the byte registers at `offset`.
    fn after_dist_write(&self, cpu: usize, offset: u64) -> Outcome {
        let mask = if (gicd::ITARGETSR..gicd::ITARGETSR + NR_IRQS as u64).contains(&offset)
            || (gicd::IPRIORITYR..gicd::IPRIORITYR + NR_IRQS as u64).contains(&offset)
        {
            self.cpu_mask()
        } else {
            1 << cpu
        };
        Outcome {
            wake: self.wake_of(mask),
            eoi: None,
        }
    }

    fn dist_write_word(&mut self, cpu: usize, offset: u64, value: u32) -> Outcome {
        let n = ((offset & 0x7f) / 4) as usize;
        let banked = n == 0;
        let all = self.cpu_mask();
        let mask = match offset {
            gicd::CTLR => {
                self.dist.ctlr = value & 1;
                all
            }
            o if (gicd::IGROUPR..gicd::IGROUPR + 0x80).contains(&o) => {
                if let Some(word) = self.dist.igroupr.get_mut(n) {
                    *word = value;
                }
                all
            }
            o if (gicd::ISENABLER..gicd::ISENABLER + 0x80).contains(&o) => {
                self.update_word(cpu, n, value, |c| &mut c.enabled0, |d| &mut d.enabled, true)
            }
            o if (gicd::ICENABLER..gicd::ICENABLER + 0x80).contains(&o) => {
                self.update_word(
                    cpu,
                    n,
                    value,
                    |c| &mut c.enabled0,
                    |d| &mut d.enabled,
                    false,
                );
                0
            }
            o if (gicd::ISPENDR..gicd::ISPENDR + 0x80).contains(&o) => {
                // SGI bits are set through GICD_SGIR or GICD_SPENDSGIR, as on
                // KVM, which ignores a guest's ISPENDR0 write to them.
                let value = if banked { value & 0xffff_0000 } else { value };
                self.update_word(cpu, n, value, |c| &mut c.latch0, |d| &mut d.latch, true)
            }
            o if (gicd::ICPENDR..gicd::ICPENDR + 0x80).contains(&o) => {
                let value = if banked { value & 0xffff_0000 } else { value };
                self.update_word(cpu, n, value, |c| &mut c.latch0, |d| &mut d.latch, false);
                0
            }
            o if (gicd::ISACTIVER..gicd::ISACTIVER + 0x80).contains(&o) => {
                self.update_word(cpu, n, value, |c| &mut c.active0, |d| &mut d.active, true);
                0
            }
            o if (gicd::ICACTIVER..gicd::ICACTIVER + 0x80).contains(&o) => {
                self.update_word(cpu, n, value, |c| &mut c.active0, |d| &mut d.active, false)
            }
            o if (gicd::ICFGR..gicd::ICFGR + (NR_IRQS / 4) as u64).contains(&o) => {
                let w = ((o - gicd::ICFGR) / 4) as usize;
                // Words 0 and 1 (SGIs and PPIs) are read-only.
                if w >= 2 {
                    self.dist.icfgr[w] = value & CFG_EDGE_BITS;
                }
                0
            }
            gicd::SGIR => self.send_sgi(cpu, value),
            _ => 0,
        };
        Outcome {
            wake: self.wake_of(mask),
            eoi: None,
        }
    }

    /// Sets (`set`) or clears the bits of `value` in word `n` of a bit
    /// register, banked word 0 in `cpu`'s interface. Returns the CPUs the
    /// change can give an interrupt.
    fn update_word(
        &mut self,
        cpu: usize,
        n: usize,
        value: u32,
        banked: impl Fn(&mut CpuIf) -> &mut u32,
        shared: impl Fn(&mut Dist) -> &mut [u32; WORDS],
        set: bool,
    ) -> u8 {
        let word = if n == 0 {
            banked(&mut self.cpus[cpu])
        } else if n < WORDS {
            &mut shared(&mut self.dist)[n]
        } else {
            return 0;
        };
        if set {
            *word |= value;
        } else {
            *word &= !value;
        }
        if n == 0 {
            1 << cpu
        } else {
            self.cpu_mask()
        }
    }

    /// Handles a `GICD_SGIR` write from `cpu`. Returns the targets.
    fn send_sgi(&mut self, cpu: usize, value: u32) -> u8 {
        let sgi = (value & 0xf) as usize;
        let all = self.cpu_mask();
        let targets = match (value >> 24) & 3 {
            0 => ((value >> 16) & 0xff) as u8 & all,
            1 => all & !(1 << cpu),
            2 => 1 << cpu,
            _ => 0,
        };
        for (t, c) in self.cpus.iter_mut().enumerate() {
            if targets & (1 << t) != 0 {
                c.sgi_sources[sgi] |= 1 << cpu;
            }
        }
        targets
    }

    // ----- CPU interface ---------------------------------------------------

    /// Reads `width` bytes at `offset` of `cpu`'s interface.
    ///
    /// Reading `GICC_IAR` acknowledges an interrupt, so this takes the model
    /// mutably.
    pub fn cpu_read(&mut self, cpu: usize, offset: u64, _width: u8) -> u32 {
        if cpu >= self.cpus.len() || offset >= GICC_DECODED {
            return 0;
        }
        let c = &self.cpus[cpu];
        match offset & !3 {
            gicc::CTLR => c.ctlr,
            gicc::PMR => c.pmr,
            gicc::BPR => c.bpr,
            gicc::ABPR => c.abpr,
            gicc::IAR => self.acknowledge(cpu),
            gicc::RPR => c.running_priority(),
            gicc::HPPIR => self.hppir(cpu),
            gicc::AIAR | gicc::AHPPIR => SPURIOUS,
            o if (gicc::APR..gicc::APR + 0x10).contains(&o) => {
                c.apr[((o - gicc::APR) / 4) as usize]
            }
            gicc::IIDR => GICC_IIDR,
            _ => 0,
        }
    }

    /// Writes `value` at `offset` of `cpu`'s interface.
    pub fn cpu_write(&mut self, cpu: usize, offset: u64, _width: u8, value: u32) -> Outcome {
        if cpu >= self.cpus.len() || offset >= GICC_DECODED {
            return Outcome::default();
        }
        let c = &mut self.cpus[cpu];
        match offset & !3 {
            gicc::CTLR => c.ctlr = value & GICC_CTLR_MASK,
            gicc::PMR => c.pmr = value & u32::from(PRIO_MASK),
            gicc::BPR => c.bpr = (value & 7).max(BPR_MIN),
            gicc::ABPR => c.abpr = (value & 7).max(ABPR_MIN),
            gicc::EOIR => return self.end_of_interrupt(cpu, value),
            o if (gicc::APR..gicc::APR + 0x10).contains(&o) => {
                c.apr[((o - gicc::APR) / 4) as usize] = value;
            }
            _ => return Outcome::default(),
        }
        Outcome {
            wake: self.wake_of(1 << cpu),
            eoi: None,
        }
    }

    /// `GICC_IAR`: acknowledges the interrupt `cpu` would take, or returns
    /// [`SPURIOUS`].
    fn acknowledge(&mut self, cpu: usize) -> u32 {
        let Some(irq) = self.deliverable(cpu) else {
            return SPURIOUS;
        };
        let prio = self.priority(cpu, irq);
        let group = self.group_priority(cpu, irq, prio);
        let edge = self.is_edge(irq);
        let c = &mut self.cpus[cpu];
        c.apr[0] |= 1 << (group >> 3);
        let mut value = irq as u32;
        if irq < 16 {
            let sources = c.sgi_sources[irq];
            let source = sources.trailing_zeros();
            c.sgi_sources[irq] &= !(1 << source);
            value |= source << 10;
            put(std::slice::from_mut(&mut c.active0), irq, true);
        } else if irq < 32 {
            put(std::slice::from_mut(&mut c.active0), irq, true);
            if edge {
                put(std::slice::from_mut(&mut c.latch0), irq, false);
            }
        } else {
            put(&mut self.dist.active, irq, true);
            if edge {
                put(&mut self.dist.latch, irq, false);
            }
        }
        value
    }

    /// `GICC_EOIR`: drops the running priority and deactivates the
    /// interrupt.
    fn end_of_interrupt(&mut self, cpu: usize, value: u32) -> Outcome {
        let irq = (value & 0x3ff) as usize;
        if irq >= NR_IRQS {
            return Outcome::default();
        }
        // The priority drop clears the highest active priority, which is
        // the interrupt's own when the guest ends interrupts in order.
        let c = &mut self.cpus[cpu];
        if c.apr[0] != 0 {
            c.apr[0] &= c.apr[0] - 1;
        }
        let level = !self.is_edge(irq);
        let mut mask = 1 << cpu;
        if irq < 32 {
            let c = &mut self.cpus[cpu];
            put(std::slice::from_mut(&mut c.active0), irq, false);
            if level {
                put(std::slice::from_mut(&mut c.latch0), irq, false);
            }
        } else {
            put(&mut self.dist.active, irq, false);
            if level {
                put(&mut self.dist.latch, irq, false);
            }
            mask |= self.dist.targets[irq];
        }
        Outcome {
            wake: self.wake_of(mask),
            eoi: Some(irq as u32),
        }
    }

    /// `GICC_HPPIR`: the highest-priority pending interrupt, whatever the
    /// priority mask and the running priority.
    fn hppir(&self, cpu: usize) -> u32 {
        match self.highest_pending(cpu) {
            Some((irq, _)) if irq < 16 => {
                let source = self.cpus[cpu].sgi_sources[irq].trailing_zeros();
                irq as u32 | (source << 10)
            }
            Some((irq, _)) => irq as u32,
            None => SPURIOUS,
        }
    }

    // ----- State -----------------------------------------------------------

    /// Returns the model's state in the canonical checkpoint form.
    #[must_use]
    pub fn state(&self) -> Gicv2State {
        let d = &self.dist;
        let mut icfgr = d.icfgr.to_vec();
        icfgr[0] = 0;
        icfgr[1] = 0;
        let zero_low = |words: &[u32; WORDS]| {
            let mut v = words.to_vec();
            v[0] = 0;
            v
        };
        let bytes_high = |bytes: &[u8; NR_IRQS]| {
            let mut v = bytes.to_vec();
            v[..32].fill(0);
            v
        };
        Gicv2State {
            dist: DistState {
                ctlr: d.ctlr,
                igroupr: d.igroupr.to_vec(),
                isenabler: zero_low(&d.enabled),
                latch: zero_low(&d.latch),
                line_level: zero_low(&d.line),
                isactiver: zero_low(&d.active),
                ipriorityr: bytes_high(&d.priority),
                itargetsr: bytes_high(&d.targets),
                icfgr,
            },
            cpus: self
                .cpus
                .iter()
                .map(|c| CpuState {
                    ctlr: c.ctlr,
                    pmr: c.pmr,
                    bpr: c.bpr,
                    abpr: c.abpr,
                    apr: c.apr.to_vec(),
                    isenabler0: c.enabled0,
                    latch0: (c.pending0() & 0xffff) | (c.latch0 & 0xffff_0000),
                    line0: c.line0 & 0xffff_0000,
                    isactiver0: c.active0,
                    ipriorityr0: c.priority0.to_vec(),
                    sgi_sources: c.sgi_sources.to_vec(),
                })
                .collect(),
        }
    }

    /// Replaces the model's state with `state`.
    ///
    /// Values are masked to what the registers can hold. The banked and
    /// fixed slots of the distributor arrays are ignored, and an SGI's latch
    /// is its source mask.
    ///
    /// # Errors
    ///
    /// Errors when `state` has another number of CPUs, or an array of the
    /// wrong length. The model is unchanged then.
    pub fn restore(&mut self, state: &Gicv2State) -> Result<(), String> {
        if state.cpus.len() != self.cpus.len() {
            return Err(format!(
                "GICv2 state has {} CPUs, this machine {}",
                state.cpus.len(),
                self.cpus.len()
            ));
        }
        let s = &state.dist;
        let words = |name: &str, v: &[u32], n: usize| -> Result<(), String> {
            if v.len() == n {
                Ok(())
            } else {
                Err(format!(
                    "GICv2 state: {name} has {} entries, not {n}",
                    v.len()
                ))
            }
        };
        words("igroupr", &s.igroupr, WORDS)?;
        words("isenabler", &s.isenabler, WORDS)?;
        words("latch", &s.latch, WORDS)?;
        words("line_level", &s.line_level, WORDS)?;
        words("isactiver", &s.isactiver, WORDS)?;
        words("icfgr", &s.icfgr, NR_IRQS / 16)?;
        if s.ipriorityr.len() != NR_IRQS || s.itargetsr.len() != NR_IRQS {
            return Err("GICv2 state: ipriorityr and itargetsr need 256 entries".into());
        }
        for (i, c) in state.cpus.iter().enumerate() {
            if c.apr.len() != 4 || c.ipriorityr0.len() != 32 || c.sgi_sources.len() != 16 {
                return Err(format!(
                    "GICv2 state: cpu {i} has an array of the wrong length"
                ));
            }
        }

        let cpu_mask = self.cpu_mask();
        let mut fresh = Gicv2::new(self.cpus.len() as u32);
        let d = &mut fresh.dist;
        d.ctlr = s.ctlr & 1;
        d.igroupr.copy_from_slice(&s.igroupr);
        let copy_high = |dst: &mut [u32; WORDS], src: &[u32]| {
            dst[1..].copy_from_slice(&src[1..]);
        };
        copy_high(&mut d.enabled, &s.isenabler);
        copy_high(&mut d.latch, &s.latch);
        copy_high(&mut d.line, &s.line_level);
        copy_high(&mut d.active, &s.isactiver);
        for irq in 32..NR_IRQS {
            d.priority[irq] = s.ipriorityr[irq] & PRIO_MASK;
            d.targets[irq] = s.itargetsr[irq] & cpu_mask;
        }
        for w in 2..NR_IRQS / 16 {
            d.icfgr[w] = s.icfgr[w] & CFG_EDGE_BITS;
        }
        for (c, cs) in fresh.cpus.iter_mut().zip(&state.cpus) {
            c.ctlr = cs.ctlr & GICC_CTLR_MASK;
            c.pmr = cs.pmr & u32::from(PRIO_MASK);
            c.bpr = (cs.bpr & 7).max(BPR_MIN);
            c.abpr = (cs.abpr & 7).max(ABPR_MIN);
            c.apr.copy_from_slice(&cs.apr);
            c.enabled0 = cs.isenabler0;
            c.latch0 = cs.latch0 & 0xffff_0000;
            c.line0 = cs.line0 & 0xffff_0000;
            c.active0 = cs.isactiver0;
            for (dst, src) in c.priority0.iter_mut().zip(&cs.ipriorityr0) {
                *dst = src & PRIO_MASK;
            }
            for (dst, src) in c.sgi_sources.iter_mut().zip(&cs.sgi_sources) {
                *dst = src & cpu_mask;
            }
        }
        *self = fresh;
        Ok(())
    }
}

/// Packs four bytes, the first in the low byte.
fn bytes_le(byte: impl Fn(usize) -> u8) -> u32 {
    (0..4).fold(0, |acc, i| acc | (u32::from(byte(i)) << (i * 8)))
}

/// The `width` bytes at `offset` of the aligned `word`.
fn sub_word(word: u32, offset: u64, width: u8) -> u32 {
    if width >= 4 {
        return word;
    }
    let shift = (offset & 3) * 8;
    let mask = (1u64 << (u32::from(width) * 8)) - 1;
    ((u64::from(word) >> shift) & mask) as u32
}

/// The GICv2's state in the canonical checkpoint form (`platform.json`
/// "irq", kind "gicv2").
///
/// The distributor arrays cover every interrupt, but their slots for
/// interrupts 0-31 are always 0 here: SGIs and PPIs are banked, so their
/// state is in each CPU's entry. `icfgr` words 0 and 1, fixed on every GICv2
/// this profile runs on, are 0 too. `igroupr` word 0 is the one exception:
/// the model keeps a single group register for interrupts 0-31, and Linux
/// never writes it. A CPU's `latch0` holds its PPI latches and, for each SGI,
/// whether any source is pending; `sgi_sources` has the sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gicv2State {
    pub dist: DistState,
    pub cpus: Vec<CpuState>,
}

/// The distributor part of [`Gicv2State`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistState {
    pub ctlr: u32,
    pub igroupr: Vec<u32>,
    pub isenabler: Vec<u32>,
    pub latch: Vec<u32>,
    pub line_level: Vec<u32>,
    pub isactiver: Vec<u32>,
    pub ipriorityr: Vec<u8>,
    pub itargetsr: Vec<u8>,
    pub icfgr: Vec<u32>,
}

/// One CPU interface and its banked distributor state in [`Gicv2State`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuState {
    pub ctlr: u32,
    pub pmr: u32,
    pub bpr: u32,
    pub abpr: u32,
    pub apr: Vec<u32>,
    pub isenabler0: u32,
    pub latch0: u32,
    pub line0: u32,
    pub isactiver0: u32,
    pub ipriorityr0: Vec<u8>,
    pub sgi_sources: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values Linux's GICv2 driver programs at boot (irq-gic.c,
    /// irq-gic-common.c): both enables on, PMR 0xf0, every priority 0xa0,
    /// every SPI to cpu0 and level.
    fn linux_init(gic: &mut Gicv2) {
        for cpu in 0..gic.ncpu() {
            gic.dist_write(cpu, gicd::ICENABLER, 4, 0xffff_0000);
            gic.dist_write(cpu, gicd::ISENABLER, 4, 0x0000_ffff);
            for w in 0..8 {
                gic.dist_write(cpu, gicd::IPRIORITYR + w * 4, 4, 0xa0a0_a0a0);
            }
            gic.cpu_write(cpu, gicc::PMR, 4, 0xf0);
            gic.cpu_write(cpu, gicc::CTLR, 4, 1);
        }
        for w in 2..16 {
            gic.dist_write(0, gicd::ICFGR + w * 4, 4, 0);
        }
        for w in 8..64 {
            gic.dist_write(0, gicd::IPRIORITYR + w * 4, 4, 0xa0a0_a0a0);
            gic.dist_write(0, gicd::ITARGETSR + w * 4, 4, 0x0101_0101);
        }
        gic.dist_write(0, gicd::CTLR, 4, 1);
    }

    fn enable(gic: &mut Gicv2, cpu: usize, irq: u32) {
        gic.dist_write(
            cpu,
            gicd::ISENABLER + u64::from(irq / 32) * 4,
            4,
            1 << (irq % 32),
        );
    }

    fn set_prio(gic: &mut Gicv2, cpu: usize, irq: u32, prio: u8) {
        gic.dist_write(cpu, gicd::IPRIORITYR + u64::from(irq), 1, u32::from(prio));
    }

    fn make_edge(gic: &mut Gicv2, irq: u32) {
        let off = gicd::ICFGR + u64::from(irq / 16) * 4;
        let v = gic.dist_read(0, off, 4) | (2 << ((irq % 16) * 2));
        gic.dist_write(0, off, 4, v);
    }

    fn iar(gic: &mut Gicv2, cpu: usize) -> u32 {
        gic.cpu_read(cpu, gicc::IAR, 4)
    }

    fn eoi(gic: &mut Gicv2, cpu: usize, value: u32) -> Outcome {
        gic.cpu_write(cpu, gicc::EOIR, 4, value)
    }

    #[test]
    fn identity_registers_match_the_pi() {
        let one = Gicv2::new(1);
        assert_eq!(one.dist_read(0, gicd::TYPER, 4), 0x7);
        let two = Gicv2::new(2);
        assert_eq!(two.dist_read(0, gicd::TYPER, 4), 0x27);
        assert_eq!(two.dist_read(1, gicd::IIDR, 4), 0x4b00_343b);
        let mut two = two;
        assert_eq!(two.cpu_read(1, gicc::IIDR, 4), 0x0202_143b);
    }

    #[test]
    fn configuration_defaults_and_read_only_words() {
        let mut gic = Gicv2::new(1);
        assert_eq!(gic.dist_read(0, gicd::ICFGR, 4), 0xaaaa_aaaa);
        assert_eq!(gic.dist_read(0, gicd::ICFGR + 4, 4), 0);
        assert_eq!(gic.dist_read(0, gicd::ICFGR + 8, 4), 0xaaaa_aaaa);
        // SGIs and PPIs keep their configuration.
        gic.dist_write(0, gicd::ICFGR, 4, 0);
        gic.dist_write(0, gicd::ICFGR + 4, 4, 0xffff_ffff);
        assert_eq!(gic.dist_read(0, gicd::ICFGR, 4), 0xaaaa_aaaa);
        assert_eq!(gic.dist_read(0, gicd::ICFGR + 4, 4), 0);
        // SPIs take only the edge bits, which Linux reads back.
        gic.dist_write(0, gicd::ICFGR + 8, 4, 0xffff_ffff);
        assert_eq!(gic.dist_read(0, gicd::ICFGR + 8, 4), 0xaaaa_aaaa);
        gic.dist_write(0, gicd::ICFGR + 8, 4, 0);
        assert_eq!(gic.dist_read(0, gicd::ICFGR + 8, 4), 0);
        // SGIs are enabled at reset.
        assert_eq!(gic.dist_read(0, gicd::ISENABLER, 4), 0x0000_ffff);
        assert_eq!(gic.dist_read(0, gicd::ICENABLER, 4), 0x0000_ffff);
    }

    #[test]
    fn targets_of_sgis_and_ppis_are_banked_and_read_only() {
        let mut gic = Gicv2::new(2);
        for w in 0..8 {
            assert_eq!(gic.dist_read(0, gicd::ITARGETSR + w * 4, 4), 0x0101_0101);
            assert_eq!(gic.dist_read(1, gicd::ITARGETSR + w * 4, 4), 0x0202_0202);
        }
        gic.dist_write(0, gicd::ITARGETSR, 4, 0x0202_0202);
        gic.dist_write(1, gicd::ITARGETSR + 1, 1, 0x01);
        assert_eq!(gic.dist_read(0, gicd::ITARGETSR, 4), 0x0101_0101);
        assert_eq!(gic.dist_read(1, gicd::ITARGETSR, 4), 0x0202_0202);
        // Linux reads its own bit one byte at a time.
        assert_eq!(gic.dist_read(1, gicd::ITARGETSR + 3, 1), 0x02);
        // SPI targets are writable a byte at a time, and only to real CPUs.
        gic.dist_write(0, gicd::ITARGETSR + 40, 1, 0xff);
        assert_eq!(gic.dist_read(0, gicd::ITARGETSR + 40, 1), 0x03);
        assert_eq!(gic.dist_read(0, gicd::ITARGETSR + 40, 4), 0x0000_0003);
    }

    #[test]
    fn priorities_keep_five_bits_and_bank_below_32() {
        let mut gic = Gicv2::new(2);
        gic.dist_write(0, gicd::IPRIORITYR + 32, 4, 0xa0a1_a2a3);
        assert_eq!(gic.dist_read(0, gicd::IPRIORITYR + 32, 4), 0xa0a0_a0a0);
        gic.dist_write(0, gicd::IPRIORITYR + 41, 1, 0x47);
        assert_eq!(gic.dist_read(0, gicd::IPRIORITYR + 41, 1), 0x40);
        gic.dist_write(1, gicd::IPRIORITYR + 27, 1, 0x88);
        assert_eq!(gic.dist_read(1, gicd::IPRIORITYR + 27, 1), 0x88);
        assert_eq!(gic.dist_read(0, gicd::IPRIORITYR + 27, 1), 0);
    }

    #[test]
    fn cpu_interface_defaults_and_masks() {
        let mut gic = Gicv2::new(1);
        assert_eq!(gic.cpu_read(0, gicc::BPR, 4), 2);
        assert_eq!(gic.cpu_read(0, gicc::ABPR, 4), 3);
        gic.cpu_write(0, gicc::BPR, 4, 0);
        assert_eq!(gic.cpu_read(0, gicc::BPR, 4), 2);
        gic.cpu_write(0, gicc::PMR, 4, 0xff);
        assert_eq!(gic.cpu_read(0, gicc::PMR, 4), 0xf8);
        gic.cpu_write(0, gicc::CTLR, 4, 0xffff_ffff);
        assert_eq!(gic.cpu_read(0, gicc::CTLR, 4), 0x1e3);
        assert_eq!(gic.cpu_read(0, gicc::RPR, 4), 0xff);
        assert_eq!(gic.cpu_read(0, 0x1000, 4), 0);
    }

    #[test]
    fn nothing_pending_reads_spurious() {
        let mut gic = Gicv2::new(1);
        linux_init(&mut gic);
        assert!(!gic.irq_pending(0));
        assert_eq!(iar(&mut gic, 0), SPURIOUS);
        assert_eq!(gic.cpu_read(0, gicc::HPPIR, 4), SPURIOUS);
    }

    #[test]
    fn level_line_stays_pending_after_eoi_while_high() {
        let mut gic = Gicv2::new(1);
        linux_init(&mut gic);
        enable(&mut gic, 0, 34);
        let out = gic.set_spi_line(34, true);
        assert_eq!(out.wake, 1);
        assert!(gic.irq_pending(0));
        assert_eq!(iar(&mut gic, 0), 34);
        // Active blocks it while the line stays high.
        assert!(!gic.irq_pending(0));
        assert_eq!(gic.cpu_read(0, gicc::RPR, 4), 0xa0);
        assert_eq!(gic.cpu_read(0, gicc::APR, 4), 1 << (0xa0 >> 3));
        let out = eoi(&mut gic, 0, 34);
        assert_eq!(out.eoi, Some(34));
        assert_eq!(gic.cpu_read(0, gicc::APR, 4), 0);
        assert!(gic.irq_pending(0));
        gic.set_spi_line(34, false);
        assert!(!gic.irq_pending(0));
        assert_eq!(iar(&mut gic, 0), SPURIOUS);
    }

    #[test]
    fn edge_latch_is_cleared_by_acknowledge() {
        let mut gic = Gicv2::new(1);
        linux_init(&mut gic);
        make_edge(&mut gic, 40);
        enable(&mut gic, 0, 40);
        gic.set_spi_line(40, true);
        gic.set_spi_line(40, false);
        // The edge is latched after the line dropped.
        assert!(gic.irq_pending(0));
        assert_eq!(iar(&mut gic, 0), 40);
        eoi(&mut gic, 0, 40);
        assert!(!gic.irq_pending(0));
        // A line held high latches one edge, not a level.
        gic.set_spi_line(40, true);
        assert_eq!(iar(&mut gic, 0), 40);
        eoi(&mut gic, 0, 40);
        assert!(!gic.irq_pending(0));
    }

    #[test]
    fn higher_priority_wins_and_ties_go_to_the_lower_id() {
        let mut gic = Gicv2::new(1);
        linux_init(&mut gic);
        for irq in [33, 35, 36] {
            enable(&mut gic, 0, irq);
        }
        set_prio(&mut gic, 0, 36, 0x80);
        gic.set_spi_line(33, true);
        gic.set_spi_line(35, true);
        gic.set_spi_line(36, true);
        assert_eq!(gic.cpu_read(0, gicc::HPPIR, 4), 36);
        assert_eq!(iar(&mut gic, 0), 36);
        eoi(&mut gic, 0, 36);
        gic.set_spi_line(36, false);
        assert_eq!(iar(&mut gic, 0), 33);
    }

    #[test]
    fn priority_mask_holds_back_lower_priorities() {
        let mut gic = Gicv2::new(1);
        linux_init(&mut gic);
        enable(&mut gic, 0, 33);
        gic.set_spi_line(33, true);
        gic.cpu_write(0, gicc::PMR, 4, 0xa0);
        assert!(!gic.irq_pending(0));
        assert_eq!(iar(&mut gic, 0), SPURIOUS);
        // HPPIR ignores the mask.
        assert_eq!(gic.cpu_read(0, gicc::HPPIR, 4), 33);
        let out = gic.cpu_write(0, gicc::PMR, 4, 0xa8);
        assert_eq!(out.wake, 1);
        assert_eq!(iar(&mut gic, 0), 33);
    }

    #[test]
    fn an_active_interrupt_blocks_lower_and_equal_priorities() {
        let mut gic = Gicv2::new(1);
        linux_init(&mut gic);
        for irq in [33, 34, 35] {
            enable(&mut gic, 0, irq);
        }
        set_prio(&mut gic, 0, 33, 0x80);
        set_prio(&mut gic, 0, 34, 0x80);
        set_prio(&mut gic, 0, 35, 0x40);
        gic.set_spi_line(33, true);
        assert_eq!(iar(&mut gic, 0), 33);
        gic.set_spi_line(34, true);
        assert!(!gic.irq_pending(0), "equal priority does not preempt");
        gic.set_spi_line(35, true);
        assert!(gic.irq_pending(0), "higher priority preempts");
        assert_eq!(iar(&mut gic, 0), 35);
        assert_eq!(gic.cpu_read(0, gicc::RPR, 4), 0x40);
        gic.set_spi_line(35, false);
        eoi(&mut gic, 0, 35);
        assert_eq!(gic.cpu_read(0, gicc::RPR, 4), 0x80);
        assert!(!gic.irq_pending(0));
        eoi(&mut gic, 0, 33);
        gic.set_spi_line(33, false);
        assert_eq!(iar(&mut gic, 0), 34);
    }

    #[test]
    fn distributor_or_interface_disabled_forwards_nothing() {
        let mut gic = Gicv2::new(1);
        linux_init(&mut gic);
        enable(&mut gic, 0, 33);
        gic.set_spi_line(33, true);
        gic.dist_write(0, gicd::CTLR, 4, 0);
        assert!(!gic.irq_pending(0));
        gic.dist_write(0, gicd::CTLR, 4, 1);
        gic.cpu_write(0, gicc::CTLR, 4, 0);
        assert!(!gic.irq_pending(0));
        gic.cpu_write(0, gicc::CTLR, 4, 1);
        assert!(gic.irq_pending(0));
        // A disabled interrupt still reads pending.
        gic.dist_write(0, gicd::ICENABLER + 4, 4, 1 << 1);
        assert!(!gic.irq_pending(0));
        assert_eq!(gic.dist_read(0, gicd::ISPENDR + 4, 4), 1 << 1);
    }

    #[test]
    fn sgi_to_self_carries_the_source() {
        let mut gic = Gicv2::new(1);
        linux_init(&mut gic);
        let out = gic.dist_write(0, gicd::SGIR, 4, (2 << 24) | 5);
        assert_eq!(out.wake, 1);
        assert_eq!(gic.dist_read(0, gicd::ISPENDR, 4), 1 << 5);
        assert_eq!(gic.dist_read(0, gicd::SPENDSGIR + 5, 1), 0x01);
        assert_eq!(iar(&mut gic, 0), 5);
        assert_eq!(gic.dist_read(0, gicd::ISACTIVER, 4), 1 << 5);
        eoi(&mut gic, 0, 5);
        assert!(!gic.irq_pending(0));
    }

    #[test]
    fn sgi_between_cpus_wakes_the_target_with_each_source() {
        let mut gic = Gicv2::new(2);
        linux_init(&mut gic);
        let out = gic.dist_write(0, gicd::SGIR, 4, (0b10 << 16) | 3);
        assert_eq!(out.wake, 0b10);
        assert!(!gic.irq_pending(0));
        let out = gic.dist_write(1, gicd::SGIR, 4, (1 << 24) | 3);
        assert_eq!(out.wake, 0b01, "all but self");
        gic.dist_write(1, gicd::SGIR, 4, (2 << 24) | 3);
        // cpu1 has SGI 3 from cpu0 and from itself: lowest source first.
        assert_eq!(iar(&mut gic, 1), 3);
        eoi(&mut gic, 1, 3);
        assert_eq!(iar(&mut gic, 1), 3 | (1 << 10));
        eoi(&mut gic, 1, 3 | (1 << 10));
        assert!(!gic.irq_pending(1));
        assert_eq!(iar(&mut gic, 0), 3 | (1 << 10));
        // CPENDSGIR drops a source.
        gic.dist_write(0, gicd::SGIR, 4, (2 << 24) | 7);
        gic.dist_write(0, gicd::CPENDSGIR + 7, 1, 0xff);
        assert_eq!(gic.dist_read(0, gicd::SPENDSGIR + 7, 1), 0);
    }

    #[test]
    fn ispendr_latch_survives_the_line_dropping_until_icpendr() {
        let mut gic = Gicv2::new(1);
        linux_init(&mut gic);
        enable(&mut gic, 0, 42);
        gic.dist_write(0, gicd::ISPENDR + 4, 4, 1 << 10);
        assert!(gic.irq_pending(0));
        gic.set_spi_line(42, true);
        gic.set_spi_line(42, false);
        assert_eq!(gic.dist_read(0, gicd::ISPENDR + 4, 4), 1 << 10);
        gic.dist_write(0, gicd::ICPENDR + 4, 4, 1 << 10);
        assert_eq!(gic.dist_read(0, gicd::ISPENDR + 4, 4), 0);
        assert!(!gic.irq_pending(0));
        // With the line high, ICPENDR leaves the interrupt pending.
        gic.set_spi_line(42, true);
        gic.dist_write(0, gicd::ICPENDR + 4, 4, 1 << 10);
        assert_eq!(gic.dist_read(0, gicd::ISPENDR + 4, 4), 1 << 10);
    }

    #[test]
    fn a_level_latch_ends_with_the_interrupt() {
        let mut gic = Gicv2::new(1);
        linux_init(&mut gic);
        enable(&mut gic, 0, 42);
        gic.dist_write(0, gicd::ISPENDR + 4, 4, 1 << 10);
        assert_eq!(iar(&mut gic, 0), 42);
        // Still latched while active, as KVM reports it.
        assert_eq!(gic.dist_read(0, gicd::ISPENDR + 4, 4), 1 << 10);
        eoi(&mut gic, 0, 42);
        assert!(!gic.irq_pending(0));
        assert_eq!(gic.dist_read(0, gicd::ISPENDR + 4, 4), 0);
    }

    #[test]
    fn a_ppi_line_reaches_only_its_cpu() {
        let mut gic = Gicv2::new(2);
        linux_init(&mut gic);
        enable(&mut gic, 1, 27);
        let out = gic.set_ppi_line(1, 27, true);
        assert_eq!(out.wake, 0b10);
        assert!(!gic.irq_pending(0));
        assert_eq!(iar(&mut gic, 1), 27);
        let out = eoi(&mut gic, 1, 27);
        assert_eq!(out.eoi, Some(27));
        // Level: still high, so pending again.
        assert!(gic.irq_pending(1));
        gic.set_ppi_line(1, 27, false);
        assert!(!gic.irq_pending(1));
    }

    #[test]
    fn an_spi_wakes_only_its_targets() {
        let mut gic = Gicv2::new(2);
        linux_init(&mut gic);
        enable(&mut gic, 0, 50);
        gic.dist_write(0, gicd::ITARGETSR + 50, 1, 0b10);
        let out = gic.set_spi_line(50, true);
        assert_eq!(out.wake, 0b10);
        assert!(!gic.irq_pending(0));
        assert_eq!(iar(&mut gic, 1), 50);
    }

    #[test]
    fn the_state_round_trips_through_json() {
        let mut gic = Gicv2::new(2);
        linux_init(&mut gic);
        enable(&mut gic, 0, 34);
        make_edge(&mut gic, 40);
        enable(&mut gic, 0, 40);
        gic.set_spi_line(34, true);
        gic.set_spi_line(40, true);
        gic.dist_write(0, gicd::SGIR, 4, (0b11 << 16) | 2);
        enable(&mut gic, 1, 27);
        gic.set_ppi_line(1, 27, true);
        assert_eq!(iar(&mut gic, 0), 2);
        let state = gic.state();
        let json = serde_json::to_string(&state).unwrap();
        let back: Gicv2State = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
        let mut other = Gicv2::new(2);
        other.restore(&back).unwrap();
        assert_eq!(other.state(), state);
        // The restored model behaves as the original.
        for cpu in 0..2 {
            assert_eq!(iar(&mut other, cpu), iar(&mut gic, cpu));
        }
        assert!(Gicv2::new(1).restore(&back).is_err());
    }

    #[test]
    fn a_small_state_has_this_exact_json() {
        let mut gic = Gicv2::new(1);
        gic.dist_write(0, gicd::CTLR, 4, 1);
        gic.dist_write(0, gicd::ITARGETSR + 33, 1, 1);
        gic.dist_write(0, gicd::IPRIORITYR + 33, 1, 0xa0);
        gic.dist_write(0, gicd::ISENABLER + 4, 4, 1 << 1);
        gic.dist_write(0, gicd::ICFGR + 8, 4, 0);
        gic.set_spi_line(33, true);
        gic.cpu_write(0, gicc::PMR, 4, 0xf0);
        gic.cpu_write(0, gicc::CTLR, 4, 1);
        gic.dist_write(0, gicd::SGIR, 4, (2 << 24) | 1);
        let zeros = |n: usize| vec!["0"; n].join(",");
        let mut prio = vec!["0"; 256];
        prio[33] = "160";
        let mut targets = vec!["0"; 256];
        targets[33] = "1";
        let icfgr = format!("0,0,0,{}", vec!["2863311530"; 13].join(","));
        let expected = format!(
            concat!(
                r#"{{"dist":{{"ctlr":1,"igroupr":[{z8}],"isenabler":[0,2,0,0,0,0,0,0],"#,
                r#""latch":[{z8}],"line_level":[0,2,0,0,0,0,0,0],"isactiver":[{z8}],"#,
                r#""ipriorityr":[{prio}],"itargetsr":[{targets}],"icfgr":[{icfgr}]}},"#,
                r#""cpus":[{{"ctlr":1,"pmr":240,"bpr":2,"abpr":3,"apr":[0,0,0,0],"#,
                r#""isenabler0":65535,"latch0":2,"line0":0,"isactiver0":0,"#,
                r#""ipriorityr0":[{z32}],"sgi_sources":[0,1,{z14}]}}]}}"#
            ),
            z8 = zeros(8),
            z32 = zeros(32),
            z14 = zeros(14),
            prio = prio.join(","),
            targets = targets.join(","),
            icfgr = icfgr,
        );
        assert_eq!(serde_json::to_string(&gic.state()).unwrap(), expected);
    }

    #[test]
    fn restore_refuses_arrays_of_the_wrong_length() {
        let gic = Gicv2::new(1);
        let mut state = gic.state();
        state.dist.ipriorityr.pop();
        assert!(Gicv2::new(1).restore(&state).is_err());
        let mut state = gic.state();
        state.cpus[0].sgi_sources.push(0);
        assert!(Gicv2::new(1).restore(&state).is_err());
    }

    #[test]
    fn narrow_writes_to_word_registers_are_ignored() {
        let mut gic = Gicv2::new(1);
        gic.dist_write(0, gicd::CTLR, 1, 1);
        assert_eq!(gic.dist_read(0, gicd::CTLR, 4), 0);
        gic.dist_write(0, gicd::ISENABLER + 4, 2, 0xffff);
        assert_eq!(gic.dist_read(0, gicd::ISENABLER + 4, 4), 0);
    }
}

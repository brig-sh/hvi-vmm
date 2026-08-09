//! Tools that attach to a running guest through [`crate::plugin`].
//!
//! Two ship with the VMM, and between them they use every part of the seam:
//!
//! - [`MemoryDump`](crate::plugins::MemoryDump) writes guest RAM to a file,
//!   with the VM parked so the image is consistent. Post-mortem debugging, and
//!   the thing you want when a guest wedges and the console has stopped
//!   answering.
//! - [`IoTrace`](crate::plugins::IoTrace) logs every virtio-blk request and
//!   virtio-net frame as it crosses the device. The ledger already aggregates
//!   flows; this is the unaggregated version, for when the aggregate is what
//!   you distrust.
//!
//! [`Chain`](crate::plugins::Chain) runs several at once, since a boot takes
//! one plugin.
//!
//! These are also the worked examples. Between them they cover the two rules
//! that are easy to get wrong and fail quietly: a pause you win, you owe (see
//! `MemoryDump::safepoint`), and set
//! a flag then kick (see
//! `MemoryDump::attach`, where the
//! timer thread would otherwise never fire on an idle guest).

use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::plugin::{CpuHandle, IoSink, MemRegion, Plugin, VmHandle};

/// Runs several plugins as one, in order.
///
/// A boot takes a single plugin, so this is how a caller attaches more than
/// one. Each hook is forwarded to every member; a plugin that has nothing to
/// do at a given hook costs the default no-op.
#[derive(Default)]
pub struct Chain(Vec<Arc<dyn Plugin>>);

impl Chain {
    #[must_use]
    pub fn new() -> Self {
        Chain(Vec::new())
    }

    /// Adds a plugin to the end of the chain.
    #[must_use]
    pub fn with(mut self, obs: Arc<dyn Plugin>) -> Self {
        self.0.push(obs);
        self
    }

    /// Whether the chain is empty, so a caller can pass `None` rather than an
    /// plugin that does nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Plugin for Chain {
    fn attach(&self, vmm: Arc<dyn VmHandle>) -> std::io::Result<()> {
        for o in &self.0 {
            o.attach(Arc::clone(&vmm))?;
        }
        Ok(())
    }

    fn safepoint(&self, cpu: &dyn CpuHandle) {
        for o in &self.0 {
            o.safepoint(cpu);
        }
    }

    fn request(&self) {
        for o in &self.0 {
            o.request();
        }
    }
}

/// Writes guest RAM to a file, with the VM parked.
///
/// Triggered by the console's interrupt key, or on a timer with
/// [`MemoryDump::after`]. The dump is raw guest-physical memory, one region
/// after another in ascending address order; [`MemoryDump::regions`] reports
/// what went where, since a guest with an MMIO hole is not one contiguous span.
pub struct MemoryDump {
    path: String,
    /// Set by a trigger, consumed at the next safe point. One relaxed swap is
    /// the whole cost of the hook when nothing is pending.
    pending: Arc<AtomicBool>,
    /// Seconds after attach to dump automatically, for unattended runs.
    after: Option<u64>,
    /// A read-only mapping of guest RAM, and where each piece lives.
    view: Mutex<Option<ReadOnlyRam>>,
}

impl MemoryDump {
    /// Dumps to `path` when asked (console key).
    #[must_use]
    pub fn new(path: &str) -> Self {
        MemoryDump {
            path: path.to_string(),
            pending: Arc::new(AtomicBool::new(false)),
            after: None,
            view: Mutex::new(None),
        }
    }

    /// Also dumps once, `secs` after the guest starts. For unattended runs,
    /// where there is no console to press a key on.
    #[must_use]
    pub fn after(mut self, secs: u64) -> Self {
        self.after = Some(secs);
        self
    }

    /// The regions this dump covers, in file order, once attached.
    #[must_use]
    pub fn regions(&self) -> Vec<MemRegion> {
        match self.view.lock() {
            Ok(v) => v.as_ref().map(|r| r.regions.clone()).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    fn write_dump(&self) -> std::io::Result<u64> {
        let guard = self
            .view
            .lock()
            .map_err(|_| std::io::Error::other("dump view lock poisoned"))?;
        let Some(view) = guard.as_ref() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "memory dump was never attached",
            ));
        };
        let mut out = BufWriter::new(File::create(&self.path)?);
        let mut written = 0u64;
        for (i, region) in view.regions.iter().enumerate() {
            // Written in 1 MiB slices rather than one call, so a partial write
            // on a full disk fails on a boundary we can report.
            let bytes = view.slice(i);
            for chunk in bytes.chunks(1 << 20) {
                out.write_all(chunk)?;
                written += chunk.len() as u64;
            }
            let _ = region;
        }
        out.flush()?;
        Ok(written)
    }
}

impl Plugin for MemoryDump {
    /// Maps its own read-only view of guest RAM and, if asked, starts the
    /// timer.
    ///
    /// The view is read-only by construction, not by convention: this tool gets
    /// `PROT_READ` pages of the same object the VMM runs the guest from, so a
    /// bug here cannot corrupt the guest it is dumping. That is what
    /// [`VmHandle::ram_fd`] is for.
    fn attach(&self, vmm: Arc<dyn VmHandle>) -> std::io::Result<()> {
        let view = ReadOnlyRam::map(vmm.ram_fd(), &vmm.ram_regions())?;
        *self
            .view
            .lock()
            .map_err(|_| std::io::Error::other("dump view lock poisoned"))? = Some(view);

        if let Some(secs) = self.after {
            let pending = Arc::clone(&self.pending);
            let vmm = Arc::clone(&vmm);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(secs.max(1)));
                pending.store(true, Ordering::SeqCst);
                // Without this the flag is never seen: an idle guest sits in
                // WFI/HLT and the safe point is only reached between guest
                // entries.
                vmm.kick();
            });
        }
        Ok(())
    }

    /// Parks the VM and writes the dump.
    ///
    /// The guest is stopped for the whole write, which for a large guest on a
    /// slow disk is a visible stall. That is the deliberate choice: a dump
    /// taken while the guest runs is torn, and a torn memory image is worse
    /// than a slow one, because nothing about it says so.
    fn safepoint(&self, cpu: &dyn CpuHandle) {
        if !self.pending.swap(false, Ordering::SeqCst) {
            return;
        }
        if !cpu.pause() {
            eprintln!("[hvi] dump: vCPUs did not park; skipping (image would be torn)");
            return;
        }
        // Every path from here owes exactly one resume().
        let result = self.write_dump();
        cpu.resume();

        match result {
            Ok(n) => eprintln!("[hvi] dumped {n} bytes of guest RAM to {}", self.path),
            Err(e) => eprintln!("[hvi] dump to {} failed: {e}", self.path),
        }
    }

    fn request(&self) {
        self.pending.store(true, Ordering::SeqCst);
    }
}

/// A read-only mapping of the guest's RAM, made from the VMM's descriptor.
struct ReadOnlyRam {
    regions: Vec<MemRegion>,
    maps: Vec<(*mut libc::c_void, usize)>,
}

// SAFETY: the mappings are `PROT_READ` and live until drop; nothing here hands
// out a `&mut`, so sharing the handle across threads cannot produce a data race
// that reading the guest's memory does not already have.
unsafe impl Send for ReadOnlyRam {}
unsafe impl Sync for ReadOnlyRam {}

impl ReadOnlyRam {
    fn map(fd: std::os::fd::RawFd, regions: &[MemRegion]) -> std::io::Result<Self> {
        let mut maps = Vec::with_capacity(regions.len());
        for r in regions {
            // SAFETY: mapping `size` bytes at `file_offset` of a descriptor the
            // VMM owns and keeps open for the VM's lifetime.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    r.size as usize,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    fd,
                    r.file_offset as libc::off_t,
                )
            };
            if p == libc::MAP_FAILED {
                for (ptr, len) in &maps {
                    // SAFETY: unmapping what this loop mapped.
                    unsafe { libc::munmap(*ptr, *len) };
                }
                return Err(std::io::Error::last_os_error());
            }
            maps.push((p, r.size as usize));
        }
        Ok(ReadOnlyRam {
            regions: regions.to_vec(),
            maps,
        })
    }

    fn slice(&self, i: usize) -> &[u8] {
        let (ptr, len) = self.maps[i];
        // SAFETY: `ptr` is a live `PROT_READ` mapping of `len` bytes.
        unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) }
    }
}

impl Drop for ReadOnlyRam {
    fn drop(&mut self) {
        for (ptr, len) in &self.maps {
            // SAFETY: unmapping this struct's own mappings, once.
            unsafe { libc::munmap(*ptr, *len) };
        }
    }
}

/// Logs every virtio-blk request and virtio-net frame as it crosses the device.
///
/// One line per event, which on a busy guest is a lot of lines -- that is the
/// point of it. The ledger's `net` records are per-flow and its `block` records
/// carry no device identity; this is what the device actually saw, in order.
pub struct IoTrace {
    out: Arc<Mutex<BufWriter<File>>>,
    /// Set by the sink, cleared by the flush at the next safe point.
    ///
    /// Without this the trace is buffered and never flushed until drop, so a
    /// VMM that is killed -- which is how most traced runs end -- loses
    /// everything it recorded. Flushing on the device path instead would put a
    /// write(2) on the guest's I/O path, which is the one place it must not go.
    dirty: Arc<AtomicBool>,
}

impl IoTrace {
    /// Traces to `path` (truncating).
    ///
    /// # Errors
    ///
    /// Errors if the file cannot be created.
    pub fn new(path: &str) -> std::io::Result<Self> {
        Ok(IoTrace {
            out: Arc::new(Mutex::new(BufWriter::new(File::create(path)?))),
            dirty: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl Plugin for IoTrace {
    fn attach(&self, vmm: Arc<dyn VmHandle>) -> std::io::Result<()> {
        let sink: Arc<dyn IoSink> = Arc::new(TraceSink {
            out: Arc::clone(&self.out),
            dirty: Arc::clone(&self.dirty),
        });
        if vmm.has_block() {
            vmm.set_block_sink(Arc::clone(&sink));
        }
        if vmm.has_net() {
            vmm.set_net_sink(sink);
        }
        Ok(())
    }

    /// Flushes what the devices buffered since the last safe point.
    ///
    /// This is the right place for it: the safe point is where slow things are
    /// allowed, and it is reached often enough that a `kill` loses at most the
    /// last few events rather than the whole trace.
    fn safepoint(&self, _cpu: &dyn CpuHandle) {
        if !self.dirty.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Ok(mut o) = self.out.lock() {
            let _ = o.flush();
        }
    }
}

/// The sink half of [`IoTrace`], separate because the devices hold it directly.
struct TraceSink {
    out: Arc<Mutex<BufWriter<File>>>,
    dirty: Arc<AtomicBool>,
}

impl IoSink for TraceSink {
    fn block(&self, sector: u64, length: u64, disk_id: u64, write: bool) {
        // Called on the vCPU thread with the device lock held: buffered, never
        // flushed here, and a failed write is dropped rather than propagated. A
        // trace that stalls the guest it is tracing is not a trace.
        if let Ok(mut o) = self.out.lock() {
            let rw = if write { 'w' } else { 'r' };
            let _ = writeln!(o, "blk {rw} disk={disk_id:#x} sector={sector} len={length}");
            self.dirty.store(true, Ordering::SeqCst);
        }
    }

    fn net(&self, frame: &[u8], egress: bool) {
        if let Ok(mut o) = self.out.lock() {
            let dir = if egress { "tx" } else { "rx" };
            let _ = writeln!(o, "net {dir} len={}", frame.len());
            self.dirty.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chain forwards each hook to every member, in order.
    #[test]
    fn chain_forwards_to_every_member() {
        #[derive(Default)]
        struct Counter(AtomicBool);
        impl Plugin for Counter {
            fn request(&self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let a = Arc::new(Counter::default());
        let b = Arc::new(Counter::default());
        let chain = Chain::new()
            .with(a.clone() as Arc<dyn Plugin>)
            .with(b.clone() as Arc<dyn Plugin>);
        assert!(!chain.is_empty());
        chain.request();
        assert!(a.0.load(Ordering::SeqCst) && b.0.load(Ordering::SeqCst));
    }

    /// An empty chain is distinguishable, so a caller passes `None` instead of
    /// attaching a plugin that would do nothing.
    #[test]
    fn an_empty_chain_says_so() {
        assert!(Chain::new().is_empty());
    }

    /// Dumping before attach reports it rather than writing a truncated file:
    /// an empty dump that looks like a dump is the worst outcome here.
    #[test]
    fn dumping_before_attach_is_an_error() {
        let path = std::env::temp_dir().join(format!("hvi-dump-{}.raw", std::process::id()));
        let d = MemoryDump::new(path.to_str().unwrap());
        assert!(d.regions().is_empty());
        let e = d.write_dump().expect_err("must not write without a view");
        assert_eq!(e.kind(), std::io::ErrorKind::NotConnected);
        assert!(!path.exists(), "no file should be left behind");
    }

    /// The read-only view maps what it was told to, and reads back the bytes
    /// the writable side wrote -- the property the dumper depends on.
    #[test]
    fn a_read_only_view_sees_the_writable_side() {
        let ram = crate::sharedmem::SharedRam::new(crate::sharedmem::PAGE).expect("ram");
        // SAFETY: writing one byte into our own mapping.
        unsafe { *ram.as_ptr() = 0xAB };
        let regions = [MemRegion {
            gpa: 0x4000_0000,
            size: crate::sharedmem::PAGE as u64,
            file_offset: 0,
        }];
        let view = ReadOnlyRam::map(ram.fd(), &regions).expect("map");
        assert_eq!(view.slice(0)[0], 0xAB);
        assert_eq!(view.slice(0).len(), crate::sharedmem::PAGE);
    }

    /// A trace writes one line per event, in the order the device saw them.
    #[test]
    fn a_trace_records_each_event_in_order() {
        let path = std::env::temp_dir().join(format!("hvi-trace-{}.log", std::process::id()));
        let p = path.to_str().unwrap();
        {
            let t = IoTrace::new(p).expect("trace");
            let sink = TraceSink {
                out: Arc::clone(&t.out),
                dirty: Arc::clone(&t.dirty),
            };
            sink.block(2048, 4096, 0x11, true);
            sink.net(&[0u8; 64], true);
            sink.block(8, 512, 0x11, false);
        }
        let text = std::fs::read_to_string(p).unwrap();
        let _ = std::fs::remove_file(p);
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(
            lines,
            vec![
                "blk w disk=0x11 sector=2048 len=4096",
                "net tx len=64",
                "blk r disk=0x11 sector=8 len=512",
            ]
        );
    }
}

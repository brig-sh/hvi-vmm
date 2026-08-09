# Writing a tool

A VMM is a useful place to stand. It holds the guest's memory, it can park the
vCPUs between guest entries, and it is the other end of every virtio request the
guest makes. Debuggers, tracers, profilers and crash-dumpers all want one or
more of those.

None of them belongs in the exit loop, so the exit loop offers them instead.
That offer is `src/plugin.rs`, and it is four traits wide. Two tools in
`src/plugins.rs` are built on it and ship with the VMM — read those first;
they are short, and between them they use every part of the seam.

## The shape of it

```rust
use std::sync::Arc;
use hvi::config::BootConfig;
use hvi::plugin::{CpuHandle, Plugin, VmHandle};

struct MyTool { /* your state */ }

impl Plugin for MyTool {
    fn attach(&self, vmm: Arc<dyn VmHandle>) -> std::io::Result<()> {
        // Called once, before any vCPU runs. Take what you need:
        //   vmm.ram()          — read guest memory
        //   vmm.ram_fd()       — map your own view of it
        //   vmm.ram_regions()  — where it lives, guest-physically
        //   vmm.ledger()       — put your own records in the VMM's stream
        //   vmm.set_block_sink(...) / set_net_sink(...) — live device I/O
        //   vmm.kick()         — get cpu0 to its next safe point
        Ok(())
    }

    fn safepoint(&self, cpu: &dyn CpuHandle) {
        // Called on cpu0 between guest entries. This is the hot path.
        if !self.something_to_do() {
            return;                    // make this the cheap case
        }
        if cpu.pause() {               // parks every other vCPU
            // ... look at cpu.regs() and cpu.ram() while the guest is still ...
            cpu.resume();              // exactly once, on every path out
        }
    }

    fn request(&self) { /* the console's interrupt key */ }
}

let cfg = BootConfig {
    plugin: Some(Arc::new(MyTool { /* ... */ })),
    // ... the rest as usual
};
hvi::machine::boot(cfg)?;
```

That is the whole seam. `hvi::plugin` has no other entry points. A boot takes
one plugin; `plugins::Chain` runs several.

## Four things worth knowing before you write one

**`safepoint` is on the hot path.** It is called between guest entries, which on
a busy guest is often. A tool with nothing to do this time round should
establish that with one atomic load and return. Do the expensive thing on a flag
your own thread sets. `MemoryDump` is the pattern.

**A pause you win, you owe.** `cpu.pause()` returning `true` means every other
vCPU is parked and you owe exactly one `resume()` — including on every early
return between the two. Miss one and the VM stays parked forever. `false` means
they did not all park; the quiesce has already been released and you owe
nothing.

**Set a flag, then kick.** If your own thread decides it is time to act — a
timer, a socket, a doorbell — set your flag and then call `VmHandle::kick()`. An
idle guest sits in WFI (arm64) or HLT (x86) and does not reach `safepoint` on
its own, so without the kick your request waits for the next unrelated exit, or
on x86 never lands at all. This is the single easiest thing to get wrong, and it
fails only under idle guests, which is to say not on your desk. `MemoryDump`'s
`--dump-after` timer is the worked example.

**Buffer on the device path, flush at the safe point.** An `IoSink` is called
from the vCPU thread with the device lock held, so it must not block — no
`write(2)`, no allocation you can avoid. But a buffer that is only flushed on
drop loses everything when the VMM is killed, which is how most traced runs end.
`IoTrace` buffers in the sink, sets a dirty flag, and flushes in `safepoint`,
where slow things are allowed.

## Putting records in the ledger

`--events <path>` opens a `RawEvent` NDJSON stream that the VMM writes its own
device observations to. A tool's records go in the same stream:

```rust
#[derive(serde::Serialize)]
struct MyPayload { interesting: u64 }

if let Ok(mut led) = cpu.ledger().lock() {
    led.emit_payload("boundary", "my-source", &MyPayload { interesting });
    led.flush();
}
```

The envelope — `sandbox_id`, `ts`, `provenance`, `source` — is this crate's, and
its wire shape is pinned by tests. The payload is entirely yours; the VMM never
looks inside it. That is the whole of the coupling between a ledger reader and
whatever produced a record.

## Reading guest memory

`CpuHandle::ram()` borrows the VMM's own mapping, which is writable. If your tool
only ever reads — most do — prefer mapping your own read-only view from
`VmHandle::ram_fd()` and `ram_regions()`, as `MemoryDump` does. It costs one
`mmap` at attach and makes a whole class of bug structurally impossible: a tool
holding `PROT_READ` pages cannot corrupt the guest it is inspecting, however
wrong the rest of it is.

Note that guest RAM is not necessarily one span. The x86 backend puts a hole in
it for MMIO, so `ram_regions()` returns two. A tool that assumes one region
reads nothing above the hole and looks like it found an empty guest, rather than
like it has a bug.

## Shipping one out of tree

A tool can live in its own crate, which depends on this one:

```toml
[dependencies]
hvi = { git = "https://github.com/nofireai/hvi", tag = "v0.1.0" }
```

and ship its own binary with its own CLI, constructing a `BootConfig` and
calling `hvi::machine::boot`. Pin a tag rather than a branch: `hvi --version`
reports the VMM core a binary was built against, and that is only worth printing
if the core is a fixed thing.

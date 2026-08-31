//! M0: the Hypervisor.framework smoke test.
//!
//! Stands the backend up end to end with no Linux involved: one VM, one mapped
//! guest page holding a two-instruction stub, one vCPU. The stub loads a marker
//! into `x0` and executes `HVC #0`; a correct backend reports an
//! `EXCEPTION` exit whose syndrome decodes to [`Ec::Hvc`](crate::esr::Ec::Hvc),
//! with the marker readable back out of `x0`. That single round trip exercises
//! VM creation, guest-RAM mapping, register programming, `hv_vcpu_run`, and the
//! exit-syndrome decode that every later milestone's exit loop depends on.
//!
//! Running this needs the `com.apple.security.hypervisor` entitlement (a live
//! boot is not run in CI because the runner cannot sign for it). A detached
//! session is fine: an ad-hoc-signed, entitled hvi creates and runs a VM from a
//! background job, so this is scriptable.
//!
//! [`run_shm`](crate::smoke::run_shm) is the same test over **shared** guest
//! memory: the page is a POSIX shared-memory object mapped `MAP_SHARED` and
//! handed to `hv_vm_map` directly, instead of an `applevisor`-owned allocation.
//! That is the mechanism out-of-process observation needs on macOS
//!, so this proves it end to end: the
//! guest executes from the shared page, writes to it, and a *separate process*
//! reads the value back out.

use applevisor::prelude::{MemPerms, Reg, VirtualMachine};

use crate::esr::Ec;

/// Guest-physical base of the single mapped page. Any aligned IPA works for the
/// smoke test; `0x4000_0000` mirrors the RAM base the arm64 Linux boot (M1)
/// will use, so the address is already familiar in later logs.
const GUEST_BASE: u64 = 0x4000_0000;

/// `MOVZ X0, #{MARKER}` — load a recognizable marker so we can prove the vCPU
/// actually executed the stub rather than exiting for some unrelated reason.
const MARKER: u64 = 0x1337;

/// Encoded stub: `movz x0, #0x1337` then `hvc #0`.
const STUB: [u32; 2] = [
    // MOVZ X0, #0x1337 : sf=1 opc=10 100101 hw=00 imm16=0x1337 Rd=0
    0xd280_0000 | ((MARKER as u32 & 0xffff) << 5),
    // HVC #0
    0xd400_0002,
];

/// Runs the M0 smoke test, returning an error if the backend misbehaves or the
/// exit does not decode to the `HVC` we planted. `HypervisorError` from the
/// `applevisor` calls converts into the boxed error via `?`; the test's own
/// assertions fail with a plain message.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Exactly one VM per process (Hypervisor.framework constraint); GIC comes
    // in M1 via the `with_gic` typestate.
    let vm = VirtualMachine::new()?;

    // One page of guest RAM, mapped RWX for the stub. `memory_create` allocates
    // host-backed memory whose host pointer we would hand a plugin in
    // M3 — that pointer is the zero-copy guest-RAM window the design note calls
    // out as "free" on hvf.
    let mut mem = vm.memory_create(0x1000)?;
    mem.map(GUEST_BASE, MemPerms::ReadWriteExec)?;
    for (i, insn) in STUB.iter().enumerate() {
        mem.write_u32(GUEST_BASE + (i as u64) * 4, *insn)?;
    }

    let vcpu = vm.vcpu_create()?;
    vcpu.set_reg(Reg::PC, GUEST_BASE)?;
    // EL1h with DAIF masked (M[3:0]=0b0101, DAIF at [9:6]); a sane MMU-off boot
    // state for executing the stub from the identity-mapped page.
    vcpu.set_reg(Reg::CPSR, 0x3c5)?;

    vcpu.run()?;

    let exit = vcpu.get_exit_info();
    let syndrome = exit.exception.syndrome;
    let ec = Ec::from_syndrome(syndrome);
    let x0 = vcpu.get_reg(Reg::X0)?;

    println!(
        "M0 exit: reason={:?} ec={:?} syndrome={:#x} x0={:#x}",
        exit.reason, ec, syndrome, x0
    );

    if ec != Ec::Hvc {
        return Err(format!("expected HVC exit, got {ec:?} (syndrome {syndrome:#x})").into());
    }
    if x0 != MARKER {
        return Err(format!("stub did not run: x0={x0:#x}, expected {MARKER:#x}").into());
    }

    println!("M0 smoke test OK: VM created, page mapped, vCPU ran, HVC decoded.");
    Ok(())
}

/// Guest-visible address the stub stores its marker to (offset 8 keeps it clear
/// of the three-instruction stub at the page base, and is 8-byte aligned).
const STORE_OFF: u64 = 8;

/// Apple silicon page size. `hv_vm_map` requires the host pointer, the IPA and
/// the length to be multiples of this, and `shm_open` objects must be sized to
/// match before mapping.
const HV_PAGE: usize = 0x4000;

/// `STR X0, [X1]` — the host presets `X1` so the stub needs no address
/// materialisation (which would cost a `movz`/`movk` pair to encode by hand).
const STR_X0_X1: u32 = 0xf900_0020;

/// The shared-memory variant of [`run`]: guest RAM is a POSIX shm object mapped
/// `MAP_SHARED` and passed straight to `hv_vm_map`, bypassing
/// `applevisor::Memory` (whose `Drop` would `hv_vm_deallocate` memory it did
/// not allocate). Proves the macOS half of out-of-process observation: the
/// vCPU executes from the shared page and stores a marker into it, then a
/// separate process opens the same object read-only and reads that marker back.
pub fn run_shm() -> Result<(), Box<dyn std::error::Error>> {
    // macOS caps shm names at 31 characters, including the leading slash.
    let name = format!("/hvi-shm-{}", std::process::id());
    let cname = std::ffi::CString::new(name.clone())?;

    // Create + size the object. O_EXCL so a stale object from a crashed run is
    // an error rather than a silently reused mapping.
    // SAFETY: `cname` is a valid NUL-terminated C string that outlives the
    // call.
    let fd = unsafe {
        libc::shm_open(
            cname.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(format!("shm_open({name}): {}", std::io::Error::last_os_error()).into());
    }
    // From here on the object exists in the namespace; unlink it on every exit.
    let cleanup = || {
        // SAFETY: `cname` is still alive; unlinking a live name is safe.
        unsafe { libc::shm_unlink(cname.as_ptr()) };
    };
    // SAFETY: `fd` is the descriptor we just created.
    if unsafe { libc::ftruncate(fd, HV_PAGE as libc::off_t) } != 0 {
        let e = std::io::Error::last_os_error();
        cleanup();
        return Err(format!("ftruncate: {e}").into());
    }

    // SAFETY: mapping `HV_PAGE` bytes of a descriptor we sized to exactly that.
    let host = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            HV_PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if host == libc::MAP_FAILED {
        let e = std::io::Error::last_os_error();
        cleanup();
        return Err(format!("mmap: {e}").into());
    }
    println!("shm {name}: fd={fd} host={host:p} size={HV_PAGE:#x}");

    // Plant the stub through the host mapping (not through applevisor).
    let stub = [STUB[0], STR_X0_X1, STUB[1]];
    // SAFETY: `host` maps HV_PAGE >= size_of(stub) writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(stub.as_ptr(), host.cast::<u32>(), stub.len()) };

    let vm = VirtualMachine::new()?;
    // The point of the exercise: map *our* shared pointer into guest physical
    // space. applevisor has no API for this, so call the raw framework entry.
    // SAFETY: `host` is a live, page-aligned mapping of `HV_PAGE` bytes.
    let ret = unsafe {
        applevisor_sys::hv_vm_map(
            host.cast::<std::ffi::c_void>(),
            GUEST_BASE,
            HV_PAGE,
            applevisor_sys::HV_MEMORY_READ
                | applevisor_sys::HV_MEMORY_WRITE
                | applevisor_sys::HV_MEMORY_EXEC,
        )
    };
    if ret != 0 {
        cleanup();
        return Err(format!("hv_vm_map(shm) failed: {ret:#x}").into());
    }
    println!("hv_vm_map(shm-backed host ptr -> ipa {GUEST_BASE:#x}) OK");

    let vcpu = vm.vcpu_create()?;
    vcpu.set_reg(Reg::PC, GUEST_BASE)?;
    vcpu.set_reg(Reg::CPSR, 0x3c5)?;
    // Preset the store address so the stub needs no address materialisation.
    vcpu.set_reg(Reg::X1, GUEST_BASE + STORE_OFF)?;
    vcpu.run()?;

    let exit = vcpu.get_exit_info();
    let ec = Ec::from_syndrome(exit.exception.syndrome);
    let x0 = vcpu.get_reg(Reg::X0)?;
    println!("shm exit: reason={:?} ec={ec:?} x0={x0:#x}", exit.reason);
    if ec != Ec::Hvc || x0 != MARKER {
        cleanup();
        return Err(format!("stub did not run from shared memory (ec={ec:?}, x0={x0:#x})").into());
    }

    // The guest's store must be visible through our host mapping...
    // SAFETY: reading 8 bytes at STORE_OFF, inside the mapping.
    let via_host = unsafe {
        host.cast::<u8>()
            .add(STORE_OFF as usize)
            .cast::<u64>()
            .read()
    };
    println!("guest store read back via host mapping: {via_host:#x}");

    // ...and, the actual point, through a *separate process* that only knows
    // the object's name. This is the plugin's access path.
    let exe = std::env::current_exe()?;
    let out = std::process::Command::new(exe)
        .arg("smoke-shm-verify")
        .arg(&name)
        .arg(format!("{MARKER:#x}"))
        .output()?;
    print!("{}", String::from_utf8_lossy(&out.stdout));
    eprint!("{}", String::from_utf8_lossy(&out.stderr));

    cleanup();
    if via_host != MARKER {
        return Err(format!("host mapping saw {via_host:#x}, expected {MARKER:#x}").into());
    }
    if !out.status.success() {
        return Err("separate process could not read the guest's write".into());
    }
    println!("shm smoke OK: guest ran from shared RAM; another process read its write.");
    Ok(())
}

/// The child half of [`run_shm`]: open the named object read-only, map it, and
/// check the guest's store is visible. Runs in a process that never touched the
/// hypervisor — exactly the plugin's position.
pub fn verify_shm(name: &str, expect: u64) -> Result<(), Box<dyn std::error::Error>> {
    let cname = std::ffi::CString::new(name)?;
    // SAFETY: valid NUL-terminated name; O_RDONLY needs no mode argument.
    let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(format!(
            "child shm_open({name}): {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    // SAFETY: read-only mapping of a page-sized object.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            HV_PAGE,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(format!("child mmap: {}", std::io::Error::last_os_error()).into());
    }
    // SAFETY: reading 8 bytes at STORE_OFF, inside the mapping.
    let got = unsafe { p.cast::<u8>().add(STORE_OFF as usize).cast::<u64>().read() };
    println!(
        "  [child pid {}] read {got:#x} from {name}",
        std::process::id()
    );
    if got != expect {
        return Err(format!("child saw {got:#x}, expected {expect:#x}").into());
    }
    Ok(())
}

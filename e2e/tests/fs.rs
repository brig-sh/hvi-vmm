// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

//! virtio-fs exports, as the guest and the host each see them.
//!
//! The tests at the top run on both backends through [`FsExport`]. The modules
//! below cover what only one backend has.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use hvi_e2e::{export_dir, pattern, sha256, FsExport, Vm};

/// Mounts the export tagged `tag` at `/mnt/<tag>` in the guest.
fn mount(vm: &Vm, tag: &str) {
    vm.sh(&format!(
        "mkdir -p /mnt/{tag} && mount -t virtiofs {tag} /mnt/{tag}"
    ))
    .assert_success();
}

#[test]
fn guest_and_host_see_each_others_files() {
    let dir = export_dir("export");
    std::fs::write(dir.join("from-host"), "written by the host\n").unwrap();
    let export = FsExport::new(&dir, "export");
    let vm = Vm::builder().fs(&export).boot();
    mount(&vm, "export");
    let read = vm.sh("cat /mnt/export/from-host").assert_success().stdout;
    vm.sh("echo written by the guest > /mnt/export/from-guest && sync")
        .assert_success();
    vm.power_off();
    assert_eq!(read, "written by the host\n");
    assert_eq!(
        std::fs::read_to_string(dir.join("from-guest")).unwrap(),
        "written by the guest\n"
    );
}

#[test]
fn large_file_round_trips_intact() {
    let dir = export_dir("export");
    let bytes = pattern(32 << 20, 1);
    std::fs::write(dir.join("big"), &bytes).unwrap();
    let export = FsExport::new(&dir, "export");
    let vm = Vm::builder().cpus(2).fs(&export).boot();
    mount(&vm, "export");
    let digest = vm
        .sh("sha256sum /mnt/export/big && cp /mnt/export/big /mnt/export/copy && sync")
        .assert_success()
        .stdout;
    vm.power_off();
    assert!(
        digest.starts_with(&sha256(&bytes)),
        "the guest read {digest}"
    );
    assert!(
        std::fs::read(dir.join("copy")).unwrap() == bytes,
        "the guest's copy differs on the host"
    );
}

// A listing this long spans several readdir requests, and every entry must come
// back once.
#[test]
fn listing_well_past_sixty_four_entries_is_whole() {
    let dir = export_dir("export");
    let many = dir.join("many");
    std::fs::create_dir(&many).unwrap();
    for n in 0..300 {
        std::fs::write(many.join(format!("file{n:03}")), "").unwrap();
    }
    let export = FsExport::new(&dir, "export");
    let vm = Vm::builder().fs(&export).boot();
    mount(&vm, "export");
    let listing = vm
        .sh("ls -1 /mnt/export/many; rm /mnt/export/many/file1*; ls -1 /mnt/export/many | wc -l")
        .assert_success()
        .stdout;
    vm.power_off();
    let mut lines: Vec<&str> = listing.lines().collect();
    let after_remove = lines.pop().unwrap().trim().to_string();
    let expected: Vec<String> = (0..300).map(|n| format!("file{n:03}")).collect();
    assert_eq!(lines, expected);
    assert_eq!(after_remove, "200");
}

// The tree has the shape of a container root filesystem, which carries absolute
// symlinks.
#[test]
fn tree_with_absolute_symlinks_is_removed_and_recreated() {
    let dir = export_dir("export");
    let tree = dir.join("tree");
    for branch in 0..10 {
        let sub = tree.join(format!("branch{branch}/leaf"));
        std::fs::create_dir_all(&sub).unwrap();
        for n in 0..5 {
            std::fs::write(sub.join(format!("file{n}")), "x").unwrap();
            std::os::unix::fs::symlink(
                format!("/usr/lib/absolute-target-{n}"),
                sub.join(format!("link{n}")),
            )
            .unwrap();
        }
    }
    let export = FsExport::new(&dir, "export");
    let vm = Vm::builder().fs(&export).boot();
    mount(&vm, "export");
    vm.sh("rm -rf /mnt/export/tree && test ! -e /mnt/export/tree && \
         mkdir -p /mnt/export/tree/a/b && ln -s /abs/target /mnt/export/tree/a/link && \
         readlink /mnt/export/tree/a/link && sync")
        .assert_success();
    vm.power_off();
    assert!(tree.join("a/b").is_dir());
    assert_eq!(
        std::fs::read_link(tree.join("a/link")).unwrap(),
        Path::new("/abs/target")
    );
    assert!(
        !tree.join("branch0").exists(),
        "the old tree is still there"
    );
}

// The waiter asks for the lock while the holder writes. The holder marks that
// it has the lock first, so the waiter always comes second.
#[test]
fn lock_holder_and_waiter_both_finish() {
    let dir = export_dir("export");
    let export = FsExport::new(&dir, "export");
    let vm = Vm::builder().cpus(2).fs(&export).boot();
    mount(&vm, "export");
    let output = vm.sh(
        "touch /mnt/export/lock && \
         (flock -x /mnt/export/lock -c 'touch /tmp/held; dd if=/dev/zero of=/mnt/export/big bs=1M count=16 conv=fsync 2>/dev/null; echo first') & \
         while [ ! -e /tmp/held ]; do sleep 0.05; done; \
         flock -x /mnt/export/lock -c 'echo second'; wait",
    );
    vm.power_off();
    let output = output.assert_success();
    assert_eq!(
        output.stdout.lines().collect::<Vec<_>>(),
        ["first", "second"]
    );
}

// The guest's sync is bounded by what the host takes to sync the export's own
// filesystem just before, so a slow host disk widens the bound.
#[test]
fn sync_returns_promptly() {
    let dir = export_dir("export");
    let export = FsExport::new(&dir, "export");
    let vm = Vm::builder().fs(&export).boot();
    mount(&vm, "export");
    vm.sh("dd if=/dev/zero of=/mnt/export/f bs=1M count=1 2>/dev/null")
        .assert_success();
    let host = sync_on_host(&dir);
    let started = Instant::now();
    vm.sh("sync").assert_success();
    let guest = started.elapsed();
    vm.power_off();
    let bound = host * 2 + Duration::from_secs(5);
    assert!(
        guest <= bound,
        "the guest's sync took {guest:?}, against {host:?} on the host"
    );
}

/// Returns how long the host takes to sync the filesystem `dir` is on.
///
/// On Linux it is synced with `syncfs`. macOS has no `syncfs`, so there `dir`
/// itself is synced with `fsync`.
fn sync_on_host(dir: &Path) -> Duration {
    let dir = File::open(dir).unwrap();
    let started = Instant::now();
    #[cfg(target_os = "linux")]
    // SAFETY: syncfs takes a descriptor this function holds open.
    let synced = unsafe { libc::syncfs(dir.as_raw_fd()) };
    #[cfg(target_os = "macos")]
    // SAFETY: fsync takes a descriptor this function holds open.
    let synced = unsafe { libc::fsync(dir.as_raw_fd()) };
    assert_eq!(synced, 0, "{}", std::io::Error::last_os_error());
    started.elapsed()
}

#[cfg(target_os = "macos")]
mod path {
    use super::*;

    #[test]
    fn read_only_export_refuses_every_change() {
        let dir = export_dir("export");
        std::fs::write(dir.join("file"), "kept\n").unwrap();
        std::fs::create_dir(dir.join("subdir")).unwrap();
        let vm = Vm::builder()
            .arg("--fs")
            .arg(format!("tag=export,path={},readonly=on", dir.display()))
            .boot();
        mount(&vm, "export");
        let attempts = [
            "touch /mnt/export/new",
            "echo x >> /mnt/export/file",
            "mkdir /mnt/export/newdir",
            "ln -s file /mnt/export/symlink",
            "ln /mnt/export/file /mnt/export/hardlink",
            "mkfifo /mnt/export/fifo",
            "truncate -s 0 /mnt/export/file",
            "chmod 777 /mnt/export/file",
            "mv /mnt/export/file /mnt/export/moved",
            "rm /mnt/export/file",
            "rmdir /mnt/export/subdir",
        ];
        let results: Vec<(&str, bool)> = attempts
            .iter()
            .map(|attempt| {
                (
                    *attempt,
                    vm.sh(&format!("{attempt} 2>/dev/null")).is_success(),
                )
            })
            .collect();
        vm.power_off();
        let allowed: Vec<&str> = results
            .iter()
            .filter(|(_, ok)| *ok)
            .map(|(attempt, _)| *attempt)
            .collect();
        assert!(allowed.is_empty(), "a read-only export allowed {allowed:?}");
        assert_eq!(std::fs::read_to_string(dir.join("file")).unwrap(), "kept\n");
        assert!(dir.join("subdir").is_dir());
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(names.len(), 2, "the host directory changed");
    }

    #[test]
    fn setuid_bit_can_be_set_under_seatbelt() {
        let dir = export_dir("export");
        std::fs::write(dir.join("tool"), "#!/bin/sh\n").unwrap();
        let export = FsExport::new(&dir, "export");
        let vm = Vm::builder().fs(&export).boot();
        mount(&vm, "export");
        let mode = vm
            .sh("chmod 4755 /mnt/export/tool && stat -c %a /mnt/export/tool")
            .assert_success()
            .stdout
            .trim()
            .to_string();
        vm.power_off();
        assert_eq!(mode, "4755");
    }
}

#[cfg(target_os = "linux")]
mod socket {
    use super::*;

    use hvi_e2e::{PendingSocket, Stop, Suite, Virtiofsd};

    #[test]
    fn more_request_queues_than_vcpus_are_refused() {
        let dir = export_dir("export");
        let daemon = Virtiofsd::start(&dir);
        Vm::builder()
            .arg("--fs")
            .arg(format!(
                "tag=export,socket={},num_queues=2",
                daemon.socket().display()
            ))
            .spawn()
            .wait(Duration::from_secs(30))
            .assert_refused("num_queues=2 is more than the guest's 1 vCPU(s)");
    }

    // virtiofsd serves one request queue beside the high-priority one.
    #[test]
    fn more_request_queues_than_the_daemon_serves_are_refused() {
        let dir = export_dir("export");
        let daemon = Virtiofsd::start(&dir);
        Vm::builder()
            .cpus(2)
            .arg("--fs")
            .arg(format!(
                "tag=export,socket={},num_queues=2",
                daemon.socket().display()
            ))
            .spawn()
            .wait(Duration::from_secs(30))
            .assert_refused("num_queues=2 needs 3 queues, and the daemon serves 2");
    }

    // A runtime may start hvi and the daemon at once, in either order.
    #[test]
    fn daemon_started_after_hvi_is_waited_for() {
        let dir = export_dir("export");
        std::fs::write(dir.join("file"), "late\n").unwrap();
        let pending = PendingSocket::reserve();
        let mut vm = Vm::builder()
            .arg("--fs")
            .arg(format!("tag=export,socket={}", pending.path().display()))
            .spawn();
        // hvi names the export just before it starts waiting for the daemon.
        let waiting = format!("virtio-fs[0]: \"export\" on {}", pending.path().display());
        assert!(
            vm.stderr_shows(&waiting, Duration::from_secs(30)),
            "hvi did not name the export"
        );
        let _daemon = Virtiofsd::spawn_into(&dir, pending);
        vm.wait_for_guest();
        mount(&vm, "export");
        let read = vm.sh("cat /mnt/export/file").assert_success().stdout;
        vm.power_off();
        assert_eq!(read, "late\n");
    }

    // Unbinding the driver resets the device, which takes its rings back from
    // the daemon. Binding it again hands them over once more.
    #[test]
    fn driver_rebind_brings_the_export_back() {
        let dir = export_dir("export");
        std::fs::write(dir.join("file"), "again\n").unwrap();
        let export = FsExport::new(&dir, "export");
        let vm = Vm::builder().fs(&export).boot();
        mount(&vm, "export");
        let read = vm
            .sh("umount /mnt/export && \
                 dev=$(basename $(readlink /sys/bus/virtio/drivers/virtiofs/virtio*)) && \
                 echo $dev > /sys/bus/virtio/drivers/virtiofs/unbind && \
                 echo $dev > /sys/bus/virtio/drivers/virtiofs/bind && \
                 mount -t virtiofs export /mnt/export && cat /mnt/export/file")
            .assert_success()
            .stdout;
        vm.power_off();
        assert_eq!(read, "again\n");
    }

    // A Linux guest waits on virtio-fs with no timeout, in a state no signal
    // ends, so a read from the dead daemon never returns. The read runs in the
    // background, and the run stops on a signal, since a guest power-off would
    // sync the dead mount first.
    #[test]
    fn daemon_killed_under_a_mount_leaves_hvi_running() {
        let dir = export_dir("export");
        std::fs::write(dir.join("file"), "x\n").unwrap();
        let mut export = FsExport::new(&dir, "export");
        let vm = Vm::builder().fs(&export).boot();
        mount(&vm, "export");
        export
            .daemon_mut()
            .expect("a Linux export should have a daemon")
            .kill();
        vm.sh("cat /mnt/export/file >/dev/null 2>&1 & echo $! > /tmp/reader")
            .assert_success();
        // The reader's request has been sent once the reader waits in
        // `request_wait_answer`.
        let tries = Suite::get().timeout(Duration::from_secs(10)).as_millis() / 100;
        vm.sh(&format!(
            "for i in $(seq {tries}); do \
               grep -q request_wait_answer /proc/$(cat /tmp/reader)/wchan && exit 0; \
               sleep 0.1; \
             done; cat /proc/$(cat /tmp/reader)/wchan; exit 1"
        ))
        .assert_success();
        vm.sh("true").assert_success();
        vm.signal(libc::SIGTERM);
        vm.wait(Duration::from_secs(10))
            .assert_stopped(Stop::Requested(libc::SIGTERM));
    }

    // The daemon exits once hvi's connection to it closes.
    #[test]
    fn stop_signal_during_writes_to_an_export_ends_the_run_and_the_daemon() {
        let dir = export_dir("export");
        let mut export = FsExport::new(&dir, "export");
        let vm = Vm::builder().fs(&export).boot();
        mount(&vm, "export");
        vm.sh("(dd if=/dev/zero of=/mnt/export/big bs=1M count=512) >/dev/null 2>&1 &")
            .assert_success();
        // Each write goes to the daemon, so a file that has grown is one the
        // daemon is writing.
        vm.sh("while [ ! -s /mnt/export/big ]; do sleep 0.05; done")
            .assert_success();
        vm.signal(libc::SIGTERM);
        vm.wait(Duration::from_secs(10))
            .assert_stopped(Stop::Requested(libc::SIGTERM));
        let daemon = export
            .daemon_mut()
            .expect("a Linux export should have a daemon");
        assert!(
            daemon.wait_for_exit(Duration::from_secs(10)),
            "virtiofsd outlived the run"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn eleven_exports_mount_and_a_twelfth_is_refused() {
        let exports: Vec<(FsExport, String)> = (0..11)
            .map(|n| {
                let tag = format!("export{n}");
                let dir = export_dir(&tag);
                std::fs::write(dir.join("name"), &tag).unwrap();
                (FsExport::new(&dir, &tag), tag)
            })
            .collect();
        let mut eleven = Vm::builder();
        for (export, _) in &exports {
            eleven = eleven.fs(export);
        }
        let vm = eleven.boot();
        for (_, tag) in &exports {
            mount(&vm, tag);
            let name = vm
                .sh(&format!("cat /mnt/{tag}/name"))
                .assert_success()
                .stdout;
            assert_eq!(&name, tag);
        }
        vm.power_off();

        let exports: Vec<FsExport> = (0..12)
            .map(|n| FsExport::new(&export_dir(&format!("again{n}")), &format!("again{n}")))
            .collect();
        let mut twelve = Vm::builder();
        for export in &exports {
            twelve = twelve.fs(export);
        }
        twelve
            .spawn()
            .wait(Duration::from_secs(30))
            .assert_refused("x86-64 has interrupt lines for 11 exports");
    }

    #[test]
    fn daemon_that_never_starts_fails_the_boot_after_the_wait() {
        let pending = PendingSocket::reserve();
        Vm::builder()
            .arg("--fs")
            .arg(format!("tag=export,socket={}", pending.path().display()))
            .spawn()
            .wait(Duration::from_secs(90))
            .assert_refused("(waited ");
    }

    // With 4 GiB the guest's RAM is two regions around the MMIO hole, and the
    // daemon gets both in its memory table.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn traffic_to_an_export_works_with_ram_above_four_gibibytes() {
        let dir = export_dir("export");
        let bytes = pattern(256 << 20, 2);
        std::fs::write(dir.join("big"), &bytes).unwrap();
        let export = FsExport::new(&dir, "export");
        let vm = Vm::builder().mem_mib(4096).cpus(2).fs(&export).boot();
        mount(&vm, "export");
        vm.sh("cp /mnt/export/big /mnt/export/copy")
            .assert_success();
        vm.power_off();
        let copy = std::fs::read(dir.join("copy")).unwrap();
        assert!(copy == bytes, "the guest's copy differs on the host");
    }
}

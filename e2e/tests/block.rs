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

//! virtio-blk disks, as the guest and the host each see them.

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::Duration;

use hvi_e2e::{pattern, sha256, sparse_file, Vm};

const MIB: u64 = 1 << 20;

/// Writes `bytes` into the file at `path`, at `offset`.
fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.write_all_at(bytes, offset).unwrap();
}

/// Returns `len` bytes of the file at `path`, from `offset`.
fn read_at(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    let file = OpenOptions::new().read(true).open(path).unwrap();
    let mut bytes = vec![0u8; len];
    file.read_exact_at(&mut bytes, offset).unwrap();
    bytes
}

#[test]
fn guest_and_host_read_each_others_writes() {
    let disk = sparse_file("disk.img", 64 * MIB);
    let from_host = pattern(64 << 10, 1);
    write_at(&disk, MIB, &from_host);
    let vm = Vm::builder().disk(&disk).boot();
    let read = vm
        .sh("dd if=/dev/vda bs=64k skip=16 count=1 2>/dev/null | sha256sum")
        .assert_success()
        .stdout;
    let wrote = vm.sh(
        "printf hvi-e2e-written-by-the-guest | dd of=/dev/vda bs=512 seek=4096 conv=notrunc,fsync",
    );
    vm.power_off();
    assert!(
        read.starts_with(&sha256(&from_host)),
        "the guest read different bytes: {read}"
    );
    wrote.assert_success();
    assert_eq!(read_at(&disk, 2 * MIB, 28), b"hvi-e2e-written-by-the-guest");
}

#[test]
fn read_only_disk_refuses_guest_writes() {
    let disk = sparse_file("disk.img", 16 * MIB);
    write_at(&disk, 0, &pattern(4096, 2));
    let before = sha256(&std::fs::read(&disk).unwrap());
    let vm = Vm::builder()
        .disk(format!("path={},readonly=on", disk.display()))
        .boot();
    let read_only = vm
        .sh("cat /sys/block/vda/ro")
        .assert_success()
        .stdout
        .trim()
        .to_string();
    let write = vm.sh("dd if=/dev/zero of=/dev/vda bs=4096 count=1 oflag=direct");
    vm.power_off();
    assert_eq!(read_only, "1");
    assert!(!write.is_success(), "a write to a read-only disk succeeded");
    assert_eq!(sha256(&std::fs::read(&disk).unwrap()), before);
}

#[test]
fn four_disks_keep_their_order_size_and_serial() {
    let sizes = [8, 16, 32, 64].map(|mib| mib * MIB);
    let mut builder = Vm::builder();
    for (index, size) in sizes.iter().enumerate() {
        let disk = sparse_file(&format!("disk{index}.img"), *size);
        builder = match index {
            3 => builder.disk(format!("path={},serial=hvi-e2e", disk.display())),
            _ => builder.disk(&disk),
        };
    }
    let vm = builder.boot();
    let listing = vm
        .sh("for d in vda vdb vdc vdd; do echo $(cat /sys/block/$d/size) $(cat /sys/block/$d/serial); done")
        .assert_success().stdout;
    vm.power_off();
    let expected: Vec<String> = sizes
        .iter()
        .zip(["disk0", "disk1", "disk2", "hvi-e2e"])
        .map(|(size, serial)| format!("{} {serial}", size / 512))
        .collect();
    assert_eq!(listing.lines().collect::<Vec<_>>(), expected);
}

#[test]
fn fifth_disk_is_refused() {
    let mut builder = Vm::builder();
    for index in 0..5 {
        builder = builder.disk(sparse_file(&format!("disk{index}.img"), MIB));
    }
    builder
        .spawn()
        .wait(Duration::from_secs(10))
        .assert_refused("5 disks given; at most 4 fit");
}

// virtio-blk gives the capacity in whole 512-byte sectors.
#[test]
fn image_not_a_multiple_of_five_hundred_twelve_bytes_loses_only_its_tail() {
    let disk = sparse_file("disk.img", 8 * MIB + 100);
    let vm = Vm::builder().disk(&disk).boot();
    let size = vm
        .sh("cat /sys/block/vda/size")
        .assert_success()
        .stdout
        .trim()
        .to_string();
    let read_all = vm.sh("dd if=/dev/vda of=/dev/null bs=64k");
    vm.power_off();
    assert_eq!(size, (8 * MIB / 512).to_string());
    read_all.assert_success();
}

#[test]
fn flushed_write_survives_a_kill() {
    let disk = sparse_file("disk.img", 16 * MIB);
    let vm = Vm::builder().disk(&disk).boot();
    vm.sh("printf hvi-e2e-flushed | dd of=/dev/vda bs=512 seek=8 conv=notrunc,fsync")
        .assert_success();
    vm.kill();
    assert_eq!(read_at(&disk, 8 * 512, 15), b"hvi-e2e-flushed");
}

#[test]
fn writable_image_is_refused_while_another_run_writes_it() {
    let disk = sparse_file("disk.img", 16 * MIB);
    let first = Vm::builder().disk(&disk).boot();
    Vm::builder()
        .disk(&disk)
        .spawn()
        .wait(Duration::from_secs(10))
        .assert_refused("the image is open elsewhere");
    first.power_off();
}

#[test]
fn read_only_image_is_refused_while_another_run_writes_it() {
    let disk = sparse_file("disk.img", 16 * MIB);
    let first = Vm::builder().disk(&disk).boot();
    Vm::builder()
        .disk(format!("path={},readonly=on", disk.display()))
        .spawn()
        .wait(Duration::from_secs(10))
        .assert_refused("the image is open for writing elsewhere");
    first.power_off();
}

#[test]
fn read_only_image_can_be_shared() {
    let disk = sparse_file("disk.img", 16 * MIB);
    let spec = format!("path={},readonly=on", disk.display());
    let first = Vm::builder().disk(&spec).boot();
    let second = Vm::builder().disk(&spec).boot();
    second.power_off();
    first.power_off();
}

// The reads are direct and run on two vCPUs for three passes, so a lost
// completion interrupt stalls a read and the script times out.
#[test]
fn large_direct_reads_complete() {
    let disk = sparse_file("disk.img", 1024 * MIB);
    let vm = Vm::builder().cpus(2).disk(&disk).boot();
    vm.sh("for pass in 1 2 3; do dd if=/dev/vda of=/dev/null bs=4M iflag=direct || exit 1; done")
        .assert_success();
    vm.power_off();
}

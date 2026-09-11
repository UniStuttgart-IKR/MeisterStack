// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a device adds to the VM's slice.

use super::*;

#[test]
fn each_device_backend_adds_headroom() {
    let one = Provisioner::limits_for(&spec(
        2,
        2048,
        vec![device("nvrm", PartitionSpec::Mediated)],
    ));
    let two = Provisioner::limits_for(&spec(
        2,
        2048,
        vec![
            device("nvrm", PartitionSpec::Mediated),
            device("crosvm-gpu", PartitionSpec::Mediated),
        ],
    ));
    assert_eq!(one.memory_max, Some((2048 + 112 + 512) * 1024 * 1024));
    assert_eq!(two.memory_max, Some((2048 + 112 + 1024) * 1024 * 1024));
}

#[test]
fn vfio_pinning_gets_extra_headroom() {
    let l = Provisioner::limits_for(&spec(
        2,
        2048,
        vec![device("vfio", PartitionSpec::Exclusive)],
    ));
    assert_eq!(l.memory_max, Some((2048 + 112 + 512 + 256) * 1024 * 1024));
}

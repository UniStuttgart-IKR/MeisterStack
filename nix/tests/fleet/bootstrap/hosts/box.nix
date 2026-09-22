# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The machine `box` of nix/tests/bootstrap.nix, which is a virtual one.
#
# What a `hardware-configuration.nix` carries, and nothing else: this file is
# the operator's half, and the operator's half is the hardware.
{ ... }:
{
  # The drivers its initrd needs to SEE the disk and the network. Measured in
  # 3A, not guessed: without them the machine booted from its own disk with
  # the right `init=` and panicked twenty-two seconds later, because no
  # driver could find a root filesystem. The medium does not have this
  # problem (`hardware.enableAllHardware` puts every driver in ITS initrd),
  # so the install succeeds and the FIRST BOOT is where it shows — which is
  # exactly the shape of this mistake on real metal.
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_scsi"
    "virtio_net"
    "ahci"
    "sd_mod"
  ];

  # One NIC, and it is called what the inventory calls it.
  #
  # A machine of this test is NOT a node of the test framework: nothing
  # writes a udev rule that renames its interface, and nothing hands it an
  # address. So the name is made simple rather than predictable — one NIC,
  # `net.ifnames=0`, `eth0` — and the address comes from the inventory
  # (`networks.management.static = true`).
  networking.usePredictableInterfaceNames = false;
  # Nothing on this virtual network answers a lease, and an interface that
  # already has its address from the plan must not have a second author.
  networking.useDHCP = false;

  # The disk the layout shapes. A virtio disk with a serial gets
  # /dev/disk/by-id/virtio-<serial> and no model in the name (M0 probe S7),
  # which is why the installer compares this device with the serial it was
  # given instead of deriving one from the other.
  disko.devices.disk.main.device = "/dev/disk/by-id/virtio-MEISTERBOX01";
}

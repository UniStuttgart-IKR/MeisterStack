# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Virtual hardware fixture; inventory supplies the deployment identity.
{ ... }:
{
  # Include the drivers required to find the installed root filesystem.
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_scsi"
    "virtio_net"
    "ahci"
    "sd_mod"
  ];

  # Match the interface name used by the static inventory.
  networking.usePredictableInterfaceNames = false;
  # Use the inventory address without DHCP.
  networking.useDHCP = false;

  # Load Intel KVM for nested guests; this fixture requires a matching host.
  boot.kernelModules = [ "kvm-intel" ];

  # Bind the layout to the virtual disk's stable serial path.
  disko.devices.disk.main.device = "/dev/disk/by-id/virtio-MEISTERN101";
}

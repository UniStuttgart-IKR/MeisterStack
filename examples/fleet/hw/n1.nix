# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The machine n1: a workload carrier that boots itself (`boot = "uefi"`).
{ ... }:
{
  # Which disk `install.layout` shapes — see hw/box.nix for why it is a
  # by-id name and not /dev/nvme0n1.
  disko.devices.disk.main.device = "/dev/disk/by-id/nvme-SAMSUNG_MZQL2480_MEISTERN10001";
}

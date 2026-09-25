# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Host hardware fixture imported through [[host]].modules.
{ ... }:
{
  boot.kernelModules = [ "kvm-intel" ];

  # Stable example disk path; an actual deployment must match the real device.
  disko.devices.disk.main.device = "/dev/disk/by-id/nvme-SAMSUNG_MZQL2960_MEISTERBOX0001";
}

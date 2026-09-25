# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Direct-boot host fixture using a provider-supplied kernel and initrd.
{ ... }:
{
  # Virtio disk path selected by serial.
  disko.devices.disk.main.device = "/dev/disk/by-id/virtio-MEISTERN20001";
}

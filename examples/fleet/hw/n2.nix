# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The machine n2: the same role as n1 and the other boot mode.
#
# n2 is `boot = "direct"` in the inventory — a guest whose hypervisor loads
# its kernel — so its layout is disko/single-direct.nix (no ESP) and this
# flake builds it a bundle: `nix build .#example-direct-boot` is the kernel,
# the initrd and the command line the provider is handed. It exists in the
# example so that both roads are BUILT by `nix flake check` rather than only
# described.
{ ... }:
{
  # A virtio disk, which is what a guest usually gets: the by-id name of one
  # is `virtio-<serial>` and carries no model (M0 probe S7).
  disko.devices.disk.main.device = "/dev/disk/by-id/virtio-MEISTERN20001";
}

# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The hardware of one box, and it is NOT ours.
#
# `[[node]] modules = [ "hw/box.nix" ]` in the plan names files like this one,
# relative to the plan itself, and they are imported into that node's system
# next to our modules. This is where an NVIDIA driver, a Mellanox firmware
# package, a kernel option or a `hardware-configuration.nix` goes — none of
# which this stack models, and none of which it should: a fleet tool that
# tries to describe somebody's cards ends up describing them badly.
#
# What is in here is the smallest thing that proves the road is real.
{ ... }:
{
  boot.kernelModules = [ "kvm-intel" ];

  # Which disk `install.layout` shapes. The layout is a shape and says
  # nothing about a machine; this line is the machine. Bound through
  # /dev/disk/by-id and never /dev/nvme0n1, because that name is handed out
  # in boot order — and the by-id name carries the transport and the model
  # as well, which is why it cannot be derived from the serial alone (M0
  # probe S7) and why `meister-install confirm` checks the two against each
  # other before it formats anything.
  disko.devices.disk.main.device = "/dev/disk/by-id/nvme-SAMSUNG_MZQL2960_MEISTERBOX0001";
}

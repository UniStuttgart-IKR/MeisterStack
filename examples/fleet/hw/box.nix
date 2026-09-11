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
}

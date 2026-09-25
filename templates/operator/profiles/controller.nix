# SPDX-License-Identifier: MIT
# A host that carries the control plane: a cloud, a cluster, or both.
{ config, lib, pkgs, ... }:
{
  # Use a labelled data device. Remove this setting if state intentionally lives
  # on root, and align inventory persistence with that decision.
  meisterstack.data.label = lib.mkDefault "meister-data";
}

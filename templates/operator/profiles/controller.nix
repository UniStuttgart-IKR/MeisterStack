# SPDX-License-Identifier: MIT
# A host that carries the control plane: a cloud, a cluster, or both.
{ config, lib, pkgs, ... }:
{
  # etcd's state on its own block device, by LABEL. Drop this line if the
  # controller keeps its state on the root filesystem — and then say so in
  # the inventory's `persistence`, because a database that quietly landed
  # somewhere else is the failure this pair of settings guards against.
  meisterstack.data.label = lib.mkDefault "meister-data";
}

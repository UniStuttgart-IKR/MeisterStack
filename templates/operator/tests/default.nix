# SPDX-License-Identifier: MIT
# Add site checks to the generated config, inventory-parity and manifest checks.
# The empty set adds no validation.
{ nixpkgs, fleet }:
{
  # Optional enrollment check after every host has a trusted SSH key.
  #
  # all-hosts-enrolled =
  #   let
  #     lib = nixpkgs.lib;
  #     missing = lib.attrNames
  #       (lib.filterAttrs (_: h: h.ssh.host_key == null) fleet.inventory.hosts);
  #   in
  #   nixpkgs.legacyPackages.x86_64-linux.runCommand "all-hosts-enrolled" { }
  #     (if missing == [ ] then "touch $out" else ''
  #       echo "not enrolled: ${lib.concatStringsSep ", " missing}"
  #       exit 1
  #     '');
}

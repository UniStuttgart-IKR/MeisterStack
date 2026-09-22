# SPDX-License-Identifier: MIT
# Your own checks, merged into `nix flake check` next to the fleet's.
#
# What the fleet already brings (nix/lib/mkFleet.nix in the stack):
#
#   config-<id>         the real parsers against this host's rendered
#                       configuration files — `meister-agent --check-config`
#                       and friends, which start nothing
#   inventory-parity    Nix and `meister-deploy inventory` agree about what
#                       every host inherited
#   manifest-json       what Nix derived, against the types that read it
#
# What belongs here instead: anything about YOUR fleet. A nixosTest that
# boots two of your hosts and checks that the one reaches the other; a
# derivation that greps your rendered config for a value your site requires;
# a check that every host in fleet.toml has a host key by now.
#
# It is empty on purpose — an empty set claims nothing. A check that says
# "ok" without looking is worse than no check.
{ nixpkgs, fleet }:
{
  # Example: every host of this fleet is enrolled (has an ssh host key in
  # the inventory). Uncomment once you have run `keys enroll` for all of
  # them; before that it is a check you would have to keep switching off.
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

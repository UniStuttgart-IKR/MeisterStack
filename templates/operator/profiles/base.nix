# SPDX-License-Identifier: MIT
# What every host of this fleet is, as a MACHINE. This file is yours.
#
# MeisterStack's own modules decide nothing in here on purpose (the check
# `services-are-pure` in the stack holds them to it): stateVersion, the
# firewall, the filesystems and the bootloader are answers about a machine,
# and a fleet tool that gave them would be a fleet tool nobody can import.
{ config, lib, pkgs, ... }:
{
  # Which NixOS this machine's state started on. Set it once, per fleet, and
  # then leave it alone.
  system.stateVersion = "25.11";

  # NO `fileSystems` here, and that is deliberate.
  #
  # A host this tool installs names a `layout` in its `install` table, and
  # `lib.mkFleet` imports that disko module into the host: the partition
  # table and the filesystems then come out of ONE file, and `disko` is
  # their only author. A `fileSystems."/"` in this profile would be a second
  # author for the same mount — the one case where the two disagree is a
  # machine that comes up on the wrong disk, and neither half would say so.
  #
  # A host this tool does NOT install — a machine somebody else partitioned,
  # or one taken over — says where its root is in its own module, and
  # hosts/cp-1.nix shows exactly that.

  # Your rules. `meisterstack.ports` is what the stack LISTENS on — it opens
  # nothing and closes nothing — so the numbers are named here, once.
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = with config.meisterstack.ports; [
    cloud.api
    cloud.grpc
    cluster.api
    cluster.grpc
    etcd.peer
  ];

  # The signing key whose closures these hosts accept.
  #
  # Measured, not assumed (M0 probe S12): a managed host runs nix with
  # `require-sigs = true`, and `nix copy --to ssh-ng://root@host` of an
  # UNSIGNED closure is refused — "cannot add path … because it lacks a
  # signature by a trusted key" — even though root is a trusted user. Being
  # trusted is not being signed.
  #
  # So this fleet needs a signing key before it can deploy. Make one, keep
  # the secret half out of git, and commit the public half:
  #
  #   nix-store --generate-binary-cache-key my-fleet keys/signing.sec signing.pub
  #
  # `keys/` is in .gitignore; `signing.pub` is public and belongs in the
  # repository. Until it is there, a host of this fleet builds nothing and
  # says this sentence — which is better than a closure no target will take.
  meisterstack.managed.trustedPublicKeys =
    lib.optional (builtins.pathExists ../signing.pub)
      (lib.fileContents ../signing.pub);

  # Binary caches these hosts may fetch from. Empty is a host that is only
  # ever pushed to, which is the smaller attack surface.
  meisterstack.managed.substituters = [ ];
}

# SPDX-License-Identifier: MIT
# Shared host policy; service modules leave these choices to the operator.
{ config, lib, pkgs, ... }:
{
  # Keep the original stateVersion when upgrading an existing host.
  system.stateVersion = "25.11";

  # Installed hosts get mounts from install.layout via disko.
  # Existing hosts declare their mounts in hosts/<id>.nix; do not define both.

  # Open the chosen service ports; the stack only publishes their numbers.
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = with config.meisterstack.ports; [
    cloud.api
    cloud.grpc
    cluster.api
    cluster.grpc
    etcd.peer
  ];

  # Read the public closure-signing key committed as signing.pub.
  # Generate its private half outside tracked files, for example:
  # nix-store --generate-binary-cache-key my-fleet keys/signing.sec signing.pub
  meisterstack.managed.trustedPublicKeys =
    lib.optional (builtins.pathExists ../signing.pub)
      (lib.fileContents ../signing.pub);

  # Configure binary caches in fleet.toml under managed.substituters.
  # Host modules can override the inventory default. Trusted signatures still apply.
}

# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Evaluate hosts that import nixosModules.services without nix/managed.nix,
# the way an existing NixOS configuration does. Each expectation names one
# default that has to fail closed on such a host.
{ nixpkgs, lib, pkgs, system, self }:
let
  # A host that is valid apart from what the modules under test contribute,
  # so that every failed assertion is one of ours.
  probe = modules: (nixpkgs.lib.nixosSystem {
    modules = [
      self.nixosModules.services
      {
        nixpkgs.hostPlatform = system;
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.grub.device = "nodev";
        system.stateVersion = "25.11";
      }
    ] ++ modules;
  }).config;

  failedAssertions = c: map (a: a.message) (lib.filter (a: !a.assertion) c.assertions);
  refusesWith = needle: c: lib.any (lib.hasInfix needle) (failedAssertions c);
  accepted = c: failedAssertions c == [ ];

  cloud = extra: probe [{ meisterstack.roles = [ "cloud" ]; } extra];
  cluster = extra: probe [{ meisterstack.roles = [ "cluster" ]; } extra];
  agent = extra: probe [{ meisterstack.roles = [ "agent" ]; } extra];

  expectations = {
    "a cloud that names no authenticator is refused" =
      refusesWith "names no authenticator" (cloud { });
    "a cloud that names its chain is accepted" =
      accepted (cloud { meisterstack.cloud.settings.auth.chain = [ "mtls" ]; });
    "a cluster names mtls without being asked" =
      accepted (cluster { });
    "a cluster whose chain was emptied is refused" =
      refusesWith "auth.chain is empty" (cluster { meisterstack.cluster.settings.auth.chain = [ ]; });

    "a host with a role runs no log collector unless asked" =
      !(cluster { }).services.alloy.enable;
    "the host's own Alloy keeps its config path" =
      (cluster { services.alloy.enable = true; }).services.alloy.configPath == "/etc/alloy";
    "asking for the collector beside the host's own Alloy is refused" =
      refusesWith "services.alloy itself" (cluster {
        services.alloy.enable = true;
        meisterstack.observability.enable = true;
      });
    "asking for the collector beside a host default for Alloy is refused" =
      refusesWith "services.alloy itself" (cluster {
        services.alloy.enable = lib.mkDefault true;
        meisterstack.observability.enable = true;
      });
    "asked for alone, the collector reads the stack's config" =
      let c = cluster { meisterstack.observability.enable = true; }; in
      accepted c && c.services.alloy.enable
      && c.services.alloy.configPath == "${c.meisterstack.configDir}/alloy.alloy";

    "a host starts no role unit at boot unless asked" =
      let c = cluster { }; in
      c.systemd.services.meister-cluster-controller.wantedBy == [ ]
      && (agent { }).systemd.services.meister-agent.wantedBy == [ ];
    "asked to, a host starts its role units at boot" =
      let c = cluster { meisterstack.autostart = true; }; in
      builtins.elem "multi-user.target" c.systemd.services.meister-cluster-controller.wantedBy;

    "a host without a data block mounts none" =
      let c = cluster { meisterstack.data.label = null; }; in
      !(c.fileSystems ? "/var/lib/etcd") && !(c.fileSystems ? "/var/lib/meister-data");

    "metrics listen on loopback unless asked" =
      (cluster { }).meisterstack.cluster.effective.metrics_listen == "127.0.0.1:9101"
      && (agent { }).meisterstack.agent.effective.metrics_listen == "127.0.0.1:9102";
    "metrics on one address wait for the network" =
      let c = cluster { meisterstack.metrics.listenAddress = "fd00::10"; }; in
      c.meisterstack.cluster.effective.metrics_listen == "[fd00::10]:9101"
      && builtins.elem "network-online.target" c.systemd.services.meister-cluster-controller.wants;

    "nix run of the package starts the CLI" =
      self.packages.${system}.meisterstack.meta.mainProgram == "meister";

    "an agent holds no address on the default guest bridge unless asked" =
      !((agent { }).meisterstack.agent.effective.network ? bridge_addr);
    "an agent keeps guests from opening connections to the host" =
      let c = agent { }; in
      c.meisterstack.agent.guestGuard.enable
      && builtins.elem "meister-agent.service" c.systemd.services.meister-guest-guard.requiredBy;
  };

  broken = lib.attrNames (lib.filterAttrs (_: holds: !holds) expectations);
in
pkgs.runCommand "standalone-host" { } (
  if broken == [ ] then ''
    ${lib.concatMapStrings (e: "echo ${lib.escapeShellArg "ok   ${e}"}\n") (lib.attrNames expectations)}
    touch $out
  '' else ''
    ${lib.concatMapStrings (e: "echo ${lib.escapeShellArg "FAIL ${e}"}\n") broken}
    echo "-> a host without nix/managed.nix got a default that does not fail closed"
    exit 1
  ''
)

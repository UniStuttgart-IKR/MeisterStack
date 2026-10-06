# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Evaluate the agent unit's sandbox. Each expectation names one property the
# agent's work depends on; a VM test would show the same thing slower.
{ nixpkgs, lib, pkgs, system, self }:
let
  agentUnit = extra: (nixpkgs.lib.nixosSystem {
    modules = [
      self.nixosModules.services
      {
        nixpkgs.hostPlatform = system;
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.grub.device = "nodev";
        system.stateVersion = "25.11";
        meisterstack.roles = [ "agent" ];
      }
      extra
    ];
  }).config.systemd.services.meister-agent.serviceConfig;

  # Every setting that gives a unit a mount namespace of its own (systemd.exec(5)).
  # systemd makes that namespace a slave of the host's whatever MountFlags says,
  # so a mount made inside it never reaches the host.
  namespacing = [
    "ProtectHome" "ProtectSystem" "PrivateTmp" "PrivateDevices" "PrivateMounts"
    "PrivateNetwork" "ProtectKernelTunables" "ProtectKernelModules"
    "ProtectKernelLogs" "ProtectControlGroups" "ProtectProc" "ProcSubset"
    "ProtectHostname" "ReadWritePaths" "ReadOnlyPaths" "InaccessiblePaths"
    "ExecPaths" "NoExecPaths" "BindPaths" "BindReadOnlyPaths"
    "TemporaryFileSystem" "MountAPIVFS" "RootDirectory" "RootImage" "MountFlags"
  ];
  unset = v: v == false || v == "" || v == [ ] || v == "no";
  ownMountNamespace = unit:
    lib.any (key: unit ? ${key} && !(unset unit.${key})) namespacing;

  root = agentUnit { };
  computeOnly = agentUnit { meisterstack.agent.unprivileged = true; };
  unprivilegedMounting = agentUnit {
    meisterstack.agent.unprivileged = true;
    meisterstack.agent.capabilities = [ "CAP_NET_ADMIN" "CAP_SYS_ADMIN" ];
  };

  expectations = {
    # IKR-B69: the routers' `ip netns` pins live in the host's /run and outlive the agent.
    "a root agent has no mount namespace of its own" = !(ownMountNamespace root);
    "an unprivileged agent that may mount has none either" =
      !(ownMountNamespace unprivilegedMounting);
    "an agent that cannot mount keeps the home directories closed" =
      computeOnly.ProtectHome or false;
  };

  broken = lib.attrNames (lib.filterAttrs (_: holds: !holds) expectations);
in
pkgs.runCommand "agent-unit-sandbox" { } (
  if broken == [ ] then ''
    ${lib.concatMapStrings (e: "echo ${lib.escapeShellArg "ok   ${e}"}\n") (lib.attrNames expectations)}
    touch $out
  '' else ''
    ${lib.concatMapStrings (e: "echo ${lib.escapeShellArg "FAIL ${e}"}\n") broken}
    exit 1
  ''
)

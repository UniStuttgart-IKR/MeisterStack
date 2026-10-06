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

  # The settings an agent that mounts may carry, each read in systemd.exec(5) and
  # known to leave the unit in the host's mount namespace. Any other setting counts
  # as one of its own until somebody has read it up and added it here: a list of the
  # settings that do namespace (ProtectHome, PrivateTmp, ReadOnlyPaths, DynamicUser,
  # LogNamespace, PrivatePIDs, MountImages, ...) missed some, and systemd adds more.
  # systemd makes such a namespace a slave of the host's whatever MountFlags says, so
  # a mount made inside it never reaches the host.
  hostMountNamespace = [
    "ExecStart" "ExecStartPre" "Restart" "RestartSec" "Environment"
    "RestrictAddressFamilies" "User" "Group" "SupplementaryGroups"
    "AmbientCapabilities" "CapabilityBoundingSet" "Delegate" "DelegateSubgroup"
    "DevicePolicy" "DeviceAllow"
  ];
  unset = v: v == false || v == "" || v == [ ] || v == "no";
  ownMountNamespace = unit:
    lib.any (key: !(lib.elem key hostMountNamespace) && !(unset unit.${key}))
      (lib.attrNames unit);

  families = unit:
    lib.sort lib.lessThan (lib.filter (f: f != "") (lib.splitString " " unit.RestrictAddressFamilies));

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
    "a setting nobody has read up counts as a mount namespace of its own" =
      lib.all (setting: ownMountNamespace (root // setting)) [
        { DynamicUser = true; }
        { LogNamespace = "meister"; }
        { PrivatePIDs = true; }
        { MountImages = [ "/img.raw:/mnt" ]; }
        { ExtensionDirectories = [ "/ext" ]; }
        { RootEphemeral = true; }
      ];

    # IKR-B75: arping opens an AF_PACKET socket, and nothing beyond it is opened.
    "the agent may open packet sockets for gratuitous ARP and no other new family" =
      lib.all (unit: families unit == lib.sort lib.lessThan [
        "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" "AF_PACKET" "AF_VSOCK"
      ]) [ root computeOnly ];
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

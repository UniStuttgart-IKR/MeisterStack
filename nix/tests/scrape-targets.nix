# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A Prometheus scrapes every role's metrics listener at the host's address.
# Each expectation names one way a host could bind its listeners where that
# address does not answer. The fleet half (a fleet host that binds elsewhere is
# refused) is meister-deploy's.
{ nixpkgs, lib, pkgs, system, self }:
let
  net = import ../lib/net.nix { inherit lib; };

  # A host whose config is rendered at boot, the way the appliance image is.
  renderedSystem = nixpkgs.lib.nixosSystem {
    modules = [
      self.nixosModules.services
      {
        nixpkgs.hostPlatform = system;
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.grub.device = "nodev";
        system.stateVersion = "25.11";
        meisterstack.roles = [ "agent" ];
        meisterstack.context.enable = true;
      }
    ];
  };
  rendered = renderedSystem.config;
  renderedWith = module: (renderedSystem.extendModules { modules = [ module ]; }).config;
  v6only = { boot.kernel.sysctl."net.ipv6.bindv6only" = 1; };

  expectations = {
    "an IPv4 host is scraped at its address, 0.0.0.0 or ::" =
      net.listensAnsweringAt rendered "10.0.0.5" 9102 == [ "10.0.0.5:9102" "0.0.0.0:9102" "[::]:9102" ];
    "an IPv4 host is not scraped at :: where IPv6 sockets take IPv6 only" =
      net.listensAnsweringAt (renderedWith v6only) "10.0.0.5" 9102 == [ "10.0.0.5:9102" "0.0.0.0:9102" ];
    "an IPv6 host is scraped at its address or ::, never at 0.0.0.0" =
      net.listensAnsweringAt rendered "fd00::5" 9102 == [ "[fd00::5]:9102" "[::]:9102" ]
      && net.listensAnsweringAt (renderedWith v6only) "fd00::5" 9102 == [ "[fd00::5]:9102" "[::]:9102" ];
    "a host that renders its config at boot binds every address of both families" =
      rendered.meisterstack.agent.effective.metrics_listen == "[::]:9102";
    "and every IPv4 address where :: takes IPv6 only" =
      (renderedWith v6only).meisterstack.agent.effective.metrics_listen == "0.0.0.0:9102";
    "and every IPv4 address where the kernel has no IPv6" =
      (renderedWith { boot.kernelParams = [ "ipv6.disable=1" ]; })
        .meisterstack.agent.effective.metrics_listen == "0.0.0.0:9102";
  };

  broken = lib.attrNames (lib.filterAttrs (_: holds: !holds) expectations);
in
pkgs.runCommand "scrape-targets" { } (
  if broken == [ ] then ''
    ${lib.concatMapStrings (e: "echo ${lib.escapeShellArg "ok   ${e}"}\n") (lib.attrNames expectations)}
    touch $out
  '' else ''
    ${lib.concatMapStrings (e: "echo ${lib.escapeShellArg "FAIL ${e}"}\n") broken}
    echo "-> a host can bind its metrics where its Prometheus does not look"
    exit 1
  ''
)

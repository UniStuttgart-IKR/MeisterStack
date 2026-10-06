# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The addons host of a fleet scrapes every role's metrics listener at the
# host's management address. Each expectation names one way a host could drop
# out of that without anyone noticing.
{ nixpkgs, lib, pkgs, system, self }:
let
  failedAssertions = c: map (a: a.message) (lib.filter (a: !a.assertion) c.assertions);
  refusesWith = needle: c: lib.any (lib.hasInfix needle) (failedAssertions c);
  dropsOut = refusesWith "silently loses this host";

  fleet = self.nixosConfigurations;
  rebound = modules: (fleet.n1.extendModules { inherit modules; }).config;

  # A host whose config is rendered at boot, the way the appliance image is.
  rendered = (nixpkgs.lib.nixosSystem {
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
  }).config;

  expectations = {
    "every host of the example fleet binds the address it is scraped at" =
      lib.all (s: !(dropsOut s.config)) (lib.attrValues fleet);
    "a fleet host whose metrics bind loopback is refused" =
      dropsOut (rebound [{ meisterstack.metrics.listenAddress = "127.0.0.1"; }]);
    "a fleet host whose role rebinds its own listener elsewhere is refused" =
      dropsOut (rebound [{ meisterstack.agent.settings.metrics_listen = "127.0.0.1:9102"; }]);
    "a fleet host may bind every address" =
      !(dropsOut (rebound [{ meisterstack.metrics.listenAddress = "0.0.0.0"; }]));
    "a host that renders its config at boot binds every address" =
      rendered.meisterstack.agent.effective.metrics_listen == "0.0.0.0:9102";
  };

  broken = lib.attrNames (lib.filterAttrs (_: holds: !holds) expectations);
in
pkgs.runCommand "scrape-targets" { } (
  if broken == [ ] then ''
    ${lib.concatMapStrings (e: "echo ${lib.escapeShellArg "ok   ${e}"}\n") (lib.attrNames expectations)}
    touch $out
  '' else ''
    ${lib.concatMapStrings (e: "echo ${lib.escapeShellArg "FAIL ${e}"}\n") broken}
    echo "-> a host can bind its metrics where the fleet's Prometheus does not look"
    exit 1
  ''
)

# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Store-built host profile: binaries and complete role configurations come from
# the system generation; credentials remain writable files outside the store.
# The config files are rendered at build time from `meisterstack.context.defaults`,
# so a boot-time renderer, which would overwrite them, is refused. A deployment
# tool (meister-deploy's nixosModules.managed) adds its transport on top.
{ lib, config, ... }:
let
  cfg = config.meisterstack.storeHost;
  ms = config.meisterstack;

  # Render inventory context defaults with the roles selected for this host.
  env = { MEISTER_NODE_ID = config.networking.hostName; } // ms.context.defaults;

  rendered = import ./lib/render.nix {
    inherit lib;
    cloudAuth = ms.cloud.authFragments;
  } env;

  # Turn MEISTER_HOSTS entries into host-file mappings for local name resolution.
  hostEntries =
    let
      fields = entry: lib.filter (x: x != "")
        (lib.splitString " " (lib.replaceStrings [ "\t" ] [ " " ] entry));
      pair = entry:
        let f = fields entry; in
        if builtins.length f < 2 then null
        else { name = builtins.head f; value = builtins.tail f; };
    in
    if ms.context.defaults ? MEISTER_HOSTS then
      builtins.listToAttrs (lib.filter (p: p != null)
        (map pair (lib.splitString "," ms.context.defaults.MEISTER_HOSTS)))
    else { };
in
{
  imports = [ ./services.nix ];

  options.meisterstack.storeHost.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = ''
      Whether this host takes its binaries and its complete role
      configurations from the system generation: `binDir` is the runtime
      package, the config files are rendered at build time from
      `meisterstack.context.defaults` into /etc/meisterstack, keys live under
      /var/lib/meisterstack/pki and the role units start at boot.

      Off by default, because importing a module should not decide where a
      machine keeps its binaries behind its owner's back. A deployment tool
      that ships closures turns it on (meister-deploy's `managed.enable`
      does), and so may a host that is built and switched by anything else.
    '';
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = !ms.context.enable;
      message =
        "this host takes its config files from the system generation "
        + "(`meisterstack.storeHost.enable`) AND renders them at boot "
        + "(`meisterstack.context.enable`). They are two authors of the same "
        + "files: one writes them into the system generation, the other "
        + "overwrites them at boot, and a rollback would take back only half of "
        + "it. Pick one. This flake ships no such renderer any more — the one the "
        + "lab's context VMs boot lives in ~/git/meisterstack-lab/legacy/nix/context.nix.";
    }];

    # Use the runtime package as the service binary directory.
    meisterstack.binDir = lib.mkDefault "${ms.runtime}/bin";

    # Install complete role configurations under /etc.
    meisterstack.configDir = "/etc/meisterstack";

    # Keep writable keys and image assets under /var/lib.
    meisterstack.pki.dir = lib.mkDefault "/var/lib/meisterstack/pki";

    # Keep guest image assets in persistent storage the host owns.
    meisterstack.agent.imageDir = lib.mkDefault "/var/lib/meisterstack/images";

    # Render role TOML from module defaults and context defaults.
    meisterstack.cloud.generated = rendered.cloud;
    meisterstack.cluster.generated = rendered.cluster;
    meisterstack.agent.generated = rendered.agent;

    # Configure etcd membership directly through NixOS options.
    meisterstack.etcd = lib.mkIf (rendered.etcd.peers != { }) ({
      peers = rendered.etcd.peers;
      clusterToken = rendered.etcd.clusterToken;
    } // lib.optionalAttrs (rendered.etcd.member != null) {
      member = rendered.etcd.member;
    });

    # Install the names the context defaults carry.
    networking.hosts = hostEntries;

    # When a provider script writes resolv.conf, disable resolvconf by default
    # to prevent competing writers during activation and rollback.
    networking.resolvconf.enable =
      lib.mkIf (ms.context.providerScript != "") (lib.mkDefault false);

    # The `meister` CLI for operators on the host, from the same build as the units.
    environment.systemPackages = [ ms.package ];

    # Start the role units at boot; credentials can still gate their startup.
    meisterstack.autostart = lib.mkDefault true;

    # The key directory exists before the first key is delivered into it.
    systemd.tmpfiles.rules = [
      "d /var/lib/meisterstack 0755 root root -"
      "d ${ms.pki.dir} 0755 root root -"
    ];
  };
}

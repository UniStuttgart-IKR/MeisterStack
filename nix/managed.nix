# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Managed NixOS profile: binaries and complete role configurations come from
# the system generation; credentials remain writable files outside the store.
# Configure signed closure transport and deployment state, and reject a
# boot-time renderer that could overwrite the generated configuration.
{ lib, config, ... }:
let
  cfg = config.meisterstack.managed;
  ms = config.meisterstack;

  # Render inventory context defaults with the roles selected for this host.
  env = { MEISTER_NODE_ID = config.networking.hostName; } // ms.context.defaults;

  rendered = import ./lib/render.nix {
    inherit lib;
    cloudAuth = ms.cloud.authFragments;
  } env;

  deployDir = "/var/lib/meisterstack/deploy";

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

  # Disk layouts declare whether they create an ESP; inventory validates that
  # against the selected boot mode.
  options.meisterstack.install.hasEsp = lib.mkOption {
    type = lib.types.bool;
    default = false;
    example = true;
    description = ''
      Whether the disk layout of this host makes an EFI system partition.

      Set by the layout (`templates/operator/disko/single-nvme.nix` says
      `true`, `disko/single-direct.nix` says `false`), read by the inventory
      module, and never guessed: a `boot = "uefi"` host whose layout makes no
      ESP would install systemd-boot nowhere and come back from its first
      reboot with no way to start, and a `boot = "direct"` host with an ESP
      would carry a partition nothing ever writes to.

      The default is `false`, which is the safe direction: a host that names
      no layout at all has no ESP this flake knows about, and only a
      `boot = "uefi"` host with an `install` table is held to it.
    '';
  };

  options.meisterstack.managed = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether this host is deployed to by `meister-deploy`: its closure is
        copied in, staged, activated and confirmed from the outside.

        Off by default, because importing a module should not turn a machine
        into a deployment target behind its owner's back — the appliance
        profile is the other way round, and the difference is that an image
        is built for one purpose and a host is not.
      '';
    };

    substituters = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "https://cache.nixos.org" ];
      description = ''
        Binary caches this host may fetch from. Empty (the default) is a host
        that is only ever pushed to: `nix copy --to ssh-ng://` carries the
        whole closure, and a target that fetches from nowhere cannot be
        surprised by what somebody else put in a cache.
      '';
    };

    trustedPublicKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "meister-lab:ygWfDO2+…" ];
      description = ''
        The signing keys whose closures this host accepts. REQUIRED when
        `enable` is on, and the assertion below says so.

        Measured, not assumed (M0 probe S12): with `require-sigs = true` a
        `nix copy --to ssh-ng://root@host` of an UNSIGNED closure is refused
        — "cannot add path … because it lacks a signature by a trusted key" —
        even though root is a trusted user. Being trusted is not being
        signed. The old `ssh://` store would take it, and that is exactly the
        guarantee `require-sigs` exists for, so the answer is to sign
        (`meister-deploy build --sign-key`) rather than to widen the target.
      '';
    };

    keepGenerations = lib.mkOption {
      type = lib.types.ints.positive;
      default = 3;
      description = ''
        How many system generations besides the running and the booted one
        this host keeps.

        Nothing on the machine acts on this number: automatic gc is off here
        (a host must not collect the closure somebody is about to roll back
        to), and the helper that does the collecting — `meister-activate gc`
        — is part of M2. Until then this is a declared intent that the
        manifest carries and no code reads. It is listed as open in the M1
        report rather than left looking finished.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.trustedPublicKeys != [ ];
        message =
          "meisterstack.managed.trustedPublicKeys is empty: with require-sigs = true "
          + "this host refuses every closure `nix copy --to ssh-ng://` offers it, root "
          + "or not (measured, M0 probe S12). Name the public half of the key "
          + "`meister-deploy build --sign-key` signs with.";
      }
      {
        assertion = !ms.context.enable;
        message =
          "this host imports nix/managed.nix AND something that renders its "
          + "config files at boot (`meisterstack.context.enable`). They are two "
          + "authors of the same files: one writes them into the system "
          + "generation, the other overwrites them at boot, and a rollback would "
          + "take back only half of it. Pick one. This flake ships no such "
          + "renderer any more — the one the lab's context VMs boot lives in "
          + "~/git/meisterstack-lab/legacy/nix/context.nix.";
      }
    ];

    # Use the runtime package as the service binary directory.
    meisterstack.binDir = lib.mkDefault "${ms.runtime}/bin";

    # Install complete role configurations under /etc.
    meisterstack.configDir = "/etc/meisterstack";

    # Keep writable keys and image assets under /var/lib.
    meisterstack.pki.dir = lib.mkDefault "/var/lib/meisterstack/pki";

    # Keep guest image assets in managed persistent storage.
    meisterstack.agent.imageDir = lib.mkDefault "/var/lib/meisterstack/images";
    # The fleet's host-local gateway on the default guest bridge, as before.
    meisterstack.agent.bridgeAddress = lib.mkDefault "10.42.0.1/24";
    # Render role TOML from module defaults and inventory settings.
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

    # Install names derived from the fleet inventory.
    networking.hosts = hostEntries;

    # When a provider script writes resolv.conf, disable resolvconf by default
    # to prevent competing writers during activation and rollback.
    networking.resolvconf.enable =
      lib.mkIf (ms.context.providerScript != "") (lib.mkDefault false);
    # Include deployment helpers used remotely over SSH, in addition to the
    # role daemons named by service units.
    environment.systemPackages = [ ms.package ];

    # Enable selected role units at boot; credentials can still gate their startup.
    systemd.services = lib.mkMerge (map
      (role:
        lib.mkIf (builtins.elem role ms.unitsFor) {
          ${if role == "agent" then "meister-agent" else "meister-${role}-controller"}
            .wantedBy = [ "multi-user.target" ];
        })
      [ "cloud" "cluster" "agent" ]);

    # Signed closure transport and local deployment support.
    nix.enable = true;
    nix.settings = {
      # Keep local builds sandboxed.
      sandbox = true;

      # Require signatures for imported and substituted store paths.
      require-sigs = true;

      trusted-users = [ "root" ];
      allowed-users = [ "root" ];

      inherit (cfg) substituters;
      trusted-public-keys = cfg.trustedPublicKeys;

      # Enable the commands used by closure transport and inspection.
      experimental-features = [ "nix-command" ];
    };

    # Disable automatic garbage collection so rollback generations remain available.
    nix.gc.automatic = false;

    # Default to key-authenticated root SSH for deployment; host modules may override it.
    services.openssh.enable = lib.mkDefault true;
    services.openssh.settings.PermitRootLogin = lib.mkDefault "prohibit-password";

    # Persist transaction records and locks across reboots with root-only access.
    systemd.tmpfiles.rules = [
      "d /var/lib/meisterstack 0755 root root -"
      "d ${ms.pki.dir} 0755 root root -"
      "d ${deployDir} 0700 root root -"
      "d ${deployDir}/txn 0700 root root -"
      "d ${deployDir}/lock 0700 root root -"
    ];
  };
}

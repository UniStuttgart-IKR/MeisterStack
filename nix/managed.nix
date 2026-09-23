# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A host `meister-deploy` deploys to.
#
# The difference to nix/appliance.nix is one sentence: here the configuration
# IS the system generation. Nothing is rendered while the machine boots, so
# there is nothing a rollback cannot take back — the config files, the etcd
# membership and the [auth] table of the cloud are all written by Nix, out of
# the same `meisterstack.context.defaults` the boot renderer would have read,
# through nix/lib/render.nix. `checks.render-parity` runs both over the same
# input and compares the parsed TOML, because two renderers is one too many.
#
# What this profile does NOT decide, on purpose: dhcp, firewall,
# `system.stateVersion`, the bootloader, the filesystems. A managed host is
# somebody's own NixOS host with a plan attached, and those are the lines
# their repository owns. What it does decide is what deploying REQUIRES: nix
# stays on and takes signed closures only, the keys live outside the store,
# and there are directories for the transaction records the helper writes.
#
# resolvconf used to be on that first list and is now the one exception,
# under a condition: see the lane 5C block below. A file with two authors is
# a file that breaks an activation AND its rollback, and the lab measured
# exactly that.
{ lib, config, ... }:
let
  cfg = config.meisterstack.managed;
  ms = config.meisterstack;

  # The same variables the boot renderer would have sourced, plus the one it
  # reads off the machine instead: `node_id` is the hostname there
  # (`cat /proc/sys/kernel/hostname`), and here it is the hostname Nix knows.
  # Written as an ordinary context variable so that the function stays a
  # function of its context and of nothing else.
  env = { MEISTER_NODE_ID = config.networking.hostName; } // ms.context.defaults;

  rendered = import ./lib/render.nix {
    inherit lib;
    cloudAuth = ms.cloud.authFragments;
  } env;

  deployDir = "/var/lib/meisterstack/deploy";

  # MEISTER_HOSTS = "10.0.0.10 box.lab.example", several of them separated by
  # commas: the /etc/hosts lines a fleet without a dns has to be told. It is
  # the one context value that is not a config key, which is why it is here
  # and not in nix/lib/render.nix.
  #
  # nix/fleet.nix calls it a CONTEXT value on purpose, because on an appliance
  # /etc/hosts has exactly one owner — the renderer, the same one resolv.conf
  # has — and a fleet can be re-pointed at a new addons box without rebuilding
  # an image. A managed host has no renderer, so the owner here is
  # `networking.hosts`, and re-pointing it is a new generation. Without this
  # the cloud of such a host could not resolve the issuer in the token it is
  # verifying (nix/addons.nix: origin, issuer, redirect and certificate are
  # one and the same NAME).
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

  # What the LAYOUT knows and nobody else does.
  #
  # `install.layout` in the inventory names a disko module, and that module
  # is the one file that decides whether this machine has an EFI system
  # partition — it either makes an EF00 partition or it does not.
  # nix/lib/inventory.nix compares the answer against `boot` (uefi needs one,
  # direct must not have one), which is a comparison somebody has to be able
  # to make without parsing a partition table. So the layout says it out
  # loud, here, in one line.
  #
  # Declared outside `config` and outside the `managed.enable` gate on
  # purpose: a layout is imported into a host by lib.mkFleet whether or not
  # that host is managed, and an option that only exists sometimes is an
  # option a layout cannot set.
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
          "this host imports both nix/managed.nix and the boot renderer "
          + "(nix/context.nix, usually through nix/appliance.nix). They are two "
          + "authors of the same config files: one writes them into the system "
          + "generation, the other overwrites them at boot, and a rollback would "
          + "take back only half of it. Pick one profile.";
      }
    ];

    # The binaries are part of the system, out of the store, and that is the
    # whole difference to an appliance: no push, no `.new` file left behind
    # by an interrupted rsync, no question which tree they were built from.
    # `meisterstack.runtime` (nix/services.nix) is the one directory the
    # agent's unit can name both of its programs in; `mkDefault` because an
    # operator who builds their own may say so.
    meisterstack.binDir = lib.mkDefault "${ms.runtime}/bin";

    # The config files are complete and in /etc, so that is where the units
    # read them — and that is what makes the configuration a generation
    # rather than a thing that happens at boot.
    meisterstack.configDir = "/etc/meisterstack";

    # Under /var/lib rather than /opt: nothing pushes into this host's
    # filesystem by hand any more, and the FHS answer for state a service
    # owns is /var/lib. Still outside the nix store, because a private key
    # must not be world-readable, and still `meister:meister 0600` — the
    # loaders refuse anything wider (M0 probe S11 measured what
    # LoadCredential hands a unit instead).
    meisterstack.pki.dir = lib.mkDefault "/var/lib/meisterstack/pki";

    # --- lane 4C ---
    # And the guest images, for the same reason and into the same place.
    # /opt/meisterstack is what `legacy context-push` writes into, and a
    # managed host has no push; the volume records and the keys are already
    # under /var/lib/meisterstack, so the image cache being somewhere else
    # was inconsistent rather than wrong (lane 1B, open point 6). The
    # appliance keeps its own answer, which is what `checks.render-parity`
    # holds both sides to.
    meisterstack.agent.imageDir = lib.mkDefault "/var/lib/meisterstack/images";
    # --- end lane 4C ---

    # The three roles' per-machine keys, from the same context the renderer
    # would have read. This is the whole point of the profile: node_id, the
    # controller addresses, the advertise addresses, the telemetry keys and
    # the cloud's [auth] table are values at build time here.
    meisterstack.cloud.generated = rendered.cloud;
    meisterstack.cluster.generated = rendered.cluster;
    meisterstack.agent.generated = rendered.agent;

    # And the etcd membership as options rather than as an env file: there is
    # no renderer to write /run/meisterstack/etcd.env, and `peers` has been
    # the build-time road since nix/etcd.nix learned to cluster.
    meisterstack.etcd = lib.mkIf (rendered.etcd.peers != { }) ({
      peers = rendered.etcd.peers;
      clusterToken = rendered.etcd.clusterToken;
    } // lib.optionalAttrs (rendered.etcd.member != null) {
      member = rendered.etcd.member;
    });

    # The names this machine must resolve without a dns, from the same
    # context. Merged with what NixOS puts there anyway (localhost), never
    # replacing it.
    networking.hosts = hostEntries;

    # --- lane 5C: one author for /etc/resolv.conf -------------------------
    #
    # Measured in the lab on 2026-09-23, on a managed host that reads an
    # OpenNebula CONTEXT cd: the strict reader writes ETH0_DNS straight into
    # /etc/resolv.conf, NixOS' resolvconf owns that file, and it refuses one
    # it did not sign —
    #
    #   network-setup-start: .resolvconf-wrapped: signature mismatch:
    #   /etc/resolv.conf
    #   network-setup.service: Failed with result 'exit-code'
    #
    # In the middle of `switch-to-configuration` that is exit 4, so the
    # ACTIVATION failed; and because the way back is the same command, the
    # ROLLBACK failed with the same sentence and the host ended in
    # `recovery-required`. nix/appliance.nix has carried
    # `resolvconf.enable = false` since 2026-09-08 for exactly this reason,
    # and the managed profile did not.
    #
    # Conditional, not flat, because the condition IS the finding: two
    # authors for one file. Where a provider script writes the resolver, it
    # is the author and resolvconf steps aside. Where there is none — the
    # ordinary managed host, with a static address or a dhcp lease — this
    # profile decides nothing, which is the promise at the top of this file.
    # `mkDefault` on top of that: an operator who runs a resolver of their
    # own says so and wins.
    networking.resolvconf.enable =
      lib.mkIf (ms.context.providerScript != "") (lib.mkDefault false);
    # --- end lane 5C ------------------------------------------------------

    # The collector stays off, and this is a gap rather than a decision: its
    # config is not TOML, the boot renderer writes it from MEISTER_LOKI_URL,
    # and baking it is work this lane did not do. A unit whose
    # ConditionPathExists can never be met would be worse — it would look
    # like a collector that is merely idle.
    meisterstack.observability.enable = lib.mkDefault false;

    # The two programs a deployment TYPES on this host, as opposed to the
    # ones its units exec.
    #
    # `meisterstack.binDir` is what an ExecStart names, and an ExecStart is
    # not a PATH. Both halves of M2 reach this host over ssh and type a bare
    # word: `meister-activate status --json` is how the observation asks what
    # is open here and `meister-activate activate` is how a rollout moves the
    # profile (D5), and the read-only probe finds it with
    # `command -v meister-activate` (tools/meister-deploy/src/observe.rs). The
    # same probe counts this node's guests with `meister --endpoint
    # unix://<socket> agent vm ls`, which is the drain check D7 stands on. So
    # the package that carries both goes on the system path — the hypervisor
    # does not, because nobody types that one.
    environment.systemPackages = [ ms.package ];

    # What starts at boot. On an appliance the renderer starts the units it
    # was told to (`systemctl start` per MEISTER_ROLE); here the roles are
    # known at build time, so the units say so themselves — and a host that
    # is a cloud has no stopped agent unit to explain.
    systemd.services = lib.mkMerge (map
      (role:
        lib.mkIf (builtins.elem role ms.unitsFor) {
          ${if role == "agent" then "meister-agent" else "meister-${role}-controller"}
            .wantedBy = [ "multi-user.target" ];
        })
      [ "cloud" "cluster" "agent" ]);

    # --- nix, because deploying is copying a closure in ---------------------
    nix.enable = true;
    nix.settings = {
      # A build that reaches the network or the host's own /etc is a build
      # whose result is not the function of its inputs it claims to be.
      sandbox = true;

      # The line the whole transport stands on (M0 probe S12). Never
      # `--no-check-sigs`, and never the legacy `ssh://` store: both take an
      # unsigned closure, which is the guarantee this option exists for.
      require-sigs = true;

      trusted-users = [ "root" ];
      allowed-users = [ "root" ];

      inherit (cfg) substituters;
      trusted-public-keys = cfg.trustedPublicKeys;

      # `nix copy` and `nix path-info --json` are both nix-command, on the
      # operator AND on the target — without this the target answers
      # "experimental Nix feature 'nix-command' is disabled", which is an
      # hour nobody gets back (M0 probe S12).
      experimental-features = [ "nix-command" ];
    };

    # Never automatically, and that is the point: the generation this host
    # would roll back to is a generation somebody has to be able to roll back
    # TO. `meisterstack.managed.keepGenerations` is the number, and
    # `meister-activate gc` is what will act on it.
    nix.gc.automatic = false;

    # The way in for the operator. mkDefault throughout: a host with its own
    # sshd configuration keeps it, and this is the minimum that makes
    # `nix copy --to ssh-ng://` and the activation helper reachable at all.
    services.openssh.enable = lib.mkDefault true;
    services.openssh.settings.PermitRootLogin = lib.mkDefault "prohibit-password";

    # Where the helper keeps what it must not lose across a reboot: the
    # transaction record of an activation that has not been confirmed yet,
    # and the lock that says who is deploying. 0700 root, because a
    # transaction record is what decides whether a machine rolls back.
    systemd.tmpfiles.rules = [
      "d /var/lib/meisterstack 0755 root root -"
      "d ${ms.pki.dir} 0755 root root -"
      "d ${deployDir} 0700 root root -"
      "d ${deployDir}/txn 0700 root root -"
      "d ${deployDir}/lock 0700 root root -"
    ];
  };
}

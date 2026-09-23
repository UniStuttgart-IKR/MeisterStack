# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# What MeisterStack IS on a machine: the units, their config files, their
# users and their state directories — and nothing about the machine itself.
#
# This module is the one a foreign host imports. It is therefore the module
# that must not decide anything host-global: no `system.stateVersion`, no
# firewall, no DHCP, no resolvconf, no bootloader, no `fileSystems."/"`, no
# `nix.enable`, no console. Somebody else's NixOS host has answers to all of
# those already, and a module that overrides them is a module nobody can
# import twice. `checks.services-are-pure` in flake.nix holds this file to it
# by evaluating a minimal host with and without these modules and comparing
# exactly those attributes.
#
# What DOES decide host-global things is the profile beside this file:
#
#   nix/managed.nix    a host `meister-deploy` deploys to: nix stays on, the
#                      config files are complete at build time, and there is
#                      no renderer at boot.
#
# There was a second one until M5B — `nix/appliance.nix`, the image the
# twelve OpenNebula VMs of the lab boot, with a renderer that wrote the
# config files AT BOOT out of a context (`nix/context.nix`,
# `nix/provider-opennebula.nix`). It went to `~/git/meisterstack-lab/
# legacy/nix/`, which is where the fleet that boots it lives. Comments in
# these modules that name those three files mean the copies there.
#
# The gate every service hangs on is `meisterstack.unitsFor`, which is
# `meisterstack.roles` for everybody except the appliance: that image ships
# every unit and lets the context decide at boot which of them starts, so it
# sets the list to all three and the role list keeps meaning "what this
# machine is".
{ lib, pkgs, config, ... }:
let
  cfg = config.meisterstack;
in
{
  imports = [
    ./roles.nix
    ./etcd.nix
    ./controllers.nix
    ./agent.nix
    # --- lane 4B: the fabric tools of a host with an RDMA card ---
    ./rdma.nix
    # --- end lane 4B ---
    ./addons.nix
    ./data.nix
    ./observability.nix
  ];

  options.meisterstack = {
    unitsFor = lib.mkOption {
      type = lib.types.listOf (lib.types.enum [ "cloud" "cluster" "agent" ]);
      default = lib.filter (r: r != "addons") cfg.roles;
      internal = true;
      description = ''
        Which of the three boot-time roles this machine carries UNITS for.
        Defaults to `meisterstack.roles`, and the appliance profile widens it
        to all three because its image is role-agnostic: every unit ships and
        the context decides at boot which of them starts.

        `addons` is not in this list. That role is build time by construction
        (nix/addons.nix says why: one name is the issuer, the origin, every
        redirect url and the name in the certificate at once), so it hangs on
        `meisterstack.roles` and on nothing else.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.meisterstack or (throw (
        "meisterstack.package has no default here: this nixpkgs has no `meisterstack` "
        + "attribute, so the overlay that declares it is not in it. Add "
        + "`nixpkgs.overlays = [ meisterstack.overlays.default ];` (lib.mkFleet does "
        + "that for you), or set meisterstack.package to your own build."));
      defaultText = lib.literalExpression "pkgs.meisterstack";
      description = ''
        The package the units of this stack take their binaries from.

        Read only where `meisterstack.binDir` is derived from it — which is
        what nix/managed.nix does. A host that is not managed by this flake
        may get its binaries pushed into /opt/meisterstack/bin instead, and
        then this option is never forced. That is also why the default may
        be a package that the operator's nixpkgs does not have: a foreign
        host importing `nixosModules.default` without the overlay is a
        perfectly good host, as long as it says where its binaries are.
      '';
    };

    runtime = lib.mkOption {
      type = lib.types.package;
      internal = true;
      default =
        if builtins.elem "agent" cfg.unitsFor
        then
          pkgs.symlinkJoin
            {
              name = "meisterstack-runtime-${cfg.package.version or "0"}";
              paths = [ cfg.package cfg.agent.vmm.package ];
            }
        else cfg.package;
      defaultText = lib.literalExpression "pkgs.meisterstack-runtime";
      description = ''
        The ONE directory `meisterstack.binDir` can point at, built out of
        the packages this host needs.

        `binDir` is a directory and not a list of binaries, and the agent's
        unit names two programs in it — `meister-agent` and
        `cloud-hypervisor` — so on a host with the agent role the two
        packages have to be joined into one path. A host without that role
        gets the workspace package alone rather than a hypervisor it never
        starts.
      '';
    };

    binariesInStore = lib.mkOption {
      type = lib.types.bool;
      internal = true;
      readOnly = true;
      default = lib.hasPrefix "${builtins.storeDir}/" cfg.binDir;
      description = ''
        Whether `binDir` is a store path, and therefore whether the
        `ConditionPathExists` lines on BINARIES mean anything.

        On an appliance they mean a great deal: /opt/meisterstack/bin is
        filled by a push, and a unit that waits visibly is better than one
        that restarts every two seconds. A store path is part of the system
        that names it — it is there or the system does not exist — so the
        same condition would only be a line that can never fail. The
        conditions on KEY material stay either way: keys are pushed on both
        roads.
      '';
    };

    binDir = lib.mkOption {
      type = lib.types.str;
      default = "/opt/meisterstack/bin";
      example = "/run/current-system/sw/bin";
      description = ''
        The directory every unit of this stack takes its binaries from:
        `ExecStart`, the `ConditionPathExists` that keeps a unit visibly
        skipped until they are there, and the hypervisor path in the agent's
        config all read this one option.

        The default is where a push has always put them — outside the nix
        store, so that an image swap does not touch them. A host whose
        binaries come from a package points
        this at that package's `bin` instead; the condition is then satisfied
        by construction, which is the honest reading of "the binary is part
        of this system".
      '';
    };

    pki.dir = lib.mkOption {
      type = lib.types.str;
      default = "/opt/meisterstack/pki";
      example = "/var/lib/meisterstack/pki";
      description = ''
        Where this machine's certificates and private keys live. The names in
        it are FIXED — `ca.crt`, `serving.crt`, `serving.key`, `identity.crt`,
        `identity.key` — because a serving certificate and an identity differ
        per host while one config template serves them all.

        Outside the nix store on purpose, in both profiles: a private key must
        never travel in an image, and the store is world-readable.

        The private keys belong to the user that reads them (`meister`, mode
        0600). systemd credentials are NOT an option here: `LoadCredential`
        hands the unit a `root:root 0440` file with an ACL, and all three of
        this project's key loaders refuse a mode with group bits in it
        (`shared/pki/src/pem.rs`, `shared/proto/src/lib.rs`,
        `components/cli/src/config.rs`). Measured in a VM, M0 probe S11.
      '';
    };

    configDir = lib.mkOption {
      type = lib.types.str;
      default = "/run/meisterstack";
      example = "/etc/meisterstack";
      description = ''
        The directory the units read their `--config` from.

        The default is where a boot-time renderer writes the completed
        files: such an image bakes a TEMPLATE under /etc/meisterstack, and
        the per-machine values — node id, controller addresses, the cloud's
        whole [auth] table — are only known once the machine has booted
        somewhere. This flake has no such renderer any more (M5B); the one
        the lab's twelve context VMs boot is in
        `~/git/meisterstack-lab/legacy/nix/context.nix`.

        A managed host has no renderer and no context: Nix knows every one of
        those values at build time, writes the complete file into /etc and
        points this option at it. Then the config a unit reads is part of the
        system generation, which is what makes a rollback a rollback.
      '';
    };

    ports = lib.mkOption {
      type = lib.types.attrsOf (lib.types.attrsOf (lib.types.either lib.types.int lib.types.str));
      readOnly = true;
      default = {
        cloud = { api = 3000; grpc = 50050; metrics = 9100; };
        cluster = { api = 3001; grpc = 50051; metrics = 9101; };
        agent = { metrics = 9102; migration = "49000-49099"; };
        etcd = { client = 2379; peer = 2380; };
      };
      description = ''
        The ports this stack listens on, per role — to be READ, not set.

        No firewall rule is written by these modules, and that is the point:
        a host's firewall belongs to the host, and a service module that
        opens a port decides something host-global behind its owner's back.
        So the numbers are published here instead, and an operator's own
        `networking.firewall` can name them:

          networking.firewall.allowedTCPPorts = with config.meisterstack.ports;
            [ cloud.api cloud.grpc etcd.peer ];

        Which of them this module actually sets: the three `metrics`
        listeners (controllers.nix, agent.nix), the agent's `migration`
        RANGE, and etcd's two (nix/etcd.nix — `client` is bound to loopback
        and is here for completeness, `peer` is the one that crosses the
        network). `api` and `grpc` are the binaries' own defaults, written
        down because a plan derives addresses from them
        (`MEISTER_CLOUD_ADDRS`, `MEISTER_CONTROLLER_ADDRS`) and an operator
        opening a hole needs the number in one place.

        The addons role is not in this list: its six services bring their own
        nixpkgs modules and their own listeners, and `meisterstack.addons` is
        where they are configured.
      '';
    };
  };

  config = {
    # The service account both controllers run as, and the group that reaches
    # the agent's socket. Stage 1 of privilege separation, and only that: no
    # shell, no home, no login — an identity to drop to and a group to put an
    # operator into, nothing else.
    #
    # The AGENT stays root by default, deliberately: it programs nftables,
    # makes taps and bridges, opens /dev/kvm and hands VFIO devices to guests.
    # What it gives away instead is its socket — `[paths] socket_group =
    # "meister"` in agent.nix — so that `meister agent vm ls` on a node needs
    # a group membership rather than sudo.
    #
    # Unconditional, and not behind a role: `socket_group` names this group in
    # every rendered config, the key files under `pki.dir` are owned by this
    # user on every host of this stack, and a `z` line in tmpfiles that names
    # a user who does not exist is a boot-time error rather than a no-op. It
    # is a system user with no shell; it decides nothing about the machine.
    users.groups.meister = { };
    users.users.meister = {
      isSystemUser = true;
      group = "meister";
      description = "MeisterStack control plane";
      shell = "${pkgs.shadow}/bin/nologin";
    };

    # --- lane 5C: the provider, on a host that has no renderer -------------
    #
    # A managed NixOS host on somebody's hypervisor: its config files are a
    # system generation (nix/managed.nix), so it must NOT have the boot
    # renderer — that module asserts against exactly this combination. But
    # there is still one thing only the provider knows, and it is the thing
    # the machine cannot be reached without: where it was booted. Address,
    # route, resolver, hostname, the operator's key.
    #
    # Until this unit existed, `meisterstack.context.providerScript` was
    # declared by the renderer, so `nixosModules.provider-opennebula` could
    # only be imported together with it — and the lab paid for that with
    # thirty hand-written lines of unit in the operator's own repository
    # (L2 finding N5, 2026-09-23).
    #
    # It does ONLY the provider's part. No template is copied, no config
    # file is rendered, no unit is started by role: on this road all of
    # that is Nix's, at build time. `mkIf` on the script being non-empty AND
    # on there being no renderer, so a host with neither has no unit at all
    # and an appliance keeps exactly the one it had — two authors for one
    # medium is the mistake this whole split exists to avoid.
    #
    # `checks.services-are-pure` is unaffected: it compares what this module
    # decides about the MACHINE (dhcp, firewall, resolvconf, bootloader,
    # stateVersion), and a unit that only exists when somebody sets an
    # option is not one of those.
    systemd.services.meister-provider-context =
      lib.mkIf (cfg.context.providerScript != "" && !cfg.context.enable) {
        description = "Read this machine's context from its provider";
        wantedBy = [ "multi-user.target" ];
        # Before anything that needs an address or a name: the whole point
        # of this unit is that the machine can be reached at all.
        before = [ "network-online.target" "sshd.service" ];
        after = [ "local-fs.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          # A context that goes wrong has to be readable from a serial
          # console, because a machine whose address is wrong is a machine
          # nothing else reaches.
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        path = with pkgs; [ iproute2 util-linux coreutils gnugrep gawk systemd ];
        script = cfg.context.providerScript;
      };
    # --- end lane 5C -------------------------------------------------------
  };
}

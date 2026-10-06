# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Public runtime module: role services, accounts, helpers, and optional storage.
# Host profiles retain control of boot, firewall, DHCP, resolver, and stateVersion.
# nix/store-host.nix adds immutable package and configuration paths separately.
{ lib, pkgs, config, ... }:
let
  cfg = config.meisterstack;
  inherit (import ./lib/net.nix { inherit lib; }) hostPort wildcard;

  metricsAddress = cfg.metrics.listenAddress;
  bindsOneAddress = !(builtins.elem metricsAddress [ "127.0.0.1" "::1" "0.0.0.0" "::" ]);
in
{
  imports = [
    ./roles.nix
    ./etcd.nix
    ./controllers.nix
    ./agent.nix
    ./guest-guard.nix
    ./single-node.nix
    # Import optional RDMA tools.
    ./rdma.nix

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
        + "`nixpkgs.overlays = [ meisterstack.overlays.default ];` (a meister-deploy fleet "
        + "does that for you), or set meisterstack.package to your own build."));
      defaultText = lib.literalExpression "pkgs.meisterstack";
      description = ''
        The package the units of this stack take their binaries from.

        Read only where `meisterstack.binDir` is derived from it — which is
        what nix/store-host.nix does. A host whose binaries do not come from
        the store may get them pushed into /opt/meisterstack/bin instead, and
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

    autostart = lib.mkOption {
      type = lib.types.bool;
      default = false;
      example = lib.literalExpression "config.my.host.holdsItsCertificates";
      description = ''
        Whether the role units of this host (`meister-agent`,
        `meister-cloud-controller`, `meister-cluster-controller`) start at
        boot, i.e. are wanted by `multi-user.target`.

        Off by default: importing `nixosModules.services` into an existing
        configuration defines the units and starts none of them, so a host
        decides when it is ready — typically once its certificates are in
        place. `nix/store-host.nix` turns it on, because there the system
        generation is the decision. Either way a unit still waits for its key
        material (`ConditionPathExists`), and the agent for its guest guard.
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

        A store-built host has no renderer and no context: Nix knows every one of
        those values at build time, writes the complete file into /etc and
        points this option at it. Then the config a unit reads is part of the
        system generation, which is what makes a rollback a rollback.
      '';
    };

    metrics.listenAddress = lib.mkOption {
      type = lib.types.str;
      # A boot-rendered image is generic and learns its address, and its
      # family, only at boot, but the fleet's Prometheus scrapes it there.
      default = if cfg.context.enable then wildcard config else "127.0.0.1";
      defaultText = lib.literalExpression
        ''if config.meisterstack.context.enable then "::" else "127.0.0.1"'';
      example = "10.0.0.10";
      description = ''
        The address the three metrics listeners (`metrics_listen` of the
        cloud, the cluster and the agent, ports in `meisterstack.ports`)
        bind. They are unauthenticated, and their series name objects across
        every tenant.

        Loopback by default, so a host that does not say otherwise exposes
        them to nobody. A fleet built with meister-deploy binds the host's
        management address, which is what its Prometheus scrapes, and refuses
        a host that binds neither that address nor a wildcard covering it; a unit that
        binds one address waits for `network-online.target`. A host that
        renders its config at boot (`meisterstack.context.enable`) binds every
        address of either family (`::`), because its image does not know the
        address it is scraped at; where the kernel keeps IPv6 sockets to IPv6
        (`net.ipv6.bindv6only = 1`) or has no IPv6, that is `0.0.0.0`. A
        wildcard binds every address, and then only the host's firewall
        decides who reads them; `0.0.0.0` takes IPv4 only. A role's
        `settings.metrics_listen` still wins over this.
      '';
    };

    metrics.listen = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      internal = true;
      readOnly = true;
      default = lib.mapAttrs (_: role: hostPort metricsAddress role.metrics)
        { inherit (cfg.ports) cloud cluster agent; };
      description = "The `metrics_listen` value of each role, from `metrics.listenAddress`.";
    };

    metrics.waitsForNetwork = lib.mkOption {
      type = lib.types.bool;
      internal = true;
      readOnly = true;
      default = bindsOneAddress;
      description = ''
        Whether the role units order after `network-online.target`: a
        listener bound to one address cannot bind before the address exists.
      '';
    };

    ports = lib.mkOption {
      type = lib.types.attrsOf (lib.types.attrsOf (lib.types.either lib.types.int lib.types.str));
      readOnly = true;
      default = (import ./lib/ports.nix).roles;
      description = ''
        The ports this stack listens on, per role — to be READ, not set.

        These modules open no port, and that is the point: a host's firewall
        belongs to the host, and a service module that opens a port decides
        something host-global behind its owner's back. The only rule they
        write is the guest guard's drop table on an agent host
        (nix/guest-guard.nix, `meisterstack.agent.guestGuard`), and it opens
        nothing. So the numbers are published here instead, and an operator's own
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
    # Controllers share the meister service account. The meister group also grants
    # access to the agent socket; membership permits local VM administration.
    # Keep supplementary device groups on the agent unit, not the shared account.
    # A host without a role gets neither, so importing the module changes nothing.
    users.groups.meister = lib.mkIf (cfg.unitsFor != [ ]) { };
    users.users.meister = lib.mkIf (cfg.unitsFor != [ ]) {
      isSystemUser = true;
      group = "meister";
      description = "MeisterStack control plane";
      shell = "${pkgs.shadow}/bin/nologin";
    };

    # Run base-image conversion in a transient systemd unit as meister-convert.
    # This account has no device groups, protecting host devices and VM state from
    # untrusted image parsers. Its transient unit receives only the required paths.
    users.groups.meister-convert =
      lib.mkIf (builtins.elem "agent" cfg.unitsFor) { };
    users.users.meister-convert =
      lib.mkIf (builtins.elem "agent" cfg.unitsFor) {
        isSystemUser = true;
        group = "meister-convert";
        description = "MeisterStack base image converter";
        shell = "${pkgs.shadow}/bin/nologin";
      };

    # Run provider initialization independently of the configuration renderer.
    # Store-built hosts can obtain network and hostname information from a provider
    # while their role configurations remain part of the system generation.
    systemd.services.meister-provider-context =
      lib.mkIf (cfg.context.providerScript != "" && !cfg.context.enable) {
        description = "Read this machine's context from its provider";
        wantedBy = [ "multi-user.target" ];
        # Run provider initialization before services that need network configuration.
        before = [ "network-online.target" "sshd.service" ];
        after = [ "local-fs.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          # Send provider diagnostics to both the journal and serial console.
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        path = with pkgs; [ iproute2 util-linux coreutils gnugrep gawk systemd ];
        script = cfg.context.providerScript;
      };

  };
}

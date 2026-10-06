# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Configure cloud and cluster services, TLS paths, generated authentication,
# and process sandboxes. Explicit role settings override generated defaults.
{ lib, pkgs, config, ... }:
let
  toml = pkgs.formats.toml { };
  cfg = config.meisterstack;

  # Shared controller defaults cover store, listening addresses, telemetry,
  # and credential paths. The binary validates the resulting configuration.
  pki = cfg.pki.dir;

  # Configure both controller listeners with a serving certificate and client CA.
  serving = {
    tls_cert = "${pki}/serving.crt";
    tls_key = "${pki}/serving.key";
    client_ca = "${pki}/ca.crt";
  };

  # The cluster authenticates machines and break-glass operators with certificates.
  # Ordinary users and OIDC authorization belong to the cloud directory.
  clusterAuth.auth.chain = [ "mtls" ];

  # Select cloud authentication from the generated issuer: mTLS alone, or mTLS
  # and OIDC. Ordinary user authorization is resolved through cloud User objects.
  cloudAuthMtls.auth.chain = [ "mtls" ];
  cloudAuthOidc.auth = {
    chain = [ "mtls" "oidc" ];
    oidc = {
      client_id = "meister-cli";
      # Derive the audience from the configured identity provider instead of fixing
      # one audience for every deployment.
      username_claim = "preferred_username";
    };
  };

  cloudDefaults = serving // {
    metrics_listen = cfg.metrics.listen.cloud;
    # Cloud replicas need a client identity to forward requests to the replica
    # holding a cluster session. This identity is distinct from the serving certificate.
    identity_cert = "${pki}/identity.crt";
    identity_key = "${pki}/identity.key";
  };

  clusterDefaults = serving // clusterAuth // {
    metrics_listen = cfg.metrics.listen.cluster;
    # Use a separate client credential for the cluster-to-cloud session.
    cloud_ca = "${pki}/ca.crt";
    cloud_cert = "${pki}/identity.crt";
    cloud_key = "${pki}/identity.key";
  };

  # A controller's file has to name its authenticators: the binary refuses
  # an empty chain, and an evaluation that knew it would be empty says so first.
  namesAuthChain = effective: (effective.auth.chain or [ ]) != [ ];

  networkOnline = lib.optional cfg.metrics.waitsForNetwork "network-online.target";

  controller = name: {
    description = "MeisterStack ${name}-controller";
    wantedBy = lib.mkIf cfg.autostart [ "multi-user.target" ];
    # Order after the context renderer only when that renderer is enabled.
    after = [ "etcd.service" "meister-context.service" ] ++ networkOnline;
    wants = [ "etcd.service" ] ++ networkOnline;
    # Gate startup on the configuration and credential files the service needs.
    unitConfig.ConditionPathExists =
      lib.optional (!cfg.binariesInStore) "${cfg.binDir}/meister-${name}-controller"
      ++ [ "${pki}/ca.crt" ];
    serviceConfig = {
      # Resolve configuration files beneath the selected configDir.
      ExecStart = "${cfg.binDir}/meister-${name}-controller --config ${cfg.configDir}/${name}.toml";
      Restart = "always";
      RestartSec = 2;
      Environment = "RUST_LOG=info";

      # Run controllers with restricted host access; persistent state lives in etcd.
      User = "meister";
      Group = "meister";
      NoNewPrivileges = true;

      # Controllers need no writable host state directories.
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      PrivateDevices = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      CapabilityBoundingSet = "";
      SystemCallFilter = "@system-service";

      # Allow TCP and Unix sockets; controllers do not program host networking.
      RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";
    };
  };
in
{
  options.meisterstack = {
    cluster.settings = lib.mkOption {
      type = toml.type;
      default = { };
      description = ''
        cluster-controller config, merged OVER the role defaults above (so a
        deployment that sets one key keeps the rest). Free-form TOML: nothing
        here validates a key, the binary does that at start-up with
        deny_unknown_fields. config/examples/cluster.toml is the reference for
        every key it takes, and config/examples/hardened/cluster.toml for a
        control plane that is not on a lab switch.

        Empty (the default) = the role defaults above and, for everything they
        do not name, the binary's own — which are the lab topology.
        cluster_name, cloud_addr and cloud_addrs are normally left out here and
        written by the context renderer from the context instead — a key in
        both places would be a duplicate TOML key.
      '';
    };

    cluster.generated = lib.mkOption {
      type = toml.type;
      default = { };
      internal = true;
      description = ''
        The per-machine keys of the cluster-controller config, merged BETWEEN
        the role defaults and the operator's `settings` — so a deployment can
        still override one of them, and the defaults still lose to both.

        Empty on an appliance: there the same keys are written at boot by the
        context renderer, which is the only thing that knows where this image
        was started. `nix/store-host.nix` fills it from
        `meisterstack.context.defaults` through `nix/lib/render.nix`, so that
        both roads render the same file out of the same input.
      '';
    };
    cloud.settings = lib.mkOption {
      type = toml.type;
      default = { };
      description = ''
        cloud-controller config, same shape and same rules; see
        config/examples/cloud.toml. This is the one tier with a public port,
        so config/examples/hardened/cloud.toml is worth reading before any
        deployment that is reachable from outside the lab.

        `auth` depends on who writes this file. A boot renderer appends the
        whole [auth] table at boot, so a key here would be a duplicate table
        and a parse error on the VM; a store-built host bakes it through
        `meisterstack.cloud.generated`. A host with neither has to name its
        chain here, e.g. `auth.chain = [ "mtls" ];` — the evaluation refuses a
        cloud without one rather than leave the choice to the binary.
      '';
    };

    cloud.authFragments = lib.mkOption {
      type = lib.types.attrsOf toml.type;
      internal = true;
      readOnly = true;
      default = { mtls = cloudAuthMtls; oidc = cloudAuthOidc; };
      description = ''
        The two halves of the cloud's [auth] table, for whoever has to finish
        it: the boot renderer reads them as files under /etc, and
        nix/lib/render.nix reads them as values. `client_id` and
        `username_claim` are decisions about this stack rather than about a
        deployment, so they have exactly one owner — this file — and both
        roads take them from here instead of typing them again.
      '';
    };

    cluster.effective = lib.mkOption {
      type = toml.type;
      internal = true;
      default = { };
      description = ''
        The file, as a VALUE: role defaults, then `generated`, then
        `settings`, which is the order the renderer has. `environment.etc`
        turns it into TOML, and a deployment tool that describes the host
        (meister-deploy's manifest) reads the same attrset — one merge with
        two readers, rather than a second one in the manifest that could
        drift from the file the unit actually reads.
      '';
    };

    cloud.effective = lib.mkOption {
      type = toml.type;
      internal = true;
      default = { };
      description = ''
        The cloud's config file as a value; see
        `meisterstack.cluster.effective`.
      '';
    };

    cloud.generated = lib.mkOption {
      type = toml.type;
      default = { };
      internal = true;
      description = ''
        The cloud-controller's per-machine keys, the counterpart of
        `meisterstack.cluster.generated` — including the whole [auth] table on
        a store-built host, where nothing appends it at boot.
      '';
    };
  };

  # Enable only the role selected for this host.
  config = lib.mkMerge [
    (lib.mkIf (builtins.elem "cluster" cfg.unitsFor) {
      assertions = [{
        assertion = namesAuthChain cfg.cluster.effective;
        message =
          "meisterstack.cluster.settings.auth.chain is empty, so the cluster-controller "
          + "would have no authenticator and would refuse to start. Machines and "
          + "break-glass operators authenticate here with certificates: [ \"mtls\" ].";
      }];
      meisterstack.cluster.effective = lib.recursiveUpdate
        (lib.recursiveUpdate clusterDefaults cfg.cluster.generated)
        cfg.cluster.settings;
      environment.etc."meisterstack/cluster.toml".source =
        toml.generate "cluster.toml" cfg.cluster.effective;
      systemd.services.meister-cluster-controller = controller "cluster";
    })

    # Set ownership and modes on delivered PEM files so the unprivileged
    # controller can read them and the shared key loader accepts private keys.
    (lib.mkIf
      (builtins.elem "cluster" cfg.unitsFor || builtins.elem "cloud" cfg.unitsFor)
      {
        systemd.tmpfiles.rules =
          lib.optional (!(builtins.elem "agent" cfg.unitsFor && cfg.agent.unprivileged))
            "z ${pki}/identity.key 0600 meister meister -"
          ++ [ "z ${pki}/serving.key 0600 meister meister -" ];
      })


    (lib.mkIf (builtins.elem "cloud" cfg.unitsFor) {
      assertions = [{
        # A boot renderer appends the [auth] table after evaluation.
        assertion = cfg.context.enable || namesAuthChain cfg.cloud.effective;
        message =
          "the cloud-controller on this host names no authenticator: no [auth] chain in "
          + "meisterstack.cloud.settings, none baked by nix/store-host.nix and no boot renderer "
          + "to append one. Name it, e.g. meisterstack.cloud.settings.auth.chain = [ \"mtls\" ] "
          + "(certificates only), or import nixosModules.store-host.";
      }];
      meisterstack.cloud.effective = lib.recursiveUpdate
        (lib.recursiveUpdate cloudDefaults cfg.cloud.generated)
        cfg.cloud.settings;
      environment.etc."meisterstack/cloud.toml".source =
        toml.generate "cloud.toml" cfg.cloud.effective;
      systemd.services.meister-cloud-controller = controller "cloud";
    })

    # Keep mTLS-only and OIDC cloud authentication fragments available to rendering.
    (lib.mkIf (builtins.elem "cloud" cfg.unitsFor && cfg.context.enable) {
      environment.etc."meisterstack/cloud-auth-mtls.toml".source =
        toml.generate "cloud-auth-mtls.toml" cloudAuthMtls;
      environment.etc."meisterstack/cloud-auth-oidc.toml".source =
        toml.generate "cloud-auth-oidc.toml" cloudAuthOidc;
    })
  ];
}

# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Both controller units ship in the one image; the OpenNebula context
# (MEISTER_ROLE) starts the right one. ConditionPathExists keeps a unit
# quietly skipped until push.sh delivered its binary.
#
# Central cluster setup: everything configurable lives in
# meisterstack.<role>.settings (free-form TOML), merged over the role
# defaults below, rendered to /etc/meisterstack/<role>.toml and consumed by
# the binaries via --config. Empty settings = the defaults below and, for
# every key they do not name, the binaries' own (the lab topology).
{ lib, pkgs, config, ... }:
let
  toml = pkgs.formats.toml { };
  cfg = config.meisterstack;

  # What both controller roles get. The rule this list follows is agent.nix's:
  # bake a key only if the BINARY requires it, or if this image must deviate
  # from the binary's default — and say why. Everything else is left to the
  # binary.
  #
  #   metrics_listen  The binary defaults to "nothing listens", deliberately:
  #                   the endpoint is unauthenticated and its series name
  #                   objects across every tenant, so a controller that does
  #                   not know where it runs must not open it. This image DOES
  #                   know where it runs — a lab-internal control-plane VM —
  #                   and there the scrape target is the point. Its own port
  #                   and never the API router (that one is authenticated and
  #                   tenant-scoped, this one is neither): 9100 cloud, 9101
  #                   cluster, 9102 agent, so that a box running two roles
  #                   never has two listeners fighting over one port.
  #
  # And the PKI. Private keys must never travel in a qcow2 — an image gets
  # copied, shared and stored in a datastore — so they live beside the
  # binaries in /opt/meisterstack, which survives an image swap the same way,
  # and deploy/push.sh puts them there.
  #
  # The names are FIXED and the same on every host, which is the whole trick:
  # a serving certificate and an identity differ per VM, and one template
  # serves them all. Either the template names per-host paths and one-context
  # renders them, or the push decides which file gets the fixed name. The
  # second: it keeps the template dumb and the decision where the operator is
  # already thinking per host — and a certificate that landed on the wrong
  # host then fails at the handshake, with a name in the message, instead of
  # at rendering time with nothing to look at.
  pki = "/opt/meisterstack/pki";

  # Both controller roles serve TLS and demand a client certificate for it.
  # A chain that names a link it cannot build is a start-up error by design
  # (rest.rs::build_chain), so this list and the keys above travel together.
  serving = {
    tls_cert = "${pki}/serving.crt";
    tls_key = "${pki}/serving.key";
    client_ca = "${pki}/ca.crt";
  };

  # The cluster tier stays on certificates, and that is a design decision of
  # this stack rather than a gap: it keeps no user directory, so it could
  # authenticate a token's name and then permit it nothing. build_chain
  # refuses `[auth.oidc]` here outright. Machines authenticate with
  # certificates; people reach the cluster with break-glass or not at all.
  clusterAuth.auth.chain = [ "mtls" ];

  # --- the cloud's [auth] table -------------------------------------------
  #
  # NOT baked into cloud.toml, and that is forced rather than chosen. Three
  # facts collide:
  #
  #   1. `auth.chain` naming "oidc" without an `[auth.oidc]` table is a
  #      start-up error (rest.rs::build_chain), so the two have to appear and
  #      disappear together.
  #   2. `OidcConfig.issuer` is a required String. A baked `[auth.oidc]`
  #      waiting for an issuer is not a quiet no-op, it is a PARSE error on
  #      every VM that never gets one.
  #   3. one-context APPENDS section overrides, and TOML has no way to
  #      redefine a `[table]` an append arrives after.
  #
  # So the whole table has one owner, and the only owner that knows whether
  # this deployment has an identity provider is one-context, at boot, holding
  # MEISTER_OIDC_ISSUER. What it gets from here is the rest: two ready-made
  # fragments, one of which it concatenates onto the rendered cloud.toml. The
  # values stay in this file, where the rest of the cloud's auth lives, and
  # TOML quoting stays Nix's problem rather than a shell's.
  #
  # `[auth.oidc]` is LAST in the oidc fragment (toml.generate orders it so,
  # and the check-context render test holds it there), which is what lets
  # one-context append the single `issuer` line into it.
  #
  # No ca_cert for the provider: the lab's Keycloak is plain http. That is
  # THE deviation from the hardened profile in this whole file, and it is
  # what makes that instance a test instance — a token's signature is checked
  # against keys fetched over a channel nobody authenticated. A real
  # deployment sets `auth.oidc.ca_cert` (or has a provider with a public
  # root) and does not run this comment's setup.
  cloudAuthMtls.auth.chain = [ "mtls" ];
  cloudAuthOidc.auth = {
    chain = [ "mtls" "oidc" ];
    oidc = {
      client_id = "meister-cli";
      # `audience` is NOT here, and it used to be. It is a property of the
      # PROVIDER and not of this stack: Keycloak writes only "account" into
      # `aud` unless an audience mapper says otherwise (the lab's mapper says
      # "meister"), and Kanidm writes the name of the oauth2 client itself and
      # has no mapper to say anything else with. So it travels with the issuer
      # — one-context renders it from MEISTER_OIDC_AUDIENCE — and defaults to
      # the "meister" this file used to bake, so that an image swap under the
      # lab's existing context changes nothing.
      #
      # Kanidm's `sub` is a uuid, and a uuid is not a name a directory
      # entry can be found under. `email` would be the other tempting answer
      # and is a trap — see OidcConfig::username_claim.
      username_claim = "preferred_username";
    };
  };

  cloudDefaults = serving // {
    metrics_listen = "0.0.0.0:9100";
    # The cloud's own client identity — `CN=system:cloud:<cloud_name>`, the
    # file push.sh gives the fixed name `identity` to. The cluster tier below
    # has had it since it learned to dial the cloud; this tier needed it the
    # day it grew SIBLINGS, and did not get it.
    #
    # What it costs when it is missing is not a warning. Image 58 turned
    # `tls_cert` on, so `serves_tls` is true and `Sibling.tls` is None: every
    # forward between cloud replicas fails with "the replica at ... is https
    # and this one has no client certificate". Measured in the mini-chaos run
    # — `vm logs` answered on one of three replicas, the WebSocket console on
    # the same one, and the uncordon after the run only went through
    # cloud-b — while the discovery document went on offering
    # `console.websocket` on all three. The comment in main.rs said "absent =
    # plain http, which is what a lab runs", and Image 58 is what made that
    # assumption false.
    #
    # Same CA as `client_ca`: one CA signs every tier in this stack, and a
    # replica asking its sibling is the cloud asking itself.
    identity_cert = "${pki}/identity.crt";
    identity_key = "${pki}/identity.key";
  };

  clusterDefaults = serving // clusterAuth // {
    metrics_listen = "0.0.0.0:9101";
    # The other direction, and separate from `serving` because the two
    # directions are: this is how a cluster DIALS the cloud, and the identity
    # it presents there is `CN=system:cluster:<name>` — the file push.sh gives
    # the fixed name `identity` to.
    cloud_ca = "${pki}/ca.crt";
    cloud_cert = "${pki}/identity.crt";
    cloud_key = "${pki}/identity.key";
  };

  controller = name: {
    description = "MeisterStack ${name}-controller";
    after = [ "etcd.service" "one-context.service" ];
    wants = [ "etcd.service" ];
    # The binary, and now also the CA. `client_ca` without `tls_cert`/`tls_key`
    # is a hard start-up error (rest.rs::server_tls, grpc.rs::server_tls, and
    # the test `half_a_tls_config_is_refused_rather_than_downgraded`), and a
    # freshly re-instantiated VM has none of the three until push.sh ran. Not
    # starting is the honest state: `systemctl status` then says
    # ConditionPathExists=/opt/meisterstack/pki/ca.crt was not met, which is a
    # sentence an operator can act on — a restart loop is not.
    unitConfig.ConditionPathExists = [
      "/opt/meisterstack/bin/meister-${name}-controller"
      "${pki}/ca.crt"
    ];
    serviceConfig = {
      # one-context renders /etc templates to /run and appends per-VM values
      # (e.g. cluster_name) from the context — units consume the /run copy.
      ExecStart = "/opt/meisterstack/bin/meister-${name}-controller --config /run/meisterstack/${name}.toml";
      Restart = "always";
      RestartSec = 2;
      Environment = "RUST_LOG=info";

      # A controller is a network daemon that reads two files and talks to
      # etcd on loopback. It needs none of the rest of a machine, so it gets
      # none of it. What it reads it reads as `meister`: the rendered config
      # (root:meister 0640, one-context.nix) and its own key (meister 0600,
      # deploy/push.sh pki).
      User = "meister";
      Group = "meister";
      NoNewPrivileges = true;

      # Nothing on disk is written by these two — the state is in etcd, and
      # etcd is its own unit running as its own user. ReadWritePaths stays
      # empty on purpose: should a controller ever want to write (an OTLP
      # spool, a cache), it fails with EROFS, and that is a design question
      # to answer rather than a line to add here.
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

      # TCP, and unix sockets for the journal. NOT AF_NETLINK: the binaries
      # push.sh ships are musl-static, and musl's resolver does not open a
      # netlink socket the way glibc's getaddrinfo does. A controller that
      # cannot resolve a NAME (the lab configures addresses) is the symptom
      # that would point back at this line.
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
        written by one-context from the OpenNebula context instead — a key in
        both places would be a duplicate TOML key.
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

        NOT `auth`: this tier's whole [auth] table is appended by one-context
        at boot (see cloudAuthMtls/cloudAuthOidc above and the reason it has
        to be one owner). A key here would be a duplicate [auth] table and a
        parse error on the VM. The values live in cloudAuthOidc; the issuer
        comes from MEISTER_OIDC_ISSUER.
      '';
    };
  };

  config = {
    environment.etc."meisterstack/cluster.toml".source =
      toml.generate "cluster.toml" (lib.recursiveUpdate clusterDefaults cfg.cluster.settings);
    environment.etc."meisterstack/cloud.toml".source =
      toml.generate "cloud.toml" (lib.recursiveUpdate cloudDefaults cfg.cloud.settings);

    # The two halves of the cloud's [auth] table; one-context picks one and
    # appends it. Fragments and not templates: nothing consumes these on their
    # own, and a role that does not exist has no config file.
    environment.etc."meisterstack/cloud-auth-mtls.toml".source =
      toml.generate "cloud-auth-mtls.toml" cloudAuthMtls;
    environment.etc."meisterstack/cloud-auth-oidc.toml".source =
      toml.generate "cloud-auth-oidc.toml" cloudAuthOidc;

    systemd.services.meister-cloud-controller = controller "cloud";
    systemd.services.meister-cluster-controller = controller "cluster";
  };
}

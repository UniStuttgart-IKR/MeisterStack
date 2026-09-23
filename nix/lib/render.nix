# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The boot renderer, as a pure function.
#
# nix/context.nix turns a set of MEISTER_* variables into config files while
# the machine boots. A managed host must not do that — its configuration is a
# nix generation, and a file written at boot is a file no rollback can take
# back — so the same variables are read HERE, at build time, and the complete
# files are in /etc before the machine has started.
#
# Two renderers is one too many, which is why this one is a function with no
# I/O in it. Until M5B a boot-time renderer did the same job from a context,
# and `checks.render-parity` ran both over the same input and
# compares the parsed TOML. If they ever disagree, the check says so in the
# key that differs rather than in the lab three weeks later.
#
#   render = import ./lib/render.nix { inherit lib; cloudAuth = …; };
#   render { MEISTER_CLUSTER_NAME = "box"; … }
#     -> { agent = { … }; cluster = { … }; cloud = { … }; etcd = { … }; }
#
# `cloudAuth` is the pair of [auth] fragments that nix/controllers.nix owns
# (`meisterstack.cloud.authFragments`): `client_id` and `username_claim` are
# decisions about this stack and have exactly one place to live, and this
# function only adds what the context knows — whether there IS an issuer, and
# which one.
#
# What is NOT in here, and why:
#
#   MEISTER_ROLE     what this machine is, and that is `meisterstack.roles`
#                    on a managed host: an option, not a rendered string.
#   MEISTER_HOSTS    /etc/hosts, which is `networking.hosts` where the plan
#                    is known at build time.
#   MEISTER_LOKI_URL the collector's own config, which is not TOML and is not
#                    baked yet (nix/observability.nix says so).
{ lib, cloudAuth }:

env:
let
  # A variable is "said" only if it is there AND not empty — the same test the
  # shell makes with ''${X:-}, because a context that sets a variable to the
  # empty string is a context that said nothing about it.
  said = k: (env ? ${k}) && env.${k} != "";
  val = k: env.${k};

  # <attrs> if the variable is said, nothing if it is not. No key, no empty
  # value: a `cloud_name = ""` in a rendered file is a start-up error waiting
  # for the first replica that reads it.
  when = k: f: if said k then f (val k) else { };

  # The shell strips ALL whitespace out of a list entry before using it
  # (`''${x// /}` in toml_list, `tr -d '[:space:]'` for physnets and BGP
  # neighbours), so this one does too — the two have to agree about
  # "a, b , c".
  squeeze = s: lib.replaceStrings [ " " "\t" ] [ "" "" ] s;
  items = s: lib.filter (x: x != "") (map squeeze (lib.splitString "," s));

  # "<name>=<value>" pairs, in the spelling MEISTER_PHYSNETS,
  # MEISTER_BGP_NEIGHBORS and MEISTER_ETCD_PEERS share. An entry without a
  # `=`, or with an empty half, is dropped with no key — which is what the
  # shell does after printing its WARNING line.
  pairs = s: lib.filter (p: p != null) (map
    (entry:
      let parts = lib.splitString "=" entry; in
      if builtins.length parts < 2 then null
      else
        let
          name = builtins.head parts;
          value = lib.concatStringsSep "=" (builtins.tail parts);
        in
        if name == "" || value == "" then null else { inherit name value; })
    (items s));

  pairsToAttrs = s: builtins.listToAttrs (pairs s);

  # Both are DEPLOYMENT values and both reach all three roles: one `vm create`
  # crosses cloud, cluster and agent, and a trace that stops at a tier that
  # was not told where to export is not a trace, it is three fragments.
  telemetry =
    when "MEISTER_OTLP_ENDPOINT" (v: { otlp_endpoint = v; })
    // when "MEISTER_LOG_FORMAT" (v: { log_format = v; });

  # MEISTER_CLOUD_ADVERTISE_API and MEISTER_CLUSTER_ADVERTISE_API, each
  # falling back to the older MEISTER_ADVERTISE_API: it used to be one
  # variable for both roles, and that was a limit as long as one VM meant one
  # role. A box that is cloud and cluster at once serves two ports, so one
  # value cannot be right for both — and every context written before the
  # split keeps meaning what it meant.
  advertise = own:
    if said own then { advertise_api = val own; }
    else when "MEISTER_ADVERTISE_API" (v: { advertise_api = v; });

  # The cloud's whole [auth] table, which is the one thing the context
  # decides rather than the image: `auth.chain` naming "oidc" without an
  # `[auth.oidc]` is a start-up error, and a baked `[auth.oidc]` waiting for
  # an issuer is a parse error on every machine that never gets one. So the
  # owner is whoever knows whether there is an identity provider, and on a
  # managed host that is the plan.
  auth =
    if said "MEISTER_OIDC_ISSUER" then
      lib.recursiveUpdate cloudAuth.oidc {
        auth.oidc = {
          issuer = val "MEISTER_OIDC_ISSUER";
          # Which name the provider writes into `aud`, and it differs BY
          # PROVIDER rather than by taste: Keycloak writes what an audience
          # mapper says, Kanidm writes the name of the client itself and has
          # no mapper at all. The default is what the image baked before it
          # was a variable.
          audience = [ (if said "MEISTER_OIDC_AUDIENCE" then val "MEISTER_OIDC_AUDIENCE" else "meister") ];
        } // when "MEISTER_OIDC_CA" (v: { ca_cert = v; });
      }
    else cloudAuth.mtls;
in
{
  cloud = telemetry
    // when "MEISTER_CLOUD_NAME" (v: { cloud_name = v; })
    // advertise "MEISTER_CLOUD_ADVERTISE_API"
    // auth;

  cluster = telemetry
    // when "MEISTER_CLUSTER_NAME" (v: { cluster_name = v; })
    // advertise "MEISTER_CLUSTER_ADVERTISE_API"
    // when "MEISTER_CLOUD_ADDR" (v: { cloud_addr = v; })
    // when "MEISTER_CLOUD_ADDRS" (v: { cloud_addrs = items v; });

  agent = telemetry
    // when "MEISTER_NODE_ID" (v: { node_id = v; })
    // when "MEISTER_CONTROLLER_ADDR" (v: { controller_addr = v; })
    // when "MEISTER_CONTROLLER_ADDRS" (v: { controller_addrs = items v; })
    // {
      network =
        # An overlay uplink, and the mtu as a NUMBER: the shell writes
        # `mtu = $MEISTER_VXLAN_MTU` without quotes, so the two renderers
        # would otherwise disagree about the type of one key.
        when "MEISTER_VXLAN_UPLINK"
          (v: { vxlan = { uplink = v; } // when "MEISTER_VXLAN_MTU" (m: { mtu = lib.toInt m; }); })

        # The interfaces this machine gives away, with the name of the
        # provider network in front of each. An empty result renders no
        # section at all: `[network.provider]` without its required
        # `physnets` key is a start-up error and not "no gateway slot", and
        # the difference is the whole semantics of the section.
        // (if said "MEISTER_PHYSNETS" && pairsToAttrs (val "MEISTER_PHYSNETS") != { }
        then { provider.physnets = pairsToAttrs (val "MEISTER_PHYSNETS"); }
        else { })

        # Both required values or nothing: `asn` and `router_id` have no
        # default in the binary, and half a section is a start-up error and
        # not "no BGP". `router_id` is named rather than left to FRR, which
        # takes the highest address on the box — on a node full of bridges
        # and taps that is the last guest's.
        // (if said "MEISTER_BGP_ASN" && said "MEISTER_BGP_ROUTER_ID"
        then {
          bgp = {
            asn = lib.toInt (val "MEISTER_BGP_ASN");
            router_id = val "MEISTER_BGP_ROUTER_ID";
          } // (
            let ns = if said "MEISTER_BGP_NEIGHBORS" then pairs (val "MEISTER_BGP_NEIGHBORS") else [ ];
            in lib.optionalAttrs (ns != [ ]) {
              neighbors = map (p: { address = p.name; remote_asn = lib.toInt p.value; }) ns;
            }
          );
        }
        else { });
    };

  # Not a TOML file but the same question: which members this machine's etcd
  # bootstraps with. nix/etcd.nix takes them as options, and a managed host
  # therefore needs no /run/meisterstack/etcd.env and no second author for
  # the three values.
  etcd =
    if said "MEISTER_ETCD_PEERS" then {
      peers = pairsToAttrs (val "MEISTER_ETCD_PEERS");
      member = if said "MEISTER_ETCD_MEMBER" then val "MEISTER_ETCD_MEMBER"
      else if said "MEISTER_NODE_ID" then val "MEISTER_NODE_ID"
      else null;
      clusterToken = if said "MEISTER_ETCD_TOKEN" then val "MEISTER_ETCD_TOKEN" else "meisterstack";
    } else { peers = { }; member = null; clusterToken = "meisterstack"; };
}

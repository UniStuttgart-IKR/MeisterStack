# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Translate provider-neutral MEISTER_* values into role configuration attrsets.
# Empty values are omitted. Build-time rendering (nix/store-host.nix) uses this module;
# individual role modules supply defaults and explicit operator overrides.
{ lib, cloudAuth }:

env:
let
  # Treat absent and empty variables as unset.
  said = k: (env ? ${k}) && env.${k} != "";
  val = k: env.${k};

  # Return no key when its source variable is unset.
  when = k: f: if said k then f (val k) else { };

  # Remove spaces and tabs from comma-separated entries.
  squeeze = s: lib.replaceStrings [ " " "\t" ] [ "" "" ] s;
  items = s: lib.filter (x: x != "") (map squeeze (lib.splitString "," s));

  # Parse comma-separated name=value pairs; ignore malformed entries.
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

  # Apply shared telemetry settings to each role.
  telemetry =
    when "MEISTER_OTLP_ENDPOINT" (v: { otlp_endpoint = v; })
    // when "MEISTER_LOG_FORMAT" (v: { log_format = v; });

  # Prefer the role-specific advertised address, falling back to the shared value.
  advertise = own:
    if said own then { advertise_api = val own; }
    else when "MEISTER_ADVERTISE_API" (v: { advertise_api = v; });

  # Choose the cloud authentication fragment from the presence of an issuer.
  auth =
    if said "MEISTER_OIDC_ISSUER" then
      lib.recursiveUpdate cloudAuth.oidc {
        auth.oidc = {
          issuer = val "MEISTER_OIDC_ISSUER";
          # Allow providers to specify their token audience.
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
        # Render the overlay MTU as an integer.
        when "MEISTER_VXLAN_UPLINK"
          (v: { vxlan = { uplink = v; } // when "MEISTER_VXLAN_MTU" (m: { mtu = lib.toInt m; }); })

        # Map provider network names to host interfaces only when configured.
        // (if said "MEISTER_PHYSNETS" && pairsToAttrs (val "MEISTER_PHYSNETS") != { }
        then { provider.physnets = pairsToAttrs (val "MEISTER_PHYSNETS"); }
        else { })

        # Emit BGP configuration only when both ASN and router ID are present.
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

  # Translate etcd membership variables into module options.
  etcd =
    if said "MEISTER_ETCD_PEERS" then {
      peers = pairsToAttrs (val "MEISTER_ETCD_PEERS");
      member = if said "MEISTER_ETCD_MEMBER" then val "MEISTER_ETCD_MEMBER"
      else if said "MEISTER_NODE_ID" then val "MEISTER_NODE_ID"
      else null;
      clusterToken = if said "MEISTER_ETCD_TOKEN" then val "MEISTER_ETCD_TOKEN" else "meisterstack";
    } else { peers = { }; member = null; clusterToken = "meisterstack"; };
}

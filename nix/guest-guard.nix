# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Keep guests from opening connections to the host they run on. A host address
# on a guest bridge is not the only way in: every bridge carries an IPv6
# link-local address, and Linux answers ARP for any of its addresses on any
# link. So the guard filters what arrives from the links the network driver
# creates, in its own nftables table, beside whatever firewall the host runs.
{ lib, pkgs, config, ... }:
let
  cfg = config.meisterstack.agent.guestGuard;
  table = "meister-guest-guard";
  nft = "${pkgs.nftables}/bin/nft";
  agentRuns = builtins.elem "agent" config.meisterstack.unitsFor;

  # The links drivers/linux-network makes for guests: bridges (meister_br0,
  # meister-vx<VNI>, meister-px-<physnet>), taps (msk), VXLAN devices (mvx)
  # and the host ends of router veths (rtx, rti).
  guestLinks = [ "meister*" "msk*" "mvx*" "rtx*" "rti*" ];

  allowed = proto: ports: lib.optionalString (ports != [ ])
    "${proto} dport { ${lib.concatMapStringsSep ", " toString ports} } accept";

  chains = ''
    chain input {
      type filter hook input priority filter; policy accept;
      ${lib.concatMapStringsSep "\n  " (l: ''iifname "${l}" jump from_guest'') guestLinks}
    }
    chain from_guest {
      ct state established,related accept
      # Address resolution for connections the host opens to a guest.
      icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
      ${allowed "tcp" cfg.allowedTCPPorts}
      ${allowed "udp" cfg.allowedUDPPorts}
      counter drop
    }
  '';

  # Replaces the table atomically: declare, delete, define, in one transaction.
  rules = pkgs.writeText "${table}.nft" ''
    table inet ${table}
    delete table inet ${table}
    table inet ${table} {
      ${chains}
    }
  '';
  load = "${nft} -f ${rules}";

  # A NixOS nftables firewall flushes the ruleset, or at least deletes its own
  # tables, on every load, reload and restart. There the guard is one of those
  # tables, so the host's own transaction carries it; elsewhere a unit of its
  # own loads it.
  hostRunsNftables = config.networking.nftables.enable;
  loader = if hostRunsNftables then "nftables.service" else "${table}.service";

  tableLoaded = pkgs.writeShellScript "${table}-loaded" ''
    if ! ${nft} list table inet ${table} >/dev/null; then
      echo "the guest guard (nftables table inet ${table}) is not loaded;" \
        "the agent does not create guest links without it" >&2
      exit 1
    fi
  '';
in
{
  options.meisterstack.agent.guestGuard = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = agentRuns;
      defaultText = lib.literalExpression ''an agent node runs it'';
      description = ''
        Whether this host drops every connection a guest opens to the host
        itself: anything arriving on a link the agent creates (`meister*`,
        `msk*`, `mvx*`, `rtx*`, `rti*`) that is not a reply, IPv6 neighbour
        discovery, or a port listed below. Traffic between guests and routed
        traffic are not touched; this is the host's INPUT, not its FORWARD.

        On by default wherever the agent runs. The agent starts after the
        table `inet meister-guest-guard` is loaded and refuses to start
        without it, but it never stops or restarts with whatever loads it.
        Where NixOS runs nftables (`networking.nftables.enable`) the table is
        part of that ruleset, so every load, reload and restart of the host's
        firewall carries it, and stopping that firewall loads the table again
        on its own; elsewhere `meister-guest-guard.service` loads it. The
        table stays when its loader stops, so guest isolation fails closed;
        `nft delete table inet meister-guest-guard` removes it by hand.
      '';
    };

    allowedTCPPorts = lib.mkOption {
      type = lib.types.listOf lib.types.port;
      default = [ ];
      example = [ 53 ];
      description = ''
        TCP ports on this host that guests may open connections to. Nothing
        of this stack listens for guests on the host, so the default is none.
      '';
    };

    allowedUDPPorts = lib.mkOption {
      type = lib.types.listOf lib.types.port;
      default = [ ];
      example = [ 53 67 ];
      description = ''
        UDP ports on this host that guests may send to, for a DHCP or DNS
        server the host runs for them itself.
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    (lib.mkIf hostRunsNftables {
      networking.nftables.tables.${table} = {
        family = "inet";
        content = chains;
      };
      # A stopped host firewall is not an open host: its stop removes the
      # table with the rest of the ruleset, so the guard goes back in after it.
      systemd.services.nftables.serviceConfig.ExecStopPost = [ load ];
    })

    (lib.mkIf (!hostRunsNftables) {
      systemd.services.${table} = {
        description = "Keep MeisterStack guests from opening connections to this host";
        wantedBy = [ "multi-user.target" ];
        before = [ "meister-agent.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = load;
          ExecReload = load;
        };
      };
    })

    # Requires= or Requisite= would stop and restart the agent whenever the
    # loader stops or restarts, and the host's firewall is restarted for
    # reasons of its own. The table outlives its loader, so the agent only
    # orders after the loader and checks for the table itself.
    (lib.mkIf agentRuns {
      systemd.services.meister-agent = {
        after = [ loader ];
        # The host's firewall is the host's to start; the guard's own unit is not.
        wants = lib.optional (!hostRunsNftables) loader;
        serviceConfig.ExecStartPre = [ "${tableLoaded}" ];
      };
    })
  ]);
}

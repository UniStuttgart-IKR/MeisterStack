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

  # The links drivers/linux-network makes for guests: bridges (meister_br0,
  # meister-vx<VNI>, meister-px-<physnet>), taps (msk), VXLAN devices (mvx)
  # and the host ends of router veths (rtx, rti).
  guestLinks = [ "meister*" "msk*" "mvx*" "rtx*" "rti*" ];

  allowed = proto: ports: lib.optionalString (ports != [ ])
    "${proto} dport { ${lib.concatMapStringsSep ", " toString ports} } accept";

  # Replaces the table atomically: declare, delete, define, in one transaction.
  rules = pkgs.writeText "${table}.nft" ''
    table inet ${table}
    delete table inet ${table}
    table inet ${table} {
      chain input {
        type filter hook input priority filter; policy accept;
        ${lib.concatMapStringsSep "\n    " (l: ''iifname "${l}" jump from_guest'') guestLinks}
      }
      chain from_guest {
        ct state established,related accept
        # Address resolution for connections the host opens to a guest.
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
        ${allowed "tcp" cfg.allowedTCPPorts}
        ${allowed "udp" cfg.allowedUDPPorts}
        counter drop
      }
    }
  '';
  load = "${pkgs.nftables}/bin/nft -f ${rules}";
  hostRunsNftables = config.networking.nftables.enable;
in
{
  options.meisterstack.agent.guestGuard = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = builtins.elem "agent" config.meisterstack.unitsFor;
      defaultText = lib.literalExpression ''an agent node runs it'';
      description = ''
        Whether this host drops every connection a guest opens to the host
        itself: anything arriving on a link the agent creates (`meister*`,
        `msk*`, `mvx*`, `rtx*`, `rti*`) that is not a reply, IPv6 neighbour
        discovery, or a port listed below. Traffic between guests and routed
        traffic are not touched; this is the host's INPUT, not its FORWARD.

        On by default wherever the agent runs, and loaded before it. The
        table `inet meister-guest-guard` is left in place when the unit
        stops, so guest isolation fails closed; `nft delete table inet
        meister-guest-guard` removes it by hand.
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

  config = lib.mkIf cfg.enable {
    systemd.services.meister-guest-guard = {
      description = "Keep MeisterStack guests from opening connections to this host";
      wantedBy = [ "multi-user.target" ];
      # The agent creates no guest link before the guard is loaded, and does
      # not start without it.
      requiredBy = [ "meister-agent.service" ];
      before = [ "meister-agent.service" ];
      # A NixOS nftables firewall may flush the whole ruleset when it is
      # (re)loaded; load the guard again after it.
      after = lib.mkIf hostRunsNftables [ "nftables.service" ];
      partOf = lib.mkIf hostRunsNftables [ "nftables.service" ];
      unitConfig.ReloadPropagatedFrom = lib.mkIf hostRunsNftables "nftables.service";
      # Apply a changed ruleset in place: a restart would restart the agent.
      reloadIfChanged = true;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = load;
        ExecReload = load;
      };
    };
  };
}

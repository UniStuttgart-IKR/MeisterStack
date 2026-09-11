# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Minimal OpenNebula contextualization: render the runtime configs, read the
# CONTEXT CD, apply network/hostname/ssh key, then start what this VM is
# meant to run (MEISTER_ROLE=cloud|cluster|agent|both).
#
# Config model: the image bakes role TEMPLATES under /etc/meisterstack/;
# this service always copies them to /run/meisterstack/<role>.toml and
# appends per-VM values from the context (cluster name, controller addr,
# node id from the hostname). The templates deliberately do NOT contain
# those keys — duplicate TOML keys are parse errors, append must be safe.
# Units consume the /run copies.
{ pkgs, ... }:
{
  systemd.services.one-context = {
    description = "Apply OpenNebula context (network, ssh key, meister role)";
    wantedBy = [ "multi-user.target" ];
    before = [ "network-online.target" "sshd.service" ];
    after = [ "local-fs.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      # context problems must be debuggable from the serial console
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
    path = with pkgs; [ iproute2 util-linux coreutils gnugrep gawk systemd ];
    script = ''
      # --- runtime configs: per-VM values must be TOP-LEVEL keys, so they
      # go BEFORE the template (appending would land them inside whatever
      # [table] the template ends with — a bug the qemu rehearsal caught).
      mkdir -p /run/meisterstack
      render_config() { # role, override lines on stdin
        local role=$1 tmpl="/etc/meisterstack/$1.toml"
        [ -f "$tmpl" ] || { cat > /dev/null; return 0; }
        { cat; echo; cat "$tmpl"; } > "/run/meisterstack/$role.toml"
      }

      # The cloud's whole [auth] table, APPENDED. It is the one table this
      # script owns rather than the image, and the reason is spelled out in
      # nix/controllers.nix: chain and [auth.oidc] have to appear together, a
      # missing issuer in a baked [auth.oidc] would be a parse error rather
      # than a quiet no-op, and an append cannot redefine a [table]. So the
      # only place that knows whether there is an identity provider renders
      # the whole thing.
      #
      # Everything except the issuer comes from a baked fragment, so the
      # client id and the audience stay in nix and TOML quoting stays Nix's
      # problem. The fragment ENDS on [auth.oidc], which is what lets the
      # issuer line land inside it.
      #
      # No issuer means ["mtls"], exactly as today: naming a link that cannot
      # be built is a start-up error, and a cloud whose provider was simply
      # not configured should come up serving certificates, not refuse to
      # come up at all.
      #
      # MEISTER_OIDC_CA travels with the issuer for the same reason the issuer
      # itself does: WHO signed the provider is a property of where this VM was
      # booted. Absent = the platform's public roots, which is right for a real
      # provider and wrong for a lab one. In this lab the value is
      # /opt/meisterstack/pki/ca.crt, because the same CA that signs the fleet
      # also signs the Keycloak — but that is a coincidence of one deployment
      # and not a default worth baking: a public provider wants no line at all,
      # and a site with its own IdP wants a different file.
      render_cloud_auth() {
        [ -f /run/meisterstack/cloud.toml ] || return 0
        # A CA without an issuer renders nowhere -- [auth.oidc] does not exist
        # then -- and silently dropping it would look exactly like a provider
        # whose certificate is not trusted. Say it on the console instead.
        if [ -z "''${MEISTER_OIDC_ISSUER:-}" ] && [ -n "''${MEISTER_OIDC_CA:-}" ]; then
          echo "WARNING: MEISTER_OIDC_CA is set but MEISTER_OIDC_ISSUER is not; no [auth.oidc] is rendered"
        fi
        {
          echo
          if [ -n "''${MEISTER_OIDC_ISSUER:-}" ]; then
            cat /etc/meisterstack/cloud-auth-oidc.toml
            echo "issuer = \"''${MEISTER_OIDC_ISSUER}\""
            # Which name the provider writes into `aud`, and it differs BY
            # PROVIDER rather than by taste: Keycloak writes what an audience
            # mapper says (the lab's says "meister"), Kanidm writes the name
            # of the client itself and has no mapper at all. So it is a
            # deployment value like the issuer, and the default is what this
            # image baked before it was one.
            echo "audience = [\"''${MEISTER_OIDC_AUDIENCE:-meister}\"]"
            [ -n "''${MEISTER_OIDC_CA:-}" ] \
              && echo "ca_cert = \"''${MEISTER_OIDC_CA}\""
          else
            cat /etc/meisterstack/cloud-auth-mtls.toml
          fi
          true
        } >> /run/meisterstack/cloud.toml
      }

      # A rendered config can carry a secret — a bearer token today, whatever
      # a future key names tomorrow — and the controllers read theirs as the
      # `meister` user (controllers.nix). root:meister 0640 is exactly that
      # much: root writes, the service reads, nobody else looks. Loud on
      # failure, because a config the controller cannot read is a unit that
      # will not start, and the serial console is where that gets diagnosed.
      harden_configs() {
        local f
        for f in /run/meisterstack/*.toml; do
          [ -e "$f" ] || continue
          chgrp meister "$f" && chmod 0640 "$f" \
            || echo "WARNING: cannot set root:meister 0640 on $f"
        done
      }

      # --- what this machine is, in two layers ---------------------------
      #
      # The baked file is the PLAN (nix/roles.nix): a box installed from this
      # flake, or somebody else's NixOS host that imports our modules, knows
      # its roles and its addresses at build time and has no cd to read them
      # from. The context cd is where this machine was actually BOOTED, and
      # that is the stronger fact — so the plan is sourced first and the
      # context overwrites it, variable by variable.
      #
      # Everything below this point is then the same code for both roads, and
      # that is the point of doing it here rather than in a second renderer:
      # the prepend rule, the [auth] table, the etcd env and the alloy config
      # have each been got wrong once already, and they should be got right in
      # one place.
      if [ -f /etc/meisterstack/context.env ]; then
        . /etc/meisterstack/context.env
        echo "plan: baked defaults, role ''${MEISTER_ROLE:-<none>}"
      fi

      dev=/dev/disk/by-label/CONTEXT
      # Waiting for a cd is for a machine that expects one. A plan node knows
      # its role already and would otherwise spend thirty seconds of every
      # boot discovering that OpenNebula is not there.
      if [ ! -e "$dev" ] && [ -z "''${MEISTER_ROLE:-}" ]; then
        for i in $(seq 30); do [ -e "$dev" ] && break; sleep 1; done
      fi

      if [ -e "$dev" ]; then
        mnt=/run/one-context
        mkdir -p "$mnt"
        mount -o ro "$dev" "$mnt"
        trap 'umount "$mnt"' EXIT
        . "$mnt/context.sh"

        # dotted netmask -> prefix length
        mask2prefix() {
          local p=0 octet
          for octet in ''${1//./ }; do
            case $octet in
              255) p=$((p+8));;
              254) p=$((p+7));; 252) p=$((p+6));; 248) p=$((p+5));;
              240) p=$((p+4));; 224) p=$((p+3));; 192) p=$((p+2));;
              128) p=$((p+1));; 0) ;;
            esac
          done
          echo "$p"
        }

        if [ -n "''${ETH0_IP:-}" ]; then
          prefix=$(mask2prefix "''${ETH0_MASK:-255.255.255.0}")
          ip addr replace "$ETH0_IP/$prefix" dev eth0
          ip link set eth0 up
          [ -n "''${ETH0_GATEWAY:-}" ] && ip route replace default via "$ETH0_GATEWAY"
          if [ -n "''${ETH0_DNS:-}" ]; then
            : > /etc/resolv.conf
            for ns in $ETH0_DNS; do echo "nameserver $ns" >> /etc/resolv.conf; done
          fi
        fi

        # daemon-free: hostnamed is not up this early in boot
        [ -n "''${SET_HOSTNAME:-}" ] && echo "$SET_HOSTNAME" > /proc/sys/kernel/hostname

        if [ -n "''${SSH_PUBLIC_KEY:-}" ]; then
          mkdir -p /root/.ssh; chmod 700 /root/.ssh
          grep -qxF "$SSH_PUBLIC_KEY" /root/.ssh/authorized_keys 2>/dev/null \
            || echo "$SSH_PUBLIC_KEY" >> /root/.ssh/authorized_keys
          chmod 600 /root/.ssh/authorized_keys
        fi
      else
        # Not an error and not a fallback: this is what a plan node looks
        # like. Its address, its hostname and its ssh key are NixOS' business,
        # and its MEISTER_* variables were sourced above.
        echo "no CONTEXT cd; the baked defaults are this machine's whole context"
      fi

      # --- names this machine has to resolve without a dns ----------------
      #
      # MEISTER_HOSTS = "10.0.0.10 box.lab.example" — /etc/hosts lines,
      # several of them separated by commas. It exists because an https url
      # cannot be flattened to an address: Kanidm's issuer, its origin, every
      # oauth2 redirect and the name in its serving certificate are one and
      # the same NAME (nix/addons.nix), so a fleet whose cloud verifies a
      # token has to resolve that name — and a lab has no dns.
      #
      # This is the same ownership resolv.conf already has above and for the
      # same reason: which names exist is a property of where this VM was
      # booted, not of the qcow2 it boots. `networking.hosts` is the road for
      # a host whose plan is known at build time (nix/fleet.nix sets both).
      #
      # /etc/hosts is a symlink into the store and the store is read-only, so
      # the file is written under /run and the symlink is pointed at it. The
      # static content comes first — localhost is in there and nothing may
      # lose it. Activation recreates the store symlink on every boot and
      # this service runs after it, so the takeover repeats itself and never
      # outlives a context that stops naming anything.
      if [ -n "''${MEISTER_HOSTS:-}" ]; then
        mkdir -p /run/meisterstack
        {
          cat /etc/static/hosts 2>/dev/null || cat /etc/hosts
          echo "# MEISTER_HOSTS, from this machine's context"
          IFS=, read -ra host_entries <<< "$MEISTER_HOSTS"
          for entry in "''${host_entries[@]}"; do
            entry="$(echo "$entry" | awk '{$1=$1; print}')"
            [ -n "$entry" ] && echo "$entry"
          done
          true
        } > /run/meisterstack/hosts
        chmod 0644 /run/meisterstack/hosts
        ln -sfn /run/meisterstack/hosts /etc/hosts
        echo "hosts: ''${MEISTER_HOSTS}"
      fi

      # --- per-VM config values from the context (as top-level prefix) ---
      # "a,b,c" -> ["a", "b", "c"] — the HA endpoint lists are TOML arrays
      toml_list() {
        local out="" x
        IFS=, read -ra items <<< "$1"
        for x in "''${items[@]}"; do
          x="''${x// /}"
          [ -n "$x" ] && out="$out\"$x\", "
        done
        echo "[''${out%, }]"
      }

      # Where spans go and how lines are written. Both are DEPLOYMENT values,
      # not image values: the same qcow2 runs in a lab with a Tempo and in one
      # without, and which collector this VM talks to is a property of where
      # it was booted. So: context, not meisterstack.<role>.settings.
      #
      # All three roles get both, and that is the point of tracing at all --
      # one `vm create` crosses cloud, cluster and agent, and a trace that
      # stops at a tier that was not told where to export is not a trace, it
      # is three fragments. Unset stays unset: no line, no export, exactly the
      # fmt subscriber this fleet has run since M1.
      #
      # Both values are passed through verbatim rather than checked here. The
      # binaries own their own vocabulary: a misspelled MEISTER_LOG_FORMAT is
      # a start-up error naming "human" and "json" (telemetry::LogFormat),
      # which is a better place to learn it than a shell test that would have
      # to be kept in step with the enum.
      telemetry_keys() {
        [ -n "''${MEISTER_OTLP_ENDPOINT:-}" ] \
          && echo "otlp_endpoint = \"''${MEISTER_OTLP_ENDPOINT}\""
        [ -n "''${MEISTER_LOG_FORMAT:-}" ] \
          && echo "log_format = \"''${MEISTER_LOG_FORMAT}\""
        true
      }

      # MEISTER_ADVERTISE_API is the REST address of THIS replica, e.g.
      # "10.128.1.104:3001" — per VM and therefore context, never the baked
      # template. Both controller roles take the key and mean the same thing
      # by it: listen_api is a BIND address, 0.0.0.0 is not one a sibling can
      # dial, so a replica that binds a wildcard cannot name itself and
      # publishes nothing. Without it the tier still runs and still logs its
      # wildcard warning at start-up; what stops working is every read that
      # has to be forwarded to the replica holding a session (console, vm
      # logs), because that address is what a sibling is told to dial.
      #
      # It USED to be one variable for both roles, and that was a limit as
      # long as one VM meant one role. It does not any more: a lab box is
      # cloud and cluster and agent and addons at once (the catalogue calls
      # that the normal case), and the two tiers serve two different ports, so
      # one value cannot be right for both. Hence MEISTER_CLOUD_ADVERTISE_API
      # and MEISTER_CLUSTER_ADVERTISE_API, each falling back to the old
      # variable — every context written before this keeps meaning what it
      # meant, and a two-role box can finally say both.
      # MEISTER_CLOUD_NAME is the CLOUD's name, shared by its three replicas
      # — the counterpart of MEISTER_CLUSTER_NAME one tier down, and the same
      # kind of value: what the tier is called rather than what this machine
      # is. It is the name in the `system:cloud:<name>` certificate
      # `push.sh pki` lays down as identity.*, so it has to be identical on
      # all three and stable across restarts. Left out, the binary defaults
      # to "cloud", which is what every single-replica deployment so far has
      # been in everything but name.
      cloud_advertise="''${MEISTER_CLOUD_ADVERTISE_API:-''${MEISTER_ADVERTISE_API:-}}"
      cluster_advertise="''${MEISTER_CLUSTER_ADVERTISE_API:-''${MEISTER_ADVERTISE_API:-}}"
      {
        telemetry_keys
        [ -n "''${MEISTER_CLOUD_NAME:-}" ] \
          && echo "cloud_name = \"''${MEISTER_CLOUD_NAME}\""
        [ -n "$cloud_advertise" ] \
          && echo "advertise_api = \"$cloud_advertise\""
        true
      } | render_config cloud
      render_cloud_auth
      {
        telemetry_keys
        [ -n "''${MEISTER_CLUSTER_NAME:-}" ] \
          && echo "cluster_name = \"''${MEISTER_CLUSTER_NAME}\""
        [ -n "$cluster_advertise" ] \
          && echo "advertise_api = \"$cluster_advertise\""
        [ -n "''${MEISTER_CLOUD_ADDR:-}" ] \
          && echo "cloud_addr = \"''${MEISTER_CLOUD_ADDR}\""
        [ -n "''${MEISTER_CLOUD_ADDRS:-}" ] \
          && echo "cloud_addrs = $(toml_list "$MEISTER_CLOUD_ADDRS")"
        true
      } | render_config cluster
      {
        telemetry_keys
        echo "node_id = \"$(cat /proc/sys/kernel/hostname)\""
        [ -n "''${MEISTER_CONTROLLER_ADDR:-}" ] \
          && echo "controller_addr = \"''${MEISTER_CONTROLLER_ADDR}\""
        [ -n "''${MEISTER_CONTROLLER_ADDRS:-}" ] \
          && echo "controller_addrs = $(toml_list "$MEISTER_CONTROLLER_ADDRS")"
        true
      } | render_config agent
      # Section-Overrides werden ANGEHÄNGT, nie prependet: das Template
      # beginnt mit Top-Level-Keys (stop_grace_secs), und alles nach einem
      # geprependeten [table]-Header fiele in diese Table — exakt der
      # Append-Bug in Gegenrichtung, live gefangen am 2026-08-27. Nach dem
      # Template ist es sicher: die Sub-Table nach ihrem [network]-Parent
      # ist valides TOML, und das Template trägt diese Keys nie selbst.
      if [ -n "''${MEISTER_VXLAN_UPLINK:-}" ] && [ -f /run/meisterstack/agent.toml ]; then
        {
          echo ""
          echo "[network.vxlan]"
          echo "uplink = \"''${MEISTER_VXLAN_UPLINK}\""
          [ -n "''${MEISTER_VXLAN_MTU:-}" ] && echo "mtu = ''${MEISTER_VXLAN_MTU}"
          true
        } >> /run/meisterstack/agent.toml
      fi

      # MEISTER_PHYSNETS = "ext=eth1" oder "ext=eth1,dmz=eth2" — die
      # Interfaces, die DIESE Maschine abgibt, mit dem Namen des
      # Provider-Netzes davor. Dieselbe Append-Regel und derselbe Grund wie
      # oben: [network.provider] ist eine Sub-Table von [network] und darf
      # erst nach dem Template kommen.
      #
      # Per Kontext und nicht im Template, weil es eine Aussage ueber die
      # MASCHINE ist und nicht ueber die Rolle: zwei Agenten aus demselben
      # Image geben verschiedene NICs ab, und einer gibt keine ab. Genau
      # dafuer gibt es meisterstack.agent.physnets als Nix-Option daneben —
      # die ist die Antwort fuer eine Flotte, die ihre Maschinen im Plan
      # stehen hat, und das hier ist die Antwort fuer eine Wolke, die
      # dieselbe qcow2 zwoelfmal instanziiert.
      #
      # Ein leerer Wert rendert nichts. Ein [network.provider] ohne seinen
      # Pflichtschluessel physnets ist ein Startfehler und nicht "kein Slot",
      # und der Unterschied ist die ganze Semantik des Abschnitts.
      if [ -n "''${MEISTER_PHYSNETS:-}" ] && [ -f /run/meisterstack/agent.toml ]; then
        physnet_pairs=""
        IFS=, read -ra physnet_entries <<< "$MEISTER_PHYSNETS"
        for entry in "''${physnet_entries[@]}"; do
          entry="$(echo "$entry" | tr -d '[:space:]')"
          [ -z "$entry" ] && continue
          case "$entry" in
            *=*) : ;;
            *)
              echo "WARNING: MEISTER_PHYSNETS entry ''${entry} is not <name>=<interface>; skipped"
              continue
              ;;
          esac
          name="''${entry%%=*}"
          iface="''${entry#*=}"
          if [ -z "$name" ] || [ -z "$iface" ]; then
            echo "WARNING: MEISTER_PHYSNETS entry ''${entry} names no ''${name:+interface}''${name:-network}; skipped"
            continue
          fi
          physnet_pairs="''${physnet_pairs:+$physnet_pairs, }$name = \"$iface\""
        done
        if [ -n "$physnet_pairs" ]; then
          {
            echo ""
            echo "[network.provider]"
            echo "physnets = { $physnet_pairs }"
          } >> /run/meisterstack/agent.toml
          echo "physnets: ''${MEISTER_PHYSNETS}"
        fi
      fi
      # MEISTER_BGP_ASN / MEISTER_BGP_ROUTER_ID / MEISTER_BGP_NEIGHBORS —
      # [network.bgp], die Ankuendigung dieses Knotens. Dieselbe Append-Regel
      # wie oben und derselbe Grund.
      #
      # Beide Pflichtwerte oder gar nichts: `asn` und `router_id` sind im
      # Binary ohne Default (components/agent/src/config.rs), und ein halber
      # Abschnitt ist ein Startfehler und kein "kein BGP". `router_id` wird
      # ausdruecklich gesetzt und nicht FRR ueberlassen — FRR nimmt die
      # hoechste Adresse der Kiste, und das ist auf einem Knoten voller
      # Bruecken und Taps die des zuletzt gebauten Gastes.
      #
      # Die Nachbarn stehen als `<adresse>=<asn>`, komma-getrennt, in der
      # Schreibweise von MEISTER_PHYSNETS. Keine Nachbarn ist erlaubt und
      # bedeutet: der Abschnitt steht, FRR laeuft, angekuendigt wird an
      # niemanden — der Zustand, in dem eine Maschine auf ihre Peers wartet.
      #
      # Der Daemon dazu laeuft im Image (services.frr.bgpd, nix/agent.nix):
      # `vtysh` ist ein Client, und ohne Daemon antwortet er auf jeden Aufruf
      # mit "failed to connect to any daemons".
      if [ -n "''${MEISTER_BGP_ASN:-}" ] && [ -f /run/meisterstack/agent.toml ]; then
        if [ -z "''${MEISTER_BGP_ROUTER_ID:-}" ]; then
          echo "WARNING: MEISTER_BGP_ASN is set but MEISTER_BGP_ROUTER_ID is not; no [network.bgp] is rendered"
        else
          {
            echo ""
            echo "[network.bgp]"
            echo "asn = ''${MEISTER_BGP_ASN}"
            echo "router_id = \"''${MEISTER_BGP_ROUTER_ID}\""
          } >> /run/meisterstack/agent.toml
          bgp_peers=0
          if [ -n "''${MEISTER_BGP_NEIGHBORS:-}" ]; then
            IFS=, read -ra bgp_entries <<< "$MEISTER_BGP_NEIGHBORS"
            for entry in "''${bgp_entries[@]}"; do
              entry="$(echo "$entry" | tr -d '[:space:]')"
              [ -z "$entry" ] && continue
              case "$entry" in
                *=*) : ;;
                *)
                  echo "WARNING: MEISTER_BGP_NEIGHBORS entry ''${entry} is not <address>=<asn>; skipped"
                  continue
                  ;;
              esac
              peer="''${entry%%=*}"
              peer_asn="''${entry#*=}"
              if [ -z "$peer" ] || [ -z "$peer_asn" ]; then
                echo "WARNING: MEISTER_BGP_NEIGHBORS entry ''${entry} names no ''${peer:+asn}''${peer:-address}; skipped"
                continue
              fi
              {
                echo ""
                echo "[[network.bgp.neighbors]]"
                echo "address = \"$peer\""
                echo "remote_asn = $peer_asn"
              } >> /run/meisterstack/agent.toml
              bgp_peers=$((bgp_peers + 1))
            done
          fi
          echo "bgp: asn ''${MEISTER_BGP_ASN}, router-id ''${MEISTER_BGP_ROUTER_ID}, ''${bgp_peers} neighbor(s)"
        fi
      fi
      harden_configs

      # --- the log collector (nix/observability.nix). Written only when the
      # context names a Loki, and the unit's ConditionPathExists reads exactly
      # this file: no variable, no config, no Alloy.
      #
      # host and role are rendered as LITERALS rather than as Alloy's
      # env("HOSTNAME"), and that is deliberate. A systemd unit inherits no
      # HOSTNAME, so env() there would be the empty string and every line of
      # the whole fleet would arrive under host="" -- a silent failure, and
      # the worst kind, because Loki would look healthy. one-context knows the
      # hostname (it just set it) and it knows the role, so it writes them.
      #
      # The body below is `alloy fmt` output, tabs and all, and check-context
      # holds it to that: a generated file that its own formatter would
      # rewrite makes every later diff on a VM unreadable.
      #
      # 0644, and said out loud: this file carries the Loki url. In the lab
      # that is a plain http address, public by construction. A deployment
      # whose url carries a credential wants it out of here -- services.alloy
      # takes an environmentFile and the config an env() -- not a chmod.
      if [ -n "''${MEISTER_LOKI_URL:-}" ]; then
        cat > /run/meisterstack/alloy.alloy <<ALLOY
loki.source.journal "fleet" {
	forward_to    = [loki.write.lab.receiver]
	labels        = {host = "$(cat /proc/sys/kernel/hostname)", role = "''${MEISTER_ROLE:-unknown}"}
	relabel_rules = loki.relabel.units.rules
}

loki.relabel "units" {
	forward_to = []

	rule {
		source_labels = ["__journal__systemd_unit"]
		target_label  = "unit"
	}

	rule {
		source_labels = ["__journal_priority_keyword"]
		target_label  = "level"
	}
}

loki.write "lab" {
	endpoint {
		url = "''${MEISTER_LOKI_URL}"
	}
}
ALLOY
        chmod 0644 /run/meisterstack/alloy.alloy
        echo "alloy: journal -> ''${MEISTER_LOKI_URL}"
      fi

      # --- etcd: a peer set in the context turns the baked single member
      # into one member of a static Raft cluster. Rendered as ETCD_* env
      # (etcd.nix hooks the file in via EnvironmentFile, which overrides
      # the module's Environment= — and etcd orders after this service).
      # MEISTER_ETCD_PEERS = "name1=ip1,name2=ip2,name3=ip3";
      # MEISTER_ETCD_MEMBER defaults to the hostname; MEISTER_ETCD_TOKEN
      # must differ between two tiers bootstrapping on one network.
      # NOTE: first 3-member boot needs an EMPTY data dir — a datablock
      # that has lived as a single member carries that cluster's identity
      # and will refuse the new Raft (wipe /var/lib/etcd once, deliberately).
      if [ -n "''${MEISTER_ETCD_PEERS:-}" ]; then
        member="''${MEISTER_ETCD_MEMBER:-$(cat /proc/sys/kernel/hostname)}"
        self_ip="" initial=""
        IFS=, read -ra peers <<< "$MEISTER_ETCD_PEERS"
        for p in "''${peers[@]}"; do
          p="''${p// /}"
          name="''${p%%=*}" ip="''${p#*=}"
          initial="$initial$name=http://$ip:2380,"
          [ "$name" = "$member" ] && self_ip="$ip"
        done
        if [ -z "$self_ip" ]; then
          echo "MEISTER_ETCD_MEMBER '$member' is not in MEISTER_ETCD_PEERS; keeping the single member"
        else
          {
            echo "ETCD_NAME=$member"
            echo "ETCD_LISTEN_PEER_URLS=http://$self_ip:2380"
            echo "ETCD_INITIAL_ADVERTISE_PEER_URLS=http://$self_ip:2380"
            echo "ETCD_INITIAL_CLUSTER=''${initial%,}"
            echo "ETCD_INITIAL_CLUSTER_STATE=new"
            echo "ETCD_INITIAL_CLUSTER_TOKEN=''${MEISTER_ETCD_TOKEN:-meisterstack}"
          } > /run/meisterstack/etcd.env
          echo "etcd: member $member of [''${initial%,}]"
        fi
      fi

      # MEISTER_ROLE is a COMMA LIST: cloud, cluster, agent, addons, in any
      # combination — because the normal deployment is one box that is all of
      # them and not four VMs that are one each (design/feature-catalogue.md,
      # "die Lab-Kiste ist der Normalfall"). `both` and `all` are the two
      # shorthands worth having; `both` is what the lab's twelve VMs and every
      # template written before this say, and it keeps meaning what it meant.
      roles="''${MEISTER_ROLE:-}"
      case "$roles" in
        both) roles="cloud,cluster" ;;
        all)  roles="cloud,cluster,agent,addons" ;;
      esac
      roles="''${roles//,/ }"
      if [ -z "$roles" ]; then
        echo "no MEISTER_ROLE in context; starting no service"
      else
        echo "$roles" > /run/meister-role
        for r in $roles; do
          case "$r" in
            cloud|cluster) systemctl start --no-block "meister-$r-controller.service" || true ;;
            agent)         systemctl start --no-block "meister-agent.service" || true ;;
            # The six services of nix/addons.nix. They are in the image only
            # if it was BUILT with the role — their whole configuration is one
            # name, and that name has to be known before a certificate is
            # signed for it — so an image without them says so in a sentence
            # instead of starting six units that are present and wrong.
            addons)
              if systemctl cat kanidm.service >/dev/null 2>&1; then
                : > /run/meisterstack/addons.enabled
                for a in kanidm garage prometheus loki tempo grafana; do
                  systemctl start --no-block "$a.service" || true
                done
              else
                echo "MEISTER_ROLE names addons, but this image was built without them:"
                echo "  build one with meisterstack.roles = [ \"addons\" ] (nix build .#image-<node>)"
              fi ;;
            *) echo "unknown MEISTER_ROLE entry: $r";;
          esac
        done
      fi
    '';
  };
}

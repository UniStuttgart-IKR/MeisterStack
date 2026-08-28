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

      dev=/dev/disk/by-label/CONTEXT
      for i in $(seq 30); do [ -e "$dev" ] && break; sleep 1; done
      if [ ! -e "$dev" ]; then
        echo "no CONTEXT cd, leaving defaults"
        render_config cloud   < /dev/null
        render_config cluster < /dev/null
        echo "node_id = \"$(cat /proc/sys/kernel/hostname)\"" | render_config agent
        exit 0
      fi

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

      render_config cloud < /dev/null
      {
        [ -n "''${MEISTER_CLUSTER_NAME:-}" ] \
          && echo "cluster_name = \"''${MEISTER_CLUSTER_NAME}\""
        [ -n "''${MEISTER_CLOUD_ADDR:-}" ] \
          && echo "cloud_addr = \"''${MEISTER_CLOUD_ADDR}\""
        [ -n "''${MEISTER_CLOUD_ADDRS:-}" ] \
          && echo "cloud_addrs = $(toml_list "$MEISTER_CLOUD_ADDRS")"
        true
      } | render_config cluster
      {
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

      # cloud | cluster | agent | both — both = cloud + cluster (small labs)
      roles="''${MEISTER_ROLE:-}"
      [ "$roles" = both ] && roles="cloud cluster"
      if [ -z "$roles" ]; then
        echo "no MEISTER_ROLE in context; starting no service"
      else
        echo "$roles" > /run/meister-role
        for r in $roles; do
          case "$r" in
            cloud|cluster) systemctl start --no-block "meister-$r-controller.service" || true ;;
            agent)         systemctl start --no-block "meister-agent.service" || true ;;
            *) echo "unknown MEISTER_ROLE entry: $r";;
          esac
        done
      fi
    '';
  };
}

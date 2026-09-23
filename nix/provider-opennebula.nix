# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# OpenNebula, and nothing else in this repository knows that word.
#
# A VM the lab starts gets a CONTEXT cd: an iso with a `context.sh` on it,
# written by the front end out of the VM template. This module is the only
# code that mounts it, and it hands what it finds to the provider-neutral
# renderer (nix/context.nix) as `meisterstack.context.providerScript`.
#
# It is NOT part of `nixosModules.default`. A renderer that knows how to
# mount a CONTEXT cd is a renderer nobody else can use, and the whole reason
# for the split in M1 was that fifty-three lines of OpenNebula had taken five
# hundred lines of rendering hostage.
#
# Two readers, and the difference between them is the point:
#
#   strict (the default)  `context.sh` is DATA. One line at a time, matched
#                         against `KEY='value'`, checked against an allowlist
#                         of six keys, and every value validated before it is
#                         used. Nothing is sourced, nothing is eval'd, and no
#                         MEISTER_* variable comes off the medium at all: what
#                         this machine IS comes from its plan.
#   legacy                `. "$mnt/context.sh"` — the medium runs as root,
#                         before the network is up. It is what the twelve VMs
#                         of the context fleet boot through today, it is
#                         `meisterstack.appliance.legacyContext`, and it goes
#                         out with them (L3).
{ lib, config, ... }:
let
  cfg = config.meisterstack.provider.opennebula;

  # Does this host already own the interface the provider would configure?
  # `networking.interfaces.<if>.ipv4.addresses` is somebody saying "this
  # address is mine"; the provider writing another one on top is two owners
  # for one interface, which is the exact shape of the resolv.conf bug of
  # 2026-09-08 (nix/appliance.nix tells that story).
  staticAddresses =
    let ifs = config.networking.interfaces; in
    if ifs ? ${cfg.interface} then ifs.${cfg.interface}.ipv4.addresses else [ ];
  hostOwnsInterface = staticAddresses != [ ];

  # What the module tells the script, and the ONLY interpolation in either of
  # them. Both scripts below are plain shell with no Nix in them, which is
  # what lets scripts/check-context.sh cut them out of this file and run them
  # against a fixture — the test sets these four variables itself.
  preamble = ''
    meister_one_device=${lib.escapeShellArg cfg.device}
    meister_one_interface=${lib.escapeShellArg cfg.interface}
    meister_one_network=${if cfg.network then "1" else "0"}
    meister_one_wait=${toString cfg.waitSeconds}
  '';

  # --- the strict reader ---------------------------------------------------
  #
  # Cut out of this file and run by scripts/check-context.sh, section N. Keep
  # it free of Nix interpolation.
  strictScript = ''
    # --- OpenNebula CONTEXT, READ rather than sourced --------------------
    #
    # Waiting for a cd is for a machine that expects one. A plan node knows
    # its role already and would otherwise spend thirty seconds of every boot
    # discovering that OpenNebula is not there.
    if [ ! -e "$meister_one_device" ] && [ -z "''${MEISTER_ROLE:-}" ]; then
      waited=0
      while [ "$waited" -lt "$meister_one_wait" ]; do
        if [ -e "$meister_one_device" ]; then break; fi
        waited=$((waited + 1))
        sleep 1
      done
    fi

    if [ -e "$meister_one_device" ]; then
      one_mnt=/run/meister-context/provider
      mkdir -p "$one_mnt"
      mount -o ro "$meister_one_device" "$one_mnt"
      trap 'umount "$one_mnt"' EXIT

      one_ip=""; one_mask=""; one_gateway=""; one_dns=""
      one_hostname=""; one_sshkey=""
      # --- lane 5C: how many keys were skipped without a word (see below)
      one_quiet=0

      # dotted netmask -> prefix length
      one_mask2prefix() {
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

      one_is_ipv4() {
        printf '%s' "$1" | grep -qE "^([0-9]{1,3}\.){3}[0-9]{1,3}$" || return 1
        local octet
        for octet in ''${1//./ }; do
          [ "$octet" -le 255 ] || return 1
        done
        return 0
      }

      # --- the parse. One line, one key, no shell.
      #
      # The grammar is what OpenNebula writes and nothing wider: KEY='value'
      # on one line, single-quoted, no continuation. A line that does not
      # match is reported and dropped rather than guessed at — and because
      # the file is never sourced, a `$(reboot)` in a value is six characters
      # that go into a variable and stay there.
      if [ -f "$one_mnt/context.sh" ]; then
        while IFS= read -r one_line || [ -n "$one_line" ]; do
          [ -z "$one_line" ] && continue
          case "$one_line" in "#"*) continue ;; esac

          if ! printf '%s' "$one_line" | grep -qE "^[A-Z0-9_]+='[^']*'$"; then
            echo "context: ignored, not KEY='value': $(printf '%s' "$one_line" | cut -c1-32)"
            continue
          fi

          one_key=''${one_line%%=*}
          one_value=''${one_line#*=}
          one_value=''${one_value#\'}
          one_value=''${one_value%\'}

          case "$one_key" in
            # What this machine IS comes from its plan, never from the
            # medium. A context that could set MEISTER_ROLE is a context that
            # can turn an agent into a cloud, and the medium is handed to the
            # VM by whoever asked for the VM.
            MEISTER_*)
              echo "context: ignored, $one_key belongs to the plan and not to the medium"
              continue ;;
            ETH0_IP)        one_ip=$one_value ;;
            ETH0_MASK)      one_mask=$one_value ;;
            ETH0_GATEWAY)   one_gateway=$one_value ;;
            ETH0_DNS)       one_dns=$one_value ;;
            SET_HOSTNAME)   one_hostname=$one_value ;;
            SSH_PUBLIC_KEY) one_sshkey=$one_value ;;
            # --- lane 5C: the block this reader already understands ------
            #
            # OpenNebula writes a whole interface block — ETH0_MAC,
            # ETH0_NETWORK, ETH0_ALIAS0_*, ETH0_SEARCH_DOMAIN, ETH0_MTU and
            # a dozen more — plus NETWORK, TARGET and DISK_ID, which are
            # about the medium and not about this machine. None of them is
            # a surprise, and naming each one made twenty-one lines on
            # every boot (L2 §10, finding 9). They are counted and named
            # ONCE, after the loop; what stays loud is what is genuinely
            # unexpected, such as an ONEAPP_* key somebody added to the
            # template.
            ETH[0-9]*_*|NETWORK|TARGET|DISK_ID)
              one_quiet=$((one_quiet + 1))
              continue ;;
            # --- end lane 5C ---
            *)
              echo "context: ignored, $one_key is not one of the six keys this provider reads"
              continue ;;
          esac
        done < "$one_mnt/context.sh"
        # --- lane 5C ---
        if [ "$one_quiet" -gt 0 ]; then
          echo "context: $one_quiet key(s) of the medium's own interface and disk block were skipped"
        fi
        # --- end lane 5C ---
      else
        echo "context: $meister_one_device carries no context.sh"
      fi

      # --- and only now, the use. Every value is checked first: each of them
      # ends up in a command line or in a file, and "the medium said so" is
      # not a reason to run it.
      if [ "$meister_one_network" = 1 ] && [ -n "$one_ip" ]; then
        if ! one_is_ipv4 "$one_ip"; then
          echo "context: ETH0_IP is not an IPv4 address; the interface is left alone"
        else
          one_mask=''${one_mask:-255.255.255.0}
          if ! one_is_ipv4 "$one_mask"; then
            echo "context: ETH0_MASK is not a netmask; falling back to 255.255.255.0"
            one_mask=255.255.255.0
          fi
          one_prefix=$(one_mask2prefix "$one_mask")
          ip addr replace "$one_ip/$one_prefix" dev "$meister_one_interface"
          ip link set "$meister_one_interface" up
          echo "context: $meister_one_interface is $one_ip/$one_prefix"
          if [ -n "$one_gateway" ]; then
            if one_is_ipv4 "$one_gateway"; then
              ip route replace default via "$one_gateway"
            else
              echo "context: ETH0_GATEWAY is not an IPv4 address; no default route"
            fi
          fi
          if [ -n "$one_dns" ]; then
            one_resolv=""
            for one_ns in $one_dns; do
              if one_is_ipv4 "$one_ns"; then
                one_resolv="$one_resolv$one_ns "
              else
                echo "context: ETH0_DNS entry $one_ns is not an IPv4 address; skipped"
              fi
            done
            if [ -n "$one_resolv" ]; then
              : > /etc/resolv.conf
              for one_ns in $one_resolv; do
                echo "nameserver $one_ns" >> /etc/resolv.conf
              done
            fi
          fi
        fi
      elif [ -n "$one_ip" ]; then
        echo "context: ETH0_IP is on the medium, but this host owns $meister_one_interface; ignored"
      fi

      # A DNS label and no more: this string is written into
      # /proc/sys/kernel/hostname and then appears in the node id of every
      # config file this renderer writes.
      if [ -n "$one_hostname" ]; then
        if printf '%s' "$one_hostname" | grep -qE "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"; then
          # daemon-free: hostnamed is not up this early in boot
          echo "$one_hostname" > /proc/sys/kernel/hostname
        else
          echo "context: SET_HOSTNAME is not a DNS label; the hostname is left alone"
        fi
      fi

      # An authorized_keys line, checked for its shape rather than trusted
      # for its name: `command=` and the other options would be a medium
      # deciding what a login does, and they are not on the allowlist.
      if [ -n "$one_sshkey" ]; then
        # The comment field may contain spaces, because ssh-keygen -C takes
        # a sentence and OpenSSH reads everything after the base64 as one
        # comment. `( [^ ]*)?$` refused such a line, and the refusal is
        # invisible where it matters: it goes to the serial console of a VM
        # that then has no key on it, which in a lab with no console is the
        # same as a machine that is gone. Measured 2026-09-23 (lane L4): four
        # fresh VMs, `Permission denied (publickey)`, and the only way back
        # was a new key and a new context. What the allowlist is ACTUALLY
        # about is the options field in FRONT of the type, which is where
        # `command=` would be — and that is still refused, because the line
        # has to START with a key type.
        if printf '%s' "$one_sshkey" | grep -qE "^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+=*( .*)?$"; then
          mkdir -p /root/.ssh
          chmod 700 /root/.ssh
          if ! grep -qxF "$one_sshkey" /root/.ssh/authorized_keys 2>/dev/null; then
            echo "$one_sshkey" >> /root/.ssh/authorized_keys
          fi
          chmod 600 /root/.ssh/authorized_keys
        else
          echo "context: SSH_PUBLIC_KEY is not a key line this provider accepts; ignored"
        fi
      fi
    else
      # Not an error and not a fallback: this is what a plan node looks like.
      # Its address, its hostname and its ssh key are NixOS' business, and
      # its MEISTER_* variables were sourced from the plan above.
      echo "no CONTEXT medium; the baked defaults are this machine's whole context"
    fi
  '';

  # --- the legacy reader ---------------------------------------------------
  #
  # Verbatim what nix/one-context.nix:130-185 did, comments and all, and it
  # stays verbatim: it is the code twelve running VMs boot through, and the
  # plan for it is removal (L3) rather than improvement. The one change is
  # its name.
  legacyScript = ''
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
  '';
in
{
  options.meisterstack.provider.opennebula = {
    mode = lib.mkOption {
      type = lib.types.enum [ "strict" "legacy" ];
      default = "strict";
      description = ''
        Which reader gets the medium.

        `strict` parses `context.sh` with a `KEY='value'` grammar and an
        allowlist of six keys (ETH0_IP, ETH0_MASK, ETH0_GATEWAY, ETH0_DNS,
        SET_HOSTNAME, SSH_PUBLIC_KEY), validates every value before it is
        used, and takes NO MEISTER_* variable off the medium: what this
        machine is comes from its plan. Anything else on the medium is named
        in the journal and dropped.

        `legacy` sources the file as root. It exists because the twelve VMs
        of the context fleet boot through it today; `nix/appliance.nix` is
        what turns it on, and both leave together (L3).
      '';
    };

    device = lib.mkOption {
      type = lib.types.str;
      default = "/dev/disk/by-label/CONTEXT";
      description = ''
        The medium. OpenNebula labels its context iso CONTEXT, and the label
        is what makes it findable whatever bus it lands on — which slot a
        disk gets is not a promise anybody made.

        Read by the strict reader only. The legacy one has the path in it,
        because it is frozen.
      '';
    };

    interface = lib.mkOption {
      type = lib.types.str;
      default = "eth0";
      description = ''
        The interface the context's ETH0_* values configure — `eth0`, because
        the appliance turns predictable interface names off and the context
        speaks of ETH0.

        Read by the strict reader only.
      '';
    };

    network = lib.mkOption {
      type = lib.types.bool;
      # The module answers its own question. `hostOwnsInterface` is the
      # reading of what this host already SAYS: a host that names a static
      # address for the interface owns it, and one that names none (the
      # generic managed image, and every VM at its first boot) lets the
      # medium own it. With a flat `true` default, every managed host on a
      # provider that also names its address in the inventory stopped at
      # `resolve` with the assertion below and had to be told, by hand, per
      # host, what the option's own description already says. Measured in
      # the lab on 2026-09-23 (lane L4, finding W1): three controllers with
      # static addresses, one sentence each, and an operator repository that
      # had to carry a module to set a default nobody disagrees with.
      default = !hostOwnsInterface;
      defaultText = lib.literalMD
        "false if this host names a static address for the interface, true otherwise";
      description = ''
        Whether the provider configures that interface at all.

        ONE owner per interface. If this host names a static address for it
        (`networking.interfaces.<if>.ipv4.addresses`), the provider must not
        write a second one on top: two owners for one file is how the fleet
        lost every name it could resolve on 2026-09-08 (nix/appliance.nix
        tells that story), and an address is the same kind of thing. The
        assertion below refuses that combination in `strict` mode and warns
        about it in `legacy`, where it is today's behaviour and a rollout is
        not the place to change two things at once.

        Turning it off keeps the rest: hostname and ssh key still come from
        the medium, because those are not the interface.
      '';
    };

    waitSeconds = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 30;
      description = ''
        How long to wait for the medium to appear, and only on a machine that
        expects one: a host whose MEISTER_ROLE is already baked does not wait
        at all, because it would be waiting for something that is not coming.

        Read by the strict reader only.
      '';
    };
  };

  config = {
    assertions = [
      {
        assertion = !(cfg.mode == "strict" && cfg.network && hostOwnsInterface);
        message =
          "meisterstack.provider.opennebula.network is on and networking.interfaces."
          + cfg.interface + ".ipv4.addresses is set: two owners for one interface. "
          + "Set meisterstack.provider.opennebula.network = false (the host keeps "
          + "the interface) or drop the static address (the context keeps it).";
      }
    ];

    warnings = lib.optional (cfg.mode == "legacy" && cfg.network && hostOwnsInterface)
      ("this host sets networking.interfaces.${cfg.interface}.ipv4.addresses AND lets "
        + "the legacy context write that interface; whichever runs last wins. The strict "
        + "reader refuses this combination instead of warning about it.");

    meisterstack.context.providerScript =
      if cfg.mode == "legacy" then legacyScript else preamble + strictScript;
  };
}

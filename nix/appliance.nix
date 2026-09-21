# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The appliance: the image the context fleet boots, and every host-global
# decision that image makes.
#
# This file was `nix/base.nix` until M1 and is the same set of decisions: ssh
# in, serial console out, a writable /opt/meisterstack for push.sh, no
# firewall, no dhcp, no resolvconf, nix off, `stateVersion` fixed. RAM-frugal
# on purpose — the lab hosts are RAM-bound.
#
# What changed is where those decisions may live. `nix/services.nix` is what
# a foreign host imports and decides NONE of them; this file is a PROFILE and
# is allowed to, because an appliance image is a whole machine rather than a
# module in somebody else's.
#
# Two properties make it an appliance rather than a plan node:
#
#   * it does not know at build time what it will be. `meisterstack.roles` is
#     empty in the generic image and the context decides at boot, so every
#     unit has to ship — `meisterstack.unitsFor` below is what says so, and it
#     is the one place where the role gates of nix/services.nix are opened all
#     at once.
#   * its config files are rendered at BOOT (nix/context.nix), out of a
#     context its provider hands it (nix/provider-opennebula.nix). The managed
#     profile is the other answer to the same question; the two are mutually
#     exclusive and nix/managed.nix says so with an assertion.
#
# The road out is L3 of the deploy-v1 plan: when the twelve context VMs are
# migrated, this file and the two modules it imports leave with them.
{ lib, config, ... }:
let
  cfg = config.meisterstack.appliance;
in
{
  imports = [
    ./services.nix
    ./context.nix
    # The provider, and yes this is a hard import: this profile exists for the
    # OpenNebula fleet, `legacyContext` below means nothing without it, and
    # the two are removed in the same step. A host that wants the strict
    # provider WITHOUT the appliance imports
    # `nixosModules.provider-opennebula` on its own.
    ./provider-opennebula.nix
  ];

  options.meisterstack.appliance = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether this machine is the appliance image.

        Importing this module is normally the decision, so the default is
        true; the option exists for a configuration that imports the profile
        and then turns it off — and for `nix/managed.nix`, which asserts that
        the two profiles are not on the same machine.
      '';
    };

    legacyContext = lib.mkOption {
      type = lib.types.bool;
      default = cfg.enable;
      description = ''
        Whether the provider's context is SOURCED as a shell script, the way
        it has been since the first lab VM.

        `. "$mnt/context.sh"` runs whatever is on the medium, as root, before
        the network is up. That is a privileged entrance, and the only reason
        it is still here is that the twelve VMs of the context fleet boot
        through it today and a rollout is not the place to change two things
        at once. Everything it is used for it did in the lab: set MEISTER_ROLE,
        write a hostname, add an ssh key — and everything else it COULD do is
        why `nix/provider-opennebula.nix` has a second reader that parses
        instead of sourcing (`mode = "strict"`).

        The way out is documented rather than implied: a managed host never
        turns this on, a migrated VM is a managed host, and when the last one
        has moved, this option and the code behind it go out together (L3).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Every unit, on every appliance, whatever the roles say.
    #
    # This is the trap the role gates in nix/services.nix would otherwise
    # spring: the generic image has `meisterstack.roles = [ ]` — it is built
    # before anybody knows what it will be — so gating its units on the role
    # list would leave it with none at all. The image's contract is the
    # opposite: every unit ships, `ConditionPathExists` keeps the ones without
    # binaries visibly skipped, and MEISTER_ROLE starts the right ones at boot.
    #
    # `roles` keeps meaning what it meant: what this machine IS, and what goes
    # into a plan node's baked MEISTER_ROLE. `unitsFor` is only about which
    # units exist. addons is not in the list and cannot be: that role is build
    # time by construction (nix/addons.nix), and the image says so in a
    # sentence when a context asks for it anyway.
    meisterstack.unitsFor = [ "cloud" "cluster" "agent" ];

    # Which reader the provider uses, and the appliance is the one profile
    # that still takes the old one. mkDefault, so that an appliance which
    # wants the strict parser can say so in one line.
    meisterstack.provider.opennebula.mode =
      lib.mkDefault (if cfg.legacyContext then "legacy" else "strict");

    networking.useDHCP = false;
    networking.usePredictableInterfaceNames = false; # context addresses eth0
    networking.firewall.enable = false;              # test rig, lab-internal

    # The context renderer owns this VM's whole network configuration —
    # address, route, hostname AND resolver — because all four come out of the
    # same CONTEXT. resolvconf owns /etc/resolv.conf, and with useDHCP off and
    # no networking.nameservers it writes a file with no nameserver in it at
    # all, AFTER the renderer wrote the real one. The result on the fleet was
    # `options edns0` and nothing else: no name resolved anywhere, while
    # ETH0_DNS sat in the context and the server answered on tcp/53.
    #
    # Two owners for one file, and the wrong one won. Found 2026-09-08, by an
    # agent that could not fetch an `image create --from-url` — the road that
    # the missing `curl` had hidden until now.
    networking.resolvconf.enable = false;

    services.openssh = {
      enable = true;
      settings.PermitRootLogin = "prohibit-password";
    };

    # Serial console so `onevm console` works.
    boot.kernelParams = [ "console=ttyS0,115200" "console=tty0" ];

    # push.sh drops the controller binaries and the certificates here; the
    # placeholder dirs exist so the units' ConditionPathExists reads cleanly
    # before the first deploy. Both are OUTSIDE the nix store on purpose — they
    # survive an image swap, and a private key must never travel in a qcow2.
    #
    # pki is 0755 and holds files that are not: ca.crt and the certificates are
    # public by construction, and the secrecy sits on the key files themselves
    # (0600 and owned by the service user, see deploy/push.sh pki).
    #
    # The two paths are `meisterstack.binDir` and `meisterstack.pki.dir`
    # rather than two more literals: the units read those options, and a
    # directory created somewhere else is a directory nobody looks in.
    systemd.tmpfiles.rules = [
      "d ${config.meisterstack.binDir} 0755 root root -"
      "d ${config.meisterstack.pki.dir} 0755 root root -"
    ];

    documentation.enable = false;
    nix.enable = false; # image is built, never rebuilt from inside

    system.stateVersion = "25.11";
  };
}

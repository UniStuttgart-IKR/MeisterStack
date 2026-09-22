# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Two renderers, one input, one answer.
#
# nix/context.nix completes the config files while the machine boots;
# nix/lib/render.nix does the same at build time for a managed host. This
# check takes hosts of a fleet, runs the boot renderer's own script text
# against each host's context.env, and compares the result with the file Nix
# wrote — as parsed TOML and not as text, because whitespace and key order are
# not the question.
#
# The script comes out of the BUILT unit rather than out of the source file,
# so what runs here is what would run on the machine, provider block and all.
# Every absolute path it touches is redirected into $TMPDIR the way
# scripts/check-context.sh does it, and mount/umount/systemctl/ip are stubs:
# there is no medium in a sandbox, which is exactly the shape a planned host
# boots in.
#
# Lane 1A wrote this check against the schema-1 plan. 1B moved it into its own
# file and onto the schema-2 inventory: the appliance twin is built HERE (a
# fleet host is `managed` now, so there is no appliance nixosConfiguration to
# borrow) and the host list is an argument, so that a fleet with a raft group
# of THREE can be checked too — on a one-box fleet the etcd variables are
# empty and this check never sees them (1A §8, open point 6).
{ nixpkgs, lib, pkgs, system, self, disko, inv, hostIds, profiles ? { } }:
let
  profileOf = name: profiles.${name} or { };

  # disko's module, with its CONFIG off.
  #
  # A host module of an operator binds the disk its layout shapes
  # (`disko.devices.disk.main.device` in hw/<id>.nix), so the option has to
  # exist wherever a host module is evaluated — and this check evaluates two
  # twins of a host that lib.mkFleet did not build. What must NOT happen here
  # is disko deriving `fileSystems`: both twins below state their own root,
  # the question this check asks is about the RENDERER, and a partition table
  # would only be a second author for a mount nobody boots.
  diskoDeclaredOnly = [
    disko.nixosModules.disko
    { disko.enableConfig = false; }
  ];

  # The same host as an APPLIANCE: the boot renderer, the provider block and
  # base.nix' host-global set. The profiles are left OUT here — they are the
  # operator's answers about a managed machine, and the appliance profile has
  # its own — so what the two sides share is exactly the inventory.
  applianceFor = id: (nixpkgs.lib.nixosSystem {
    modules = diskoDeclaredOnly ++ [
      { nixpkgs.hostPlatform = system; nixpkgs.overlays = [ self.overlays.default ]; }
      self.nixosModules.appliance
      (inv.hostModule id)
      {
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.systemd-boot.enable = lib.mkForce false;
        boot.loader.grub.device = "nodev";
      }
    ] ++ inv.hosts.${id}.modulePaths;
  }).config;
in

  let
    # The managed twin of a planned node. `pki.dir` is pinned to the
    # appliance's value because the question here is what the
    # RENDERER produces, not where a managed host keeps its keys —
    # that difference is a decision of nix/managed.nix and would
    # otherwise be reported as a mismatch of `controller_ca`.
    managedFor = id: (nixpkgs.lib.nixosSystem {
      modules = diskoDeclaredOnly ++ [
        { nixpkgs.hostPlatform = system; nixpkgs.overlays = [ self.overlays.default ]; }
        self.nixosModules.services
        self.nixosModules.managed
        {
          meisterstack.managed.enable = true;
          meisterstack.managed.trustedPublicKeys = [ "render-parity:not-a-real-key" ];
          meisterstack.pki.dir = "/opt/meisterstack/pki";
          # And `binDir` for the same reason (1B): a managed host takes its
          # binaries out of the store and an appliance out of the push
          # directory, so the agent's `hypervisor.cloud-hypervisor.binary`
          # differs between the two — by design, and held by
          # `checks.managed-uses-the-package`. Pinning it here keeps this
          # check about the RENDERER instead of reporting that difference
          # once per agent host.
          meisterstack.binDir = "/opt/meisterstack/bin";
        }
        (inv.hostModule id)
      ]
      ++ map profileOf inv.hosts.${id}.profiles
      ++ inv.hosts.${id}.modulePaths;
    }).config;

    parity = id:
      let
        appliance = applianceFor id;
        managed = managedFor id;
        roles = managed.meisterstack.unitsFor;
        etcOf = c: name: c.environment.etc."meisterstack/${name}.toml".source;
      in
      ''
        echo "== ${id}: ${lib.concatStringsSep "," roles}"
        root=$TMPDIR/${id}
        mkdir -p $root/etc/meisterstack $root/run $root/bin $root/root
        for stub in mount umount systemctl ip; do
          printf '#!/bin/sh\nexit 0\n' > $root/bin/$stub
          chmod +x $root/bin/$stub
        done
        install -m0644 ${appliance.environment.etc."meisterstack/context.env".source} \
          $root/etc/meisterstack/context.env
        ${lib.concatMapStrings (name: ''
          install -m0644 ${etcOf appliance name} $root/etc/meisterstack/${name}.toml
        '') (map (r: if r == "agent" then "agent" else r) roles)}
        ${lib.optionalString (builtins.elem "cloud" roles) ''
          install -m0644 ${appliance.environment.etc."meisterstack/cloud-auth-mtls.toml".source} \
            $root/etc/meisterstack/cloud-auth-mtls.toml
          install -m0644 ${appliance.environment.etc."meisterstack/cloud-auth-oidc.toml".source} \
            $root/etc/meisterstack/cloud-auth-oidc.toml
        ''}
        echo "${id}" > $root/hostname
        : > $root/static-hosts

        cat ${pkgs.writeText "meister-context-${id}.sh"
          appliance.systemd.services.meister-context.script} > $root/render.sh
        sed -i \
          -e "s#/etc/meisterstack#$root/etc/meisterstack#g" \
          -e "s#/run/meisterstack#$root/run/meisterstack#g" \
          -e "s#/run/meister-context#$root/run/meister-context#g" \
          -e "s#/run/one-context#$root/run/one-context#g" \
          -e "s#/run/meister-role#$root/run/meister-role#g" \
          -e "s#/dev/disk/by-label/CONTEXT#$root/no-such-medium#g" \
          -e "s#/proc/sys/kernel/hostname#$root/hostname#g" \
          -e "s#/etc/resolv.conf#$root/resolv.conf#g" \
          -e "s#/etc/static/hosts#$root/static-hosts#g" \
          -e "s#/etc/hosts#$root/hosts#g" \
          -e "s#/root/.ssh#$root/root/.ssh#g" \
          $root/render.sh
        PATH="$root/bin:$PATH" ${pkgs.bash}/bin/bash $root/render.sh > $root/render.log 2>&1 \
          || { echo "the renderer exited non-zero:"; cat $root/render.log; exit 1; }

        ${lib.concatMapStrings (name: ''
          python3 ${compare} ${id} ${name} \
            $root/run/meisterstack/${name}.toml ${etcOf managed name}
        '') roles}
        ${lib.optionalString (managed.meisterstack.etcd.peers != { }) ''
          python3 ${compareEtcd} ${id} $root/run/meisterstack/etcd.env ${etcdExpected id}
        ''}
      '';

    # The etcd half, which the TOMLs do not carry: the boot renderer writes
    # ETCD_* into an env file the unit reads, and a managed host sets
    # `services.etcd.*` instead. Lane 1A could not compare them because the
    # one-box fleet has a raft group of ONE and the variables are empty
    # there (1A §8, point 6); with examples/fleet/ha.toml they are not.
    etcdExpected = id:
      let etcd = (managedFor id).services.etcd; in
      pkgs.writeText "etcd-expected-${id}.json" (builtins.toJSON {
        ETCD_NAME = etcd.name;
        ETCD_INITIAL_CLUSTER = lib.concatStringsSep "," etcd.initialCluster;
        ETCD_INITIAL_CLUSTER_STATE = etcd.initialClusterState;
        ETCD_INITIAL_CLUSTER_TOKEN = etcd.initialClusterToken;
        ETCD_LISTEN_PEER_URLS = lib.concatStringsSep "," etcd.listenPeerUrls;
        ETCD_INITIAL_ADVERTISE_PEER_URLS =
          lib.concatStringsSep "," etcd.initialAdvertisePeerUrls;
      });

    compareEtcd = pkgs.writeText "render-parity-etcd.py" ''
      import json, sys

      node, booted, built = sys.argv[1:4]
      env = {}
      with open(booted) as fh:
          for line in fh:
              line = line.strip()
              if not line or line.startswith("#") or "=" not in line:
                  continue
              key, value = line.split("=", 1)
              env[key] = value
      with open(built) as fh:
          want = json.load(fh)

      bad = []
      for key in sorted(want):
          if env.get(key, "<absent>") != want[key]:
              bad.append("  %s: renderer %r, nix %r"
                         % (key, env.get(key, "<absent>"), want[key]))
      if bad:
          print("%s/etcd.env differs between the two renderers:" % node)
          print("\n".join(bad))
          sys.exit(1)
      print("  ok   %s/etcd.env is the same membership both ways (%d keys)"
            % (node, len(want)))
    '';

    compare = pkgs.writeText "render-parity.py" ''
      import sys, tomllib

      node, role, booted, built = sys.argv[1:5]
      with open(booted, "rb") as fh:
          a = tomllib.load(fh)
      with open(built, "rb") as fh:
          b = tomllib.load(fh)


      def flat(d, prefix=""):
          out = {}
          for k, v in d.items():
              key = prefix + k
              if isinstance(v, dict):
                  out.update(flat(v, key + "."))
              else:
                  out[key] = v
          return out


      fa, fb = flat(a), flat(b)
      bad = []
      for key in sorted(set(fa) | set(fb)):
          if fa.get(key, "<absent>") != fb.get(key, "<absent>"):
              bad.append("  %s: renderer %r, nix %r"
                         % (key, fa.get(key, "<absent>"), fb.get(key, "<absent>")))
      if bad:
          print("%s/%s.toml differs between the two renderers:" % (node, role))
          print("\n".join(bad))
          sys.exit(1)
      print("  ok   %s/%s.toml is the same file both ways (%d keys)" % (node, role, len(fa)))
    '';
  in
  pkgs.runCommand "render-parity"
    { nativeBuildInputs = [ pkgs.python3 ]; }
    (lib.concatMapStrings parity hostIds + "touch $out\n")

# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# `meisterDeployment` — what `meister-deploy resolve` reads.
#
# The contract is `tools/meister-deploy/src/manifest.rs`
# (`meister-deploy/nix-manifest/1`), and it is a contract rather than a
# suggestion: EVERY field is required, the empty ones are `null` or `[ ]`
# rather than absent, and every struct is `deny_unknown_fields`. So a key that
# is forgotten here is an error on the Rust side and not a value quietly
# dropped on the way to a receipt — `meister-deploy schema nix-manifest`
# prints the machine-readable shape, and `checks.manifest-json` pipes what
# this file produces into `meister-deploy validate --manifest -`.
#
# Two halves, and the split is about COST: `inventory` is a pure function of
# `fleet.toml` (nix/lib/inventory.nix, no module evaluation), while `hosts`
# forces the real `nixosConfigurations.<id>.config` of each host — which is
# also what makes a host's assertions fire at `resolve` time rather than at
# somebody's first `nix build`. `resolve --hosts a,b` narrows the expensive
# half; the cheap half is always whole.
{ lib }:

{ inventory
  # attrs: host id -> the evaluated `nixosConfigurations.<id>.config`
, configs
  # { meisterstack, cloudHypervisor, guestTiny, leandro, srcRev, patchDir }
, packages
  # attrs: host id -> { installerDrv, diskImageDrv }, both nullable
, images ? { }
}:

let
  inherit (inventory) hosts;

  directBoot = import ./direct-boot.nix { inherit lib; };

  # Only the hosts this flake builds a system for. A `context` host has no
  # closure to name, and nix/lib/inventory.nix leaves it out of the inventory
  # half for the same reason, so the two key sets stay equal — which
  # `manifest::resolve` requires.
  ids = inventory.nixosHostIds;

  # --- what a host runs -------------------------------------------------
  settingsOf = id: role:
    let
      cfg = configs.${id};
      present = builtins.elem role cfg.meisterstack.unitsFor;
    in
    if !present then null else cfg.meisterstack.${role}.effective;

  etcdOf = id:
    let cfg = configs.${id}; in
    if !cfg.meisterstack.etcd.enable then null else {
      name = cfg.services.etcd.name;
      # --- lane 4A ---
      # A STRING and not the list the NixOS option holds, because the
      # string is what etcd is given: the module writes
      # `ETCD_INITIAL_CLUSTER = concatStringsSep "," initialCluster`, and
      # the topology check of D8 compares the membership etcd REPORTS
      # against the membership this fleet CONFIGURED. Written as a list it
      # was a json array, the planner asked it for a string, got nothing,
      # and fell back to comparing member names — half the check, quietly,
      # on every real manifest. (The hand-written fixture had it as a
      # string all along, which is why no test saw it.)
      initial_cluster = lib.concatStringsSep "," cfg.services.etcd.initialCluster;
      # --- end lane 4A ---
      initial_cluster_token = cfg.services.etcd.initialClusterToken;
      data_dir = cfg.services.etcd.dataDir;
    };

  # The collector is OFF on a managed host today: its configuration is not
  # TOML, the boot renderer writes it from MEISTER_LOKI_URL, and baking it is
  # work M1 did not do (lane 1A §8, point 2). `null` says that, where an
  # empty attrset would have claimed there was nothing to say.
  observabilityOf = id:
    let cfg = configs.${id}; in
    if !cfg.meisterstack.observability.enable then null else {
      loki_url = cfg.meisterstack.context.defaults.MEISTER_LOKI_URL or null;
    };

  bootOf = id:
    let
      cfg = configs.${id};
      mode = hosts.${id}.boot;
    in
    {
      kernel_out = "${cfg.system.build.kernel}/${cfg.system.boot.loader.kernelFile}";
      initrd_out = "${cfg.system.build.initialRamdisk}/${cfg.system.boot.loader.initrdFile}";
      # The command line changes without any store path changing — a new
      # `console=`, a new `nvme_core.io_timeout` — and a changed command line
      # is a reboot. So it is hashed rather than compared as a list.
      kernel_params_sha256 =
        builtins.hashString "sha256" (lib.concatStringsSep " " cfg.boot.kernelParams);
      kernel_version = cfg.boot.kernelPackages.kernel.version;
      # Who decides which of the three above this machine actually starts.
      # `uefi` means the machine does, out of its own boot menu, and a plan
      # can say "it will boot this" by reading the system profile. `direct`
      # means the PROVIDER does, from outside, and then the next boot is not
      # a fact about the guest at all — which is why the mode travels with
      # the boot block rather than sitting in the inventory half only.
      inherit mode;
      # …and for a direct host, the exact string that provider is handed.
      # Null for a uefi host, because there is nothing outside it to hand
      # anything to.
      cmdline = if mode == "direct" then directBoot.cmdlineOf cfg else null;
    };

  buildOf = id:
    let
      cfg = configs.${id};
      img = images.${id} or { };
    in
    {
      # `.drvPath` and not a build: a manifest is produced by `nix eval`, and
      # forcing the derivation is also what makes this host's assertions fire
      # here — with the host's name in the message — rather than during
      # somebody's first `nix build`.
      toplevel_drv = cfg.system.build.toplevel.drvPath;
      # Still only a promise at manifest time; the RELEASE (M2) is what
      # records that the path exists and what its nar hash is.
      toplevel_out = cfg.system.build.toplevel.outPath;
      installer_drv = img.installerDrv or null;
      disk_image_drv = img.diskImageDrv or null;
      # The kernel, the initrd and the command line in one directory, for a
      # host whose hypervisor loads them. Null for a uefi host, which has no
      # such hypervisor.
      direct_boot_drv = img.directBootDrv or null;
      boot = bootOf id;
    };

  configArtifacts = id:
    let cfg = configs.${id}; in
    builtins.listToAttrs (map
      (role: lib.nameValuePair "${role}_toml_out"
        cfg.environment.etc."meisterstack/${role}.toml".source.outPath)
      cfg.meisterstack.unitsFor);

  # Every unit this host's system generation carries, by name.
  #
  # The NAMES and not the units: a name is a string that costs nothing to
  # produce (`systemd.units` is already forced by the toplevel beside it),
  # while the unit texts would put a megabyte of shell into a manifest that
  # is read, committed and diffed. What a plan does with them is say what an
  # operator's OWN modules brought onto a host: a unit this stack does not
  # name is a unit whose disruption nobody here can predict, which is the
  # `unknowns[]` of D-C (lane 4A). So the list has to be the whole list —
  # sorted, because `builtins.attrNames` is and a manifest that reordered
  # itself would change its own id for nothing.
  unitNames = id: builtins.attrNames configs.${id}.systemd.units;

  # --- the key material a host needs ------------------------------------
  #
  # Derived from the files the rendered configuration NAMES, not from a list
  # kept beside it: every path under `meisterstack.pki.dir` that appears in a
  # role's own config is something that role opens, so a key that is added to
  # a template shows up here without anybody remembering to.
  #
  # One entry per file AND per unit that reads it. `SecretRef.reload` is one
  # unit (the contract), a file on a four-role box is read by three, and the
  # delivery is keyed by `target_path` — so `keys deliver` (M3B) writes each
  # path once and pokes each unit named. The alternative would have been to
  # name one unit and leave the others stale.
  unitOf = role: if role == "agent" then "meister-agent.service"
  else "meister-${role}-controller.service";

  # `[operator] ca_dir` is a REFERENCE into the operator's own repository, and
  # never a secret: what lives there is the CA this fleet trusts.
  caDir = (inventory.operator or { }).ca_dir or "pki";

  secretKinds = {
    "ca.crt" = { kind = "ca_bundle"; source = "operator-file"; ref = "${caDir}/ca.crt"; owner = "root"; mode = "0644"; };
    "identity.key" = { kind = "identity_key"; source = "target-generated"; ref = "node"; owner = "meister"; mode = "0600"; };
    "identity.crt" = { kind = "identity_key"; source = "meister-ca"; ref = "node"; owner = "meister"; mode = "0644"; };
    "serving.key" = { kind = "serving_key"; source = "target-generated"; ref = "serving"; owner = "meister"; mode = "0600"; };
    "serving.crt" = { kind = "serving_key"; source = "meister-ca"; ref = "serving"; owner = "meister"; mode = "0644"; };
    "secrets.key" = { kind = "secrets_key"; source = "operator-file"; ref = "${caDir}/secrets.key"; owner = "meister"; mode = "0600"; };
    "crl.pem" = { kind = "crl"; source = "meister-ca"; ref = "crl"; owner = "root"; mode = "0644"; };
  };

  leaves = v:
    if builtins.isAttrs v then lib.concatMap leaves (lib.attrValues v)
    else if builtins.isList v then lib.concatMap leaves v
    else if builtins.isString v then [ v ]
    else [ ];

  secretRefs = id:
    let
      cfg = configs.${id};
      h = hosts.${id};
      dir = cfg.meisterstack.pki.dir;
      base = p: lib.last (lib.splitString "/" p);
      forRole = role:
        let
          settings = settingsOf id role;
          named = lib.unique (lib.filter (s: lib.hasPrefix "${dir}/" s)
            (leaves (if settings == null then { } else settings)));
        in
        map
          (path:
            let
              file = base path;
              spec = secretKinds.${file} or (throw
                ("host ${id}: ${role}.toml names ${path} under meisterstack.pki.dir, and "
                  + "nix/lib/manifest.nix has no secret kind for ${file}. Give it one — a "
                  + "file this stack opens is a file `keys deliver` has to know about."));
            in
            {
              # The id is what a receipt refers to, so it names the file AND
              # the unit: one file read by three units is three things to
              # poke and one thing to write.
              id = "${lib.replaceStrings [ "." ] [ "-" ] file}-${role}";
              inherit (spec) kind owner mode;
              source = {
                kind = spec.source;
                ref =
                  if spec.ref == "node" then "system:node:${h.id}"
                  else if spec.ref == "serving" then "${h.name}:${h.address}"
                  else spec.ref;
              };
              target_path = path;
              # Always a file, never a systemd credential: `LoadCredential`
              # hands the unit a `root:root 0440` file with an ACL, and all
              # three of this project's key loaders refuse a mode with group
              # bits in it (measured in a VM, M0 probe S11).
              delivery = "file";
              reload = { unit = unitOf role; action = "restart"; };
            })
          named;
    in
    lib.concatMap forRole cfg.meisterstack.unitsFor;

  manifestHost = id: {
    effective_settings = {
      agent = settingsOf id "agent";
      cloud = settingsOf id "cloud";
      cluster = settingsOf id "cluster";
      etcd = etcdOf id;
      observability = observabilityOf id;
    };
    build = buildOf id;
    config_artifacts = configArtifacts id;
    units = unitNames id;
    secret_refs = secretRefs id;
    persistence = map
      (p: {
        inherit (p) path;
        device_ref = p.device;
        required = p.required or true;
        preserve_on_reinstall = p.preserve_on_reinstall or true;
      })
      hosts.${id}.persistence;
    checks = hosts.${id}.checks;
    rollout = {
      canary_class = hosts.${id}.rollout.canary;
      max_unavailable = hosts.${id}.rollout.max_unavailable;
      reboot = hosts.${id}.rollout.reboot;
    };
  };

  # --- the packages this fleet is built from ----------------------------
  patchFiles = lib.sort lib.lessThan
    (lib.filter (p: lib.hasSuffix ".patch" (toString p))
      (lib.filesystem.listFilesRecursive packages.patchDir));
in
{
  schema = "meister-deploy/nix-manifest/1";

  inventory = inventory.manifestInventory;

  hosts = builtins.listToAttrs (map (id: lib.nameValuePair id (manifestHost id)) ids);

  packages = {
    meisterstack = {
      drv = packages.meisterstack.drvPath;
      version = packages.meisterstack.version;
      src_rev = packages.srcRev;
    };
    cloud_hypervisor = {
      drv = packages.cloudHypervisor.drvPath;
      version = packages.cloudHypervisor.version;
      # One digest per patch, in the order they are applied: a reordered
      # series is a different hypervisor, and the series has grown twice.
      patches_sha256 = map (p: builtins.hashFile "sha256" p) patchFiles;
    };
    # Null for a fleet that declares no `leandro` input. A CPU-only fleet
    # builds without it, which is what keeps this flake buildable in a
    # sandbox without anybody's home directory (L01/V04).
    leandro =
      if packages.leandro == null then null
      else { drv = packages.leandro.drvPath; version = packages.leandro.version; };
    guest_tiny = {
      drv = packages.guestTiny.drvPath;
      version = packages.guestTiny.version;
    };
  };
}

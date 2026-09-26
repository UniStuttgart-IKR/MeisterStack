# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Build meisterDeployment from inventory and evaluated NixOS configurations.
# The inventory half is inexpensive; host details force system assertions and
# derivation paths. manifest-json checks the emitted JSON against the tool schema.
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

  # Context hosts have no system closure and are excluded from both manifest halves.
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
      # Record etcd's comma-separated membership string for topology comparisons.
      initial_cluster = lib.concatStringsSep "," cfg.services.etcd.initialCluster;

      initial_cluster_token = cfg.services.etcd.initialClusterToken;
      data_dir = cfg.services.etcd.dataDir;
    };

  # No managed Alloy configuration is emitted here; represent its absence as null.
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
      # Hash kernel parameters because changing them can require a reboot even
      # when the kernel and initrd store paths are unchanged.
      kernel_params_sha256 =
        builtins.hashString "sha256" (lib.concatStringsSep " " cfg.boot.kernelParams);
      kernel_version = cfg.boot.kernelPackages.kernel.version;
      # Record who owns the next boot: the host loader or an external provider.
      inherit mode;
      # Direct-boot hosts also expose the command line passed to the provider.
      cmdline = if mode == "direct" then directBoot.cmdlineOf cfg else null;
    };

  buildOf = id:
    let
      cfg = configs.${id};
      img = images.${id} or { };
    in
    {
      # Derivation evaluation forces host assertions without building the system.
      toplevel_drv = cfg.system.build.toplevel.drvPath;
      # The manifest names outputs; release construction records their realized hashes.
      toplevel_out = cfg.system.build.toplevel.outPath;
      installer_drv = img.installerDrv or null;
      disk_image_drv = img.diskImageDrv or null;
      # Expose a provider bundle only for direct-boot hosts.
      direct_boot_drv = img.directBootDrv or null;
      boot = bootOf id;
    };

  configArtifacts = id:
    let cfg = configs.${id}; in
    builtins.listToAttrs (map
      (role: lib.nameValuePair "${role}_toml_out"
        cfg.environment.etc."meisterstack/${role}.toml".source.outPath)
      cfg.meisterstack.unitsFor);

  # List all systemd unit names, including operator modules, in stable order.
  # Consumers use unfamiliar units to identify disruption they cannot classify.
  unitNames = id: builtins.attrNames configs.${id}.systemd.units;

  # Derive credential references from PKI paths in rendered role configurations.
  # Emit one reference per file and consuming unit so delivery can deduplicate
  # paths while reloading every reader.
  unitOf = role: if role == "agent" then "meister-agent.service"
  else "meister-${role}-controller.service";

  # Record the operator's CA directory reference without embedding its contents.
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
              # Identify both the file and the consuming unit.
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
              # Use ordinary files: the key loaders reject systemd credential modes
              # that include group permissions.
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
  # Identify the evaluated inventory by content.
  inventory_sha256 = inventory.sha256;

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
      # Hash patches in application order.
      patches_sha256 = map (p: builtins.hashFile "sha256" p) patchFiles;
    };
    # The optional GPU stack remains null for fleets without a leandro input.
    leandro =
      if packages.leandro == null then null
      else { drv = packages.leandro.drvPath; version = packages.leandro.version; };
    guest_tiny = {
      drv = packages.guestTiny.drvPath;
      version = packages.guestTiny.version;
    };
  };
}

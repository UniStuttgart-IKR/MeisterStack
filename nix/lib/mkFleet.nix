# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Compose a fleet from schema-2 inventory, public service and managed modules,
# and operator profiles. Return host configurations, images, checks, and
# meisterDeployment. inventory.nix owns address and topology derivation.
{ nixpkgs
, meisterstack
  # Import disko for hosts with install layouts. Fleets without install tables
  # may omit this input; layouts and filesystems then belong to host modules.
, disko ? null
  # Optional image generator for formats not using the native NixOS builder.
, nixos-generators ? null
  # Optional GPU stack; CPU fleets need no leandro input.
, leandro ? null
}:

{ inventory
  # Map profile names to NixOS modules. Inventory determines profile import order.
, profiles ? { }
  # Additional modules keyed by host ID. Inventory module paths are another
  # input and resolve relative to the inventory file.
, hostModules ? { }
  # Modules every host of this fleet gets.
, extraModules ? [ ]
, system ? "x86_64-linux"
  # Overlays on top of ours, for an operator who builds their own agent.
, pkgsOverlays ? [ ]
  # Select native system.build.images or the optional nixos-generators input
  # for each image format.
, images ? { }
}:

let
  lib = nixpkgs.lib;

  inv = (import ./inventory.nix { inherit lib; }).load inventory;

  directBoot = import ./direct-boot.nix { inherit lib; };

  pkgs = import nixpkgs {
    inherit system;
    overlays = [ (import ../overlay.nix) ] ++ pkgsOverlays;
  };

  imageSource = format: images.${format} or "native";

  # --- the modules a host of this fleet is ------------------------------
  profileFor = id: name:
    profiles.${name} or (throw
      ("host ${id} names the profile ${name}, and the profiles passed to mkFleet are "
        + (if profiles == { } then "none at all" else lib.concatStringsSep ", " (lib.attrNames profiles))
        + ". A profile is a module of yours: pass it in `profiles`."));

  extraFor = id:
    let m = hostModules.${id} or [ ]; in
    if builtins.isList m then m else [ m ];

  # Reuse one instantiated package set across the fleet.
  platform = { nixpkgs.pkgs = pkgs; };

  # The leandro input's vhost-user-nvrm and this stack's cloud-hypervisor negotiate a
  # shared-memory window only when both are built from the same patch series. Which Leandro
  # revision that is, patches/README.md says; a fleet pinned to another one is refused here
  # instead of booting GPU guests that never get a window.
  patchSeries = import ./leandro-series.nix { inherit lib; };
  leandroSeriesDrift =
    if leandro == null then [ ]
    else patchSeries.driftedPatches {
      leandroPatchDir = "${leandro}/patches";
      patchDir = ../../patches;
    };
  leandroSeries = {
    assertions = [{
      assertion = leandroSeriesDrift == [ ];
      message = "[leandro-series] the cloud-hypervisor patches of the leandro input differ "
        + "from MeisterStack's patches/ (${patchSeries.describeDrift leandroSeriesDrift}). "
        + "Pin leandro to the revision MeisterStack's patches/README.md names: the GPU "
        + "backend and the hypervisor negotiate a shared-memory window only on the same series.";
    }];
  };

  # Import the selected layout and disko only for hosts with an install table.
  layoutFor = id:
    let h = inv.hosts.${id}; in
    if h.install == null then [ ]
    else if disko == null then
      throw ("host ${id} has an install table (layout ${h.install.layout}) and mkFleet was "
        + "called without the `disko` input, so there is nothing to turn a partition table "
        + "into filesystems. Pass `disko` — an operator's flake does that with "
        + "`disko.follows = \"meisterstack/disko\"`.")
    else [
      disko.nixosModules.disko
      (inv.planDir + "/${h.install.layout}")
    ];

  modulesFor = id:
    [
      platform
      leandroSeries
      ../services.nix
      ../managed.nix
      {
        # Every nixos inventory host uses managed deployment.
        meisterstack.managed.enable = true;

        # Apply inherited cache configuration here, where managed options are available.
        # Host modules can override these defaults.
        meisterstack.managed.substituters = lib.mkDefault inv.hosts.${id}.substituters;
      }
      (inv.hostModule id)
      # Configure the installer in its image sub-evaluation, where isoImage options
      # exist. Use the module argument to avoid recursion through configs.
      ({ config, ... }: lib.mkIf (inv.hosts.${id}.install != null) {
        image.modules.iso-installer = import ../install.nix {
          inherit id;
          host = inv.hosts.${id};
          target = config;
          fleet = inv.fleet;
        };

        # Disable the host's disko layout inside a prebuilt disk image: the image
        # builder supplies its own partition table and filesystem definitions.
        image.modules.raw-efi = { ... }: { disko.enableConfig = false; };
        image.modules.qemu = { ... }: { disko.enableConfig = false; };
      })
      {
        # Hosts without install tables get no installer target. Resolve the SSH
        # root-login default shared by the image and managed profiles.
        image.modules.iso-installer = { lib, ... }: {
          services.openssh.settings.PermitRootLogin = lib.mkForce "prohibit-password";
        };
      }
    ]
    ++ layoutFor id
    ++ map (profileFor id) inv.hosts.${id}.profiles
    ++ inv.hosts.${id}.modulePaths
    ++ extraFor id
    ++ extraModules;

  nixosFor = id: nixpkgs.lib.nixosSystem { modules = modulesFor id; };

  ids = inv.nixosHostIds;
  systems = builtins.listToAttrs (map (id: lib.nameValuePair id (nixosFor id)) ids);
  configs = lib.mapAttrs (_: s: s.config) systems;

  # --- images -----------------------------------------------------------
  installerFor = id:
    if imageSource "installer" == "nixos-generators" then
      (if nixos-generators == null
      then throw ("images.installer = \"nixos-generators\" needs the nixos-generators input; "
        + "pass it to mkFleet or use the native builder")
      else nixos-generators.nixosGenerate {
        inherit system;
        modules = modulesFor id;
        format = "install-iso";
      })
    else configs.${id}.system.build.images.iso-installer;

  # Build raw-efi images for hosts with a local loader. Direct hosts instead
  # receive an installer and a separate kernel/initrd/command-line bundle.
  diskImageFor = id:
    if imageSource "disk" == "nixos-generators" then
      (if nixos-generators == null
      then throw ("images.disk = \"nixos-generators\" needs the nixos-generators input; "
        + "pass it to mkFleet or use the native builder")
      else nixos-generators.nixosGenerate {
        inherit system;
        modules = modulesFor id;
        format = "raw-efi";
      })
    else configs.${id}.system.build.images.raw-efi;

  # Build provider bundles only for direct-boot hosts.
  directHostIds = lib.filter (id: inv.hosts.${id}.boot == "direct") ids;
  directBootFor = id: directBoot.bundleOf pkgs id configs.${id};

  # Build a generic managed image without a fleet member's identity or roles.
  genericManaged = nixpkgs.lib.nixosSystem {
    modules = [
      platform
      ../services.nix
      ../managed.nix
      { meisterstack.managed.enable = true; }
      # The generic QEMU image needs virtio drivers in its initrd. Host-specific
      # images obtain their hardware drivers from operator modules.
      "${nixpkgs}/nixos/modules/profiles/qemu-guest.nix"
    ]
    # Use fleet default profiles for the generic image, independent of host order.
    ++ map (profileFor "managed-disk-image") (inv.defaults.profiles or [ ])
    ++ extraModules;
  };

  imagesOf = builtins.listToAttrs (map
    (id: lib.nameValuePair id {
      installerDrv = (installerFor id).drvPath;
      diskImageDrv =
        if builtins.elem id directHostIds then null else (diskImageFor id).drvPath;
      directBootDrv =
        if builtins.elem id directHostIds then (directBootFor id).drvPath else null;
    })
    ids);

  # --- the manifest -----------------------------------------------------
  meisterDeployment = import ./manifest.nix { inherit lib; } {
    inventory = inv;
    inherit configs;
    images = imagesOf;
    packages = {
      inherit (pkgs) meisterstack;
      cloudHypervisor = pkgs.cloud-hypervisor-meister;
      guestTiny = pkgs.guest-tiny;
      leandro = if leandro == null then null else leandro.packages.${system}.vhost-user-nvrm;
      patchDir = ../../patches;
      # Record the source revision when available; dirty trees have no clean revision.
      srcRev = meisterstack.rev or (meisterstack.dirtyRev or "unknown");
    };
  };

  # Discard string context before writing manifest JSON. Otherwise store paths
  # in the description make its validation build every referenced system and image.
  manifestJson = pkgs.writeText "meister-deployment.json"
    (builtins.unsafeDiscardStringContext (builtins.toJSON meisterDeployment));

  # --- checks -----------------------------------------------------------
  binaryOf = role: if role == "agent" then "meister-agent" else "meister-${role}-controller";

  # Run the real binaries' pure --check-config validation on rendered files.
  # These checks do not open runtime listeners, databases, or host devices.
  configCheck = id:
    let cfg = configs.${id}; in
    pkgs.runCommand "config-${id}" { } (''
      fail=0
    '' + lib.concatMapStrings
      (role: ''
        echo "== ${id}: ${role}.toml"
        ${pkgs.meisterstack}/bin/${binaryOf role} --check-config \
          --config ${cfg.environment.etc."meisterstack/${role}.toml".source} || fail=1
      '')
      cfg.meisterstack.unitsFor
    + ''
      test $fail = 0 || { echo "-> the configuration of ${id} is not one"; exit 1; }
      touch $out
    '');

  # Compare Nix and CLI inventory precedence using the same input file.
  inventoryParity =
    let
      nixSide = pkgs.writeText "inventory-nix.json" (builtins.toJSON
        (lib.mapAttrs
          (_: h: {
            inherit (h) profiles boot substituters;
            ssh = h.ssh;
            rollout = h.rollout;
            checks = h.checks;
          })
          inv.hosts));
    in
    pkgs.runCommand "inventory-parity"
      { nativeBuildInputs = [ pkgs.python3 ]; } ''
      ${pkgs.meisterstack}/bin/meister-deploy inventory --json -f ${inventory} > rust.json
      python3 ${./inventory-parity.py} rust.json ${nixSide}
      touch $out
    '';

  manifestCheck = pkgs.runCommand "manifest-json" { } ''
    # The pipe lane 1B and 1C agreed on: what Nix says, checked against the
    # types that read it. Every field required, every struct
    # deny_unknown_fields — so a key this fleet forgot is an error here and
    # not a surprise in a receipt three milestones later.
    ${pkgs.meisterstack}/bin/meister-deploy validate --manifest ${manifestJson}
    touch $out
  '';
in
{
  # Expose the parsed inventory for inspection.
  inventory = inv;

  # Expose host module lists for callers that do not need the fleet outputs.
  hostModules = builtins.listToAttrs (map (id: lib.nameValuePair id (modulesFor id)) ids);

  nixosConfigurations = systems;

  packages.${system} =
    builtins.listToAttrs
      (lib.concatMap
        (id: [
          (lib.nameValuePair "${id}-installer" (installerFor id))
          (lib.nameValuePair "${id}-toplevel" configs.${id}.system.build.toplevel)
        ]
        ++ lib.optional (!(builtins.elem id directHostIds))
          (lib.nameValuePair "${id}-disk-image" (diskImageFor id))
        ++ lib.optional (builtins.elem id directHostIds)
          (lib.nameValuePair "${id}-direct-boot" (directBootFor id)))
        ids)
    // {
      managed-disk-image = genericManaged.config.system.build.images.qemu;
      manifest = manifestJson;
    };

  checks.${system} =
    builtins.listToAttrs (map (id: lib.nameValuePair "config-${id}" (configCheck id)) ids)
    // {
      inventory-parity = inventoryParity;
      manifest-json = manifestCheck;
    };

  inherit meisterDeployment;
}

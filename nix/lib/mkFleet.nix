# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# `lib.mkFleet` — the whole of what an operator's flake calls.
#
#   outputs = { nixpkgs, meisterstack, disko, ... }:
#     meisterstack.lib.mkFleet { inherit nixpkgs disko; meisterstack = meisterstack; } {
#       inventory = ./fleet.toml;
#       profiles = import ./profiles.nix;
#     };
#
# What comes back is a flake's worth of outputs: one `nixosConfigurations.<id>`
# per host the inventory calls `nixos`, the images beside them, the checks
# that hold the inventory to the tool that reads it, and
# `meisterDeployment` — the attribute `meister-deploy resolve` evaluates.
#
# Two rules this file exists to keep:
#
# * **One derivation.** Everything a host ends up being comes out of
#   nix/lib/inventory.nix. mkFleet arranges modules and outputs; it derives
#   no address, no peer set and no port of its own.
# * **One road into the modules.** A host of a fleet is
#   `nixosModules.services` + `nixosModules.managed` + what the inventory says
#   + the operator's own profiles — the same options a foreign flake uses
#   (examples/fleet/foreign-flake is that flake, and it takes its module from
#   right here).
{ nixpkgs
, meisterstack
  # The partition tables. A host with an `install` table names a layout, and
  # THIS is where that layout is imported — together with disko's own module,
  # which is what turns `disko.devices` into `fileSystems`. From then on
  # disko is the only author of that host's mounts, which is why the
  # operator's own profiles set none (templates/operator/profiles/base.nix
  # says so where somebody will read it).
  #
  # Null is allowed and is a fleet that installs nothing: a host with an
  # `install` table then gets a sentence rather than a partition table
  # nobody imported.
, disko ? null
  # The pre-v1 image generator. Only needed where a format has not been
  # measured against the native `system.build.images` yet.
, nixos-generators ? null
  # The GPU stack. Null for a CPU-only fleet, which is what keeps this
  # buildable in a sandbox with no developer home (L01/V04).
, leandro ? null
}:

{ inventory
  # attrs: profile name -> NixOS module. The operator's half: stateVersion,
  # filesystems, firewall, sshd. A host gets the profiles its inventory entry
  # names, in precedence order (defaults, then its groups, then itself).
, profiles ? { }
  # attrs: host id -> module (or list of modules), for anything that has no
  # place in a profile. `modules = [ … ]` in the inventory is the other road
  # and takes paths relative to the inventory file.
, hostModules ? { }
  # Modules every host of this fleet gets.
, extraModules ? [ ]
, system ? "x86_64-linux"
  # Overlays on top of ours, for an operator who builds their own agent.
, pkgsOverlays ? [ ]
  # Which generator each image format comes from. `native` is
  # `config.system.build.images.<format>`; `nixos-generators` is the pre-v1
  # road and needs that input. For the installer the two were measured
  # byte-for-byte equal in M0 (probe S4), which is why `native` is the
  # default here.
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

  # `system` and the overlay, in one place. `nixpkgs.pkgs` rather than
  # `nixpkgs.overlays`: the `pkgs` above is already instantiated with the
  # overlay and reusing it means one nixpkgs per fleet instead of one per
  # host, which on seventy hosts is the difference between minutes and an
  # afternoon.
  platform = { nixpkgs.pkgs = pkgs; };

  # The partition table of a host this fleet installs, plus the module that
  # turns it into filesystems.
  #
  # Only for a host with an `install` table: a machine somebody else
  # partitioned has no layout to import, and disko's module on such a host
  # would add an activation script that formats nothing and a `fileSystems`
  # set that is empty — a second author with nothing to say. The path is
  # relative to the INVENTORY file (the same rule as `modules = [ … ]`), so
  # that a layout is a file of the operator's repository and not a name this
  # flake has to know.
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
      ../services.nix
      ../managed.nix
      {
        # A host the inventory calls `nixos` IS a deployment target: its
        # closure is copied in, staged, activated and confirmed from the
        # outside, and that is what this profile means.
        meisterstack.managed.enable = true;
      }
      (inv.hostModule id)
      # The installer MEDIUM of this host, which is a medium and not this
      # host: nix/install.nix says what is in it and why. It lives in
      # `image.modules.iso-installer` — the sub-evaluation the image is built
      # in — because `isoImage.*` set on a host is an option that does not
      # exist (M0 finding A10).
      #
      # `{ config, ... }:` and not `configs.${id}`: reading the evaluated
      # host out of the attribute set this list BUILDS would be a recursion
      # that only laziness keeps from closing. The module argument is the
      # same value with none of that.
      ({ config, ... }: lib.mkIf (inv.hosts.${id}.install != null) {
        image.modules.iso-installer = import ../install.nix {
          inherit id;
          host = inv.hosts.${id};
          target = config;
          fleet = inv.fleet;
        };

        # And the disk IMAGE brings its own partition table, so the host's
        # layout has to step aside inside it.
        #
        # A `<id>-disk-image` is a prebuilt filesystem somebody writes to a
        # disk or registers with a provider; the image builder decides where
        # its root is (`/dev/disk/by-label/nixos`, nixos/modules/
        # virtualisation/disk-image.nix) and it says so without a priority.
        # disko says the same thing about the partition table it would
        # CREATE, also without a priority, and two unprioritised definitions
        # of one `device` is an evaluation error — measured, the moment the
        # layout started being imported. Turning disko's config off inside
        # the image is the honest reading: nothing partitions anything here,
        # so the layout has nothing to say.
        #
        # Inside the `install` condition, and that is not tidiness either: a
        # host with no install table never imported disko, so setting one of
        # its options there is an option that does not exist — measured, on
        # the ha example, which has no install tables at all.
        image.modules.raw-efi = { ... }: { disko.enableConfig = false; };
        image.modules.qemu = { ... }: { disko.enableConfig = false; };
      })
      {
        # A host with no `install` table is never installed by this tool, so
        # its medium carries no target and settles only the one option the
        # two profiles disagree about: nixpkgs' installation-device profile
        # says `PermitRootLogin = "yes"` and nix/managed.nix says
        # `"prohibit-password"`, both as defaults, which is a conflict rather
        # than a precedence.
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

  # A prebuilt disk for a host that boots itself.
  #
  # Only for a `uefi` host, and that is not a gap: `raw-efi` IS an EFI image
  # — it makes an ESP and installs systemd-boot into it — so an image of that
  # format for a machine that has no boot loader would be an image that
  # contradicts its own host (measured: the two `mkDefault`s for
  # `boot.loader.systemd-boot.enable` are a conflict, which is the module
  # system saying exactly this). A direct-boot host's road is the installer
  # medium plus the bundle `<id>-direct-boot`, which is the pair its provider
  # loads.
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

  # The kernel, the initrd and the command line of a host that boots
  # `direct`, in one directory for the provider to take. Only for those
  # hosts: a uefi host reads its own boot menu, and a bundle for it would be
  # a directory nothing ever loads — which is why `packages.<id>-direct-boot`
  # does not exist for one.
  directHostIds = lib.filter (id: inv.hosts.${id}.boot == "direct") ids;
  directBootFor = id: directBoot.bundleOf pkgs id configs.${id};

  # A managed host with NO identity: no host name of a fleet member, no
  # roles, no keys. It is what a lab boots two or three fresh VMs from (L2)
  # before `keys enroll` and the first `apply` make each of them a host —
  # which is the whole point of a managed host, since everything that makes
  # it one arrives in a closure.
  genericManaged = nixpkgs.lib.nixosSystem {
    modules = [
      platform
      ../services.nix
      ../managed.nix
      { meisterstack.managed.enable = true; }
      # It IS a qemu image — `system.build.images.qemu` — and a qcow2 whose
      # initrd has no virtio driver is a qcow2 that boots a kernel, waits
      # twenty-two seconds for a root filesystem no driver can see, and
      # panics with "Attempted to kill init". Measured, in
      # `checks.vm-two-instances-same-image`, on both copies at once.
      #
      # This is the one hardware statement this flake makes, and it makes it
      # because the format already did: a host of a fleet gets its drivers
      # from its own module (that is what a `hardware-configuration.nix`
      # is), and this image has no host.
      "${nixpkgs}/nixos/modules/profiles/qemu-guest.nix"
    ]
    # The fleet's DEFAULT profiles — `[defaults] profiles` — and not one
    # host's: this image is every host and none of them. Taking the first
    # host's list would have made the image depend on which host happens to
    # sort first, and `builtins.head` on a fleet with no nixos host would
    # have thrown where a sentence belongs.
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
      # Which MeisterStack these binaries come from. A git flake knows its
      # revision; a dirty one knows only that it is dirty, and saying
      # "unknown" is better than naming a revision nobody could check out.
      srcRev = meisterstack.rev or (meisterstack.dirtyRev or "unknown");
    };
  };

  # The manifest as a FILE, for the check below — and without its string
  # context, which is the whole point of this line.
  #
  # `meisterDeployment` is full of store paths: `toplevel_out` is an
  # `outPath`, `toplevel_drv` and the two image derivations are `drvPath`s.
  # Written into a derivation, each of those strings carries a dependency
  # with it, so `nix build` of this text file builds the systems AND the
  # disk images of every host — measured: a `nix flake check` of the example
  # fleet started building `nixos-disk-image` and ate the disk. A manifest is
  # a DESCRIPTION: `meister-deploy resolve` produces it with `nix eval`, which
  # builds nothing, and the check that validates its SHAPE must not build a
  # fleet either. What the paths mean is checked elsewhere and later — the
  # RELEASE (M2) is what records that a path exists and what its nar hash is.
  manifestJson = pkgs.writeText "meister-deployment.json"
    (builtins.unsafeDiscardStringContext (builtins.toJSON meisterDeployment));

  # --- checks -----------------------------------------------------------
  binaryOf = role: if role == "agent" then "meister-agent" else "meister-${role}-controller";

  # The real parsers, on a host that is not the host: `--check-config` reads
  # the file, runs every pure check and starts nothing — no listener, no
  # database, no group lookup (D12, lane 1C position 7). So a build machine
  # can say whether a config is a config.
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

  # What Nix derived and what the tool that reads the same file says about
  # it, side by side. This is the check that replaced scripts/check-fleet.sh:
  # there the comparison was between two DERIVATIONS (and a shell script
  # measured it); here there is one derivation, and what is compared is the
  # one thing both halves still do — precedence.
  inventoryParity =
    let
      nixSide = pkgs.writeText "inventory-nix.json" (builtins.toJSON
        (lib.mapAttrs
          (_: h: {
            inherit (h) profiles boot;
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
  # The inventory as Nix read it, for an operator who wants to look.
  inventory = inv;

  # The module list of a host, for a flake that wants the host without the
  # fleet: examples/fleet/foreign-flake imports exactly this.
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

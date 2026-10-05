# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Evaluate the optional GPU profile with and without a stub leandro input.
# Validate both rendered configurations with the real agent parser. This does
# not test the actual GPU package build or hardware.
{ nixpkgs, lib, pkgs, system, self }:
let
  inherit (import ./lib.nix { inherit lib; }) require tagOf failedOf failsOnly;

  profileOf = leandro:
    import ../../templates/operator/profiles/compute-gpu-pro6000.nix {
      inherit lib leandro system;
    };

  # A host that carries a card, as small as a host of this fleet can be. `extra` are the
  # rest of the host's modules: its driver, its CPU and whatever a case needs.
  hostWith = leandro: extra: (nixpkgs.lib.nixosSystem {
    modules = [
      {
        nixpkgs.hostPlatform = system;
        nixpkgs.overlays = [ self.overlays.default ];
        networking.hostName = "gpu-probe";
        system.stateVersion = "25.11";
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.grub.device = "nodev";
      }
      self.nixosModules.services
      self.nixosModules.managed
      {
        meisterstack.roles = [ "agent" ];
        meisterstack.managed.enable = true;
        meisterstack.managed.trustedPublicKeys = [ "gpu-probe:not-a-real-key" ];
      }
      (profileOf leandro)
    ] ++ extra;
  }).config;

  # What the host's own modules provide: the open driver with the persistence daemon, and
  # the CPU (every GPU host of the IKR fleet is AMD).
  driver = {
    services.xserver.videoDrivers = [ "nvidia" ];
    hardware.nvidia.open = true;
    hardware.nvidia.nvidiaPersistenced = true;
    # Evaluating the driver's own module reads its package's metadata, and the licence
    # check refuses that for unfree packages. Nothing here is built or fetched.
    nixpkgs.config.allowUnfreePredicate = pkg:
      builtins.elem (lib.getName pkg) [ "nvidia-x11" "nvidia-settings" "nvidia-persistenced" ];
  };
  amd = { hardware.cpu.amd.updateMicrocode = true; };
  intel = { hardware.cpu.intel.updateMicrocode = true; };

  # What the `leandro` input looks like from this profile's point of view:
  # two outputs, two binaries, and the DRIVER_VERSION file of its source tree.
  # Two trivial scripts because the check is about the SHAPE of the
  # configuration — which keys, pointing where — and building an NVIDIA driver
  # stack to find that out would be an afternoon for a question a store path
  # already answers.
  stub = {
    outPath = ./leandro-stub;
    packages.${system} = {
      vhost-user-nvrm = pkgs.writeShellScriptBin "vhost-user-nvrm" "exit 0";
      leandro = pkgs.writeShellScriptBin "vgpuprofile" "exit 0";
    };
  };

  # The stub's driver version, pinned the way the profile's message tells an operator to.
  # Only the version is read: nothing is fetched or built, so the hashes are placeholders.
  stubDriverVersion = lib.fileContents ./leandro-stub/DRIVER_VERSION;
  pinnedDriver = { config, ... }: {
    hardware.nvidia.package = config.boot.kernelPackages.nvidiaPackages.mkDriver {
      version = stubDriverVersion;
      sha256_64bit = lib.fakeHash;
      openSha256 = lib.fakeHash;
      settingsSha256 = lib.fakeHash;
      persistencedSha256 = lib.fakeHash;
    };
  };

  without = hostWith null [ driver amd ];
  with' = hostWith stub [ driver amd pinnedDriver ];
  # nixpkgs' default driver, which is not the version the stub targets.
  unpinnedHost = hostWith stub [ driver amd ];

  # The cases of the profile's own assertions, told apart by their tags (./lib.nix).
  paramsOf = c: " ${lib.concatStringsSep " " c.boot.kernelParams} ";
  intelHost = hostWith null [ driver intel ];
  unknownHost = hostWith null [ driver ];
  forcedIntel = hostWith null [ driver { meisterstack.gpuProfile.iommuVendor = "intel"; } ];
  noDriverHost = hostWith null [ amd ];
  closedHost = hostWith null [ driver amd { hardware.nvidia.open = lib.mkForce false; } ];
  noPersistenceHost = hostWith null [ driver amd { hardware.nvidia.nvidiaPersistenced = lib.mkForce false; } ];
  migHost = hostWith null [
    driver
    amd
    { systemd.services.nvidia-mig-setup = { script = "true"; wantedBy = [ "multi-user.target" ]; }; }
  ];

  tomlOf = c: c.environment.etc."meisterstack/agent.toml".source;
in
pkgs.runCommand "gpu-profile" { } ''
  echo "== without the leandro input"
  cat ${tomlOf without}
  if grep -q 'device.nvrm' ${tomlOf without}; then
    echo "-> a fleet with no GPU stack rendered an nvrm device anyway"
    exit 1
  fi
  # The machine half is unconditional: the card is bound to vfio whether or
  # not anything hands it to a guest.
  case "${paramsOf without}" in
    *" iommu=pt "*) ;;
    *) echo "-> the profile did not turn the IOMMU on"; exit 1 ;;
  esac
  # AMD host: the vendor-neutral switch and nothing Intel-specific.
  case "${paramsOf without}" in
    *intel_iommu*) echo "-> an AMD host got an Intel IOMMU parameter"; exit 1 ;;
  esac
  case " ${lib.concatStringsSep " " without.boot.kernelModules} " in
    *" vfio-pci "*) ;;
    *) echo "-> the profile did not load vfio-pci"; exit 1 ;;
  esac
  # And it says so, once, where an operator sees it. The host carries other
  # warnings of its own (the agent's `network-online.target` ordering, 1A
  # §8 point 5), so what is asked for is THIS one and not an empty list.
  ${lib.optionalString (!(lib.any (w: tagOf w == "no-gpu-backend") without.warnings)) ''
    echo "-> a fleet with no GPU stack got no warning about it"; exit 1
  ''}

  # The profile's assertions: a host that meets them has none failed, and each way of not
  # meeting one fails exactly that one.
  ${require (failedOf without == [ ]) "a complete GPU host failed: ${lib.concatStringsSep " | " (failedOf without)}"}
  ${require (lib.hasInfix " intel_iommu=on " (paramsOf intelHost) && failedOf intelHost == [ ])
    "an Intel GPU host did not get intel_iommu=on, or failed an assertion"}
  ${require (lib.hasInfix " intel_iommu=on " (paramsOf forcedIntel) && failedOf forcedIntel == [ ])
    "iommuVendor = intel did not select the Intel parameter"}
  ${require (failsOnly unknownHost "iommu-vendor") "a host of unknown CPU vendor was not refused"}
  ${require (failsOnly noDriverHost "driver") "a host without the NVIDIA driver was not refused with just that"}
  ${require (failsOnly closedHost "open-modules") "the closed kernel module was not refused"}
  ${require (failsOnly noPersistenceHost "persistenced") "a host without nvidia-persistenced was not refused"}
  ${require (failsOnly migHost "mig") "a host with MIG units was not refused"}
  echo "  ok   vendor-neutral IOMMU switch and the five assertions"

  echo "== with it"
  cat ${tomlOf with'}
  grep -q 'binary = "/nix/store/.*/bin/vhost-user-nvrm"' ${tomlOf with'} \
    || { echo "-> the backend is not named out of the input"; exit 1; }
  grep -q 'vgpuprofile = "/nix/store/.*/bin/vgpuprofile"' ${tomlOf with'} \
    || { echo "-> the profile tool is not named out of the input"; exit 1; }
  # Both keys or neither: `NvrmConfig` requires them together, and the real
  # parser is what says so rather than this check's opinion.
  ${pkgs.meisterstack}/bin/meister-agent --check-config --config ${tomlOf with'} \
    || { echo "-> the agent refuses the configuration this profile produced"; exit 1; }
  ${pkgs.meisterstack}/bin/meister-agent --check-config --config ${tomlOf without} \
    || { echo "-> the agent refuses the configuration a CPU-only fleet produced"; exit 1; }
  ${require (failedOf with' == [ ]) "a GPU host on the stack's driver version failed: ${lib.concatStringsSep " | " (failedOf with')}"}
  ${require (unpinnedHost.hardware.nvidia.package.version != stubDriverVersion)
    "nixpkgs' default driver is the stub's version, so the mismatch case shows nothing"}
  ${require (failsOnly unpinnedHost "driver-version") "a host on another driver version than the GPU stack's was not refused"}
  ${lib.optionalString (lib.any (w: tagOf w == "no-gpu-backend") with'.warnings) ''
    echo "-> a fleet WITH the GPU stack was warned about not having it"
    exit 1
  ''}
  echo "  ok   both branches of the template's GPU profile parse, the driver version is pinned"
  touch $out
''

# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Evaluate the optional GPU profile with and without a stub leandro input.
# Validate both rendered configurations with the real agent parser. This does
# not test the actual GPU package build or hardware.
{ nixpkgs, lib, pkgs, system, self }:
let
  profileOf = leandro:
    import ../../templates/operator/profiles/compute-gpu-pro6000.nix {
      inherit lib leandro system;
    };

  # A host that carries a card, as small as a host of this fleet can be.
  hostWith = leandro: (nixpkgs.lib.nixosSystem {
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
    ];
  }).config;

  # What the `leandro` input looks like from this profile's point of view:
  # two outputs, two binaries. Two trivial scripts because the check is about
  # the SHAPE of the configuration — which keys, pointing where — and
  # building an NVIDIA driver stack to find that out would be an afternoon
  # for a question a store path already answers.
  stub = {
    packages.${system} = {
      vhost-user-nvrm = pkgs.writeShellScriptBin "vhost-user-nvrm" "exit 0";
      leandro = pkgs.writeShellScriptBin "vgpuprofile" "exit 0";
    };
  };

  without = hostWith null;
  with' = hostWith stub;
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
  ${lib.concatMapStrings (p: ''
    echo ${lib.escapeShellArg p} | grep -qx ${lib.escapeShellArg p}
  '') without.boot.kernelParams}
  case " ${lib.concatStringsSep " " without.boot.kernelParams} " in
    *" iommu=pt "*) ;;
    *) echo "-> the profile did not turn the IOMMU on"; exit 1 ;;
  esac
  case " ${lib.concatStringsSep " " without.boot.kernelModules} " in
    *" vfio-pci "*) ;;
    *) echo "-> the profile did not load vfio-pci"; exit 1 ;;
  esac
  # And it says so, once, where an operator sees it. The host carries other
  # warnings of its own (the agent's `network-online.target` ordering, 1A
  # §8 point 5), so what is asked for is THIS one and not an empty list.
  ${lib.optionalString (!(lib.any (w: lib.hasInfix "compute-gpu-pro6000" w) without.warnings)) ''
    echo "-> a fleet with no GPU stack got no warning about it"; exit 1
  ''}

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
  ${lib.optionalString (lib.any (w: lib.hasInfix "compute-gpu-pro6000" w) with'.warnings) ''
    echo "-> a fleet WITH the GPU stack was warned about not having it"
    exit 1
  ''}
  echo "  ok   both branches of the template's GPU profile parse"
  touch $out
''

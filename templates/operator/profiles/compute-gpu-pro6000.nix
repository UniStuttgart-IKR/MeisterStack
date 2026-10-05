# SPDX-License-Identifier: MIT
# NVIDIA host profile: IOMMU/VFIO settings, the host-driver assertions and an optional
# Leandro backend. Hardware availability and working GPU execution require separate
# host validation.
{ lib
  # The GPU stack, as flake.nix hands it over: the whole flake, or `null`.
, leandro ? null
, system ? "x86_64-linux"
}:
{ config, ... }:
let
  cfg = config.meisterstack.gpuProfile;

  # NVRM configuration requires both the vhost backend and the profile utility.
  gpu = lib.optionalAttrs (leandro != null) {
    device.nvrm = {
      binary = "${leandro.packages.${system}.vhost-user-nvrm}/bin/vhost-user-nvrm";
      vgpuprofile = "${leandro.packages.${system}.leandro}/bin/vgpuprofile";
    };
  };

  # The CPU vendor, as far as the host's own configuration says. nixos-generate-config
  # writes `kvm-intel` or `kvm-amd` into boot.kernelModules and sets the matching
  # hardware.cpu.<vendor>.updateMicrocode. Both vendors, or neither, is "unknown":
  # a host whose vendor nothing says is not guessed at (see the first assertion).
  hasModule = m: builtins.elem m config.boot.kernelModules;
  looksIntel = config.hardware.cpu.intel.updateMicrocode || hasModule "kvm-intel";
  looksAmd = config.hardware.cpu.amd.updateMicrocode || hasModule "kvm-amd";
  detected =
    if looksIntel && !looksAmd then "intel"
    else if looksAmd && !looksIntel then "amd"
    else null;
  vendor = if cfg.iommuVendor == "auto" then detected else cfg.iommuVendor;

  # The vendor-specific half of the IOMMU switch. `iommu=pt` is vendor-neutral and always
  # set (passthrough for host-owned devices, translation only for what vfio takes). Intel's
  # driver stays off unless asked: `intel_iommu=on`. AMD's driver starts by itself when the
  # firmware publishes an IVRS table and has no `on` switch (`amd_iommu=` takes tuning
  # keywords only), so AMD adds nothing. `intel_iommu=on` on an AMD host is an unknown
  # parameter the kernel hands on to init: harmless, and a lie in the configuration.
  vendorParams = lib.optional (vendor == "intel") "intel_iommu=on";

  # MIG leaves no trace in NixOS options: it is `nvidia-smi -mig 1` plus a partition setup,
  # kept in the GPU's own state across reboots. What can be seen is a declarative unit that
  # does that. This catches units named like the usual ones (`nvidia-mig-*`, `mig-parted`);
  # a card put into MIG mode by hand is invisible here, and Leandro refuses MIG classes at
  # runtime instead (docs/SECURITY.md in the Leandro repository).
  migUnits = builtins.filter
    (n: lib.hasInfix "nvidia-mig" n || lib.hasInfix "mig-parted" n)
    (builtins.attrNames config.systemd.services);

  # The driver's own options are only readable with the driver on: nixpkgs computes the
  # default of hardware.nvidia.open from the package, which is null without it and fails the
  # evaluation with an error that names neither this profile nor the missing driver. The
  # assertions about the driver's settings therefore hold for free when there is no driver;
  # the driver assertion carries that case.
  nvidiaPresent = config.hardware.nvidia.enabled or false;

  # Every message of this profile starts with its name, so an operator reading a failed
  # build (and the check in nix/tests/gpu-profile.nix) can tell whose assertion it was.
  refuseUnless = assertion: message: {
    inherit assertion;
    message = "profiles/compute-gpu-pro6000.nix: ${message}";
  };
in
{
  options.meisterstack.gpuProfile.iommuVendor = lib.mkOption {
    type = lib.types.enum [ "auto" "intel" "amd" ];
    default = "auto";
    description = ''
      Which CPU vendor's IOMMU the host has. `auto` reads it from the host's own
      configuration (kvm-intel / kvm-amd in boot.kernelModules, hardware.cpu.*.updateMicrocode)
      and fails the build when that says nothing or both. Set it in the host module for a
      host whose hardware-configuration.nix carries neither.
    '';
  };

  config = {
    # Load VFIO and set the IOMMU switches of the host CPU's vendor.
    boot.kernelModules = [ "vfio-pci" ];
    boot.kernelParams = [ "iommu=pt" ] ++ vendorParams;

    # Select PCI devices in the host module; record declared hardware in the inventory.

    # Without Leandro, no NVRM backend is configured.
    meisterstack.agent.settings = gpu;

    assertions = [
      (refuseUnless (vendor != null) ''
        cannot tell an Intel host from an AMD one (hardware.cpu.*.updateMicrocode and
        boot.kernelModules name both vendors or neither). Set
        meisterstack.gpuProfile.iommuVendor = "intel" or "amd" in the host module.
      '')
      (refuseUnless nvidiaPresent ''
        the host has no NVIDIA driver. Set services.xserver.videoDrivers = [ "nvidia" ]
        and hardware.nvidia.open = true in the host module, at the version the GPU stack
        targets: the guest is handed the host's libcuda, and the ioctl layouts are version
        specific.
      '')
      (refuseUnless (!nvidiaPresent || config.hardware.nvidia.open == true) ''
        hardware.nvidia.open must be true. Blackwell cards (RTX PRO 6000) run on the open
        kernel modules only, and the GPU stack is written against them.
      '')
      (refuseUnless (!nvidiaPresent || config.hardware.nvidia.nvidiaPersistenced) ''
        hardware.nvidia.nvidiaPersistenced must be true. Without the persistence daemon the
        driver tears the GPU state down when the last client exits, and every guest start
        pays the initialisation again.
      '')
      (refuseUnless (migUnits == [ ]) ''
        MIG and the GPU stack exclude each other on one card, and this host declares MIG
        units (${lib.concatStringsSep ", " migUnits}). Give the card to one of them: remove
        the MIG setup from this host, or use a profile without a GPU backend.
      '')
    ];

    # Explain the missing optional backend during evaluation.
    warnings = lib.optional (leandro == null) (
      "profiles/compute-gpu-pro6000.nix configures the IOMMU and vfio-pci, and no NVIDIA "
      + "backend: the `leandro` input is not declared in flake.nix. Uncomment it there, or "
      + "this fleet's GPU hosts carry cards that nothing hands to a guest."
    );
  };
}

# SPDX-License-Identifier: MIT
# A workload carrier with an NVIDIA RTX PRO 6000 in it.
#
# Two halves, and only the second needs anything from outside:
#
#   * the MACHINE half — the IOMMU and the vfio driver — which is a fact
#     about the box and is set here unconditionally;
#   * the AGENT half — the vhost-user backend for NVIDIA's resource manager
#     and the profile tool beside it — which comes out of the `leandro`
#     input. That input is commented out in flake.nix on purpose: a CPU-only
#     fleet has to build without it (scenario L01, and nothing in this
#     repository may need somebody's home directory), so this profile takes
#     it as an argument that defaults to `null` and configures no card at all
#     when it is not there.
#
# What this profile does NOT do is claim the card works. `meister-deploy
# verify --suite gpu` is what says that, on the machine, with a deterministic
# computation whose result is checked — and `capabilities = ["vfio"]` in the
# inventory is what makes that suite required rather than `not_applicable`.
{ lib
  # The GPU stack, as flake.nix hands it over: the whole flake, or `null`.
, leandro ? null
, system ? "x86_64-linux"
}:
{ ... }:
let
  # Both binaries the agent's `[device.nvrm]` names, and they come out of two
  # different outputs of that flake: `vhost-user-nvrm` is the backend crate on
  # its own, and `vgpuprofile` is a binary of `nvrm-client`, which is in the
  # whole build. `[device.nvrm]` requires both keys (`NvrmConfig` in
  # components/agent/src/config.rs), so naming one without the other would be
  # a configuration the agent refuses at start-up.
  gpu = lib.optionalAttrs (leandro != null) {
    device.nvrm = {
      binary = "${leandro.packages.${system}.vhost-user-nvrm}/bin/vhost-user-nvrm";
      vgpuprofile = "${leandro.packages.${system}.leandro}/bin/vgpuprofile";
    };
  };
in
{
  # The devices the agent hands to guests, and the driver behind them.
  #
  # `iommu=pt` is pass-through mode: the IOMMU is on for assigned devices and
  # out of the way for everything else, which is what keeps the host's own
  # NICs at full speed. On an AMD box the first parameter is `amd_iommu=on`;
  # the kernel ignores the one that is not its own, and a host module of
  # yours is the place to say which, if you want only one.
  boot.kernelModules = [ "vfio-pci" ];
  boot.kernelParams = [ "intel_iommu=on" "iommu=pt" ];

  # WHICH cards, by PCI address, is a fact about one machine and belongs in
  # `hosts/<id>.nix` beside the rest of its hardware. The fleet declares them
  # in `hardware.gpus` so that a plan can check them against `lspci`; this
  # profile is what every GPU host of the fleet has in common.

  # The agent half. Empty without the input, and that is a working fleet:
  # the cards are bound to vfio and nothing hands them to a guest.
  meisterstack.agent.settings = gpu;

  # Said once, where an operator will see it, and only when it is true.
  warnings = lib.optional (leandro == null) (
    "profiles/compute-gpu-pro6000.nix configures the IOMMU and vfio-pci, and no NVIDIA "
    + "backend: the `leandro` input is not declared in flake.nix. Uncomment it there, or "
    + "this fleet's GPU hosts carry cards that nothing hands to a guest."
  );
}

# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The packages of this repository, as an overlay.
#
# An overlay and not just a `packages` output because the modules reach them
# through `pkgs`: `meisterstack.package` defaults to `pkgs.meisterstack`, and
# an operator who wants their own build of one of these — a patched
# hypervisor, a fork of the agent — overrides the attribute once instead of
# passing a package into every option.
#
# `meisterstack-runtime` is the one attribute that is not a build of its own.
# The agent's unit takes `meister-agent` AND `cloud-hypervisor` out of ONE
# directory (`meisterstack.binDir`, nix/agent.nix), because that option is a
# directory rather than a list of binaries — so the directory has to exist,
# and a symlinkJoin is what makes one out of two store paths. It is also the
# honest shape for M2: a managed host's closure contains exactly what its
# units name.
final: prev: {
  meisterstack = final.callPackage ./packages/meisterstack.nix { };

  cloud-hypervisor-meister = final.callPackage ./packages/cloud-hypervisor.nix { };

  vhost-device-input = final.callPackage ./packages/vhost-device-input.nix { };

  guest-tiny = final.callPackage ./packages/guest-tiny.nix { };

  meisterstack-runtime = final.symlinkJoin {
    name = "meisterstack-runtime-${final.meisterstack.version}";
    paths = [ final.meisterstack final.cloud-hypervisor-meister ];
    meta.description =
      "The binaries a managed host's units name, in one directory: the workspace and the hypervisor";
  };
}

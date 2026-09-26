# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Expose repository packages through pkgs so operators can override builds
# once for all modules. The runtime joins workspace and hypervisor binaries
# under the single binDir used by service units.
final: prev: {
  meisterstack = final.callPackage ./packages/meisterstack.nix { };

  cloud-hypervisor-meister = final.callPackage ./packages/cloud-hypervisor.nix { };

  vhost-device-input = final.callPackage ./packages/vhost-device-input.nix { };

  guest-tiny = final.callPackage ./packages/guest-tiny.nix { };

  # Operator-side CA utility; runtime hosts do not need the CA signing tool.
  meister-ca = final.callPackage ./packages/meister-ca.nix { };

  # Static workspace binaries for deployments outside the managed NixOS closure.
  meisterstack-static = final.pkgsStatic.callPackage ./packages/meisterstack.nix { };

  # Static patched hypervisor for the same deployment path.
  cloud-hypervisor-meister-static =
    final.pkgsStatic.callPackage ./packages/cloud-hypervisor.nix { };

  meisterstack-runtime = final.symlinkJoin {
    name = "meisterstack-runtime-${final.meisterstack.version}";
    paths = [ final.meisterstack final.cloud-hypervisor-meister ];
    meta.description =
      "The binaries a managed host's units name, in one directory: the workspace and the hypervisor";
  };
}

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

  # The CA, for the OPERATOR's side. Deliberately not in
  # `meisterstack-runtime` below: the runtime is what a fleet host's units
  # exec, and a fleet host has no CA key on it (D10) — the key stays with the
  # operator and a node sends a request. `meister-deploy keys issue` looks up
  # a bare `meister-ca` on PATH, which is what this attribute makes possible
  # without a `nix shell` around every invocation.
  meister-ca = final.callPackage ./packages/meister-ca.nix { };

  # The same five binaries, statically linked. The legacy context fleet gets
  # its binaries pushed into /opt/meisterstack/bin on a host whose libc is
  # not ours (`meister-deploy legacy context-push`, M2C), so that push needs
  # a binary that depends on nothing — which is what deploy/push.sh built by
  # hand in `nix develop .#musl` until now.
  #
  # `pkgsStatic` and not a cross toolchain by hand: if it builds, it is one
  # attribute; if it does not, the devShells.musl road stays and the report
  # says so rather than a half-working package pretending otherwise.
  meisterstack-static = final.pkgsStatic.callPackage ./packages/meisterstack.nix { };

  meisterstack-runtime = final.symlinkJoin {
    name = "meisterstack-runtime-${final.meisterstack.version}";
    paths = [ final.meisterstack final.cloud-hypervisor-meister ];
    meta.description =
      "The binaries a managed host's units name, in one directory: the workspace and the hypervisor";
  };
}

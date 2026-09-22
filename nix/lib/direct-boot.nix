# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# What a hypervisor is handed for a host that boots `direct`.
#
# A `boot = "direct"` machine carries no boot loader: the thing that decides
# which kernel it starts is OUTSIDE it, and what that thing needs is three
# values — a kernel, an initrd and a command line. This file is the one place
# they are derived, because two of them are read in two places: `lib.mkFleet`
# builds the bundle as a package (`packages.<id>-direct-boot`), and
# `nix/lib/manifest.nix` writes the command line into the manifest so that
# `meister-deploy build` can put it in the release. Two derivations of one
# string would be two strings waiting to disagree, and the one that disagrees
# is a guest that boots the wrong system.
#
# The `init=` is the whole reason the command line is not just
# `boot.kernelParams`: a NixOS system is started by `<toplevel>/init`, and a
# guest whose loader does not say so boots the kernel of the new generation
# into the userland of whatever the initrd finds. Naming the toplevel is what
# makes a direct-boot guest's "next boot" a fact somebody can point at.
{ lib }:

rec {
  # `<kernel params> init=<toplevel>/init`, exactly as the file `cmdline` in
  # the bundle holds it and exactly as the manifest records it.
  #
  # Taken from `boot.kernelParams` rather than from `${toplevel}/kernel-params`
  # (which holds the same list, space-separated) because this has to be a
  # STRING at evaluation time: the manifest is produced by `nix eval`, and
  # reading a file out of a derivation would mean building the system to be
  # able to describe it.
  cmdlineOf = cfg:
    lib.concatStringsSep " "
      (cfg.boot.kernelParams ++ [ "init=${cfg.system.build.toplevel}/init" ]);

  # The bundle as a directory: `kernel`, `initrd`, `cmdline`.
  #
  # Symlinks and not copies: the kernel and the initrd are already in the
  # store, many hosts of a fleet share the same pair, and a copy per host
  # would be a gigabyte per host for no fact anybody gains. What the
  # provider reads is `readlink -f` of the two names — which is the store
  # path the release records.
  bundleOf = pkgs: name: cfg:
    pkgs.runCommand "${name}-direct-boot" { } ''
      mkdir -p "$out"
      ln -s ${cfg.system.build.kernel}/${cfg.system.boot.loader.kernelFile} "$out/kernel"
      ln -s ${cfg.system.build.initialRamdisk}/${cfg.system.boot.loader.initrdFile} "$out/initrd"
      printf '%s\n' ${lib.escapeShellArg (cmdlineOf cfg)} > "$out/cmdline"
    '';
}

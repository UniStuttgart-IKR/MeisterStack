# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Derive the kernel, initrd, and command line for a provider-booted host.
# Share this derivation between the manifest and bundle. The init argument
# selects the target system generation, independently of the kernel path.
{ lib }:

rec {
  # Derive the command line from evaluated options without building the target
  # to read kernel-params from its output.
  cmdlineOf = cfg:
    lib.concatStringsSep " "
      (cfg.boot.kernelParams ++ [ "init=${cfg.system.build.toplevel}/init" ]);

  # Expose kernel and initrd through symlinks, plus a command-line file.
  bundleOf = pkgs: name: cfg:
    pkgs.runCommand "${name}-direct-boot" { } ''
      mkdir -p "$out"
      ln -s ${cfg.system.build.kernel}/${cfg.system.boot.loader.kernelFile} "$out/kernel"
      ln -s ${cfg.system.build.initialRamdisk}/${cfg.system.boot.loader.initrdFile} "$out/initrd"
      printf '%s\n' ${lib.escapeShellArg (cmdlineOf cfg)} > "$out/cmdline"
    '';
}

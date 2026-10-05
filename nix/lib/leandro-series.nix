# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Compare the Cloud Hypervisor patch series of a Leandro source tree with ours.
# Leandro's vhost-user-nvrm and this stack's cloud-hypervisor negotiate a
# shared-memory window only when both are built from the same series, so every
# patch in Leandro's patches/ must be in ours with the same bytes. Patches only
# ours has (0004, MeisterStack's hardening) are not compared: they are not
# Leandro's to carry.
{ lib }:

{
  # The names of Leandro's patches that `patchDir` lacks or holds with other
  # bytes; empty when the two series agree.
  driftedPatches = { leandroPatchDir, patchDir }:
    let
      isPatch = name: type: type == "regular" && lib.hasSuffix ".patch" name;
      theirs = lib.attrNames (lib.filterAttrs isPatch (builtins.readDir leandroPatchDir));
      sha256 = builtins.hashFile "sha256";
      drifted = name:
        let ours = patchDir + "/${name}"; in
        !(builtins.pathExists ours) || sha256 ours != sha256 (leandroPatchDir + "/${name}");
    in
    lib.throwIfNot (builtins.pathExists leandroPatchDir)
      "the leandro input has no ${toString leandroPatchDir}, so its cloud-hypervisor patch series cannot be compared with MeisterStack's patches/"
      (lib.filter drifted theirs);
}

# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Compare the Cloud Hypervisor patch series of a Leandro source tree with ours.
# Leandro's vhost-user-nvrm and this stack's cloud-hypervisor negotiate a
# shared-memory window only when both are built from the same series, so the
# two must agree in both directions: every patch of ours except `ownPatches` is
# in Leandro's series with the same bytes, and Leandro's series has no other
# patch. What cannot be compared is drift or refused, never agreement.
{ lib }:
let
  # MeisterStack's own patches on top of Leandro's series (patches/README.md, "Hardening"):
  # the only ones our patches/ may hold and Leandro's not.
  ownPatches = [ "0004-generic-vhost-user-shmem-window-overflow.patch" ];

  # The patches a cloud-hypervisor package built from `dir` applies, keyed by their path
  # relative to `dir`: every `*.patch` at any depth, as Leandro's package and ours pick
  # them with lib.filesystem.listFilesRecursive. The relative path also orders them. A
  # `*.patch` that is a link or a special file is refused rather than followed or skipped:
  # what it stands for depends on where the tree lies.
  seriesIn = dir:
    let
      entriesBelow = sub: prefix: lib.concatLists (lib.mapAttrsToList
        (name: type:
          let rel = prefix + name; in
          if type == "directory" then entriesBelow (sub + "/${name}") "${rel}/"
          else if !(lib.hasSuffix ".patch" name) then [ ]
          else if type == "regular" then [ (lib.nameValuePair rel (sub + "/${name}")) ]
          else throw ("${rel} in ${toString dir} is a ${type}, not a regular file, so the "
            + "cloud-hypervisor patch series there cannot be compared byte for byte"))
        (builtins.readDir sub));
    in
    lib.listToAttrs (entriesBelow dir "");
in
{
  inherit ownPatches;

  # Where the two series differ, one `{ patch; problem; }` per patch, sorted by patch;
  # empty when they agree. `problem` is "missing-in-leandro" for a patch of ours that
  # Leandro's series lacks (an empty series lacks them all), "only-in-leandro" for one of
  # Leandro's that we do not carry, and "changed" for one both carry with other bytes.
  driftedPatches = { leandroPatchDir, patchDir }:
    let
      theirs = seriesIn leandroPatchDir;
      shared = removeAttrs (seriesIn patchDir) ownPatches;
      sha256 = builtins.hashFile "sha256";
      problemOf = patch:
        if !(theirs ? ${patch}) then "missing-in-leandro"
        else if !(shared ? ${patch}) then "only-in-leandro"
        else if sha256 theirs.${patch} != sha256 shared.${patch} then "changed"
        else null;
      patches = lib.unique (lib.sort lib.lessThan (lib.attrNames theirs ++ lib.attrNames shared));
    in
    lib.throwIfNot (builtins.pathExists leandroPatchDir)
      "the leandro input has no ${toString leandroPatchDir}, so its cloud-hypervisor patch series cannot be compared with MeisterStack's patches/"
      (lib.throwIf (shared == { })
        "${toString patchDir} holds no patch besides MeisterStack's own (${lib.concatStringsSep ", " ownPatches}), so there is no Leandro series to compare"
        (lib.filter (d: d.problem != null)
          (map (patch: { inherit patch; problem = problemOf patch; }) patches)));

  # A drift as one line of an assertion message: "0002-...patch: changed; ...".
  describeDrift = lib.concatMapStringsSep "; " (d: "${d.patch}: ${d.problem}");
}

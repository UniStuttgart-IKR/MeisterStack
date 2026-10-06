# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A Leandro source tree whose cloud-hypervisor patch series differs from
# patches/ is drift. The comparison runs both ways, so a series that lacks one
# of ours, has none at all or keeps it elsewhere is drift too. One of our own
# patches that Leandro's series carries as well is no drift when the bytes are
# the same, and drift when they differ. Only source trees are looked at: nothing
# is built. That a fleet on a drifted series is refused is meister-deploy's half.
{ lib, pkgs }:
let
  inherit (import ./lib.nix { inherit lib; }) require;
  series = import ../lib/leandro-series.nix { inherit lib; };

  p0001 = "0001-generic-vhost-user-shmem.patch";
  p0002 = "0002-generic-vhost-user-device-features.patch";
  p0003 = "0003-generic-vhost-user-refused-request.patch";
  p0004 = "0004-generic-vhost-user-shmem-window-overflow.patch";

  # A Leandro tree as far as the comparison looks: patches/ holding our patches but `left`,
  # that is our series copied unchanged, without `left`.
  leandroTreeWithout = left: lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.fileFilter
      (f: f.hasExt "patch" && !(lib.elem f.name left))
      ../../patches;
  };
  # Leandro's own series: ours but our own patches.
  sameSeries = leandroTreeWithout series.ownPatches;
  seriesWithout0003 = leandroTreeWithout (series.ownPatches ++ [ p0003 ]);
  # Its series has taken up our 0004 unchanged.
  upstreamedSeries = leandroTreeWithout [ ];
  # Its patches/ holds no patch, only our README.
  emptySeries = lib.fileset.toSource { root = ../..; fileset = ../../patches/README.md; };
  # Its patches/ holds a changed 0002 and a 0005 we do not have, and neither 0001 nor 0003.
  driftedSeries = ./leandro-stub;
  # Its patches/ holds a 0002 one directory down, where Leandro's package still applies it.
  nestedSeries = ./leandro-series/nested;
  # Its patches/ holds 0002 as a link to our own 0002.
  linkedSeries = ./leandro-series/linked;
  # Its patches/ holds a 0004 with other bytes than ours, and neither 0001, 0002 nor 0003.
  changedOwnSeries = ./leandro-series/own-changed;

  driftOf = src: series.driftedPatches {
    leandroPatchDir = "${src}/patches";
    patchDir = ../../patches;
  };
  missing = patch: { inherit patch; problem = "missing-in-leandro"; };
  onlyInLeandro = patch: { inherit patch; problem = "only-in-leandro"; };
  changed = patch: { inherit patch; problem = "changed"; };

  # One step per case: the tree's drift must be exactly `drift`.
  requireDrift = case: src: drift: require (driftOf src == drift)
    "${case}: expected [${series.describeDrift drift}], got [${series.describeDrift (driftOf src)}]";
  # Comparing with this tree is refused outright instead of reported as drift.
  isRefused = src: !(builtins.tryEval (builtins.deepSeq (driftOf src) true)).success;

in
pkgs.runCommand "leandro-series" { } ''
  ${requireDrift "Leandro's own series" sameSeries [ ]}
  ${requireDrift "a series without our 0003" seriesWithout0003 [ (missing p0003) ]}
  ${requireDrift "a series with our own 0004 unchanged" upstreamedSeries [ ]}
  ${requireDrift "a series with another 0004" changedOwnSeries [
    (missing p0001)
    (missing p0002)
    (missing p0003)
    (changed p0004)
  ]}
  ${requireDrift "an empty series" emptySeries [ (missing p0001) (missing p0002) (missing p0003) ]}
  ${requireDrift "a drifted series" driftedSeries [
    (missing p0001)
    (changed p0002)
    (missing p0003)
    (onlyInLeandro "0005-only-in-leandro.patch")
  ]}
  ${requireDrift "a nested series" nestedSeries [
    (missing p0001)
    (missing p0002)
    (missing p0003)
    (onlyInLeandro "v53/${p0002}")
  ]}
  ${require (isRefused linkedSeries) "a series with a linked patch was compared instead of refused"}
  echo "  ok   the series are compared both ways; a link is refused"

  ${require (series.upstreamedOwnPatches { leandroPatchDir = "${upstreamedSeries}/patches"; patchDir = ../../patches; } == [ p0004 ])
    "a series that took up our 0004 unchanged does not name it as upstreamed"}
  ${require (series.upstreamedOwnPatches { leandroPatchDir = "${sameSeries}/patches"; patchDir = ../../patches; } == [ ])
    "a series without our own patches names one as upstreamed"}
  echo "  ok   an own patch Leandro's series carries with the same bytes is named as upstreamed"
  touch $out
''

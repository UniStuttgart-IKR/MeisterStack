# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A fleet whose leandro input carries another cloud-hypervisor patch series than
# patches/ is refused at evaluation, and one on the same series is not. The
# comparison runs both ways, so a series that lacks one of ours, has none at
# all or keeps it elsewhere is drift too. One of our own patches that Leandro's
# series carries as well is no drift when the bytes are the same, and drift when
# they differ. Only the leandro input's source tree is looked at: nothing is built.
{ lib, pkgs, fleetWith }:
let
  inherit (import ./lib.nix { inherit lib; }) require tagOf failedOf failsOnly;
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

  # One host of a fleet with this leandro source; the stub has no packages because the
  # series assertion reads the source tree only.
  hostOf = src:
    (lib.head (lib.attrValues (fleetWith { outPath = src; }).nixosConfigurations)).config;
  # Whether that host is warned that Leandro's series carries one of our own patches now.
  warnsOfUpstreamed = src: lib.any (w: tagOf w == "leandro-series") (hostOf src).warnings;
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

  ${require (failedOf (hostOf sameSeries) == [ ]) "a fleet on Leandro's series was refused"}
  ${require (failsOnly (hostOf driftedSeries) "leandro-series") "a fleet on a drifted series was not refused"}
  ${require (failsOnly (hostOf emptySeries) "leandro-series") "a fleet on an empty series was not refused"}
  ${require (failedOf (hostOf upstreamedSeries) == [ ]) "a fleet on a series that took up our 0004 was refused"}
  ${require (failsOnly (hostOf changedOwnSeries) "leandro-series") "a fleet on a series with another 0004 was not refused"}
  echo "  ok   a fleet on the same series passes, one on a drifted, empty or other-0004 series is refused"

  ${require (warnsOfUpstreamed upstreamedSeries) "a series that took up our 0004 did not warn that it can be dropped"}
  ${require (!(warnsOfUpstreamed sameSeries)) "a series without our own patches was warned about one"}
  echo "  ok   a series that took up our own patch is told it can be dropped from ownPatches"
  touch $out
''

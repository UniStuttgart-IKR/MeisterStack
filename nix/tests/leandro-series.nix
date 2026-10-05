# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A fleet whose leandro input carries another cloud-hypervisor patch series than
# patches/ is refused at evaluation, and one on the same series is not. Only
# the leandro input's source tree is looked at: nothing is built.
{ lib, pkgs, fleetWith }:
let
  series = import ../lib/leandro-series.nix { inherit lib; };

  # A Leandro tree as far as the comparison looks: patches/ holding our 0001-0003, which are
  # Leandro's series copied unchanged, and not our own 0004.
  sameSeries = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.fileFilter
      (f: f.hasExt "patch" && !(lib.hasPrefix "0004-" f.name))
      ../../patches;
  };
  # Its patches/ holds a changed 0002 and a 0005 that patches/ does not have.
  driftedSeries = ./leandro-stub;

  driftOf = src: series.driftedPatches {
    leandroPatchDir = "${src}/patches";
    patchDir = ../../patches;
  };

  # The series assertion of one host of a fleet with this leandro source; the stub has no
  # packages because the assertion reads the source tree only.
  seriesFailuresOf = src:
    let host = lib.head (lib.attrValues (fleetWith { outPath = src; }).nixosConfigurations); in
    lib.filter (a: !a.assertion && lib.hasPrefix "[leandro-series]" a.message) host.config.assertions;

  # One shell step of the check: nothing when `ok`, else the reason and a failing exit.
  require = ok: reason:
    lib.optionalString (!ok) "echo ${lib.escapeShellArg "-> ${reason}"}; exit 1";
in
pkgs.runCommand "leandro-series" { } ''
  ${require (driftOf sameSeries == [ ])
    "Leandro's own series was reported as drift: ${toString (driftOf sameSeries)}"}
  ${require (driftOf driftedSeries == [
      "0002-generic-vhost-user-device-features.patch"
      "0005-only-in-leandro.patch"
    ])
    "a changed and a missing patch were not both named: ${toString (driftOf driftedSeries)}"}
  ${require (seriesFailuresOf sameSeries == [ ]) "a fleet on Leandro's series was refused"}
  ${require (lib.length (seriesFailuresOf driftedSeries) == 1) "a fleet on a drifted series was not refused"}
  echo "  ok   the same series passes, a drifted one is refused and named per patch"
  touch $out
''

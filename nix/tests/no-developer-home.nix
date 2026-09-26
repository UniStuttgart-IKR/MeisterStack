# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Inspect built units and rendered configurations for developer-specific paths
# and external binary push directories.
{ lib, pkgs, configs }:

let
  files = lib.concatMap
    (cfg:
      map (role: cfg.environment.etc."meisterstack/${role}.toml".source)
        cfg.meisterstack.unitsFor
      ++ [ cfg.system.build.toplevel ])
    (lib.attrValues configs);
in
pkgs.runCommand "no-developer-home" { } ''
  bad=0
  for f in ${lib.concatStringsSep " " (map toString files)}; do
    if [ -d "$f" ]; then
      # A toplevel: our own units, not all of nixpkgs'.
      hits=$(grep -rl -e /home/ -e Leandro -e /opt/meisterstack/bin \
        "$f"/etc/systemd/system/meister-*.service 2>/dev/null || true)
    else
      hits=$(grep -l -e /home/ -e Leandro -e /opt/meisterstack/bin "$f" 2>/dev/null || true)
    fi
    if [ -n "$hits" ]; then
      echo "$hits names a path this fleet was not built from:"
      grep -h -e /home/ -e Leandro -e /opt/meisterstack/bin $hits | head -5
      bad=1
    fi
  done
  test $bad = 0 || { echo "-> V04: a fleet has to be buildable without anybody's home"; exit 1; }
  echo "${toString (lib.length files)} built artefacts, none of them names a home directory"
  touch $out
''

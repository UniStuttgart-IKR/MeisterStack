# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Nothing this fleet is made of comes out of a developer's home directory.
#
# It used to: the units expected /opt/meisterstack/bin, filled by
# `deploy/push.sh` from `$HOME/git/Leandro/target/release` and by
# `get_patched_binaries.sh`, which clones two repositories into `bin/` and
# — measured in M0 — writes a GLOBAL git identity while it is at it. A fleet
# built that way cannot be rebuilt by anybody else, which is scenario V04.
#
# Two halves, and the first one is the build itself: this derivation only
# exists if the example fleet's systems, the rendered configuration files and
# the packages were all built in the nix sandbox, where there is no home
# directory to read. The second half is the grep below, because a path can
# also travel as a STRING in a config file — `inputBackend`, a hypervisor
# binary, a kernel — and a string like that would only fail on the machine.
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
      hits=$(grep -rl -e /home/ -e Leandro -e /opt/meisterstack \
        "$f"/etc/systemd/system/meister-*.service 2>/dev/null || true)
    else
      hits=$(grep -l -e /home/ -e Leandro -e /opt/meisterstack "$f" 2>/dev/null || true)
    fi
    if [ -n "$hits" ]; then
      echo "$hits names a path this fleet was not built from:"
      grep -h -e /home/ -e Leandro -e /opt/meisterstack $hits | head -5
      bad=1
    fi
  done
  test $bad = 0 || { echo "-> V04: a fleet has to be buildable without anybody's home"; exit 1; }
  echo "${toString (lib.length files)} built artefacts, none of them names a home directory"
  touch $out
''

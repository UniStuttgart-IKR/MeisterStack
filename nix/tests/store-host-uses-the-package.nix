# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A store-built host (nixosModules.store-host, all three roles) runs the
# runtime package of its own system generation: every role unit starts its
# binary out of `binDir`, the agent starts guests with the hypervisor out of the
# same directory, and the units wait for keys, never for a binary, which on
# such a host cannot be missing. What meister-deploy's managed profile adds on
# top is checked there.
{ lib, pkgs, host }:

let
  top = host.system.build.toplevel;
  runtime = host.meisterstack.binDir;
  roleUnits = [ "meister-cloud-controller" "meister-cluster-controller" "meister-agent" ];
in
pkgs.runCommand "store-host-uses-the-package" { } ''
  units=${top}/etc/systemd/system
  test '${runtime}' = '${host.meisterstack.runtime}/bin' \
    || { echo "-> binDir is ${runtime}, not the runtime package ${host.meisterstack.runtime}/bin"; exit 1; }
  for u in ${lib.concatStringsSep " " roleUnits}; do
    grep -q "^ExecStart=${runtime}/$u " $units/$u.service \
      || { echo "-> $u.service does not start ${runtime}/$u:"; grep ExecStart $units/$u.service; exit 1; }
    test -x ${runtime}/$u || { echo "-> ${runtime}/$u is not there"; exit 1; }
  done

  # The agent starts guests with the hypervisor out of the SAME directory,
  # because `binDir` is a directory and agent.toml names the binary in it.
  test -x ${runtime}/cloud-hypervisor \
    || { echo "-> the hypervisor is not in ${runtime}"; exit 1; }
  grep -q '${runtime}/cloud-hypervisor' ${host.environment.etc."meisterstack/agent.toml".source} \
    || { echo "-> agent.toml does not name the hypervisor in ${runtime}"; exit 1; }
  # The one program that talks to a RUNNING VMM from outside it: a test that
  # stops a guest it started, or an operator looking at one that will not die.
  test -x ${runtime}/ch-remote \
    || { echo "-> ch-remote is not in ${runtime}; nothing outside a VMM can talk to it"; exit 1; }

  if grep -h ConditionPathExists $units/meister-*.service | grep -q '/bin/'; then
    echo "-> a unit waits for a binary that is part of its own system generation:"
    grep -h ConditionPathExists $units/meister-*.service
    exit 1
  fi
  grep -q '^ConditionPathExists=.*/pki/ca.crt' $units/meister-agent.service \
    || { echo "-> the agent no longer waits for its CA"; exit 1; }

  echo "the role units of a store-built host start ${runtime} and wait only for keys"
  touch $out
''

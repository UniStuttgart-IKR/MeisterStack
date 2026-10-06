# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A store-built host (nixosModules.store-host, all three roles) runs the
# runtime package of its own system generation: every role unit starts its
# binary out of `binDir`, the agent starts guests with the hypervisor out of the
# same directory, and every role unit waits for its CA, never for a binary,
# which on such a host cannot be missing. meister-deploy's
# managed-uses-the-package checks only what its managed profile adds on top.
{ lib, pkgs, host }:

let
  top = host.system.build.toplevel;
  binDir = host.meisterstack.binDir;
  caCert = "${host.meisterstack.pki.dir}/ca.crt";
  roleUnits = [ "meister-cloud-controller" "meister-cluster-controller" "meister-agent" ];
in
pkgs.runCommand "store-host-uses-the-package" { } ''
  units=${top}/etc/systemd/system
  test '${binDir}' = '${host.meisterstack.runtime}/bin' \
    || { echo "-> binDir is ${binDir}, not the runtime package ${host.meisterstack.runtime}/bin"; exit 1; }
  for u in ${lib.concatStringsSep " " roleUnits}; do
    grep -q "^ExecStart=${binDir}/$u " $units/$u.service \
      || { echo "-> $u.service does not start ${binDir}/$u:"; grep ExecStart $units/$u.service; exit 1; }
    test -x ${binDir}/$u || { echo "-> ${binDir}/$u is not there"; exit 1; }
  done

  # The agent starts guests with the hypervisor out of the SAME directory,
  # because `binDir` is a directory and agent.toml names the binary in it.
  test -x ${binDir}/cloud-hypervisor \
    || { echo "-> the hypervisor is not in ${binDir}"; exit 1; }
  grep -q '${binDir}/cloud-hypervisor' ${host.environment.etc."meisterstack/agent.toml".source} \
    || { echo "-> agent.toml does not name the hypervisor in ${binDir}"; exit 1; }
  # The one program that talks to a RUNNING VMM from outside it: a test that
  # stops a guest it started, or an operator looking at one that will not die.
  test -x ${binDir}/ch-remote \
    || { echo "-> ch-remote is not in ${binDir}; nothing outside a VMM can talk to it"; exit 1; }

  if grep -h ConditionPathExists $units/meister-*.service | grep -q '/bin/'; then
    echo "-> a unit waits for a binary that is part of its own system generation:"
    grep -h ConditionPathExists $units/meister-*.service
    exit 1
  fi
  # Keys are not part of the generation: each role unit stays visibly skipped
  # until its CA is there, instead of restarting into a missing file, and
  # waits for nothing else.
  for u in ${lib.concatStringsSep " " roleUnits}; do
    conditions=$(grep '^ConditionPathExists=' $units/$u.service || true)
    test "$conditions" = 'ConditionPathExists=${caCert}' \
      || { echo "-> $u.service does not wait for exactly ${caCert}:"; echo "$conditions"; exit 1; }
  done

  echo "the role units of a store-built host start ${binDir} and wait only for their CA"
  touch $out
''

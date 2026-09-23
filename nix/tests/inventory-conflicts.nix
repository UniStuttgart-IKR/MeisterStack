# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# An inventory that cannot be deployed cannot be BUILT either.
#
# Every rule in nix/lib/inventory.nix throws at evaluation, and this check is
# the counter-proof that they do: five broken inventories under
# examples/fleet/broken/, each evaluated through `builtins.tryEval`, each
# required to fail. A rule that stopped firing would show up here as a
# success, which is the one outcome this file treats as an error.
#
# What it does NOT check is the WORDING, and that is a limit of `tryEval`: it
# reports whether an evaluation failed and never what it said. The sentences
# are held to their shape on the Rust side, where the same rules are tested
# against the same words (`tools/meister-deploy/src/inventory.rs`), and the
# report of this lane quotes each one from a real `nix eval`.
{ lib, pkgs, inventoryLib }:

let
  broken = {
    # Two groups of equal rank disagree about rollout.reboot.
    conflict = ../../examples/fleet/broken/conflict.toml;
    # A raft group of two.
    even-raft = ../../examples/fleet/broken/even-raft.toml;
    # An addons host and no [fleet] domain.
    addons-without-domain = ../../examples/fleet/broken/addons-without-domain.toml;
    # The pre-v1 plan, which nothing reads any more.
    schema1 = ../../examples/fleet/broken/schema1.toml;
    # --- lane 5B ---
    # A schema 2 file that still carries `[opennebula]`. Both readers refuse
    # an undeclared table; this is the one that was really in the lab's
    # inventory, so it gets its own sentence and its own case.
    opennebula-table = ../../examples/fleet/broken/opennebula-table.toml;
    # --- end lane 5B ---
  };

  # `deepSeq` because the rules are lazy on purpose: what forces them is a
  # consumer, and the manifest is the consumer that touches every host.
  survives = file:
    (builtins.tryEval
      (builtins.deepSeq (inventoryLib.load file).manifestInventory true)).success;

  accepted = lib.attrNames (lib.filterAttrs (_: file: survives file) broken);
in
pkgs.runCommand "inventory-conflicts" { } (
  if accepted == [ ] then ''
    echo "${toString (lib.length (lib.attrNames broken))} broken inventories, ${
      toString (lib.length (lib.attrNames broken))
    } refused at evaluation"
    touch $out
  '' else ''
    ${lib.concatMapStrings
      (n: "echo 'examples/fleet/broken/${n}.toml evaluated without a complaint'\n")
      accepted}
    echo "-> a rule in nix/lib/inventory.nix stopped firing"
    exit 1
  ''
)

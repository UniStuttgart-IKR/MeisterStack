# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The five binaries of this workspace, as one derivation.
#
# Before this package the units took their binaries from
# /opt/meisterstack/bin, filled by `deploy/push.sh` out of somebody's
# `target/release` — so what a machine ran was whatever the last push had
# compiled, on whichever laptop, and nothing recorded which tree that was. A
# store path IS that record: the same inputs give the same path, the manifest
# names it, and a rollback takes the binaries back with the generation.
#
# Five packages in one derivation and not five derivations: they share a
# Cargo.lock, a proto crate and a build, and building the workspace once is
# cheaper than building it five times. `meister-deploy` is in the list
# because the managed profile needs `meister-activate` (M2) in the closure,
# and that is a second binary of the same crate.
{ lib, rustPlatform, protobuf }:

let
  root = ../..;
  fs = lib.fileset;

  # Exactly what the build reads, and nothing else. Not a `src = ./..`:
  # that copies `target/` (gigabytes), `bin/` (git links into two foreign
  # checkouts), `docs/`, `deploy/` and every `result` symlink into the store,
  # and — worse for this project — it makes the source hash change on a
  # documentation commit, which changes every host's toplevel and makes
  # "only the systems that really changed" (V10/V11) a lie.
  src = fs.toSource {
    inherit root;
    fileset = fs.unions [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      # The workspace members, as Cargo.toml globs them: shared/*,
      # components/*, drivers/* and tools/meister-deploy. `shared/proto`
      # carries `proto/control.proto`, which its build.rs compiles, so the
      # whole directory travels rather than a hand-kept list of files.
      (root + "/shared")
      (root + "/components")
      (root + "/drivers")
      (root + "/tools/meister-deploy")
    ];
  };

  cargo = lib.importTOML (root + "/Cargo.toml");
in
rustPlatform.buildRustPackage {
  pname = "meisterstack";
  version = cargo.workspace.package.version;
  inherit src;

  # No `outputHashes`: `grep -c 'source = "git' Cargo.lock` is 0, so every
  # dependency comes from crates.io and the lock file is the whole answer
  # (measured, M0 probe S2).
  cargoLock.lockFile = root + "/Cargo.lock";

  # shared/proto/build.rs runs prost-build, which needs protoc. It is the
  # only build.rs in the tree.
  nativeBuildInputs = [ protobuf ];

  cargoBuildFlags = [
    "-p"
    "meister-agent"
    "-p"
    "meister-cloud-controller"
    "-p"
    "meister-cluster-controller"
    "-p"
    "meister-cli"
    "-p"
    "meister-deploy"
  ];

  # The workspace's tests are not sandbox tests, and this is measured rather
  # than assumed: they want /dev/kvm and a cloud-hypervisor (the agent's
  # `stufe3_ch`, `input_ch`, `unprivileged_ch` suites), a running etcd
  # (`tickets_etcd`), a network namespace (`gateway_netns`) — 17 of them are
  # `#[ignore]`d for exactly that — and one of them reads a real host device
  # off /dev/input (M0 §1, finding B1). A build that ran them would either
  # fail in the sandbox or, worse, pass only on a machine that happens to
  # have the hardware. `cargo test --workspace` is where they run, and the
  # lane reports its numbers from there.
  doCheck = false;

  # NO `MEISTER_GIT_REV` here, deliberately. Baking the revision in would
  # change every binary on every commit — including a commit that only
  # touches a brief — and with it the toplevel of every host in the fleet.
  # `tool.git_rev` in a manifest resolved with a nix-built tool is therefore
  # `null`, which is the honest answer: the tree is named by
  # `source.fingerprint`, which is a fact about the operator's repository and
  # not about this binary.

  meta = {
    description = "The MeisterStack control plane: agent, both controllers, the cli and meister-deploy";
    license = lib.licenses.mit;
    mainProgram = "meister-agent";
    platforms = [ "x86_64-linux" ];
  };
}

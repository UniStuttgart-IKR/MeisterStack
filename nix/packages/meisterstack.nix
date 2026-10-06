# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Build the workspace's runtime and CLI binaries together, sharing one Cargo
# lockfile and vendored dependency set.
{ lib, rustPlatform, protobuf }:

let
  root = ../..;
  fs = lib.fileset;

  # Include only build inputs so unrelated documentation does not change the source hash.
  src = fs.toSource {
    inherit root;
    fileset = fs.unions [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      # Include all workspace members and the protobuf schema compiled by build.rs.
      (root + "/shared")
      (root + "/components")
      (root + "/drivers")
    ];
  };

  cargo = lib.importTOML (root + "/Cargo.toml");
in
rustPlatform.buildRustPackage {
  pname = "meisterstack";
  version = cargo.workspace.package.version;
  inherit src;

  # Cargo.lock pins registry dependencies.
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
  ];

  # Hardware and service integration tests run separately from this package build.
  doCheck = false;

  # Do not embed a commit revision: unrelated commits should not alter binaries.
  # A deployment records the source revision separately.

  meta = {
    description = "The MeisterStack control plane: agent, both controllers and the cli";
    license = lib.licenses.mit;
    # `nix run` is for a person at a shell; the daemons are started by units by path.
    mainProgram = "meister";
    platforms = [ "x86_64-linux" ];
  };
}

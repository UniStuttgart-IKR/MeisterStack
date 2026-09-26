# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Build Cloud Hypervisor v53.0 with the repository's sorted patch series.
# Generic vhost-user shared-memory regions are required by the GPU backends.
{ lib
, rustPlatform
, fetchFromGitHub
, pkg-config
, openssl
, zstd
, chVersion ? "v53.0"
, patchDir ? ../../patches
}:
rustPlatform.buildRustPackage {
  pname = "cloud-hypervisor-meister";
  version = lib.removePrefix "v" chVersion;
  src = fetchFromGitHub {
    owner = "cloud-hypervisor";
    repo = "cloud-hypervisor";
    rev = chVersion;
    hash = "sha256-fPTGf8bAITDA8QwllWbbGXA7tJ6p/SxRDfcBQVRvCTI=";
  };
  # The patches touch no Cargo.lock, so the vendor hash is upstream's.
  cargoHash = "sha256-+RbW/9ap/69MyODUk/bHBlH6ZuqYYIyKaarYSMQ2G7w=";
  patches = lib.sort lib.lessThan (lib.filter (p: lib.hasSuffix ".patch" (toString p))
    (lib.filesystem.listFilesRecursive patchDir));
  # Check that the shared-memory patch marker remains in the source.
  postPatch = ''
    grep -q get_shmem_config virtio-devices/src/vhost_user/generic_vhost_user.rs \
      || { echo "patch marker (SHMEM) missing from the source"; exit 1; }
  '';
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl zstd ];
  env.OPENSSL_NO_VENDOR = true;
  env.ZSTD_SYS_USE_PKG_CONFIG = true;
  # Build the VMM and its ch-remote management client explicitly.
  cargoBuildFlags = [ "--bin" "cloud-hypervisor" "--bin" "ch-remote" ];
  # Upstream tests require host facilities unavailable in the build sandbox.
  doCheck = false;
  meta = {
    description = "cloud-hypervisor ${chVersion} with MeisterStack's generic-vhost-user SHMEM patches";
    license = lib.licenses.asl20;
    mainProgram = "cloud-hypervisor";
    platforms = [ "x86_64-linux" ];
  };
}

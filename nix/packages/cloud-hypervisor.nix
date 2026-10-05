# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Build Cloud Hypervisor v53.0 with the repository's sorted patch series.
# Generic vhost-user shared-memory regions are required by the GPU backends.
# The series is Leandro's, rewritten against the vhost-user specification on
# 2026-09-23 (vhost 0.17 for the frontend, SHMEM = protocol feature bit 22,
# BACKEND_SEND_FD offered); it is the same series Leandro HEAD 73eb298 builds,
# so both ends of the vhost-user channel negotiate SHMEM. Replace 0001-0003
# together: a backend on the old series (SHMEM = bit 21) never gets a window.
# 0004 is MeisterStack's own hardening on top (overflow-checked window layout,
# see patches/README.md); it must still apply after a new Leandro series.
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
  # Patch 0001 changes Cargo.lock (vhost 0.17 for the vhost-user frontend), so
  # the series goes in as cargoPatches: they reach the vendoring derivation as
  # well as the build, and the vendor hash below is the patched lock's, not
  # upstream's. `patches` would leave the vendored crates on the old lock.
  cargoPatches = lib.sort lib.lessThan (lib.filter (p: lib.hasSuffix ".patch" (toString p))
    (lib.filesystem.listFilesRecursive patchDir));
  cargoHash = "sha256-E6aBvXcFhmkhKE0xK70KZsgdgkpgfY2+FMx6cNSlwq8=";
  # Check that the shared-memory patch marker remains in the source, and that
  # 0004's checked window layout does: without it the build would still pass.
  postPatch = ''
    grep -q get_shmem_config virtio-devices/src/vhost_user/generic_vhost_user.rs \
      || { echo "patch marker (SHMEM) missing from the source"; exit 1; }
    grep -q checked_next_power_of_two virtio-devices/src/vhost_user/generic_vhost_user.rs \
      || { echo "patch marker (0004 window hardening) missing from the source"; exit 1; }
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

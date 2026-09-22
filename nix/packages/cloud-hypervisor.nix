# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# cloud-hypervisor v53.0 with this repository's patch series.
#
# Not nixpkgs' `cloud-hypervisor`: that one is whichever version the pinned
# nixpkgs ships, and `patches/0001-generic-vhost-user-shmem.patch` is written
# against exactly v53.0 — the generic vhost-user device learns SHARED MEMORY
# REGIONS there, which is what every RM mapping into a guest runs over.
# Without the series the device comes up, ioctls work, and there is no
# host-visible window, hence no CUDA in a guest.
#
# The recipe is ~/git/Leandro/nix/packages/cloud-hypervisor.nix, unchanged
# except for the two defaults: `patches` is WHICHEVER patches/*.patch exist,
# sorted, rather than a list repeated here — the series has grown twice and a
# second list would have gone stale both times. Built and measured in M0
# probe S3: 123 s, `cloud-hypervisor v53.0.0`, 49 MiB closure, both hashes
# still valid and `diff -r patches ~/git/Leandro/patches` identical.
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
  # Counter-check on the patched tree: the series brings exactly ONE
  # capability, and without it there is no window. A silently dropped patch
  # would otherwise be discovered by a guest that has no GPU memory.
  postPatch = ''
    grep -q get_shmem_config virtio-devices/src/vhost_user/generic_vhost_user.rs \
      || { echo "patch marker (SHMEM) missing from the source"; exit 1; }
  '';
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl zstd ];
  env.OPENSSL_NO_VENDOR = true;
  env.ZSTD_SYS_USE_PKG_CONFIG = true;
  cargoBuildFlags = [ "--bin" "cloud-hypervisor" ];
  # The test suite wants /dev/kvm, /dev/net/tun and io_uring; none of it is
  # available in the sandbox and none of it is ours.
  doCheck = false;
  meta = {
    description = "cloud-hypervisor ${chVersion} with MeisterStack's generic-vhost-user SHMEM patches";
    license = lib.licenses.asl20;
    mainProgram = "cloud-hypervisor";
    platforms = [ "x86_64-linux" ];
  };
}

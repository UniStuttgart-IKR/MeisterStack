#!/usr/bin/env bash
set -euo pipefail

# This script is created with the help of AI
# Model used: Claude Fable 5
# The model created the script mostly by itself with strict specification by the author.
# The author reviewed the script and did some minor changes.
#
# Author: Silas Müller
#
# This script downloads Cloud-Hypervisor and CrosVM, applies the patches from
# ./patches, builds both repositories and finally creates symlinks in ./bin.
# The repositories are cloned into ./bin/dependencies.
# This is required, so the agent can control the binaries to for example spawn VMs.
#
# Cloud-Hypervisor is built at v53.0 with the three generic-vhost-user patches
# from the Leandro project (~/git/Leandro/patches, copied into ./patches):
#   0001: negotiate and serve the shared memory window (required for CUDA and
#         for virtio-gpu host_visible/blob resources)
#   0002: pass device-specific feature bits 0..=23 through (required for
#         virgl/venus with a crosvm gpu backend)
#   0003: a backend-refused request no longer kills the whole device
# The former SpectrumOS patch (and its patched vhost crate) is obsolete since
# v51 ships the generic vhost-user device; crosvm-gpu now attaches through it.


# ---- Configuration ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPS_DIR="${SCRIPT_DIR}/bin/dependencies"
BIN_DIR="${SCRIPT_DIR}/bin"
PATCHES_DIR="${SCRIPT_DIR}/patches"

CH_REPO="https://github.com/cloud-hypervisor/cloud-hypervisor.git"
CH_TAG="v53.0"
CH_PATCHES=(
    "${PATCHES_DIR}/0001-generic-vhost-user-shmem.patch"
    "${PATCHES_DIR}/0002-generic-vhost-user-device-features.patch"
    "${PATCHES_DIR}/0003-generic-vhost-user-refused-request.patch"
)

CROSVM_REPO="https://chromium.googlesource.com/crosvm/crosvm"
# main as of 2026-08-26. The old minijail build fix (crosvm_minijail-fix.patch)
# is upstreamed at this pin and no longer applied.
CROSVM_COMMIT="8be640000662beb921bb1a718eb96935fcc6785a"

# Cleanup previouse installs
echo "==> Cleaning previous build..."
rm -rf "${DEPS_DIR}"
mkdir -p "${DEPS_DIR}"
cd "${DEPS_DIR}"


# Check for required tools: git, cargo
for cmd in git cargo; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: '$cmd' is required but not installed." >&2; exit 1; }
done

# Set identity if not already configured (required by git am)
git config --global user.email >/dev/null 2>&1 || git config --global user.email "build@meisterstack.local"
git config --global user.name  >/dev/null 2>&1 || git config --global user.name  "MeisterStack Build"

# Clone Cloud-Hypervisor and checkout v53.0
echo "==> Cloning cloud-hypervisor..."
if [[ ! -d "cloud-hypervisor" ]]; then
    git clone "${CH_REPO}" cloud-hypervisor
fi
cd cloud-hypervisor
git fetch origin --tags
git checkout "${CH_TAG}"
git rev-parse HEAD

# The patches are plain diffs (no From: header), so git apply, not git am.
echo "==> Applying generic-vhost-user patches..."
for patch in "${CH_PATCHES[@]}"; do
    git apply "${patch}"
done

# The shmem patch is the load-bearing one; fail loudly if it did not land.
grep -rq "get_shmem_config\|GET_SHMEM_CONFIG" virtio-devices/src/vhost_user/ || {
    echo "Error: shmem patch did not land in virtio-devices/src/vhost_user" >&2
    exit 1
}

# Build cloud-hypervisor with applied patches
echo "==> Building cloud-hypervisor..."
cargo build --release

# Static musl build for the NixOS agent VMs (no global glibc loader there).
# The C deps (ring, zstd) need a musl C compiler; nixpkgs' cross toolchain
# provides it without touching the host.
echo "==> Building cloud-hypervisor (musl, for agent VMs)..."
if command -v nix >/dev/null 2>&1; then
    nix shell nixpkgs#pkgsCross.musl64.stdenv.cc -c bash -c \
        'export CC_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-gcc \
                AR_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-ar \
         && cargo build --release --target x86_64-unknown-linux-musl'
else
    echo "NOTE: nix not found — skipping the musl build (only needed to deploy agents onto NixOS VMs)."
fi

# Clone crosvm
echo "==> Cloning crosvm..."
cd "${DEPS_DIR}"
if [[ ! -d "crosvm" ]]; then
    git clone "${CROSVM_REPO}" crosvm
fi
cd crosvm
git submodule update --init
git config submodule.recurse true
git config push.recurseSubmodules no
git fetch origin
git checkout "${CROSVM_COMMIT}"

# Build crosvm
# Later extend features bases on experiments
# GOAL: Run CS-2 single-player and llama.cpp 24GB Model
echo "==> Building crosvm..."
cargo build --release --features=gpu,virgl_renderer

cd "${DEPS_DIR}"

# Create symlinks
echo "==> Creating symlinks in ${BIN_DIR}..."
mkdir -p "${BIN_DIR}"

ln -sf "${DEPS_DIR}/cloud-hypervisor/target/release/cloud-hypervisor" "${BIN_DIR}/cloud-hypervisor"
ln -sf "${DEPS_DIR}/cloud-hypervisor/target/release/ch-remote"        "${BIN_DIR}/ch-remote"
ln -sf "${DEPS_DIR}/crosvm/target/release/crosvm"                     "${BIN_DIR}/crosvm"
[ -x "${DEPS_DIR}/cloud-hypervisor/target/x86_64-unknown-linux-musl/release/cloud-hypervisor" ] \
    && ln -sf "${DEPS_DIR}/cloud-hypervisor/target/x86_64-unknown-linux-musl/release/cloud-hypervisor" "${BIN_DIR}/cloud-hypervisor-musl"

# Leandro's backend + profile tool for the nvrm driver. Built in the Leandro
# checkout (cargo build --release), not by this script -- only linked here.
LEANDRO_RELEASE="${LEANDRO_RELEASE:-$HOME/git/Leandro/target/release}"
for b in vhost-user-nvrm vgpuprofile; do
    if [[ -x "${LEANDRO_RELEASE}/${b}" ]]; then
        ln -sf "${LEANDRO_RELEASE}/${b}" "${BIN_DIR}/${b}"
    else
        echo "NOTE: ${LEANDRO_RELEASE}/${b} not found -- the nvrm driver needs it; build it in ~/git/Leandro."
    fi
done

echo "==> Done. Binaries linked in: ${BIN_DIR}"

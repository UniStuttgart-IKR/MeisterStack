# Cloud Hypervisor patches

The [Nix package](../nix/packages/cloud-hypervisor.nix) applies all `.patch` files
recursively, sorted by path, to the pinned Cloud Hypervisor source. The default
version is v53.0, the same tag Leandro builds (`CH_VERSION`); changing the version
also requires checking source/vendor hashes and patch compatibility.

The three files are Leandro's series, copied unchanged from `patches/` at Leandro
HEAD `73eb298` (the rewrite of 2026-09-23 against the vhost-user specification).
They are `git format-patch` output, so `git apply` and `git am` both accept them.
Leandro's `patches/README.md` is the reference for the message formats, the
negotiated protocol features, the verification record and the upstreaming notes;
its `patches/REVIEW-vhost-user.md` lists what the previous series got wrong.
Keep the two copies identical: the vhost-user channel between Cloud Hypervisor and
`vhost-user-nvrm` only negotiates a shared-memory window when both ends are on the
same series.

| Patch | Purpose |
| --- | --- |
| `0001-generic-vhost-user-shmem.patch` | VIRTIO Shared Memory Regions in the generic vhost-user device: negotiate `SHMEM` (protocol feature bit 22) and `BACKEND_SEND_FD` (bit 10), `GET_SHMEM_CONFIG`, `SHMEM_MAP`/`SHMEM_UNMAP` into a PCI-visible host window. Moves the vhost-user frontend to the `vhost` 0.17 crate. |
| `0002-generic-vhost-user-device-features.patch` | Offer the device-specific feature-bit ranges (0-23, 50-63); negotiation intersects them with the backend's advertised features. |
| `0003-generic-vhost-user-refused-request.patch` | Keep the backend request worker alive after a refused (acknowledged) backend request; other request errors remain fatal. |

## Why `cargoPatches`

Patch 0001 changes `Cargo.lock`: it adds `vhost` 0.17.0 and `vm-memory` 0.18.0
beside the `vhost` 0.16 and `vm-memory` 0.17 the rest of Cloud Hypervisor v53.0
uses (`vhost` 0.16 defines `SHMEM` as bit 21, which the specification assigns to
`GPA_ADDRESSES`). The package therefore passes the series as `cargoPatches`, so
the vendoring derivation sees the patched lock file, and its `cargoHash` is the
hash of that vendor tree, not upstream's. After changing a patch that touches
`Cargo.lock`, set `cargoHash = lib.fakeHash;`, build once and take the hash Nix
reports.

## Compatibility and checks

- A backend on the old series (`SHMEM` = bit 21, `vhost` 0.16) and this
  hypervisor never negotiate `SHMEM`: the device comes up without a window and
  the guest cannot map GPU memory (`cuInit` returns 100). Rebuild both ends.
- The package checks for a shared-memory patch marker after applying the patches
  and sets `doCheck = false`: the marker shows presence, not correctness. The
  patched tree's own tests (`cargo test -p virtio-devices`, 112 tests) run in
  the Leandro repository, which records them in its README; the Rust workspace
  tests here do not compile or exercise this series.
- The agent starts the GPU backends and attaches their sockets to Cloud
  Hypervisor; see [drivers](../docs/DRIVERS.md).

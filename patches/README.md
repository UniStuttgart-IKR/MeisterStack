# Cloud Hypervisor patches

The [Nix package](../nix/packages/cloud-hypervisor.nix) applies all `.patch` files
recursively, sorted by path, to the pinned Cloud Hypervisor source. The default
version is v53.0, the same tag Leandro builds (`CH_VERSION`); changing the version
also requires checking source/vendor hashes and patch compatibility.

Patches 0001-0003 are Leandro's series, copied unchanged from `patches/` at
Leandro revision `73eb2985f32098500d851520710439d30f7c3ffe` (the rewrite of
2026-09-23 against the vhost-user specification). This is the one place that
records the revision; the Nix package and meister-deploy's operator template refer here.
Leandro's `patches/README.md` is the reference for the message
formats, the negotiated protocol features, the verification record and the
upstreaming notes; its `patches/REVIEW-vhost-user.md` lists what the previous
series got wrong. Keep these three identical to Leandro's: the vhost-user channel
between Cloud Hypervisor and `vhost-user-nvrm` only negotiates a shared-memory
window when both ends are on the same series. A fleet that declares the
`leandro` input is held to that: meister-deploy's `mkFleet` asserts on every host that the
input's `patches/`, searched recursively as Leandro's package does, holds
exactly the patches here except MeisterStack's own, under the same relative
paths and with the same bytes
([`nix/lib/leandro-series.nix`](../nix/lib/leandro-series.nix)). An input
whose series lacks one of them, is empty or carries a patch as a link is
refused too. That file's `ownPatches` names the patches that are this
repository's alone, today 0004; a new patch of our own goes there as well, or
every fleet with the `leandro` input is refused. Once Leandro's series carries
one of them with the same bytes, `mkFleet` warns that it can be dropped from
`ownPatches`; with other bytes the fleet is refused.

Patch 0004 is MeisterStack's own and applies on top of them; see
[Hardening](#hardening-patch-0004). All files are `git format-patch` output, so
`git apply` and `git am` both accept them.

| Patch | Purpose |
| --- | --- |
| `0001-generic-vhost-user-shmem.patch` | VIRTIO Shared Memory Regions in the generic vhost-user device: negotiate `SHMEM` (protocol feature bit 22) and `BACKEND_SEND_FD` (bit 10), `GET_SHMEM_CONFIG`, `SHMEM_MAP`/`SHMEM_UNMAP` into a PCI-visible host window. Moves the vhost-user frontend to the `vhost` 0.17 crate. |
| `0002-generic-vhost-user-device-features.patch` | Offer the device-specific feature-bit ranges (0-23, 50-63); negotiation intersects them with the backend's advertised features. |
| `0003-generic-vhost-user-refused-request.patch` | Keep the backend request worker alive after a refused (acknowledged) backend request; other request errors remain fatal. |
| `0004-generic-vhost-user-shmem-window-overflow.patch` | MeisterStack hardening: lay out the shared-memory window with checked arithmetic, bound it by the 64-bit PCI aperture, and keep every backend mapping inside the window. |

## Hardening (patch 0004)

Leandro's series at that revision has one limitation this repository does not accept.
The backend chooses the region sizes it reports with `GET_SHMEM_CONFIG`, and the
VMM sums them and rounds the total up to a power of two without overflow checks
(`shmem_sizes.iter().sum().next_power_of_two()` in `vmm/src/device_manager.rs`).
Cloud Hypervisor's release profile has no overflow checks, so sizes such as 2^63,
2^63 and one page wrap to a one-page window while the region list still describes
regions of 2^63 bytes. A `SHMEM_MAP` request is only checked against the length
of its region (`host_range`), not against the window, so such a backend could
make the VMM map its file descriptor with `MAP_FIXED` over any address of the
VMM process.

Patch 0004 closes this in three places:

- The device lays the regions out with `checked_add` over the sizes and
  `checked_next_power_of_two` for the window, and refuses a configuration whose
  window does not fit in a `u64`. The VMM takes the window length and the region
  list from that layout instead of computing them again.
- The VMM refuses a window larger than the 64-bit PCI aperture of its segment
  before it allocates anything for it.
- `host_range` also checks region offset + request offset + length against the
  window length, so a region list that reaches past the window never yields an
  address outside it.

It changes no `Cargo.lock`, so the vendor hash stays that of 0001. The patch is a
candidate for upstreaming to Leandro; once Leandro's series carries the same
checks, take the new series and drop 0004.

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
- The package checks for a marker of 0001 (shared memory) and one of 0004 (the
  checked window layout) after applying the patches and sets `doCheck = false`:
  the markers show presence, not correctness. The
  patched tree's own tests (`cargo test -p virtio-devices`) run in the Leandro
  repository for 0001-0003, which records them in its README; the Rust
  workspace tests here do not compile or exercise this series.
- 0004 adds tests of its own to `virtio-devices`. To run them, apply 0001-0004
  with `git apply` to a copy of `.#cloud-hypervisor-meister.src`, point Cargo at
  the vendor tree of `.#cloud-hypervisor-meister.cargoDeps` (its
  `.cargo/config.toml`, with `@vendor@` replaced by the store path) and run
  `cargo test --offline -p virtio-devices` (115 tests on 2026-10-06, three of
  them 0004's).
- The agent starts the GPU backends and attaches their sockets to Cloud
  Hypervisor; see [drivers](../docs/DRIVERS.md).

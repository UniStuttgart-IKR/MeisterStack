# Cloud Hypervisor patches

The [Nix package](../nix/packages/cloud-hypervisor.nix) applies all `.patch` files
recursively, sorted by path, to the pinned Cloud Hypervisor source. The default
version is v53.0; changing the version also requires checking source/vendor hashes
and patch compatibility. Patch files retain their original context and experiment
notes. Those notes are not measurements from the current source review.

| Patch | Purpose |
| --- | --- |
| `0001-generic-vhost-user-shmem.patch` | Negotiate shared-memory regions, allocate a PCI-visible host window, and handle backend map/unmap requests within that window. Skip empty region capabilities while retaining region indexes. |
| `0002-generic-vhost-user-device-features.patch` | Offer the device-specific feature-bit range; negotiation intersects it with the backend's advertised features. |
| `0003-generic-vhost-user-refused-request.patch` | Keep the backend request worker alive after an acknowledged handler refusal; other request errors remain fatal. |

The shared-memory handler replaces mappings inside its reserved window with
backend-provided file descriptors. Unmap restores a `PROT_NONE` placeholder.
`window_target` checks offset-plus-length overflow and the window bound. Allocation
has a separate limitation: summing backend region sizes and rounding the total to
a power of two use unchecked arithmetic. Per-request bounds checks do not validate
that allocation input.

The package checks for a shared-memory patch marker after applying patches and
sets `doCheck = false`. That marker establishes presence, not correctness. Rust
workspace tests do not compile or exercise this upstream patch series. A meaningful
patch validation needs a patched VMM build, backend feature negotiation, mapping
bounds tests, and restore tests. In particular, the patch leaves `shmem_sizes` empty
on restore; complete restoration of the allocated window requires verification
against the upstream restore path.

See [drivers](../docs/DRIVERS.md) for how the agent starts GPU backends and attaches
their sockets to Cloud Hypervisor.

# Drivers

[Contracts](../shared/agent-api/src/lib.rs) · [Registry](../components/agent/src/drivers.rs) · [Agent lifecycle](AGENT.md) · [Cleanup limits](RESOURCE_LIFECYCLE.md).

Configuration selects drivers; prerequisite screening can omit unavailable implementations. Advertisements reflect the built registry, which remains fixed until restart.

## Contract boundaries

| Contract | Owns/does | Boundary |
| --- | --- | --- |
| Confiner | Resource groups, limits and process termination | Group handle does not prove exit |
| Volume provider | Persistent data: create, probe, grow, snapshot, forget, delete | Handle survives attachments |
| Volume attacher | Node-local path or backend connection | Detach preserves provider data |
| Device driver | Admission and device attachment lifecycle | Process-backed and hardware attachments differ |
| NIC/bridge | Taps, bridges and overlays | Shared-resource cleanup requires ownership checks |
| Router/announcer | Router state and published prefixes | Advertisement does not fence another gateway |
| Hypervisor | VMM/guest lifecycle; optional operations | API acceptance may precede completion |

- The registry combines provider/attacher traits as `VolumeDriver`. `Path` means raw file or block device; `FsShare`/`VhostUserBlk` mean backend sockets/processes requiring shared guest memory. Device vhost-user attachments also require it. [Storage](../shared/agent-api/src/storage.rs) · [VMM types](../shared/agent-api/src/hypervisor.rs).
- ID-derived names support retries after incomplete persistence. Implementations must verify existing ownership; trait idempotence does not make external commands transactional.

## Storage implementations

| Driver | Data/locality | Attachment | Snapshot/growth |
| --- | --- | --- | --- |
| [filesystem](../drivers/filesystem/src/lib.rs) | Raw files; NodeLocal | Path | File copy; consistency selected by reflink probe; grows |
| [lvm-thin](../drivers/lvm-thin/src/lib.rs) | Thin LVs; NodeLocal | Device path | Atomic thin snapshots; growth measured after extent rounding |
| [nfs](../drivers/nfs/src/lib.rs) | Raw files/directories; Shared | Path / virtiofsd tag/socket | File mode only |
| [nvmeof-import](../drivers/nvmeof-import/src/lib.rs) | Existing namespaces; Networked | nvmeof delegation | No target creation/deletion, snapshots or growth |
| [nvmeof](../drivers/nvmeof/src/lib.rs) | TCP/RDMA connection layer | nvme-cli + local device | Provider operations unsupported |

| Mechanism | Requirements/limits |
| --- | --- |
| Image provisioning | Filesystem/LVM convert qcow2 through the [base-image sandbox](../shared/agent-api/src/base_image.rs); publish completed staging files/LVs |
| LVM admission | Checks current pool data usage; does not reserve future physical capacity |
| NFS mount | Existing or driver-managed; every eligible node must reach the same data. Current screening requires mount privileges even with management disabled |
| NFS share | Provision creates directory; attachment starts virtiofsd; detach preserves data. File-mode snapshot advertisements do not cover shares |
| NVMe import assignment | Controller-supplied by default; `allow_local_claims` enables local allocation. Claims record ownership/provenance; releasing claims preserves target data |
| **Import ownership gaps** | NQN filename sanitization can collide; claim deletion does not compare the current volume owner |
| **NVMe attachment limits** | Assumes the controller's first namespace; rejects reserved deployment port 4420, also the standard NVMe-oF default. Disconnect errors are logged but returned as success |

## Snapshot consistency and concurrent writers

- `Atomic` does not flush application buffers. `NeedsQuiesce` requires coordinating every writer throughout copying. Agent snapshot calls are awaited before ACK. See [storage coordination](STORAGE.md).
- **Consistency gap:** filesystem probes FICLONE but copies with looping `copy_file_range` or byte-copy fallback; an Atomic advertisement does not enforce one atomic clone. NFS file mode shares this implementation. [Copy implementation](../drivers/filesystem/src/layout.rs).
- **Concurrent cleanup gap:** constructor cleanup removes `.snap.tmp` without proving writer death; another agent opening the same pool can unlink active staging. Space reservations are process-local, including on NFS.

## VMM lifecycle, capabilities and consoles

| Mechanism | Behavior/limit |
| --- | --- |
| [Cloud Hypervisor](../drivers/cloud-hypervisor/src/lib.rs) | Pause/resume, migration and hotplug; no VM snapshot/restore implementation |
| Disks | Stable volume-derived IDs; read-only cloud-init seed follows boot volumes |
| [Process ownership](../drivers/cloud-hypervisor/src/process.rs) | Owned children vs adopted PIDs; identity checked before signalling. Process existence, socket response and guest Running are separate observations |
| Restart/migration | Ordinary VMM adoption supported. **Receiving bypasses adoption; API transport errors/timeouts become receive failure.** See [migration limits](MIGRATION.md) |
| `vmm_user` | Transfer writable files, switch credentials, hand off taps through SCM_RIGHTS add-net. Descriptor NICs cannot currently migrate. [Handoff](../drivers/cloud-hypervisor/src/fd.rs) |
| Sandboxing | Explicit seccomp; Landlock hotplug directories must be allowed at VM creation |
| [Hot-unplug](../drivers/cloud-hypervisor/src/api.rs) | Wait for config removal and, when PID/path available, fd closure. Socket-backed disks use weaker evidence. Default timeout 30 s; timeout does not authorize detach |
| Consoles | Virtio-console file; serial socket through the [agent recorder](../components/agent/src/attach.rs). Separate VMM diagnostics; nonempty logs retained after teardown, then expired by sweeps. Trimming is best effort |

## Devices and backend processes

| Driver | Attachment/admission |
| --- | --- |
| [vfio](../drivers/vfio/src/lib.rs) | Exclusive configured PCI devices; vfio-pci binding |
| [nvrm](../drivers/nvrm/src/lib.rs) | vhost-user GPU; VRAM and optional vGPU-profile limits |
| [crosvm-gpu](../drivers/crosvm-gpu/src/lib.rs) | crosvm vhost-user GPU; configured/request parameters |
| [input](../drivers/input/src/lib.rs) | Upstream vhost-device-input, mediated evdev profile; conflicts by device number, including aliases |

- **NVRM restart gap:** `get` observes existing backends without rebuilding admission accounting. Surviving allocations do not consume subsequent VRAM/profile budgets.
- Input backend user needs host evdev access; guest identity/capabilities come from that device. [Setup and required upstream fix](../drivers/input/README.md).
- [Local VMM patches](../patches/README.md): shared-memory/vhost-user GPU integration and restore limitations.
- [Backend launcher](../drivers/backend/src/lib.rs): spawning, socket-file readiness, logs and optional credentials. Adopted-process checks use executable name + socket argument. **`stop_adopted` sends SIGTERM without waiting/escalating; successful driver cleanup can leave the backend alive**, including NFS virtiofsd.
- [Cgroup v2](../drivers/cgroup/src/lib.rs): VMM/backend limits require delegated controllers. Fixed headroom is policy, not measured peak usage; membership alone does not identify a recycled PID.

## Networking and verification

- [Linux driver](../drivers/linux-network/src/lib.rs): taps/bridges, VXLAN, nftables, namespace routers and FRR through NIC/bridge/router traits. Retain shared overlays while ownership or ports require them. [Failover and limits](NETWORKING.md).
- Configuration tests, temporary storage and call-recording fakes check contracts; they do not qualify kernel, firmware or daemon behavior. Hardware/VMM integration tests require the prerequisites in their module notes.

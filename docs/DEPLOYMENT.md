# Deployment and operation

Choose the runtime mode before copying configuration. The same agent and drivers
support standalone and controller-managed operation; their ownership and access
models differ.

| Mode | Services | State and access |
| --- | --- | --- |
| Standalone node | Agent and local CLI | Agent redb; administrative Unix socket |
| Development control plane | Cloud, cluster, agent and an existing etcd | Separate etcd prefixes; explicit development authentication |
| NixOS fleet | Selected roles per inventory host | Generated service configuration, persistent state and external credentials |
| Existing NixOS host | Imported service or generated host modules | Operator retains hardware, mount and firewall policy |

The deployment tool under `tools/` is outside this runtime review. Its command
examples below describe the established workflow, not newly validated installation,
rollback or provider guarantees. No deployment or destructive test was performed
for this documentation revision.

## Prerequisites

- A Linux host and `/dev/kvm` for VM execution.
- The built runtime binaries and configured VMM/backend executables.
- Storage, image and runtime directories with ownership matching the configured
  agent and VMM users.
- Host tools required by selected drivers, such as `ip`, `qemu-img`, `curl`,
  `nft`, LVM, NFS or NVMe utilities. See [drivers](DRIVERS.md).
- Controller etcd endpoints, distinct namespace prefixes, advertised addresses and
  trust material when using the control plane.
- Firewall rules for the selected REST/gRPC services and data-plane paths. An
  outbound agent session does not eliminate migration or storage listener needs.

Use [configuration](CONFIGURATION.md) for field meanings and path resolution.
A configuration check validates syntax and selected startup prerequisites; it does
not prove that hardware, peers, certificates or live operations work.

## Standalone node

A standalone agent has neither `controller_addr` nor `controller_addrs`. It serves
its Unix socket and owns locally created VMs without cloud objects, scheduling or
tenant authorization. Inline VM disks are tied to those guests.

On NixOS, `meisterstack.singleNode.enable` supplies a local CLI profile and socket
group configuration. The host has the `agent` role only. Add authorized users to
`meisterstack.singleNode.operators`; membership grants administrative node access.
See [the example inventory](../examples/fleet/single-node.toml) and
[the operator profile](../templates/operator/profiles/single-node.nix).

For another Linux system, [meisterstack-install.sh](../scripts/meisterstack-install.sh)
accepts either `single-node` or `cli`. Static build outputs are exposed as
`meisterstack-static` and `cloud-hypervisor-meister-static` in the flake. The script
expects their executable files together in `--bin-dir`.

| Installed path | Purpose |
| --- | --- |
| `/opt/meisterstack/bin/` | Copied binaries |
| `/usr/local/bin/meister` | CLI symlink |
| `/etc/meisterstack/agent.toml` | Standalone agent configuration |
| `/etc/meisterstack/cli.toml` | System CLI profile |
| `/var/lib/meisterstack/` | Images, volumes and agent database |
| `/etc/systemd/system/meister-agent.service` | Agent service |

`--root DIR` writes below a scratch root and skips groups and systemd.
`--dry-run` prints steps. Existing config files and units are retained unless
`--force` is supplied; binaries are still replaced. This is not a transactional
upgrade of a running node. Missing host tools are warnings, not installation
failures.

For OIDC, create a user-owned CLI profile and session path. A system profile without
an explicit token path derives its cache under `/etc/meisterstack`, which ordinary
users cannot normally write. The installer's current output suggesting a user
cache does not match that default.

```sh
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm ls
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm create -f spec.json
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm observe <id>
```

Use a bare `NewVmSpec` from [config/json](../config/json/README.md). Replace example
image paths, devices and network settings with actual host resources.

## Development control plane

Build the four runtime packages shown in the [root README](../README.md).
Start with the cloud, cluster and agent examples in [config/](../config/README.md).
Keep development bearer tokens and plain HTTP listeners on a controlled local
network. Hardened examples use explicit trust and identity files.

An already-running development etcd can serve both tiers with distinct prefixes.
Start the cloud and cluster against the intended namespaces, then connect the
agent. Before creating a guest, inspect discovery, node readiness, capability
reports, pool state and image availability. Acceptance of a VM resource does not
prove successful scheduling or boot.

## NixOS fleet

[templates/operator](../templates/operator/) is the starting point for an operator
repository. Pin inputs, replace example addresses and signing keys, and provide
host modules for actual hardware. See [Nix](NIX.md) for inheritance and rendering.

1. Describe hosts, groups, roles and addresses in `fleet.toml`.
2. Put shared host policy in profiles and hardware-specific values in host modules.
3. Choose an installation layout or declare existing filesystems, without two
   definitions for the same mount.
4. Keep private keys outside the repository and Nix store. Record public trust
   material and verified SSH host keys separately.
5. Evaluate configurations and inspect the manifest before building a release.
6. Review a concrete deployment plan before applying it; inspect the resulting
   state and workload evidence afterwards.

The deployment workflow is `resolve → build → plan → apply`. Enrollment, credential
issuance, installation and workload verification are separate operations. Consult
`meister-deploy --help` and its own documentation for current flags and recovery
procedures. Its dry-run is a different implementation from the runtime CLI's
[limited dry-run](CLI.md#dry-run-limits).

UEFI installations use an ESP and systemd-boot. Direct-boot guests receive kernel,
initrd and command line from their provider. Existing grub hosts supply their own
bootloader and do not use the installation path. A successful Nix build does not
establish a safe provider reboot or rollback.

An existing NixOS host can import `nixosModules.services` or use the generated
`hostModules.<id>` alongside its own hardware configuration. The
[foreign-flake example](../examples/fleet/foreign-flake/flake.nix) exercises this
boundary. The local observability profile is presently a placeholder, and its
baseline Nix expression has a syntax error recorded for later correction.

## Privileges and persistent state

The agent normally runs as root. The optional unprivileged service profile limits
available drivers according to host access and capabilities. `vmm_user` separately
runs supported VMM/backend processes under another Unix identity. It requires
working access to binaries, images, volumes and devices; parent-directory
permissions matter too. `virtiofsd` has its own privileged sandbox path.

The local socket and VMM API sockets remain administrative interfaces. Dropping
the VMM user alone does not make local agent access tenant-safe. See
[security](SECURITY.md) for the complete boundary and known console issues.

Preserve agent databases, volume state, controller namespaces and migration
receipts across restarts. Do not delete a record merely because its owner is
unreachable. Driver reconfiguration can make old handles unusable; retain the
backend names and namespaces needed to finish cleanup.

## Upgrades and recovery

- Quiesce migration admission and settle active attempts before a protocol change.
  Upgrade participating agents and controller replicas together before resuming.
- Preserve both old data and configuration needed for recovery. Additive decoding
  alone does not establish semantic compatibility with older binaries.
- After restart, inspect actual VMM processes, agent records, sessions and resource
  conditions. A healthy service is not proof that every operation completed.
- Treat unknown migration outcome as unresolved ownership. Current receive timeout
  and adoption defects require correction; see [migration](MIGRATION.md).
- For failed cleanup, retain evidence and identify remaining writers before changing
  ownership records. Local locks are not distributed fencing.
- CRL configuration is opt-in. Maintain a valid file and monitor reload errors;
  see [security](SECURITY.md). Identity rotation and system rollback are separate.

Historical lab measurements and deployment-tool runbooks belong to their experiment
records. They are not carried forward as current guarantees in this runtime guide.
